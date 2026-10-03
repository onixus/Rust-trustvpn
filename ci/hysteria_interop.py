#!/usr/bin/env python3
"""Loopback-only official Hysteria 2 fixture with pinned binary digests."""
import hashlib,heapq,json,os,pathlib,platform,secrets,socket,struct,subprocess,tempfile,threading,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
RELEASE='app/v2.12.3'
ASSETS={('Darwin','arm64'):('hysteria-darwin-arm64','9065dc5dc9cd75f7ba881f481e8cb77e7eae17139460ca09d399682ca6fad443'),('Linux','x86_64'):('hysteria-linux-amd64','8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e'),('Linux','aarch64'):('hysteria-linux-arm64','c8dc653c3ba0a28d29a26b8fa52d2086f27c0927afddce95c09965e7174e78b0')}
def binary():
    asset,digest=ASSETS[(platform.system(),platform.machine())]
    target=pathlib.Path(os.environ.get('RTRUST_HYSTERIA_CACHE',str(ROOT/'.ci-tools/hysteria')))/asset;target.parent.mkdir(parents=True,exist_ok=True)
    if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest()!=digest:
        # GitHub release downloads occasionally stall; retry before failing the stage.
        for attempt in range(4):
            try:
                with urllib.request.urlopen('https://github.com/HyNetworks/hysteria/releases/download/'+RELEASE+'/'+asset,timeout=60) as response:data=response.read(64*1024*1024)
                break
            except OSError:
                if attempt==3:raise
                time.sleep(5*(attempt+1))
        if hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError('Hysteria release checksum mismatch')
        target.write_bytes(data);target.chmod(0o755)
    return target

class Relay:
    """Userspace stand-in for the server's port-range redirect: every listen port
    forwards to the single server port, one upstream socket per client path.
    Each direction is delayed so congestion control sees a WAN-like RTT."""
    DELAY=0.02
    def __init__(self,server,count):
        self.server=server;self.sockets=[];self.paths={};self.used=set();self.sources=set();self.lock=threading.Lock();self.closed=False
        self.queue=[];self.sequence=0;self.ready=threading.Condition()
        threading.Thread(target=self.deliver,daemon=True).start()
        for _ in range(count):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));self.sockets.append(s)
            threading.Thread(target=self.downstream,args=(s,),daemon=True).start()
        self.listen=[s.getsockname()[1] for s in self.sockets]
    def ports(self):
        ranges=[]
        for p in sorted(self.listen):
            if ranges and p==ranges[-1][1]+1:ranges[-1][1]=p
            else:ranges.append([p,p])
        return ','.join(str(a) if a==b else f'{a}-{b}' for a,b in ranges) if len(ranges)>1 else f'{ranges[0][0]}-{ranges[0][1]}'
    def downstream(self,listen):
        while True:
            try:data,client=listen.recvfrom(65535)
            except OSError:return
            key=(listen.getsockname()[1],client)
            with self.lock:
                self.used.add(key[0]);self.sources.add(client)
                upstream=self.paths.get(key)
                if upstream is None:
                    upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.connect(self.server);self.paths[key]=upstream
                    threading.Thread(target=self.upstream,args=(upstream,listen,client),daemon=True).start()
            self.later(upstream,data,None)
    def upstream(self,upstream,listen,client):
        while True:
            try:data=upstream.recv(65535)
            except OSError:return
            self.later(listen,data,client)
    def later(self,sock,data,address):
        with self.ready:
            self.sequence+=1;heapq.heappush(self.queue,(time.monotonic()+self.DELAY,self.sequence,sock,data,address));self.ready.notify()
    def deliver(self):
        while True:
            with self.ready:
                while not self.queue or self.queue[0][0]>time.monotonic():
                    if self.closed:return
                    self.ready.wait(None if not self.queue else self.queue[0][0]-time.monotonic())
                _,_,sock,data,address=heapq.heappop(self.queue)
            try:sock.send(data) if address is None else sock.sendto(data,address)
            except OSError:pass
    def close(self):
        with self.ready:self.closed=True;self.ready.notify()
        for s in self.sockets+list(self.paths.values()):s.close()

def main():
    executable=binary()
    tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen();udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0))
    def serve_tcp():
        while True:
            try:c,_=tcp.accept()
            except OSError:return
            def exchange(c):
                with c:
                    c.settimeout(20);digest=hashlib.sha256();header=b''
                    while len(header)<4:
                        chunk=c.recv(4-len(header))
                        if not chunk:return
                        header+=chunk
                    remaining=struct.unpack('!I',header)[0]
                    while remaining:
                        chunk=c.recv(min(remaining,65536))
                        if not chunk:return
                        digest.update(chunk);remaining-=len(chunk)
                    c.sendall(digest.hexdigest().encode())
            threading.Thread(target=exchange,args=(c,),daemon=True).start()
    seen=[]
    def serve_udp():
        while True:
            try:data,addr=udp.recvfrom(65535);seen.append(len(data));udp.sendto(data if len(data)<=4000 else ("SHA256:"+str(len(data))+":"+hashlib.sha256(data).hexdigest()).encode(),addr)
            except OSError:return
    threading.Thread(target=serve_tcp,daemon=True).start();threading.Thread(target=serve_udp,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='rtrust-hysteria-') as temporary:
        work=pathlib.Path(temporary);probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        auth=secrets.token_urlsafe(32);obfs=secrets.token_urlsafe(32)
        config={'listen':f'127.0.0.1:{port}','tls':{'cert':str(work/'cert.pem'),'key':str(work/'key.pem')},'auth':{'type':'password','password':auth},'obfs':{'type':'salamander','salamander':{'password':obfs}},'bandwidth':{'up':'1 gbps','down':'1 gbps'}}
        profile={'schema_version':1,'protocol':'hysteria2','hysteria2':{'salamander':obfs},'name':'Isolated Hysteria','endpoint':{'hostname':'localhost','addresses':[f'127.0.0.1:{port}'],'username':'hysteria2','password':auth,'upstream_protocol':'http3','certificate':(work/'cert.pem').read_text()}}
        server=work/'server.json';server.write_text(json.dumps(config));server.chmod(0o600)
        client=work/'client.json';client.write_text(json.dumps(profile));client.chmod(0o600)
        relay=Relay(('127.0.0.1',port),16)
        hopping={**profile,'name':'Isolated Hysteria hopping','hysteria2':{'salamander':obfs,'hop_ports':relay.ports(),'hop_interval_min_ms':5000,'hop_interval_max_ms':5000,'up_bps':20_000_000,'down_bps':50_000_000,'congestion':'reno','quic':{'stream_receive_window':4194304,'connection_receive_window':16777216,'max_idle_timeout_ms':20000,'keep_alive_ms':4000}},'endpoint':{**profile['endpoint'],'addresses':[f'127.0.0.1:{relay.listen[0]}']}}
        hop_client=work/'hop.json';hop_client.write_text(json.dumps(hopping));hop_client.chmod(0o600)
        # A second official server uses Gecko, which cannot coexist with Salamander on one listener.
        probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.bind(('127.0.0.1',0));gecko_port=probe.getsockname()[1];probe.close()
        # It also requires mutual TLS with a separate client CA.
        quiet={'check':True,'stdout':subprocess.DEVNULL,'stderr':subprocess.DEVNULL}
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj','/CN=Fixture client CA','-keyout',str(work/'client-ca.key'),'-out',str(work/'client-ca.pem')],**quiet)
        subprocess.run(['openssl','req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=fixture-client','-keyout',str(work/'client.key'),'-out',str(work/'client.csr')],**quiet)
        (work/'client.ext').write_text('basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n')
        subprocess.run(['openssl','x509','-req','-in',str(work/'client.csr'),'-CA',str(work/'client-ca.pem'),'-CAkey',str(work/'client-ca.key'),'-CAcreateserial','-days','1','-extfile',str(work/'client.ext'),'-out',str(work/'client.pem')],**quiet)
        gecko_config={**config,'listen':f'127.0.0.1:{gecko_port}','tls':{**config['tls'],'clientCA':str(work/'client-ca.pem')},'obfs':{'type':'gecko','gecko':{'password':obfs,'minPacketSize':600,'maxPacketSize':1400}}}
        gecko_server=work/'gecko-server.json';gecko_server.write_text(json.dumps(gecko_config));gecko_server.chmod(0o600)
        gecko={**profile,'name':'Isolated Hysteria Gecko','hysteria2':{'salamander':obfs,'gecko':{'min_packet_size':700,'max_packet_size':1300},'client_certificate':(work/'client.pem').read_text(),'client_key':(work/'client.key').read_text()},'endpoint':{**profile['endpoint'],'addresses':[f'127.0.0.1:{gecko_port}']}}
        gecko_client=work/'gecko.json';gecko_client.write_text(json.dumps(gecko));gecko_client.chmod(0o600)
        with (work/'server.log').open('wb') as log,(work/'gecko-server.log').open('wb') as gecko_log:
            process=subprocess.Popen([str(executable),'server','-c',str(server)],stdout=log,stderr=log,env={**os.environ,'HYSTERIA_DISABLE_UPDATE_CHECK':'1'})
            gecko_process=subprocess.Popen([str(executable),'server','-c',str(gecko_server)],stdout=gecko_log,stderr=gecko_log,env={**os.environ,'HYSTERIA_DISABLE_UPDATE_CHECK':'1'})
            try:
                time.sleep(.5)
                if process.poll() is not None or gecko_process.poll() is not None:raise RuntimeError('Hysteria fixture did not start')
                env={**os.environ,'RTRUST_HYSTERIA_FIXTURE':str(client),'RTRUST_HYSTERIA_HOP_FIXTURE':str(hop_client),'RTRUST_HYSTERIA_GECKO_FIXTURE':str(gecko_client),'RTRUST_HYSTERIA_MAX_UDP':'8192' if platform.system()=='Darwin' else '65507','RTRUST_HYSTERIA_TCP':str(tcp.getsockname()[1]),'RTRUST_HYSTERIA_UDP':str(udp.getsockname()[1])}
                subprocess.run(['cargo','test','--locked','-p','rtrust-engine','--test','hysteria_fixture','--','--ignored','--test-threads','1'],cwd=ROOT,env=env,check=True,timeout=240)
                # Each hop must use a new client socket and the set must be spread over server ports.
                if len(relay.sources)<3 or len(relay.used)<2:raise RuntimeError(f'Port hopping not observed: {len(relay.sources)} client sockets, {len(relay.used)} server ports')
            finally:
                for p in (process,gecko_process):p.terminate();p.wait(timeout=10)
                tcp.close();udp.close();relay.close();print("UDP fixture payload lengths:",seen)
    print('PASS official Hysteria 2: TCP payload, UDP fragmentation and independent sessions')
    print('PASS official Hysteria 2 Gecko + mutual TLS: fragmented handshake, TCP/UDP, missing client certificate and Salamander mismatch rejected')
    print(f'PASS official Hysteria 2 port hopping: {len(relay.sources)} client sockets over {len(relay.used)} of 16 server ports, Brutal/reno and QUIC options')
if __name__=='__main__':main()
