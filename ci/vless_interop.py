#!/usr/bin/env python3
"""Loopback-only official Xray-core VLESS (WebSocket + TLS) fixture with pinned release digests.

Server config mirrors the onixus/tunnel CDN origin (vless, decryption none, ws, tls, freedom + blackhole);
mode private adds its PRIVATE block rule, so loopback targets must close without data.
Xray 26 freedom already blackholes private targets by default (delayed close); mode open adds a
freedom finalRules allow for 127.0.0.1/32 only, so the loopback echo targets are reachable.
"""
import argparse,base64,signal,sys,hashlib,io,json,os,pathlib,platform,secrets,socket,ssl,string,struct,subprocess,tempfile,threading,time,urllib.parse,urllib.request,uuid,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
RELEASE='v26.10.21'
ASSETS={('Darwin','arm64'):('Xray-macos-arm64-v8a.zip','926cc55fda2a8757dabe4f22dc98772f218ace025f101bd0b68aee232e59d5dc'),('Linux','x86_64'):('Xray-linux-64.zip','0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978'),('Linux','aarch64'):('Xray-linux-arm64-v8a.zip','d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c')}
DOMAIN='vless.test'
# Same list as the server's routing policy (onixus/tunnel cdn.py PRIVATE).
PRIVATE=['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','::1/128','fc00::/7','fe80::/10']
UDP_SIZES=(1,1400,8190,8191,20000)

def binary():
    asset,digest=ASSETS[(platform.system(),platform.machine())]
    cache=pathlib.Path(os.environ.get('RTRUST_XRAY_CACHE',str(ROOT/'.ci-tools/xray')));cache.mkdir(parents=True,exist_ok=True)
    archive=cache/f'{RELEASE}-{asset}'
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest()!=digest:
        # GitHub release downloads occasionally stall; retry before failing the stage.
        for attempt in range(4):
            try:
                with urllib.request.urlopen(f'https://github.com/XTLS/Xray-core/releases/download/{RELEASE}/{asset}',timeout=60) as response:data=response.read(64*1024*1024)
                break
            except OSError:
                if attempt==3:raise
                time.sleep(5*(attempt+1))
        if hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError('Xray release checksum mismatch')
        archive.write_bytes(data)
    # Only the single verified member is extracted, into its own directory.
    with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as z:member=z.read('xray')
    target=cache/f'{RELEASE}-{asset[:-4]}'/'xray';target.parent.mkdir(exist_ok=True)
    if not target.exists() or target.read_bytes()!=member:
        partial=target.with_suffix('.partial');partial.write_bytes(member);partial.chmod(0o755);partial.replace(target)
    return target

def free_port():
    s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();return port

def certificates(work):
    quiet={'check':True,'stdout':subprocess.DEVNULL,'stderr':subprocess.DEVNULL};ec=['-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes']
    subprocess.run(['openssl','req','-x509',*ec,'-days','1','-subj','/CN=R-Trust VLESS fixture CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(work/'ca.key'),'-out',str(work/'ca.pem')],**quiet)
    subprocess.run(['openssl','req',*ec,'-subj','/CN='+DOMAIN,'-keyout',str(work/'server.key'),'-out',str(work/'server.csr')],**quiet)
    (work/'server.ext').write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{DOMAIN}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
    subprocess.run(['openssl','x509','-req','-in',str(work/'server.csr'),'-CA',str(work/'ca.pem'),'-CAkey',str(work/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(work/'server.ext'),'-out',str(work/'server.pem')],**quiet)
    for name in ('ca.key','server.key'):(work/name).chmod(0o600)

def render_server(work,port,user,path,mode):
    stream={'network':'ws','security':'tls','wsSettings':{'path':path},'tlsSettings':{'minVersion':'1.2','certificates':[{'certificateFile':str(work/'server.pem'),'keyFile':str(work/'server.key')}]}}
    return {'log':{'loglevel':os.environ.get('RTRUST_XRAY_LOGLEVEL','warning'),'access':'none'},
            'inbounds':[{'tag':'cdn','listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'clients':[{'id':user,'email':'fixture'}],'decryption':'none'},'streamSettings':stream}],
            'outbounds':[{'tag':'direct','protocol':'freedom',**({'settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}} if mode=='open' else {})},{'tag':'block','protocol':'blackhole'}],
            'routing':{'rules':[{'type':'field','ip':PRIVATE,'outboundTag':'block'}] if mode=='private' else []}}

def render_client(user,port,path,name):
    query={'encryption':'none','security':'tls','sni':DOMAIN,'host':DOMAIN,'fp':'chrome','type':'ws','path':path,'alpn':'http/1.1'}
    return f'vless://{user}@127.0.0.1:{port}?'+urllib.parse.urlencode(query,quote_via=urllib.parse.quote)+'#'+urllib.parse.quote(name)

class Echo:
    """TCP and UDP echo on loopback; counts what actually reached the target."""
    def __init__(self):
        self.tcp=socket.socket();self.tcp.bind(('127.0.0.1',0));self.tcp.listen();self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind(('127.0.0.1',0))
        # A second UDP target: several destinations share one tunnel.
        self.udp2=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp2.bind(('127.0.0.1',0))
        self.accepted=0;self.tcp_bytes=0;self.udp_seen=[]
        threading.Thread(target=self.serve_tcp,daemon=True).start()
        for sock in (self.udp,self.udp2):threading.Thread(target=self.serve_udp,args=(sock,),daemon=True).start()
    ports=property(lambda self:(self.tcp.getsockname()[1],self.udp.getsockname()[1]))
    def serve_tcp(self):
        while True:
            try:c,_=self.tcp.accept()
            except OSError:return
            self.accepted+=1;threading.Thread(target=self.exchange,args=(c,),daemon=True).start()
    def exchange(self,c):
        with c:
            # Longer than any client keepalive: an idle flow must outlive its pings.
            c.settimeout(300)
            try:
                while (data:=c.recv(65536)):self.tcp_bytes+=len(data);c.sendall(data)
            except OSError:pass
    def serve_udp(self,sock):
        while True:
            try:data,addr=sock.recvfrom(65535);self.udp_seen.append(len(data));sock.sendto(data,addr)
            except OSError:return
    def close(self):self.tcp.close();self.udp.close();self.udp2.close()

class Slow:
    """TCP target that reads about 32 KiB/s and answers nothing until it reads
    the end marker 0xFF, then the number of bytes before it. The client sees
    steady back-pressure and no downlink traffic for as long as the upload lasts.
    VLESS over WebSocket carries no TCP half-close, so the end is in-band.
    After SLOW_FOR seconds it reads at full speed, so buffered bytes drain quickly."""
    RATE=32*1024;SLOW_FOR=95
    def __init__(self):
        self.tcp=socket.socket();self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,32*1024);self.tcp.bind(('127.0.0.1',0));self.tcp.listen()
        threading.Thread(target=self.serve,daemon=True).start()
    port=property(lambda self:self.tcp.getsockname()[1])
    def serve(self):
        while True:
            try:c,_=self.tcp.accept()
            except OSError:return
            threading.Thread(target=self.exchange,args=(c,),daemon=True).start()
    def exchange(self,c):
        with c:
            c.settimeout(300);start=time.monotonic();total=0
            try:
                while True:
                    slow=time.monotonic()-start<self.SLOW_FOR
                    data=c.recv(4096 if slow else 262144)
                    if not data:return
                    if (end:=data.find(b'\xff'))>=0:total+=end;break
                    total+=len(data)
                    if slow:time.sleep(len(data)/self.RATE)
                c.sendall(str(total).encode())
            except OSError:pass
    def close(self):self.tcp.close()

class Stand:
    def __init__(self,executable,work,mode,name=None):
        name=name or mode;self.mode=mode;self.port=free_port();self.user=str(uuid.uuid4())
        self.path='/'+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(24))
        self.config=work/f'server-{name}.json';self.config.write_text(json.dumps(render_server(work,self.port,self.user,self.path,mode)));self.config.chmod(0o600)
        self.logfile=work/f'server-{name}.log';self.log=self.logfile.open('wb')
        self.process=subprocess.Popen([str(executable),'run','-c',str(self.config)],stdout=self.log,stderr=self.log,cwd=work)
        for _ in range(100):
            if self.process.poll() is not None:raise RuntimeError(f'Xray ({name}) exited: '+self.logfile.read_text()[-2000:])
            try:socket.create_connection(('127.0.0.1',self.port),timeout=.2).close();break
            except OSError:time.sleep(.1)
        else:raise RuntimeError(f'Xray ({name}) did not listen')
        self.link=render_client(self.user,self.port,self.path,'Isolated VLESS '+name)
    def close(self):
        if self.process.poll() is None:self.process.terminate()
        self.process.wait(timeout=10);self.log.close()

# --- minimal independent client for --self-test (no project code involved) ---
class WS:
    def __init__(self,stand,ca,path=None):
        context=ssl.create_default_context(cafile=str(ca));context.set_alpn_protocols(['http/1.1'])
        self.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',stand.port),timeout=5),server_hostname=DOMAIN);self.sock.settimeout(3)
        self.alpn=self.sock.selected_alpn_protocol();self.buffer=b''
        key=base64.b64encode(secrets.token_bytes(16)).decode()
        self.sock.sendall(f'GET {path or stand.path} HTTP/1.1\r\nHost: {DOMAIN}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode())
        while b'\r\n\r\n' not in self.buffer:
            chunk=self.sock.recv(4096)
            if not chunk:break
            self.buffer+=chunk
        head,_,self.buffer=self.buffer.partition(b'\r\n\r\n');lines=head.decode('latin1').split('\r\n')
        self.status=int(lines[0].split()[1]) if lines[0] else 0
        headers={k.strip().lower():v.strip() for k,_,v in (l.partition(':') for l in lines[1:])}
        if self.status==101 and headers.get('sec-websocket-accept')!=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode():raise RuntimeError('bad Sec-WebSocket-Accept')
    def send(self,payload,opcode=2):
        mask=secrets.token_bytes(4);n=len(payload)
        head=bytes([0x80|opcode])+(bytes([0x80|n]) if n<126 else bytes([0xfe])+struct.pack('!H',n) if n<65536 else bytes([0xff])+struct.pack('!Q',n))
        self.sock.sendall(head+mask+bytes(b^mask[i&3] for i,b in enumerate(payload)))
    def read(self,n):
        while len(self.buffer)<n:
            chunk=self.sock.recv(65536)
            if not chunk:raise EOFError
            self.buffer+=chunk
        data,self.buffer=self.buffer[:n],self.buffer[n:];return data
    def frame(self,timeout=3):
        """One data frame payload, or a tag: 'eof', 'close:<code>', 'timeout'."""
        self.sock.settimeout(timeout)
        try:
            while True:
                b0,b1=self.read(2);n=b1&0x7f
                if n==126:n=struct.unpack('!H',self.read(2))[0]
                elif n==127:n=struct.unpack('!Q',self.read(8))[0]
                mask=self.read(4) if b1&0x80 else b'';data=self.read(n)
                if mask:data=bytes(b^mask[i&3] for i,b in enumerate(data))
                op=b0&0x0f
                if op==8:return 'close:'+(str(struct.unpack('!H',data[:2])[0]) if len(data)>=2 else '-')
                if op==9:self.send(data,10);continue
                if op in (0,1,2):return data
        except (TimeoutError,socket.timeout):return 'timeout'
        except (EOFError,ConnectionError,ssl.SSLError):return 'eof'
    def close(self):
        try:self.sock.close()
        except OSError:pass

def vless_header(user,cmd,port):
    return b'\x00'+uuid.UUID(user).bytes+b'\x00'+bytes([cmd])+struct.pack('!H',port)+b'\x01'+socket.inet_aton('127.0.0.1')

class Stream:
    """VLESS response reader over WS frames: strips the 2+n byte response header once."""
    def __init__(self,ws):self.ws=ws;self.data=b'';self.header=None;self.end=None;self.frames=[]
    def pull(self,timeout=3):
        f=self.ws.frame(timeout)
        if isinstance(f,str):self.end=f;return False
        self.frames.append(len(f));self.data+=f
        if self.header is None and len(self.data)>=2 and len(self.data)>=2+self.data[1]:self.header=self.data[:2+self.data[1]];self.data=self.data[2+self.data[1]:]
        return True
    def take(self,n,timeout=3):
        deadline=time.monotonic()+timeout
        while (self.header is None or len(self.data)<n) and time.monotonic()<deadline:
            if not self.pull(max(.05,deadline-time.monotonic())):break
        out,self.data=self.data[:n],self.data[n:];return out

def self_test(executable,work,echo):
    tcp_port,udp_port=echo.ports;results=[];notes=[]
    def check(name,ok,detail=''):results.append(ok);print(('PASS ' if ok else 'FAIL ')+name+(': '+detail if detail else ''),flush=True)
    stand=Stand(executable,work,'open');private=Stand(executable,work,'private');ca=work/'ca.pem'
    try:
        # 1. TCP: header + payload in the first frame.
        ws=WS(stand,ca);check('TLS ALPN http/1.1 + WS upgrade',ws.status==101 and ws.alpn=='http/1.1',f'status={ws.status} alpn={ws.alpn}')
        payload=secrets.token_bytes(3000);ws.send(vless_header(stand.user,1,tcp_port)+payload);s=Stream(ws);got=s.take(len(payload))
        check('TCP echo via VLESS cmd=1',got==payload and s.header==b'\x00\x00',f'response header={s.header.hex() if s.header else None} first frame len={s.frames[:1]}')
        notes.append(f'response header arrives in the same WS frame as the first data: first frame {s.frames[0] if s.frames else None} bytes = 2 + data')
        big=secrets.token_bytes(200000);ws.send(big);got=s.take(len(big),10);check('TCP 200000 bytes follow-up',got==big,f'{len(got)} bytes in {len(s.frames)} frames')
        ws.close()
        # 2. Header without payload: is the target dialed, and is the response header sent early?
        before=echo.accepted;ws=WS(stand,ca);ws.send(vless_header(stand.user,1,tcp_port));s=Stream(ws);s.pull(1.5)
        dialed=echo.accepted-before;early=s.frames[:]
        ws.send(b'ping');got=s.take(4)
        check('header-only request then payload',got==b'ping',f'target dialed before payload={dialed>0}; frames before payload={early} ({s.end or "no frame"}); after payload first frame len={s.frames[len(early):len(early)+1]}')
        notes.append(f'header without payload: Xray dialed target={dialed>0}, sent nothing within 1.5 s={not early}; response header only came with first data')
        ws.close()
        # 3. UDP cmd=2 with [u16 len][payload]; each size on its own session.
        delivered={}
        for size in UDP_SIZES:
            mark=len(echo.udp_seen);ws=WS(stand,ca);data=secrets.token_bytes(size)
            try:ws.send(vless_header(stand.user,2,udp_port)+struct.pack('!H',size)+data)
            except struct.error:pass
            s=Stream(ws);raw=s.take(2,3);back=None
            if len(raw)==2:back=s.take(struct.unpack('!H',raw)[0],3)
            reached=echo.udp_seen[mark:];delivered[size]=(reached,len(back) if back is not None else None,back==data,s.end)
            ws.close()
        for size,(reached,back,ok,end) in delivered.items():print(f'  UDP {size}: reached echo {reached}, returned {back} bytes, intact={ok}, end={end}')
        check('UDP 1/1400/8190 round trip',all(delivered[n][2] for n in (1,1400,8190)))
        notes.append('UDP sizes delivered intact: '+', '.join(str(n) for n,v in delivered.items() if v[2])+'; not delivered: '+(', '.join(str(n) for n,v in delivered.items() if not v[2]) or 'none'))
        # Several datagrams on one session, coalesced into one WS frame.
        ws=WS(stand,ca);parts=[secrets.token_bytes(n) for n in (10,500,1400)]
        ws.send(vless_header(stand.user,2,udp_port)+b''.join(struct.pack('!H',len(p))+p for p in parts));s=Stream(ws);back=[]
        for _ in parts:
            raw=s.take(2);back.append(s.take(struct.unpack('!H',raw)[0]) if len(raw)==2 else b'')
        check('UDP three datagrams in one WS frame',back==parts,f'lengths back={[len(b) for b in back]}');ws.close()
        # 4. Wrong path.
        ws=WS(stand,ca,'/'+'x'*24);check('wrong path rejected before WS',ws.status!=101,f'HTTP status {ws.status}');notes.append(f'wrong path -> HTTP {ws.status}');ws.close()
        # 5. Wrong UUID.
        before=echo.accepted;ws=WS(stand,ca);ws.send(vless_header(str(uuid.uuid4()),1,tcp_port)+b'hello');f=ws.frame(4)
        check('wrong UUID: no data, target not dialed',isinstance(f,str) and echo.accepted==before,f'result={f if isinstance(f,str) else len(f)}');notes.append(f'wrong UUID -> WS upgrade 101 then {f if isinstance(f,str) else "data"}');ws.close()
        # 6. Private mode: loopback targets blocked.
        before=(echo.accepted,len(echo.udp_seen))
        ws=WS(private,ca);ws.send(vless_header(private.user,1,tcp_port)+b'hello');s=Stream(ws);t0=time.monotonic()
        while s.pull(8) and time.monotonic()-t0<8:pass
        elapsed=time.monotonic()-t0
        check('private: TCP to 127.0.0.1 ends without data',(s.end=='eof' or (s.end or '').startswith('close')) and not s.data,f'end={s.end} after {elapsed:.1f}s frames={s.frames} header={s.header.hex() if s.header else None} data={len(s.data)}');tcp_end=f'{s.end} after {elapsed:.1f}s, response header={s.header.hex() if s.header else None}, data bytes={len(s.data)}';ws.close()
        ws=WS(private,ca);ws.send(vless_header(private.user,2,udp_port)+b'\x00\x05hello');s=Stream(ws);s.pull(4)
        check('private: UDP to 127.0.0.1 gets no data',not s.frames,f'end={s.end} frames={s.frames}');ws.close()
        check('private: echo never reached',(echo.accepted,len(echo.udp_seen))==before)
        notes.append(f'private TCP -> {tcp_end}; private UDP -> {s.end}')
    finally:
        stand.close();private.close()
        if not all(results):
            for mode in ('open','private'):print(f'--- Xray {mode} log tail ---\n'+(work/f'server-{mode}.log').read_text()[-3000:])
    print('Observations:');[print('  - '+n) for n in notes]
    if not all(results):raise SystemExit('FAIL self-test')
    print('PASS VLESS fixture self-test (official Xray-core '+RELEASE+')')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--serve-only',action='store_true');parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--mode',choices=('open','private','both'),default='both');args=parser.parse_args()
    # SIGTERM (CI abort) unwinds like Ctrl-C, so Xray and the temporary keys are removed.
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(143))
    executable=binary();echo=Echo();slow=Slow()
    with tempfile.TemporaryDirectory(prefix='rtrust-vless-') as temporary:
        work=pathlib.Path(temporary);certificates(work)
        try:
            if args.self_test:return self_test(executable,work,echo)
            modes=['open','private'] if args.mode=='both' else [args.mode]
            if args.serve_only:modes=modes[:1]
            for mode in modes:
                stand=Stand(executable,work,mode);extra=[]
                try:
                    env={'RTRUST_VLESS_LINK':stand.link,'RTRUST_VLESS_CA':str(work/'ca.pem'),'RTRUST_VLESS_TCP':str(echo.ports[0]),'RTRUST_VLESS_UDP':str(echo.ports[1]),'RTRUST_VLESS_UDP2':str(echo.udp2.getsockname()[1]),'RTRUST_VLESS_SLOW':str(slow.port),'RTRUST_VLESS_MODE':mode}
                    if args.serve_only:
                        print('\n'.join(f"export {k}='{v}'" for k,v in env.items()),flush=True);print('Serving on 127.0.0.1; Ctrl-C to stop',flush=True)
                        try:
                            while stand.process.poll() is None:time.sleep(1)
                        except KeyboardInterrupt:pass
                        return
                    if mode=='open':
                        # A separate server the crash test kills and restarts on the same port.
                        restart=Stand(executable,work,'open','restart');extra.append(restart)
                        env.update({'RTRUST_VLESS_RESTART_LINK':restart.link,'RTRUST_VLESS_RESTART_PID':str(restart.process.pid),'RTRUST_VLESS_RESTART_CONFIG':str(restart.config),'RTRUST_VLESS_XRAY':str(executable)})
                    before=(echo.accepted,len(echo.udp_seen))
                    # One test at a time: the socket-release test counts this process's descriptors.
                    subprocess.run(['cargo','test','--locked','-p','rtrust-engine','--test','vless_fixture','--','--ignored','--nocapture','--test-threads=1'],cwd=ROOT,env={**os.environ,**env},check=True,timeout=1200)
                    # Independent of the client: blocked targets never saw a packet.
                    if mode=='private' and (echo.accepted,len(echo.udp_seen))!=before:raise SystemExit(f'FAIL private mode reached the echo: {before} -> {(echo.accepted,len(echo.udp_seen))}')
                    print(f'PASS official Xray-core {RELEASE} VLESS ws+tls, mode {mode}')
                finally:
                    for s in [stand,*extra]:s.close()
        finally:echo.close();slow.close()
if __name__=='__main__':main()
