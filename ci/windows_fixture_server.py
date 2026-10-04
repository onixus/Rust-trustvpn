"""Runs only in the disposable Docker endpoint fixture."""
import http.server,os,pathlib,signal,socket,subprocess,threading,time,struct,hashlib
# The container's own addresses; a fixture may move them off the default subnet.
IP=os.environ.get('RTRUST_FIXTURE_IP','10.231.243.2');IP6=os.environ.get('RTRUST_FIXTURE_IP6','fd00:5254:243::2')
BODY=bytes(range(256))*2048
paused=threading.Event()
token=pathlib.Path('/fixture/control-token').read_text()
class Control(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get('Authorization')!='Bearer '+token:
            self.send_error(403);return
        if self.path=='/pause':paused.set()
        elif self.path=='/resume':paused.clear()
        elif self.path=='/cycle':
            # QUIC has no TCP EOF when the endpoint process disappears. Keep
            # it down past the client's 30-second idle deadline and health poll.
            # A fixture may lengthen it: a client that detects the outage only
            # by idle timeout needs a margin before the endpoint returns.
            override=pathlib.Path('/fixture/outage-seconds')
            duration=int(override.read_text()) if override.exists() else 45 if pathlib.Path('/fixture/hysteria.json').exists() else 12
            threading.Timer(1,paused.set).start();threading.Timer(duration,paused.clear).start()
        else:self.send_error(404);return
        self.send_response(204);self.end_headers()
    def log_message(self,*_):pass
control=http.server.ThreadingHTTPServer(('0.0.0.0',8082),Control)
threading.Thread(target=control.serve_forever,daemon=True).start()
class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length',str(len(BODY)));self.end_headers();self.wfile.write(BODY)
    def log_message(self,*_):pass
server=http.server.ThreadingHTTPServer(('0.0.0.0',8080),HTTP)
threading.Thread(target=server.serve_forever,daemon=True).start()
class HTTP6(http.server.ThreadingHTTPServer):
    address_family=socket.AF_INET6
server6=HTTP6((IP6,8080),HTTP)
threading.Thread(target=server6.serve_forever,daemon=True).start()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('0.0.0.0',8081))
def echo(sock):
    while True:
        data,addr=sock.recvfrom(65535)
        response=("SHA256:"+str(len(data))+":"+hashlib.sha256(data).hexdigest()).encode() if len(data)>4000 and pathlib.Path('/fixture/hysteria.json').exists() else data
        sock.sendto(response,addr)
threading.Thread(target=echo,args=(udp,),daemon=True).start()
udp6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);udp6.bind((IP6,8081))
threading.Thread(target=echo,args=(udp6,),daemon=True).start()
# Synthetic DNS; all A answers point to the isolated TCP/UDP target.
dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('0.0.0.0',53))
def answer_dns():
    while True:
        data,addr=dns.recvfrom(4096)
        if len(data)<17:continue
        i=12; labels=[]
        while i<len(data) and data[i]:
            labels.append(data[i+1:i+1+data[i]].lower());i+=data[i]+1
        end=i+5
        if end>len(data):continue
        qtype=struct.unpack('!H',data[i+1:i+3])[0]
        # Do not map OS connectivity checks and unrelated names to the same
        # test IP: domain routing deliberately keeps shared-IP conflicts in VPN.
        known=bool(labels) and (labels[-1]==b'example' or labels[-2:]==[b'fixture',b'test'])
        answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(IP) if qtype==1 and known else b''
        result=data[:2]+struct.pack('!HHHHH',0x8180 if known else 0x8183,1,int(bool(answer)),0,0)+data[12:end]+answer
        dns.sendto(result,addr)
threading.Thread(target=answer_dns,daemon=True).start()

# Path attribution for mobile split-routing tests (isolated fixture only).
class SourceHTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=self.client_address[0].encode('ascii')
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass
source_http=http.server.ThreadingHTTPServer(('0.0.0.0',8083),SourceHTTP)
threading.Thread(target=source_http.serve_forever,daemon=True).start()
source_udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);source_udp.bind(('0.0.0.0',8084))
def report_source():
    while True:
        _,addr=source_udp.recvfrom(4096);source_udp.sendto(addr[0].encode('ascii'),addr)
threading.Thread(target=report_source,daemon=True).start()
# Start/restart only the endpoint, keeping the TCP/UDP test targets alive.
# RTRUST_FIXTURE_FREEZE suspends the endpoint instead of stopping it. Docker
# Desktop's userspace UDP port forward stops delivering once the listener
# inside the container has gone away, even after it is back; a suspended
# process keeps its socket and is as silent to the client.
freeze=bool(os.environ.get('RTRUST_FIXTURE_FREEZE'));frozen=False
process=None
try:
    until=time.monotonic()+900
    while time.monotonic()<until:
        if paused.is_set() and process and freeze:
            if not frozen:process.send_signal(signal.SIGSTOP);frozen=True
        elif paused.is_set() and process:
            process.terminate();process.wait(timeout=5);process=None
        if not paused.is_set() and frozen:
            process.send_signal(signal.SIGCONT);frozen=False
        if not paused.is_set() and process is None:
            command=['/fixture/hysteria','server','-c','/fixture/hysteria.json'] if pathlib.Path('/fixture/hysteria.json').exists() else ['/fixture/amneziawg','serve','/fixture/amneziawg.uapi'] if pathlib.Path('/fixture/amneziawg.uapi').exists() else ['/fixture/trusttunnel_endpoint','/fixture/vpn.toml','/fixture/hosts.toml','--jobs','2']
            process=subprocess.Popen(command,cwd='/fixture')
        time.sleep(.2)
finally:
    if process:
        if frozen:process.send_signal(signal.SIGCONT)
        process.terminate();process.wait(timeout=5)
