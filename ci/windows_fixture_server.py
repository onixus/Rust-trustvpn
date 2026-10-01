"""Runs only in the disposable Docker endpoint fixture."""
import http.server,pathlib,socket,subprocess,threading,time,struct
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
            threading.Timer(1,paused.set).start();threading.Timer(12,paused.clear).start()
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
server6=HTTP6(('fd00:5254:243::2',8080),HTTP)
threading.Thread(target=server6.serve_forever,daemon=True).start()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('0.0.0.0',8081))
def echo(sock):
    while True:
        data,addr=sock.recvfrom(65535);sock.sendto(data,addr)
threading.Thread(target=echo,args=(udp,),daemon=True).start()
udp6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);udp6.bind(('fd00:5254:243::2',8081))
threading.Thread(target=echo,args=(udp6,),daemon=True).start()
# Synthetic DNS; all A answers point to the isolated TCP/UDP target.
dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('0.0.0.0',53))
def answer_dns():
    while True:
        data,addr=dns.recvfrom(4096)
        if len(data)<17:continue
        i=12
        while i<len(data) and data[i]:i+=data[i]+1
        end=i+5
        if end>len(data):continue
        qtype=struct.unpack('!H',data[i+1:i+3])[0]
        answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton('10.231.243.2') if qtype==1 else b''
        result=data[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(answer)),0,0)+data[12:end]+answer
        dns.sendto(result,addr)
threading.Thread(target=answer_dns,daemon=True).start()
# Start/restart only the endpoint, keeping the TCP/UDP test targets alive.
process=None
try:
    until=time.monotonic()+900
    while time.monotonic()<until:
        if paused.is_set() and process:
            process.terminate();process.wait(timeout=5);process=None
        if not paused.is_set() and process is None:
            process=subprocess.Popen(['/fixture/trusttunnel_endpoint','/fixture/vpn.toml','/fixture/hosts.toml','--jobs','2'],cwd='/fixture')
        time.sleep(.2)
finally:
    if process:process.terminate();process.wait(timeout=5)
