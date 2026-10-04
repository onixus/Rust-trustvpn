"""Temporary official endpoint for native macOS/Windows interop, synthetic credentials."""
import http.server,json,pathlib,secrets,socket,subprocess,threading,time,signal,sys
from datetime import datetime,timedelta,timezone
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from interop import HTTP
from tools import install
root=pathlib.Path('.ci-fixture').resolve();root.mkdir(exist_ok=True)
stop=threading.Event()
for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,lambda *_:stop.set())
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
    route.connect(('192.168.68.116',22));host=route.getsockname()[0]
issued=datetime.now(timezone.utc)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-not_before',(issued-timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),'-not_after',(issued+timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-keyout','key.pem','-out','cert.pem'],cwd=root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
with socket.socket() as reserve:reserve.bind((host,0));port=reserve.getsockname()[1]
password=secrets.token_urlsafe(32)
(root/'vpn.toml').write_text(f'listen_address="{host}:{port}"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n[listen_protocols.quic]\n')
(root/'hosts.toml').write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
(root/'credentials.toml').write_text(f'[[client]]\nusername="interop"\npassword="{password}"\n')
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP)
threading.Thread(target=server.serve_forever,daemon=True).start()
# The endpoint connects to the first address "localhost" resolves to; a host
# with IPv6 routes (e.g. a VPN client) may list ::1 first. Serve both.
class HTTP6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
try:
    server6=HTTP6(('::1',server.server_port),HTTP)
    threading.Thread(target=server6.serve_forever,daemon=True).start()
except OSError:pass
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(.2)
def echo():
    while not stop.is_set():
        try:
            data,addr=udp.recvfrom(65535);udp.sendto(data,addr)
        except socket.timeout:pass
threading.Thread(target=echo,daemon=True).start()
endpoint=install('endpoint')
with (root/'endpoint.log').open('w') as log:
    process=subprocess.Popen([endpoint,'vpn.toml','hosts.toml','--jobs','2'],cwd=root,stdout=log,stderr=log)
    try:
        for _ in range(100):
            if process.poll() is not None:raise RuntimeError('Endpoint exited')
            try:
                with socket.create_connection((host,port),timeout=.2):break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('Endpoint unavailable')
        exported=subprocess.check_output([endpoint,'vpn.toml','hosts.toml','-c','interop','-a',f'{host}:{port}','--format','deeplink'],cwd=root,text=True)
        link=next(s.strip() for s in exported.splitlines() if s.strip().startswith('tt://'))
        data={'created_at':issued.isoformat(),'base':dict(hostname='localhost',addresses=[f'{host}:{port}'],username='interop',password=password,certificate=(root/'cert.pem').read_text()),'http_port':server.server_port,'udp':list(udp.getsockname()),'link':link}
        manifest=root/'client.json';manifest.write_text(json.dumps(data));manifest.chmod(0o600)
        (root/'ready').write_text('ready')
        deadline=time.monotonic()+1200
        while not stop.wait(.2) and time.monotonic()<deadline and not (root/'stop').exists():
            if process.poll() is not None:raise RuntimeError('Endpoint exited during test')
    finally:
        stop.set();process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        server.shutdown();server.server_close();udp.close()
        for name in ['key.pem','credentials.toml','client.json','ready']:(root/name).unlink(missing_ok=True)
