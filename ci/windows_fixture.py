"""Official endpoint in a disposable bridge; no Mac aliases or host route changes."""
import hashlib,json,pathlib,secrets,socket,subprocess,tarfile,time
from datetime import datetime,timedelta,timezone
ROOT=pathlib.Path('.ci-wintun').resolve()
NAME='rtrust-wintun-'+secrets.token_hex(4)
IP='10.231.243.2'
def run(*args,**kwargs):
    kwargs.setdefault('timeout',90)
    return subprocess.check_output(args,**kwargs).decode().strip()
def main():
    ROOT.mkdir(mode=0o700,exist_ok=True)
    token=secrets.token_urlsafe(32)
    (ROOT/'control-token').write_text(token)
    cache=pathlib.Path('.ci-tools/linux-endpoint');cache.mkdir(parents=True,exist_ok=True)
    archive=cache/'endpoint.tar.gz'
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest()!='c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686':
        run('curl','-fLsS','--connect-timeout','15','--max-time','80','--retry','1','https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-aarch64.tar.gz','-o',str(archive),timeout=180)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!='c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686':raise RuntimeError('Endpoint checksum mismatch')
    with tarfile.open(archive) as tar:
        member=next(m for m in tar if m.name.endswith('/trusttunnel_endpoint'))
        binary=ROOT/'trusttunnel_endpoint';binary.write_bytes(tar.extractfile(member).read());binary.chmod(0o755)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
        route.connect(('192.168.68.116',22));host=route.getsockname()[0]
    with socket.socket() as reserve:reserve.bind((host,0));port=reserve.getsockname()[1]
    with socket.socket() as reserve:reserve.bind((host,0));control_port=reserve.getsockname()[1]
    issued=datetime.now(timezone.utc)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-not_before',(issued-timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),'-not_after',(issued+timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-keyout','key.pem','-out','cert.pem'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    password=secrets.token_urlsafe(32)
    (ROOT/'vpn.toml').write_text('listen_address="0.0.0.0:4433"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n[icmp]\ninterface_name="eth0"\n')
    (ROOT/'hosts.toml').write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
    (ROOT/'credentials.toml').write_text(f'[[client]]\nusername="interop"\npassword="{password}"\n')
    network=False;container=False
    try:
        run('docker','network','create','--subnet','10.231.243.0/29','--ipv6','--subnet','fd00:5254:243::/64',NAME);network=True
        run('docker','run','-d','--rm','--name',NAME,'--network',NAME,'--ip',IP,'--ip6','fd00:5254:243::2','--cap-drop=ALL','--cap-add=NET_RAW','--security-opt=no-new-privileges','--read-only','--tmpfs','/tmp','-p',f'{host}:{port}:4433/tcp','-v',f'{ROOT}:/fixture:ro','-p',f'{host}:{control_port}:8082/tcp','-v',f'{pathlib.Path("ci/windows_fixture_server.py").resolve()}:/server.py:ro','python:3.11-slim','python','/server.py');container=True
        for _ in range(150):
            try:
                with socket.create_connection((host,port),timeout=.2):break
            except OSError:time.sleep(.2)
        else:raise RuntimeError('Windows endpoint fixture unavailable')
        data={'base':dict(hostname='localhost',addresses=[f'{host}:{port}'],username='interop',password=password,certificate=(ROOT/'cert.pem').read_text(),upstream_protocol='http2'),'target':IP,'target6':'fd00:5254:243::2','control':f'http://{host}:{control_port}','control_token':token,'created_at':issued.isoformat()}
        manifest=ROOT/'client.json';manifest.write_text(json.dumps(data));manifest.chmod(0o600)
        (ROOT/'ready').write_text('ready')
        until=time.monotonic()+900
        while time.monotonic()<until and not (ROOT/'stop').exists():time.sleep(.2)
    finally:
        if container:run('docker','rm','-f',NAME)
        if network:run('docker','network','rm',NAME)
        for name in ['key.pem','credentials.toml','client.json','control-token','ready']:(ROOT/name).unlink(missing_ok=True)
if __name__=='__main__':main()
