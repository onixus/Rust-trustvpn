"""Official endpoint in a disposable bridge; no Mac aliases or host route changes."""
import argparse,hashlib,json,os,pathlib,secrets,shutil,socket,subprocess,sys,tarfile,time
from datetime import datetime,timedelta,timezone
ROOT=pathlib.Path('.ci-wintun').resolve()
NAME='rtrust-wintun-'+secrets.token_hex(4)
# Not the Android fixture's 10.231.243.0/29: a Windows host that also serves the
# emulator keeps a persistent route for that subnet, which would bypass the tunnel.
IP='10.231.244.2';IP6='fd00:5254:244::2'
def run(*args,**kwargs):
    kwargs.setdefault('timeout',90)
    return subprocess.check_output(args,**kwargs).decode().strip()
def main():
    # "http3" is TrustTunnel over QUIC; "trusttunnel" keeps HTTP/2.
    parser=argparse.ArgumentParser();parser.add_argument('--protocol',choices=['trusttunnel','http3','amneziawg'],default='trusttunnel')
    protocol=parser.parse_args().protocol;amnezia=protocol=='amneziawg';http3=protocol=='http3'
    ROOT.mkdir(mode=0o700,exist_ok=True)
    for name in ['amneziawg.uapi','amneziawg-client.json','outage-seconds']:(ROOT/name).unlink(missing_ok=True)
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
    with socket.socket(type=socket.SOCK_DGRAM if amnezia else socket.SOCK_STREAM) as reserve:reserve.bind((host,0));port=reserve.getsockname()[1]
    with socket.socket() as reserve:reserve.bind((host,0));control_port=reserve.getsockname()[1]
    issued=datetime.now(timezone.utc)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-not_before',(issued-timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),'-not_after',(issued+timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-keyout','key.pem','-out','cert.pem'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    password=secrets.token_urlsafe(32)
    (ROOT/'vpn.toml').write_text('listen_address="0.0.0.0:4433"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n'+('[listen_protocols.quic]\n' if http3 else '')+'[icmp]\ninterface_name="eth0"\n')
    (ROOT/'hosts.toml').write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
    (ROOT/'credentials.toml').write_text(f'[[client]]\nusername="interop"\npassword="{password}"\n')
    if amnezia:
        # The official amneziawg-go device as a forwarding peer (ci/amneziawg_fixture),
        # built for this Docker host. Its keys are generated inside a container:
        # the binary is a Linux one and this script may run on macOS.
        sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
        from amneziawg_server import binary as build
        import platform
        shutil.copy2(build('arm64' if platform.machine() in ('arm64','aarch64') else 'amd64'),ROOT/'amneziawg')
        run('docker','run','--rm','--network','none','--user',f'{os.getuid()}:{os.getgid()}','-v',f'{ROOT}:/fixture','python:3.11-slim','/fixture/amneziawg','keygen','/fixture')
        # The service notices a silent WireGuard peer through unanswered traffic,
        # about 35 s into an outage.
        (ROOT/'outage-seconds').write_text('60')
    if http3:
        # QUIC has no reset to signal a dead endpoint: the service notices it
        # through its 5 s health check (10 s timeout) instead of at once.
        (ROOT/'outage-seconds').write_text('45')
    transport='udp' if amnezia else 'tcp'
    # HTTP/3 also publishes the TCP port: the drivers probe endpoint readiness
    # with an h2 TLS handshake.
    published=['-p',f'{host}:{port}:4433/{transport}']+(['-p',f'{host}:{port}:4433/udp'] if http3 else [])
    network=False;container=False
    try:
        run('docker','network','create','--subnet','10.231.244.0/29','--ipv6','--subnet','fd00:5254:244::/64',NAME);network=True
        run('docker','run','-d','--rm','--name',NAME,'--network',NAME,'--ip',IP,'--ip6',IP6,'-e','RTRUST_FIXTURE_IP='+IP,'-e','RTRUST_FIXTURE_IP6='+IP6,'-e','RTRUST_FIXTURE_VERBOSE='+os.environ.get('RTRUST_FIXTURE_VERBOSE',''),'-e','RTRUST_FIXTURE_FREEZE='+('1' if amnezia or http3 else ''),'--cap-drop=ALL','--cap-add=NET_RAW','--security-opt=no-new-privileges','--read-only','--tmpfs','/tmp',*published,'-v',f'{ROOT}:/fixture:ro','-p',f'{host}:{control_port}:8082/tcp','-v',f'{pathlib.Path("ci/windows_fixture_server.py").resolve()}:/server.py:ro','python:3.11-slim','python','/server.py');container=True
        for _ in range(150):
            try:
                with socket.create_connection((host,control_port if amnezia else port),timeout=.2):break
            except OSError:time.sleep(.2)
        else:raise RuntimeError('Windows endpoint fixture unavailable')
        data={'base':dict(hostname='localhost',addresses=[f'{host}:{port}'],username='interop',password=password,certificate=(ROOT/'cert.pem').read_text(),upstream_protocol='http3' if http3 else 'http2'),'target':IP,'target6':IP6,'control':f'http://{host}:{control_port}','control_token':token,'created_at':issued.isoformat()}
        if amnezia:
            profile=json.loads((ROOT/'amneziawg-client.json').read_text())
            profile['endpoint'].update(hostname=host,addresses=[f'{host}:{port}'])
            # "base" stays the endpoint for the address and secret checks of the drivers.
            data.update(protocol='amneziawg',profile=profile,base=profile['endpoint'])
        manifest=ROOT/'client.json';manifest.write_text(json.dumps(data));manifest.chmod(0o600)
        (ROOT/'ready').write_text('ready')
        until=time.monotonic()+900
        while time.monotonic()<until and not (ROOT/'stop').exists():time.sleep(.2)
    finally:
        if container:run('docker','rm','-f',NAME)
        if network:run('docker','network','rm',NAME)
        for name in ['key.pem','credentials.toml','client.json','control-token','ready','amneziawg.uapi','amneziawg-client.json']:(ROOT/name).unlink(missing_ok=True)
if __name__=='__main__':main()
