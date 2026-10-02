"""Authorized physical Windows acceptance using disposable production profiles.
Runs as SYSTEM with the existing maintenance driver's independent recovery task.
Never pauses/restarts a production endpoint or changes any production route.

Run through windows_authorized_full.py --worker windows_production_e2e.py.
The fixture JSON (never committed) holds "target" for the shared helpers and
"profiles": disposable production profiles. Name resolution is left to the
system on purpose: on a dual-stack host this exercises IPv6, including the
local IPv4 fallback for endpoints without IPv6 (has_ipv6=false).
"""
import json,os,pathlib,socket,struct,subprocess,sys,time,urllib.request
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import windows_service_e2e as fixture
ROOT=pathlib.Path(__file__).resolve().parent
SERVICE=pathlib.Path(os.environ['ProgramFiles'])/'RTrustTunnel Service/rtrust-service.exe'
pipe=None
before=fixture.routes()
checks=[]
def blocked(host,port):
    try:
        with socket.create_connection((host,port),timeout=2):pass
    except OSError:return
    raise AssertionError('Application escaped WFP endpoint protection')
def recover():
    fixture.ps("Stop-Service RTrustTunnel -ErrorAction SilentlyContinue; (Get-Service RTrustTunnel).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(25))")
    subprocess.run([str(SERVICE),'--disable-always-on'],check=True,timeout=45)
    fixture.ps('Start-Service RTrustTunnel')
def traffic(protocol):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url,status in [('https://www.google.com/generate_204',204),('https://example.com/',200),('https://api.ipify.org/',200)]:
        print('Checking '+protocol+' '+url,flush=True)
        print('DNS addresses: '+str(sorted({a[4][0] for a in socket.getaddrinfo(url.split('/')[2],443,type=socket.SOCK_STREAM)})),flush=True)
        with opener.open(url,timeout=25) as r:
            assert r.status==status,(protocol,status,r.status)
            data=r.read(65536)
            if 'ipify' in url:
                address=data.decode().strip();socket.inet_aton(address);print('Production '+protocol+' egress: '+address,flush=True)
    socket.getaddrinfo('www.google.com',443)
    tx=os.urandom(2);question=b''.join(bytes([len(s)])+s.encode() for s in 'www.google.com'.split('.'))+b'\0'+struct.pack('!HH',1,1)
    packet=tx+struct.pack('!HHHHH',0x0100,1,0,0,0)+question
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.settimeout(15);udp.sendto(packet,('1.1.1.1',53));response,peer=udp.recvfrom(4096)
        assert peer==('1.1.1.1',53) and response[:2]==tx and len(response)>=12
        assert struct.unpack('!H',response[6:8])[0]>0 and response[3]&15==0
    print('PASS production '+protocol+': verified TLS Google/example, system DNS and UDP DNS',flush=True)
def main():
    global pipe
    for profile in fixture.FIXTURE['profiles']:
        protocol=profile.get('protocol','trusttunnel');host=profile['endpoint']['addresses'][0].rsplit(':',1)[0]
        # The endpoint IP has a physical bypass route. Only the VPN service can
        # use it while the guard is active; ordinary application sockets cannot.
        canary=8443
        with socket.create_connection((host,canary),timeout=10):pass
        pipe=fixture.Pipe();answer=pipe.request(dict(op='StartFull',profile=profile,dns='1.1.1.1'))
        assert answer['state']=='Connected',{'protocol':protocol,'state':answer['state']}
        traffic(protocol);blocked(host,canary)
        # Abrupt UI/IPC death must retain the guard until explicit recovery.
        pipe.close();pipe=None;time.sleep(2);blocked(host,canary)
        p=fixture.Pipe();assert p.request(dict(op='Recover'))['state']=='Idle';p.close()
        assert fixture.routes()==before,'Production profile recovery changed baseline routes'
        with socket.create_connection((host,canary),timeout=10):pass
        print('PASS production '+protocol+': WFP guard, IPC death fail-closed and exact recovery',flush=True)
        checks.append(protocol)
result={'success':False}
try:
    main();result={'success':True,'protocols':checks}
except Exception as e:
    import traceback;traceback.print_exc();result={'success':False,'error':str(e),'completed_protocols':checks}
finally:
    if pipe is not None:pipe.close()
    try:recover()
    except Exception as e:result={'success':False,'error':'Recovery failed: '+str(e)}
    (ROOT/'result.json').write_text(json.dumps(result));print(json.dumps(result),flush=True)
if not result['success']:raise SystemExit(1)
