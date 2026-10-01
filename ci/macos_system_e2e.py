"""Authorized live Mac test. Driver always recovers the service and original VPN.
Requires an installed candidate and a separate temporary official endpoint.
Never run automatically from ordinary CI; Hiddify may be disconnected briefly.
"""
import argparse,contextlib,json,os,pathlib,socket,struct,subprocess,sys,threading,time,urllib.request
SOCKET='/private/var/run/rtrust/control.sock'
BODY=bytes(range(256))*2048
class Pipe:
    def __init__(self):
        self.lock=threading.Lock()
        self.socket=socket.socket(socket.AF_UNIX);self.socket.settimeout(45);self.socket.connect(SOCKET)
    def request(self,command):
        with self.lock:return self._request(command)
    def _request(self,command):
        data=json.dumps(dict(version=1,command=command)).encode()
        self.socket.sendall(struct.pack('!I',len(data))+data)
        def receive(n):
            data=b''
            while len(data)<n:
                part=self.socket.recv(n-len(data))
                if not part:raise RuntimeError('IPC closed')
                data+=part
            return data
        size=struct.unpack('!I',receive(4))[0]
        assert 0<size<=2*1024*1024
        return json.loads(receive(size))
    def close(self):self.socket.close()
@contextlib.contextmanager
def status_trace(pipe):
    stop=threading.Event()
    failures=[]
    def monitor():
        previous=None
        while not stop.wait(.25):
            try:
                response=pipe.request(dict(op='Status'))
                current=(response['state'],response.get('message'))
                if response['state']!='Connected':failures.append(current)
                if current!=previous:
                    print('Transport state during traffic: '+repr(current),flush=True)
                    previous=current
            except Exception as error:
                failures.append(type(error).__name__)
                print('Status monitor stopped: '+type(error).__name__,flush=True)
                return
    thread=threading.Thread(target=monitor,daemon=True);thread.start()
    try:yield
    finally:stop.set();thread.join(timeout=6)
    assert not failures, 'Unexpected transport reset during traffic: '+repr(failures[:3])
def recover():
    pipe=Pipe()
    try:
        response=pipe.request(dict(op='Recover'));assert response['state']=='Idle',response
    finally:pipe.close()
def traffic(data):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for target in (data['target'],'['+data['target6']+']'):
        with opener.open(f'http://{target}:8080/',timeout=15) as response:assert response.read()==BODY
        print(f'PASS TCP 512 KiB {target}',flush=True)
    for family,target in ((socket.AF_INET,data['target']),(socket.AF_INET6,data['target6'])):
        with socket.socket(family,socket.SOCK_DGRAM) as udp:
            udp.settimeout(10)
            # Darwin defaults to a 9216-byte UDP send buffer. Raise only this
            # test socket's buffers so 60 KB datagrams reach IP fragmentation.
            udp.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,128*1024)
            udp.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,128*1024)
            for size in (1,1472,5000,60000):
                body=os.urandom(size);udp.sendto(body,(target,8081));answer,_=udp.recvfrom(65535);assert answer==body
                print(f'PASS UDP {size} bytes {target}',flush=True)
    for command,target in (('/sbin/ping',data['target']),('/sbin/ping6',data['target6'])):
        for size in (56,5000):
            result=subprocess.run([command,'-n','-c','2','-s',str(size),target],capture_output=True,text=True,timeout=15)
            assert result.returncode==0, result.stdout+result.stderr
            print(f'PASS ICMP {size} bytes {target}',flush=True)
    assert socket.gethostbyname('rtrust-'+os.urandom(8).hex()+'.fixture.test')==data['target']
    print('PASS dual-stack TCP/UDP, 60 KB fragmentation and system DNS',flush=True)
def worker(path, original_vpn, service_crash=False):
    data=json.loads(pathlib.Path(path).read_text());pipe=Pipe()
    routes=subprocess.check_output(['/usr/sbin/netstat','-rn','-f','inet'],text=True)
    physical=[row.split()[3] for row in routes.splitlines() if row.startswith('default ') and 'I' not in row.split()[2]]
    assert len(physical)==1 and not physical[0].startswith('utun'), 'Physical default not ready: '+repr(physical)
    interface=socket.if_nametoindex(physical[0]);host=data['base']['addresses'][0].rsplit(':',1)[0]
    def direct():
        sock=socket.socket();sock.settimeout(2)
        try:
            sock.setsockopt(socket.IPPROTO_IP,25,interface) # Darwin IP_BOUND_IF
            sock.connect((host,22))
        finally:sock.close()
    direct() # Prove the bypass target was reachable before installing the guard.
    try:
        profile=dict(schema_version=1,name='macOS acceptance fixture',endpoint=data['base'])
        result=pipe.request(dict(op='StartFull',profile=profile,dns=data['target']))
        if result['state']!='Connected':
            routes=subprocess.check_output(['/usr/sbin/netstat','-rn','-f','inet'],text=True,timeout=5)
            print('Default routes after failed Start: '+repr([r for r in routes.splitlines() if r.startswith('default ')]),flush=True)
        assert result['state']=='Connected',result
        if os.environ.get('RTRUST_E2E_CAPTURE')=='1':time.sleep(2)
        with status_trace(pipe):traffic(data)
        try:direct()
        except OSError:pass
        else:raise AssertionError('Direct flow escaped guard')
        print('PASS direct physical traffic blocked',flush=True)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request=urllib.request.Request('http://'+data['target']+':8082/cycle',data=b'',headers={'Authorization':'Bearer '+data['control_token']})
        with status_trace(pipe):
            with opener.open(request,timeout=5) as response:assert response.status==204
        seen=False;deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            response=pipe.request(dict(op='Status'));state=response['state']
            if state=='Blocked' and not seen:print('Outage reason: '+response['message'],flush=True)
            if state=='Blocked':seen=True
            if seen and state=='Connected':break
            time.sleep(.5)
        else:raise AssertionError('Outage/reconnect not observed')
        with status_trace(pipe):traffic(data)
        result=pipe.request(dict(op='Stop'));assert result['state']=='Idle',result
        print('PASS transport outage, reconnect and explicit Stop',flush=True)
        direct()
        pipe.close();pipe=Pipe()
        result=pipe.request(dict(op='StartFull',profile=profile,dns=data['target']))
        assert result['state']=='Connected',result
        pipe.close() # Same lease loss as a crashed GUI process.
        time.sleep(.5)
        try:direct()
        except OSError:pass
        else:raise AssertionError('GUI crash released the network guard')
        recover();direct()
        assert subprocess.run(['/sbin/ifconfig','utun5254'],capture_output=True).returncode!=0
        print('PASS GUI/IPC crash retains guard; explicit recovery restores direct access and removes utun',flush=True)
        if service_crash:
            pipe=Pipe()
            result=pipe.request(dict(op='StartFull',profile=profile,dns=data['target']))
            assert result['state']=='Connected',result
            print('READY for authorized launchctl SIGKILL of org.rtrusttunnel.service',flush=True)
            pipe.socket.settimeout(60)
            assert pipe.socket.recv(1)==b'', 'Service must close IPC after SIGKILL'
            try:direct()
            except OSError:pass
            else:raise AssertionError('Service crash released the network guard')
            deadline=time.monotonic()+20
            while True:
                try:recover();break
                except (OSError,RuntimeError,AssertionError):
                    if time.monotonic()>deadline:raise
                    time.sleep(.25)
            direct()
            assert subprocess.run(['/sbin/ifconfig','utun5254'],capture_output=True).returncode!=0
            print('PASS service SIGKILL/restart retains guard; authorized recovery restores network',flush=True)
    except Exception:
        try:print('Service status at failure: '+repr(pipe.request(dict(op='Status'))),flush=True)
        except (OSError,RuntimeError):pass
        vpn_state=subprocess.check_output(['/usr/sbin/scutil','--nc','status',original_vpn],text=True,timeout=5).splitlines()[0]
        routes=subprocess.check_output(['/usr/sbin/netstat','-rn','-f','inet'],text=True,timeout=5)
        print('Original VPN at failure: '+vpn_state,flush=True)
        print('Default routes at failure: '+repr([r for r in routes.splitlines() if r.startswith('default ')]),flush=True)
        raise
    finally:pipe.close()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('fixture');parser.add_argument('--original-vpn',required=True);parser.add_argument('--worker',action='store_true');parser.add_argument('--service-crash',action='store_true',help='Wait for a separately authorized launchctl SIGKILL during the active tunnel');args=parser.parse_args()
    if args.worker:return worker(args.fixture,args.original_vpn,args.service_crash)
    fixture=json.loads(pathlib.Path(args.fixture).read_text())
    if 'expires_at' in fixture and fixture['expires_at']<time.time()+180:
        raise RuntimeError('Refresh the disposable endpoint before disconnecting the original VPN')
    # The independent driver survives child timeout/failure and restores VPN.
    try:
        subprocess.run(['/usr/sbin/scutil','--nc','stop',args.original_vpn],check=True,timeout=15)
        deadline=time.monotonic()+25
        while True:
            status=subprocess.check_output(['/usr/sbin/scutil','--nc','status',args.original_vpn],text=True,timeout=5).splitlines()[0]
            routes=subprocess.check_output(['/usr/sbin/netstat','-rn','-f','inet'],text=True,timeout=5)
            vpn_default=any(row.startswith('default ') and 'utun' in row for row in routes.splitlines())
            if status=='Disconnected' and not vpn_default:break
            if time.monotonic()>=deadline:raise RuntimeError('Original VPN did not disconnect: '+status)
            time.sleep(.25)
        subprocess.run([sys.executable,__file__,args.fixture,'--original-vpn',args.original_vpn,'--worker']+(['--service-crash'] if args.service_crash else []),check=True,timeout=220 if args.service_crash else 160)
    finally:
        try:recover()
        finally:
            subprocess.run(['/usr/sbin/scutil','--nc','start',args.original_vpn],check=True,timeout=20)
            print('Original VPN restart requested',flush=True)
if __name__=='__main__':main()
