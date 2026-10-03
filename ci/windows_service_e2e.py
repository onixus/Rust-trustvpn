"""SCM install → authenticated IPC → real Wintun TCP/UDP → Stop/EOF → uninstall.
Touches only RTrustTunnel service and fixture /32; refuses an existing service.
"""
import concurrent.futures,ctypes,json,os,pathlib,socket,struct,subprocess,sys,time,urllib.request
from ctypes import wintypes as W
ROOT=pathlib.Path(__file__).resolve().parents[1]
FIXTURE=json.loads(pathlib.Path(sys.argv[1]).read_text())
TARGET=FIXTURE['target'];NETWORK=TARGET+'/32'
BODY=bytes(range(256))*2048
K=ctypes.WinDLL('kernel32',use_last_error=True)
K.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE];K.CreateFileW.restype=W.HANDLE
K.ReadFile.argtypes=[W.HANDLE,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
K.WriteFile.argtypes=K.ReadFile.argtypes
K.CloseHandle.argtypes=[W.HANDLE]
K.PeekNamedPipe.argtypes=[W.HANDLE,ctypes.c_void_p,W.DWORD,ctypes.c_void_p,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
def ps(code):
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop'; "+code],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    if p.returncode:raise RuntimeError(p.stdout+p.stderr)
    return p.stdout.strip()
def routes():return json.loads(ps("ConvertTo-Json -Compress -InputObject @(Get-NetRoute | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.DestinationPrefix,$_.InterfaceIndex,$_.NextHop,$_.RouteMetric } | Sort-Object)"))
class Pipe:
    def __init__(self):
        self.handle=K.CreateFileW(r'\\.\pipe\RTrustTunnel.Control.v1',0x12019b,0,None,3,0x00110000,None)
        if self.handle==W.HANDLE(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    def close(self):
        if self.handle is not None:K.CloseHandle(self.handle);self.handle=None
    def read(self,n):
        result=b'';until=time.monotonic()+45
        while len(result)<n:
            available=W.DWORD()
            if not K.PeekNamedPipe(self.handle,None,0,None,ctypes.byref(available),None):raise ctypes.WinError(ctypes.get_last_error())
            if not available.value:
                if time.monotonic()>until:raise TimeoutError('IPC response timeout')
                time.sleep(.02);continue
            buffer=ctypes.create_string_buffer(min(n-len(result),available.value));count=W.DWORD()
            if not K.ReadFile(self.handle,buffer,len(buffer),ctypes.byref(count),None):raise ctypes.WinError(ctypes.get_last_error())
            result+=buffer.raw[:count.value]
        return result
    def request(self,command,version=1):
        data=json.dumps(dict(version=version,command=command)).encode();frame=struct.pack('>I',len(data))+data;count=W.DWORD()
        if not K.WriteFile(self.handle,frame,len(frame),ctypes.byref(count),None):raise ctypes.WinError(ctypes.get_last_error())
        assert count.value==len(frame)
        length=struct.unpack('>I',self.read(4))[0];assert 0<length<=2*1024*1024
        return json.loads(self.read(length))
def start(pipe,networks=None,base=None):
    profile=dict(schema_version=1,name='Wintun E2E',endpoint=base or FIXTURE['base'])
    return pipe.request(dict(op='Start',profile=profile,networks=networks or [NETWORK]))
def http():
    # Explicitly bypass proxy environment: traffic must go through Windows IP routing.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f'http://{TARGET}:8080/',timeout=30) as response:assert response.read()==BODY

def verify_traffic():
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda _:http(),range(8)))
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.settimeout(10)
        for size in [1,512,1472]:
            body=os.urandom(size);udp.sendto(body,(TARGET,8081));data,peer=udp.recvfrom(65535);assert data==body and peer==(TARGET,8081)
    print('PASS Wintun: 8 x 512KiB TCP + UDP 1/512/1472, direct OS sockets')
def control(action):
    req=urllib.request.Request(FIXTURE['control']+'/'+action,data=b'',headers={'Authorization':'Bearer '+FIXTURE['control_token']})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=10) as response:assert response.status==204

def wait_state(pipe,state,timeout=60):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        response=pipe.request(dict(op='Status'))
        if response['state']==state:return
        time.sleep(.5)
    raise TimeoutError('Service did not reach '+state+'; last status: '+repr((response['state'],response.get('message'))))

def no_routes():
    for _ in range(60):
        if not any(NETWORK in r for r in routes()):return
        time.sleep(.25)
    raise AssertionError('Fixture route remains after disconnect')

def main():
    if ps("if (Get-Service RTrustTunnel -ErrorAction SilentlyContinue) { 'exists' }"):raise RuntimeError('Refusing to replace an existing RTrustTunnel service')
    before=routes();pipe=None;installed=False
    source=ROOT/'dist/native-preview-windows';installer=source/'install-windows-service.ps1'
    try:
        installed=True
        subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(installer),'-Source',str(source)],check=True,timeout=90)
        environment=dict(os.environ,RTRUST_INSTALLED_SERVICE_TEST='1',RUSTUP_TOOLCHAIN='1.98.1')
        subprocess.run([str(pathlib.Path.home()/'.cargo/bin/cargo.exe'),'test','-p','rtrust-control','--test','windows_access','--locked','--','--nocapture'],env=environment,check=True,timeout=120)
        pipe=Pipe()
        assert pipe.request(dict(op='Status'),version=99)['state']=='Error';pipe.close()
        pipe=Pipe();assert start(pipe,['0.0.0.0/0'])['state']=='Error';pipe.close()
        pipe=Pipe();bad=dict(FIXTURE['base'],password='wrong');assert start(pipe,base=bad)['state']=='Error';pipe.close()
        assert not any(NETWORK in r for r in routes())
        pipe=Pipe();answer=start(pipe);assert answer['state']=='Connected',answer
        another=Pipe();assert start(another)['state']=='Error';another.close()
        try:verify_traffic()
        except Exception:
            print(ps("Get-NetIPAddress -InterfaceAlias RTrustTunnel | Select-Object IPAddress,AddressState,SkipAsSource | ConvertTo-Json -Compress"),flush=True)
            print(ps("Get-NetAdapter -Name RTrustTunnel | Select-Object Name,Status,InterfaceIndex | ConvertTo-Json -Compress"),flush=True)
            raise
        assert pipe.request(dict(op='Status'))['state']=='Connected'
        control('pause');wait_state(pipe,'Blocked')
        assert any(NETWORK in r for r in routes()),'Reconnect lost the Wintun route'
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f'http://{TARGET}:8080/',timeout=2)
        except (OSError,TimeoutError):pass
        else:raise AssertionError('Traffic succeeded during endpoint outage')
        control('resume');wait_state(pipe,'Connected');http()
        print('PASS endpoint outage, held Wintun route, automatic reconnect and real TCP recovery')
        assert pipe.request(dict(op='Stop'))['state']=='Idle';pipe.close();pipe=None
        no_routes();print('PASS authenticated IPC, version/network/auth rejection, exclusive lease, Stop cleanup')
        subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(installer),'-Source',str(source)],check=True,timeout=90)
        print('PASS service upgrade/reinstall')
        # Exercise the exact Rust IPC client used by the native UI, then process death.
        profile=ROOT/'.ci-wintun/client-profile.json';profile.write_text(json.dumps(FIXTURE['base']))
        client=subprocess.Popen([str(ROOT/'target/release/rtrust-inspect.exe'),str(profile),'--serve-tun',NETWORK],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
        try:
            until=time.monotonic()+45
            import queue,threading
            lines=queue.Queue()
            threading.Thread(target=lambda:[lines.put(line.strip()) for line in client.stdout],daemon=True).start()
            while time.monotonic()<until:
                if client.poll() is not None:raise RuntimeError('Rust IPC client exited: '+client.stderr.read())
                try:
                    if lines.get(timeout=.2)=='SERVICE connected':break
                except queue.Empty:pass
            else:raise TimeoutError('Rust IPC start timeout')
            http()
        finally:
            client.kill();client.wait(timeout=10);client.stdout.close();client.stderr.close();profile.unlink(missing_ok=True)
        no_routes();print('PASS native Rust IPC client, GUI-process death releases routes')
        pipe=Pipe();assert start(pipe)['state']=='Connected';http()
        ps('Stop-Service RTrustTunnel');pipe.close();pipe=None
        no_routes();print('PASS SCM Stop during active tunnel')
    finally:
        try:control('resume')
        except Exception:pass
        if pipe:pipe.close()
        if installed:
            subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(installer),'-Action','Remove'],check=True,timeout=90)
    after=routes()
    assert before==after,'Windows route table did not return to its original state'
    print('PASS install/uninstall lifecycle; original routes and existing VPN preserved')
if __name__=='__main__':main()
