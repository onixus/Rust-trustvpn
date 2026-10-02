"""Runs as an isolated scheduled task: Jenkins may disconnect during full VPN."""
import json,os,pathlib,socket,ssl,subprocess,sys,time,urllib.request
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import windows_service_e2e as fixture
ROOT=pathlib.Path(__file__).resolve().parent
SERVICE=pathlib.Path(os.environ['ProgramFiles'])/'RTrustTunnel Service/rtrust-service.exe'
pipe=None
before=fixture.routes()
(ROOT/'routes-before.json').write_text(json.dumps(before))

def blocked(host,port):
    try:
        with socket.create_connection((host,port),timeout=2):pass
    except OSError:return
    raise AssertionError('Direct connection escaped WFP guard')
def start():
    global pipe
    pipe=fixture.Pipe()
    p=dict(schema_version=1,name='Full tunnel E2E',endpoint=fixture.FIXTURE['base'])
    response=pipe.request(dict(op='StartFull',profile=p,dns=fixture.TARGET))
    assert response['state']=='Connected',response

def recover():
    fixture.ps("Stop-Service RTrustTunnel -ErrorAction SilentlyContinue; (Get-Service RTrustTunnel).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(25))")
    subprocess.run([str(SERVICE),'--disable-always-on'],check=True,timeout=45)
    fixture.ps('Start-Service RTrustTunnel')

def adapter_diagnostics():
    # Capture the blocked state, not the already-cleaned state in finally.
    # Do not collect profile, policy, keys, or endpoint credentials.
    script=r"""
$ErrorActionPreference='Stop'
Get-CimInstance Win32_Service -Filter "Name='RTrustTunnel'" | Select-Object State,ProcessId | Format-List
Get-NetAdapter -IncludeHidden | Where-Object Name -eq RTrustTunnel | Select-Object Name,InterfaceGuid,InterfaceIndex,Status | Format-List
Get-PnpDevice -Class Net | Where-Object InstanceId -like 'SWD\WINTUN\*' | Select-Object Status,InstanceId,Problem | Format-List
$journal=Join-Path $env:ProgramFiles 'RTrustTunnel Service/full-state.json'
if(Test-Path $journal) { Get-Content $journal -Raw | ConvertFrom-Json | Select-Object version,adapter | Format-List }
"""
    try:
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=10)
        print('Wintun pending snapshot:',result.stdout,result.stderr,flush=True)
    except subprocess.TimeoutExpired:
        print('Wintun pending snapshot timed out',flush=True)

def main():
    global pipe
    host,port=fixture.FIXTURE['base']['addresses'][0].rsplit(':',1)
    from urllib.parse import urlsplit
    control=urlsplit(fixture.FIXTURE['control'])
    # Check direct path before the guard; it must be blocked while connected.
    old=socket.create_connection((host,control.port),timeout=5);old.settimeout(2)
    start()
    fixture.verify_traffic()
    assert socket.gethostbyname('rtrust-'+os.urandom(8).hex()+'.fixture.test')==fixture.TARGET
    print('PASS full tunnel: real system DNS and TCP/UDP',flush=True)
    blocked(host,control.port)
    try:
        old.sendall(b'GET / HTTP/1.0\r\n\r\n')
        assert not old.recv(256),'Pre-existing direct TCP escaped guard'
    except OSError:pass
    old.close()
    target6=fixture.FIXTURE['target6']
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f'http://[{target6}]:8080/',timeout=20) as response:
        assert response.read()==fixture.BODY
    with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as udp:
        udp.settimeout(15)
        for size in [1,1472,5000,60000]:
            body=os.urandom(size);udp.sendto(body,(target6,8081));data,_=udp.recvfrom(65535);assert data==body
    for address in [fixture.TARGET,target6]:
        subprocess.run(['ping.exe','-n','2','-w','4000','-l','5000',address],check=True,timeout=15)
    print('PASS IPv6 TCP/UDP fragmentation and dual-stack ICMP; direct endpoint traffic and old flows blocked',flush=True)
    # Pause/restart endpoint using its control port reached through the VPN itself.
    request=urllib.request.Request('http://'+fixture.TARGET+':8082/cycle',data=b'',headers={'Authorization':'Bearer '+fixture.FIXTURE['control_token']})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as r:assert r.status==204
    fixture.wait_state(pipe,'Blocked');blocked(host,control.port)
    fixture.wait_state(pipe,'Connected');fixture.verify_traffic()
    print('PASS endpoint outage keeps guard and reconnect restores traffic',flush=True)
    # A completed transport task must not be polled a second time on Stop.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as r:assert r.status==204
    fixture.wait_state(pipe,'Blocked')
    response=pipe.request(dict(op='Stop'));assert response['state']=='Idle',response
    pipe.close();pipe=None
    assert fixture.routes()==before,'Stop during reconnect changed original routes'
    resume=urllib.request.Request(fixture.FIXTURE['control']+'/resume',data=b'',headers={'Authorization':'Bearer '+fixture.FIXTURE['control_token']})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(resume,timeout=5) as r:assert r.status==204
    until=time.monotonic()+10
    tls=ssl.create_default_context(cadata=fixture.FIXTURE['base']['certificate'])
    tls.set_alpn_protocols(['h2'])
    while True:
        try:
            # Docker's published TCP port accepts connections before the
            # restarted endpoint is ready. Require its verified TLS handshake.
            with socket.create_connection((host,int(port)),timeout=1) as tcp:
                with tls.wrap_socket(tcp,server_hostname=fixture.FIXTURE['base']['hostname']):break
        except OSError:
            assert time.monotonic()<until,'Endpoint did not resume';time.sleep(.2)
    start();fixture.verify_traffic()
    print('PASS Stop while transport is down; no completed-task panic and exact route recovery',flush=True)
    # Abrupt GUI/IPC disconnect retains guard; only explicit recovery opens network.
    pipe.close();pipe=None;time.sleep(2);blocked(host,control.port)
    recovery=fixture.Pipe();assert recovery.request(dict(op='Recover'))['state']=='Idle';recovery.close()
    with socket.create_connection((host,control.port),timeout=5):pass
    assert fixture.routes()==before,'Routes changed after crash recovery'
    print('PASS GUI crash retains guard; explicit recovery restores original routes',flush=True)
    start()
    fixture.ps("$p=(Get-CimInstance Win32_Service -Filter \"Name='RTrustTunnel'\").ProcessId; Stop-Process -Id $p -Force")
    pipe.close();pipe=None;time.sleep(2);blocked(host,control.port)
    deadline=time.monotonic()+20
    while fixture.ps('(Get-Service RTrustTunnel).Status')!='Running':
        assert time.monotonic()<deadline,'SCM did not automatically restart crashed service'
        time.sleep(.5)
    blocked(host,control.port)
    recovery=fixture.Pipe();assert recovery.request(dict(op='Recover'))['state']=='Idle';recovery.close()
    assert fixture.routes()==before,'Routes changed after service crash recovery'
    print('PASS service SIGKILL/automatic SCM restart retains guard; explicit recovery restores routes',flush=True)
    start();assert pipe.request(dict(op='Stop'))['state']=='Idle';pipe.close();pipe=None
    assert fixture.routes()==before,'Stop failed to restore original routes'
    print('PASS Stop restores routes and DNS adapter removed',flush=True)
    def ipc(op,**values):
        p=fixture.Pipe()
        try:return p.request(dict(op=op,**values))
        finally:p.close()
    def connected():
        until=time.monotonic()+120
        previous=None
        snapshot_at=time.monotonic()+10
        while time.monotonic()<until:
            response=ipc('AlwaysOnStatus')
            if response!=previous:print(response,flush=True);previous=response
            if response['state']=='Connected':return
            if time.monotonic()>=snapshot_at:
                adapter_diagnostics()
                snapshot_at=float('inf')
            time.sleep(.5)
        raise AssertionError(response)
    p=dict(schema_version=1,name='Always-on E2E',endpoint=fixture.FIXTURE['base'])
    response=ipc('EnableAlwaysOn',profile=p,dns=fixture.TARGET);assert response['state']=='Blocked',response
    connected();fixture.verify_traffic()
    assert fixture.FIXTURE['base']['password'].encode() not in (SERVICE.parent/'always-on.rtrust').read_bytes()
    for op in ['PrepareUpdate','Recover']:
        assert ipc(op)['state']=='Error'
    cycles=fixture.FIXTURE.get('always_on_crash_cycles',1)
    assert type(cycles) is int and 1<=cycles<=3,'Invalid crash cycle count'
    for cycle in range(cycles):
        started=time.monotonic()
        fixture.ps("$p=(Get-CimInstance Win32_Service -Filter \"Name='RTrustTunnel'\").ProcessId; Stop-Process -Id $p -Force")
        time.sleep(1);blocked(host,control.port)
        until=time.monotonic()+30
        while fixture.ps('(Get-Service RTrustTunnel).Status')!='Running':
            assert time.monotonic()<until;time.sleep(.5)
        connected();fixture.verify_traffic()
        print(f'PASS always-on crash {cycle+1}/{cycles}: traffic restored in {time.monotonic()-started:.1f}s',flush=True)
    final_baseline=before
    alias=fixture.FIXTURE.get('network_handoff_alias')
    if alias:
        alias=alias.replace("'","''")
        fixture.ps(f"try {{ Disable-NetAdapter -Name '{alias}' -Confirm:$false; Start-Sleep -Seconds 8 }} finally {{ Enable-NetAdapter -Name '{alias}' -Confirm:$false }}")
        connected()
        until=time.monotonic()+90
        while True:
            try:fixture.http();break
            except Exception:
                if time.monotonic()>until:raise
                time.sleep(1)
        print('PASS physical network loss/restore with always-on guard and automatic traffic recovery',flush=True)
        # Link restart can legitimately change physical IPv6 addresses/routes.
        # Freeze the resulting physical table, excluding only journal-owned VPN
        # routes, then still require exact equality after disabling the VPN.
        fixture.ps(f"$until=(Get-Date).AddSeconds(15); while(Get-NetIPAddress -InterfaceAlias '{alias}' | Where-Object AddressState -eq Tentative) {{if((Get-Date) -gt $until){{throw 'Physical interface DAD timeout'}}; Start-Sleep -Milliseconds 200}}")
        indices=set(json.loads(fixture.ps("ConvertTo-Json -Compress -InputObject @(Get-NetIPInterface -InterfaceAlias RTrustTunnel | Select-Object -ExpandProperty InterfaceIndex -Unique)")))
        journal=json.loads((SERVICE.parent/'full-state.json').read_text())
        exceptions={(item['ip']+'/32',item['gateway'],'21076') for item in journal['routes']}
        def owned(row):
            prefix,index,gateway,metric=row.split('|')
            return int(index) in indices or (prefix,gateway,metric) in exceptions
        final_baseline=[row for row in fixture.routes() if not owned(row)]
        (ROOT/'routes-after-link-restart.json').write_text(json.dumps(final_baseline))

    response=ipc('DisableAlwaysOn');assert response['state']=='Idle',response
    after=fixture.routes();(ROOT/'routes-after-stop.json').write_text(json.dumps(after))
    assert after==final_baseline,dict(error='Always-on disable changed physical routes',removed=sorted(set(final_baseline)-set(after)),added=sorted(set(after)-set(final_baseline)))
    assert not (SERVICE.parent/'always-on.rtrust').exists()
    with socket.create_connection((host,control.port),timeout=5):pass
    print('PASS always-on encrypted policy, GUI-independent VPN, SCM crash/restart and explicit disable',flush=True)


result={'success':False}
try:
    main();result={'success':True}
except Exception as error:
    result={'success':False,'error':str(error)}
    import traceback;traceback.print_exc()
finally:
    if pipe is not None:pipe.close()
    try:recover()
    except Exception as error:result={'success':False,'error':'Recovery failed: '+str(error)}
    (ROOT/'result.json').write_text(json.dumps(result))
    print(json.dumps(result),flush=True)
if not result['success']:raise SystemExit(1)
