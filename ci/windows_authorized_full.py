"""Opt-in maintenance E2E on the user's idle installation, with timed rollback.
Never called by ordinary CI. Preserves GUI, vault, SCM identity and original service.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, time, uuid
p=argparse.ArgumentParser();p.add_argument('fixture',type=pathlib.Path);p.add_argument('--allow-existing-installation',action='store_true');p.add_argument('--service-sha256',required=True);p.add_argument('--crash-cycles',type=int,choices=range(1,4),default=1)
# windows_production_e2e.py runs the same rollback-guarded flow with production profiles.
p.add_argument('--worker',choices=['windows_full_e2e.py','windows_production_e2e.py','windows_sleep_e2e.py'],default='windows_full_e2e.py')
# windows_sleep_e2e.py suspends the host; worker and rollback deadlines include the sleep.
p.add_argument('--sleep-minutes',type=int,choices=range(1,121),default=None);a=p.parse_args()
assert (a.worker=='windows_sleep_e2e.py')==(a.sleep_minutes is not None),'--sleep-minutes is required by, and only valid for, the sleep worker'
assert a.allow_existing_installation,'Explicit authorization required'
sys.stdout.reconfigure(encoding='utf-8',errors='replace')
sys.stderr.reconfigure(encoding='utf-8',errors='replace')
ROOT=pathlib.Path(__file__).resolve().parents[1]
SERVICE=pathlib.Path(os.environ['ProgramFiles'])/'RTrustTunnel Service'
SOURCE=ROOT/'dist/native-preview-windows/rtrust-service.exe'
WORK=pathlib.Path(os.environ['ProgramData'])/('RTrustTunnel-E2E-'+uuid.uuid4().hex)
TASK=WORK.name
# Each additional crash gets the same bounded SCM/reconnect allowance.
worker_minutes=5+3*(a.crash_cycles-1)+((a.sleep_minutes or 0)+10 if a.sleep_minutes else 0)
rollback_minutes=worker_minutes+1

def ps(code):
    r=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop'; "+code],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
    if r.returncode:raise RuntimeError(r.stdout+r.stderr)
    return r.stdout.strip()
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(*args):subprocess.run(list(map(str,args)),check=True,timeout=120)
binary=SOURCE.read_bytes()
assert hashlib.sha256(binary).hexdigest()==a.service_sha256,'Source does not match reviewed CI artifact'
assert not ps("if(Get-Process R-TrustTunnel -ErrorAction SilentlyContinue){'running'}"),'Close GUI before maintenance'
assert ps('(Get-Service RTrustTunnel).Status')=='Running'
for name in ['full-state.json','always-on.rtrust','always-on.key']:
    assert not (SERVICE/name).exists(),'Refusing an existing VPN policy or recovery journal'
original={name:digest(SERVICE/name) for name in ['rtrust-service.exe','wintun.dll']}
scm=ps("(Get-CimInstance Win32_Service -Filter \"Name='RTrustTunnel'\").PathName")
# Use the real authenticated client to prove that no live service lease exists.
# The maintenance connection is closed before SCM stop; the GUI is closed above.
sys.path.insert(0,str(ROOT/'ci'))
sys.argv[1]=str(a.fixture)
import windows_service_e2e as fixture
permit=fixture.Pipe()
try:
    response=permit.request(dict(op='PrepareUpdate'));assert response['state']=='Idle',response
finally:permit.close()
ps(f"New-Item '{WORK}' -ItemType Directory | Out-Null; $acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'); Set-Acl '{WORK}' $acl")
backup=WORK/'before';backup.mkdir()
for name in original:shutil.copy2(SERVICE/name,backup/name)
(WORK/'original.json').write_text(json.dumps(dict(hashes=original,scm=scm)))
runtime=WORK/'python';runtime.mkdir();base=pathlib.Path(sys.base_prefix)
for item in base.iterdir():
    if item.is_file() and (item.name=='python.exe' or item.suffix.lower()=='.dll'):shutil.copy2(item,runtime/item.name)
for name in ['Lib','DLLs']:
    shutil.copytree(base/name,runtime/name,ignore=shutil.ignore_patterns('site-packages','__pycache__','test','tests','idlelib','ensurepip','tkinter'))
for name in [a.worker,'windows_service_e2e.py']:shutil.copy2(ROOT/'ci'/name,WORK/name)
fixture_data=json.loads(a.fixture.read_text())
physical=json.loads(ps("ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -Physical | Where-Object Status -eq Up | Select-Object -ExpandProperty Name)"))
assert len(physical)==1,'Handoff test requires one known active physical adapter'
fixture_data['network_handoff_alias']=physical[0]
fixture_data['always_on_crash_cycles']=a.crash_cycles
if a.sleep_minutes:fixture_data['sleep_minutes']=a.sleep_minutes
(WORK/'fixture.json').write_text(json.dumps(fixture_data))
adapter=physical[0].replace("'","''")
# Recovery is independent of Python/Jenkins and survives network loss.
recovery=f"""$ErrorActionPreference='Stop'
Enable-NetAdapter -Name '{adapter}' -Confirm:$false
Stop-Service RTrustTunnel -ErrorAction SilentlyContinue
(Get-Service RTrustTunnel).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
for ($attempt=0; $attempt -lt 4; $attempt++) {{
 & '{SERVICE/'rtrust-service.exe'}' --recover
 if ($LASTEXITCODE) {{ & '{SERVICE/'rtrust-service.exe'}' --disable-always-on }}
 if (-not $LASTEXITCODE) {{ break }}
 Start-Sleep -Seconds 5
}}
if ($LASTEXITCODE) {{ throw 'Network recovery failed; retain new service and backup' }}
Copy-Item '{backup/'rtrust-service.exe'}' '{SERVICE/'rtrust-service.exe'}' -Force
Remove-Item '{SERVICE/'always-on.key'}' -ErrorAction SilentlyContinue
Start-Service RTrustTunnel
'RESTORED' | Set-Content '{WORK/'recovered'}'
"""
(WORK/'recover.ps1').write_text(recovery,encoding='utf-8-sig')
(WORK/'run.ps1').write_text(f"$PSDefaultParameterValues['Out-File:Encoding']='utf8'; [Console]::OutputEncoding=[Text.Encoding]::UTF8\n& '{runtime/'python.exe'}' -X utf8 -I '{WORK/a.worker}' '{WORK/'fixture.json'}' *> '{WORK/'worker.log'}'\n",encoding='utf-8-sig')
armed=False;changed=False
try:
    ps(f"$p=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest; $s=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 8); $a=New-ScheduledTaskAction -Execute \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{WORK/'recover.ps1'}\"'; $t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes({rollback_minutes}); Register-ScheduledTask -TaskName '{TASK}-recovery' -Principal $p -Action $a -Trigger $t -Settings $s | Out-Null")
    armed=True
    ps("Stop-Service RTrustTunnel; (Get-Service RTrustTunnel).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))")
    (SERVICE/'rtrust-service.exe').write_bytes(binary);changed=True
    run(SERVICE/'rtrust-service.exe','--wfp-self-test')
    ps('Start-Service RTrustTunnel')
    ps(f"$p=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest; $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes {worker_minutes}); $a=New-ScheduledTaskAction -Execute \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{WORK/'run.ps1'}\"'; Register-ScheduledTask -TaskName '{TASK}' -Principal $p -Action $a -Settings $s | Out-Null; Start-ScheduledTask -TaskName '{TASK}'")
    print(f'E2E running with independent {rollback_minutes}-minute service/network rollback: '+str(WORK),flush=True)
    deadline=time.monotonic()+worker_minutes*60+10
    while time.monotonic()<deadline and not (WORK/'result.json').exists():time.sleep(1)
    assert (WORK/'result.json').exists(),'E2E timeout; timed recovery remains armed'
    result=json.loads((WORK/'result.json').read_text())
    print((WORK/'worker.log').read_text(encoding='utf-8-sig',errors='replace'),flush=True)
    assert result['success'],result
finally:
    ps(f"if(Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue){{Stop-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue}}")
    restored=False
    if changed:
        run('powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',WORK/'recover.ps1')
        restored=True
    else:
        ps('Start-Service RTrustTunnel');restored=True
    if restored:
        assert {name:digest(SERVICE/name) for name in original}==original
        assert ps("(Get-CimInstance Win32_Service -Filter \"Name='RTrustTunnel'\").PathName")==scm
        for name in [TASK,TASK+'-recovery']:
            ps(f"if(Get-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue){{Stop-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false}}")
        (WORK/'fixture.json').unlink(missing_ok=True)
        print('Original service hashes, SCM identity and running state restored. Evidence: '+str(WORK),flush=True)
