"""Admin CI driver. Protected SYSTEM task + independent timed recovery task.
Only use on an explicitly authorized host with other VPNs disconnected.
"""
import json,os,pathlib,shutil,subprocess,sys,time,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
WORK=pathlib.Path(os.environ['ProgramData'])/('RTrustTunnel-CI-'+uuid.uuid4().hex)
TASK=WORK.name
SERVICE=pathlib.Path(os.environ['ProgramFiles'])/'RTrustTunnel Service/rtrust-service.exe'
REPORTS=ROOT/'reports';REPORTS.mkdir(exist_ok=True)
def ps(code):
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "+code],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
    if result.returncode:raise RuntimeError(result.stdout+result.stderr)
    return result.stdout.strip()
def command(*args):subprocess.run(args,check=True,timeout=90)
if ps("if (Get-Service RTrustTunnel -ErrorAction SilentlyContinue) { 'exists' }"):raise SystemExit('Refusing to replace an existing VPN service')
ps(f"New-Item '{WORK}' -ItemType Directory | Out-Null; $acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'); Set-Acl '{WORK}' $acl")
installed=False;cleanup=False
try:
    runtime=WORK/'python';runtime.mkdir()
    base=pathlib.Path(sys.base_prefix)
    for p in base.iterdir():
        if p.is_file() and (p.name=='python.exe' or p.suffix.lower()=='.dll'):shutil.copy2(p,runtime/p.name)
    for name in ['Lib','DLLs']:
        shutil.copytree(base/name,runtime/name,ignore=shutil.ignore_patterns('site-packages','__pycache__','test','tests','idlelib','ensurepip','tkinter'))
    python=runtime/'python.exe'
    command(str(python),'-I','-c','import ctypes,http.server,socket,json')
    shutil.copytree(ROOT/'dist/native-preview-windows',WORK/'payload')
    shutil.copy2(ROOT/'scripts/install-windows-service.ps1',WORK/'payload/install-windows-service.ps1')
    for name in ['windows_full_e2e.py','windows_service_e2e.py']:shutil.copy2(ROOT/'ci'/name,WORK/name)
    shutil.copy2(sys.argv[1],WORK/'fixture.json')
    sid=ps('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value')
    installer=WORK/'payload/install-windows-service.ps1'
    command('powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(installer),'-Source',str(WORK/'payload'),'-AllowedSid',sid)
    installed=True
    # Prove recovery API on a harmless reserved-address canary before full mode.
    command(str(SERVICE),'--wfp-self-test')
    (WORK/'run.ps1').write_text(f"$PSDefaultParameterValues['Out-File:Encoding']='utf8'\n& '{python}' -I '{WORK/'windows_full_e2e.py'}' '{WORK/'fixture.json'}' *> '{WORK/'worker.log'}'\n",encoding='utf-8-sig')
    (WORK/'recover.ps1').write_text(f"$ErrorActionPreference='Continue'\nStop-Service RTrustTunnel -ErrorAction SilentlyContinue\n(Get-Service RTrustTunnel).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))\n& '{SERVICE}' --recover\n",encoding='utf-8-sig')
    ps(f"$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $s=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5); $a=New-ScheduledTaskAction -Execute \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{WORK/'recover.ps1'}\"'; $t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(4); Register-ScheduledTask -TaskName '{TASK}-recovery' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null; $a=New-ScheduledTaskAction -Execute \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{WORK/'run.ps1'}\"'; Register-ScheduledTask -TaskName '{TASK}' -Action $a -Principal $p -Settings $s -Force | Out-Null; Start-ScheduledTask -TaskName '{TASK}'")
    print('Full-tunnel task started; independent 4-minute network recovery armed.',flush=True)
    deadline=time.monotonic()+300
    while time.monotonic()<deadline:
        if (WORK/'result.json').exists():break
        time.sleep(1)
    else:raise TimeoutError('Full tunnel E2E did not complete; timed recovery remains armed')
    time.sleep(2)
    result=json.loads((WORK/'result.json').read_text())
    print((WORK/'worker.log').read_text(encoding='utf-8-sig',errors='replace'),flush=True)
    (REPORTS/'windows-full-result.json').write_text(json.dumps(result))
    assert result['success'],result
finally:
    if (WORK/'worker.log').exists():shutil.copy2(WORK/'worker.log',REPORTS/'windows-full-worker.log')
    if installed:
        command('powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(WORK/'payload/install-windows-service.ps1'),'-Action','Remove')
    cleanup=True
    for name in (TASK,TASK+'-recovery'):
        ps(f"if(Get-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue){{Stop-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false}}")
    shutil.rmtree(WORK)
print('PASS full-tunnel scheduled task, uninstall and independent watchdog cleanup')
