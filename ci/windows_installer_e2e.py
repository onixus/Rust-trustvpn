"""Verify the actual Setup.exe install/upgrade/uninstall lifecycle on an idle CI host."""
import os,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
APP=pathlib.Path(os.environ['ProgramFiles'])/'R-TrustTunnel'
SERVICE=pathlib.Path(os.environ['ProgramFiles'])/'RTrustTunnel Service'
REPORTS=ROOT/'reports';REPORTS.mkdir(exist_ok=True)
def ps(code):
    return subprocess.check_output(['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop'; "+code],text=True).strip()
def run(*args):subprocess.run([str(a) for a in args],check=True,timeout=150)
assert not APP.exists(),'Refusing to replace an existing user application'
assert not ps("if(Get-Service RTrustTunnel -ErrorAction SilentlyContinue){'exists'}"),'Existing service'
account=ps('[Security.Principal.WindowsIdentity]::GetCurrent().Name')
sid=ps('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value')
setup=ROOT/'dist/R-TrustTunnel-Windows-x64-Setup.exe'
try:
    failed=subprocess.run([str(setup),'/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/ACCOUNT=RTrustTunnel-Invalid-CI-Account','/LOG='+str(REPORTS/'windows-setup-rejected.log')],timeout=150)
    assert failed.returncode!=0,'Setup falsely reported success for invalid service account'
    assert not ps("if(Get-Service RTrustTunnel -ErrorAction SilentlyContinue){'exists'}")
    print('PASS Setup rejects invalid account with nonzero exit code',flush=True)
    for phase in ['install','upgrade']:
        run(setup,'/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/ACCOUNT='+account,'/LOG='+str(REPORTS/('windows-setup-'+phase+'.log')))
        assert (APP/'R-TrustTunnel.exe').is_file()
        assert ps('(Get-Service RTrustTunnel).Status')=='Running'
        assert sid in ps("(Get-CimInstance Win32_Service -Filter \"Name='RTrustTunnel'\").PathName")
        run(APP/'R-TrustTunnel.exe','--ci-smoke')
        run(SERVICE/'rtrust-service.exe','--wfp-self-test')
        print('PASS Setup '+phase+': native GUI smoke, SCM account, persistent WFP cleanup',flush=True)
finally:
    uninstaller=APP/'unins000.exe'
    if uninstaller.exists():
        run(uninstaller,'/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/LOG='+str(REPORTS/'windows-setup-remove.log'))
assert not ps("if(Get-Service RTrustTunnel -ErrorAction SilentlyContinue){'exists'}")
assert not SERVICE.exists(),'Protected service directory remains'
assert not (APP/'R-TrustTunnel.exe').exists(),'Application remains'
print('PASS Setup uninstall removes service and application')
