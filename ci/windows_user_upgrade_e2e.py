"""Explicitly authorized maintenance of an existing user installation.
Run manually with --allow-existing-installation; never part of unattended CI.
Leaves the latest client installed. Does not connect VPN or write a profile vault.
"""
import argparse, datetime, hashlib, json, os, pathlib, shutil, subprocess, winreg
p=argparse.ArgumentParser();p.add_argument('--allow-existing-installation',action='store_true');args=p.parse_args()
assert args.allow_existing_installation,'Explicit existing-installation authorization required'
ROOT=pathlib.Path(__file__).resolve().parents[1]
APP=pathlib.Path(os.environ['ProgramFiles'])/'R-TrustTunnel'
DATA=pathlib.Path(os.environ['LOCALAPPDATA'])/'RTrustTunnel'/'RTrustTunnel'/'data'
SETUP=pathlib.Path(os.environ['USERPROFILE'])/'Downloads/R-TrustTunnel-Windows-x64-Setup.exe'
EXPECTED='4c2f9a30fccdde83915eb70d1c47423e178e0a97b4170bc5667fcebadfde11c2'
BACKUP=SETUP.parent/('RTrustTunnel-maintenance-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
RUN=r'Software\Microsoft\Windows\CurrentVersion\Run'
def ps(code):
    return subprocess.check_output(['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop'; "+code],text=True,encoding='utf-8',errors='replace',timeout=45).strip()
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def manifest(path):return {str(f.relative_to(path)):digest(f) for f in path.rglob('*') if f.is_file()} if path.exists() else {}
def run(*cmd):subprocess.run(list(map(str,cmd)),check=True,timeout=180)
def startup():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,RUN) as key:return winreg.QueryValueEx(key,'RTrustTunnel')
    except FileNotFoundError:return None
def restore_startup(value):
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,RUN) as key:
        if value is not None:winreg.SetValueEx(key,'RTrustTunnel',0,value[1],value[0])
        else:
            try:winreg.DeleteValue(key,'RTrustTunnel')
            except FileNotFoundError:pass
assert digest(SETUP)==EXPECTED,'Unexpected installer; use verified build 32'
assert APP.is_dir(),'Expected existing installation'
assert not ps("if(Get-Process R-TrustTunnel -ErrorAction SilentlyContinue){'running'}"),'Close client before maintenance'
sid=ps('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value')
account=ps('[Security.Principal.WindowsIdentity]::GetCurrent().Name')
service_path=ps("(Get-CimInstance Win32_Service -Filter \"Name='RTrustTunnel'\").PathName")
assert service_path.endswith(' '+sid),'Do not change another account service ownership'
BACKUP.mkdir()
for tree in (APP,DATA):
    if tree.exists():
        assert not tree.is_symlink() and not any(f.is_symlink() for f in tree.rglob('*')),'Unexpected linked installation/data'
shutil.copytree(APP,BACKUP/'application')
if DATA.exists():shutil.copytree(DATA,BACKUP/'data')
before=manifest(DATA);login=startup()
(BACKUP/'before.json').write_text(json.dumps({'data_hashes':before,'startup':login,'setup_sha256':EXPECTED},indent=2))
print('Backup:',BACKUP,flush=True)
print('Existing encrypted profile file:',(DATA/'profiles.rtrust').exists(),flush=True)
steps=[]
def preserved():assert manifest(DATA)==before,'User data changed during installer operation'
def install(phase):
    run(SETUP,'/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/ACCOUNT='+account,'/LOG='+str(BACKUP/(phase+'.log')))
    assert ps('(Get-Service RTrustTunnel).Status')=='Running'
    assert ps("(Get-CimInstance Win32_Service -Filter \"Name='RTrustTunnel'\").PathName").endswith(' '+sid)
    assert digest(APP/'R-TrustTunnel.exe')==digest(ROOT/'dist/native-preview-windows/R-TrustTunnel.exe')
    assert digest(pathlib.Path(os.environ['ProgramFiles'])/'RTrustTunnel Service/rtrust-service.exe')==digest(ROOT/'dist/native-preview-windows/rtrust-service.exe')
    preserved();steps.append(phase);print('PASS',phase,'binary hashes, SCM running, account, data preserved',flush=True)
try:
    install('upgrade')
    assert startup()==login,'Upgrade changed autostart'
    install('reinstall-over-existing')
    assert startup()==login,'Reinstall changed autostart'
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r'Software\Microsoft\Windows\CurrentVersion\Uninstall\{E9F177EC-7790-42A6-92C0-377DA6D29E9F}_is1',
            0,winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        uninstaller=pathlib.Path(winreg.QueryValueEx(key,'UninstallString')[0].strip('"'))
    assert uninstaller.parent==APP and uninstaller.name.startswith('unins')
    run(uninstaller,'/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/LOG='+str(BACKUP/'uninstall.log'))
    assert not (APP/'R-TrustTunnel.exe').exists()
    assert not ps("if(Get-Service RTrustTunnel -ErrorAction SilentlyContinue){'exists'}")
    assert not (pathlib.Path(os.environ['ProgramFiles'])/'RTrustTunnel Service').exists()
    preserved();steps.append('uninstall');print('PASS uninstall: application/service removed, data preserved',flush=True)
    install('clean-reinstall')
    restore_startup(login)
    for mode in ['--ci-smoke','--ci-settings-smoke','--ci-tray-smoke']:
        run('python',ROOT/'ci/windows_desktop.py','python','-c',
            'import subprocess,sys;sys.exit(subprocess.run(sys.argv[1:],timeout=30).returncode)',
            APP/'R-TrustTunnel.exe',mode)
        steps.append(mode)
    preserved();assert startup()==login
    (BACKUP/'result.json').write_text(json.dumps({'result':'PASS','steps':steps,'data_files':len(before),'setup_sha256':EXPECTED},indent=2))
    print('PASS installed application GUI/settings/tray; original startup setting preserved',flush=True)
except BaseException:
    (BACKUP/'result.json').write_text(json.dumps({'result':'FAIL','completed_steps':steps},indent=2))
    if not (APP/'R-TrustTunnel.exe').exists() or not ps("if(Get-Service RTrustTunnel -ErrorAction SilentlyContinue){'exists'}"):
        install('recovery-install')
    raise
finally:
    restore_startup(login)
