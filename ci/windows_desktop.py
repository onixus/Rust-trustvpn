"""Run nonprivileged GUI/keyring checks in the logged-in user's desktop session.
The temporary task is always removed; no VPN/service or user vault is touched.
"""
import os,pathlib,shutil,subprocess,sys,tempfile,time,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
TASK='RTrustTunnel-Desktop-CI-'+uuid.uuid4().hex
def quote(value):return "'"+str(value).replace("'","''")+"'"
def ps(code):
    return subprocess.check_output(['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop'; "+code],text=True,encoding='utf-8',errors='replace',timeout=30).strip()
command=sys.argv[1:]
assert command
command[0]=shutil.which(command[0]) or command[0]
with tempfile.TemporaryDirectory(prefix='rtrust-desktop-') as directory:
    work=pathlib.Path(directory);script=work/'run.ps1';result=work/'exit.txt';log=work/'output.log'
    script.write_text("$ErrorActionPreference='Stop'\n"+
        f"Set-Location {quote(ROOT)}\n$env:PATH={quote(os.environ['PATH'])}\n"+
        "$env:RUSTUP_TOOLCHAIN='1.98.1'\n$env:RUSTFLAGS='-C target-feature=+crt-static'\n"+
        "try {\n$ErrorActionPreference='Continue'\n& "+' '.join(map(quote,command))+f" *> {quote(log)}\n$code=$LASTEXITCODE\n"+
        f"}} catch {{ $_ | Out-File {quote(log)} -Append; $code=1 }}\n"+
        f"if ($null -eq $code) {{ $code=1 }}\n$code | Set-Content {quote(work / 'exit.tmp')} -Encoding ascii\n"+
        f"Move-Item {quote(work / 'exit.tmp')} {quote(result)}\nexit $code\n",encoding='utf-8-sig')
    try:
        ps("$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "+
           "$p=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited; "+
           "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 3); "+
           "$a=New-ScheduledTaskAction -Execute \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Argument "+quote(f'-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{script}"')+"; "+
           f"Register-ScheduledTask -TaskName '{TASK}' -Principal $p -Action $a -Settings $s | Out-Null; Start-ScheduledTask -TaskName '{TASK}'")
        deadline=time.monotonic()+170
        while not result.exists() and time.monotonic()<deadline:time.sleep(.3)
        if not result.exists():raise TimeoutError('Interactive desktop check did not complete; a logged-in desktop is required')
        if log.exists():
            raw=log.read_bytes()
            print(raw.decode('utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8-sig',errors='replace'))
        code=int(result.read_text().strip())
        if code:raise SystemExit(code)
        print('PASS interactive desktop check (limited user token)')
    finally:
        ps(f"if(Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue){{Stop-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false}}")
