"""Exercise portal mutations in a disposable container; no live data or network."""
import subprocess
import time
from pathlib import Path

name='vpn-console-isolated-acceptance'
root=Path(__file__).resolve().parents[1]
def run(args):
    p=subprocess.run(args,capture_output=True,text=True)
    if p.returncode:
        print(p.stdout);print(p.stderr);raise RuntimeError('Isolated test failed')
    return p.stdout+p.stderr
image=run(['docker','inspect','vpn-console','--format','{{.Image}}']).strip()
try:
    run(['docker','run','-d','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/data:rw,noexec,nosuid,uid=10001,gid=10001,mode=0700','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-e','CONSOLE_ISOLATED_ACCEPTANCE=1','-e','ENDPOINT_WORKDIR=/data/runtime','-e','ENDPOINT_BIN=/nonexistent-fixture-endpoint','--mount',f'type=bind,src={root}/server/tests/console_portal_acceptance.py,dst=/accept.py,readonly',image,'uvicorn','app.main:app','--host','127.0.0.1','--port','8000','--no-access-log'])
    for _ in range(20):
        p=subprocess.run(['docker','exec',name,'python','-c','import urllib.request;urllib.request.urlopen("http://127.0.0.1:8000/healthz",timeout=2)'],capture_output=True)
        if p.returncode==0:break
        time.sleep(.5)
    print(run(['docker','exec',name,'python','/accept.py']))
except BaseException:
    print(run(['docker','logs','--tail','70',name]))
    raise
finally:
    run(['docker','rm','-f',name])
print('PASS isolated container removed; no live DB mounts or external network')
