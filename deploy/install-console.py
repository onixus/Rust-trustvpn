#!/usr/bin/env python3
"""Run from the uploaded repository subset as root. Additive sidecar + local agent."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import urllib.request

os.umask(0o077)
ROOT=Path(__file__).resolve().parents[1]
DEST=Path('/opt/vpn-console')
STAMP=time.strftime('%Y%m%d-%H%M%S')
BACK=DEST/'backups'/STAMP
NGINX=Path('/opt/rtrust-releases/20260930-portal/portal-nginx.conf')
IMAGE='vpn-console:'+STAMP
UNIT=Path('/etc/systemd/system/vpn-console-agent.service')

def run(args):return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout

def main():
    if os.geteuid()!=0:raise SystemExit('Run as root')
    BACK.mkdir(parents=True,mode=0o700)
    current=json.loads(run(['docker','inspect','trusttunnel-web']))[0]
    env=dict(v.split('=',1) for v in current['Config']['Env'])
    if not env.get('SECRET_KEY'):raise RuntimeError('Expected explicit portal SECRET_KEY; inspect before installing')
    data=next(Path(m['Source']) for m in current['Mounts'] if m['Destination']=='/data')
    with sqlite3.connect(data/'trusttunnel-web.db') as source, sqlite3.connect(BACK/'portal.db') as dest:source.backup(dest)
    for name in ('.rtrust-profile-key','.secret_key'):
        if (data/name).is_file():shutil.copy2(data/name,BACK/name)
    shutil.copy2(NGINX,BACK/'nginx.conf')
    for p in ('agent.py','root.pub','console.env'):
        if (DEST/p).exists():shutil.copy2(DEST/p,BACK/p)
    unit=UNIT
    if unit.exists():shutil.copy2(unit,BACK/'agent.service')
    previous=None
    p=subprocess.run(['docker','inspect','vpn-console'],capture_output=True,text=True)
    if p.returncode==0:previous=json.loads(p.stdout)[0];(BACK/'container.json').write_text(p.stdout)
    (BACK/'portal-container.json').write_text(json.dumps(current))
    run(['docker','build','--build-arg','BASE_IMAGE='+current['Image'],'-f',str(ROOT/'deploy/console.Dockerfile'),'-t',IMAGE,str(ROOT)])
    run(['docker','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-e','DATA_DIR=/tmp/portal','-e','CONSOLE_DATA=/tmp/console',IMAGE,'python','-c','import console_app; console_app.init(); print("Import and schema OK")'])
    # Persist only the inherited settings this service needs, never print their values.
    settings={k:env[k] for k in ('SECRET_KEY','SMTP_CONNECT_HOST','PUBLIC_ADDRESS','CLIENT_CA_FILE') if k in env}
    if any('\n' in v or '\r' in v for v in settings.values()):raise RuntimeError('Unsupported multiline environment')
    agent_active=subprocess.run(['systemctl','is-active','--quiet','vpn-console-agent'],capture_output=True).returncode==0
    agent_enabled=subprocess.run(['systemctl','is-enabled','--quiet','vpn-console-agent'],capture_output=True).returncode==0
    old_nginx=NGINX.read_text()
    previous_renamed=False; new_container_attempted=False
    try:
        state=DEST/'data';state.mkdir(mode=0o700,exist_ok=True);os.chown(state,10001,10001)
        if (state/'console.db').exists():
            with sqlite3.connect(state/'console.db') as source, sqlite3.connect(BACK/'console.db') as dest:source.backup(dest)
        (DEST/'packages').mkdir(mode=0o700,exist_ok=True)
        shutil.copy2(ROOT/'server/console/agent.py',DEST/'agent.py')
        shutil.copy2(ROOT/'crates/update/src/root.pub',DEST/'root.pub')
        shutil.copy2(ROOT/'deploy/vpn-console-agent.service',unit)
        (DEST/'console.env').write_text(''.join(k+'='+v+'\n' for k,v in settings.items()))
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','vpn-console-agent'])
        run(['systemctl','restart','vpn-console-agent'])
        for _ in range(20):
            if Path('/run/vpn-console/agent.sock').exists():break
            time.sleep(.2)
        if previous:
            run(['docker','stop','vpn-console']); run(['docker','rename','vpn-console','vpn-console-backup-'+STAMP])
            previous_renamed=True
        args=['docker','run','-d','--name','vpn-console','--network','trusttunnel-web_default','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--restart','unless-stopped','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--env-file',str(DEST/'console.env'),'-p','127.0.0.1:18090:8000','--mount',f'type=bind,src={data},dst=/data','--mount',f'type=bind,src={state},dst=/console-data','--mount','type=bind,src=/run/vpn-console,dst=/run/vpn-console,readonly']
        cert=next(m['Source'] for m in current['Mounts'] if m['Destination']=='/certs')
        args+=['--mount',f'type=bind,src={cert},dst=/certs,readonly',IMAGE]
        new_container_attempted=True
        run(args)
        for _ in range(25):
            try:
                with urllib.request.urlopen('http://127.0.0.1:18090/console/healthz',timeout=2) as r:assert r.status==200
                break
            except Exception:time.sleep(.4)
        else:raise RuntimeError('Console health failed')
        block='''    # BEGIN VPN CONSOLE
    location = /admin/dashboard { return 302 /console; }
    location = /console { return 302 /console/; }
    location ^~ /console/ {
        set $console http://vpn-console:8000;
        proxy_pass $console;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_cookie_flags ~ secure httponly samesite=strict;
        client_max_body_size 32k;
        proxy_read_timeout 35s;
    }
    # END VPN CONSOLE
'''
        import re
        clean=re.sub(r'    # BEGIN VPN CONSOLE\n.*?    # END VPN CONSOLE\n','',old_nginx,flags=re.S)
        if clean.count('    location / {')!=1:raise RuntimeError('Nginx anchor mismatch')
        NGINX.write_text(clean.replace('    location / {',block+'    location / {',1))
        run(['docker','exec','rtrust-portal-https','nginx','-t']);run(['docker','exec','rtrust-portal-https','nginx','-s','reload'])
        with urllib.request.urlopen('https://onixus-rf.duckdns.org/console/healthz',timeout=10) as r:assert r.status==200
        print('Installed',IMAGE,'backup',BACK)
    except BaseException:
        NGINX.write_text(old_nginx)
        subprocess.run(['docker','exec','rtrust-portal-https','nginx','-t'],capture_output=True)
        subprocess.run(['docker','exec','rtrust-portal-https','nginx','-s','reload'],capture_output=True)
        if new_container_attempted:subprocess.run(['docker','rm','-f','vpn-console'],capture_output=True)
        if previous_renamed:subprocess.run(['docker','rename','vpn-console-backup-'+STAMP,'vpn-console'],capture_output=True)
        if previous:subprocess.run(['docker','start','vpn-console'],capture_output=True)
        subprocess.run(['systemctl','stop','vpn-console-agent'],capture_output=True)
        for name in ('agent.py','root.pub','console.env'):
            if (BACK/name).exists():shutil.copy2(BACK/name,DEST/name)
            else:(DEST/name).unlink(missing_ok=True)
        if not agent_enabled:subprocess.run(['systemctl','disable','vpn-console-agent'],capture_output=True)
        if (BACK/'agent.service').exists():
            shutil.copy2(BACK/'agent.service',unit)
        else:unit.unlink(missing_ok=True)
        subprocess.run(['systemctl','daemon-reload'],capture_output=True)
        if agent_active:subprocess.run(['systemctl','start','vpn-console-agent'],capture_output=True)
        # Existing VPN containers are never replaced by this installer.
        print('Installation failed; original nginx restored. Recovery files:',BACK)
        raise

if __name__=='__main__':main()
