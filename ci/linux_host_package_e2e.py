"""Explicitly authorized lifecycle test of our installed Arch candidate only.
Run as its desktop owner; sudo must already be available. No VPN is started.
"""
import argparse
import hashlib
import os
import pathlib
import subprocess
import time

p=argparse.ArgumentParser();p.add_argument('previous',type=pathlib.Path);p.add_argument('candidate',type=pathlib.Path);args=p.parse_args()
assert os.getuid()!=0
uid=os.getuid()
def run(*cmd,ok=True):
    result=subprocess.run(cmd,text=True,capture_output=True,timeout=90)
    if ok:assert result.returncode==0,result.stdout+'\n'+result.stderr
    return result
assert run('pacman','-Q','rtrust-host').stdout.strip().startswith('rtrust-host ')
assert run('sudo','-n','cat','/var/lib/rtrust/desktop-uid').stdout.strip()==str(uid)
for marker in ('/run/rtrust/full.json','/run/rtrust/lease.json','/var/lib/rtrust/always-on.rtrust'):
    assert run('sudo','-n','test','-e',marker,ok=False).returncode!=0,'Disconnect/recover before package test'
service=pathlib.Path('/usr/libexec/rtrust/rtrust-service')
def pid():return run('systemctl','show','-p','MainPID','--value',f'rtrust-service@{uid}.service').stdout.strip()
def ready():
    for _ in range(30):
        result=run('flatpak','run','--user','org.rtrusttunnel.Native','--ci-service-smoke',ok=False)
        if result.returncode==0:return
        time.sleep(.2)
    raise AssertionError(result.stderr)
def install(path):
    run('sudo','-n','pacman','-U','--noconfirm',str(path.resolve()))
    ready()
old_pid=pid();old_hash=hashlib.sha256(service.read_bytes()).hexdigest()
# An inert marker exercises the actual ALPM AbortOnFail hook. No route is added.
marker='/run/rtrust/full.json'
run('sudo','-n','install','-m','600','/dev/null',marker)
try:
    result=run('sudo','-n','pacman','-U','--noconfirm',str(args.candidate.resolve()),ok=False)
    assert result.returncode!=0,'Package manager must abort, not just log a scriptlet failure'
    assert 'R-TrustTunnel: disable always-on' in result.stdout+result.stderr
    assert pid()==old_pid and hashlib.sha256(service.read_bytes()).hexdigest()==old_hash
finally:run('sudo','-n','rm','--',marker)
print('PASS real pacman transaction rejects active journal without replacing/restarting service',flush=True)
install(args.candidate);assert pid()!=old_pid
print('PASS real package upgrade and Flatpak IPC',flush=True)
install(args.previous);assert hashlib.sha256(service.read_bytes()).hexdigest()==old_hash
print('PASS real package rollback and Flatpak IPC',flush=True)
install(args.candidate)
print('PASS candidate restored after rollback; configured owner preserved',flush=True)
run('sudo','-n','pacman','-R','--noconfirm','rtrust-host')
assert not service.exists()
for manager in ('NetworkManager','systemd-networkd'):
    assert not pathlib.Path(f'/etc/systemd/system/{manager}.service.d/rtrust-boot-guard.conf').exists()
print('PASS package removal clears its network-manager dependencies',flush=True)
run('sudo','-n','pacman','-U','--noconfirm',str(args.candidate.resolve()))
run('sudo','-n','env',f'PKEXEC_UID={uid}','/usr/libexec/rtrust/enable-service')
ready()
print('PASS reinstall/configuration restores the same desktop owner and Flatpak IPC',flush=True)
