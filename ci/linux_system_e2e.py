"""Explicitly authorized Linux host-network acceptance, never an ordinary CI step.
Run the root driver as a transient systemd service; SSH can disappear under guard.
A separate systemd timer must run --restore if this driver is interrupted.
"""
import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.request
import macos_system_e2e as shared

shared.SOCKET='/run/rtrust/control.sock'

def traffic(data):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for family,target in ((socket.AF_INET,data['target']),(socket.AF_INET6,data['target6'])):
        address='['+target+']' if family==socket.AF_INET6 else target
        with opener.open(f'http://{address}:8080/',timeout=15) as response:assert response.read()==shared.BODY
        with socket.socket(family,socket.SOCK_DGRAM) as udp:
            udp.settimeout(10)
            for size in (1,1472,5000,60000):
                body=os.urandom(size);udp.sendto(body,(target,8081));answer,_=udp.recvfrom(65535);assert answer==body
        for size in (56,5000):
            r=subprocess.run(['ping','-6' if family==socket.AF_INET6 else '-4','-n','-c','2','-s',str(size),target],capture_output=True,text=True,timeout=15)
            assert r.returncode==0,r.stdout+r.stderr
        print('PASS Linux TCP 512 KiB, UDP through 60 KB, ICMP 56/5000 '+target,flush=True)
    assert socket.gethostbyname('rtrust-'+os.urandom(8).hex()+'.fixture.test')==data['target']
    print('PASS actual system DNS through VPN',flush=True)

def worker(args):
    assert os.geteuid()==args.uid
    data=json.loads(pathlib.Path(args.fixture).read_text())
    host=data['base']['addresses'][0].rsplit(':',1)[0]
    route=json.loads(subprocess.check_output(['ip','-j','route','get',host]))[0]
    interface=route['dev'];assert interface not in ('wig','hy-tun','rtrust0')
    def direct():
        with socket.socket() as sock:
            sock.settimeout(2);sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0');sock.connect((host,22))
    direct()
    profile=dict(schema_version=1,name='Linux acceptance fixture',endpoint=data['base'])
    pipe=shared.Pipe()
    try:
        response=pipe.request(dict(op='StartFull',profile=profile,dns=data['target']))
        assert response['state']=='Connected',response
        with shared.status_trace(pipe):traffic(data)
        try:direct()
        except OSError:pass
        else:raise AssertionError('Physical interface bypassed VPN guard')
        print('PASS physical-bound direct bypass rejected',flush=True)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request=urllib.request.Request('http://'+data['target']+':8082/cycle',data=b'',headers={'Authorization':'Bearer '+data['control_token']})
        with opener.open(request,timeout=5) as response:assert response.status==204
        blocked=False;deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            response=pipe.request(dict(op='Status'))
            blocked |= response['state']=='Blocked'
            if blocked and response['state']=='Connected':break
            time.sleep(.5)
        else:raise AssertionError('Outage/reconnect not observed')
        with shared.status_trace(pipe):traffic(data)
        assert pipe.request(dict(op='Stop'))['state']=='Idle'
        direct();print('PASS outage, reconnect and explicit Stop',flush=True)
        # Linux ends the authenticated lease after Stop; start a new connection.
        pipe.close();pipe=shared.Pipe()
        assert pipe.request(dict(op='StartFull',profile=profile,dns=data['target']))['state']=='Connected'
        pipe.close();time.sleep(.5)
        try:direct()
        except OSError:pass
        else:raise AssertionError('GUI crash removed guard')
        shared.recover();direct();print('PASS GUI crash retains guard; Recover restores access',flush=True)
        pipe=shared.Pipe()
        assert pipe.request(dict(op='StartFull',profile=profile,dns=data['target']))['state']=='Connected'
        subprocess.run(['sudo','-n','systemctl','kill','--signal=SIGKILL',f'rtrust-service@{args.uid}.service'],check=True,timeout=10)
        assert pipe.socket.recv(1)==b''
        try:direct()
        except OSError:pass
        else:raise AssertionError('Service crash removed guard')
        deadline=time.monotonic()+20
        while True:
            try:shared.recover();break
            except (OSError,RuntimeError,AssertionError):
                if time.monotonic()>deadline:raise
                time.sleep(.25)
        direct();assert subprocess.run(['ip','link','show','rtrust0'],capture_output=True).returncode!=0
        print('PASS systemd service crash/restart retains guard; recovery removes TUN',flush=True)
    finally:pipe.close()

def restore(args):
    assert os.geteuid()==0
    subprocess.run(['systemctl','start',f'rtrust-service@{args.uid}.service'],check=True,timeout=15)
    for attempt in range(5):
        result=subprocess.run(['runuser','-u',args.user,'--',sys.executable,__file__,'--recover-only'],timeout=20)
        if result.returncode==0:break
        time.sleep(2)
    else:raise RuntimeError('R-TrustTunnel recovery failed; leaving original VPN unchanged')
    try:
        subprocess.run(['nmcli','connection','up','uuid',args.wireguard_uuid],check=True,timeout=35)
    finally:
        subprocess.run(['systemctl','start',args.vpn_unit],check=True,timeout=20)
    print('Original WireGuard and tunnel service restored',flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('fixture',nargs='?');p.add_argument('--user');p.add_argument('--uid',type=int);p.add_argument('--wireguard-uuid');p.add_argument('--vpn-unit');p.add_argument('--worker',action='store_true');p.add_argument('--restore',action='store_true');p.add_argument('--recover-only',action='store_true');p.add_argument('--allow-network-switch',action='store_true');args=p.parse_args()
    if args.recover_only:return shared.recover()
    if args.worker:return worker(args)
    assert args.allow_network_switch and os.geteuid()==0
    assert args.user and args.uid and args.uid!=0 and args.wireguard_uuid and args.vpn_unit=='sing-box.service'
    if args.restore:return restore(args)
    data=json.loads(pathlib.Path(args.fixture).read_text());assert data['expires_at']>time.time()+240
    assert not pathlib.Path('/run/rtrust/full.json').exists()
    assert not pathlib.Path('/run/rtrust/lease.json').exists()
    assert not pathlib.Path('/var/lib/rtrust/always-on.rtrust').exists()
    subprocess.run(['systemctl','is-active','--quiet',args.vpn_unit],check=True)
    active=subprocess.check_output(['nmcli','-g','UUID','connection','show','--active'],text=True)
    assert args.wireguard_uuid in active.splitlines()
    try:
        subprocess.run(['systemctl','stop',args.vpn_unit],check=True,timeout=20)
        subprocess.run(['nmcli','connection','down','uuid',args.wireguard_uuid],check=True,timeout=20)
        time.sleep(2)
        result=subprocess.run(['runuser','-u',args.user,'--',sys.executable,__file__,args.fixture,'--uid',str(args.uid),'--worker'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=210)
        print(result.stdout,flush=True)
        result.check_returncode()
    finally:restore(args)
if __name__=='__main__':main()
