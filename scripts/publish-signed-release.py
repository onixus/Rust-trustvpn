"""Publish immutable signed release files; promote latest only after maintenance evidence.
Private signing keys never leave this workstation.
"""
import argparse, hashlib, pathlib, subprocess
p=argparse.ArgumentParser();p.add_argument('--sequence',type=int,required=True);p.add_argument('--target',choices=['windows-x86_64','macos-aarch64'],required=True);p.add_argument('--promote',action='store_true');a=p.parse_args()
assert a.sequence>0
root=pathlib.Path(__file__).resolve().parents[1]/'dist/signed-releases'/str(a.sequence)/a.target
files=['manifest.json','setup.exe' if a.target=='windows-x86_64' else 'client.dmg']
host='onixus-rf.duckdns.org';remote=f'/opt/rtrust-updates/{a.sequence}/{a.target}'
subprocess.run(['ssh','-o','BatchMode=yes',host,f'install -d -m 755 {remote}'],check=True)
for name in files:
 source=root/name;digest=hashlib.sha256(source.read_bytes()).hexdigest();dest=f'{remote}/{name}'
 # Never overwrite an existing version with a different package or envelope.
 exists=subprocess.run(['ssh','-o','BatchMode=yes',host,f'test -f {dest}'],check=False).returncode==0
 if exists:
  actual=subprocess.check_output(['ssh','-o','BatchMode=yes',host,f'sha256sum {dest}'],text=True).split()[0]
  assert actual==digest,'Published release sequence is immutable'
 else:
  subprocess.run(['scp',str(source),f'{host}:{dest}.part'],check=True)
  subprocess.run(['ssh','-o','BatchMode=yes',host,f'test "$(sha256sum {dest}.part | cut -d " " -f 1)" = {digest} && chmod 644 {dest}.part && mv -n {dest}.part {dest}'],check=True)
 print('Verified public versioned artifact',name,digest)
if a.promote:
 subprocess.run(['ssh','-o','BatchMode=yes',host,f'install -d -m 755 /opt/rtrust-updates/{a.target} && cp {remote}/manifest.json /opt/rtrust-updates/{a.target}/latest.json.part && mv /opt/rtrust-updates/{a.target}/latest.json.part /opt/rtrust-updates/{a.target}/latest.json'],check=True)
 print('Promoted verified release',a.sequence)
