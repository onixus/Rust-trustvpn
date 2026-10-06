"""Sign an archived successful Jenkins artifact with the offline local release key.
Does not publish latest.json. Private key is never copied to the output directory.
"""
import argparse,base64,hashlib,json,pathlib,shutil,subprocess,time,tomllib,re,urllib.request,xml.etree.ElementTree as ET
p=argparse.ArgumentParser();p.add_argument('--job',default='rtrust-native');p.add_argument('--signing-key',type=pathlib.Path);p.add_argument('--build',type=int,required=True);p.add_argument('--sequence',type=int,required=True);p.add_argument('--version',required=True);p.add_argument('--target',choices=['windows-x86_64','macos-aarch64'],required=True);a=p.parse_args()
ROOT=pathlib.Path(__file__).resolve().parents[1]
assert re.fullmatch(r'[A-Za-z0-9_-]+',a.job),'Invalid Jenkins job name'
# Jenkins may expose result=SUCCESS while it is still archiving. Require completion.
token=pathlib.Path('/Users/onixus/jenkins_home/admin-token.txt').read_text().strip()
request=urllib.request.Request(f'http://localhost:8081/job/{a.job}/{a.build}/api/json?tree=building,result',headers={'Authorization':'Basic '+base64.b64encode(('admin:'+token).encode()).decode()})
with urllib.request.urlopen(request,timeout=15) as response:status=json.load(response)
assert status['building'] is False and status['result']=='SUCCESS','Build has not completed successfully'

build=pathlib.Path('/Users/onixus/jenkins_home/jobs')/a.job/'builds'/str(a.build)
assert ET.parse(build/'build.xml').getroot().findtext('result')=='SUCCESS','Only completed successful builds may be signed'
archive=build/'archive';manifest=json.loads((archive/'source-manifest.json').read_text())
# Bind signed release identity to the exact compiled source, before touching output.
for name in ['crates/update/src/lib.rs','Cargo.toml']:
 assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==manifest[name],f'Archived build source differs: {name}'
sequence=re.search(r'pub const CURRENT_SEQUENCE: u64 = (\d+);',(ROOT/'crates/update/src/lib.rs').read_text())
assert sequence and int(sequence.group(1))==a.sequence,'Manifest sequence differs from compiled CURRENT_SEQUENCE'
assert tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['package']['version']==a.version,'Manifest version differs from compiled package version'

assert hashlib.sha256((ROOT/'crates/update/src/root.pub').read_bytes()).hexdigest()==manifest['crates/update/src/root.pub'],'Archived build has a different update root'
source=archive/'dist'/('R-TrustTunnel-Windows-x64-Setup.exe' if a.target=='windows-x86_64' else 'R-TrustTunnel-macOS-arm64-preview.dmg')
filename='setup.exe' if a.target=='windows-x86_64' else 'client.dmg'
output=ROOT/'dist/signed-releases'/str(a.sequence)/a.target
output.mkdir(parents=True,exist_ok=True)
sha=hashlib.sha256(source.read_bytes()).hexdigest()
if (output/filename).exists():assert hashlib.sha256((output/filename).read_bytes()).hexdigest()==sha,'Release sequence is immutable'
shutil.copyfile(source,output/filename);(output/filename).chmod(0o644)
now=int(time.time());payload=dict(schema=1,sequence=a.sequence,version=a.version,target=a.target,min_ipc=1,max_ipc=1,published=now,expires=now+30*86400,url=f'https://onixus-rf.duckdns.org/rtrust/releases/{a.sequence}/{a.target}/{filename}',size=source.stat().st_size,sha256=sha)
input_file=output/'payload.json';input_file.write_text(json.dumps(payload,separators=(',',':')))
subprocess.run(['cargo','run','--offline','--quiet','-p','rtrust-update','--example','sign_release','--',str(a.signing_key or ROOT/'.release-secrets/update-signing.pk8'),str(input_file),str(output/'manifest.json')],cwd=ROOT,check=True)
(output/'manifest.json').chmod(0o644)
print('Prepared signed public release:',output,'SHA256:',sha)
