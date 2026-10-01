#!/usr/bin/env python3
"""Package a verified ELF binary for its explicit Flatpak architecture.
No host service or host execution permission is included in the sandbox.
"""
import argparse,hashlib,json,pathlib,platform,shutil,struct,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo-dir',type=pathlib.Path,help='OSTree repository on a native Linux filesystem')
    parser.add_argument('--arch',choices=['aarch64','x86_64'],help='Explicit target for cross-built binaries')
    parser.add_argument('--binary-dir',type=pathlib.Path,help='Directory containing the verified rtrust-native binary')
    args=parser.parse_args()
    architecture={'aarch64':('aarch64',183),'x86_64':('x86_64',62)}.get(args.arch or platform.machine())
    if platform.system()!='Linux' or architecture is None:raise SystemExit('Run on Linux with a supported target architecture')
    binary=(args.binary_dir or ROOT/'target/release')/'rtrust-native';header=binary.read_bytes()[:20]
    assert header[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',header,18)[0]==architecture[1], 'Wrong ELF architecture'
    template=ROOT/'packaging/flatpak/org.rtrusttunnel.Native.json'
    manifest=json.loads(template.read_text())
    for source in manifest['modules'][0]['sources']:
        path=binary.resolve() if source['path']=='../../target/release/rtrust-native' else (template.parent/source['path']).resolve()
        source['path']=str(path)
        source['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    output=ROOT/'dist';output.mkdir(exist_ok=True)
    repo=args.repo_dir or output/'flatpak-repo'
    with tempfile.TemporaryDirectory(prefix='rtrust-flatpak-') as temporary:
        work=pathlib.Path(temporary);definition=work/template.name;definition.write_text(json.dumps(manifest,indent=2))
        subprocess.run(['flatpak-builder','--force-clean','--disable-rofiles-fuse','--state-dir='+str(work/'state'),'--repo='+str(repo),'--arch='+architecture[0],str(work/'build'),str(definition)],check=True)
        bundle=output/('R-TrustTunnel-Linux-'+architecture[0]+'.flatpak')
        staged_bundle=work/bundle.name
        subprocess.run(['flatpak','build-bundle','--arch='+architecture[0],'--runtime-repo=https://flathub.org/repo/flathub.flatpakrepo',str(repo),str(staged_bundle),manifest['app-id'],'master'],check=True)
        shutil.copyfile(staged_bundle,bundle)
    bundle.with_suffix('.flatpak.sha256').write_text(hashlib.sha256(bundle.read_bytes()).hexdigest()+'  '+bundle.name+'\n')
    print('Packaged candidate:',bundle)
if __name__=='__main__':main()
