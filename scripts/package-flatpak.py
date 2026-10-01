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
    parser.add_argument('--ui',choices=['native','webview','both'],default='native')
    parser.add_argument('--webview-libs',type=pathlib.Path,help='Verified Linux tray libraries from the build environment')
    args=parser.parse_args()
    architecture={'aarch64':('aarch64',183),'x86_64':('x86_64',62)}.get(args.arch or platform.machine())
    if platform.system()!='Linux' or architecture is None:raise SystemExit('Run on Linux with a supported target architecture')
    binary_dir=args.binary_dir or ROOT/'target/release'
    binary=binary_dir/('rtrust-webview' if args.ui=='webview' else 'rtrust-native');header=binary.read_bytes()[:20]
    assert header[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',header,18)[0]==architecture[1], 'Wrong ELF architecture'
    template=ROOT/'packaging/flatpak/org.rtrusttunnel.Native.json'
    manifest=json.loads(template.read_text())
    if args.ui!='native':
        manifest['runtime']='org.gnome.Platform';manifest['runtime-version']='50';manifest['sdk']='org.gnome.Sdk'
        manifest['finish-args'] += ['--env=GDK_BACKEND=wayland','--env=LD_LIBRARY_PATH=/app/lib']
        manifest['command']='rtrust-webview' if args.ui=='webview' else 'rtrust-native'
        module=manifest['modules'][0]
        if args.ui=='webview':
            module['build-commands'][0]='install -Dm755 rtrust-webview /app/bin/rtrust-webview'
            module['sources'][0]['path']='../../target/release/rtrust-webview'
        else:
            module['build-commands'].append('install -Dm755 rtrust-webview /app/bin/rtrust-webview')
            module['sources'].append({'type':'file','path':'../../target/release/rtrust-webview'})
        if args.webview_libs is None:raise SystemExit('--webview-libs is required for a self-contained tray runtime')
        for pattern in ('libayatana-appindicator3.so.1','libayatana-indicator3.so.7','libayatana-ido3-0.4.so.0','libdbusmenu-glib.so.4','libdbusmenu-gtk3.so.4'):
            library=(args.webview_libs/pattern).resolve(strict=True)
            module['sources'].append({'type':'file','path':str(library),'dest-filename':pattern})
            module['build-commands'].append('install -Dm755 '+pattern+' /app/lib/'+pattern)
    for source in manifest['modules'][0]['sources']:
        path=(binary_dir/pathlib.Path(source['path']).name).resolve() if source['path'].startswith('../../target/release/') else (template.parent/source['path']).resolve()
        source['path']=str(path)
        source['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    output=ROOT/'dist';output.mkdir(exist_ok=True)
    repo=args.repo_dir or output/'flatpak-repo'
    with tempfile.TemporaryDirectory(prefix='rtrust-flatpak-') as temporary:
        work=pathlib.Path(temporary)
        if args.ui=='webview':
            desktop=work/'org.rtrusttunnel.Native.desktop'
            desktop.write_text((template.parent/desktop.name).read_text().replace('Exec=rtrust-native','Exec=rtrust-webview'))
            for source in manifest['modules'][0]['sources']:
                if source['path'].endswith(desktop.name):source.update(path=str(desktop),sha256=hashlib.sha256(desktop.read_bytes()).hexdigest())
        if args.ui=='both':
            desktop=work/'org.rtrusttunnel.Native.WebView.desktop'
            desktop.write_text((template.parent/'org.rtrusttunnel.Native.desktop').read_text().replace('Name=R-TrustTunnel','Name=R-TrustTunnel WebView').replace('Exec=rtrust-native','Exec=rtrust-webview'))
            manifest['modules'][0]['sources'].append({'type':'file','path':str(desktop),'sha256':hashlib.sha256(desktop.read_bytes()).hexdigest()})
            manifest['modules'][0]['build-commands'].append('install -Dm644 '+desktop.name+' /app/share/applications/'+desktop.name)
        definition=work/template.name;definition.write_text(json.dumps(manifest,indent=2))
        subprocess.run(['flatpak-builder','--force-clean','--disable-rofiles-fuse','--state-dir='+str(work/'state'),'--repo='+str(repo),'--arch='+architecture[0],str(work/'build'),str(definition)],check=True)
        bundle=output/('R-TrustTunnel-Linux-'+architecture[0]+('' if args.ui=='native' else '-'+args.ui)+'.flatpak')
        staged_bundle=work/bundle.name
        subprocess.run(['flatpak','build-bundle','--arch='+architecture[0],'--runtime-repo=https://flathub.org/repo/flathub.flatpakrepo',str(repo),str(staged_bundle),manifest['app-id'],'master'],check=True)
        shutil.copyfile(staged_bundle,bundle)
    bundle.with_suffix('.flatpak.sha256').write_text(hashlib.sha256(bundle.read_bytes()).hexdigest()+'  '+bundle.name+'\n')
    print('Packaged candidate:',bundle)
if __name__=='__main__':main()
