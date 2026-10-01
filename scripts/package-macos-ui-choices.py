#!/usr/bin/env python3
"""Build a DMG with explicit Native, WebView and Both installer choices."""
import argparse,hashlib,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--binary-dir',type=pathlib.Path,required=True);a=p.parse_args()
    output=ROOT/'dist/R-TrustTunnel-macOS-arm64-UI-Choices.dmg'
    with tempfile.TemporaryDirectory(prefix='rtrust-ui-choices-') as temporary:
        stage=pathlib.Path(temporary)/'image';stage.mkdir()
        for ui in ('native','webview','both'):
            subprocess.run(['python3',str(ROOT/'scripts/package-macos-system.py'),'--binary-dir',str(a.binary_dir),'--ui',ui],check=True)
            source=ROOT/('dist/R-TrustTunnel-macOS-arm64-system-candidate'+('' if ui=='native' else '-'+ui)+'.pkg')
            shutil.copy2(source,stage/('Install-'+ui.capitalize()+'.pkg'))
        (stage/'Read me.txt').write_text('Choose exactly one installer: Native, WebView, or Both.\nAll variants install the same privileged VPN service and use the same encrypted profile store.\nQuit both interfaces and disconnect/recover VPN before installing or changing variants.\nUnsigned preview: a per-app Gatekeeper approval may be required.\nNative does not install a WebView application. WebView uses macOS WKWebView.\nChanging variants does not delete an already installed secondary WebView app.\n')
        staged=pathlib.Path(temporary)/output.name
        subprocess.run(['hdiutil','create','-quiet','-volname','R-TrustTunnel UI Choices','-srcfolder',str(stage),'-format','UDZO',str(staged)],check=True)
        subprocess.run(['hdiutil','verify',str(staged)],check=True)
        shutil.copy2(staged,output)
    output.with_suffix('.dmg.sha256').write_text(hashlib.sha256(output.read_bytes()).hexdigest()+'  '+output.name+'\n')
    print(output)
if __name__=='__main__':main()
