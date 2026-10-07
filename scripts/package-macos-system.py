#!/usr/bin/env python3
"""Build an unsigned macOS system VPN candidate; does not install it."""
import argparse
import hashlib
import pathlib
import plistlib
import shutil
import subprocess
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--pkg-only', action='store_true', help='Create and verify the PKG without a disk image')
    parser.add_argument('--binary-dir', type=pathlib.Path,
                        help='Use binaries from a verified CI build')
    parser.add_argument('--bundled-service', action='store_true',
                        help='Use the separately named bundled-candidate output')
    parser.add_argument('--ui',choices=['native','webview','both'],default='native')
    args = parser.parse_args()
    frontend='rtrust-webview' if args.ui=='webview' else 'rtrust-native'
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    binary = args.binary_dir or ROOT / 'target' / ('debug' if args.debug else 'release')
    for name in (frontend, 'rtrust-service', *(['rtrust-webview'] if args.ui=='both' else [])):
        if run('/usr/bin/lipo', '-archs', str(binary / name)).strip() != b'arm64':
            raise RuntimeError('Expected macOS arm64 binary: ' + name)
    output = ROOT / 'dist/R-TrustTunnel-macOS-arm64-system-candidate.dmg'
    if args.bundled_service:
        output = output.with_name('R-TrustTunnel-macOS-arm64-bundled-candidate.dmg')
    if args.ui!='native':output=output.with_name(output.stem+'-'+args.ui+output.suffix)
    output.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rtrust-system-package-') as temporary:
        work = pathlib.Path(temporary)
        payload = work / 'payload'
        app = payload / 'Applications/R-TrustTunnel.app/Contents'
        (app / 'MacOS').mkdir(parents=True)
        shutil.copy2(binary / frontend, app / ('MacOS/'+frontend))
        (app / 'Info.plist').write_bytes(plistlib.dumps(dict(
            CFBundleExecutable=frontend, CFBundleIdentifier='org.rtrusttunnel.Native',
            CFBundleName='R-TrustTunnel', CFBundlePackageType='APPL', CFBundleIconFile='rtrust.icns',
            CFBundleShortVersionString=version, CFBundleVersion=version,
            NSHighResolutionCapable=True,
            # Only the primary app claims profile links so LaunchServices has one handler.
            CFBundleURLTypes=[dict(CFBundleURLName='org.rtrusttunnel.profile-link',
                CFBundleURLSchemes=['tt','hy2','hysteria2'])])))
        (app / 'Resources').mkdir()
        shutil.copy2(ROOT / 'packaging/branding/icon.icns', app / 'Resources/rtrust.icns')
        secondary=None
        if args.ui=='both':
            secondary=payload/'Applications/R-TrustTunnel WebView.app/Contents'
            (secondary/'MacOS').mkdir(parents=True)
            shutil.copy2(binary/'rtrust-webview',secondary/'MacOS/rtrust-webview')
            (secondary/'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleExecutable='rtrust-webview',CFBundleIdentifier='org.rtrusttunnel.Webview',CFBundleName='R-TrustTunnel WebView',CFBundlePackageType='APPL',CFBundleIconFile='rtrust.icns',CFBundleShortVersionString=version,CFBundleVersion=version,NSHighResolutionCapable=True)))
            (secondary/'Resources').mkdir()
            shutil.copy2(ROOT/'packaging/branding/icon.icns',secondary/'Resources/rtrust.icns')
            run('/usr/bin/codesign','--force','--sign','-',str(secondary.parent))
        helper = app / 'Library/LaunchServices/org.rtrusttunnel.service'
        helper.parent.mkdir(parents=True)
        shutil.copy2(binary / 'rtrust-service', helper)
        helper.chmod(0o755)
        # Ad-hoc signing seals nested code; this is NOT Developer ID signing
        # or notarization. A per-app macOS approval may still be required.
        run('/usr/bin/codesign', '--force', '--sign', '-', '--identifier',
            'org.rtrusttunnel.service', str(helper))
        run('/usr/bin/codesign', '--force', '--sign', '-', str(app.parent))
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', str(app.parent))
        daemon = payload / 'Library/LaunchDaemons/org.rtrusttunnel.service.plist'
        daemon.parent.mkdir(parents=True)
        daemon.write_bytes(plistlib.dumps(dict(
            Label='org.rtrusttunnel.service',
            ProgramArguments=['/' + str(helper.relative_to(payload)), '501'],
            AssociatedBundleIdentifiers=['org.rtrusttunnel.Native'],
            UserName='root', GroupName='wheel', RunAtLoad=True, KeepAlive=True,
            ThrottleInterval=5, ProcessType='Background', Umask=63)))
        scripts = work / 'scripts'
        shutil.copytree(ROOT / 'packaging/macos', scripts)
        post=scripts/'postinstall'
        post.write_text(post.read_text().replace('/MacOS/rtrust-native --ci-service-smoke','/MacOS/'+frontend+' --ci-service-smoke'))
        stage = work / 'image'
        stage.mkdir()
        pkg = stage / 'R-TrustTunnel-System.pkg'
        run('/usr/bin/pkgbuild', '--root', str(payload), '--scripts', str(scripts),
            '--identifier', 'org.rtrusttunnel.system', '--version', version,
            '--install-location', '/', '--ownership', 'recommended', str(pkg))
        # Extract the actual package and compare both payload binaries, rather
        # than treating successful pkgbuild as proof of correct packaging.
        expanded = work / 'expanded'
        run('/usr/sbin/pkgutil', '--expand-full', str(pkg), str(expanded))
        for source in (app / ('MacOS/'+frontend), helper, *([secondary/'MacOS/rtrust-webview'] if secondary else [])):
            bundled = expanded / 'Payload' / source.relative_to(payload)
            if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(bundled.read_bytes()).digest():
                raise RuntimeError('Package payload hash mismatch')
        run('/usr/bin/codesign', '--verify', '--deep', '--strict',
            str(expanded / 'Payload/Applications/R-TrustTunnel.app'))
        (stage / 'READ ME.txt').write_text(
            'R-TrustTunnel system VPN candidate for macOS Apple Silicon\n\n'
            'Open R-TrustTunnel-System.pkg to install the app and root LaunchDaemon.\n'
            'The installer requires macOS administrator authorization.\n'
            'Disconnect/recover R-TrustTunnel before reinstalling or updating.\n'
            'System VPN uses utun and PF, without an Apple Network Extension.\n'
            'This candidate is not signed or notarized with an Apple certificate.\n'
            'Privileged networking and package lifecycle require runtime acceptance tests.\n'
            'Do not disable Gatekeeper globally.\n')
        if args.pkg_only:
            destination = output.with_suffix('.pkg')
            shutil.copy2(pkg, destination)
            destination.with_suffix('.pkg.sha256').write_text(f'{hashlib.sha256(destination.read_bytes()).hexdigest()}  {destination.name}\n')
            print(f'PASS package payload and ad-hoc signature: {destination}')
            return
        image = work / output.name
        run('/usr/bin/hdiutil', 'create', '-quiet', '-volname', 'R-TrustTunnel System',
            '-srcfolder', str(stage), '-format', 'UDZO', str(image))
        run('/usr/bin/hdiutil', 'verify', str(image))
        shutil.copy2(pkg, output.with_suffix('.pkg'))
        shutil.copy2(image, output)
    for path in (output, output.with_suffix('.pkg')):
        path.with_suffix(path.suffix + '.sha256').write_text(
            f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n')
    print(f'PASS unsigned package payload and DMG integrity: {output}')


if __name__ == '__main__':
    main()
