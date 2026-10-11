#!/usr/bin/env python3
"""Add the WidgetKit extension and its reload bridge to a macOS app bundle.

Builds with the Xcode toolchain without an Xcode project: swiftc emits the
constant values that appintentsmetadataprocessor turns into Metadata.appintents,
which the Control Center toggle's App Intent needs. Command Line Tools alone
lack that processor. The Control Center toggle is built only with a real
signing identity: linkd rejects App Intents clients without a Team ID, so an
ad-hoc toggle would hang until chronod kills the extension. The caller signs
the app last, with the same identity.
"""
import argparse
import functools
import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'apps/macos'
TARGET = 'arm64-apple-macos14.0'  # containerBackground and current WidgetKit APIs
SCHEME = 'rtrust-widget'
# Conformances whose constant values the metadata processor reads.
PROTOCOLS = ['AppIntent', 'EntityQuery', 'AppEntity', 'TransientEntity', 'AppEnum',
             'AppShortcutProviding', 'AppShortcutsProvider', 'AnyResolverProviding',
             'AppIntentsPackage', 'DynamicOptionsProvider', '_IntentValueRepresentable',
             'IntentValueQuery', 'Resolver']


@functools.cache
def developer_dir():
    path = pathlib.Path(os.environ.get('DEVELOPER_DIR', '/Applications/Xcode.app/Contents/Developer'))
    if not (path / 'Toolchains/XcodeDefault.xctoolchain/usr/bin/appintentsmetadataprocessor').exists():
        raise RuntimeError('Xcode is required (set DEVELOPER_DIR): Command Line Tools '
                           'cannot produce App Intents metadata')
    return path


def run(*args):
    result = subprocess.run(args, capture_output=True, env={**os.environ, 'DEVELOPER_DIR': str(developer_dir())})
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): '
                           + result.stderr.decode(errors='replace'))
    return result.stdout


def url_type():
    """Info.plist entry the containing app needs to receive widget actions."""
    return dict(CFBundleURLName='org.rtrusttunnel.widget', CFBundleURLSchemes=[SCHEME])


def install(contents: pathlib.Path, version: str, identity: str = '-'):
    info = plistlib.loads((contents / 'Info.plist').read_bytes())
    app_id = info['CFBundleIdentifier']
    if SCHEME not in {s for t in info.get('CFBundleURLTypes', []) for s in t['CFBundleURLSchemes']}:
        raise RuntimeError('The app Info.plist must declare the rtrust-widget URL scheme')
    sdk = run('/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path').decode().strip()
    xcode = run('/usr/bin/xcodebuild', '-version').decode().split()[-1]
    swiftc = ['/usr/bin/xcrun', 'swiftc', '-O', '-target', TARGET, '-sdk', sdk]
    control = identity != '-'
    with tempfile.TemporaryDirectory(prefix='rtrust-widget-') as temporary:
        work = pathlib.Path(temporary)
        appex = work / 'VPNWidget.appex/Contents'
        (appex / 'MacOS').mkdir(parents=True)
        source = SOURCES / 'Widget/VPNWidget.swift'
        (work / 'protocols.json').write_text(json.dumps(PROTOCOLS))
        # Const values are only emitted by a separate whole-module compile step.
        run(*swiftc, '-parse-as-library', '-module-name', 'VPNWidget', '-wmo', '-c',
            '-application-extension', *(['-D', 'RTRUST_CONTROL'] if control else []),
            str(source), '-o', str(work / 'VPNWidget.o'),
            '-emit-const-values-path', str(work / 'VPNWidget.swiftconstvalues'),
            '-Xfrontend', '-const-gather-protocols-file',
            '-Xfrontend', str(work / 'protocols.json'))
        # Like Xcode: the extension starts in NSExtensionMain, which serves
        # chronod; the Swift @main alone returns and the process exits at once.
        run(*swiftc, '-application-extension', str(work / 'VPNWidget.o'),
            '-Xlinker', '-e', '-Xlinker', '_NSExtensionMain',
            '-o', str(appex / 'MacOS/VPNWidget'))
        (work / 'sources.txt').write_text(f'{source}\n')
        (work / 'consts.txt').write_text(f'{work / "VPNWidget.swiftconstvalues"}\n')
        (appex / 'Resources').mkdir()
        run('/usr/bin/xcrun', 'appintentsmetadataprocessor',
            '--output', str(appex / 'Resources'),
            '--toolchain-dir', str(developer_dir() / 'Toolchains/XcodeDefault.xctoolchain'),
            '--module-name', 'VPNWidget', '--sdk-root', sdk, '--xcode-version', xcode,
            '--platform-family', 'macOS', '--deployment-target', TARGET.split('macos')[1],
            '--target-triple', TARGET, '--source-file-list', str(work / 'sources.txt'),
            '--swift-const-vals-list', str(work / 'consts.txt'),
            '--binary-file', str(appex / 'MacOS/VPNWidget'),
            '--deployment-aware-processing', '--no-app-shortcuts-localization')
        actions = json.loads((appex / 'Resources/Metadata.appintents/extract.actionsdata').read_text())
        if control and 'SetVPNIntent' not in actions['actions']:
            raise RuntimeError('App Intents metadata lacks the Control Center toggle intent')
        (appex / 'Info.plist').write_bytes(plistlib.dumps(dict(
            CFBundleDevelopmentRegion='ru', CFBundleExecutable='VPNWidget',
            CFBundleIdentifier=app_id + '.VPNWidget', CFBundleName='VPNWidget',
            CFBundleDisplayName=info.get('CFBundleName', 'R-TrustTunnel'),
            CFBundleInfoDictionaryVersion='6.0', CFBundlePackageType='XPC!',
            CFBundleSupportedPlatforms=['MacOSX'],
            CFBundleShortVersionString=version, CFBundleVersion=version,
            LSMinimumSystemVersion='14.0', RTrustAppBundleID=app_id,
            NSExtension=dict(NSExtensionPointIdentifier='com.apple.widgetkit-extension'))))
        run('/usr/bin/codesign', '--force', '--sign', identity, '--entitlements',
            str(SOURCES / 'Widget/Widget.entitlements'), str(appex.parent))
        bridge = work / 'libRTrustWidgetBridge.dylib'
        run(*swiftc, '-emit-library', '-module-name', 'RTrustWidgetBridge',
            '-Xlinker', '-install_name', '-Xlinker', '@rpath/libRTrustWidgetBridge.dylib',
            str(SOURCES / 'WidgetBridge/Bridge.swift'), '-o', str(bridge))
        run('/usr/bin/codesign', '--force', '--sign', identity, str(bridge))
        plugins, frameworks = contents / 'PlugIns', contents / 'Frameworks'
        plugins.mkdir(exist_ok=True)
        frameworks.mkdir(exist_ok=True)
        shutil.rmtree(plugins / 'VPNWidget.appex', ignore_errors=True)
        run('/usr/bin/ditto', str(appex.parent), str(plugins / 'VPNWidget.appex'))
        shutil.copy2(bridge, frameworks / bridge.name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', type=pathlib.Path, help='Path to the .app bundle')
    parser.add_argument('--version', required=True)
    parser.add_argument('--sign', default='-', help='codesign identity; "-" omits the toggle')
    args = parser.parse_args()
    install(args.app / 'Contents', args.version, args.sign)
    print(f'Widget extension added to {args.app}; sign the app afterwards')


if __name__ == '__main__':
    main()
