#!/usr/bin/env python3
"""Build Android APKs using an installed SDK/NDK, Rust targets and Gradle 8.13.

No SDK licenses are accepted by this script. Install tools explicitly first.
Release APKs remain unsigned: provide a separately managed signing workflow.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def run(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gradle', default='gradle')
    parser.add_argument('--ndk-version', default='28.2.13676358')
    parser.add_argument('--release', action='store_true')
    args = parser.parse_args()
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if not sdk:
        parser.error('Set ANDROID_HOME to your installed Android SDK')
    host = 'linux-x86_64' if sys.platform == 'linux' else 'darwin-x86_64' if sys.platform == 'darwin' else None
    if host is None:
        parser.error('Native Rust build currently requires Linux or macOS')
    toolchain = Path(sdk) / 'ndk' / args.ndk_version / 'toolchains/llvm/prebuilt' / host / 'bin'
    if not toolchain.is_dir():
        parser.error('Pinned Android NDK is not installed')
    target_root = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
    if not target_root.is_absolute():
        target_root = ROOT / target_root
    for target, abi in [('x86_64-linux-android', 'x86_64'), ('aarch64-linux-android', 'arm64-v8a')]:
        env = dict(os.environ)
        env['PATH'] = str(toolchain) + os.pathsep + env['PATH']
        suffix = target.replace('-', '_')
        env['CC_' + suffix] = target + '29-clang'
        env['AR_' + suffix] = 'llvm-ar'
        env['CARGO_TARGET_' + suffix.upper() + '_LINKER'] = target + '29-clang'
        run(['cargo', 'build', '--locked', '--release', '-p', 'rtrust-android', '--target', target], cwd=ROOT, env=env)
        output = ROOT / 'apps/android/app/src/main/jniLibs' / abi
        output.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target_root / target / 'release/librtrust_android.so', output)
    run([args.gradle, '-p', str(ROOT / 'apps/android'), '--no-daemon', 'assembleRelease' if args.release else 'assembleDebug', 'assembleDebugAndroidTest', 'lintDebug'], cwd=ROOT)
    output = ROOT / 'dist/android'
    output.mkdir(parents=True, exist_ok=True)
    for apk in (ROOT / 'apps/android/app/build/outputs/apk').rglob('*.apk'):
        shutil.copy2(apk, output / apk.name)

if __name__ == '__main__':
    main()
