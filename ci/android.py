#!/usr/bin/env python3
"""Android build on a Linux agent with explicitly provisioned SDK/Gradle/KVM.

Rust builds in Docker; only output directories are writable mounts. The caller
owns SDK license acceptance and emulator creation. Nothing changes host routes.
"""
import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
NAME = 'rtrust-android-build-' + secrets.token_hex(4)
IMAGE = 'rtrust-android-rust:1.98.1'

def run(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)

def interrupt(signum, _):
    subprocess.run(['docker', 'rm', '-f', NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    raise SystemExit(128 + signum)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gradle', default=os.environ.get('GRADLE', 'gradle'))
    p.add_argument('--serial', required=True)
    args = p.parse_args()
    if not args.serial.startswith('emulator-'):
        p.error('Only an explicitly selected emulator is accepted')
    sdk = Path(os.environ.get('ANDROID_HOME', Path.home() / 'Android/Sdk')).resolve()
    ndk = sdk / 'ndk/28.2.13676358'
    if not (ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin').is_dir():
        p.error('Provision Android NDK 28.2.13676358 first')
    env = dict(os.environ, ANDROID_HOME=str(sdk))
    for name in ('SIGTERM', 'SIGINT'):
        signal.signal(getattr(signal, name), interrupt)
    if subprocess.run(['docker', 'image', 'inspect', IMAGE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(['docker', 'build', '-t', IMAGE, '-'], input='FROM rust:1.98.1-bookworm\nRUN rustup target add x86_64-linux-android aarch64-linux-android\n', text=True)
    libs = ROOT / 'apps/android/app/src/main/jniLibs'
    libs.mkdir(parents=True, exist_ok=True)
    (ROOT / 'target').mkdir(exist_ok=True)
    script = '''set -eu
export PATH=/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
export CC_x86_64_linux_android=x86_64-linux-android29-clang
export AR_x86_64_linux_android=llvm-ar
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=x86_64-linux-android29-clang
export CC_aarch64_linux_android=aarch64-linux-android29-clang
export AR_aarch64_linux_android=llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android29-clang
cargo test --locked -p rtrust-android -p rtrust-engine
cargo build --locked --release -p rtrust-android --target x86_64-linux-android
cargo build --locked --release -p rtrust-android --target aarch64-linux-android
mkdir -p /out/x86_64 /out/arm64-v8a
cp target/x86_64-linux-android/release/librtrust_android.so /out/x86_64/
cp target/aarch64-linux-android/release/librtrust_android.so /out/arm64-v8a/
'''
    try:
        run(['docker', 'run', '--rm', '--name', NAME, '-v', f'{ROOT}:/work:ro,z', '-v', f'{ndk}:/ndk:ro,z',
             '-v', f'{libs}:/out:z', '-v', 'rtrust-android-target:/work/target', '-v', 'rtrust-android-cargo:/usr/local/cargo',
             '-w', '/work', IMAGE, 'sh', '-c', script], timeout=2400)
    finally:
        subprocess.run(['docker', 'rm', '-f', NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        run(['docker', 'run', '--rm', '--network', 'none', '-v', f'{libs}:/out:z', IMAGE, 'chown', '-hR', f'{os.getuid()}:{os.getgid()}', '/out'], timeout=60)
    run([args.gradle, '-p', str(ROOT / 'apps/android'), '--no-daemon', 'assembleDebug', 'assembleRelease', 'assembleDebugAndroidTest', 'lintDebug'], env=env, timeout=1200)
    run(['python3', 'ci/android_smoke.py', '--adb', str(sdk / 'platform-tools/adb'), '--serial', args.serial], cwd=ROOT, env=env)
    for protocol in ('trusttunnel','hysteria2','amneziawg'):
        print('Android network protocol:',protocol,flush=True)
        if protocol == 'hysteria2':
            # Download and verify the pinned tool before timing server readiness.
            # A cold release download is not an endpoint startup failure.
            from hysteria_interop import binary
            binary()
        if protocol == 'amneziawg':
            # Likewise a cold image pull and module download for the fixture peer.
            from amneziawg_server import binary
            binary()
        fixture = subprocess.Popen(['python3', 'ci/android_fixture.py','--protocol',protocol], cwd=ROOT)
        try:
            for _ in range(120):
                if fixture.poll() is not None: raise RuntimeError('Android fixture failed to start')
                if (ROOT / '.ci-android/ready').exists(): break
                time.sleep(.5)
            else: raise RuntimeError('Android fixture readiness timeout')
            run(['python3', 'ci/android_network_e2e.py', '--adb', str(sdk / 'platform-tools/adb'), '--serial', args.serial], cwd=ROOT, env=env)
            if protocol == 'trusttunnel':
                run(['python3', 'ci/android_always_on_e2e.py', '--adb', str(sdk / 'platform-tools/adb'), '--serial', args.serial], cwd=ROOT, env=env)
        finally:
            fixture.terminate()
            try: fixture.wait(timeout=40)
            except subprocess.TimeoutExpired: fixture.kill(); fixture.wait()
    run(['python3', 'ci/android_process_death_e2e.py', '--adb', str(sdk / 'platform-tools/adb'), '--serial', args.serial], cwd=ROOT, env=env)
    run(['python3', 'ci/android_upgrade_e2e.py', '--adb', str(sdk / 'platform-tools/adb'), '--serial', args.serial, '--gradle', args.gradle], cwd=ROOT, env=env)
    dist = ROOT / 'dist/android'
    dist.mkdir(parents=True, exist_ok=True)
    # Publish only product APK. Test APK is intentionally not a user download.
    shutil.copy2(ROOT / 'apps/android/app/build/outputs/apk/debug/app-debug.apk', dist / 'R-TrustTunnel-Android-debug.apk')
    shutil.copy2(ROOT / 'apps/android/app/build/outputs/apk/release/app-release-unsigned.apk', dist / 'R-TrustTunnel-Android-unsigned.apk')

if __name__ == '__main__':
    main()
