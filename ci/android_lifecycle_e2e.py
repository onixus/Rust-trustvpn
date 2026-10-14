#!/usr/bin/env python3
"""Run real STOP/START lifecycle acceptance in an isolated emulator-only package.

Uses TEST-NET synthetic endpoints and app-only routing. This proves service/TUN
cleanup and request ordering, not connected transport or absence of leaks.
"""
import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def application_id():
    return 'org.rtrusttunnel.android.run_' + secrets.token_hex(16) + '.lifecycle_test'


@contextmanager
def emulator_lock(serial, timeout):
    # Stable across workspaces/TMPDIR overrides. Never delete or steal a held lock.
    directory = Path('/tmp') / ('rtrust-android-lifecycle-' + str(os.getuid()))
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError('Lifecycle lock directory is not private and owned by this user')
    fd = os.open(directory / (serial + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    acquired = False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError('Lifecycle lock file is not private and owned by this user')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Selected emulator lifecycle test lock is busy')
                time.sleep(min(.1, remaining))
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--gradle', default=os.environ.get('GRADLE', 'gradle'))
    parser.add_argument('--lock-timeout', type=float, default=30)
    args = parser.parse_args()
    if not re.fullmatch(r'emulator-[0-9]+', args.serial):
        parser.error('Only an explicitly selected emulator serial is accepted')
    if not 0 <= args.lock_timeout <= 60:
        parser.error('Lock timeout must be between zero and 60 seconds')
    adb = [args.adb, '-s', args.serial]
    package = application_id()
    test_package = package + '.test'
    packages = (package, test_package)
    runner = test_package + '/org.rtrusttunnel.android.SmokeInstrumentation'

    def run(*command, timeout=180):
        return subprocess.run([*adb, *command], check=True, capture_output=True,
                              text=True, timeout=timeout).stdout.strip()

    def installed(name):
        return 'package:' + name in run('shell', 'pm', 'list', 'packages', name).splitlines()

    def idle_vpn():
        if run('shell', 'getprop', 'ro.kernel.qemu') != '1':
            parser.error('Selected device must report an emulator kernel')
        if run('shell', 'settings', 'get', 'secure', 'always_on_vpn_app') not in ('', 'null'):
            parser.error('Emulator has an Always-on VPN; refusing to change it')
        # Observe only: never stop another package or alter its VPN settings.
        connectivity = run('shell', 'dumpsys', 'connectivity')
        if re.search(r'Transports: [A-Z_|]*\bVPN\b', connectivity):
            parser.error('Emulator has an active VPN; lifecycle test requires an idle VPN slot')

    def absent_packages():
        if any(installed(name) for name in packages):
            parser.error('Invocation package already installed; refusing to replace its data')

    with emulator_lock(args.serial, args.lock_timeout):
        idle_vpn()
        absent_packages()
        subprocess.run([args.gradle, '-p', str(ROOT / 'apps/android'), '--no-daemon',
                        '-PrtrustApplicationId=' + package, 'assembleDebug',
                        'assembleDebugAndroidTest'], check=True, timeout=1200)
        # A long Gradle build is not an authority to displace a subsequently started VPN.
        idle_vpn()
        absent_packages()
        outputs = ROOT / 'apps/android/app/build/outputs/apk'
        apks = (outputs / 'debug/app-debug.apk', outputs / 'androidTest/debug/app-debug-androidTest.apk')
        owned = []
        try:
            for name, apk in zip(packages, apks):
                output = run('install', str(apk))
                if 'Success' not in output.splitlines():
                    raise RuntimeError('Isolated APK installation was not confirmed')
                owned.append(name)
            run('shell', 'pm', 'grant', package, 'android.permission.POST_NOTIFICATIONS')
            run('shell', 'appops', 'set', package, 'ACTIVATE_VPN', 'allow')
            idle_vpn()
            if not all(installed(name) for name in owned):
                raise RuntimeError('Owned lifecycle package disappeared before instrumentation')
            output = run('shell', 'am', 'instrument', '-w', '-r', '-e', 'lifecycle', '1', runner)
            print(output, flush=True)
            if ('PASS: immediate STOP/START' not in output
                    or 'INSTRUMENTATION_CODE: -1' not in output or 'FAIL:' in output):
                raise RuntimeError('Android real service lifecycle acceptance failed')
        finally:
            # A failed/timed-out install does not grant ownership. Only acknowledged
            # successful installations are force-stopped/uninstalled by this invocation.
            cleanup_errors = []
            for name in reversed(owned):
                try:
                    if installed(name):
                        run('shell', 'am', 'force-stop', name, timeout=30)
                        run('uninstall', name, timeout=60)
                    if installed(name):
                        raise RuntimeError('Owned lifecycle package remained installed')
                except Exception as error:
                    cleanup_errors.append(type(error).__name__)
            if cleanup_errors:
                raise RuntimeError('Confirmed owned lifecycle package cleanup failed')
    print('PASS: five real STOP/START cycles; latest profile, TUN/callback replacement and native cleanup; owned isolated packages removed', flush=True)


if __name__ == '__main__':
    main()
