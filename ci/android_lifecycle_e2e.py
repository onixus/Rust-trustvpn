#!/usr/bin/env python3
"""Run real STOP/START lifecycle acceptance in an isolated emulator-only package.

Uses TEST-NET synthetic endpoints and app-only routing. This proves service/TUN
cleanup and request ordering, not connected transport or absence of leaks.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'org.rtrusttunnel.android.lifecycle_test'
TEST_PACKAGE = PACKAGE + '.test'
RUNNER = TEST_PACKAGE + '/org.rtrusttunnel.android.SmokeInstrumentation'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--gradle', default=os.environ.get('GRADLE', 'gradle'))
    args = parser.parse_args()
    if not re.fullmatch(r'emulator-[0-9]+', args.serial):
        parser.error('Only an explicitly selected emulator serial is accepted')
    adb = [args.adb, '-s', args.serial]

    def run(*command, timeout=180):
        return subprocess.run([*adb, *command], check=True, capture_output=True,
                              text=True, timeout=timeout).stdout.strip()

    def installed(package):
        return 'package:' + package in run('shell', 'pm', 'list', 'packages', package).splitlines()

    if run('shell', 'getprop', 'ro.kernel.qemu') != '1':
        parser.error('Selected device must report an emulator kernel')
    if run('shell', 'settings', 'get', 'secure', 'always_on_vpn_app') not in ('', 'null'):
        parser.error('Emulator has an Always-on VPN; refusing to change it')
    # Observe only: never stop another package or alter its VPN settings.
    connectivity = run('shell', 'dumpsys', 'connectivity')
    if re.search(r'Transports: [A-Z_|]*\bVPN\b', connectivity):
        parser.error('Emulator has an active VPN; lifecycle test requires an idle VPN slot')
    if any(installed(package) for package in (PACKAGE, TEST_PACKAGE)):
        parser.error('Reserved lifecycle test package already installed; refusing to replace its data')

    subprocess.run([args.gradle, '-p', str(ROOT / 'apps/android'), '--no-daemon',
                    '-PrtrustApplicationId=' + PACKAGE, 'assembleDebug',
                    'assembleDebugAndroidTest'], check=True, timeout=1200)
    outputs = ROOT / 'apps/android/app/build/outputs/apk'
    apks = (outputs / 'debug/app-debug.apk', outputs / 'androidTest/debug/app-debug-androidTest.apk')
    try:
        for apk in apks:
            run('install', str(apk))
        run('shell', 'pm', 'grant', PACKAGE, 'android.permission.POST_NOTIFICATIONS')
        run('shell', 'appops', 'set', PACKAGE, 'ACTIVATE_VPN', 'allow')
        output = run('shell', 'am', 'instrument', '-w', '-r', '-e', 'lifecycle', '1', RUNNER)
        print(output, flush=True)
        if ('PASS: immediate STOP/START' not in output
                or 'INSTRUMENTATION_CODE: -1' not in output or 'FAIL:' in output):
            raise RuntimeError('Android real service lifecycle acceptance failed')
    finally:
        # Only packages installed by this invocation are owned by this test.
        # Force-stop bounds cleanup even if instrumentation failed inside native code.
        if installed(PACKAGE):
            run('shell', 'am', 'force-stop', PACKAGE, timeout=30)
        for package in (TEST_PACKAGE, PACKAGE):
            if installed(package):
                run('uninstall', package, timeout=60)
        if any(installed(package) for package in (PACKAGE, TEST_PACKAGE)):
            raise RuntimeError('Isolated lifecycle test package cleanup failed')
    print('PASS: five real STOP/START cycles; latest profile, TUN/callback replacement and native cleanup; isolated packages removed', flush=True)


if __name__ == '__main__':
    main()
