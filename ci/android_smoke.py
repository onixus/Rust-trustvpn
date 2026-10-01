#!/usr/bin/env python3
"""Install and exercise a test APK on an explicitly selected Android emulator."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', default='adb')
    p.add_argument('--serial', required=True)
    args = p.parse_args()
    if not args.serial.startswith('emulator-'):
        p.error('This test changes app data and only accepts an emulator serial')
    adb = [args.adb, '-s', args.serial]
    def run(*cmd):
        return subprocess.check_output([*adb, *cmd], text=True, timeout=180)
    app = ROOT / 'apps/android/app/build/outputs/apk/debug/app-debug.apk'
    test = ROOT / 'apps/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'
    for package in ['org.rtrusttunnel.android.test', 'org.rtrusttunnel.android']:
        if ('package:' + package) in run('shell', 'pm', 'list', 'packages', package).splitlines():
            print(run('uninstall', package))
    for apk in [app, test]:
        print(run('install', '-r', str(apk)))
    output = run('shell', 'am', 'instrument', '-w', '-r', 'org.rtrusttunnel.android.test/org.rtrusttunnel.android.SmokeInstrumentation')
    print(output)
    if 'PASS: JNI codec' not in output or 'INSTRUMENTATION_CODE: -1' not in output or 'FAIL:' in output:
        raise SystemExit('Android instrumentation failed')
    print(run('shell', 'am', 'start', '-W', '-n', 'org.rtrusttunnel.android/.MainActivity'))

if __name__ == '__main__':
    main()
