#!/usr/bin/env python3
"""Verify app reinstall and increasing versionCode preserve default and Keystore."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', default='adb'); p.add_argument('--serial', required=True)
    p.add_argument('--gradle', default=os.environ.get('GRADLE', 'gradle'))
    args = p.parse_args()
    if not args.serial.startswith('emulator-'): p.error('Only an isolated emulator is accepted')
    adb = [args.adb, '-s', args.serial]
    package = 'org.rtrusttunnel.android'
    def run(*cmd): return subprocess.check_output([*adb, *cmd], text=True, timeout=180)
    def phase(name):
        output = run('shell', 'am', 'instrument', '-w', '-r', '-e', 'upgrade', name, package + '.test/' + package + '.SmokeInstrumentation')
        print(output)
        assert 'PASS: upgrade ' + name in output and 'INSTRUMENTATION_CODE: -1' in output
    apk = ROOT / 'apps/android/app/build/outputs/apk/debug/app-debug.apk'
    phase('seed')
    try:
        run('shell', 'am', 'force-stop', package)
        print(run('install', '-r', str(apk))); phase('check')
        before = run('shell', 'dumpsys', 'package', package)
        import re
        version = int(re.search(r'versionCode=(\d+)', before).group(1))
        subprocess.run([args.gradle, '-p', str(ROOT / 'apps/android'), '--no-daemon', '-PrtrustVersionCode=' + str(version + 1), 'assembleDebug'], check=True, timeout=600)
        print(run('install', '-r', str(apk)))
        after = run('shell', 'dumpsys', 'package', package)
        assert int(re.search(r'versionCode=(\d+)', after).group(1)) == version + 1
        phase('check')
    finally:
        phase('finish')
    print('PASS: process restart, same-version reinstall and higher-version APK upgrade')

if __name__ == '__main__': main()
