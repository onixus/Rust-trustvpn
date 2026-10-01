#!/usr/bin/env python3
"""Exercise VpnService against ci/android_fixture.py on an isolated emulator.

Shell-granted VPN consent is a test prerequisite, not proof of the human consent
flow. No production APK exposes fixture injection or command receivers.
"""
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
        p.error('Network acceptance is restricted to an isolated emulator')
    adb = [args.adb, '-s', args.serial]
    def run(*cmd, **kwargs):
        return subprocess.run([*adb, *cmd], check=True, timeout=180, **kwargs)
    package = 'org.rtrusttunnel.android'
    source = ROOT / '.ci-android/client.json'
    if not source.is_file():
        p.error('Start ci/android_fixture.py first')
    run('shell', 'pm', 'grant', package, 'android.permission.POST_NOTIFICATIONS')
    run('shell', 'appops', 'set', package, 'ACTIVATE_VPN', 'allow')
    run('shell', "run-as org.rtrusttunnel.android sh -c 'cat > cache/vpn-fixture.json'", input=source.read_bytes(), stdout=subprocess.DEVNULL)
    result = run('shell', 'am', 'instrument', '-w', '-r', '-e', 'network', 'true', package + '.test/' + package + '.SmokeInstrumentation', capture_output=True, text=True)
    print(result.stdout)
    if 'PASS: VPN IPv4/IPv6' not in result.stdout or 'INSTRUMENTATION_CODE: -1' not in result.stdout or 'FAIL:' in result.stdout:
        raise SystemExit('Android network acceptance failed')

if __name__ == '__main__': main()
