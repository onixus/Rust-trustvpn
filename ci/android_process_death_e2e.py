#!/usr/bin/env python3
"""Verify Always-on recovery after the VPN process dies on an isolated emulator.

Android does not restart a VpnService whose process died (see docs/android.md).
This drives the AOSP Settings screen to enable system Always-on and lockdown,
kills the process by Java crash, native abort and SIGKILL, and checks that
lockdown keeps blocking, that opening the app reconnects, and that it does not
reconnect once this app is no longer the Always-on VPN. Requires a debuggable
APK (run-as) and an English AOSP Settings UI.
"""
import argparse
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'org.rtrusttunnel.android'
PROBE = 'toybox nc -w 3 1.1.1.1 443 </dev/null >/dev/null 2>&1 && echo open || echo blocked'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', default='adb')
    p.add_argument('--serial', required=True)
    args = p.parse_args()
    if not args.serial.startswith('emulator-'):
        p.error('Always-on acceptance is restricted to an isolated emulator')
    adb = [args.adb, '-s', args.serial]
    def sh(command, check=True):
        result = subprocess.run([*adb, 'shell', command], capture_output=True, text=True, timeout=180)
        if check and result.returncode: raise RuntimeError(f'adb shell failed: {command}\n{result.stderr}')
        return result.stdout.strip()
    def wait(condition, timeout, message):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if condition(): return
            time.sleep(1)
        raise SystemExit('FAIL: ' + message)
    def pid(): return sh('pidof ' + PACKAGE, check=False)
    def vpn_up(): return f'VPN CONNECTED extra: VPN:{PACKAGE}' in sh('dumpsys connectivity')
    def instrument(phase):
        output = sh(f'am instrument -w -r -e recovery {phase} {PACKAGE}.test/{PACKAGE}.SmokeInstrumentation')
        if f'PASS: recovery {phase}' not in output or 'INSTRUMENTATION_CODE: -1' not in output: raise SystemExit(output)
    def nodes():
        root = ET.fromstring(sh('uiautomator dump /sdcard/rtrust-ui.xml >/dev/null && cat /sdcard/rtrust-ui.xml'))
        return list(root.iter('node'))
    def tap(node):
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', node.get('bounds')))
        sh(f'input tap {(x1 + x2) // 2} {(y1 + y2) // 2}'); time.sleep(2)
    def setting(name): return sh('settings get secure ' + name)
    def always_on(enable):
        close = [n for n in nodes() if n.get('text') == 'Close app']
        if close: tap(close[0])
        sh('am force-stop com.android.settings')  # Open the VPN list, not a resumed sub-page.
        sh('am start -W -a android.settings.VPN_SETTINGS'); time.sleep(2)
        title = next(n for n in nodes() if n.get('text') == 'R-TrustTunnel')
        row = int(re.findall(r'\d+', title.get('bounds'))[1])
        gear = next(n for n in nodes() if n.get('resource-id', '').endswith('settings_button')
                    and int(re.findall(r'\d+', n.get('bounds'))[1]) <= row <= int(re.findall(r'\d+', n.get('bounds'))[3]))
        tap(gear)
        for index in ((0, 1) if enable else (0,)):
            switch = [n for n in nodes() if n.get('checkable') == 'true'][index]
            if (switch.get('checked') == 'true') != enable:
                tap(switch)
                confirm = [n for n in nodes() if n.get('text') == 'Turn on']
                if confirm: tap(confirm[0])
        sh('input keyevent HOME')
        state = (setting('always_on_vpn_app'), setting('always_on_vpn_lockdown'))
        if enable and state != (PACKAGE, '1'): raise SystemExit(f'FAIL: Always-on/lockdown not enabled: {state}')
        if not enable and state[0] == PACKAGE: raise SystemExit('FAIL: Always-on not disabled')

    def kill(method):
        # Whether Android restarts the service is a race (docs/android.md), so retry
        # until the process stays dead; that is the state recovery has to handle.
        for attempt in range(4):
            # An explicit app start resets Android's crash time; without it a second crash
            # within two minutes shows a "keeps stopping" dialog instead of killing the process.
            sh(f'am start -W -n {PACKAGE}/.MainActivity'); wait(vpn_up, 30, 'VPN down before ' + method)
            sh('input keyevent HOME'); time.sleep(2)
            victim = pid()
            if not victim: raise SystemExit('FAIL: VPN process missing before ' + method)
            if method == 'am crash': sh('am crash ' + PACKAGE)
            else: sh(f'run-as {PACKAGE} kill -{method[3:]} {victim}')
            wait(lambda: pid() != victim, 20, f'process survived {method}')
            time.sleep(10)
            if not pid() and not vpn_up(): return
            wait(vpn_up, 30, f'platform restart after {method} did not bring the VPN up')
            print(f'{method}: Android restarted the service (attempt {attempt + 1}); retrying')
        raise SystemExit(f'FAIL: Android restarted the service after every {method}')

    sh('pm grant ' + PACKAGE + ' android.permission.POST_NOTIFICATIONS')
    sh('appops set ' + PACKAGE + ' ACTIVATE_VPN allow')
    sh('am force-stop ' + PACKAGE)
    if setting('always_on_vpn_app') == PACKAGE: always_on(False)
    direct = sh(PROBE)
    print('Direct baseline before lockdown:', direct)
    instrument('seed')
    try:
        always_on(True)
        wait(vpn_up, 30, 'system Always-on did not start the VPN')
        for method in ('am crash', 'SIGKILL', 'SIGABRT'):
            kill(method)
            if setting('always_on_vpn_lockdown') != '1': raise SystemExit('FAIL: lockdown setting lost after ' + method)
            if direct == 'open' and sh(PROBE) != 'blocked': raise SystemExit('FAIL: direct traffic leaked after ' + method)
            sh(f'am start -W -n {PACKAGE}/.MainActivity')
            wait(vpn_up, 30, 'opening the app did not restore the Always-on VPN after ' + method)
            sh('input keyevent HOME'); time.sleep(2)
            print(f'PASS: {method} kept lockdown and the app restored the VPN')
        kill('SIGKILL')
        always_on(False)
        sh(f'am start -W -n {PACKAGE}/.MainActivity'); time.sleep(8)
        if vpn_up(): raise SystemExit('FAIL: app reconnected although Always-on was disabled')
        sh('input keyevent HOME')
        print('PASS: no reconnect after Always-on was disabled')
    finally:
        if setting('always_on_vpn_app') == PACKAGE: always_on(False)
        sh('am force-stop ' + PACKAGE)
        instrument('finish')
    print('PASS: Always-on lockdown and app recovery after Java crash, native abort and SIGKILL')

if __name__ == '__main__': main()
