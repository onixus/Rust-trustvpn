#!/usr/bin/env python3
"""A kill_switch = "always_on" profile under real system Always-on, on an isolated emulator.

Drives AOSP Settings (English UI) to switch Always-on VPN and "Block connections
without VPN". The profile must be refused without lockdown and connect with it,
both for the system's own Always-on start and for an app start. Requires
ci/android_fixture.py; Always-on is switched off again on every exit path.
"""
import argparse
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'org.rtrusttunnel.android'
LABEL = 'R-TrustTunnel'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', default='adb')
    p.add_argument('--serial', required=True)
    args = p.parse_args()
    if not args.serial.startswith('emulator-'):
        p.error('Always-on acceptance is restricted to an isolated emulator')
    source = ROOT / '.ci-android/client.json'
    if not source.is_file():
        p.error('Start ci/android_fixture.py first')
    adb = [args.adb, '-s', args.serial]

    def run(*cmd, **kwargs):
        return subprocess.run([*adb, *cmd], check=True, timeout=180, **kwargs)
    def shell(command):
        return run('shell', command, capture_output=True, text=True).stdout.strip()
    def instrument(phase, fixture=False):
        if fixture:
            run('shell', f"run-as {PACKAGE} sh -c 'cat > cache/vpn-fixture.json'", input=source.read_bytes(), stdout=subprocess.DEVNULL)
        out = run('shell', 'am', 'instrument', '-w', '-r', '-e', 'always_on', phase, f'{PACKAGE}.test/{PACKAGE}.SmokeInstrumentation', capture_output=True, text=True).stdout
        print(out, flush=True)
        if f'PASS: always-on {phase}' not in out or 'INSTRUMENTATION_CODE: -1' not in out or 'FAIL:' in out:
            raise SystemExit(f'Android Always-on acceptance failed: {phase}')
    def nodes():
        root = ET.fromstring(run('exec-out', 'uiautomator', 'dump', '/dev/tty', capture_output=True, text=True).stdout.split('UI hierchary dumped')[0].strip())
        return list(root.iter('node'))
    def center(node):
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', node.get('bounds')))
        return str((x1 + x2) // 2), str((y1 + y2) // 2)
    def tap(node):
        run('shell', 'input', 'tap', *center(node)); time.sleep(1.5)
    def find(predicate, what):
        for _ in range(10):
            match = next((n for n in nodes() if predicate(n)), None)
            if match is not None: return match
            time.sleep(.5)
        raise SystemExit(f'Settings UI element not found: {what}')
    def vpn_settings():
        run('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP'); run('shell', 'wm', 'dismiss-keyguard')
        run('shell', 'am', 'start', '-S', '-W', '-a', 'android.settings.VPN_SETTINGS', stdout=subprocess.DEVNULL)
        time.sleep(1.5)
        # The app row is a parent holding both the label and its gear button.
        for row in nodes():
            kids = list(row.iter('node'))
            if any(k.get('text') == LABEL for k in kids):
                gear = next((k for k in kids if k.get('resource-id', '').endswith('/settings_button')), None)
                if gear is not None and not any(k.get('resource-id', '').endswith('/recycler_view') for k in kids):
                    tap(gear); return
        raise SystemExit('VPN settings row not found')
    def setting(name):
        return shell(f'settings get secure {name}')
    def set_mode(always_on, lockdown):
        vpn_settings()
        for title, wanted in (('Always-on VPN', always_on), ('Block connections without VPN', lockdown)):
            if title != 'Always-on VPN' and not always_on: break  # lockdown depends on Always-on
            label = find(lambda n: n.get('text') == title, title)
            switch = None
            for row in nodes():
                kids = list(row.iter('node'))
                if any(k.get('text') == title for k in kids) and sum(k.get('resource-id', '').endswith('id/title') for k in kids) == 1:
                    switch = next((k for k in kids if k.get('checkable') == 'true'), switch)
            if switch is None: raise SystemExit(f'Switch not found: {title}')
            if (switch.get('checked') == 'true') != wanted:
                tap(label)
                confirm = next((n for n in nodes() if n.get('resource-id') == 'android:id/button1'), None)
                if confirm is not None: tap(confirm)
        app, locked = setting('always_on_vpn_app'), setting('always_on_vpn_lockdown')
        if (app == PACKAGE) != always_on or (locked == '1') != (always_on and lockdown):
            raise SystemExit(f'Always-on settings not applied: app={app} lockdown={locked}')
        run('shell', 'input', 'keyevent', 'KEYCODE_HOME')
    def vpn_up():
        # A VPN agent lists its underlying transports too, e.g. "Transports: CELLULAR|VPN".
        return re.search(r'Transports: [A-Z_|]*\bVPN\b', shell('dumpsys connectivity | grep NetworkAgentInfo')) is not None

    if setting('always_on_vpn_app') not in ('', 'null'):
        raise SystemExit('Emulator already has an Always-on VPN; refusing to change it')
    run('shell', 'pm', 'grant', PACKAGE, 'android.permission.POST_NOTIFICATIONS')
    run('shell', 'appops', 'set', PACKAGE, 'ACTIVATE_VPN', 'allow')
    instrument('seed', fixture=True)
    try:
        instrument('refused')
        set_mode(True, False)
        # Enabling Always-on makes the system start the service; it must refuse.
        time.sleep(5)
        if vpn_up(): raise SystemExit('System Always-on start without lockdown left a VPN up')
        instrument('refused')
        set_mode(True, True)
        for _ in range(60):
            if vpn_up(): break
            time.sleep(.5)
        else: raise SystemExit('System Always-on start with lockdown did not establish')
        # The TUN is established before the lockdown check; a refusal closes it at once.
        time.sleep(5)
        if not vpn_up(): raise SystemExit('System Always-on start with lockdown was refused')
        instrument('connected', fixture=True)
        print('PASS: require_lockdown refused without Always-on/lockdown, connected under system Always-on with lockdown', flush=True)
    finally:
        set_mode(False, False)
        instrument('finish')

if __name__ == '__main__': main()
