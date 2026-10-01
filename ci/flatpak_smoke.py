"""Exercise an installed candidate on a disposable Linux Wayland test host.

Install the bundle with flatpak --user first. Does not start a VPN connection.
"""
import argparse
import configparser
import os
import pathlib
import subprocess
import sys
import tempfile
import time

APP = 'org.rtrusttunnel.Native'
parser = argparse.ArgumentParser()
parser.add_argument('--installation')
args = parser.parse_args()
scope = '--installation='+args.installation if args.installation else '--user'
metadata = subprocess.check_output(
    ['flatpak', scope, 'info', '--show-permissions', APP], text=True)
permissions = configparser.ConfigParser()
permissions.read_string(metadata)
context = permissions['Context']
assert set(context.get('sockets', '').strip(';').split(';')) == {'wayland'}
assert not context.get('filesystems', ''), 'Unexpected host filesystem access'
assert not context.get('devices', ''), 'Unexpected device access'
assert permissions['System Bus Policy'] == {'org.rtrusttunnel.service': 'talk'}

with tempfile.TemporaryDirectory(prefix='rtrust-flatpak-smoke-') as directory:
    runtime = pathlib.Path(directory)
    runtime.chmod(0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=directory, WAYLAND_DISPLAY='rtrust-flatpak',
               XDG_SESSION_TYPE='wayland', WINIT_UNIX_BACKEND='wayland')
    env.pop('DISPLAY', None)
    env.pop('WAYLAND_SOCKET', None)
    log = runtime / 'weston.log'
    compositor = subprocess.Popen([
        'weston', '--backend=headless-backend.so', '--use-pixman',
        '--socket=rtrust-flatpak', '--idle-time=0', '--no-config', '--log='+str(log)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic()+15
        while not (runtime / 'rtrust-flatpak').exists():
            if compositor.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(log.read_text())
            time.sleep(.05)
        for mode in ('--ci-smoke', '--ci-settings-smoke', '--ci-portal-smoke'):
            result = subprocess.run([
                'dbus-run-session', '--', 'flatpak', 'run', scope,
                '--env=WAYLAND_DEBUG=1', APP, mode], env=env,
                text=True, capture_output=True, timeout=40)
            assert result.returncode == 0, result.stderr[-4000:]
            assert 'set_app_id("org.rtrusttunnel.Native")' in result.stderr
            print('PASS installed Flatpak Wayland '+mode, flush=True)
        if args.installation:
            subprocess.run(['dbus-run-session', '--', sys.executable,
                            'ci/linux_tray_smoke.py', '--flatpak-installation',
                            args.installation], env=env, check=True, timeout=35)
        assert compositor.poll() is None
    finally:
        compositor.terminate()
        try:
            compositor.wait(timeout=5)
        except subprocess.TimeoutExpired:
            compositor.kill()
            compositor.wait(timeout=5)
print('PASS sandbox permissions: Wayland only, no host files or devices')
