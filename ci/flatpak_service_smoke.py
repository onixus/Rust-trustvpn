"""Authenticated Flatpak FD transport in a disposable container, without VPN.

Requires a system bus with deploy/org.rtrusttunnel.Service.conf, a non-root test
account, and an installed Flatpak accessible through --installation. Never run
against a user's actual service or network namespace.
"""
import argparse
import os
import pathlib
import pwd
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--installation', required=True)
parser.add_argument('--user', required=True)
args = parser.parse_args()
assert os.geteuid() == 0 and pathlib.Path('/.dockerenv').exists(), 'Disposable root container required'
uid = pwd.getpwnam(args.user).pw_uid
assert uid != 0
assert not pathlib.Path('/run/rtrust/control.sock').exists(), 'Existing service must not be touched'
command = ['dbus-run-session', '--', 'flatpak', 'run',
           '--installation='+args.installation, 'org.rtrusttunnel.Native', '--ci-service-smoke']
with tempfile.TemporaryFile(mode='w+') as log:
    service = subprocess.Popen(['target/release/rtrust-service', str(uid)],
                               env=dict(os.environ, RTRUST_DBUS='1'), stdout=log, stderr=log)
    try:
        deadline = time.monotonic()+10
        while True:
            result = subprocess.run(['runuser', '-u', args.user, '--', 'env',
                                     'XDG_RUNTIME_DIR=/run/user/'+str(uid), *command],
                                    capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                assert 'PASS authenticated service channel' in result.stdout
                break
            if service.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError(result.stderr[-3000:])
            time.sleep(.1)
        print('PASS unprivileged Flatpak → root D-Bus broker → private FD → maintenance lease', flush=True)
        rejected = subprocess.run(command, capture_output=True, text=True, timeout=15)
        assert rejected.returncode != 0 and 'VPN broker rejected this desktop user' in rejected.stderr
        print('PASS wrong UID rejected inside real Flatpak sandbox', flush=True)
    finally:
        service.terminate()
        try:
            service.wait(timeout=10)
        except subprocess.TimeoutExpired:
            service.kill()
            service.wait(timeout=5)
