"""Installer lifecycle contract in a disposable root container, with fake systemd.
No actual system service or network is started. Run only before installing one.
"""
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile

assert os.geteuid() == 0 and pathlib.Path('/.dockerenv').exists()
ROOT = pathlib.Path(__file__).resolve().parents[1]
service = pathlib.Path('/usr/libexec/rtrust/rtrust-service')
assert not service.exists(), 'Existing installation must not be touched'
assert not pathlib.Path('/run/rtrust/control.sock').exists()
markers = [pathlib.Path(p) for p in ('/run/rtrust/full.json', '/run/rtrust/lease.json', '/var/lib/rtrust/always-on.rtrust')]
assert not any(p.exists() or p.is_symlink() for p in markers)
pathlib.Path('/dev/net').mkdir(exist_ok=True)
if not pathlib.Path('/dev/net/tun').exists():
    os.mknod('/dev/net/tun', stat.S_IFCHR | 0o600, os.makedev(10, 200))
with tempfile.TemporaryDirectory(prefix='rtrust-installer-') as directory:
    work = pathlib.Path(directory)
    log = work/'systemctl.log'
    fake = work/'systemctl'
    fake.write_text('''#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$RTRUST_TEST_LOG"
case "$1" in
 list-units) printf 'rtrust-service@1000.service loaded active running test\\n';;
 cat) exit 0;;
 stop)
   test "$(cat /usr/libexec/rtrust/rtrust-service)" = old
   if [ "${RTRUST_TEST_RACE:-0}" = 1 ]; then touch /run/rtrust/full.json; fi
   ;;
esac
''')
    fake.chmod(0o755)
    binary = work/'candidate'
    binary.write_text('new\n'); binary.chmod(0o755)
    service.parent.mkdir(parents=True, exist_ok=True)
    for marker in markers: marker.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PATH=str(work)+':'+os.environ['PATH'], RTRUST_TEST_LOG=str(log))
    def run(race=False):
        return subprocess.run(['sh', str(ROOT/'scripts/install-linux-service.sh'), '1000', str(binary)], env=dict(env, RTRUST_TEST_RACE=str(int(race))), text=True, capture_output=True)
    try:
        for marker in markers:
            service.write_text('old\n'); marker.touch(); log.write_text('')
            result=run()
            assert result.returncode != 0, result.stdout
            assert service.read_text() == 'old\n'
            assert log.read_text() == '', 'Active VPN must be refused before systemd operations'
            marker.unlink()
        print('PASS active/full/selected/always-on states refuse replacement', flush=True)
        service.write_text('old\n'); log.write_text('')
        result=run(race=True)
        assert result.returncode != 0
        assert service.read_text() == 'old\n'
        assert 'start rtrust-service@1000.service' in log.read_text()
        markers[0].unlink()
        print('PASS connection race retains old binary and restarts old service', flush=True)
        log.write_text('')
        result=run()
        assert result.returncode == 0, result.stderr
        assert service.read_text() == 'new\n'
        assert 'stop rtrust-service@1000.service' in log.read_text()
        assert 'restart rtrust-service@1000.service' in log.read_text()
        print('PASS idle upgrade stops old executable before replacement', flush=True)
    finally:
        for marker in markers: marker.unlink(missing_ok=True)
        service.unlink(missing_ok=True)
        for path in ('/etc/systemd/system/rtrust-service@.service','/etc/systemd/system/rtrust-boot-guard@.service','/etc/systemd/system/NetworkManager.service.d/rtrust-boot-guard.conf','/etc/systemd/system/systemd-networkd.service.d/rtrust-boot-guard.conf'):
            pathlib.Path(path).unlink(missing_ok=True)
