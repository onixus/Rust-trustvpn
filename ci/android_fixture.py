#!/usr/bin/env python3
"""Ephemeral official endpoint for the Android emulator; loopback publication only.

Run from repository root, then stop by creating .ci-android/stop. Never changes
host routes or existing VPNs. Secrets and all Docker resources expire in 15 min.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path('.ci-android').resolve()
NAME = 'rtrust-android-fixture-' + secrets.token_hex(4)
IP = '10.231.243.2'
SHA = '91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7'

def run(*args, **kwargs):
    return subprocess.check_output(args, timeout=90, **kwargs).decode().strip()

def main():
    ROOT.mkdir(mode=0o700, exist_ok=True)
    if (ROOT / 'ready').exists():
        raise SystemExit('An Android fixture is already active')
    (ROOT / 'stop').unlink(missing_ok=True)
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, lambda *_: (ROOT / 'stop').touch())
    cache = Path('.ci-tools/linux-endpoint')
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / 'endpoint.tar.gz'
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA:
        with urllib.request.urlopen('https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-x86_64.tar.gz', timeout=60) as response:
            archive.write_bytes(response.read(32 * 1024 * 1024))
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == SHA
    with tarfile.open(archive) as tar:
        member = next(m for m in tar if m.name.endswith('/trusttunnel_endpoint'))
        binary = ROOT / 'trusttunnel_endpoint'; binary.write_bytes(tar.extractfile(member).read()); binary.chmod(0o755)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', 'key.pem', '-out', 'cert.pem'], cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    token, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    (ROOT / 'control-token').write_text(token)
    (ROOT / 'vpn.toml').write_text('listen_address="0.0.0.0:4433"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n')
    (ROOT / 'hosts.toml').write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
    (ROOT / 'credentials.toml').write_text(f'[[client]]\nusername="interop"\npassword="{password}"\n')
    for name in ['key.pem', 'control-token', 'credentials.toml']: (ROOT / name).chmod(0o600)
    network = container = False
    try:
        run('docker', 'network', 'create', '--subnet', '10.231.243.0/29', '--ipv6', '--subnet', 'fd00:5254:243::/64', NAME); network = True
        run('docker', 'run', '-d', '--name', NAME, '--network', NAME, '--ip', IP, '--ip6', 'fd00:5254:243::2', '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--security-opt=no-new-privileges', '--read-only', '--tmpfs', '/tmp', '-p', '127.0.0.1::4433/tcp', '-v', f'{ROOT}:/fixture:ro', '-v', f'{Path("ci/windows_fixture_server.py").resolve()}:/server.py:ro', 'python:3.11-slim', 'python', '/server.py'); container = True
        port = int(run('docker', 'port', NAME, '4433/tcp').rsplit(':', 1)[1])
        tls = ssl.create_default_context(cafile=str(ROOT / 'cert.pem'))
        tls.set_alpn_protocols(['h2'])
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.5) as tcp:
                    with tls.wrap_socket(tcp, server_hostname='localhost'): break
            except OSError: time.sleep(.2)
        else: raise RuntimeError('Android fixture endpoint did not start')
        data = {'base': dict(hostname='localhost', addresses=[f'10.0.2.2:{port}'], username='interop', password=password, certificate=(ROOT / 'cert.pem').read_text(), upstream_protocol='http3', dns_upstreams=[IP]), 'target': IP, 'target6': 'fd00:5254:243::2', 'control': f'http://{IP}:8082', 'control_token': token}
        manifest = ROOT / 'client.json'; manifest.write_text(json.dumps(data)); manifest.chmod(0o600)
        (ROOT / 'ready').write_text(NAME)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline and not (ROOT / 'stop').exists():
            if run('docker', 'inspect', '--format', '{{.State.Running}}', NAME) != 'true':
                print(run('docker', 'logs', '--tail', '30', NAME))
                raise RuntimeError('Android fixture container exited')
            time.sleep(1)
    finally:
        if container: subprocess.run(['docker', 'rm', '-f', NAME], timeout=30, stdout=subprocess.DEVNULL)
        if network: subprocess.run(['docker', 'network', 'rm', NAME], timeout=30, stdout=subprocess.DEVNULL)
        for name in ['key.pem', 'credentials.toml', 'control-token', 'client.json', 'ready']: (ROOT / name).unlink(missing_ok=True)

if __name__ == '__main__': main()
