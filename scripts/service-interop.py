#!/usr/bin/env python3
"""Isolated Linux service/IPC/routing test. Disposable root Docker only.
Usage: python3 scripts/service-interop.py /path/to/trusttunnel_endpoint
"""
import contextlib
import http.server
import json
import os
import pathlib
import queue
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
NS = "rtrust-service-test"
SOCKET = "/run/rtrust/control.sock"
BODY = bytes(range(256)) * 2048

def command(*args, success=True):
    result = subprocess.run(args, capture_output=True, timeout=35)
    assert (result.returncode == 0) == success, result.stderr.decode(errors="replace")[-1200:]
    return result.stdout

def ns(*args, **kwargs):
    return command("ip", "netns", "exec", NS, *args, **kwargs)

def app(uid, *args, **kwargs):
    return ns("setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", *args, **kwargs)

def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("X-Peer", self.client_address[0])
        self.end_headers()
        self.wfile.write(BODY)
    def log_message(self, *args):
        pass

@contextlib.contextmanager
def client(profile, mode="--serve-tun", scope="198.18.0.1/32"):
    process = subprocess.Popen(["ip", "netns", "exec", NS, "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", str(ROOT / "target/debug/rtrust-inspect"), str(profile), mode, scope], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    def read_lines():
        for line in process.stdout:
            lines.put(line.strip())
        lines.put(None)
    threading.Thread(target=read_lines, daemon=True).start()
    try:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            line = lines.get(timeout=40)
            if line == "SERVICE connected":
                break
            if line is None:
                raise RuntimeError("IPC client startup failed: " + process.stderr.read()[-1000:])
        else:
            raise RuntimeError("IPC startup timeout")
        yield process, lines
    finally:
        stop(process)
        process.stdout.close()
        process.stderr.close()

def main():
    if os.geteuid() != 0 or not pathlib.Path("/.dockerenv").exists():
        raise SystemExit("Disposable root Docker container required")
    endpoint_binary = pathlib.Path(sys.argv[1]).resolve()
    command("ip", "netns", "add", NS)
    daemon = None
    endpoint = None
    server = None
    veth = False
    address = False
    try:
        command("ip", "link", "add", "rtrust-host", "type", "veth", "peer", "name", "rtrust-client")
        veth = True
        command("ip", "link", "set", "rtrust-client", "netns", NS)
        command("ip", "addr", "add", "10.99.0.1/30", "dev", "rtrust-host")
        command("ip", "link", "set", "rtrust-host", "up")
        ns("ip", "addr", "add", "10.99.0.2/30", "dev", "rtrust-client")
        ns("ip", "link", "set", "rtrust-client", "up")
        ns("ip", "link", "set", "lo", "up")
        ns("ip", "route", "add", "default", "via", "10.99.0.1")
        command("ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
        address = True
        server = http.server.ThreadingHTTPServer(("198.18.0.1", 0), HTTP)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://198.18.0.1:{server.server_port}/"
        def fetch(uid, peer):
            response = app(uid, "curl", "--noproxy", "*", "-sSf", "--max-time", "10", "-D", "-", url)
            headers, body = response.split(b"\r\n\r\n", 1)
            assert body == BODY and f"X-Peer: {peer}".encode() in headers, "wrong path or body"
        with tempfile.TemporaryDirectory(prefix="rtrust-service-") as directory:
            d = pathlib.Path(directory)
            d.chmod(0o711)
            command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"))
            (d / "vpn.toml").write_text('listen_address="10.99.0.1:8443"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n')
            (d / "hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (d / "credentials.toml").write_text('[[client]]\nusername="interop"\npassword="synthetic-service-test"\n')
            profile = d / "profile.json"
            profile.write_text(json.dumps(dict(schema_version=1, name="Isolated service test", endpoint=dict(hostname="localhost", addresses=["10.99.0.1:8443"], username="interop", password="synthetic-service-test", certificate=(d / "cert.pem").read_text(), upstream_protocol="http2"))))
            profile.chmod(0o600)
            os.chown(profile, 1000, 1000)
            with (d / "endpoint.log").open("wb") as endpoint_log, (d / "daemon.log").open("wb") as daemon_log:
                def start_endpoint():
                    p = subprocess.Popen([str(endpoint_binary), "vpn.toml", "hosts.toml", "--jobs", "2"], cwd=d, stdout=endpoint_log, stderr=endpoint_log)
                    for _ in range(100):
                        if p.poll() is not None:
                            raise RuntimeError("Endpoint exited during startup")
                        try:
                            with socket.create_connection(("10.99.0.1", 8443), timeout=0.1):
                                return p
                        except OSError:
                            time.sleep(0.05)
                    stop(p)
                    raise RuntimeError("Endpoint readiness timeout")
                endpoint = start_endpoint()
                def start_daemon():
                    p = subprocess.Popen(["ip", "netns", "exec", NS, os.environ.get("RTRUST_SERVICE_BINARY", str(ROOT / "target/debug/rtrust-service")), "1000"], stdout=daemon_log, stderr=daemon_log)
                    for _ in range(100):
                        if p.poll() is not None:
                            raise RuntimeError((d / "daemon.log").read_text()[-1000:])
                        try:
                            with socket.socket(socket.AF_UNIX) as s:
                                s.settimeout(0.2)
                                s.connect(SOCKET)
                                assert s.recv(1) == b"", "root caller unexpectedly authorized"
                            return p
                        except OSError:
                            time.sleep(0.05)
                    raise RuntimeError("Daemon readiness timeout")
                daemon = start_daemon()
                app(1000, "python3", "-c", '''
import socket,struct,json,time

def request(s):
    data=json.dumps({"version":2,"command":{"op":"PrepareUpdate"}}).encode()
    s.sendall(struct.pack("!I",len(data))+data)
    header=s.recv(4);size=struct.unpack("!I",header)[0]
    raw=b""
    while len(raw)<size:raw+=s.recv(size-len(raw))
    return json.loads(raw)["state"]
with socket.socket(socket.AF_UNIX) as first:
    first.settimeout(5);first.connect("/run/rtrust/control.sock")
    assert request(first)=="Idle"
    with socket.socket(socket.AF_UNIX) as second:
        second.settimeout(5);second.connect("/run/rtrust/control.sock")
        assert request(second)=="Error", "maintenance reservation must be exclusive"
time.sleep(.1)
''')
                print("PASS idle service maintenance reservation is exclusive and released on close",flush=True)
                fetch(1000, "10.99.0.2")
                # Authorized malformed/versioned requests cannot start a tunnel.
                app(1000, "python3", "-c", '''
import socket,struct,json
for request in (None, {"version":999,"command":{"op":"Status"}}):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5); s.connect("/run/rtrust/control.sock")
        if request is None:
            s.sendall(struct.pack("!I", 0xffffffff)); assert s.recv(1) == b""
        else:
            data=json.dumps(request).encode(); s.sendall(struct.pack("!I",len(data))+data)
            size=struct.unpack("!I",s.recv(4))[0]; response=json.loads(s.recv(size)); assert response["state"]=="Error"
''')
                with client(profile) as (process, _):
                    fetch(1000, "198.18.0.1")
                    fetch(1001, "10.99.0.2")
                    # Same-user second connection is rejected while the lease exists.
                    app(1000, "python3", "-c", '''
import socket,struct,json,sys
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(5); s.connect("/run/rtrust/control.sock")
    request={"version":2,"command":{"op":"Start","profile":json.load(open(sys.argv[1])),"networks":["198.18.0.1/32"]}}
    data=json.dumps(request).encode(); s.sendall(struct.pack("!I",len(data))+data)
    size=struct.unpack("!I",s.recv(4))[0]; assert json.loads(s.recv(size))["state"]=="Error"
''', str(profile))
                    journal = pathlib.Path("/run/rtrust/lease.json").read_text()
                    assert "synthetic-service-test" not in journal
                    stop(process)
                    assert process.returncode == 0, "Stop ACK failed"
                fetch(1000, "10.99.0.2")
                assert not pathlib.Path("/run/rtrust/lease.json").exists()
                print("PASS authenticated IPC, version/size limits, exclusive lease, per-UID routing, real TCP, Stop ACK/restore", flush=True)
                with client(profile) as (process, _):
                    fetch(1000, "198.18.0.1")
                    process.kill(); process.wait(timeout=5)
                    deadline = time.monotonic() + 10
                    while pathlib.Path("/run/rtrust/lease.json").exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    assert not pathlib.Path("/run/rtrust/lease.json").exists()
                    fetch(1000, "10.99.0.2")
                print("PASS client crash closes IPC lease and restores routes", flush=True)
                with client(profile) as (process, _):
                    fetch(1000, "198.18.0.1")
                    daemon.kill(); daemon.wait(timeout=5)
                    app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "2", url, success=False)
                    fetch(1001, "10.99.0.2")
                    assert pathlib.Path("/run/rtrust/lease.json").exists()
                    stop(process)
                daemon = start_daemon()
                app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "2", url, success=False)
                app(1000, str(ROOT / "target/debug/rtrust-inspect"), "--recover-service")
                fetch(1000, "10.99.0.2")
                print("PASS SIGKILL retains unreachable route; restart retains guard; explicit authorized recovery restores route", flush=True)
                def wait_state(lines, expected, seconds=45):
                    deadline = time.monotonic() + seconds
                    while time.monotonic() < deadline:
                        try:
                            line = lines.get(timeout=max(0.1, deadline-time.monotonic()))
                        except queue.Empty:
                            break
                        if line == "SERVICE " + expected:
                            return
                        if line is None:
                            raise RuntimeError("IPC client exited while waiting for " + expected)
                    raise RuntimeError("Missing service state: " + expected)
                with client(profile) as (process, lines):
                    for cycle in range(2):
                        stop(endpoint)
                        wait_state(lines, "blocked", 25)
                        app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "2", url, success=False)
                        # Let a reconnect fail before restoring the endpoint.
                        time.sleep(3)
                        fetch(1001, "10.99.0.2")
                        endpoint = start_endpoint()
                        wait_state(lines, "connected")
                        fetch(1000, "198.18.0.1")
                        rules = json.loads(ns("ip", "-N", "-j", "-4", "rule", "show"))
                        assert len([r for r in rules if str(r.get("table")) == "51830"]) == 1, "duplicated policy rules"
                    print("PASS two endpoint outages: blocked during retries, automatic recovery, real TCP, no duplicate rules", flush=True)
                    stop(endpoint)
                    wait_state(lines, "blocked", 25)
                    stop(process)
                    assert process.returncode == 0
                endpoint = start_endpoint()
                # Longer than the maximum backoff: a detached retry would fire.
                time.sleep(35)
                fetch(1000, "10.99.0.2")
                ns("ip", "link", "show", "rtrust0", success=False)
                assert not pathlib.Path("/run/rtrust/lease.json").exists()
                print("PASS Stop cancels reconnect; restored endpoint cannot resurrect TUN or routes", flush=True)
                stop(daemon)
                assert daemon.returncode == 0
                ns("ip", "link", "show", "rtrust0", success=False)
                assert not pathlib.Path("/run/rtrust/lease.json").exists()
    finally:
        for process in (daemon, endpoint):
            if process:
                stop(process)
        if server:
            server.shutdown(); server.server_close()
        command("ip", "netns", "delete", NS)
        if veth:
            subprocess.run(["ip", "link", "delete", "rtrust-host"], capture_output=True, timeout=5)
        if address:
            command("ip", "addr", "del", "198.18.0.1/32", "dev", "lo")

if __name__ == "__main__":
    main()
