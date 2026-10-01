#!/usr/bin/env python3
"""Isolated official endpoint interoperability. No production profiles or traffic.

Usage: python3 scripts/interop.py /absolute/path/to/trusttunnel_endpoint
Requires openssl and built target/debug/rtrust-inspect.
"""
import contextlib
import queue
import struct
import http.server
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(args, cwd, *, success=True):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=40)
    if (result.returncode == 0) != success:
        raise RuntimeError("unexpected command result: " + pathlib.Path(str(args[0])).name + " " + result.stderr.decode(errors="replace")[:500])
    return result.stdout.decode()


@contextlib.contextmanager
def socks_proxy(inspect, profile, cwd):
    process = subprocess.Popen([inspect, str(profile), "--serve-socks", "0"], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    def read_lines():
        for line in process.stdout:
            lines.put(line)
        lines.put(None)
    threading.Thread(target=read_lines, daemon=True).start()
    try:
        while True:
            line = lines.get(timeout=35)
            if line is None:
                raise RuntimeError("proxy exited before readiness")
            if line.startswith("SOCKS5 "):
                yield line.strip().split(" ", 1)[1]
                break
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def read_exact(socket, size):
    data = b""
    while len(data) < size:
        part = socket.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected SOCKS EOF")
        data += part
    return data


def check_socks(proxy, udp_address):
    host, port = proxy.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=5) as control:
        control.sendall(bytes([5, 1, 0]))
        assert read_exact(control, 2) == bytes([5, 0])
        control.sendall(bytes([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
        bound = read_exact(control, 10)
        assert bound[:4] == bytes([5, 0, 0, 1])
        relay = (socket.inet_ntoa(bound[4:8]), struct.unpack("!H", bound[8:])[0])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("127.0.0.1", 0))
            client.settimeout(3)
            header = bytes([0, 0, 0, 1]) + socket.inet_aton(udp_address[0]) + struct.pack("!H", udp_address[1])
            for payload in (b"SOCKS-UDP-echo", bytes(range(256)) * 32):
                client.sendto(header + payload, relay)
                assert client.recvfrom(65535)[0] == header + payload
            # Reject fragments and datagrams from a different source port after pinning.
            client.settimeout(0.3)
            client.sendto(bytes([0, 0, 1]) + header[3:] + b"fragment", relay)
            try:
                client.recvfrom(65535)
                raise AssertionError("fragment was forwarded")
            except socket.timeout:
                pass
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stranger:
                stranger.settimeout(0.3)
                stranger.sendto(header + b"spoof", relay)
                try:
                    stranger.recvfrom(65535)
                    raise AssertionError("association accepted a different source")
                except socket.timeout:
                    pass
            client.settimeout(3)
            client.sendto(header + b"still-alive", relay)
            assert client.recvfrom(65535)[0] == header + b"still-alive"
            control.shutdown(socket.SHUT_WR)
            assert control.recv(1) == b"", "UDP control connection did not close"
            client.settimeout(0.3)
            client.sendto(header + b"after-close", relay)
            try:
                client.recvfrom(65535)
                raise AssertionError("UDP relay survived its control connection")
            # Windows reports ICMP Port Unreachable as WSAECONNRESET.
            # Only accepted after the control socket has closed; live relay
            # checks above must still deliver exact payloads.
            except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
                pass


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass


def main():
    endpoint = pathlib.Path(sys.argv[1]).resolve()
    inspect = str(ROOT / "target/debug/rtrust-inspect")
    with tempfile.TemporaryDirectory(prefix="rtrust-interop-") as directory:
        d = pathlib.Path(directory)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", "key.pem", "-out", "cert.pem"], d)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        (d / "vpn.toml").write_text(f'listen_address="127.0.0.1:{port}"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n[listen_protocols.quic]\n')
        (d / "hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
        (d / "credentials.toml").write_text('[[client]]\nusername="interop"\npassword="synthetic-interop-password"\n')
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(0.2)
        stop = threading.Event()

        def echo():
            while not stop.is_set():
                try:
                    payload, address = udp.recvfrom(65535)
                    udp.sendto(payload, address)
                except socket.timeout:
                    pass

        thread = threading.Thread(target=echo, daemon=True)
        thread.start()
        log = (d / "endpoint.log").open("wb")
        process = subprocess.Popen([str(endpoint), "vpn.toml", "hosts.toml", "--jobs", "2"], cwd=d, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("isolated endpoint exited: " + (d / "endpoint.log").read_text()[:1500])
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("endpoint did not start")
            base = dict(hostname="localhost", addresses=[f"127.0.0.1:{port}"], username="interop", password="synthetic-interop-password", certificate=(d / "cert.pem").read_text())
            for protocol in ("http2", "http3"):
                config = dict(base, upstream_protocol=protocol)
                profile = d / "profile.json"
                profile.write_text(json.dumps(config))
                print(run([inspect, str(profile), "--probe-http", f"127.0.0.1:{server.server_port}"], d).strip())
                print(run([inspect, str(profile), "--probe-udp", f"127.0.0.1:{udp.getsockname()[1]}"], d).strip())
                with socks_proxy(inspect, profile, d) as proxy:
                    output = run(["curl", "--silent", "--show-error", "--max-time", "10", "--noproxy", "", "--socks5-hostname", proxy, f"http://localhost:{server.server_port}/"], d)
                    assert output == "OK", "SOCKS TCP body mismatch"
                    check_socks(proxy, udp.getsockname())
                    print(protocol + ": curl through SOCKS5 + UDP echo/8KiB + fragment/source rejection passed")
                config["password"] = "wrong-password"
                profile.write_text(json.dumps(config))
                run([inspect, str(profile), "--probe-http", f"127.0.0.1:{server.server_port}"], d, success=False)
                config.update(password=base["password"], hostname="wrong.invalid")
                profile.write_text(json.dumps(config))
                run([inspect, str(profile), "--probe-http", f"127.0.0.1:{server.server_port}"], d, success=False)
                print(protocol + ": wrong password and wrong TLS identity rejected")
            exported = run([str(endpoint), "vpn.toml", "hosts.toml", "-c", "interop", "-a", f"127.0.0.1:{port}", "--format", "deeplink"], d)
            link = next(line.strip() for line in exported.splitlines() if line.strip().startswith("tt://"))
            (d / "official.tt").write_text(link)
            print(run([inspect, str(d / "official.tt")], d).strip())
            print("PASS: official endpoint tt export parsed; TCP/UDP over HTTP/2 and HTTP/3 interoperable")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()
            stop.set()
            thread.join(timeout=1)
            udp.close()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
