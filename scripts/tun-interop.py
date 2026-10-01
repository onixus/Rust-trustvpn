#!/usr/bin/env python3
"""Run ONLY in a disposable Linux container with NET_ADMIN, SYS_ADMIN and /dev/net/tun.

Usage: python3 scripts/tun-interop.py /path/to/official/trusttunnel_endpoint
Build target/debug/rtrust-tun first. Never uses the production server or host routes.
"""
import contextlib
import http.server
import json
import os
import pathlib
import queue
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
NS = "rtrust-tun-test"
BODY = bytes(range(256)) * 2048


def command(*args, success=True):
    p = subprocess.run(args, capture_output=True, timeout=40)
    if (p.returncode == 0) != success:
        raise RuntimeError(f"{args[0]} unexpected result: {(p.stdout + p.stderr).decode(errors='replace')[-2500:]}")
    return p.stdout


def ns(*args, **kwargs):
    return command("ip", "netns", "exec", NS, *args, **kwargs)


def stop(p):
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)


@contextlib.contextmanager
def adapter(profile):
    p = subprocess.Popen(["ip", "netns", "exec", NS, str(ROOT / "target/debug/rtrust-tun"), str(profile), "rtrust0", "10.77.0.2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    def reader():
        for line in p.stdout:
            lines.put(line)
        lines.put(None)
    threading.Thread(target=reader, daemon=True).start()
    try:
        line = lines.get(timeout=35)
        if line is None or not line.startswith("TUN "):
            raise RuntimeError("TUN not ready: " + p.stderr.read()[:1000])
        ns("ip", "route", "add", "198.18.0.1/32", "dev", "rtrust0", "src", "10.77.0.2")
        ns("ip", "-6", "route", "add", "fd00:18::1/128", "dev", "rtrust0", "src", "fd00:5254::2")
        yield p
    except Exception:
        print((profile.parent / "endpoint.log").read_text()[-5000:], flush=True)
        raise
    finally:
        was_running = p.poll() is None
        stop(p)
        if was_running:
            assert p.returncode == 0, "TUN did not exit cleanly on SIGTERM"
        p.stdout.close()
        p.stderr.close()
        ns("ip", "link", "show", "rtrust0", success=False)


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)
    def log_message(self, *args):
        pass


class HTTP6(http.server.ThreadingHTTPServer):
    address_family=socket.AF_INET6

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        body = bytearray()
        try:
            while data := self.request.recv(16384):
                body.extend(data)
                if len(body) > 2 * 1024 * 1024:
                    return
        except TimeoutError:
            print(f"Echo timed out before FIN after {len(body)} bytes", flush=True)
            return
        self.request.sendall(body)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, udp = self.request
        question = b"\x07example\x04test\x00\x00\x01\x00\x01"
        if len(data) >= 12 and data[12:] == question:
            answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 60, 4) + socket.inet_aton("203.0.113.9")
            udp.sendto(data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer, self.client_address)


def main():
    if not pathlib.Path("/.dockerenv").exists() or os.geteuid() != 0:
        raise SystemExit("Run in a disposable root Docker container only")
    endpoint = pathlib.Path(sys.argv[1]).resolve()
    command("ip", "netns", "add", NS)
    resolver = pathlib.Path("/etc/netns") / NS
    processes = []
    servers = []
    udp = None
    veth_created = False
    address_added = False
    done = threading.Event()
    try:
        command("ip", "link", "add", "rtrust-host", "type", "veth", "peer", "name", "rtrust-client")
        veth_created = True
        command("ip", "link", "set", "rtrust-client", "netns", NS)
        command("ip", "addr", "add", "10.99.0.1/30", "dev", "rtrust-host")
        command("ip", "link", "set", "rtrust-host", "up")
        ns("ip", "addr", "add", "10.99.0.2/30", "dev", "rtrust-client")
        ns("ip", "link", "set", "rtrust-client", "up")
        ns("ip", "link", "set", "lo", "up")
        command("ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
        command("ip", "-6", "addr", "add", "fd00:18::1/128", "dev", "lo", "nodad")
        address_added = True
        resolver.mkdir(parents=True, exist_ok=False)
        (resolver / "resolv.conf").write_text("nameserver 198.18.0.1\noptions timeout:2 attempts:1\n")
        http_server = http.server.ThreadingHTTPServer(("198.18.0.1", 0), HTTP)
        http6=HTTP6(("fd00:18::1",0),HTTP)
        echo = socketserver.ThreadingTCPServer(("198.18.0.1", 0), Echo)
        dns = socketserver.ThreadingUDPServer(("198.18.0.1", 53), DNS)
        for server in (http_server, http6, echo, dns):
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("198.18.0.1", 0))
        udp.settimeout(0.2)
        def udp_echo():
            while not done.is_set():
                try:
                    data, peer = udp.recvfrom(65535)
                    udp.sendto(data, peer)
                except socket.timeout:
                    pass
        thread = threading.Thread(target=udp_echo, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory(prefix="rtrust-tun-") as directory:
            d = pathlib.Path(directory)
            command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"))
            (d / "vpn.toml").write_text('listen_address="10.99.0.1:8443"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n[listen_protocols.quic]\n[icmp]\ninterface_name="lo"\n')
            (d / "hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (d / "credentials.toml").write_text('[[client]]\nusername="interop"\npassword="synthetic-tun-test"\n')
            with (d / "endpoint.log").open("wb") as log:
                server = subprocess.Popen([str(endpoint), "vpn.toml", "hosts.toml", "--jobs", "2", "--loglvl", "debug"], cwd=d, stdout=log, stderr=log)
                processes.append(server)
                for _ in range(100):
                    try:
                        with socket.create_connection(("10.99.0.1", 8443), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("Endpoint startup failed: " + (d / "endpoint.log").read_text()[:1000])
                profile = d / "profile.json"
                for protocol in ("http2",):
                    profile.write_text(json.dumps(dict(hostname="localhost", addresses=["10.99.0.1:8443"], username="interop", password="synthetic-tun-test", certificate=(d / "cert.pem").read_text(), upstream_protocol=protocol)))
                    from interop import socks_proxy, read_exact
                    with socks_proxy(str(ROOT / "target/debug/rtrust-inspect"), profile, d) as proxy:
                        host, port = proxy.rsplit(":", 1)
                        with socket.create_connection((host, int(port)), timeout=15) as client:
                            client.sendall(bytes([5, 1, 0]))
                            assert read_exact(client, 2) == bytes([5, 0])
                            client.sendall(bytes([5, 1, 0, 1]) + socket.inet_aton("198.18.0.1") + struct.pack("!H", echo.server_address[1]))
                            assert read_exact(client, 10)[:2] == bytes([5, 0])
                            client.sendall(BODY)
                            client.shutdown(socket.SHUT_WR)
                            assert read_exact(client, len(BODY)) == BODY
                    print(protocol + ": SOCKS control half-close passed", flush=True)
                    # The namespace has no direct route to the destination.
                    ns("curl", "--noproxy", "*", "--max-time", "2", f"http://198.18.0.1:{http_server.server_port}/", success=False)
                    with adapter(profile):
                        actual6=ns("curl","--noproxy","*","-sSf","--max-time","10",f"http://[fd00:18::1]:{http6.server_port}/")
                        assert actual6==BODY
                        ns("ping", "-6", "-n", "-c", "2", "-W", "3", "fd00:18::1")
                        ns("ping", "-6", "-n", "-c", "1", "-W", "3", "-M", "dont", "-s", "5000", "fd00:18::1")
                        print("PASS IPv6 TUN TCP 512KiB, remote ICMPv6 and fragmented echo",flush=True)
                        ns("ping", "-n", "-c", "2", "-W", "3", "198.18.0.1")
                        ns("ping", "-n", "-c", "1", "-W", "3", "-M", "dont", "-s", "5000", "198.18.0.1")
                        command("ip", "route", "add", "blackhole", "198.18.0.2/32")
                        ns("ip", "route", "add", "198.18.0.2/32", "dev", "rtrust0", "src", "10.77.0.2")
                        ns("ping", "-n", "-c", "1", "-W", "1", "198.18.0.2", success=False)
                        command("ip", "route", "del", "blackhole", "198.18.0.2/32")
                        print("PASS remote ICMP echo, fragmented 5000-byte echo, unreachable target does not produce fake success", flush=True)
                        actual = ns("curl", "--noproxy", "*", "--silent", "--show-error", "--max-time", "15", f"http://198.18.0.1:{http_server.server_port}/")
                        assert actual == BODY, "TCP payload corruption"
                        ns("python3", "-c", f'''
import socket
import concurrent.futures
import urllib.request
assert socket.getaddrinfo("example.test", 80, socket.AF_INET, socket.SOCK_STREAM)[0][4][0] == "203.0.113.9"
def fetch(_):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}))
    with opener.open("http://198.18.0.1:{http_server.server_port}/", timeout=15) as response:
        assert response.read() == bytes(range(256)) * 2048
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(fetch, range(12)))
data = bytes(range(256)) * 2048
with socket.create_connection(("198.18.0.1", {echo.server_address[1]}), timeout=15) as s:
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    response = bytearray()
    while chunk := s.recv(16384): response.extend(chunk)
    assert response == data, "half-close lost response"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(5)
    s.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER=IP_PMTUDISC_DONT
    for size in (1, 512, 1472, 5000, 60000):
        data = bytes([size % 251]) * size
        s.sendto(data, ("198.18.0.1", {udp.getsockname()[1]}))
        reply, peer = s.recvfrom(65535)
        assert reply == data and peer == ("198.18.0.1", {udp.getsockname()[1]})
    # Endpoint 1.1.0 decoder defers an empty datagram until the next frame.
    s.sendto(b"", ("198.18.0.1", {udp.getsockname()[1]}))
    s.sendto(b"after-empty", ("198.18.0.1", {udp.getsockname()[1]}))
    assert sorted([s.recvfrom(65535)[0], s.recvfrom(65535)[0]]) == [b"", b"after-empty"]
''')
                        # Endpoint 1.1.0 closes _udp2 after a destination reports
                        # ECONNREFUSED. That must not terminate established TCP.
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                            reserve.bind(("198.18.0.1", 0))
                            refused_port = reserve.getsockname()[1]
                        ns("python3", "-c", f'''
import socket,time
with socket.create_connection(("198.18.0.1", {echo.server_address[1]}), timeout=10) as tcp:
    tcp.sendall(b"before UDP failure")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as bad:
        for _ in range(3):
            bad.sendto(b"closed-port", ("198.18.0.1", {refused_port}))
            time.sleep(.3)
    time.sleep(3)
    tcp.sendall(b"; TCP survived")
    tcp.shutdown(socket.SHUT_WR)
    body=b""
    while chunk:=tcp.recv(4096):body+=chunk
    assert body==b"before UDP failure; TCP survived", body
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
    udp.settimeout(1)
    for attempt in range(10):
        udp.sendto(b"UDP recovered", ("198.18.0.1", {udp.getsockname()[1]}))
        try:
            assert udp.recvfrom(65535)[0]==b"UDP recovered"
            break
        except socket.timeout:pass
    else:raise AssertionError("UDP channel did not recover")
''')
                        print("PASS refused UDP destination preserves established TCP and UDP channel recovers",flush=True)
                    print(f"PASS {protocol}: real TUN TCP 512KiB, 12 concurrent downloads/4 workers, half-close 512KiB, DNS getaddrinfo, UDP 1/512/1472/5000/60000 bytes + empty with follow-up, SIGTERM cleanup", flush=True)
                config = json.loads(profile.read_text())
                config["upstream_protocol"] = "http3"
                profile.write_text(json.dumps(config))
                rejected = subprocess.run(["ip", "netns", "exec", NS, str(ROOT / "target/debug/rtrust-tun"), str(profile), "rtrust0", "10.77.0.2"], capture_output=True, timeout=10)
                assert rejected.returncode != 0 and b"TUN requires HTTP/2" in rejected.stderr
                ns("ip", "link", "show", "rtrust0", success=False)
                config["upstream_protocol"] = "http2"
                profile.write_text(json.dumps(config))
                print("PASS unsupported TUN transport rejected before interface creation", flush=True)
                with adapter(profile) as client:
                    stop(server)
                    assert client.wait(timeout=25) != 0, "endpoint failure did not stop TUN"
                ns("curl", "--noproxy", "*", "--max-time", "2", f"http://198.18.0.1:{http_server.server_port}/", success=False)
                print("PASS endpoint failure removes TUN; no direct route fallback in isolated namespace", flush=True)
    finally:
        for p in processes:
            stop(p)
        done.set()
        if udp:
            thread.join(timeout=1)
            udp.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        command("ip", "netns", "delete", NS)
        if veth_created:
            subprocess.run(["ip", "link", "delete", "rtrust-host"], capture_output=True, timeout=5)
        (resolver / "resolv.conf").unlink(missing_ok=True)
        if resolver.exists():
            resolver.rmdir()
        if address_added:
            command("ip", "addr", "del", "198.18.0.1/32", "dev", "lo")
        subprocess.run(["ip", "-6", "addr", "del", "fd00:18::1/128", "dev", "lo"], capture_output=True)


if __name__ == "__main__":
    main()
