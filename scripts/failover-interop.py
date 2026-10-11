#!/usr/bin/env python3
"""Opt-in backup profiles on a real whole-host Linux VPN (issue #34).

Two endpoints on different addresses. The requested endpoint dies while an
application keeps sending traffic; the service must move to the allowed backup
without one packet leaving the client namespace except to an endpoint, then
respect the switch cooldown when the backup dies too. Disposable Docker only.
Usage: python3 scripts/failover-interop.py /path/to/trusttunnel_endpoint
"""
import importlib.util
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

here = pathlib.Path(__file__).with_name
spec = importlib.util.spec_from_file_location("service_interop", here("service-interop.py"))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
spec = importlib.util.spec_from_file_location("full_interop", here("full-tunnel-interop.py"))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
s.NS = f.s.NS = "rtrust-failover-test"
PRIMARY, BACKUP = "10.99.0.1", "10.99.1.1"
COOLDOWN = 20


def leak_counters():
    """Host-side count of client packets to anything but an endpoint port."""
    rules = f"""
table inet rtrust_leakwatch {{
  counter stray4 {{}}
  counter port4 {{}}
  counter icmp4 {{}}
  counter any6 {{}}
  chain input {{
    type filter hook input priority -300; policy accept;
    ip saddr 10.99.0.2 ip daddr != {{ {PRIMARY}, {BACKUP} }} counter name stray4
    ip saddr 10.99.0.2 meta l4proto {{ tcp, udp }} th dport != 8443 counter name port4
    ip saddr 10.99.0.2 meta l4proto icmp counter name icmp4
    ip6 saddr fd00:99::2 counter name any6
  }}
}}
"""
    subprocess.run(["nft", "-f", "-"], input=rules.encode(), check=True, timeout=10)


def leaks():
    data = json.loads(s.command("nft", "-j", "list", "counters", "table", "inet", "rtrust_leakwatch"))
    return {c["counter"]["name"]: c["counter"]["packets"] for c in data["nftables"] if "counter" in c}


def reset_leaks():
    s.command("nft", "reset", "counters", "table", "inet", "rtrust_leakwatch")


def established(address):
    out = s.command("ss", "-Htn", "state", "established", "src", f"{address}:8443")
    return bool(out.strip())


def main():
    assert os.geteuid() == 0 and pathlib.Path("/.dockerenv").exists(), "Disposable root Docker required"
    endpoint_binary = str(pathlib.Path(sys.argv[1]).resolve())
    processes, servers = [], []
    original_resolv = pathlib.Path("/etc/resolv.conf").read_bytes()
    s.command("mount", "-o", "remount,rw", "/proc/sys")
    s.command("ip", "netns", "add", s.NS)
    try:
        s.command("ip", "link", "add", "rtrust-host", "type", "veth", "peer", "name", "rtrust-client")
        s.command("ip", "link", "set", "rtrust-client", "netns", s.NS)
        s.command("ip", "addr", "add", "10.99.0.1/30", "dev", "rtrust-host")
        s.command("ip", "addr", "add", f"{BACKUP}/32", "dev", "rtrust-host")
        s.command("ip", "-6", "addr", "add", "fd00:99::1/64", "dev", "rtrust-host", "nodad")
        s.command("ip", "link", "set", "rtrust-host", "up")
        s.ns("ip", "addr", "add", "10.99.0.2/30", "dev", "rtrust-client")
        s.ns("ip", "-6", "addr", "add", "fd00:99::2/64", "dev", "rtrust-client", "nodad")
        s.ns("ip", "link", "set", "rtrust-client", "up")
        s.ns("ip", "link", "set", "lo", "up")
        s.ns("ip", "route", "add", "default", "via", "10.99.0.1")
        s.command("ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
        http = s.http.server.ThreadingHTTPServer(("198.18.0.1", 0), s.HTTP)
        dns = f.socketserver.ThreadingUDPServer(("198.18.0.1", 53), f.DNS)
        servers.extend([http, dns])
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://198.18.0.1:{http.server_port}/"

        def fetch(peer):
            result = s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "8", "-D", "-", url)
            headers, body = result.split(b"\r\n\r\n", 1)
            assert body == s.BODY and f"X-Peer: {peer}".encode() in headers

        with tempfile.TemporaryDirectory(prefix="rtrust-failover-") as directory:
            d = pathlib.Path(directory)
            d.chmod(0o711)

            def spawn(args, filename, namespace=False, cwd=None):
                with (d / filename).open("wb") as log:
                    p = subprocess.Popen((["ip", "netns", "exec", s.NS] if namespace else []) + args,
                                         stdout=log, stderr=log, cwd=cwd)
                processes.append(p)
                return p

            pathlib.Path("/run/dbus").mkdir(exist_ok=True)
            spawn(["dbus-daemon", "--system", "--nofork", "--nopidfile"], "dbus.log", True)
            for _ in range(100):
                if pathlib.Path("/run/dbus/system_bus_socket").exists():
                    break
                time.sleep(.05)
            spawn(["/lib/systemd/systemd-resolved"], "resolved.log", True)
            for _ in range(100):
                if subprocess.run(["ip", "netns", "exec", s.NS, "resolvectl", "status"], capture_output=True).returncode == 0:
                    break
                time.sleep(.05)
            pathlib.Path("/etc/resolv.conf").write_text("nameserver 127.0.0.53\noptions timeout:1 attempts:1\n")
            s.ns("resolvectl", "dns", "rtrust-client", "198.18.0.1")
            s.ns("resolvectl", "domain", "rtrust-client", "~.")
            baseline_rules = s.ns("ip", "-j", "-4", "rule", "show")
            baseline_routes = s.ns("ip", "-j", "-4", "route", "show", "table", "all")
            baseline_nft = s.ns("nft", "-j", "list", "tables")
            s.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                      "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE",
                      "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"))
            (d / "hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (d / "credentials.toml").write_text('[[client]]\nusername="interop"\npassword="synthetic-failover-test"\n')
            profiles = {}
            for name, address in (("primary", PRIMARY), ("backup", BACKUP)):
                (d / f"{name}.toml").write_text(f'listen_address="{address}:8443"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n')
                profile = d / f"{name}.json"
                profile.write_text(json.dumps(dict(schema_version=1, name=name, endpoint=dict(
                    hostname="localhost", addresses=[f"{address}:8443"], username="interop",
                    password="synthetic-failover-test", certificate=(d / "cert.pem").read_text(), upstream_protocol="http2"))))
                profile.chmod(0o600)
                os.chown(profile, 1000, 1000)
                profiles[name] = profile

            def endpoint(name, address):
                p = spawn([endpoint_binary, f"{name}.toml", "hosts.toml", "--jobs", "2"], f"{name}.log", cwd=d)
                for _ in range(100):
                    try:
                        with socket.create_connection((address, 8443), timeout=.1):
                            return p
                    except OSError:
                        time.sleep(.05)
                raise AssertionError((d / f"{name}.log").read_text())

            primary = endpoint("primary", PRIMARY)
            backup = endpoint("backup", BACKUP)
            spawn([str(s.ROOT / "target/debug/rtrust-service"), "1000"], "daemon.log", True)
            time.sleep(.3)
            leak_counters()
            # Positive control: a direct request before the VPN must be counted,
            # otherwise zero counters below would prove nothing.
            fetch("10.99.0.2")
            assert leaks()["stray4"] > 0, leaks()
            reset_leaks()

            def wait(lines, expected, timeout=60):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    try:
                        line = lines.get(timeout=max(.1, deadline - time.monotonic()))
                    except Exception:
                        break
                    assert line is not None, "client exited"
                    if line == "SERVICE " + expected:
                        return time.monotonic()
                raise AssertionError(f"missing: {expected}\n" + (d / "daemon.log").read_text()[-4000:])

            # Applications keep sending HTTP and DNS throughout every transition.
            stop_traffic = threading.Event()
            attempts = [0]

            def traffic():
                while not stop_traffic.is_set():
                    for cmd in (["curl", "--noproxy", "*", "-s", "--max-time", "1", "-o", "/dev/null", url],
                                ["getent", "ahostsv4", f"t{time.time_ns()}.rtrust.test"]):
                        subprocess.run(["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000",
                                        "--clear-groups", *cmd], capture_output=True, timeout=5)
                        attempts[0] += 1
                    stop_traffic.wait(.2)

            client = subprocess.Popen(
                ["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
                 str(s.ROOT / "target/debug/rtrust-inspect"), str(profiles["primary"]), "--serve-full", "198.18.0.1",
                 "--fallback", str(profiles["backup"])],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(client)
            lines = s.queue.Queue()
            threading.Thread(target=lambda: ([lines.put(l.strip()) for l in client.stdout], lines.put(None)), daemon=True).start()
            wait(lines, "connected", 40)
            fetch("198.18.0.1")
            assert established(PRIMARY) and not established(BACKUP)
            # A backup endpoint exception never becomes an application bypass.
            for address in (PRIMARY, BACKUP):
                s.app(1000, "python3", "-c", f"import socket; socket.create_connection(('{address}',8443),timeout=1)", success=False)
            reset_leaks()
            worker = threading.Thread(target=traffic, daemon=True)
            worker.start()

            s.stop(primary)
            lost = time.monotonic()
            wait(lines, "blocked")
            switched = wait(lines, "active 1")
            recovered = wait(lines, "connected")
            fetch("198.18.0.1")
            assert established(BACKUP), "backup endpoint carries the session"
            counters = leaks()
            assert not any(counters.values()), counters
            print(f"PASS requested endpoint lost: switched to the allowed backup after {switched - lost:.1f}s, "
                  f"connected after {recovered - lost:.1f}s; {attempts[0]} app attempts, leak counters {counters}", flush=True)

            # The backup dies right away: the next switch waits for the cooldown,
            # and with both endpoints down the host stays blocked without leaks.
            primary = endpoint("primary", PRIMARY)
            s.stop(backup)
            wait(lines, "blocked")
            back = wait(lines, "active 0", COOLDOWN + 40)
            assert back - switched >= COOLDOWN - 1, f"switched again after {back - switched:.1f}s"
            wait(lines, "connected")
            fetch("198.18.0.1")
            assert established(PRIMARY)
            counters = leaks()
            assert not any(counters.values()), counters
            print(f"PASS backup lost: returned to the requested profile {back - switched:.1f}s after the previous "
                  f"switch (cooldown {COOLDOWN}s); leak counters {counters}", flush=True)

            s.stop(primary)
            wait(lines, "blocked")
            time.sleep(COOLDOWN + 10)
            s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "2", url, success=False)
            counters = leaks()
            assert not any(counters.values()), counters
            stop_traffic.set()
            worker.join()
            print(f"PASS no usable endpoint: blocked for {COOLDOWN + 10}s, candidates retried, leak counters {counters}", flush=True)

            client.terminate()
            client.wait(timeout=30)
            assert client.returncode == 0, client.stderr.read()[-2000:]
            assert s.ns("ip", "-j", "-4", "rule", "show") == baseline_rules
            assert s.ns("ip", "-j", "-4", "route", "show", "table", "all") == baseline_routes
            assert s.ns("nft", "-j", "list", "tables") == baseline_nft
            assert "synthetic" not in (d / "daemon.log").read_text()
            # Stop cancels pending attempts: a returning endpoint cannot revive it.
            backup = endpoint("backup", BACKUP)
            time.sleep(35)
            s.ns("ip", "link", "show", "rtrust0", success=False)
            fetch("10.99.0.2")
            print("PASS Stop restores routes/firewall; a returning backup cannot resurrect the tunnel", flush=True)

            # Cold start with the primary already down and the first backup
            # unresolvable. The working backup must keep its request index 2.
            skipped = d / "skipped.json"
            skipped_data = json.loads(profiles["backup"].read_text())
            skipped_data["name"] = "skipped"
            skipped_data["endpoint"]["addresses"] = ["rtrust-unresolvable.invalid:8443"]
            skipped.write_text(json.dumps(skipped_data))
            skipped.chmod(0o600)
            os.chown(skipped, 1000, 1000)
            restarted = subprocess.Popen(
                ["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
                 str(s.ROOT / "target/debug/rtrust-inspect"), str(profiles["primary"]), "--serve-full", "198.18.0.1",
                 "--fallback", str(skipped), "--fallback", str(profiles["backup"])],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(restarted)
            startup_lines = s.queue.Queue()
            threading.Thread(target=lambda: ([startup_lines.put(l.strip()) for l in restarted.stdout], startup_lines.put(None)), daemon=True).start()
            wait(startup_lines, "active 2", 45)
            wait(startup_lines, "connected", 5)
            assert established(BACKUP) and not established(PRIMARY)
            reset_leaks()
            fetch("198.18.0.1")
            s.app(1000, "python3", "-c", f"import socket; socket.create_connection(('{BACKUP}',8443),timeout=1)", success=False)
            assert not any(leaks().values()), leaks()
            restarted.terminate()
            restarted.wait(timeout=30)
            assert restarted.returncode == 0, restarted.stderr.read()[-2000:]
            assert s.ns("ip", "-j", "-4", "rule", "show") == baseline_rules
            assert s.ns("ip", "-j", "-4", "route", "show", "table", "all") == baseline_routes
            assert s.ns("nft", "-j", "list", "tables") == baseline_nft
            print("PASS cold start: failed primary, skipped DNS backup, active original index 2; no bypass; clean Stop", flush=True)

    except BaseException:
        if 'd' in locals() and (d / "daemon.log").exists():
            print((d / "daemon.log").read_text()[-12000:], flush=True)
        raise
    finally:
        for p in reversed(processes):
            s.stop(p)
        pathlib.Path("/etc/resolv.conf").write_bytes(original_resolv)
        for server in servers:
            server.shutdown()
            server.server_close()
        subprocess.run(["nft", "delete", "table", "inet", "rtrust_leakwatch"], capture_output=True)
        s.command("ip", "netns", "delete", s.NS)
        subprocess.run(["ip", "link", "delete", "rtrust-host"], capture_output=True)
        subprocess.run(["ip", "addr", "del", "198.18.0.1/32", "dev", "lo"], capture_output=True)


if __name__ == "__main__":
    main()
