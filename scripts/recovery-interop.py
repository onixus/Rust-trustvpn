#!/usr/bin/env python3
"""Always-on automatic recovery (EnableRecovery) on a real whole-host Linux VPN (issue #34).

The system service owns the VPN through its always-on supervisor with one
permitted backup. While applications keep sending IPv4/IPv6 traffic:

  b. every endpoint down: Blocked, attempts alternate candidates with the
     documented backoff, no leaks;
  c. DisableAlwaysOn during the cooldown restores the baseline; endpoints that
     return later never raise the tunnel;
  d. EnableRecovery with a generation from before Disable, or none, is refused;
  a. requested endpoint down: recovery connects through backup index 1;
  e. SIGKILL of the service in the transition window keeps the boot guard; a
     restarted service loads the policy with a fresh budget;
  f. physical interface/gateway/source-IP handoff and return.

Host ingress and client egress counters (scripts/failover-interop.py) must
show zero leaks in every protected window. Disposable Docker only.
Usage: python3 scripts/recovery-interop.py /path/to/trusttunnel_endpoint
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

spec = importlib.util.spec_from_file_location("failover_interop", pathlib.Path(__file__).with_name("failover-interop.py"))
fo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fo)
s, f = fo.s, fo.f
s.NS = f.s.NS = "rtrust-recovery-test"
PRIMARY, BACKUP, HOST6 = fo.PRIMARY, fo.BACKUP, fo.HOST6
ALT_HOST, ALT_CLIENT = "10.99.3.1", "10.99.3.2"
POLICY = pathlib.Path("/var/lib/rtrust/always-on.rtrust")
DNS = "198.18.0.1"
# crates/control/src/lib.rs VERSION and crates/control/src/recovery.rs.
IPC_VERSION = 7
BACKOFF = (3, 6, 12, 24, 48)
JITTER = 3
HYSTERESIS = 60
ATTEMPT_TIMEOUT = 45
# Status polling latency (one short-lived IPC client per sample).
TOL = 1.0
# A refused attempt (guard, journal recovery, StartFull) is short; bounds the
# upper end of an observed inter-attempt interval only.
ATTEMPT_SLACK = 5

IPC = """import socket,struct,sys
c=socket.socket(socket.AF_UNIX);c.settimeout(60);c.connect('/run/rtrust/control.sock')
b=open(sys.argv[1],'rb').read();c.sendall(struct.pack('!I',len(b))+b)
def exact(n):
 b=b''
 while len(b)<n:
  part=c.recv(n-len(b));assert part;b+=part
 return b
n=struct.unpack('!I',exact(4))[0];assert n<1048576
print(exact(n).decode())
"""
AUTO = object()


def summary(response):
    """Only the fields the assertions use; never messages or profiles."""
    return dict(state=response.get("state"), always_on=response.get("always_on"),
                recovery=response.get("recovery"))


def phase(response):
    message = response.get("message", "")
    recovery = response.get("recovery") or {}
    if response.get("state") == "Connected":
        return "connected"
    if recovery.get("exhausted"):
        return "exhausted"
    # apps/tun/src/always_on.rs: a candidate attempt in progress, and the
    # Blocked state written after a failed attempt while the backoff runs.
    if message.startswith("Автовосстановление: подготовка"):
        return "attempt"
    if response.get("state") == "Blocked" and message.startswith("Always-on:"):
        return "cooldown"
    return "other"


def established(address, peer=None):
    return bool(s.command("ss", "-Htn", "state", "established", "src", f"{address}:8443",
                          *(["dst", peer] if peer else [])).strip())


def main():
    assert os.geteuid() == 0 and pathlib.Path("/.dockerenv").exists(), "Disposable root Docker required"
    assert not POLICY.exists(), "Never replace an existing boot policy"
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
        s.command("ip", "-6", "addr", "add", f"{HOST6}/64", "dev", "rtrust-host", "nodad")
        s.command("ip", "link", "set", "rtrust-host", "up")
        s.ns("ip", "addr", "add", "10.99.0.2/30", "dev", "rtrust-client")
        s.ns("ip", "-6", "addr", "add", "fd00:99::2/64", "dev", "rtrust-client", "nodad")
        s.ns("ip", "link", "set", "rtrust-client", "up")
        s.ns("ip", "link", "set", "lo", "up")
        s.ns("sysctl", "-w", "net.ipv4.conf.rtrust-client.rp_filter=1", "net.ipv4.conf.all.src_valid_mark=0")
        s.ns("ip", "route", "add", "default", "via", "10.99.0.1")
        s.command("ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
        http = s.http.server.ThreadingHTTPServer(("198.18.0.1", 0), s.HTTP)
        http6 = f.HTTP6((HOST6, 0), s.HTTP)
        dns = f.socketserver.ThreadingUDPServer(("198.18.0.1", 53), f.DNS)
        dns6 = fo.DNS6((HOST6, 53), f.DNS)
        servers.extend([http, http6, dns, dns6])
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://198.18.0.1:{http.server_port}/"
        url6 = f"http://[{HOST6}]:{http6.server_port}/"

        def fetch(peer, address_url=url):
            result = s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "8", "-D", "-", address_url)
            headers, body = result.split(b"\r\n\r\n", 1)
            assert body == s.BODY and f"X-Peer: {peer}".encode() in headers

        def blocked():
            for target in (url, url6):
                s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "2", target, success=False)
            for address in (PRIMARY, BACKUP):
                s.app(1000, "python3", "-c", f"import socket; socket.create_connection(('{address}',8443),timeout=1)", success=False)

        with tempfile.TemporaryDirectory(prefix="rtrust-recovery-") as directory:
            d = pathlib.Path(directory)
            d.chmod(0o711)

            def spawn(args, filename, namespace=False, cwd=None):
                with (d / filename).open("ab") as log:
                    p = subprocess.Popen((["ip", "netns", "exec", s.NS] if namespace else []) + args,
                                         stdout=log, stderr=log, cwd=cwd)
                processes.append(p)
                return p

            def request_ipc(op, generation=AUTO, **values):
                if op in ("EnableAlwaysOn", "EnableRecovery"):
                    if generation is AUTO:
                        generation = request_ipc("AlwaysOnStatus")["always_on_generation"]
                    if generation is not None:
                        values["generation"] = generation
                # Profiles travel in a private file, not on a command line.
                request = d / "request.json"
                request.write_text(json.dumps(dict(version=IPC_VERSION, command=dict(op=op, **values))))
                request.chmod(0o600)
                os.chown(request, 1000, 1000)
                try:
                    return json.loads(s.app(1000, "python3", "-c", IPC, str(request)))
                finally:
                    request.unlink(missing_ok=True)
            ipc = request_ipc

            def poll(until, timeout, label, samples=None, interval=.25):
                deadline = time.monotonic() + timeout
                while True:
                    response = ipc("AlwaysOnStatus")
                    now = time.monotonic()
                    if samples is not None:
                        samples.append((now, phase(response), response.get("recovery") or {}))
                    if until(response):
                        return now, response
                    if now > deadline:
                        raise AssertionError(f"{label}: timeout after {timeout:.0f}s, last {summary(response)}")
                    time.sleep(interval)

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
            else:
                raise AssertionError("systemd-resolved did not start")
            pathlib.Path("/etc/resolv.conf").write_text("nameserver 127.0.0.53\noptions timeout:1 attempts:1\n")
            s.ns("resolvectl", "dns", "rtrust-client", DNS)
            s.ns("resolvectl", "domain", "rtrust-client", "~.")
            fo.install_watch([PRIMARY, BACKUP])
            s.ns("nft", "add", "table", "inet", "foreign_test")
            fo.dad_settled()
            baseline = fo.snapshot()
            s.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                      "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE",
                      "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"))
            (d / "hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (d / "credentials.toml").write_text('[[client]]\nusername="interop"\npassword="synthetic-recovery-test"\n')
            profiles = {}
            for name, address in (("primary", PRIMARY), ("backup", BACKUP)):
                (d / f"{name}.toml").write_text(f'listen_address="{address}:8443"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n')
                profiles[name] = dict(schema_version=1, name=name, endpoint=dict(
                    hostname="localhost", addresses=[f"{address}:8443"], username="interop",
                    password="synthetic-recovery-test", certificate=(d / "cert.pem").read_text(), upstream_protocol="http2"))
            enable = dict(profile=profiles["primary"], dns=DNS, backups=[profiles["backup"]])

            def endpoint(name, address):
                p = spawn([endpoint_binary, f"{name}.toml", "hosts.toml", "--jobs", "2"], f"{name}.log", cwd=d)
                for _ in range(100):
                    try:
                        with socket.create_connection((address, 8443), timeout=.1):
                            return p
                    except OSError:
                        time.sleep(.05)
                raise AssertionError(f"{name} endpoint did not start")

            def daemon():
                p = spawn([str(s.ROOT / "target/debug/rtrust-service"), "1000"], "daemon.log", True)
                for _ in range(50):
                    time.sleep(.2)
                    assert p.poll() is None, "service exited"
                    try:
                        ipc("AlwaysOnStatus")
                        return p
                    except AssertionError:
                        pass
                raise AssertionError("service IPC unavailable")

            def boot_guard():
                return ("inet", "rtrust_boot") in fo.tables()

            service = daemon()
            status = ipc("AlwaysOnStatus")
            assert status["capabilities"]["automatic_recovery"], "service lacks automatic_recovery"
            assert status["state"] == "Idle" and status.get("always_on") is False, summary(status)
            load = fo.Load(url, url6, [PRIMARY, BACKUP])
            fetch("10.99.0.2")
            fetch("fd00:99::2", url6)
            fo.positive_controls(load, PRIMARY)
            load.start()

            # (b) Every permitted endpoint is down from the start. EnableRecovery
            # pins numeric endpoints without a handshake, then each protected
            # attempt fails; candidates alternate, delays follow the backoff.
            generation = ipc("AlwaysOnStatus")["always_on_generation"]
            response = ipc("EnableRecovery", generation=generation, **enable)
            assert response["state"] == "Blocked" and response.get("always_on") is True, summary(response)
            fo.reset_counters()
            assert boot_guard() and POLICY.exists()
            assert POLICY.stat().st_mode & 0o077 == 0
            assert b"synthetic" not in POLICY.read_bytes()
            samples = []
            failed4, _ = poll(lambda r: phase(r) == "cooldown" and (r.get("recovery") or {}).get("attempts") == 4,
                              4 * ATTEMPT_TIMEOUT + sum(BACKOFF[:3]) + 3 * JITTER + 30, "four failed attempts", samples)
            seen, failed = {}, {}
            for at, kind, recovery in samples:
                attempts = recovery.get("attempts")
                assert kind not in ("connected", "exhausted"), (kind, recovery)
                if attempts is None:
                    continue
                assert recovery.get("enabled") is True and recovery.get("exhausted") is False, recovery
                seen.setdefault(attempts, at)
                if kind == "attempt":
                    assert recovery["selected_index"] == (attempts - 1) % 2, recovery
                if kind == "cooldown":
                    assert recovery["selected_index"] == attempts % 2, recovery
                    failed.setdefault(attempts, at)
            intervals = []
            for n in (1, 2, 3):
                assert n in failed and n + 1 in seen, (sorted(failed), sorted(seen))
                delay = seen[n + 1] - failed[n]
                expected = BACKOFF[n - 1]
                assert expected - TOL <= delay <= expected + JITTER + TOL + ATTEMPT_SLACK, \
                    f"attempt {n + 1} began {delay:.1f}s after failure {n}; backoff {expected}s + jitter <= {JITTER}s"
                intervals.append(round(delay, 2))
            values = fo.assert_no_leaks("(b) every endpoint down")
            assert not established(PRIMARY) and not established(BACKUP)
            fo.evidence(scenario="recovery-all-down", backoff_s=list(BACKOFF[:3]), jitter_max_s=JITTER,
                        observed_failure_to_next_attempt_s=intervals, attempts=4, counters=values)
            print(f"PASS (b) every endpoint down: Blocked, candidates alternate, retries after {intervals}s "
                  f"(backoff 3/6/12 s + jitter <= 3 s), no leaks", flush=True)

            # (c) Disable while the fourth backoff (24 s) runs.
            stale = ipc("AlwaysOnStatus")["always_on_generation"]
            response = ipc("DisableAlwaysOn")
            disabled = time.monotonic()
            assert disabled - failed4 < BACKOFF[3], f"Disable after {disabled - failed4:.1f}s is outside the cooldown"
            assert response["state"] == "Idle" and response.get("always_on") is False, summary(response)
            assert not POLICY.exists() and not boot_guard()
            fo.assert_baseline(baseline, "(c) Disable during cooldown")

            # (d) A request fenced before Disable, or not fenced, cannot re-enable.
            for fence in (stale, None):
                response = ipc("EnableRecovery", generation=fence, **enable)
                assert response["state"] == "Error", summary(response)
            status = ipc("AlwaysOnStatus")
            assert status["state"] == "Idle" and status.get("always_on") is False, summary(status)
            assert status["always_on_generation"] != stale
            assert not POLICY.exists() and not boot_guard()
            fo.assert_baseline(baseline, "(d) stale EnableRecovery")
            print("PASS (d) EnableRecovery with a pre-Disable or missing generation is refused; nothing installed", flush=True)

            # (c) Endpoints return after Disable: nothing may raise the tunnel,
            # longer than the hysteresis and the largest backoff.
            primary = endpoint("primary", PRIMARY)
            backup = endpoint("backup", BACKUP)
            returned = time.monotonic()
            while time.monotonic() - returned < HYSTERESIS + 5:
                s.ns("ip", "link", "show", "rtrust0", success=False)
                assert not established(PRIMARY) and not established(BACKUP)
                status = ipc("AlwaysOnStatus")
                assert status["state"] == "Idle" and status.get("always_on") is False, summary(status)
                assert not POLICY.exists() and not boot_guard()
                time.sleep(5)
            fetch("10.99.0.2")
            fetch("fd00:99::2", url6)
            fo.assert_baseline(baseline, "(c) after endpoints returned")
            fo.evidence(scenario="recovery-disable-in-cooldown", disable_after_failure_s=round(disabled - failed4, 2),
                        returned_watch_s=HYSTERESIS + 5)
            print(f"PASS (c) Disable {disabled - failed4:.1f}s into the cooldown restores the baseline; returning "
                  f"endpoints do not raise the tunnel for {HYSTERESIS + 5}s", flush=True)

            # (a) Requested endpoint down, backup up.
            s.stop(primary)
            response = ipc("EnableRecovery", **enable)
            assert response["state"] == "Blocked" and response.get("always_on") is True, summary(response)
            fo.reset_counters()
            started = time.monotonic()
            connected, response = poll(lambda r: r["state"] == "Connected",
                                       2 * ATTEMPT_TIMEOUT + BACKOFF[0] + JITTER + 10, "(a) connected via backup")
            recovery = response.get("recovery")
            assert recovery == dict(enabled=True, selected_index=1, attempts=2, exhausted=False), recovery
            assert established(BACKUP) and not established(PRIMARY)
            fetch("198.18.0.1")
            fetch(HOST6, url6)
            # While Connected, an application flow to an endpoint address is
            # routed into rtrust0 like any other destination; what must never
            # happen is the same flow leaving outside the tunnel. The proof is
            # app_direct == 0 (client egress) and zero host leak counters. The
            # handshake result is context only: it says nothing about the path.
            handshake = {}
            for name, address in (("primary", PRIMARY), ("backup", BACKUP)):
                probe = f"import socket; socket.create_connection(('{address}',8443),timeout=1)"
                handshake[name] = subprocess.run(["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000",
                                                 "--clear-groups", "python3", "-c", probe],
                                                capture_output=True, timeout=35).returncode == 0
            assert boot_guard() and ("inet", "foreign_test") in fo.tables()
            values = fo.assert_no_leaks("(a) recovery through backup")
            fo.evidence(scenario="recovery-primary-down", enable_to_connected_s=round(connected - started, 2),
                        recovery=recovery, counters=values, app_probe_handshake_completed=handshake)
            print(f"PASS (a) requested endpoint down: Connected through backup index 1 after "
                  f"{connected - started:.1f}s, no direct endpoint bypass, no leaks", flush=True)

            # (e) The backup fails; the service dies in the backoff window.
            fo.reset_counters()
            s.stop(backup)
            poll(lambda r: phase(r) == "cooldown", 45, "(e) backup loss noticed")
            service.kill()
            service.wait(timeout=5)
            assert boot_guard() and POLICY.exists(), "boot guard or policy lost with the service"
            blocked()
            time.sleep(3)
            fo.assert_no_leaks("(e) service killed", service_traffic=False)
            backup = endpoint("backup", BACKUP)
            service = daemon()
            status = ipc("AlwaysOnStatus")
            assert status.get("always_on") is True and status["state"] == "Blocked", summary(status)
            restarted = time.monotonic()
            connected, response = poll(lambda r: r["state"] == "Connected",
                                       2 * ATTEMPT_TIMEOUT + BACKOFF[0] + JITTER + 10, "(e) reconnected after restart")
            recovery = response.get("recovery")
            # A fresh budget: one failed attempt on the requested profile, then the backup.
            assert recovery == dict(enabled=True, selected_index=1, attempts=2, exhausted=False), recovery
            assert established(BACKUP)
            fetch("198.18.0.1")
            fetch(HOST6, url6)
            values = fo.assert_no_leaks("(e) SIGKILL and restart")
            fo.evidence(scenario="recovery-service-sigkill", restart_to_connected_s=round(connected - restarted, 2),
                        recovery=recovery, counters=values)
            print("PASS (e) SIGKILL in the backoff window keeps the boot guard without leaks; restart reloads the "
                  "policy with a fresh budget", flush=True)

            # (f) A second physical link changes the endpoint's source IP and
            # gateway (scripts/full-tunnel-interop.py handoff).
            def traffic_returns(label, timeout=150):
                until = time.monotonic() + timeout
                while True:
                    try:
                        fetch("198.18.0.1")
                        fetch(HOST6, url6)
                        status = ipc("AlwaysOnStatus")
                        assert status["state"] == "Connected", summary(status)
                        return status
                    except AssertionError:
                        if time.monotonic() > until:
                            raise AssertionError(f"{label}: traffic did not return; {summary(ipc('AlwaysOnStatus'))}")
                        time.sleep(.5)

            fo.reset_counters()
            s.command("ip", "link", "add", "rtrust-alt-host", "type", "veth", "peer", "name", "rtrust-alt")
            s.command("ip", "link", "set", "rtrust-alt", "netns", s.NS)
            s.command("ip", "addr", "add", f"{ALT_HOST}/30", "dev", "rtrust-alt-host")
            s.command("ip", "link", "set", "rtrust-alt-host", "up")
            fo.watch_device("alt", "rtrust-alt-host", [PRIMARY, BACKUP])
            s.ns("ip", "addr", "add", f"{ALT_CLIENT}/30", "dev", "rtrust-alt")
            s.ns("ip", "link", "set", "rtrust-alt", "up")
            s.ns("sysctl", "-w", "net.ipv4.conf.rtrust-alt.rp_filter=1")
            handoff = time.monotonic()
            s.ns("ip", "route", "replace", "default", "via", ALT_HOST, "dev", "rtrust-alt")
            s.ns("ip", "-6", "addr", "del", "fd00:99::2/64", "dev", "rtrust-client")
            s.ns("ip", "link", "set", "rtrust-client", "down")
            s.ns("ip", "addr", "del", "10.99.0.2/30", "dev", "rtrust-client")
            assert b"dev rtrust-alt" in s.ns("ip", "route", "get", BACKUP, "mark", "0x5254")
            status = traffic_returns("(f) handoff")
            moved = time.monotonic()
            assert established(BACKUP, ALT_CLIENT), "session not carried over the new link"
            assert boot_guard()
            assert status["recovery"]["selected_index"] == 1 and not status["recovery"]["exhausted"], status["recovery"]
            values = fo.assert_no_leaks("(f) handoff")
            # Positive control for the new link's observer: the reconnected
            # transport was seen on the alt chain itself.
            assert values["alt_endpoint4"] > 0, f"alt link observer saw no endpoint transport: {values}"
            s.ns("ip", "addr", "add", "10.99.0.2/30", "dev", "rtrust-client")
            s.ns("ip", "-6", "addr", "add", "fd00:99::2/64", "dev", "rtrust-client", "nodad")
            s.ns("ip", "link", "set", "rtrust-client", "up")
            s.ns("ip", "route", "replace", "default", "via", "10.99.0.1", "dev", "rtrust-client")
            fo.dad_settled()
            # Remove the link while its observer is still attached, so no
            # packet can leave through an unwatched alt link; the counters of
            # this window (not reset) are checked after traffic returns.
            s.ns("ip", "link", "delete", "rtrust-alt")
            fo.unwatch_device("alt")
            fo.dad_settled()
            status = traffic_returns("(f) return")
            assert boot_guard()
            assert status["recovery"]["selected_index"] == 1 and not status["recovery"]["exhausted"], status["recovery"]
            values_back = fo.assert_no_leaks("(f) return")
            fo.evidence(scenario="recovery-handoff", handoff_to_traffic_s=round(moved - handoff, 2),
                        recovery=status["recovery"], counters_handoff=values, counters_return=values_back)
            print(f"PASS (f) interface/gateway/source-IP handoff and return: traffic back after "
                  f"{moved - handoff:.1f}s, boot guard retained, no leaks", flush=True)

            load.stop()
            response = ipc("DisableAlwaysOn")
            assert response["state"] == "Idle" and response.get("always_on") is False, summary(response)
            assert not POLICY.exists() and not boot_guard()
            fo.assert_baseline(baseline, "final Disable")
            fetch("10.99.0.2")
            fetch("fd00:99::2", url6)
            assert "synthetic" not in (d / "daemon.log").read_text()
            print("PASS final Disable restores the exact dual-stack baseline and the foreign nft table", flush=True)

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
        subprocess.run(["nft", "delete", "table", "netdev", "rtrust_leakwatch"], capture_output=True)
        s.command("ip", "netns", "delete", s.NS)
        subprocess.run(["ip", "link", "delete", "rtrust-host"], capture_output=True)
        subprocess.run(["ip", "link", "delete", "rtrust-alt-host"], capture_output=True)
        subprocess.run(["ip", "addr", "del", "198.18.0.1/32", "dev", "lo"], capture_output=True)


if __name__ == "__main__":
    main()
