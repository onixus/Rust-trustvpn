#!/usr/bin/env python3
"""Opt-in backup profiles on a real whole-host Linux VPN (issue #34).

Two endpoints on different addresses. The requested endpoint dies while an
application keeps sending IPv4 and IPv6 traffic; the service must move to the
allowed backup without one packet leaving the client namespace except to a
pinned endpoint port, then respect the switch cooldown when the backup dies
too. Disposable Docker only.
Usage: python3 scripts/failover-interop.py /path/to/trusttunnel_endpoint

The helpers above main() are shared with scripts/recovery-interop.py.
"""
import importlib.util
import json
import os
import pathlib
import socket
import socketserver
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
PORT = 8443
MARK = 0x5254
HOST6 = "fd00:99::1"

# docs/failover.md and apps/tun/src/failover.rs: two consecutive failures
# before a switch, switches at least 20 s apart, reconnect backoff 2 -> 30 s
# (+ up to 25 % jitter, crates/control/src/recovery.rs Budget), one shared
# 30 s handshake budget.
FAILURES_BEFORE_SWITCH = 2
COOLDOWN = 20
BACKOFF_MIN = 2
BACKOFF_MAX = 30
JITTER = 1.25
BUDGET = 30
# rtrust-inspect reports a switch on a 1 s tick from a status the IPC client
# refreshes every 2 s: observed times lag the service by up to 3 s.
LAG = 3

# Host-side ingress counters (everything the client namespace emits on the
# veth, whatever the destination) and client-side egress counters. Leaks must
# stay zero while the VPN owns the host; the rest is expected link/transport
# traffic, reported separately and never mixed with leaks.
LEAKS = ("stray4", "port4", "icmp4", "dns4", "dns6", "any6",
         "app_direct", "mark_stray4", "mark6")
BENIGN = ("endpoint4", "dhcp4", "ndp6", "dhcp6", "marked")
# Exactly the IPv6 link control the full/boot guard lets out
# (apps/tun/src/service/full.rs guard_script): hop limit 255 router
# solicitation, neighbor solicitation/advertisement. Anything else, MLD
# included, is counted as any6 and is a leak while the guard is installed.
NDP_TYPES = "133, 135, 136"
# A session shorter than this counts as a failed attempt (apps/tun/src/failover.rs STABLE).
STABLE = 30
# Minimum reconnect delays of crates/control/src/recovery.rs Budget from its
# reset state, without jitter: 2, 4, 8, 16, then 30 s for the rest of an
# eight-attempt burst, then a pause of at least 300 s. Every later state only
# waits longer, so this bounds how many attempts can fit in a window.
BURST = 8
BURST_PAUSE = 300


def budget_delays():
    delays = [min(2 << exponent, BACKOFF_MAX) for exponent in range(BURST)]
    return delays + [BURST_PAUSE]


def max_attempts(seconds):
    """Upper bound on reconnect attempts within `seconds` of a session ending."""
    elapsed, attempts = 0, 0
    for delay in budget_delays():
        elapsed += delay
        if elapsed > seconds:
            break
        attempts += 1
    return attempts


# Per pinned endpoint: SYNs of the service's marked transport sockets, one per
# connection attempt (a refused attempt gets an RST, no retransmission).
SYN_COUNTERS = {}


def host_chain(name, device, pinned, own_endpoint_counter=None):
    endpoints = ", ".join(pinned)
    own = (f"    meta protocol ip ip daddr {{ {endpoints} }} meta l4proto tcp th dport {PORT} counter name {own_endpoint_counter}\n"
           if own_endpoint_counter else "")
    return f"""  chain {name} {{
    type filter hook ingress device "{device}" priority -500; policy accept;
{own}    meta protocol ip ip daddr {{ {endpoints} }} meta l4proto tcp th dport {PORT} counter name endpoint4 accept
    meta protocol ip ip daddr 255.255.255.255 meta l4proto udp th sport 68 th dport 67 counter name dhcp4 accept
    meta protocol ip meta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} counter name dns4 accept
    meta protocol ip meta l4proto icmp counter name icmp4 accept
    meta protocol ip ip daddr {{ {endpoints} }} counter name port4 accept
    meta protocol ip counter name stray4 accept
    meta protocol ip6 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type {{ {NDP_TYPES} }} counter name ndp6 accept
    meta protocol ip6 ip6 daddr ff02::1:2 meta l4proto udp th sport 546 th dport 547 counter name dhcp6 accept
    meta protocol ip6 meta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} counter name dns6 accept
    meta protocol ip6 counter name any6 accept
  }}
"""


def install_watch(pinned, device="rtrust-host"):
    """Install host ingress and client egress observers (not enforcement)."""
    host = "table netdev rtrust_leakwatch {\n"
    host += "".join(f"  counter {name} {{}}\n" for name in
                    ("endpoint4", "dhcp4", "dns4", "icmp4", "port4", "stray4", "ndp6", "dhcp6", "dns6", "any6"))
    host += host_chain("host", device, pinned) + "}\n"
    subprocess.run(["nft", "-f", "-"], input=host.encode(), check=True, timeout=10)
    endpoints = ", ".join(pinned)
    # Last hook in the client namespace: only packets the guard accepted and
    # that leave through a non-tunnel interface. The service marks its own
    # transport sockets; an unmarked packet to a pinned endpoint is an
    # application using the union endpoint exception as a direct bypass.
    SYN_COUNTERS.clear()
    SYN_COUNTERS.update({address: f"syn{index}" for index, address in enumerate(pinned)})
    syn_counters = "".join(f"  counter {name} {{}}\n" for name in SYN_COUNTERS.values())
    syn_rules = "".join(
        f"    meta mark {MARK:#x} ip daddr {address} tcp dport {PORT} tcp flags & (syn | ack) == syn counter name {name}\n"
        for address, name in SYN_COUNTERS.items())
    client = f"""table inet rtrust_appwatch {{
{syn_counters}  counter app_direct {{}}
  counter mark_stray4 {{}}
  counter mark6 {{}}
  counter marked {{}}
  chain egress {{
    type filter hook postrouting priority 300; policy accept;
    oifname {{ "lo", "rtrust0" }} accept
{syn_rules}    meta mark {MARK:#x} meta nfproto ipv4 ip daddr != {{ {endpoints} }} counter name mark_stray4 accept
    meta mark {MARK:#x} meta nfproto ipv6 counter name mark6 accept
    meta mark {MARK:#x} counter name marked accept
    meta nfproto ipv4 ip daddr {{ {endpoints} }} counter name app_direct accept
  }}
}}
"""
    subprocess.run(["ip", "netns", "exec", s.NS, "nft", "-f", "-"], input=client.encode(), check=True, timeout=10)


def watch_device(name, device, pinned):
    """Watch another client link. `<name>_endpoint4` counts endpoint transport
    seen on this link only, a positive control that the chain is live."""
    rules = (f"table netdev rtrust_leakwatch {{\n  counter {name}_endpoint4 {{}}\n"
             + host_chain(name, device, pinned, f"{name}_endpoint4") + "}\n")
    subprocess.run(["nft", "-f", "-"], input=rules.encode(), check=True, timeout=10)


def unwatch_device(name):
    # Call after deleting the link: some kernels drop a netdev chain together
    # with its device, others keep it unbound. Named counters stay either way.
    subprocess.run(["nft", "delete", "chain", "netdev", "rtrust_leakwatch", name], capture_output=True, timeout=10)


def reset_syns():
    for name in SYN_COUNTERS.values():
        s.ns("nft", "reset", "counter", "inet", "rtrust_appwatch", name)


def syns(address=None):
    values = counters()
    if address is not None:
        return values[SYN_COUNTERS[address]]
    return sum(values[name] for name in SYN_COUNTERS.values())


def counters():
    values = {}
    for listing in (s.command("nft", "-j", "list", "counters", "table", "netdev", "rtrust_leakwatch"),
                    s.ns("nft", "-j", "list", "counters", "table", "inet", "rtrust_appwatch")):
        for item in json.loads(listing)["nftables"]:
            if "counter" in item:
                values[item["counter"]["name"]] = item["counter"]["packets"]
    return values


def reset_counters():
    s.command("nft", "reset", "counters", "table", "netdev", "rtrust_leakwatch")
    s.ns("nft", "reset", "counters", "table", "inet", "rtrust_appwatch")


def leaked(values):
    return {name: values[name] for name in LEAKS if values.get(name)}


def assert_no_leaks(label, service_traffic=True):
    """Zero leak counters; with service_traffic, the observers must also have
    seen the service's own marked endpoint transport (a live positive control)."""
    values = counters()
    assert not leaked(values), f"{label}: leak counters {leaked(values)}"
    if service_traffic:
        assert values["endpoint4"] > 0 and values["marked"] > 0, f"{label}: observers saw no service transport {values}"
    return values


def evidence(**values):
    print("EVIDENCE " + json.dumps(values, sort_keys=True), flush=True)


APP_CONTROL = """import socket,sys
query=bytes.fromhex('abcd01000001000000000000017804746573740000010001')
def tcp(family,address,port):
    s=socket.socket(family);s.settimeout(1)
    try:s.connect((address,port))
    except OSError:pass
    s.close()
def udp(family,address,port):
    s=socket.socket(family,socket.SOCK_DGRAM)
    try:s.sendto(query,(address,port))
    except OSError:pass
    s.close()
tcp(socket.AF_INET,sys.argv[1],9)
tcp(socket.AF_INET,sys.argv[1],8443)
udp(socket.AF_INET,'198.18.0.1',53);tcp(socket.AF_INET,'198.18.0.1',853)
udp(socket.AF_INET6,'fd00:99::1',53);tcp(socket.AF_INET6,'fd00:99::1',853)
"""
ROOT_CONTROL = """import socket,sys
def marked(family,kind,address,port):
    s=socket.socket(family,kind);s.setsockopt(socket.SOL_SOCKET,36,0x5254);s.settimeout(1)
    try:
        if kind==socket.SOCK_STREAM:s.connect((address,port))
        else:s.sendto(b'x',(address,port))
    except OSError:pass
    s.close()
marked(socket.AF_INET,socket.SOCK_STREAM,'198.18.0.1',9)
marked(socket.AF_INET6,socket.SOCK_DGRAM,'fd00:99::1',9)
d=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
d.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);d.setsockopt(socket.SOL_SOCKET,25,sys.argv[1].encode())
d.bind(('0.0.0.0',68));d.sendto(b'\\x01'+bytes(239),('255.255.255.255',67));d.close()
v=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);v.bind(('::',546))
v.sendto(b'\\x01\\x00\\x00\\x01',('ff02::1:2',547,0,socket.if_nametoindex(sys.argv[1])));v.close()
"""
DNS6_QUERY = """import os,socket,struct,sys
name=b''.join(bytes([len(p)])+p for p in sys.argv[1].encode().split(b'.'))+b'\\0'
q=os.urandom(2)+bytes.fromhex('01000001000000000000')+name+struct.pack('!HH',28,1)
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.settimeout(1)
s.sendto(q,('fd00:99::1',53))
try:s.recv(512)
except OSError:pass
"""
APP_ENDPOINTS = """import socket,sys
for address in sys.argv[1:]:
    s=socket.socket();s.settimeout(.5)
    try:s.connect((address,8443))
    except OSError:pass
    s.close()
"""


class DNS6(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6


class Load:
    """Applications keep sending IPv4/IPv6 HTTP, A/AAAA DNS and direct
    attempts at the pinned endpoints throughout every transition."""

    def __init__(self, url, url6, pinned):
        self.url, self.url6, self.pinned = url, url6, pinned
        self.attempts = 0
        self.stopped = threading.Event()
        self.thread = None

    def commands(self):
        name = f"t{time.time_ns()}.rtrust.test"
        return (["curl", "--noproxy", "*", "-s", "--max-time", "1", "-o", "/dev/null", self.url],
                ["curl", "--noproxy", "*", "-s", "--max-time", "1", "-o", "/dev/null", self.url6],
                ["getent", "ahostsv4", name],
                ["getent", "ahostsv6", "v6" + name],
                ["python3", "-c", DNS6_QUERY, "raw" + name],
                ["python3", "-c", APP_ENDPOINTS, *self.pinned])

    def once(self):
        for cmd in self.commands():
            try:
                subprocess.run(["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000",
                                "--clear-groups", *cmd], capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                pass
            self.attempts += 1

    def start(self):
        def run():
            while not self.stopped.is_set():
                self.once()
                self.stopped.wait(.2)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stopped.set()
        if self.thread:
            self.thread.join(timeout=60)


def positive_controls(load, endpoint_address, device="rtrust-client"):
    """Every leak counter must count the same kind of flow without the VPN;
    otherwise zero counters later would prove nothing."""
    s.ns("ip", "-6", "neigh", "flush", "dev", device)
    reset_counters()
    load.once()
    generated = counters()
    for name in ("stray4", "dns4", "any6", "dns6", "app_direct", "ndp6"):
        assert generated[name] > 0, f"application load not observed without VPN: {name} {generated}"
    s.app(1000, "python3", "-c", APP_CONTROL, endpoint_address)
    s.ns("python3", "-c", ROOT_CONTROL, device)
    s.ns("ping", "-c", "1", "-W", "1", "198.18.0.1")
    s.ns("ping", "-6", "-c", "1", "-W", "1", HOST6)
    values = counters()
    missing = [name for name in LEAKS + ("endpoint4", "dhcp4", "ndp6", "dhcp6") if not values.get(name)]
    assert not missing, f"positive control missing {missing}: {values}"
    reset_counters()
    evidence(scenario="positive-control", load=generated, synthetic=values)


def dad_settled(device="rtrust-client"):
    # Link-local DAD can finish after interface-up and legitimately add a
    # kernel local route. Freeze or compare only after it completes.
    for _ in range(100):
        addresses = json.loads(s.ns("ip", "-j", "-6", "address", "show", "dev", device))
        if not any(a.get("tentative", False) or "tentative" in a.get("flags", [])
                   for entry in addresses for a in entry.get("addr_info", [])):
            return
        time.sleep(.05)
    raise AssertionError("Fixture IPv6 DAD did not complete")


def tables():
    return {(t["table"]["family"], t["table"]["name"]) for t in
            json.loads(s.ns("nft", "-j", "list", "tables"))["nftables"] if "table" in t}


def snapshot():
    return dict(rules4=s.ns("ip", "-j", "-4", "rule", "show"),
                routes4=s.ns("ip", "-j", "-4", "route", "show", "table", "all"),
                rules6=s.ns("ip", "-j", "-6", "rule", "show"),
                routes6=s.ns("ip", "-j", "-6", "route", "show", "table", "all"),
                nft=s.ns("nft", "-j", "list", "tables"))


def assert_baseline(baseline, label):
    """Routes, rules and firewall tables exactly as before the VPN; the foreign
    table and the observers survive. Reports only which part differs."""
    dad_settled()
    current = snapshot()
    present = tables()
    assert ("inet", "foreign_test") in present, f"{label}: foreign nft table removed"
    differs = sorted(key for key in baseline if baseline[key] != current[key])
    extra = sorted(present - {(t["table"]["family"], t["table"]["name"]) for t in
                              json.loads(baseline["nft"])["nftables"] if "table" in t})
    assert not differs, f"{label}: differs from baseline in {differs}; extra tables {extra}"


def reader(process):
    """Timestamped SERVICE lines: a queue for waiting, a list for the timeline."""
    lines, timeline = s.queue.Queue(), []

    def run():
        for raw in process.stdout:
            item = (time.monotonic(), raw.strip())
            timeline.append(item)
            lines.put(item)
        lines.put((time.monotonic(), None))
    threading.Thread(target=run, daemon=True).start()
    return lines, timeline


def switches(timeline, start=0, end=float("inf")):
    return [t for t, line in timeline if line.startswith("SERVICE active ") and start <= t <= end]


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
        s.command("ip", "-6", "addr", "add", f"{HOST6}/64", "dev", "rtrust-host", "nodad")
        s.command("ip", "link", "set", "rtrust-host", "up")
        s.ns("ip", "addr", "add", "10.99.0.2/30", "dev", "rtrust-client")
        s.ns("ip", "-6", "addr", "add", "fd00:99::2/64", "dev", "rtrust-client", "nodad")
        s.ns("ip", "link", "set", "rtrust-client", "up")
        s.ns("ip", "link", "set", "lo", "up")
        s.ns("ip", "route", "add", "default", "via", "10.99.0.1")
        s.command("ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
        http = s.http.server.ThreadingHTTPServer(("198.18.0.1", 0), s.HTTP)
        http6 = f.HTTP6((HOST6, 0), s.HTTP)
        dns = f.socketserver.ThreadingUDPServer(("198.18.0.1", 53), f.DNS)
        dns6 = DNS6((HOST6, 53), f.DNS)
        servers.extend([http, http6, dns, dns6])
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://198.18.0.1:{http.server_port}/"
        url6 = f"http://[{HOST6}]:{http6.server_port}/"

        def fetch(peer):
            result = s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "8", "-D", "-", url)
            headers, body = result.split(b"\r\n\r\n", 1)
            assert body == s.BODY and f"X-Peer: {peer}".encode() in headers

        def fetch6(peer):
            result = s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "8", "-D", "-", url6)
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
            install_watch([PRIMARY, BACKUP])
            # An unrelated table must survive every Start/Stop.
            s.ns("nft", "add", "table", "inet", "foreign_test")
            dad_settled()
            baseline = snapshot()
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
            load = Load(url, url6, [PRIMARY, BACKUP])
            # Positive controls: the same flows without the VPN are counted.
            fetch("10.99.0.2")
            fetch6("fd00:99::2")
            positive_controls(load, PRIMARY)

            def wait(lines, expected, timeout=60):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    try:
                        at, line = lines.get(timeout=max(.1, deadline - time.monotonic()))
                    except s.queue.Empty:
                        break
                    assert line is not None, "client exited"
                    if line == "SERVICE " + expected:
                        return at
                raise AssertionError(f"missing: {expected}\n" + (d / "daemon.log").read_text()[-4000:])

            client = subprocess.Popen(
                ["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
                 str(s.ROOT / "target/debug/rtrust-inspect"), str(profiles["primary"]), "--serve-full", "198.18.0.1",
                 "--fallback", str(profiles["backup"])],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(client)
            lines, timeline = reader(client)
            connected_at = wait(lines, "connected", 40)
            fetch("198.18.0.1")
            fetch6(HOST6)
            assert established(PRIMARY) and not established(BACKUP)
            # A backup endpoint exception never becomes an application bypass.
            reset_counters()
            for address in (PRIMARY, BACKUP):
                s.app(1000, "python3", "-c", f"import socket; socket.create_connection(('{address}',8443),timeout=1)", success=False)
            fetch("198.18.0.1")
            assert_no_leaks("direct endpoint attempts")
            assert ("inet", "foreign_test") in tables()
            reset_counters()
            load.start()
            limits = dict(failures_before_switch=FAILURES_BEFORE_SWITCH, cooldown_s=COOLDOWN, backoff_min_s=BACKOFF_MIN,
                          backoff_max_s=BACKOFF_MAX, jitter_factor=JITTER, budget_s=BUDGET, observation_lag_s=LAG,
                          stable_s=STABLE, burst_attempts=BURST, burst_pause_s=BURST_PAUSE)

            def retried_before_switch(address, session_start, lost_at):
                """Packet-level proof of the switch threshold: the lost session
                is one failure only if it lasted less than STABLE; every
                further failure needs a reconnect attempt, i.e. one marked
                SYN to that endpoint, before the switch. The observed connect
                time lags the real one, so the real session lasted at least
                lost_at - session_start."""
                needed = FAILURES_BEFORE_SWITCH - (0 if lost_at - session_start >= STABLE else 1)
                seen = syns(address)
                assert seen >= needed, f"{seen} reconnect SYNs to {address} before the switch, need {needed}"
                return dict(syns_before_switch=seen, required=needed)

            # SYN-only counters: closing packets of the dying session never count.
            reset_syns()
            s.stop(primary)
            lost = time.monotonic()
            wait(lines, "blocked")
            switched = wait(lines, "active 1")
            # After the switch attempts go to the backup; nothing more can
            # reach the primary's counter until the backup fails.
            retries = retried_before_switch(PRIMARY, connected_at, lost)
            recovered = wait(lines, "connected")
            fetch("198.18.0.1")
            fetch6(HOST6)
            assert established(BACKUP), "backup endpoint carries the session"
            values = assert_no_leaks("requested endpoint lost")
            # The switch plus the backup handshake fit the startup budget.
            assert switched - lost <= BUDGET, f"switch after {switched - lost:.1f}s"
            assert recovered - switched <= BUDGET, f"backup connected {recovered - switched:.1f}s after switch"
            assert len(switches(timeline, lost, recovered)) == 1, switches(timeline, lost, recovered)
            evidence(scenario="primary-lost", lost_to_switch_s=round(switched - lost, 2),
                     switch_to_connected_s=round(recovered - switched, 2), switches=1, retries=retries,
                     app_attempts=load.attempts, counters=values, limits=limits)
            print(f"PASS requested endpoint lost: switched to the allowed backup after {switched - lost:.1f}s, "
                  f"connected after {recovered - lost:.1f}s; {load.attempts} app attempts, no leaks", flush=True)

            # The backup dies right away: the next switch waits for the cooldown,
            # and with both endpoints down the host stays blocked without leaks.
            reset_counters()
            primary = endpoint("primary", PRIMARY)
            reset_syns()
            s.stop(backup)
            backup_lost = time.monotonic()
            wait(lines, "blocked")
            back_limit = COOLDOWN + JITTER * BACKOFF_MAX + 2 * LAG
            back = wait(lines, "active 0", back_limit + 10)
            retries = retried_before_switch(BACKUP, recovered, backup_lost)
            back_connected = wait(lines, "connected", JITTER * BACKOFF_MAX + BUDGET)
            fetch("198.18.0.1")
            fetch6(HOST6)
            assert established(PRIMARY)
            values = assert_no_leaks("backup lost")
            assert COOLDOWN - 1 <= back - switched <= back_limit, f"switched again after {back - switched:.1f}s"
            assert len(switches(timeline, backup_lost, back_connected)) == 1, switches(timeline, backup_lost, back_connected)
            evidence(scenario="backup-lost", previous_switch_to_switch_s=round(back - switched, 2),
                     lost_to_switch_s=round(back - backup_lost, 2), switch_to_connected_s=round(back_connected - back, 2),
                     switches=1, retries=retries, counters=values, limits=limits)
            print(f"PASS backup lost: returned to the requested profile {back - switched:.1f}s after the previous "
                  f"switch (cooldown {COOLDOWN}s); no leaks", flush=True)

            # Both endpoints down. The leak window starts before the session
            # closes; retries are proven by marked SYNs only, never by the
            # closing packets of the dead session. The window covers the
            # cooldown plus the longest jittered backoff.
            reset_counters()
            s.stop(primary)
            outage = time.monotonic()
            wait(lines, "blocked")
            window = COOLDOWN + JITTER * BACKOFF_MAX + 5
            time.sleep(max(0, outage + window - time.monotonic()))
            s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "2", url, success=False)
            s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "2", url6, success=False)
            values = assert_no_leaks("no usable endpoint", service_traffic=False)
            elapsed = time.monotonic() - outage
            during = switches(timeline, outage, time.monotonic())
            attempts = syns()
            # Budget: no more attempts than its shortest delays allow. Each
            # switch consumes two failures: the lost session plus attempts.
            attempt_limit = max_attempts(elapsed)
            switch_limit = min((1 + attempts) // FAILURES_BEFORE_SWITCH, int(elapsed // COOLDOWN) + 1)
            assert 1 <= attempts <= attempt_limit, f"{attempts} reconnect SYNs in {elapsed:.0f}s, Budget allows <= {attempt_limit}"
            assert len(during) <= switch_limit, f"{len(during)} switches in {elapsed:.0f}s, limit {switch_limit}"
            load.stop()
            every = switches(timeline)
            gaps = [round(b - a, 2) for a, b in zip(every, every[1:])]
            assert all(gap >= COOLDOWN - LAG for gap in gaps), f"switches closer than the cooldown: {gaps}"
            evidence(scenario="all-endpoints-down", window_s=round(elapsed, 2), switches=len(during),
                     switch_limit=switch_limit, reconnect_syns=attempts, reconnect_syn_limit=attempt_limit,
                     switch_gaps_s=gaps, counters=values, app_attempts=load.attempts, limits=limits)
            print(f"PASS no usable endpoint: blocked for {elapsed:.0f}s, {attempts} reconnect attempts "
                  f"(<= {attempt_limit}), {len(during)} switches (<= {switch_limit}), no leaks", flush=True)

            client.terminate()
            client.wait(timeout=30)
            assert client.returncode == 0, client.stderr.read()[-2000:]
            assert_baseline(baseline, "after Stop")
            assert "synthetic" not in (d / "daemon.log").read_text()
            # Stop cancels pending attempts: a returning endpoint cannot revive
            # it. Watch longer than the longest pending jittered backoff; the
            # burst pause is cancelled the same way. No service SYN may follow.
            reset_counters()
            backup = endpoint("backup", BACKUP)
            after_stop = JITTER * BACKOFF_MAX + 2 * LAG + 1
            time.sleep(after_stop)
            s.ns("ip", "link", "show", "rtrust0", success=False)
            assert not established(BACKUP)
            values = counters()
            assert syns() == 0 and values["marked"] == 0 and values["endpoint4"] == 0, \
                f"service traffic after Stop: syns {syns()}, marked {values['marked']}, endpoint4 {values['endpoint4']}"
            evidence(scenario="after-stop", watched_s=after_stop, counters=values)
            fetch("10.99.0.2")
            assert_baseline(baseline, "after returning endpoint")
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
            startup_lines, _ = reader(restarted)
            wait(startup_lines, "active 2", 45)
            wait(startup_lines, "connected", 5)
            assert established(BACKUP) and not established(PRIMARY)
            reset_counters()
            fetch("198.18.0.1")
            fetch6(HOST6)
            s.app(1000, "python3", "-c", f"import socket; socket.create_connection(('{BACKUP}',8443),timeout=1)", success=False)
            assert_no_leaks("cold start")
            restarted.terminate()
            restarted.wait(timeout=30)
            assert restarted.returncode == 0, restarted.stderr.read()[-2000:]
            assert_baseline(baseline, "after cold-start Stop")
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
        subprocess.run(["nft", "delete", "table", "netdev", "rtrust_leakwatch"], capture_output=True)
        s.command("ip", "netns", "delete", s.NS)
        subprocess.run(["ip", "link", "delete", "rtrust-host"], capture_output=True)
        subprocess.run(["ip", "addr", "del", "198.18.0.1/32", "dev", "lo"], capture_output=True)


def established(address):
    out = s.command("ss", "-Htn", "state", "established", "src", f"{address}:8443")
    return bool(out.strip())


if __name__ == "__main__":
    main()
