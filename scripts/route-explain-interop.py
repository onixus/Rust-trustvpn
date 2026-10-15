#!/usr/bin/env python3
"""Route explain versus the actual Linux dataplane (issue #32). Disposable Docker only.

Every scenario compares an offline `rtrust-inspect` explanation with what the
packets did: the X-Peer seen by an HTTP server behind the endpoint (the client
veth address means direct, anything else came through the endpoint) and
nftables output counters in the client namespace (TUN versus physical veth).

P1/P2 desktop selected IPv4 through raw service IPC Start/Stop.
P3/P6 mobile flow policy through examples/flow-lab (numeric rules, IPv6).
P4/P5 mobile domain rules with a synthetic DNS server behind the endpoint,
      then a hot local revision with a late DNS answer of the old revision.
Decision and event JSON never contain the tested addresses or names.
Usage: python3 scripts/route-explain-interop.py /path/to/trusttunnel_endpoint
"""
import hashlib
import http.server
import importlib.util
import ipaddress
import json
import os
import pathlib
import queue
import re
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

spec = importlib.util.spec_from_file_location("service_interop", pathlib.Path(__file__).with_name("service-interop.py"))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
s.NS = "rtrust-explain-test"
INSPECT = str(s.ROOT / "target/debug/rtrust-inspect")
FLOW_LAB = str(s.ROOT / "target/debug/flow-lab")
CLIENT4, CLIENT6 = "10.99.0.2", "fd00:99::2"
DNS_SERVER = "198.18.10.53"  # inside a numeric exclusion: DNS is still tunneled
# Every tested destination and name; none may appear in decision/event JSON.
SECRETS = ["198.18.1.1", "198.18.2.1", "10.99.0.1", "10.98.0.1", "203.0.113.1", "169.254.1.1",
           "198.18.0.7", "198.18.10.1", "198.18.10.7", "198.18.10.53", "198.18.11.1", "198.18.12.1",
           "198.18.20.1", "198.18.21.1", "198.18.22.1", "198.18.23.1", "198.18.24.1", "198.18.25.1",
           "198.18.26.1", "198.18.27.1", "fd00:18::1", "fd00:18:0:1::1", "direct.lab", "short.lab", "edge.lab",
           "alias.lab", "cdn.lab", "ruled.lab", "other.lab", "num.lab", "num-pair.lab", "nodns.lab", "slow.lab",
           "fence.lab", "keep.lab", "late.lab"]
POLICY_A = {"networks": ["198.18.0.0/16", "10.0.0.0/8"], "exclude": ["198.18.2.0/24"], "exclude_lan": True}
# 0.0.0.0/0 must exclude the client's own subnet: the service preflight rejects
# a selection containing a local address when LAN exclusion is off.
POLICY_B = {"networks": ["0.0.0.0/0"], "exclude": ["198.18.0.0/24", "10.99.0.0/30"], "exclude_lan": False}
# Documented gap: explain does not model that preflight; the service refuses it.
POLICY_RAW = {"networks": ["0.0.0.0/0"], "exclude": [], "exclude_lan": False}
NUMERIC = ["198.18.10.0/24", "198.18.11.1:8080", "fd00:18:0:1::/64"]
DOMAINS = ["198.18.10.0/24", "direct.lab", "short.lab", "*.cdn.lab", "ruled.lab", "num.lab",
           "nodns.lab", "slow.lab", "fence.lab", "keep.lab"]
REVISED = DOMAINS + ["late.lab"]
PROTECTIVE = {"unknown_name_protected", "shared_ip_conflict_protected", "endpoint_unresolved",
              "local_networks_unobserved", "unsupported_family"}
transcript = []  # every decision/event JSON, checked for redaction at the end
processes = []  # stopped on every exit path


# --- synthetic DNS behind the endpoint ------------------------------------
TTL = 5  # direct within the first half of the window, expired >= 1 s after its end
LATE = 4  # seconds before a slow answer; the client resolver gives up after 2
RECORDS = {
    "direct.lab": [("A", "direct.lab", "198.18.20.1", TTL)],
    "short.lab": [("CNAME", "short.lab", "edge.lab", TTL), ("A", "edge.lab", "198.18.21.1", 300)],
    "alias.lab": [("CNAME", "alias.lab", "node.cdn.lab", 300), ("A", "node.cdn.lab", "198.18.22.1", 300)],
    "ruled.lab": [("A", "ruled.lab", "198.18.23.1", 300)],
    "other.lab": [("A", "other.lab", "198.18.23.1", 300)],
    "num.lab": [("A", "num.lab", "198.18.10.7", 300)],
    "other.num-pair.lab": [("A", "other.num-pair.lab", "198.18.10.7", 300)],
    "keep.lab": [("A", "keep.lab", "198.18.26.1", 300)],
    # Answered LATE seconds after receipt: the positive control and the fence.
    "slow.lab": [("A", "slow.lab", "198.18.25.1", 300)],
    "fence.lab": [("A", "fence.lab", "198.18.27.1", 300)],
}
dns_seen = {name: {"received": 0, "answered": 0} for name in ("slow.lab", "fence.lab")}


def encode(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        end = 12
        while data[end]:
            end += data[end] + 1
        labels, i = [], 12
        while data[i]:
            labels.append(data[i + 1:i + 1 + data[i]].decode(errors="replace").lower())
            i += data[i] + 1
        name = ".".join(labels)
        kind = int.from_bytes(data[end + 1:end + 3], "big")
        question = data[12:end + 5]
        records = RECORDS.get(name)
        answers = b""
        count = 0
        if records is not None and kind == 1:
            for rtype, owner, value, ttl in records:
                rdata = encode(value) if rtype == "CNAME" else socket.inet_aton(value)
                answers += encode(owner) + struct.pack("!HHIH", 5 if rtype == "CNAME" else 1, 1, ttl, len(rdata)) + rdata
                count += 1
        rcode = 3 if records is None else 0
        response = data[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 1, count, 0, 0) + question + answers
        late = name in dns_seen and kind == 1
        if late:
            dns_seen[name]["received"] += 1
            time.sleep(LATE)
        sock.sendto(response, self.client_address)
        if late:
            dns_seen[name]["answered"] += 1


class HTTP6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


# --- packet-path oracle ----------------------------------------------------
def run(args, timeout=30):
    return subprocess.run(args, capture_output=True, timeout=timeout)


def as_user(uid, *args, timeout=15):
    return run(["ip", "netns", "exec", s.NS, "setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", *args], timeout)


def counters_arm(destination, port, uid, proto="tcp"):
    family = "ip6" if ":" in destination else "ip"
    s.ns("nft", "flush", "chain", "inet", "rtrust_explain", "out")
    match = [family, "daddr", destination, proto, "dport", str(port)]
    s.ns("nft", "add", "rule", "inet", "rtrust_explain", "out", *match, "meta", "skuid", str(uid),
         "oifname", "rtrust0", "counter", "comment", "tun")
    # Desktop direct packets are the user's; mobile direct packets are the root
    # flow-lab's protected sockets. Either way nothing else sends to this tuple.
    s.ns("nft", "add", "rule", "inet", "rtrust_explain", "out", *match,
         "oifname", "rtrust-client", "counter", "comment", "phys")


def counters_read():
    data = json.loads(s.ns("nft", "-j", "list", "chain", "inet", "rtrust_explain", "out"))
    result = {}
    for item in data["nftables"]:
        rule = item.get("rule")
        if rule:
            packets = sum(e["counter"]["packets"] for e in rule["expr"] if "counter" in e)
            result[rule["comment"]] = packets
    return result


def fetch(destination, port, uid=1000):
    """HTTP through whatever path the system picks; returns (ok, peer, counters)."""
    counters_arm(destination, port, uid)
    target = f"[{destination}]" if ":" in destination else destination
    result = as_user(uid, "curl", "-g", "--noproxy", "*", "-sS", "--max-time", "8",
                     "-D", "-", "-o", "/dev/null", f"http://{target}:{port}/")
    peer = None
    match = re.search(rb"X-Peer: (\S+)", result.stdout)
    if match:
        peer = match.group(1).decode()
    return result.returncode == 0, peer, counters_read()


def path_of(ok, peer, counters, client, mobile=False):
    tun, phys = counters.get("tun", 0), counters.get("phys", 0)
    if tun > 0 and phys == 0:
        assert not ok or peer != client, "tunnel path reached the server from the client veth"
        return "tunnel"
    if not mobile and phys > 0 and tun == 0:
        # Desktop direct: the application's packets never touch rtrust0.
        assert not ok or peer == client, ("direct path answered by an unexpected peer", ok)
        return "direct"
    if mobile and tun > 0 and phys > 0:
        # Mobile direct: the app writes to the TUN, flow-lab's protected socket
        # leaves through the veth. The server must see the veth address.
        assert ok and peer == client, ("mobile direct without a direct peer", ok)
        return "direct"
    return "none"


def record(decision, label):
    text = json.dumps(decision, sort_keys=True)
    transcript.append(text)
    print(f"DECISION {label} {text}", flush=True)
    if decision["reason"] in PROTECTIVE or decision["action"] == "unknown":
        assert decision["action"] != "direct", (label, "unknown/conflict became direct")


# --- desktop selected IPv4 ---------------------------------------------------
def explain_selected(destination, policy, lan):
    args = [INSPECT, "--explain-selected", destination, "--include", ",".join(policy["networks"])]
    if policy["exclude"]:
        args += ["--exclude", ",".join(policy["exclude"])]
    if policy["exclude_lan"]:
        args += ["--lan", ",".join(lan)] if lan is not None else ["--exclude-lan"]
    out = s.command(*args).decode().splitlines()
    decision, routes = json.loads(out[0]), json.loads(out[1])["routes"]
    assert destination not in out[0]
    return decision, routes


def observed_local():
    """The service's Routes::local() view, read before Start."""
    nets = set()
    for route in json.loads(s.ns("ip", "-j", "-4", "route", "show", "table", "main")):
        if route.get("dst") and route["dst"] != "default":
            nets.add(str(ipaddress.ip_network(route["dst"], strict=False)))
    for device in json.loads(s.ns("ip", "-j", "-4", "address", "show")):
        if device.get("ifname") == "rtrust0":
            continue
        for address in device.get("addr_info", []):
            nets.add(str(ipaddress.ip_network(f"{address['local']}/{address['prefixlen']}", strict=False)))
    return sorted(nets)


def installed():
    """UID policy rules and device routes of table 51830 actually present."""
    rules = set()
    for line in s.ns("ip", "-4", "rule", "show").decode().splitlines():
        if "lookup 51830" in line:
            match = re.search(r"to (\S+) uidrange 1000-1000 lookup 51830", line)
            assert match, ("unexpected 51830 rule", line.split(":")[0])
            rules.add(str(ipaddress.ip_network(match.group(1), strict=False)))
    table = set()
    result = run(["ip", "netns", "exec", s.NS, "ip", "-4", "route", "show", "table", "51830"])
    for line in result.stdout.decode().splitlines():
        if " dev rtrust0" in line:
            table.add(str(ipaddress.ip_network(line.split()[0], strict=False)))
    return rules, table, result.stdout.strip() != b""


START = r'''
import json,socket,struct,sys
def exact(s,n):
    data=b""
    while len(data)<n:
        part=s.recv(n-len(data));assert part,"IPC closed";data+=part
    return data
def request(s,command):
    data=json.dumps({"version":6,"command":command}).encode()
    s.sendall(struct.pack("!I",len(data))+data)
    return json.loads(exact(s,struct.unpack("!I",exact(s,4))[0]))
s=socket.socket(socket.AF_UNIX);s.settimeout(45);s.connect("/run/rtrust/control.sock")
reply=request(s,dict(op="Start",profile=json.load(open(sys.argv[2])),**json.loads(sys.argv[1])))
print(json.dumps({"state":reply["state"]}),flush=True)
if reply["state"]!="Connected":
    print(reply["message"][:400],file=sys.stderr);sys.exit(1)
sys.stdin.readline()
print(json.dumps({"state":request(s,{"op":"Stop"})["state"]}),flush=True)
'''


class Lease:
    """A uid 1000 desktop client holding one IPC Start lease until stop()."""

    def __init__(self, policy, profile):
        self.p = subprocess.Popen(["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000",
                                   "--clear-groups", "python3", "-c", START, json.dumps(policy), str(profile)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(self.p)
        line = self.p.stdout.readline()
        assert line and json.loads(line)["state"] == "Connected", self.p.stderr.read()[-800:]

    @staticmethod
    def rejected(policy, profile):
        """Start that the service must refuse without installing anything."""
        p = subprocess.Popen(["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000",
                              "--clear-groups", "python3", "-c", START, json.dumps(policy), str(profile)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        processes.append(p)
        out, _ = p.communicate(timeout=60)
        assert p.returncode == 1 and json.loads(out.splitlines()[0])["state"] == "Error", "raw 0.0.0.0/0 was accepted"

    def stop(self):
        self.p.stdin.write("\n")
        self.p.stdin.flush()
        assert json.loads(self.p.stdout.readline())["state"] == "Idle"
        assert self.p.wait(timeout=20) == 0


def desktop(profile):
    lan = observed_local()
    ipv6 = IPV6
    # Requested LAN exclusion without observed local networks is unknown.
    unknown, routes = explain_selected("198.18.1.1", POLICY_A, None)
    record(unknown, "P1 lan-unobserved")
    assert unknown["action"] == "unknown" and unknown["reason"] == "local_networks_unobserved" and routes is None
    lease = Lease(POLICY_A, profile)
    cases = [("selected", "198.18.1.1", "tunnel"), ("excluded", "198.18.2.1", "direct"),
             ("lan", "10.99.0.1", "direct"), ("selected-second-prefix", "10.98.0.1", "tunnel"),
             ("outside", "203.0.113.1", "direct")]
    revision_a = None
    expected_routes = None
    for label, destination, expected in cases:
        decision, routes = explain_selected(destination, POLICY_A, lan)
        record(decision, "P1 " + label)
        revision_a = decision["context"]["revision"]
        expected_routes = set(routes)
        assert decision["action"] == expected, (label, decision["action"])
        for port in (80, 8081):  # selected IPv4 ignores ports
            ok, peer, counters = fetch(destination, port)
            actual = path_of(ok, peer, counters, CLIENT4)
            assert actual == expected, (label, port, actual, counters)
            assert ok, (label, port, "HTTP failed")
        # Other users are outside the UID-scoped policy whatever the prefix.
        ok, peer, counters = fetch(destination, 8081, uid=1001)
        assert path_of(ok, peer, counters, CLIENT4) == "direct" and ok, (label, "uid 1001")
        print(f"PASS P1 {label}: explain {expected}, packets {expected} on ports 80/8081, uid 1001 direct", flush=True)
    decision, _ = explain_selected("fd00:18::1", POLICY_A, lan)
    record(decision, "P1 ipv6")
    assert decision["action"] == "unknown" and decision["reason"] == "unsupported_family"
    if ipv6:
        ok, peer, counters = fetch("fd00:18::1", 8081)
        assert counters.get("tun", 0) == 0 and path_of(ok, peer, counters, CLIENT6) == "direct" and ok, counters
        print("PASS P1 ipv6: explain unknown/unsupported_family (no tunnel claim); packets left the veth, not rtrust0", flush=True)
    else:
        print("BLOCKED P1 ipv6 packet path: IPv6 addressing unavailable in this container; explain is unknown, not tunnel", flush=True)
        BLOCKED.append("P1 ipv6")
    rules, table, _ = installed()
    assert rules == expected_routes == table, ("installed prefix set differs from Selection::routes",
                                               len(rules), len(expected_routes), len(table))
    print(f"PASS P1 routes(): {len(rules)} UID rules and table 51830 routes equal the CLI prefix set", flush=True)
    lease.stop()
    rules, table, present = installed()
    assert not rules and not present, "policy A remained after Stop"

    # Explain predicts tunnel for a raw 0.0.0.0/0 without LAN exclusion, but the
    # Linux preflight rejects a selection containing a local address.
    decision, routes = explain_selected("198.18.1.1", POLICY_RAW, None)
    record(decision, "P2 raw-default prediction")
    assert decision["action"] == "tunnel" and routes, decision
    Lease.rejected(POLICY_RAW, profile)
    rules, table, present = installed()
    assert not rules and not present, "rejected Start left UID rules or table 51830"
    s.ns("ip", "link", "show", "rtrust0", success=False)
    print("PASS P2 documented gap: explain predicts tunnel for raw 0.0.0.0/0, the service refuses Start "
          "(local address inside the selection) and installs nothing", flush=True)

    lease = Lease(POLICY_B, profile)
    b = {}
    evidence = []
    for label, destination, expected in [("reserved", "169.254.1.1", "direct"), ("excluded", "198.18.0.7", "direct"),
                                         ("previously-excluded", "198.18.2.1", "tunnel"),
                                         ("previously-outside", "203.0.113.1", "tunnel")]:
        decision, routes = explain_selected(destination, POLICY_B, None)
        record(decision, "P2 " + label)
        b[label] = decision
        assert decision["action"] == expected, (label, decision["action"])
        ok, peer, counters = fetch(destination, 8081)
        assert path_of(ok, peer, counters, CLIENT4) == expected, (label, counters)
        if expected == "direct" or destination != "203.0.113.1":
            assert ok, (label, "HTTP failed")
        evidence.append(f"{label}: {expected} by counters" + (" and X-Peer" if ok else
                        ", HTTP through the endpoint failed (packet counter is the only proof)"))
        expected_routes = set(routes)
    assert b["reserved"]["reason"] == "reserved_address"
    assert b["reserved"]["context"]["revision"] != revision_a, "policy B kept revision A"
    rules, table, _ = installed()
    assert rules == expected_routes == table, "policy B installation differs from Selection::routes"
    assert not any(ipaddress.ip_network(r).overlaps(ipaddress.ip_network("169.254.0.0/16")) for r in rules)
    print("PASS P2 Stop/Start B: new revision, reserved stays direct, only B's prefixes installed; "
          + "; ".join(evidence), flush=True)
    lease.stop()
    rules, table, present = installed()
    assert not rules and not present, "table 51830 remained after Stop"
    print("PASS P2 Stop removed every UID rule and table 51830", flush=True)


# --- mobile flow dataplane -----------------------------------------------------
def explain_mobile(profile, destination, port):
    target = f"[{destination}]:{port}" if ":" in destination else f"{destination}:{port}"
    out = s.command(INSPECT, str(profile), "--explain-mobile-flow", target).decode().splitlines()
    assert destination not in out[-1]
    return json.loads(out[-1])


class FlowLab:
    def __init__(self, profile, log):
        self.p = subprocess.Popen(["ip", "netns", "exec", s.NS, FLOW_LAB, str(profile), "rtrust0", "rtrust-client"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        processes.append(self.p)
        self.lines = queue.Queue()
        threading.Thread(target=lambda: ([self.lines.put(l) for l in self.p.stdout], self.lines.put(None)),
                         daemon=True).start()
        ready = self.read(40)
        assert ready.get("ready"), ready
        self.ipv6 = ready["ipv6"]
        self.version = ready["version"]
        s.ns("ip", "route", "add", "0.0.0.0/1", "dev", "rtrust0", "src", "169.254.254.2")
        s.ns("ip", "route", "add", "128.0.0.0/1", "dev", "rtrust0", "src", "169.254.254.2")
        if IPV6:
            s.ns("ip", "-6", "route", "add", "::/1", "dev", "rtrust0", "src", "fd00:5254::2")
            s.ns("ip", "-6", "route", "add", "8000::/1", "dev", "rtrust0", "src", "fd00:5254::2")

    def read(self, timeout=15):
        line = self.lines.get(timeout=timeout)
        assert line is not None, "flow-lab exited"
        value = json.loads(line)
        assert "error" not in value, value
        return value

    def send(self, command, timeout=15):
        self.p.stdin.write(command + "\n")
        self.p.stdin.flush()
        return self.read(timeout)

    def events(self):
        self.p.stdin.write("poll\n")
        self.p.stdin.flush()
        events = []
        while True:
            value = self.read()
            if "event" in value:
                events.append(value["event"])
                continue
            assert value["lagged"] == 0 and value["discarded_oversize"] == 0, value
            return events

    def close(self):
        s.stop(self.p)


def same(event, decision, label, revision=None):
    record(event["decision"], label + " event")
    got = event["decision"]
    assert got["prediction"] is False and decision["prediction"] is True
    for key in ("action", "reason", "basis", "rules", "scope"):
        assert got[key] == decision[key], (label, key, got[key], decision[key])
    assert got["context"]["source"] == decision["context"]["source"]
    expected = revision or hashlib.sha256(decision["context"]["revision"].encode()).hexdigest()
    assert got["context"]["revision"] == expected == event["version"]["revision"], (label, "revision")


def mobile_probe(lab, profile, label, destination, port, expected, proto="tcp"):
    decision = explain_mobile(profile, destination, port)
    record(decision, label + " offline")
    assert decision["action"] == expected, (label, decision["action"])
    assert lab.send("observe on")["observe"] is True
    if proto == "udp":
        counters_arm(destination, port, 1000, "udp")
        result = as_user(1000, "python3", "-c", QUERY, destination, "num.lab")
        ok, peer, counters = result.returncode == 0, None, counters_read()
        assert ok and counters.get("phys", 0) == 0 and counters.get("tun", 0) > 0, ("udp dns", counters)
        actual = "tunnel"
    else:
        client = CLIENT6 if ":" in destination else CLIENT4
        ok, peer, counters = fetch(destination, port)
        actual = path_of(ok, peer, counters, client, mobile=True)
        assert ok, (label, "HTTP failed")
    assert actual == expected, (label, actual, counters)
    events = lab.events()
    assert events, (label, "no observed decision")
    for event in events:
        same(event, decision, label)
    print(f"PASS {label}: offline {expected}, observed {len(events)} event(s) {expected}, packets {actual}", flush=True)


QUERY = r'''
import socket,struct,sys
q=struct.pack("!HHHHHH",0x5132,0x0100,1,0,0,0)+b"".join(bytes([len(p)])+p.encode() for p in sys.argv[2].split("."))+b"\0"+struct.pack("!HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(8);s.sendto(q,(sys.argv[1],53))
assert s.recvfrom(4096)[0][:2]==q[:2]
'''


def domain_probe(lab, label, destination, expected, reason, by_name=None, revision=None, within=None):
    """One HTTP flow after optional DNS; compares the observed TCP selection.

    Returns (query_sent, answered). DNS evidence is learned in between, so it
    lives at least until query_sent + TTL and ends by answered + TTL. With
    `within`, the flow must be selected before query_sent + within.
    """
    assert lab.send("observe on")["observe"] is True
    query_sent = answered = None
    if by_name:
        counters_arm(DNS_SERVER, 53, 1000, "udp")
        query_sent = time.monotonic()
        resolved = as_user(1000, "getent", "ahostsv4", by_name)
        answered = time.monotonic()
        assert resolved.returncode == 0 and destination.encode() in resolved.stdout, (label, "DNS")
        dns = counters_read()
        assert dns.get("phys", 0) == 0 and dns.get("tun", 0) > 0, (label, "DNS left the veth", dns)
    ok, peer, counters = fetch(destination, 8081)
    if within is not None:
        elapsed = time.monotonic() - query_sent
        assert elapsed < within, (label, f"flow finished {elapsed:.2f}s after the query", within)
    actual = path_of(ok, peer, counters, CLIENT4, mobile=True)
    assert ok and actual == expected, (label, actual, counters)
    flows = [e for e in lab.events() if e["decision"]["reason"] != "dns_always_tunneled"]
    assert flows, (label, "no observed flow decision")
    for event in flows:
        record(event["decision"], label + " event")
        got = event["decision"]
        assert got["prediction"] is False and got["action"] == expected and got["reason"] == reason, (label, got)
        if revision:
            assert got["context"]["revision"] == revision, (label, "revision")
    print(f"PASS {label}: observed {expected}/{reason}, packets {actual}", flush=True)
    return query_sent, answered


def slow_query(name):
    """Start a query whose answer arrives LATE s after the client resolver gave up."""
    seen = dns_seen[name]
    before = dict(seen)
    pending = subprocess.Popen(["ip", "netns", "exec", s.NS, "setpriv", "--reuid=1000", "--regid=1000",
                                "--clear-groups", "getent", "ahostsv4", name],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(pending)
    deadline = time.monotonic() + 8
    while seen["received"] == before["received"] and time.monotonic() < deadline:
        time.sleep(.05)
    assert seen["received"] == before["received"] + 1, "slow query did not reach the DNS server once"
    return pending, before["answered"]


def late_answer_sent(name, pending, answered):
    assert pending.wait(timeout=15) != 0, "resolver should time out before the late answer"
    deadline = time.monotonic() + LATE + 4
    while dns_seen[name]["answered"] == answered and time.monotonic() < deadline:
        time.sleep(.05)
    assert dns_seen[name]["answered"] == answered + 1, "the late answer was never sent"
    time.sleep(.5)  # let the endpoint relay it back to the dataplane


def write_profile(d, name, base, exclusions, ipv6):
    data = json.loads(base.read_text())
    data["name"] = name
    data["endpoint"]["has_ipv6"] = ipv6
    data["policy"] = {"mode": "general", "exclusions": exclusions}
    path = d / f"{name}.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def mobile(d, base, log):
    numeric = write_profile(d, "numeric", base, NUMERIC, IPV6)
    lab = FlowLab(numeric, log)
    try:
        # Without a subscriber nothing is recorded, so nothing is replayed later.
        assert lab.send("observe off")["observe"] is False
        ok, _, counters = fetch("198.18.12.1", 8081)
        assert ok and counters.get("tun", 0) > 0, ("no-subscriber flow did not reach the dataplane", counters)
        assert lab.send("observe on")["observe"] is True
        assert lab.events() == [], "observations recorded without a subscriber"
        print("PASS no subscriber: real flows produced no retrospective events", flush=True)
        mobile_probe(lab, numeric, "P3 excluded-cidr", "198.18.10.1", 8081, "direct")
        mobile_probe(lab, numeric, "P3 excluded-port-match", "198.18.11.1", 8080, "direct")
        mobile_probe(lab, numeric, "P3 excluded-port-other", "198.18.11.1", 8081, "tunnel")
        mobile_probe(lab, numeric, "P3 outside-rules", "198.18.12.1", 8081, "tunnel")
        mobile_probe(lab, numeric, "P3 udp-dns-to-excluded", DNS_SERVER, 53, "tunnel", "udp")
        if IPV6 and lab.ipv6:
            mobile_probe(lab, numeric, "P6 ipv6-outside-rules", "fd00:18::1", 8081, "tunnel")
            mobile_probe(lab, numeric, "P6 ipv6-excluded-cidr", "fd00:18:0:1::1", 8081, "direct")
        else:
            print("BLOCKED P6 mobile IPv6: " + ("container IPv6 addressing unavailable" if not IPV6
                                               else "session reports no endpoint IPv6"), flush=True)
            BLOCKED.append("P6 mobile IPv6")
    finally:
        lab.close()
    s.ns("ip", "link", "show", "rtrust0", success=False)

    domains = write_profile(d, "domains", base, DOMAINS, False)
    revised = write_profile(d, "revised", base, REVISED, False)
    for destination in ("198.18.20.1", "198.18.21.1", "198.18.22.1", "198.18.23.1", "198.18.24.1",
                        "198.18.25.1", "198.18.26.1"):
        decision = explain_mobile(domains, destination, 8081)
        record(decision, "P4 offline domain-only")
        assert decision["action"] == "tunnel" and decision["reason"] == "unknown_name_protected", decision
    decision = explain_mobile(domains, "198.18.10.7", 8081)
    record(decision, "P4 offline numeric")
    assert decision["action"] == "direct" and decision["basis"] == "numeric_destination"
    print("PASS P4 offline CLI: domain-only addresses stay protected tunnel (no DNS cache offline)", flush=True)
    old = hashlib.sha256(explain_mobile(domains, "198.18.12.1", 8081)["context"]["revision"].encode()).hexdigest()
    new = hashlib.sha256(explain_mobile(revised, "198.18.12.1", 8081)["context"]["revision"].encode()).hexdigest()
    lab = FlowLab(domains, log)
    try:
        assert lab.version["revision"] == old and lab.version["epoch"] == 1
        # TTL windows are anchored to the query: direct must be seen in the first
        # half, and the expiry check waits until 1 s after the latest possible end.
        _, answered = domain_probe(lab, "P4 domain ttl", "198.18.20.1", "direct", "matched_rule",
                                   "direct.lab", old, within=TTL / 2)
        time.sleep(max(0.0, answered + TTL + 1 - time.monotonic()))
        domain_probe(lab, "P4 domain ttl expired", "198.18.20.1", "tunnel", "unknown_name_protected")
        _, answered = domain_probe(lab, "P4 cname ttl", "198.18.21.1", "direct", "matched_rule",
                                   "short.lab", within=TTL / 2)
        time.sleep(max(0.0, answered + TTL + 1 - time.monotonic()))
        domain_probe(lab, "P4 cname ttl expired (chain ttl, not the 300 s address ttl)", "198.18.21.1",
                     "tunnel", "unknown_name_protected")
        domain_probe(lab, "P4 cname target under rule", "198.18.22.1", "tunnel", "default_tunnel", "alias.lab")
        domain_probe(lab, "P4 single name", "198.18.23.1", "direct", "matched_rule", "ruled.lab")
        assert as_user(1000, "getent", "ahostsv4", "other.lab").returncode == 0
        domain_probe(lab, "P4 shared ip conflict", "198.18.23.1", "tunnel", "shared_ip_conflict_protected")
        assert as_user(1000, "getent", "ahostsv4", "other.num-pair.lab").returncode == 0
        domain_probe(lab, "P4 shared ip with numeric rule", "198.18.10.7", "direct", "matched_rule", "num.lab")
        domain_probe(lab, "P4 rule ip without dns", "198.18.24.1", "tunnel", "unknown_name_protected")

        # P5: hot local revision while an old-revision DNS answer is pending.
        domain_probe(lab, "P5 cached before revision", "198.18.26.1", "direct", "matched_rule", "keep.lab", old)
        # Positive control: without a revision change a late answer IS evidence.
        pending, answered = slow_query("slow.lab")
        late_answer_sent("slow.lab", pending, answered)
        domain_probe(lab, "P5 control: late answer of the current revision applies", "198.18.25.1",
                     "direct", "matched_rule", revision=old)
        # Fence: the same late answer, but a revision commits while it is pending.
        pending, answered = slow_query("fence.lab")
        applied = lab.send("apply-local " + json.dumps({"mode": "general", "exclusions": REVISED}), 20)["applied"]
        assert dns_seen["fence.lab"]["answered"] == answered, "answer arrived before the commit; fence unproven"
        assert applied["revision"] == new != old and applied["epoch"] == 2, applied
        late_answer_sent("fence.lab", pending, answered)
        domain_probe(lab, "P5 cache cleared", "198.18.26.1", "tunnel", "unknown_name_protected", revision=new)
        domain_probe(lab, "P5 late answer of old revision ignored", "198.18.27.1", "tunnel",
                     "unknown_name_protected", revision=new)
        domain_probe(lab, "P5 new revision learns again", "198.18.26.1", "direct", "matched_rule", "keep.lab", new)
        print("PASS P5 hot revision: new revision/epoch, cache cleared, late old-revision DNS answer not applied", flush=True)
    finally:
        lab.close()
    s.ns("ip", "link", "show", "rtrust0", success=False)


def main():
    global IPV6
    assert os.geteuid() == 0 and pathlib.Path("/.dockerenv").exists(), "Disposable root Docker required"
    endpoint_binary = str(pathlib.Path(sys.argv[1]).resolve())
    servers, added = [], []
    netns_etc = pathlib.Path("/etc/netns") / s.NS
    s.command("ip", "netns", "add", s.NS)
    try:
        s.command("ip", "link", "add", "rtrust-host", "type", "veth", "peer", "name", "rtrust-client")
        s.command("ip", "link", "set", "rtrust-client", "netns", s.NS)
        s.command("ip", "addr", "add", "10.99.0.1/30", "dev", "rtrust-host")
        s.command("ip", "link", "set", "rtrust-host", "up")
        s.ns("ip", "addr", "add", f"{CLIENT4}/30", "dev", "rtrust-client")
        s.ns("ip", "link", "set", "rtrust-client", "up")
        s.ns("ip", "link", "set", "lo", "up")
        s.ns("ip", "route", "add", "default", "via", "10.99.0.1")
        # Destinations live behind the endpoint host: any 198.18/16 address is local.
        s.command("ip", "route", "add", "local", "198.18.0.0/16", "dev", "lo", "table", "local")
        added.append(["ip", "route", "del", "local", "198.18.0.0/16", "dev", "lo", "table", "local"])
        for address in ("10.98.0.1/32", "203.0.113.1/32", "169.254.1.1/32"):
            s.command("ip", "addr", "add", address, "dev", "lo")
            added.append(["ip", "addr", "del", address, "dev", "lo"])
        try:
            s.command("ip", "-6", "addr", "add", "fd00:99::1/64", "dev", "rtrust-host", "nodad")
            s.ns("ip", "-6", "addr", "add", f"{CLIENT6}/64", "dev", "rtrust-client", "nodad")
            s.ns("ip", "-6", "route", "add", "default", "via", "fd00:99::1")
            for address in ("fd00:18::1/128", "fd00:18:0:1::1/128"):
                s.command("ip", "-6", "addr", "add", address, "dev", "lo")
                added.append(["ip", "-6", "addr", "del", address, "dev", "lo"])
            IPV6 = True
        except (AssertionError, subprocess.SubprocessError):
            IPV6 = False
        netns_etc.mkdir(parents=True, exist_ok=True)
        (netns_etc / "resolv.conf").write_text(f"nameserver {DNS_SERVER}\noptions timeout:2 attempts:1\n")
        s.ns("nft", "add", "table", "inet", "rtrust_explain")
        s.ns("nft", "add", "chain", "inet", "rtrust_explain", "out",
             "{ type filter hook output priority 0; policy accept; }")
        for port in (80, 8080, 8081):
            servers.append(http.server.ThreadingHTTPServer(("0.0.0.0", port), s.HTTP))
        if IPV6:
            servers.append(HTTP6(("::", 8081), s.HTTP))
        servers.append(socketserver.ThreadingUDPServer((DNS_SERVER, 53), DNS))
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with tempfile.TemporaryDirectory(prefix="rtrust-explain-") as directory:
            d = pathlib.Path(directory)
            d.chmod(0o711)
            s.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                      "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE",
                      "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"))
            (d / "vpn.toml").write_text('listen_address="10.99.0.1:8443"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n')
            (d / "hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (d / "credentials.toml").write_text('[[client]]\nusername="interop"\npassword="synthetic-explain-test"\n')
            base = d / "profile.json"
            base.write_text(json.dumps(dict(schema_version=1, name="Isolated explain test", endpoint=dict(
                hostname="localhost", addresses=["10.99.0.1:8443"], username="interop", password="synthetic-explain-test",
                certificate=(d / "cert.pem").read_text(), upstream_protocol="http2"))))
            base.chmod(0o600)
            os.chown(base, 1000, 1000)
            logs = {name: (d / f"{name}.log").open("wb") for name in ("endpoint", "daemon", "flow-lab")}
            try:
                endpoint = subprocess.Popen([endpoint_binary, "vpn.toml", "hosts.toml", "--jobs", "2"], cwd=d,
                                            stdout=logs["endpoint"], stderr=logs["endpoint"])
                processes.append(endpoint)
                for _ in range(100):
                    try:
                        with socket.create_connection(("10.99.0.1", 8443), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError("endpoint readiness timeout")
                daemon = subprocess.Popen(["ip", "netns", "exec", s.NS, str(s.ROOT / "target/debug/rtrust-service"), "1000"],
                                          stdout=logs["daemon"], stderr=logs["daemon"])
                processes.append(daemon)
                for _ in range(100):
                    if pathlib.Path(s.SOCKET).exists():
                        break
                    time.sleep(.05)
                desktop(base)
                s.stop(daemon)
                assert daemon.returncode == 0
                s.ns("ip", "link", "show", "rtrust0", success=False)
                mobile(d, base, logs["flow-lab"])
                text = "\n".join(transcript)
                leaked = [token for token in SECRETS if token in text]
                assert not leaked and text, f"{len(leaked)} tested destinations/names in decision JSON"
                print(f"PASS redaction: {len(transcript)} decision/event JSON objects contain none of "
                      f"{len(SECRETS)} tested destinations or names", flush=True)
            except BaseException:
                for name in ("daemon", "flow-lab"):
                    logs[name].flush()
                    tail = (d / f"{name}.log").read_text(errors="replace")[-3000:]
                    print(f"--- {name}.log tail ---\n{tail.replace('synthetic-explain-test', '[REDACTED]')}", flush=True)
                raise
            finally:
                for p in reversed(processes):
                    s.stop(p)
                for log in logs.values():
                    log.close()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        subprocess.run(["ip", "netns", "delete", s.NS], capture_output=True)
        subprocess.run(["ip", "link", "delete", "rtrust-host"], capture_output=True)
        for args in reversed(added):
            subprocess.run(args, capture_output=True)
        if netns_etc.exists():
            for path in netns_etc.iterdir():
                path.unlink()
            netns_etc.rmdir()


IPV6 = False
# An unavailable gate is not a pass: the lane fails after cleanup and names it.
BLOCKED = []

if __name__ == "__main__":
    main()
    if BLOCKED:
        print("FAIL blocked gates: " + ", ".join(BLOCKED), flush=True)
        sys.exit(3)
