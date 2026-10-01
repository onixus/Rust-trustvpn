#!/usr/bin/env python3
"""Real full-host Linux VPN, resolved and persistent firewall tests. Disposable Docker only."""
import importlib.util
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

spec = importlib.util.spec_from_file_location("service_interop", pathlib.Path(__file__).with_name("service-interop.py"))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
s.NS = "rtrust-full-test"
peers = []

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        end = 12
        while data[end]:
            end += data[end] + 1
        end += 1
        kind = int.from_bytes(data[end:end+2], "big")
        question = data[12:end+4]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton("198.18.0.1") if kind == 1 else b""
        response = data[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0) + question + answer
        peers.append(self.client_address[0])
        sock.sendto(response, self.client_address)

class HTTP6(s.http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

def wait_state(lines, state):
    deadline = time.monotonic() + 50
    while time.monotonic() < deadline:
        try:
            line = lines.get(timeout=max(.1, deadline-time.monotonic()))
        except queue.Empty:
            break
        if line == "SERVICE " + state:
            return
        assert line is not None, "client exited"
    raise AssertionError("missing state: " + state)

def main():
    assert os.geteuid() == 0 and pathlib.Path("/.dockerenv").exists(), "Disposable root Docker required"
    endpoint_binary = str(pathlib.Path(sys.argv[1]).resolve())
    processes, servers = [], []
    original_resolv = pathlib.Path("/etc/resolv.conf").read_bytes()
    s.command("ip", "netns", "add", s.NS)
    try:
        s.command("ip", "link", "add", "rtrust-host", "type", "veth", "peer", "name", "rtrust-client")
        s.command("ip", "link", "set", "rtrust-client", "netns", s.NS)
        s.command("ip", "addr", "add", "10.99.0.1/30", "dev", "rtrust-host")
        s.command("ip", "-6", "addr", "add", "fd00:99::1/64", "dev", "rtrust-host", "nodad")
        s.command("ip", "link", "set", "rtrust-host", "up")
        s.ns("ip", "addr", "add", "10.99.0.2/30", "dev", "rtrust-client")
        s.ns("ip", "-6", "addr", "add", "fd00:99::2/64", "dev", "rtrust-client", "nodad")
        s.ns("ip", "link", "set", "rtrust-client", "up")
        s.ns("ip", "link", "set", "lo", "up")
        s.ns("ip", "route", "add", "default", "via", "10.99.0.1")
        s.command("ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
        http = s.http.server.ThreadingHTTPServer(("198.18.0.1", 0), s.HTTP)
        http6 = HTTP6(("fd00:99::1", 0), s.HTTP)
        dns = socketserver.ThreadingUDPServer(("198.18.0.1", 53), DNS)
        servers.extend([http, http6, dns])
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://198.18.0.1:{http.server_port}/"
        url6 = f"http://[fd00:99::1]:{http6.server_port}/"
        def fetch(uid, peer):
            result = s.app(uid, "curl", "--noproxy", "*", "-sSf", "--max-time", "8", "-D", "-", url)
            headers, body = result.split(b"\r\n\r\n", 1)
            assert body == s.BODY and f"X-Peer: {peer}".encode() in headers
        def ipv6(works, tunneled=False):
            result=s.app(1000, "curl", "--noproxy", "*", "-sSf", "--max-time", "4", "-D", "-", url6, success=works)
            if works:
                headers,body=result.split(b"\r\n\r\n",1)
                assert body==s.BODY
                assert (b"X-Peer: fd00:99::1" if tunneled else b"X-Peer: fd00:99::2") in headers
        def lookup(peer):
            start = len(peers)
            result = s.app(1000, "python3", "-c", "import socket,sys; print(socket.getaddrinfo(sys.argv[1],80,socket.AF_INET,socket.SOCK_STREAM)[0][4][0])", f"name-{time.time_ns()}.rtrust.test")
            assert result.strip() == b"198.18.0.1"
            assert peers[start:] and set(peers[start:]) == {peer}, peers[start:]
        with tempfile.TemporaryDirectory(prefix="rtrust-full-") as directory:
            d = pathlib.Path(directory); d.chmod(0o711)
            def spawn(args, filename, namespace=False, cwd=None):
                with (d / filename).open("wb") as log:
                    p = subprocess.Popen((["ip", "netns", "exec", s.NS] if namespace else []) + args, stdout=log, stderr=log, cwd=cwd)
                processes.append(p)
                return p
            pathlib.Path("/run/dbus").mkdir(exist_ok=True)
            spawn(["dbus-daemon", "--system", "--nofork", "--nopidfile"], "dbus.log", True)
            for _ in range(100):
                if pathlib.Path("/run/dbus/system_bus_socket").exists(): break
                time.sleep(.05)
            spawn(["/lib/systemd/systemd-resolved"], "resolved.log", True)
            for _ in range(100):
                r = subprocess.run(["ip", "netns", "exec", s.NS, "resolvectl", "status"], capture_output=True)
                if r.returncode == 0: break
                time.sleep(.05)
            else: raise AssertionError((d / "resolved.log").read_text())
            pathlib.Path("/etc/resolv.conf").write_text("nameserver 127.0.0.53\noptions timeout:1 attempts:1\n")
            s.ns("resolvectl", "dns", "rtrust-client", "198.18.0.1")
            s.ns("resolvectl", "domain", "rtrust-client", "~.")
            # Link-local DAD can finish after interface-up and legitimately add a
            # kernel local route. Freeze the baseline only after it completes.
            for _ in range(100):
                addresses=json.loads(s.ns("ip","-j","-6","address","show","dev","rtrust-client"))
                if not any(addr.get("tentative",False) or "tentative" in addr.get("flags",[]) for device in addresses for addr in device.get("addr_info",[])):
                    break
                time.sleep(.05)
            else: raise AssertionError("Fixture IPv6 DAD did not complete")
            baseline_rules6=s.ns("ip","-j","-6","rule","show")
            baseline_routes6=s.ns("ip","-j","-6","route","show","table","all")
            baseline_rules = s.ns("ip", "-j", "-4", "rule", "show")
            baseline_routes = s.ns("ip", "-j", "-4", "route", "show", "table", "all")
            # Preserve an unrelated nftables table throughout install/recovery.
            s.ns("nft", "add", "table", "inet", "foreign_test")
            baseline_nft = s.ns("nft", "-j", "list", "tables")
            s.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", str(d/"key.pem"), "-out", str(d/"cert.pem"))
            (d/"vpn.toml").write_text('listen_address="10.99.0.1:8443"\nallow_private_network_connections=true\ncredentials_file="credentials.toml"\n[listen_protocols.http2]\n')
            (d/"hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (d/"credentials.toml").write_text('[[client]]\nusername="interop"\npassword="synthetic-full-test"\n')
            profile=d/"profile.json"
            profile.write_text(json.dumps(dict(schema_version=1, name="Full test", endpoint=dict(hostname="localhost", addresses=["10.99.0.1:8443"],username="interop",password="synthetic-full-test",certificate=(d/"cert.pem").read_text(),upstream_protocol="http2"))))
            profile.chmod(0o600); os.chown(profile,1000,1000)
            def endpoint():
                p = spawn([endpoint_binary,"vpn.toml","hosts.toml","--jobs","2"],"endpoint.log",cwd=d)
                for _ in range(100):
                    try:
                        with socket.create_connection(("10.99.0.1",8443), timeout=.1): return p
                    except OSError: time.sleep(.05)
                raise AssertionError((d/"endpoint.log").read_text())
            def daemon():
                p=spawn([str(s.ROOT/"target/debug/rtrust-service"),"1000"],"daemon.log",True)
                time.sleep(.3)
                assert p.poll() is None, (d/"daemon.log").read_text()
                return p
            ep=endpoint(); service=daemon()
            fetch(1000,"10.99.0.2"); ipv6(True); lookup("10.99.0.2")
            with s.client(profile,"--serve-full","198.18.0.1") as (client,lines):
                for uid in (0,1000,1001): fetch(uid,"198.18.0.1")
                lookup("198.18.0.1"); ipv6(True,True)
                assert "synthetic" not in pathlib.Path("/run/rtrust/full.json").read_text()
                print("PASS whole-host IPv4 (root + two users), system getaddrinfo DNS path, IPv6 tunneled (peer checked)", flush=True)
                s.stop(ep); wait_state(lines,"blocked")
                for uid in (0,1000,1001): s.app(uid,"curl","--noproxy","*","-sSf","--max-time","2",url,success=False)
                ipv6(False)
                # Direct DNS attempt cannot reach the physical resolver during outage.
                before=len(peers)
                s.app(1000,"python3","-c","import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.sendto(bytes.fromhex('abcd01000001000000000000017804746573740000010001'),('198.18.0.1',53)); s.recv(512)",success=False)
                assert len(peers)==before
                ep=endpoint(); wait_state(lines,"connected"); fetch(1000,"198.18.0.1"); lookup("198.18.0.1"); ipv6(True,True)
                s.stop(client); assert client.returncode==0
            assert s.ns("ip","-j","-4","rule","show")==baseline_rules
            assert s.ns("ip","-j","-4","route","show","table","all")==baseline_routes
            assert s.ns("ip","-j","-6","rule","show")==baseline_rules6
            assert s.ns("ip","-j","-6","route","show","table","all")==baseline_routes6, (baseline_routes6,s.ns("ip","-j","-6","route","show","table","all"))
            assert s.ns("nft","-j","list","tables")==baseline_nft
            fetch(1000,"10.99.0.2"); ipv6(True); lookup("10.99.0.2")
            print("PASS endpoint loss blocks IPv4/DNS/IPv6; reconnect restores VPN; Stop restores routes/DNS/firewall",flush=True)
            with s.client(profile,"--serve-full","198.18.0.1") as (client,_):
                fetch(1000,"198.18.0.1")
                client.kill(); client.wait(timeout=5)
                time.sleep(.3)
                assert pathlib.Path("/run/rtrust/full.json").exists()
                s.app(1000,"curl","--noproxy","*","-sSf","--max-time","2",url,success=False)
                ipv6(False)
                s.app(1000,str(s.ROOT/"target/debug/rtrust-inspect"),"--recover-service")
            fetch(1000,"10.99.0.2"); ipv6(True)
            print("PASS GUI/IPC client crash retains guard until explicit recovery",flush=True)
            with s.client(profile,"--serve-full","198.18.0.1") as (client,_):
                fetch(1000,"198.18.0.1")
                service.kill();service.wait(timeout=5)
                for uid in (0,1000,1001): s.app(uid,"curl","--noproxy","*","-sSf","--max-time","2",url,success=False)
                ipv6(False)
                service=daemon()
                s.app(1000,"curl","--noproxy","*","-sSf","--max-time","2",url,success=False)
                assert pathlib.Path("/run/rtrust/full.json").exists()
                # A new lease cannot silently clear the crash guard.
                s.app(1000,str(s.ROOT/"target/debug/rtrust-inspect"),str(profile),"--serve-full","198.18.0.1",success=False)
                s.app(1000,str(s.ROOT/"target/debug/rtrust-inspect"),"--recover-service")
            fetch(1000,"10.99.0.2");ipv6(True);lookup("10.99.0.2")
            assert s.ns("ip","-j","-6","rule","show")==baseline_rules6
            assert s.ns("ip","-j","-6","route","show","table","all")==baseline_routes6, (baseline_routes6,s.ns("ip","-j","-6","route","show","table","all"))
            assert s.ns("nft","-j","list","tables")==baseline_nft
            assert not pathlib.Path("/run/rtrust/full.json").exists()
            print("PASS SIGKILL/restart retain firewall guard; explicit recovery restores connectivity and foreign nft table",flush=True)
            # Each command uses a short-lived authenticated GUI connection. The
            # supervisor must keep the VPN alive after that connection closes.
            def ipc(op, **values):
                request=json.dumps(dict(version=1,command=dict(op=op,**values)))
                program="""import socket,struct,json,sys
c=socket.socket(socket.AF_UNIX);c.settimeout(60);c.connect('/run/rtrust/control.sock')
b=sys.argv[1].encode();c.sendall(struct.pack('!I',len(b))+b)
def exact(n):
 b=b''
 while len(b)<n:
  part=c.recv(n-len(b));assert part;b+=part
 return b
n=struct.unpack('!I',exact(4))[0];assert n<1048576
print(exact(n).decode())
"""
                return json.loads(s.app(1000,"python3","-c",program,request))
            def connected():
                for _ in range(100):
                    result=ipc("AlwaysOnStatus")
                    if result["state"]=="Connected": return
                    time.sleep(.15)
                raise AssertionError(result)
            policy=pathlib.Path('/var/lib/rtrust/always-on.rtrust')
            assert not policy.exists(), "Never replace an existing boot policy"
            assert ipc("EnableAlwaysOn",profile=json.loads(profile.read_text()),dns="198.18.0.1")["state"]=="Blocked"
            connected(); fetch(1000,"198.18.0.1"); ipv6(True,True)
            assert policy.stat().st_mode & 0o077 == 0
            assert b'synthetic-full-test' not in policy.read_bytes()
            for op in ("Recover","PrepareUpdate"):
                assert ipc(op)["state"]=="Error"
            service.kill();service.wait(timeout=5)
            s.app(1000,"curl","--noproxy","*","-sSf","--max-time","2",url,success=False)
            ipv6(False)
            service=daemon(); connected(); fetch(1000,"198.18.0.1"); ipv6(True,True)
            # A second physical link changes the endpoint's source IP/gateway.
            # The service must reconnect without a GUI command or guard removal.
            s.command("ip","link","add","rtrust-alt-host","type","veth","peer","name","rtrust-alt")
            s.command("ip","link","set","rtrust-alt","netns",s.NS)
            s.command("ip","addr","add","10.99.1.1/30","dev","rtrust-alt-host")
            s.command("ip","link","set","rtrust-alt-host","up")
            s.ns("ip","addr","add","10.99.1.2/30","dev","rtrust-alt")
            s.ns("ip","link","set","rtrust-alt","up")
            s.ns("ip","route","replace","default","via","10.99.1.1","dev","rtrust-alt")
            s.ns("ip","-6","addr","del","fd00:99::2/64","dev","rtrust-client")
            s.ns("ip","link","set","rtrust-client","down")
            s.ns("ip","addr","del","10.99.0.2/30","dev","rtrust-client")
            assert b'dev rtrust-alt' in s.ns("ip","route","get","10.99.0.1","mark","0x5254")
            s.ns("python3","-c","import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,36,0x5254); s.settimeout(3); s.connect(('10.99.0.1',8443)); print('PASS marked endpoint TCP after physical handoff')")
            def traffic_returns():
                until=time.monotonic()+70
                while True:
                    try:fetch(1000,"198.18.0.1");ipv6(True,True);return
                    except AssertionError:
                        if time.monotonic()>until:
                            print(ipc("AlwaysOnStatus"),flush=True)
                            print((d/"daemon.log").read_text(),flush=True)
                            raise
                        time.sleep(.5)
            traffic_returns()
            assert b'rtrust_boot' in s.ns("nft","-j","list","tables")
            s.ns("ip","addr","add","10.99.0.2/30","dev","rtrust-client")
            s.ns("ip","-6","addr","add","fd00:99::2/64","dev","rtrust-client","nodad")
            s.ns("ip","link","set","rtrust-client","up")
            s.ns("ip","route","replace","default","via","10.99.0.1","dev","rtrust-client")
            s.ns("ip","link","delete","rtrust-alt")
            traffic_returns()
            print("PASS always-on physical interface/gateway/source-IP handoff and return with firewall retained",flush=True)
            result=ipc("DisableAlwaysOn");assert result["state"]=="Idle", result
            assert not policy.exists()
            assert s.ns("nft","-j","list","tables")==baseline_nft
            assert s.ns("ip","-j","-4","rule","show")==baseline_rules
            assert s.ns("ip","-j","-4","route","show","table","all")==baseline_routes
            assert s.ns("ip","-j","-6","rule","show")==baseline_rules6
            assert s.ns("ip","-j","-6","route","show","table","all")==baseline_routes6
            fetch(1000,"10.99.0.2");ipv6(True)
            with s.client(profile,"--serve-full","198.18.0.1") as (client,_):
                assert ipc("DisableAlwaysOn")["state"]=="Idle"
                fetch(1000,"198.18.0.1")
                s.stop(client);assert client.returncode==0
            print("PASS always-on survives GUI disconnect and service SIGKILL/restart; encrypted policy; update/recover refused; disable restores exact dual-stack state",flush=True)
            assert ipc("EnableAlwaysOn",profile=json.loads(profile.read_text()),dns="198.18.0.1")["state"]=="Blocked"
            connected();service.kill();service.wait(timeout=5)
            # Corrupt ciphertext must never silently disable the stored intent.
            damaged=bytearray(policy.read_bytes());damaged[-1]^=1;policy.write_bytes(damaged)
            s.ns("nft","delete","table","inet","rtrust_boot")
            s.ns(str(s.ROOT/"target/debug/rtrust-service"),"--boot-guard","1000")
            assert b'rtrust_boot' in s.ns("nft","-j","list","tables")
            service=daemon()
            result=ipc("AlwaysOnStatus");assert result["state"]=="Blocked",result
            s.app(1000,"curl","--noproxy","*","-sSf","--max-time","2",url,success=False)
            ipv6(False)
            result=ipc("DisableAlwaysOn");assert result["state"]=="Idle",result
            fetch(1000,"10.99.0.2");ipv6(True)
            assert s.ns("nft","-j","list","tables")==baseline_nft
            print("PASS early boot guard and corrupted policy fail closed; explicit disable restores network",flush=True)


    finally:
        for p in reversed(processes): s.stop(p)
        pathlib.Path("/etc/resolv.conf").write_bytes(original_resolv)
        for server in servers: server.shutdown();server.server_close()
        s.command("ip","netns","delete",s.NS)
        subprocess.run(["ip","link","delete","rtrust-host"],capture_output=True)
        subprocess.run(["ip","link","delete","rtrust-alt-host"],capture_output=True)
        subprocess.run(["ip","addr","del","198.18.0.1/32","dev","lo"],capture_output=True)

if __name__ == "__main__": main()
