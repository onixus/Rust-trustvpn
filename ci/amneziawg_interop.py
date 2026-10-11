#!/usr/bin/env python3
"""Loopback-only interoperability with the official amneziawg-go v3.1 peer.

The fixture runs the reference device on a userspace network stack: it creates
no TUN device and changes no routes or DNS. Go module versions are pinned by
ci/amneziawg_fixture/go.sum."""
import hashlib,json,os,pathlib,platform,socket,socketserver,struct,subprocess,tempfile,threading,sys
from amneziawg_server import TOOLCHAIN
ROOT=pathlib.Path(__file__).resolve().parents[1]
MODES={'plain':'unmodified WireGuard wire format','awg2':'junk, signature packets, S1-S4 prefixes and H1-H4 ranges','awg3':'header protection, content padding, random trailers and configured timers'}
class Digest(socketserver.StreamRequestHandler):
    """Length-prefixed upload answered by its SHA-256, as the built-in fixture target."""
    def handle(self):
        size=struct.unpack('!I',self.rfile.read(4))[0];self.wfile.write(hashlib.sha256(self.rfile.read(size)).hexdigest().encode())
class DualStack(socketserver.ThreadingTCPServer):
    address_family=socket.AF_INET6;allow_reuse_address=True;daemon_threads=True
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);super().server_bind()
def forwarding(work,fixture):
    """The Android fixture's forwarding peer against loopback targets of this script,
    reached through the peer's loopback alias."""
    host,alias='127.0.0.1','198.18.0.1'
    tcp=DualStack(('::',0),Digest);threading.Thread(target=tcp.serve_forever,daemon=True).start()
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind((host,0))
    def echo():
        while True:
            try:data,peer=udp.recvfrom(65535)
            except OSError:return
            udp.sendto(data,peer)
    threading.Thread(target=echo,daemon=True).start()
    subprocess.run([str(fixture),'keygen',str(work)],check=True,timeout=30)
    # The peer listens on a fixed port inside the Android container; move it to a free one here.
    probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
    uapi=work/'amneziawg.uapi';uapi.write_text(uapi.read_text().replace('listen_port=4433',f'listen_port={port}'))
    profile=json.loads((work/'amneziawg-client.json').read_text());profile['endpoint'].update(hostname='localhost',addresses=[f'127.0.0.1:{port}'])
    client=work/'forward.json';client.write_text(json.dumps(profile));client.chmod(0o600)
    process=subprocess.Popen([str(fixture),'serve',str(uapi),alias],stdout=subprocess.PIPE)
    try:
        if process.stdout.readline().strip()!=b'ready':raise RuntimeError('AmneziaWG forwarding peer did not start')
        env={**os.environ,'RTRUST_AMNEZIAWG_FORWARD':str(client),'RTRUST_AMNEZIAWG_TCP':f'{alias}:{tcp.server_address[1]}','RTRUST_AMNEZIAWG_UDP':f'{alias}:{udp.getsockname()[1]}','RTRUST_AMNEZIAWG_MAX_UDP':'8192' if platform.system()=='Darwin' else '60000'}
        subprocess.run(['cargo','test','--locked','-p','rtrust-engine','--test','amneziawg_fixture','forwarding_peer','--','--ignored','--nocapture'],cwd=ROOT,env=env,check=True,timeout=300)
    finally:
        process.terminate();process.wait(timeout=10);tcp.shutdown();udp.close()
def main():
    subprocess.run([sys.executable, str(ROOT / 'ci/test_amneziawg_cache.py')], check=True)
    with tempfile.TemporaryDirectory(prefix='rtrust-awg-') as tmp:
        work=pathlib.Path(tmp);fixture=work/'fixture'
        subprocess.run(['go','build','-mod=readonly','-o',str(fixture),'.'],cwd=ROOT/'ci/amneziawg_fixture',env={**os.environ,'GOTOOLCHAIN':TOOLCHAIN},check=True,timeout=600)
        subprocess.run(['cargo','test','--locked','-p','rtrust-engine','--test','amneziawg_fixture','--no-run'],cwd=ROOT,check=True,timeout=1800)
        for mode in MODES:
            client=work/f'{mode}.conf'
            with (work/f'{mode}.log').open('wb') as log:
                process=subprocess.Popen([str(fixture),mode,str(client)],stdout=subprocess.PIPE,stderr=log)
                try:
                    if process.stdout.readline().strip()!=b'ready':raise RuntimeError(f'AmneziaWG fixture did not start: {(work/f"{mode}.log").read_text()}')
                    env={**os.environ,'RTRUST_AMNEZIAWG_FIXTURE':str(client)}
                    if mode=='awg3':env['RTRUST_AMNEZIAWG_REKEY']='1'
                    subprocess.run(['cargo','test','--locked','-p','rtrust-engine','--test','amneziawg_fixture','reference_peer','--','--ignored','--nocapture'],cwd=ROOT,env=env,check=True,timeout=300)
                finally:
                    process.terminate();process.wait(timeout=10)
        forwarding(work,fixture)
    print('PASS amneziawg-go 3.1 forwarding peer: TCP, refused port, fragmented UDP')
    for mode,what in MODES.items():print(f'PASS official amneziawg-go 3.1 ({mode}): {what}; TCP over IPv4/IPv6, tunnel DNS, UDP, wrong key rejected')
if __name__=='__main__':main()
