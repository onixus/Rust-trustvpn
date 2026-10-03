#!/usr/bin/env python3
"""Loopback-only interoperability with the official amneziawg-go v3.1 peer.

The fixture runs the reference device on a userspace network stack: it creates
no TUN device and changes no routes or DNS. Go module versions are pinned by
ci/amneziawg_fixture/go.sum."""
import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
MODES={'plain':'unmodified WireGuard wire format','awg2':'junk, signature packets, S1-S4 prefixes and H1-H4 ranges','awg3':'header protection, content padding, random trailers and configured timers'}
def main():
    with tempfile.TemporaryDirectory(prefix='rtrust-awg-') as tmp:
        work=pathlib.Path(tmp);fixture=work/'fixture'
        subprocess.run(['go','build','-mod=readonly','-o',str(fixture),'.'],cwd=ROOT/'ci/amneziawg_fixture',check=True,timeout=600)
        subprocess.run(['cargo','test','--locked','-p','rtrust-engine','--test','amneziawg_fixture','--no-run'],cwd=ROOT,check=True,timeout=1800)
        for mode in MODES:
            client=work/f'{mode}.conf'
            with (work/f'{mode}.log').open('wb') as log:
                process=subprocess.Popen([str(fixture),mode,str(client)],stdout=subprocess.PIPE,stderr=log)
                try:
                    if process.stdout.readline().strip()!=b'ready':raise RuntimeError(f'AmneziaWG fixture did not start: {(work/f"{mode}.log").read_text()}')
                    env={**os.environ,'RTRUST_AMNEZIAWG_FIXTURE':str(client)}
                    if mode=='awg3':env['RTRUST_AMNEZIAWG_REKEY']='1'
                    subprocess.run(['cargo','test','--locked','-p','rtrust-engine','--test','amneziawg_fixture','--','--ignored','--nocapture'],cwd=ROOT,env=env,check=True,timeout=300)
                finally:
                    process.terminate();process.wait(timeout=10)
    for mode,what in MODES.items():print(f'PASS official amneziawg-go 3.1 ({mode}): {what}; TCP over IPv4/IPv6, tunnel DNS, UDP, wrong key rejected')
if __name__=='__main__':main()
