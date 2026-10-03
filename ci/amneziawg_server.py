#!/usr/bin/env python3
"""Build the AmneziaWG fixture peer for Linux in a pinned Go container.

CI nodes have Docker but no Go toolchain. Module versions are pinned by
ci/amneziawg_fixture/go.sum; the result is cached by a hash of the sources.
"""
import hashlib,os,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/'ci/amneziawg_fixture'
IMAGE='golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d'
def binary():
    digest=hashlib.sha256()
    for path in sorted(SOURCE.iterdir()):digest.update(path.name.encode()+b'\0'+path.read_bytes())
    directory=ROOT/'.ci-tools/amneziawg'/digest.hexdigest()[:16];target=directory/'amneziawg-fixture'
    if not target.exists():
        directory.mkdir(parents=True,exist_ok=True)
        # Build as the calling user so that nothing root-owned is left behind;
        # the Go caches then live in the container's temporary directory.
        subprocess.run(['docker','run','--rm','--user',f'{os.getuid()}:{os.getgid()}','-e','HOME=/tmp','-e','GOCACHE=/tmp/cache','-e','GOMODCACHE=/tmp/mod','-e','CGO_ENABLED=0','-e','GOFLAGS=-mod=readonly',
                        '-v',f'{SOURCE}:/src:ro,z','-v',f'{directory}:/out:z','-w','/src',IMAGE,'go','build','-trimpath','-o','/out/amneziawg-fixture.partial','.'],check=True,timeout=900)
        (directory/'amneziawg-fixture.partial').replace(target)
    return target
if __name__=='__main__':print(binary())
