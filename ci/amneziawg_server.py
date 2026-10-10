#!/usr/bin/env python3
"""Build the AmneziaWG fixture peer for Linux in a pinned Go container.

CI nodes have Docker but no Go toolchain. Module versions are pinned by
ci/amneziawg_fixture/go.sum; the result is cached by a hash of the sources, architecture and pinned toolchain.
"""
import hashlib,os,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/'ci/amneziawg_fixture'
TOOLCHAIN='go1.26.9'
IMAGE='golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c'
def binary(arch='amd64'):
    digest=hashlib.sha256((arch+'\0'+IMAGE+'\0').encode())
    for path in sorted(SOURCE.iterdir()):digest.update(path.name.encode()+b'\0'+path.read_bytes())
    directory=ROOT/'.ci-tools/amneziawg'/digest.hexdigest()[:16];target=directory/'amneziawg-fixture'
    if not target.exists():
        directory.mkdir(parents=True,exist_ok=True)
        # Build as the calling user so that nothing root-owned is left behind;
        # the Go caches then live in the container's temporary directory.
        subprocess.run(['docker','run','--rm','--user',f'{os.getuid()}:{os.getgid()}','-e','HOME=/tmp','-e','GOCACHE=/tmp/cache','-e','GOMODCACHE=/tmp/mod','-e','CGO_ENABLED=0','-e','GOOS=linux','-e','GOARCH='+arch,'-e','GOFLAGS=-mod=readonly','-e','GOTOOLCHAIN=local',
                        '-v',f'{SOURCE}:/src:ro,z','-v',f'{directory}:/out:z','-w','/src',IMAGE,'go','build','-trimpath','-o','/out/amneziawg-fixture.partial','.'],check=True,timeout=900)
        (directory/'amneziawg-fixture.partial').replace(target)
    return target
if __name__=='__main__':print(binary(*sys.argv[1:2]))
