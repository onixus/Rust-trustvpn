# Exact-commit Linux laboratory evidence

`ci/linux_lab.py` runs the existing service IPC, full-tunnel HTTP/2, HTTP/3 and permitted
failover scenarios against an immutable source archive. This checks synthetic
traffic in disposable Docker and nested Linux network namespaces. It does not
establish installed-package, physical-device, signing or update acceptance.

Run the script from the commit being evaluated. The runner rejects abbreviated
SHAs, non-commit objects, and a runner that differs from that commit:

```sh
python3 ci/linux_lab.py \
  --sha FULL_40_CHARACTER_COMMIT_SHA \
  --host fedor \
  --endpoint-archive /home/onixus/rtrust-recovery/.ci-tools/linux-endpoint/endpoint.tar.gz
```

The SSH destination must already be configured and trusted. The pinned tool
image and official TrustTunnel v1.1.0 x86_64 endpoint archive must already be
cached on an x86_64 Linux Docker VM. The archive checksum is checked before
extracting a new fixture binary. The runner uses the existing
`rtrust-linux-cargo` registry and `rtrust-ci-linux-x86_64-target` build caches;
`cargo build --locked --offline` fails explicitly if a dependency is absent.
Only `rtrust-tun` and `rtrust-inspect` are built. Unit tests and strict all-target Clippy check `rtrust-tun` and
`rtrust-control`. The disposable extracted source receives fresh regular-file
timestamps before the build, preventing commit timestamps older than a shared
build cache from hiding changed inputs. Source contents remain the archived
bytes. Test binaries are copied and
hashed immediately after that build; packet scenarios do not execute mutable
cache paths.

The tool image starts from a digest-pinned Rust 1.98.1 image. Container-only
package installation prepares route, firewall, resolver and fixture tools.
Clippy is installed only inside this image from the checksum-pinned official
1.98.1 x86_64 archive. A validated local cache is preferred; otherwise a bounded
HTTPS download retrieves that fixed archive from static.rust-lang.org. Its
checksum, the tool image ID, Dockerfile checksum and package inventory are
recorded. Each packet
scenario gets a fresh container with `--network none`, `NET_ADMIN`, `SYS_ADMIN`
and `/dev/net/tun`, as required by the existing nested-network-namespace
harness. It receives only read-only source, newly built binaries and the fixture.
No host network, host PID namespace, Docker socket, host service directory or
host resolver configuration is mounted. The runner never installs a system
service or changes host routes/firewall.

Build/image/scenario steps have independent deadlines. Interrupts and failures
remove only this run's explicitly named containers and image. If SSH is lost,
the local cleanup path stops only the recorded worker whose process command
still matches this run's temporary directory, then removes its containers.
An unreachable VM prevents remote cleanup confirmation; reconnect and inspect
that run's recorded names before treating the run as complete.

Evidence is saved under `dist/lab/SHA-RUN_ID/` (or `--output NEW_DIRECTORY`):

- The original exact-commit source archive and its SHA256.
- `evidence.tar.gz`, containing the source archive, manifest, Dockerfile and
  per-step stdout/stderr logs, including compiler and package versions.
- Manifest hashes for the runner, all imported packet harnesses, endpoint
  archive/binary, tool image and all three built binaries.
- `artifact_sha256.json` binding the retained evidence files. Build binaries are
  discarded after recording their hashes.

`manifest.json` reports each lane's exit code, elapsed time, overall result and
cleanup failures. Missing or failed lanes are not acceptance evidence. Fixture
credentials and destinations are synthetic and confined to the laboratory;
this runner does not read a user's profile vault or contact configured endpoints.
