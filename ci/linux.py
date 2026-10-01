"""Linux native/TUN checks in a disposable Docker VM namespace, from this source snapshot."""
import hashlib
import os
import pathlib
import platform
import secrets
import signal
import subprocess
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / ".ci-tools/linux-endpoint"
NAME = "rtrust-linux-ci-" + secrets.token_hex(4)
ARCH = 'aarch64' if platform.machine() in ('arm64', 'aarch64') else 'x86_64'
DOCKER_ARCH = 'arm64' if ARCH == 'aarch64' else 'amd64'
SHA = {'aarch64':'c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686',
       'x86_64':'91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7'}[ARCH]
CLIPPY_SHA = {'aarch64':'396e17c0a669399823d0e59073686a4e5f50b2d41f062f1d3afc9210f9d3553d',
              'x86_64':'e167f333be24e1d5eea56ea563c7def0aa0bd613f5ce3445976c93b0288799d1'}[ARCH]
CLIPPY_URL = f"https://static.rust-lang.org/dist/2026-09-03/clippy-1.98.1-{ARCH}-unknown-linux-gnu.tar.xz"
URL = f"https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-{ARCH}.tar.gz"

def interrupted(signum, _frame):
    # Jenkins cancellation also kills the Docker CLI; the daemon container must
    # be removed explicitly instead of surviving a cancelled pipeline.
    subprocess.run(["docker", "rm", "-f", NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)

def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    clippy=CACHE/CLIPPY_SHA
    if not clippy.exists() or hashlib.sha256(clippy.read_bytes()).hexdigest()!=CLIPPY_SHA:
        with urllib.request.urlopen(CLIPPY_URL,timeout=30) as response: data=response.read(8*1024*1024)
        assert hashlib.sha256(data).hexdigest()==CLIPPY_SHA,"Official Clippy checksum mismatch"
        clippy.write_bytes(data)
    archive = CACHE / "endpoint.tar.gz"
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA:
        with urllib.request.urlopen(URL, timeout=60) as response:
            archive.write_bytes(response.read(32 * 1024 * 1024))
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == SHA, "Official endpoint checksum mismatch"
    with tarfile.open(archive) as tar:
        member = next(m for m in tar if m.name.endswith("/trusttunnel_endpoint"))
        binary = CACHE / "trusttunnel_endpoint"
        binary.write_bytes(tar.extractfile(member).read()); binary.chmod(0o755)
    (ROOT / "dist").mkdir(exist_ok=True)
    # runc cannot create a nested volume mountpoint through the read-only source bind.
    (ROOT / "target").mkdir(exist_ok=True)
    script = '''set -eu
apt-get -o Acquire::http::Timeout=20 update -qq
apt-get install -y -qq iproute2 iputils-ping curl python3 libdbus-1-dev nftables systemd-resolved dbus libglib2.0-bin python3-dbus python3-gi gnome-keyring weston libwayland-client0 libxkbcommon0 libegl1 libfontconfig1-dev
mkdir -p /usr/local/rustup/downloads
cp /fixture/CLIPPY_ARCHIVE /usr/local/rustup/downloads/
rustup component add clippy
cargo test --workspace --locked --quiet
cargo test -p rtrust-native --locked desktop_entry_exec_roundtrip -- --ignored
dbus-run-session -- sh -c 'printf "%s" "rtrust-isolated-ci" | gnome-keyring-daemon --unlock --components=secrets >/tmp/rtrust-keyring-env; cargo test -p rtrust-store --locked os_keyring_restart_roundtrip -- --ignored --exact tests::os_keyring_restart_roundtrip'
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release -p rtrust-native -p rtrust-tun -p rtrust-inspect --locked
# The existing packet harness uses debug paths.
mkdir -p target/debug
cp target/release/rtrust-service target/release/rtrust-inspect target/release/rtrust-tun target/debug/
python3 ci/wayland_smoke.py
python3 scripts/service-interop.py /fixture/trusttunnel_endpoint
python3 scripts/tun-interop.py /fixture/trusttunnel_endpoint
python3 scripts/full-tunnel-interop.py /fixture/trusttunnel_endpoint
python3 ci/linux_installer_smoke.py
python3 scripts/package-preview.py
mkdir -p dist/service-preview-linux
cp target/release/rtrust-service scripts/install-linux-service.sh deploy/rtrust-service@.service deploy/rtrust-boot-guard@.service docs/linux-service.md dist/service-preview-linux/
'''.replace('CLIPPY_ARCHIVE', CLIPPY_SHA)
    try:
        subprocess.run(["docker", "run", "--rm", "--name", NAME, "--platform", "linux/"+DOCKER_ARCH, "--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN", "--device", "/dev/net/tun",
            "-v", f"{ROOT}:/work:ro", "-v", f"{ROOT / 'dist'}:/work/dist", "-v", f"rtrust-ci-linux-{ARCH}-target:/work/target", "-v", "rtrust-linux-cargo:/usr/local/cargo/registry", "-v", f"{CACHE}:/fixture:ro", "-w", "/work", "rust:1.98.1-bookworm", "sh", "-c", script], check=True, timeout=1800)
    finally:
        subprocess.run(["docker", "rm", "-f", NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        # Root is needed only inside the disposable network test container.
        # Return its published files to the agent so the next deleteDir works.
        subprocess.run(["docker", "run", "--rm", "--network", "none",
            "-v", f"{ROOT / 'dist'}:/artifacts", "rust:1.98.1-bookworm",
            "chown", "-hR", f"{os.getuid()}:{os.getgid()}", "/artifacts"],
            check=True, timeout=60)

if __name__ == "__main__": main()
