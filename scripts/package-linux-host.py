#!/usr/bin/env python3
"""Build an Arch host-service package; the unprivileged GUI remains a Flatpak."""
import argparse
import hashlib
import pathlib
import platform
import shutil
import struct
import subprocess
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=pathlib.Path, default=ROOT/'target/release/rtrust-service')
parser.add_argument('--pkgrel', type=int, default=1)
args = parser.parse_args()
assert platform.system() == 'Linux' and args.pkgrel > 0
arch = platform.machine()
assert arch in ('x86_64', 'aarch64')
header = args.binary.read_bytes()[:20]
assert header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 18)[0] == {'x86_64':62,'aarch64':183}[arch]
version = tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['package']['version']
output = ROOT/'dist'; output.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='rtrust-host-package-') as directory:
    work = pathlib.Path(directory)
    files = work/'files'
    def copy(source, destination, mode=0o644):
        target = files/destination; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target); target.chmod(mode)
    copy(args.binary, 'usr/libexec/rtrust/rtrust-service', 0o755)
    for name in ('setup','enable-service','package-guard'):
        copy(ROOT/'packaging/linux-host'/name, 'usr/libexec/rtrust/'+name, 0o755)
    copy(ROOT/'packaging/linux-host/org.rtrusttunnel.HostSetup.desktop', 'usr/share/applications/org.rtrusttunnel.HostSetup.desktop')
    copy(ROOT/'packaging/linux-host/org.rtrusttunnel.configure.policy', 'usr/share/polkit-1/actions/org.rtrusttunnel.configure.policy')
    copy(ROOT/'deploy/org.rtrusttunnel.Service.conf', 'usr/share/dbus-1/system.d/org.rtrusttunnel.Service.conf')
    copy(ROOT/'deploy/rtrust-flatpak.conf', 'usr/lib/systemd/system/rtrust-service@.service.d/flatpak.conf')
    for name in ('rtrust-service@.service','rtrust-boot-guard@.service'):
        copy(ROOT/'deploy'/name, 'usr/lib/systemd/system/'+name)
    copy(ROOT/'packaging/linux-host/rtrust-host.install', 'usr/libexec/rtrust/package-lifecycle')
    copy(ROOT/'packaging/linux-host/rtrust-guard.hook', 'usr/share/libalpm/hooks/00-rtrust-guard.hook')
    copy(ROOT/'LICENSE', 'usr/share/licenses/rtrust-host/LICENSE')
    shutil.copyfile(ROOT/'packaging/linux-host/rtrust-host.install', work/'rtrust-host.install')
    (work/'PKGBUILD').write_text(f'''pkgname=rtrust-host
pkgver={version}
pkgrel={args.pkgrel}
pkgdesc='Privileged VPN service and desktop setup for R-TrustTunnel Flatpak'
arch=('{arch}')
license=('Apache-2.0')
depends=('glibc' 'gcc-libs' 'systemd' 'iproute2' 'nftables' 'dbus' 'polkit' 'kdialog')
install=rtrust-host.install
options=('!strip' '!debug')
package() {{ cp -a "$startdir/files/." "$pkgdir/"; }}
''')
    subprocess.run(['makepkg','--nodeps','--noconfirm'], cwd=work, check=True)
    package = next(work.glob('rtrust-host-*.pkg.tar.*'))
    target = output/package.name; shutil.copyfile(package, target)
    target.with_name(target.name+'.sha256').write_text(hashlib.sha256(target.read_bytes()).hexdigest()+'  '+target.name+'\n')
    print(target)
