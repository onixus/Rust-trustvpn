"""Fetch the official signed Wintun distribution with the publisher's SHA256."""
import hashlib,pathlib,shutil,subprocess,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
SHA='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
def install(destination):
    cache=ROOT/'.ci-tools/wintun';cache.mkdir(parents=True,exist_ok=True)
    archive=cache/'wintun-0.14.1.zip'
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA:
        subprocess.run(['curl.exe','-fLsS','--connect-timeout','15','--max-time','120','--retry','2','https://www.wintun.net/builds/wintun-0.14.1.zip','-o',str(archive)],check=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA:raise RuntimeError('Wintun checksum mismatch')
    destination=pathlib.Path(destination);destination.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive) as package:
        (destination/'wintun.dll').write_bytes(package.read('wintun/bin/amd64/wintun.dll'))
        (destination/'WINTUN-LICENSE.txt').write_bytes(package.read('wintun/LICENSE.txt'))
    shutil.copy2(ROOT/'target/release/rtrust-service.exe',destination/'rtrust-service.exe')
    shutil.copy2(ROOT/'scripts/install-windows-service.ps1',destination/'install-windows-service.ps1')
    (destination/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(destination.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
    shutil.make_archive(str(ROOT/'dist/R-TrustTunnel-Windows-preview'),'zip',destination)
if __name__=='__main__':install(ROOT/'dist/native-preview-windows')
