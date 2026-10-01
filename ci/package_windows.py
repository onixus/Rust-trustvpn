"""Build the native x64 Setup with a SHA256-pinned official Inno compiler."""
import hashlib, os, pathlib, struct, subprocess, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[1]
def imports(path):
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe+4] == b'PE\0\0', 'Expected PE executable'
    count = struct.unpack_from('<H', data, pe+6)[0]
    optional_size = struct.unpack_from('<H', data, pe+20)[0]
    optional = pe+24
    assert struct.unpack_from('<H', data, optional)[0] == 0x20b, 'Expected PE32+ x64'
    sections = optional+optional_size
    def offset(rva):
        for i in range(count):
            size, address, raw_size, raw = struct.unpack_from('<IIII', data, sections+i*40+8)
            if address <= rva < address+max(size, raw_size): return raw+rva-address
        raise ValueError('Invalid PE section RVA')
    cursor = offset(struct.unpack_from('<I', data, optional+120)[0])
    names = []
    while any(data[cursor:cursor+20]):
        name = offset(struct.unpack_from('<I', data, cursor+12)[0])
        names.append(data[name:data.index(b'\0', name)].decode('ascii').lower())
        cursor += 20
    return names
for name in ['R-TrustTunnel.exe', 'rtrust-service.exe', 'rtrust-update.exe']:
    required = imports(ROOT/'dist/native-preview-windows'/name)
    assert not any(d.startswith(('vcruntime', 'msvcp')) for d in required), 'Build with static MSVC CRT: '+name
VERSION = '6.7.1'
SHA256 = '4d11e8050b6185e0d49bd9e8cc661a7a59f44959a621d31d11033124c4e8a7b0'
TOOLS = pathlib.Path(os.environ['USERPROFILE']) / '.jenkins-agent/tools' / ('inno-' + VERSION)
TOOLS.mkdir(parents=True, exist_ok=True)
archive = TOOLS / ('innosetup-' + VERSION + '.exe')
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
    with urllib.request.urlopen('https://github.com/jrsoftware/issrc/releases/download/is-6_7_1/innosetup-6.7.1.exe', timeout=60) as response:
        archive.write_bytes(response.read())
assert hashlib.sha256(archive.read_bytes()).hexdigest() == SHA256, 'Inno installer digest mismatch'
compiler = TOOLS / 'compiler/ISCC.exe'
if not compiler.exists():
    subprocess.run([str(archive), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', '/DIR=' + str(compiler.parent)], check=True, timeout=180)
subprocess.run([str(compiler), str(ROOT / 'deploy/windows/setup.iss')], check=True, timeout=180)
setup = ROOT / 'dist/R-TrustTunnel-Windows-x64-Setup.exe'
setup.with_suffix('.exe.sha256').write_text(hashlib.sha256(setup.read_bytes()).hexdigest() + '  ' + setup.name + '\n')
print('PASS native Windows Setup and SHA256')
