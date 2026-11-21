"""Stage the Rttun driver package beside the Windows service.

The Windows node builds rttun.sys with the WDK. This host only checks that the
three package files exist and that the catalog is Authenticode-valid. A missing
file or a signature other than Valid fails the stage. Test-signing is not a
success path, and wintun.dll is not fetched or copied.
"""
import hashlib, os, pathlib, shutil, subprocess, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "drivers/windows/rttun"
FILES = ("rttun_umdf.dll", "rttun.inf", "rttun.cat")

def require_wdk():
    """The Windows node has the SDK. The driver still needs the WDK."""
    if not sys.platform.startswith("win"):
        return
    kits = pathlib.Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10"
    inf2cat = list(kits.glob("bin/*/x64/inf2cat.exe")) if kits.is_dir() else []
    wdf = kits / "Include" / "wdf"
    if not inf2cat or not wdf.is_dir():
        raise SystemExit("WDK is not installed; refusing to ship a package without rttun_umdf.dll")

def install(destination):
    require_wdk()
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        source = PACKAGE / name
        if not source.is_file():
            raise SystemExit(f"missing {source}; WDK build did not produce the driver")
        shutil.copy2(source, destination / name)
    catalog = destination / "rttun.cat"
    signature = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "(Get-AuthenticodeSignature -LiteralPath $args[0]).Status"],
        args := [str(catalog)], capture_output=True, text=True, timeout=60)
    del args
    status = (signature.stdout or "").strip()
    if signature.returncode or status != "Valid":
        raise SystemExit(f"rttun.cat signature is {status or 'unavailable'}; refusing unsigned or test-signed driver")
    if (destination / "wintun.dll").exists():
        raise SystemExit("wintun.dll is staged beside the service; refusing to ship it")
    sums = destination / "SHA256SUMS"
    sums.write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
        for path in sorted(destination.iterdir())
        if path.is_file() and path.name != "SHA256SUMS"
    ))
    print("PASS rttun package staged; catalog signature Valid")

if __name__ == "__main__":
    install(ROOT / "dist/native-preview-windows")
    sys.exit(0)
