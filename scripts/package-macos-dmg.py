#!/usr/bin/env python3
"""Create and verify an unsigned DMG from the already packaged native app."""
import hashlib
import pathlib
import platform
import plistlib
import shutil
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "dist/native-preview-darwin/R-TrustTunnel Preview.app"
OUTPUT = ROOT / "dist/R-TrustTunnel-macOS-arm64-preview.dmg"


def run(*args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr.decode(errors='replace')}")
    return result.stdout


def main():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Run on macOS Apple Silicon with an arm64 native app")
    executable = APP / "Contents/MacOS/rtrust-native"
    with executable.open("rb") as binary:
        header = binary.read(8)
    if header != struct.pack("<II", 0xFEEDFACF, 0x0100000C):
        raise SystemExit("Expected an arm64 executable")
    with tempfile.TemporaryDirectory(prefix="rtrust-dmg-") as temporary:
        work = pathlib.Path(temporary)
        stage = work / "stage"
        stage.mkdir()
        run("ditto", str(APP), str(stage / APP.name))
        (stage / "Applications").symlink_to("/Applications")
        (stage / "READ ME.txt").write_text(
            "R-TrustTunnel — macOS Apple Silicon preview\n\n"
            "Drag the app to Applications. No VPN service is installed.\n"
            "Profiles and SOCKS5 work directly. System VPN requires the separate system-service installer.\n"
            "No Apple Developer certificate, notarization or Network Extension is included.\n"
            "macOS may require explicit approval in Privacy & Security after the first launch.\n"
            "Do not disable Gatekeeper globally.\n", encoding="utf-8")
        candidate = work / OUTPUT.name
        run("hdiutil", "create", "-quiet", "-volname", "R-TrustTunnel",
            "-srcfolder", str(stage), "-format", "UDZO", str(candidate))
        run("hdiutil", "verify", str(candidate))
        mounted = plistlib.loads(run("hdiutil", "attach", "-readonly", "-nobrowse", "-plist", str(candidate)))
        volumes = [v for v in mounted["system-entities"] if "mount-point" in v]
        try:
            if len(volumes) != 1:
                raise RuntimeError("Expected exactly one application volume")
            volume = pathlib.Path(volumes[0]["mount-point"])
            bundled = volume / APP.name / "Contents/MacOS/rtrust-native"
            if hashlib.sha256(bundled.read_bytes()).digest() != hashlib.sha256(executable.read_bytes()).digest():
                raise RuntimeError("Packaged binary differs from input")
            if (volume / "Applications").readlink() != pathlib.Path("/Applications"):
                raise RuntimeError("Invalid Applications shortcut")
            # Launch from the mounted read-only image, with no access to the real vault.
            subprocess.run([str(bundled), "--ci-smoke"], check=True, timeout=30)
        finally:
            for entity in reversed(mounted["system-entities"]):
                if "mount-point" in entity:
                    run("hdiutil", "detach", entity["dev-entry"])
        shutil.copy2(candidate, OUTPUT)
    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    OUTPUT.with_suffix(".dmg.sha256").write_text(f"{digest}  {OUTPUT.name}\n")
    print(f"PASS read-only DMG verification and packaged GUI smoke: {OUTPUT}")


if __name__ == "__main__":
    main()
