#!/usr/bin/env python3
"""Package the native preview from an already built binary. No VPN service installed."""
import argparse
import pathlib
import platform
import plistlib
import shutil

p = argparse.ArgumentParser()
p.add_argument("--debug", action="store_true")
args = p.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
system = platform.system()
source = root / "target" / ("debug" if args.debug else "release") / ("rtrust-native.exe" if system == "Windows" else "rtrust-native")
destination = root / "dist" / ("native-preview-" + system.lower())
destination.mkdir(parents=True, exist_ok=True)
if system == "Darwin":
    app = destination / "R-TrustTunnel Preview.app" / "Contents"
    (app / "MacOS").mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, app / "MacOS" / "rtrust-native")
    with (app / "Info.plist").open("wb") as f:
        plistlib.dump(dict(CFBundleExecutable="rtrust-native", CFBundleIdentifier="org.rtrusttunnel.preview", CFBundleName="R-TrustTunnel Preview", CFBundlePackageType="APPL", CFBundleShortVersionString="0.3.2", CFBundleVersion="6", NSHighResolutionCapable=True), f)
elif system == "Linux":
    shutil.copy2(source, destination / "rtrust-native")
    (destination / "rtrust-preview.desktop").unlink(missing_ok=True)
    (destination / "org.rtrusttunnel.Native.desktop").write_text('[Desktop Entry]\nType=Application\nName=R-TrustTunnel Preview\nComment=Native profile manager and tunnel diagnostics\nExec=rtrust-native %f\nTerminal=false\nCategories=Network;\n')
elif system == "Windows":
    shutil.copy2(source, destination / "R-TrustTunnel.exe")
    shutil.copy2(source.with_name("rtrust-update.exe"), destination / "rtrust-update.exe")
else:
    raise SystemExit("Unsupported packaging host")
shutil.copy2(root / "Readme.md", destination / "Readme.md")
shutil.copy2(root / "readme_ru.md", destination / "readme_ru.md")
shutil.copy2(root / "LICENSE", destination / "LICENSE")
print(destination)
