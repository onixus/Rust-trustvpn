"""Verify pinned-root signed releases locally before publishing immutable files."""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def verify_release(repo, root, target, sequence):
    artifact = root / ("setup.exe" if target == "windows-x86_64" else "client.dmg")
    result = subprocess.run(
        ["cargo", "run", "--offline", "--locked", "--quiet", "--manifest-path",
         str(repo / "Cargo.toml"), "-p", "rtrust-update", "--example", "verify_release", "--",
         str(root / "manifest.json"), str(artifact), target, str(sequence)],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)["version"]


def publish(repo, sequence, target, promote=False, acceptance=None):
    if sequence <= 0:
        raise ValueError("Sequence must be positive")
    if promote and acceptance is None:
        raise ValueError("--promote requires --acceptance with exact-package production evidence")
    source = repo / "dist/signed-releases" / str(sequence) / target
    files = ["manifest.json", "setup.exe" if target == "windows-x86_64" else "client.dmg"]
    # Upload a private snapshot of the same bytes verified here. Concurrent changes
    # to the preparation directory must not replace a checked envelope or package.
    with tempfile.TemporaryDirectory(prefix="rtrust-publish-") as folder:
        root = pathlib.Path(folder)
        for name in files:
            shutil.copyfile(source / name, root / name)
        version = verify_release(repo, root, target, sequence)
        hashes = {name: digest(root / name) for name in files}
        if promote:
            subprocess.run(
                [sys.executable, str(repo / "scripts/release-acceptance.py"), str(acceptance),
                 "--production", "--target", target, "--artifact-sha256", hashes[files[1]],
                 "--update-manifest-sha256", hashes[files[0]], "--version", version], check=True,
            )
        # All local verification finishes before the first remote operation.
        host = "onixus-rf.duckdns.org"
        remote = f"/opt/rtrust-updates/{sequence}/{target}"
        subprocess.run(["ssh", "-o", "BatchMode=yes", host, f"install -d -m 755 {remote}"], check=True)
        for name in files:
            checksum = hashes[name]
            dest = f"{remote}/{name}"
            exists = subprocess.run(["ssh", "-o", "BatchMode=yes", host, f"test -f {dest}"], check=False).returncode == 0
            if exists:
                actual = subprocess.check_output(["ssh", "-o", "BatchMode=yes", host, f"sha256sum {dest}"], text=True).split()[0]
                if actual != checksum:
                    raise ValueError("Published release sequence is immutable")
            else:
                subprocess.run(["scp", str(root / name), f"{host}:{dest}.part"], check=True)
                subprocess.run(["ssh", "-o", "BatchMode=yes", host,
                    f'test "$(sha256sum {dest}.part | cut -d " " -f 1)" = {checksum} && chmod 644 {dest}.part && mv -n {dest}.part {dest} && test "$(sha256sum {dest} | cut -d " " -f 1)" = {checksum}'], check=True)
            print("Verified public versioned artifact", name, checksum)
        if promote:
            # Recheck the immutable remote pair immediately before changing latest.
            checks = " && ".join(f'test "$(sha256sum {remote}/{name} | cut -d " " -f 1)" = {hashes[name]}' for name in files)
            subprocess.run(["ssh", "-o", "BatchMode=yes", host,
                f"{checks} && install -d -m 755 /opt/rtrust-updates/{target} && cp {remote}/manifest.json /opt/rtrust-updates/{target}/latest.json.part && mv /opt/rtrust-updates/{target}/latest.json.part /opt/rtrust-updates/{target}/latest.json"], check=True)
            print("Promoted verified release", sequence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--target", choices=["windows-x86_64", "macos-aarch64"], required=True)
    parser.add_argument("--promote", action="store_true")
    parser.add_argument("--acceptance", type=pathlib.Path)
    args = parser.parse_args()
    try:
        publish(pathlib.Path(__file__).resolve().parents[1], args.sequence, args.target, args.promote, args.acceptance)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Publication rejected: {error}\n")


if __name__ == "__main__":
    main()
