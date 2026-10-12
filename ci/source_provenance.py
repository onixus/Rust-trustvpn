"""Commit-bound source export and verification; never reads untracked files."""
import hashlib
import io
import json
import pathlib
import re
import subprocess
import tarfile


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args])


def commit_files(source, sha):
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('A full lowercase commit SHA is required')
    resolved = git(source, 'rev-parse', '--verify', sha + '^{commit}').decode().strip()
    if resolved != sha:
        raise ValueError('Commit identity mismatch')
    entries = git(source, 'ls-tree', '-r', '-z', sha).split(b'\0')
    if any(e and not e.startswith((b'100644 ', b'100755 ')) for e in entries):
        raise ValueError('Source tree contains unsupported symlinks or submodules')
    tree = git(source, 'rev-parse', sha + '^{tree}').decode().strip()
    with tarfile.open(fileobj=io.BytesIO(git(source, 'archive', '--format=tar', sha))) as archive:
        files = {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
    names = {e.split(b'\t', 1)[1].decode() for e in entries if e}
    if set(files) != names:
        raise ValueError('Git archive attributes omit or alter source tree entries')
    # Read raw blobs in one bounded Git process; archive attributes cannot rewrite bytes.
    blobs = [e.split(b'\t', 1) for e in entries if e]
    raw = subprocess.check_output(['git', '-C', str(source), 'cat-file', '--batch'],
                                  input=b''.join(info.split()[2] + b'\n' for info, _ in blobs))
    offset = 0
    for info, name in blobs:
        end = raw.index(b'\n', offset)
        size = int(raw[offset:end].split()[2])
        data = raw[end + 1:end + 1 + size]
        offset = end + size + 2
        if files[name.decode()] != data:
            raise ValueError('Git archive bytes differ from committed blob')
    return tree, files


def hashes(files):
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}


def snapshot(source, sha, destination):
    source, destination = pathlib.Path(source).resolve(), pathlib.Path(destination).resolve()
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError('Snapshot destination must be separate from source')
    if destination.exists() and any(destination.iterdir()):
        raise ValueError('Snapshot destination must be empty')
    tree, files = commit_files(source, sha)
    if {'source-manifest.json', 'source-identity.json'} & files.keys():
        raise ValueError('Reserved provenance filenames in source tree')
    destination.mkdir(parents=True, exist_ok=True)
    modes = {e.split(b'\t', 1)[1].decode(): e.split()[0] for e in git(source, 'ls-tree', '-r', '-z', sha).split(b'\0') if e}
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if modes[name] == b'100755' else 0o644)
    manifest = destination / 'source-manifest.json'
    manifest.write_text(json.dumps(hashes(files), indent=2) + '\n')
    identity = {'schema': 1, 'commit': sha, 'tree': tree,
                'source_manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}
    (destination / 'source-identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    return identity


def verify(source, archive, sha):
    """Verify archived identity and every source hash, plus signing checkout bytes."""
    source, archive = pathlib.Path(source), pathlib.Path(archive)
    identity = json.loads((archive / 'source-identity.json').read_text())
    manifest_bytes = (archive / 'source-manifest.json').read_bytes()
    tree, files = commit_files(source, sha)
    expected = {'schema': 1, 'commit': sha, 'tree': tree,
                'source_manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest()}
    if identity != expected or json.loads(manifest_bytes) != hashes(files):
        raise ValueError('Archived source provenance differs from expected commit')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != sha:
        raise ValueError('Signing checkout HEAD differs from expected commit')
    if git(source, 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('Signing checkout has tracked changes')
    for name, data in files.items():
        path = source / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise ValueError('Signing checkout source differs from expected commit')
    return identity
