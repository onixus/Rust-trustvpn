"""Synthetic local Git fixtures; no credentials or network operations."""
import json
import os
from unittest.mock import patch
import pathlib
import subprocess
import tempfile
import unittest
import unicodedata
from source_provenance import reject_path_collisions, snapshot, verify

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        self.run_git('init', '-q')
        self.run_git('config', 'user.email', 'fixture@example.invalid')
        self.run_git('config', 'user.name', 'Fixture')
        self.run_git('config', 'core.autocrlf', 'false')
        (self.repo / 'service.rs').write_bytes(b'synthetic service\n')
        (self.repo / 'tool.sh').write_bytes(b'#!/bin/sh\nexit 0\n')
        (self.repo / 'tool.sh').chmod(0o755)
        self.run_git('add', '.')
        self.run_git('update-index', '--chmod=+x', 'tool.sh')
        self.run_git('commit', '-qm', 'fixture')
        self.sha = self.run_git('rev-parse', 'HEAD').strip()
        self.dest = self.base / 'snapshot'

    def run_git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args]).decode()

    def export(self):
        return snapshot(self.repo, self.sha, self.dest)

    def test_clean_roundtrip_and_executable(self):
        modes = []
        original = pathlib.Path.chmod
        def chmod(path, mode):
            modes.append((path.name, mode))
            original(path, mode)
        with patch.object(pathlib.Path, 'chmod', autospec=True, side_effect=chmod):
            self.export()
        verify(self.repo, self.dest, self.sha)
        self.assertIn(('tool.sh', 0o755), modes)
        self.assertIn(('service.rs', 0o644), modes)
        # NTFS does not expose POSIX executable bits for shell files.
        if os.name != 'nt':
            self.assertTrue((self.dest / 'tool.sh').stat().st_mode & 0o111)

    def test_autocrlf_does_not_rewrite_snapshot_bytes(self):
        self.run_git('config', 'core.autocrlf', 'true')
        self.export()
        self.assertEqual((self.dest / 'service.rs').read_bytes(), b'synthetic service\n')
        self.assertEqual((self.dest / 'tool.sh').read_bytes(), b'#!/bin/sh\nexit 0\n')

    def test_dirty_source_exports_commit_and_stays_immutable(self):
        (self.repo / 'service.rs').write_text('dirty service\n')
        (self.repo / 'private-untracked').write_text('synthetic excluded\n')
        self.export()
        self.assertEqual((self.dest / 'service.rs').read_text(), 'synthetic service\n')
        self.assertFalse((self.dest / 'private-untracked').exists())
        (self.repo / 'service.rs').write_text('later edit\n')
        self.assertEqual((self.dest / 'service.rs').read_text(), 'synthetic service\n')
        with self.assertRaises(ValueError):
            verify(self.repo, self.dest, self.sha)

    def test_wrong_and_short_sha(self):
        for sha in [self.sha[:8], '0' * 40]:
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                snapshot(self.repo, sha, self.dest)
        self.assertFalse(self.dest.exists())

    def test_manifest_missing_extra_and_tampered(self):
        self.export()
        path = self.dest / 'source-manifest.json'
        original = json.loads(path.read_text())
        for variant in [{}, {**original, 'extra.rs': '0' * 64}, {**original, 'service.rs': '0' * 64}]:
            path.write_text(json.dumps(variant))
            # Even if receipt hash is replaced, compare the whole manifest to Git.
            import hashlib
            identity = json.loads((self.dest / 'source-identity.json').read_text())
            identity['source_manifest_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            (self.dest / 'source-identity.json').write_text(json.dumps(identity))
            with self.assertRaises(ValueError):
                verify(self.repo, self.dest, self.sha)

    def test_service_only_change_and_other_head_rejected(self):
        self.export()
        (self.repo / 'service.rs').write_text('changed service\n')
        with self.assertRaises(ValueError):
            verify(self.repo, self.dest, self.sha)
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'changed')
        with self.assertRaises(ValueError):
            verify(self.repo, self.dest, self.sha)
        with self.assertRaises(ValueError):
            verify(self.repo, self.dest, self.run_git('rev-parse', 'HEAD').strip())

    def test_nonempty_destination_rejected(self):
        self.dest.mkdir()
        (self.dest / 'stale').write_text('fixture')
        with self.assertRaises(ValueError):
            self.export()

    def test_symlink_commit_rejected(self):
        (self.repo / 'link').symlink_to('service.rs')
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'link')
        with self.assertRaises(ValueError):
            snapshot(self.repo, self.run_git('rev-parse', 'HEAD').strip(), self.dest)


    def commit_tree(self, files):
        """Commit synthetic paths via the index so case-insensitive hosts can hold them."""
        for name, data in files.items():
            blob = subprocess.run(['git', '-C', str(self.repo), 'hash-object', '-w', '--stdin'],
                                  input=data, capture_output=True, check=True).stdout.decode().strip()
            self.run_git('update-index', '--add', '--cacheinfo', '100644,%s,%s' % (blob, name))
        self.run_git('commit', '-qm', 'colliding fixture')
        return self.run_git('rev-parse', 'HEAD').strip()

    def test_path_collisions_rejected_before_any_write(self):
        nfc = unicodedata.normalize('NFC', 'caf\u00e9.rs')
        nfd = unicodedata.normalize('NFD', nfc)
        variants = [
            {'A.rs': b'upper\n', 'a.rs': b'lower\n'},
            {nfc: b'composed\n', nfd: b'decomposed\n'},
            {'Dir/x.rs': b'dir\n', 'dir': b'file\n'},
            {'Dir/x.rs': b'one\n', 'dir/y.rs': b'two\n'},
            {'Source-Manifest.json': b'{}\n'},
        ]
        # Keep NFD argv spelling on macOS so the fixture commit holds both forms.
        self.run_git('config', 'core.precomposeunicode', 'false')
        for files in variants:
            with self.subTest(files=sorted(files)):
                self.run_git('reset', '-q', '--hard', self.sha)
                sha = self.commit_tree(files)
                committed = self.run_git('ls-tree', '-r', '--name-only', '-z', sha).split('\0')
                self.assertTrue(set(files) <= set(committed))
                with self.assertRaises(ValueError):
                    snapshot(self.repo, sha, self.dest)
                self.assertFalse(self.dest.exists())
                with self.assertRaises(ValueError):
                    verify(self.repo, self.dest, sha)

    def test_collision_keys_are_filesystem_independent(self):
        reject_path_collisions(['a/b.rs', 'a/c.rs', 'b.rs'])
        for names in [['A.rs', 'a.rs'], ['x/\u00c5.rs', 'x/A\u030a.rs'], ['Dir/x', 'dir']]:
            with self.assertRaises(ValueError):
                reject_path_collisions(names)

    def test_snapshot_read_back_mismatch_fails_closed(self):
        original = pathlib.Path.write_bytes
        def corrupt(path, data):
            return original(path, b'altered\n' if path.name == 'service.rs' else data)
        with patch.object(pathlib.Path, 'write_bytes', autospec=True, side_effect=corrupt):
            with self.assertRaises(ValueError):
                self.export()
        self.assertFalse((self.dest / 'source-identity.json').exists())
        self.assertFalse((self.dest / 'source-manifest.json').exists())

    def test_untracked_and_cargo_override_rejected(self):
        self.export()
        (self.repo / 'target' / 'debug').mkdir(parents=True)
        (self.repo / 'target' / 'debug' / 'out').write_bytes(b'synthetic build output\n')
        (self.repo / '.git' / 'info' / 'exclude').write_text('/target/\n/.cargo/\n/ignored-ok\n')
        (self.repo / 'ignored-ok').write_text('synthetic ignored\n')
        verify(self.repo, self.dest, self.sha)
        (self.repo / 'untracked.rs').write_text('synthetic untracked\n')
        with self.assertRaisesRegex(ValueError, 'tracked changes|untracked'):
            verify(self.repo, self.dest, self.sha)
        (self.repo / 'untracked.rs').unlink()
        (self.repo / '.cargo').mkdir()
        (self.repo / '.cargo' / 'config.toml').write_text('[build]\n')
        with self.assertRaisesRegex(ValueError, 'build override'):
            verify(self.repo, self.dest, self.sha)
        (self.repo / '.cargo' / 'config.toml').unlink()
        (self.repo / '.cargo').rmdir()
        verify(self.repo, self.dest, self.sha)
        for name in ['rust-toolchain.toml', 'Rust-Toolchain']:
            (self.repo / name).write_text('[toolchain]\n')
            (self.repo / '.git' / 'info' / 'exclude').write_text(f'/target/\n/ignored-ok\n/{name}\n')
            with self.assertRaisesRegex(ValueError, 'build override'):
                verify(self.repo, self.dest, self.sha)
            (self.repo / name).unlink()
        (self.repo / 'nested' / '.cargo').mkdir(parents=True)
        (self.repo / 'nested' / '.cargo' / 'config').write_text('[build]\n')
        (self.repo / '.git' / 'info' / 'exclude').write_text('/target/\n/ignored-ok\n/nested/\n')
        verify(self.repo, self.dest, self.sha)

    def test_jenkinsfiles_validate_parameters_before_git(self):
        for name in ['Jenkinsfile', 'Jenkinsfile.android', 'Jenkinsfile.linux']:
            with self.subTest(name=name):
                text = (ROOT / name).read_text()
                sha_check = text.index('case "$SOURCE_SHA" in')
                length_check = text.index('test "${#SOURCE_SHA}" -eq 40')
                path_check = text.index('case "$SOURCE_PATH" in')
                first_git = min(i for i in [text.find('git '), text.find('git\t')] if i >= 0)
                self.assertLess(max(sha_check, length_check, path_check), first_git)
                self.assertIn('*[!0123456789abcdef]*', text)
                self.assertNotIn('show "$SOURCE_SHA', text)
                self.assertIn('cat-file blob "$SOURCE_SHA:ci/snapshot.py"', text)


if __name__ == '__main__':
    unittest.main()
