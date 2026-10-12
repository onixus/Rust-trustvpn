"""Synthetic local Git fixtures; no credentials or network operations."""
import json
import pathlib
import subprocess
import tempfile
import unittest
from source_provenance import snapshot, verify


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
        self.run_git('commit', '-qm', 'fixture')
        self.sha = self.run_git('rev-parse', 'HEAD').strip()
        self.dest = self.base / 'snapshot'

    def run_git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args]).decode()

    def export(self):
        return snapshot(self.repo, self.sha, self.dest)

    def test_clean_roundtrip_and_executable(self):
        self.export()
        verify(self.repo, self.dest, self.sha)
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


if __name__ == '__main__':
    unittest.main()
