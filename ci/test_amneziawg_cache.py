"""A patched fixture toolchain must not reuse a binary built before the update."""
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import amneziawg_server as fixture

class CacheTests(unittest.TestCase):
    def test_toolchain_and_architecture_invalidate_the_binary_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'source'; source.mkdir()
            (source / 'main.go').write_text('package main\n')
            def build(args, **_):
                output = next(a.removesuffix(':/out:z') for a in args if a.endswith(':/out:z'))
                (pathlib.Path(output) / 'amneziawg-fixture.partial').write_bytes(b'fixture')
                self.assertIn('GOTOOLCHAIN=local', args)
                self.assertIn('GOFLAGS=-mod=readonly', args)
            with patch.object(fixture, 'ROOT', root), patch.object(fixture, 'SOURCE', source), patch.object(fixture.subprocess, 'run', side_effect=build) as run:
                original = fixture.binary('amd64')
                self.assertEqual(original, fixture.binary('amd64'))
                self.assertEqual(run.call_count, 1)
                with patch.object(fixture, 'IMAGE', 'patched-toolchain@sha256:new'):
                    patched = fixture.binary('amd64')
                    self.assertNotEqual(original, patched)
                    self.assertTrue(patched.is_file())
                    self.assertEqual(run.call_count, 2)
                    self.assertNotEqual(patched, fixture.binary('arm64'))
                    self.assertEqual(run.call_count, 3)

if __name__ == '__main__': unittest.main()
