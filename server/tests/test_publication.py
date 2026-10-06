"""Packaging regressions: upgrading an installed overlay and preserving live images."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


patcher = module('portal_patch', ROOT / 'deploy/portal_patch.py')
builder = module('portal_build', ROOT / 'deploy/prepare-portal-update.py')


class PublicationTests(unittest.TestCase):
    def test_install_then_upgrade_registers_only_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'templates').mkdir()
            (root / 'main.py').write_text('app.include_router(client_router)\n')
            (root / 'templates/base_client.html').write_text('<span class="sp"></span>')
            patcher.integrate(root)
            first = [(root / p).read_text() for p in ('main.py', 'templates/base_client.html')]
            patcher.integrate(root)
            self.assertEqual(first, [(root / p).read_text() for p in ('main.py', 'templates/base_client.html')])
            self.assertEqual(first[0].count('rtrust_profiles.install(app)'), 1)
            self.assertEqual(first[1].count('href="/profiles"'), 1)
            (root / 'templates/base_client.html').write_text('changed upstream')
            before = (root / 'main.py').read_text()
            with self.assertRaises(RuntimeError):
                patcher.integrate(root)
            self.assertEqual((root / 'main.py').read_text(), before)

    def test_build_pins_base_and_does_not_replace_containers(self):
        calls = []
        base = 'sha256:' + 'a' * 64
        built = 'sha256:' + 'b' * 64

        def docker(*args):
            calls.append(args)
            if args[:3] == ('docker', 'image', 'inspect'):
                return base if args[-1] == 'installed:current' else built
            if args[:2] == ('docker', 'build'):
                context = Path(args[-1])
                self.assertTrue((context / 'server/overlay/app/rtrust_profiles.py').exists())
                self.assertEqual(set(p.name for p in context.iterdir()), {'server', 'deploy'})
                self.assertFalse(list(context.rglob('*.pyc')))
                self.assertIn('BASE_IMAGE=rtrust-portal-base:' + 'a' * 64, args)
            return ''

        with patch.object(builder, 'run', side_effect=docker):
            result = builder.prepare('installed:current', 'routes:new')
        self.assertEqual(result['base_image'], base)
        self.assertEqual(result['image'], built)
        self.assertFalse(result['running_containers_changed'])
        self.assertEqual([args[1] for args in calls], ['image', 'tag', 'build', 'run', 'image'])
        smoke = calls[3]
        self.assertIn('--read-only', smoke)
        self.assertEqual(smoke[smoke.index('--network') + 1], 'none')
        self.assertNotIn('--mount', smoke)
        self.assertNotIn('-v', smoke)

    def test_invalid_base_stops_before_build(self):
        with patch.object(builder, 'run', return_value='not-an-image') as run:
            with self.assertRaises(RuntimeError):
                builder.prepare('missing', 'routes:new')
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
