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
            (root / 'main.py').write_text('app.include_router(client_router)\n', encoding='utf-8')
            (root / 'templates/base_client.html').write_text('<span class="sp"></span>', encoding='utf-8')
            patcher.integrate(root)
            first = [(root / p).read_text(encoding='utf-8') for p in ('main.py', 'templates/base_client.html')]
            patcher.integrate(root)
            self.assertEqual(first, [(root / p).read_text(encoding='utf-8') for p in ('main.py', 'templates/base_client.html')])
            self.assertEqual(first[0].count('rtrust_profiles.install(app)'), 1)
            self.assertEqual(first[1].count('href="/profiles"'), 1)
            (root / 'templates/base_client.html').write_text('changed upstream', encoding='utf-8')
            before = (root / 'main.py').read_text(encoding='utf-8')
            with self.assertRaises(RuntimeError):
                patcher.integrate(root)
            self.assertEqual((root / 'main.py').read_text(encoding='utf-8'), before)

    def test_utf8_templates_do_not_depend_on_windows_locale(self):
        original_open = Path.open

        def cp1252_default(path, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
            return original_open(path, mode, buffering, encoding or 'cp1252', errors, newline)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'templates').mkdir()
            (root / 'main.py').write_text('# Портал\napp.include_router(client_router)\n', encoding='utf-8')
            template = root / 'templates/base_client.html'
            template.write_text('<title>Кабинет</title><span class="sp"></span>', encoding='utf-8')
            with patch.object(Path, 'open', cp1252_default):
                patcher.integrate(root)
                patcher.integrate(root)
            self.assertIn('Кабинет', template.read_text(encoding='utf-8'))
            self.assertEqual(template.read_text(encoding='utf-8').count('Обмен профилями'), 1)

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
                self.assertNotIn('-t', args)
                Path(args[args.index('--iidfile') + 1]).write_text(built, encoding='utf-8')
            return ''

        with patch.object(builder, 'run', side_effect=docker):
            result = builder.prepare('installed:current', 'routes:new')
        self.assertEqual(result['base_image'], base)
        self.assertEqual(result['image'], built)
        self.assertFalse(result['running_containers_changed'])
        self.assertEqual([args[1] for args in calls], ['image', 'image', 'tag', 'build', 'run', 'image', 'tag'])
        smoke = calls[4]
        self.assertEqual(calls[-1], ('docker', 'tag', built, 'routes:new'))
        self.assertIn(built, smoke)
        self.assertIn('--read-only', smoke)
        self.assertEqual(smoke[smoke.index('--network') + 1], 'none')
        self.assertNotIn('--mount', smoke)
        self.assertNotIn('-v', smoke)

    def test_existing_tag_rejected_even_when_base_is_an_id(self):
        base = 'sha256:' + 'a' * 64
        with patch.object(builder, 'run', side_effect=[base, 'existing-image']) as run:
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                builder.prepare(base, 'portal:live')
            self.assertEqual(run.call_count, 2)

    def test_failed_check_or_concurrent_tag_never_publishes(self):
        base = 'sha256:' + 'a' * 64
        candidate = 'sha256:' + 'b' * 64
        for fail_smoke in (True, False):
            calls = []
            checks = 0

            def docker(*args):
                nonlocal checks
                calls.append(args)
                if args[:3] == ('docker', 'image', 'inspect'):
                    return base
                if args[:3] == ('docker', 'image', 'ls'):
                    checks += 1
                    return 'another-image' if checks > 1 else ''
                if args[:2] == ('docker', 'build'):
                    Path(args[args.index('--iidfile') + 1]).write_text(candidate, encoding='utf-8')
                if args[:2] == ('docker', 'run') and fail_smoke:
                    raise RuntimeError('Smoke failed')
                return ''

            with patch.object(builder, 'run', side_effect=docker):
                with self.assertRaises(RuntimeError):
                    builder.prepare(base, 'routes:new')
            self.assertNotIn(('docker', 'tag', candidate, 'routes:new'), calls)

    def test_invalid_base_stops_before_build(self):
        with patch.object(builder, 'run', return_value='not-an-image') as run:
            with self.assertRaises(RuntimeError):
                builder.prepare('missing', 'routes:new')
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
