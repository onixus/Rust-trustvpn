"""Publisher orchestration tests use synthetic fixtures and never contact a server."""
import importlib.util
import json
import pathlib
import shutil
import subprocess
import unittest
from unittest.mock import patch
import test_release_acceptance as fixtures
acceptance = fixtures.acceptance

spec = importlib.util.spec_from_file_location("publisher", pathlib.Path(__file__).resolve().parents[1] / "scripts/publish-signed-release.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublisherGate(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AcceptanceGate()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.repo = self.fixture.base
        self.root = self.repo / "dist/signed-releases/42/windows-x86_64"
        self.root.mkdir(parents=True)
        shutil.copyfile(self.repo / "package", self.root / "setup.exe")
        shutil.copyfile(self.repo / "envelope", self.root / "manifest.json")
        self.matrix = self.repo / "matrix.json"
        self.matrix.write_text(json.dumps(self.fixture.matrix))
        self.calls = []

    def run_command(self, command, **kwargs):
        self.calls.append(command)
        if command[0] == "cargo":
            return subprocess.CompletedProcess(command, 0, stdout='{"version":"test"}')
        if command[0] not in {"ssh", "scp"}:
            args = command
            failures = acceptance.validate(json.loads(self.matrix.read_text()), self.repo, True,
                args[args.index("--artifact-sha256") + 1], args[args.index("--target") + 1],
                args[args.index("--update-manifest-sha256") + 1], args[args.index("--version") + 1])
            if failures:
                raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, int(command[0] == "ssh" and command[-1].startswith("test -f")))

    def publish(self):
        with patch.object(publisher.subprocess, "run", side_effect=self.run_command):
            publisher.publish(self.repo, 42, "windows-x86_64", True, self.matrix)

    def assert_no_remote(self):
        self.assertFalse(any(c[0] in {"ssh", "scp"} for c in self.calls))

    def test_failed_signature_verification_stops_before_acceptance_or_remote(self):
        def reject(command, **kwargs):
            self.calls.append(command)
            raise subprocess.CalledProcessError(1, command)
        with patch.object(publisher.subprocess, "run", side_effect=reject):
            with self.assertRaises(subprocess.CalledProcessError):
                publisher.publish(self.repo, 42, "windows-x86_64", True, self.matrix)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], "cargo")
        self.assert_no_remote()

    def test_missing_acceptance_cannot_even_stage_or_contact_server(self):
        with patch.object(publisher.subprocess, "run", side_effect=self.run_command):
            with self.assertRaises(ValueError):
                publisher.publish(self.repo, 42, "windows-x86_64", True)
        self.assertEqual(self.calls, [])

    def test_changed_envelope_cannot_reuse_acceptance(self):
        (self.root / "manifest.json").write_text("different envelope")
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()
        self.assert_no_remote()

    def test_different_signed_version_rejected_before_remote(self):
        self.fixture.package["version"] = "different"
        self.matrix.write_text(json.dumps(self.fixture.matrix))
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()
        self.assert_no_remote()

    def test_verification_gate_precede_upload_and_original_changes_do_not_replace_snapshot(self):
        original = self.run_command
        uploaded = {}
        def mutate(command, **kwargs):
            if command[0] == "ssh":
                (self.root / "manifest.json").write_bytes(b"changed after verification")
                (self.root / "setup.exe").write_bytes(b"changed after verification")
            if command[0] == "scp":
                uploaded[pathlib.Path(command[1]).name] = pathlib.Path(command[1]).read_bytes()
            return original(command, **kwargs)
        with patch.object(publisher.subprocess, "run", side_effect=mutate):
            publisher.publish(self.repo, 42, "windows-x86_64", True, self.matrix)
        self.assertEqual(self.calls[0][0], "cargo")
        self.assertIn("--update-manifest-sha256", self.calls[1])
        self.assertEqual(uploaded["manifest.json"], b"synthetic envelope")
        self.assertEqual(uploaded["setup.exe"], b"synthetic installer")
        self.assertIn("latest.json", self.calls[-1][-1])


class LockedReleaseTools(unittest.TestCase):
    def test_release_scripts_run_cargo_with_the_committed_lockfile(self):
        import ast
        scripts = pathlib.Path(__file__).resolve().parents[1] / "scripts"
        for name in ("prepare-signed-release.py", "publish-signed-release.py"):
            commands = [
                [e.value for e in node.elts if isinstance(e, ast.Constant)]
                for node in ast.walk(ast.parse((scripts / name).read_text()))
                if isinstance(node, ast.List) and node.elts
                and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "cargo"
            ]
            self.assertTrue(commands, name)
            for command in commands:
                self.assertIn("--locked", command, name)
                self.assertIn("--offline", command, name)


class PackagingVersions(unittest.TestCase):
    """Packaged version metadata must follow the workspace, never a stale literal."""

    def setUp(self):
        import re
        self.re = re
        self.root = pathlib.Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location("package_preview", self.root / "scripts/package-preview.py")
        self.preview = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.preview)
        self.version = self.preview.workspace_version(self.root)
        self.sequence = self.preview.update_sequence(self.root)

    def test_macos_preview_bundle_uses_workspace_version_and_update_sequence(self):
        info = self.preview.preview_info(self.root)
        self.assertEqual(info["CFBundleShortVersionString"], self.version)
        self.assertEqual(info["CFBundleVersion"], self.sequence)

    def test_packaging_scripts_do_not_hardcode_bundle_versions(self):
        literal = self.re.compile(r"""CFBundle(ShortVersionString|Version)\s*=\s*['"]""")
        for path in sorted((self.root / "scripts").glob("*.py")) + sorted((self.root / "ci").glob("*.py")):
            if path.name.startswith("test"):
                continue
            self.assertIsNone(literal.search(path.read_text()), path.name)

    def test_platform_manifests_match_workspace_version(self):
        import plistlib
        codes = set()
        for target in ("App", "PacketTunnel", "Widget"):
            with (self.root / "apps/ios" / target / "Info.plist").open("rb") as f:
                info = plistlib.load(f)
            self.assertEqual(info["CFBundleShortVersionString"], self.version, target)
            codes.add(info["CFBundleVersion"])
        gradle = (self.root / "apps/android/app/build.gradle").read_text()
        self.assertIn(f"versionName '{self.version}-", gradle)
        android_code = self.re.search(r"rtrustVersionCode'\) \?: '(\d+)'", gradle).group(1)
        self.assertEqual(codes, {android_code})
        self.assertIn(f'#define AppVersion "{self.version}"', (self.root / "deploy/windows/setup.iss").read_text())
        self.assertEqual(json.loads((self.root / "apps/webview/tauri.conf.json").read_text())["version"], self.version)


if __name__ == "__main__":
    unittest.main()
