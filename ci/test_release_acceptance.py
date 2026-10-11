"""Negative gates use synthetic reports; they are not runtime acceptance evidence."""
import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/release-acceptance.py"
spec = importlib.util.spec_from_file_location("acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        (self.base / "package").write_bytes(b"synthetic installer")
        (self.base / "sources").write_text("{}")
        (self.base / "envelope").write_text("synthetic envelope")
        self.package = {
            "commit": "a" * 40,
            "source_manifest_sha256": acceptance.digest(self.base / "sources"),
            "artifact_sha256": acceptance.digest(self.base / "package"),
            "source_manifest": "sources", "artifact": "package",
            "update_manifest": "envelope",
            "update_manifest_sha256": acceptance.digest(self.base / "envelope"),
            "version": "test", "target": "windows-x86_64",
            "os": "synthetic", "device": "synthetic", "preview": False,
            "claims": [{"protocol": "trusttunnel", "mode": "full", "always_on": False}],
            "checks": [],
        }
        for scenario in acceptance.SCENARIOS + acceptance.SIGNING["windows-x86_64"]:
            check = {"scenario": scenario, "status": "passed"}
            if scenario in acceptance.SCENARIOS:
                check.update(self.package["claims"][0])
            else:
                check.update(protocol=None, mode=None, always_on=None)
            self.package["checks"].append(check)
            self.report(check)
        self.matrix = {"schema": 1, "packages": [self.package]}

    def report(self, check, mutate=lambda report: None):
        report = {k: self.package[k] for k in acceptance.IDENTITY}
        report["update_manifest_sha256"] = self.package["update_manifest_sha256"]
        report.update({k: check.get(k) for k in ("scenario", "protocol", "mode", "always_on", "status")})
        report["recorded_at"] = "2026-10-11T00:00:00Z"
        report["metrics"] = {"limits": {"recovery_ms": 1000}, "measured": {"recovery_ms": 900}}
        mutate(report)
        path = self.base / (check["scenario"] + ".json")
        path.write_text(json.dumps(report))
        check["evidence"] = {"path": path.name, "sha256": acceptance.digest(path)}

    def errors(self, production=True):
        return acceptance.validate(self.matrix, self.base, production)

    def test_complete_matching_fixture_and_exact_artifact_filter(self):
        self.assertEqual(self.errors(), [])
        self.assertTrue(acceptance.validate(self.matrix, self.base, True, target="macos-aarch64"))
        with self.assertRaises(ValueError):
            acceptance.validate(self.matrix, self.base, True, "0" * 64)

    def test_reusing_old_package_report_is_rejected_even_with_updated_report_hash(self):
        check = self.package["checks"][0]
        for field, value in [("artifact_sha256", "0" * 64), ("commit", "b" * 40),
                             ("device", "other device"), ("always_on", True)]:
            self.report(check, lambda r: r.update({field: value}))
            self.assertTrue(self.errors(), field)
        self.report(check)
        self.assertEqual(self.errors(), [])

    def test_missing_failed_unsupported_and_not_run_cannot_promote(self):
        original = copy.deepcopy(self.package["checks"])
        self.package["checks"].pop()
        self.assertTrue(self.errors())
        for status in ["failed", "unsupported", "not_run"]:
            self.package["checks"] = copy.deepcopy(original)
            check = self.package["checks"][0]
            check.update(status=status, owner="test owner", dependency="test device")
            self.assertTrue(self.errors())
            self.assertEqual(self.errors(False), [])

    def test_package_source_and_evidence_checksums_are_required(self):
        for filename in ["package", "sources", "envelope", "clean_install.json"]:
            path = self.base / filename
            original = path.read_bytes()
            path.write_bytes(b"changed")
            self.assertTrue(self.errors(), filename)
            path.write_bytes(original)

    def test_preview_and_over_budget_measurements_cannot_promote(self):
        self.package["preview"] = True
        self.assertTrue(self.errors())
        self.assertEqual(self.errors(False), [])
        self.package["preview"] = False
        check = next(c for c in self.package["checks"] if c["scenario"] == "recovery_budget")
        for value in [1001, -1, float("inf"), float("nan"), True]:
            self.report(check, lambda r: r["metrics"]["measured"].update(recovery_ms=value))
            self.assertTrue(self.errors(), value)

    def test_different_signed_metadata_and_version_cannot_reuse_acceptance(self):
        self.assertTrue(acceptance.validate(self.matrix, self.base, True, update_manifest_sha256="0" * 64))
        self.assertTrue(acceptance.validate(self.matrix, self.base, True, version="other"))
        check = next(c for c in self.package["checks"] if c["scenario"] == "update_metadata")
        self.report(check, lambda report: report.update(update_manifest_sha256="0" * 64))
        self.assertTrue(self.errors())

    def test_always_on_claim_requires_its_own_failure_evidence(self):
        claim = dict(self.package["claims"][0], always_on=True)
        self.package["claims"].append(claim)
        self.assertTrue(self.errors())


if __name__ == "__main__":
    unittest.main()
