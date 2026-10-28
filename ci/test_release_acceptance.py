"""Negative gates use synthetic reports; they are not runtime acceptance evidence."""
import copy
import unittest

if __package__:
    from .release_test_support import acceptance, create_release_fixture
else:
    from release_test_support import acceptance, create_release_fixture


class AcceptanceGate(unittest.TestCase):
    def setUp(self):
        self.fixture = create_release_fixture(self.addCleanup)
        self.base = self.fixture.base
        self.package = self.fixture.package
        self.matrix = self.fixture.matrix

    def report(self, check, mutate=lambda report: None):
        self.fixture.report(check, mutate)

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
