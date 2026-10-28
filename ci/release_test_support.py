"""Synthetic release evidence for local tests, never runtime acceptance evidence."""
import importlib.util
import json
import pathlib
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/release-acceptance.py"
spec = importlib.util.spec_from_file_location("acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def create_release_fixture(add_cleanup):
    """Register cleanup before populating files, including on setup failure."""
    temp = tempfile.TemporaryDirectory()
    add_cleanup(temp.cleanup)
    return SyntheticReleaseFixture(pathlib.Path(temp.name))


class SyntheticReleaseFixture:
    def __init__(self, base):
        self.base = base
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

