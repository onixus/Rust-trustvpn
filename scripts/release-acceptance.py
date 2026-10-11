"""Validate exact-package acceptance evidence; never installs or publishes anything.

Reports are human/runtime evidence, not generated passes. This gate checks their
identity and coverage and cannot establish that the recorded observations are true.
"""
import argparse
import datetime
import hashlib
import json
import math
import pathlib
import re
import sys

SCENARIOS = (
    "clean_install", "service_permissions", "uninstall", "update", "rollback",
    "vault_preserved", "cold_boot", "sleep_wake", "network_handoff",
    "gui_crash", "service_crash", "endpoint_outage", "dns_https_egress",
    "no_direct_dns_ipv4_ipv6", "owned_state_restored", "recovery_budget", "soak",
)
SIGNING = {
    "macos-aarch64": ("developer_id", "notarization", "update_metadata"),
    "windows-x86_64": ("authenticode", "update_metadata"),
    "linux-x86_64": ("repository_signature", "update_metadata"),
    "android": ("apk_signature",),
    "ios": ("apple_distribution",),
}
STATUSES = {"passed", "failed", "not_run", "unsupported"}
IDENTITY = ("commit", "source_manifest_sha256", "artifact_sha256", "version", "target", "os", "device")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def validate(matrix, base, production=False, artifact_sha256=None, target=None):
    if not isinstance(matrix, dict):
        raise ValueError("Matrix must be an object")
    if matrix.get("schema") != 1 or not isinstance(matrix.get("packages"), list):
        raise ValueError("Expected acceptance matrix schema 1")
    packages = matrix["packages"]
    if not all(isinstance(p, dict) for p in packages):
        raise ValueError("Package records must be objects")
    if artifact_sha256 is not None:
        packages = [p for p in packages if p.get("artifact_sha256") == artifact_sha256]
    if not packages:
        raise ValueError("No acceptance records for the requested artifact")
    failures = []
    seen = set()
    for package in packages:
        label = package.get("target", "unknown") + "/" + package.get("version", "unknown")
        def reject(message):
            failures.append(f"{label}: {message}")
        if not all(isinstance(package.get(k), str) and package[k].strip() for k in IDENTITY):
            reject("incomplete package identity")
            continue
        identity = tuple(package[k] for k in IDENTITY)
        if identity in seen:
            reject("duplicate package/device record")
        seen.add(identity)
        if target is not None and package["target"] != target:
            reject("acceptance target differs from requested publication")
        if not re.fullmatch(r"[0-9a-f]{40}", package["commit"]):
            reject("commit must be a full Git SHA")
        if not all(re.fullmatch(r"[0-9a-f]{64}", package[k]) for k in ("artifact_sha256", "source_manifest_sha256")):
            reject("invalid SHA256")
        for path_key, hash_key in (("artifact", "artifact_sha256"), ("source_manifest", "source_manifest_sha256")):
            path = package.get(path_key)
            if not isinstance(path, str) or not path:
                reject(f"missing {path_key}")
                continue
            try:
                if digest(base / path) != package[hash_key]:
                    reject(f"{path_key} checksum mismatch")
            except OSError:
                reject(f"{path_key} file unavailable")
        if type(package.get("preview")) is not bool:
            reject("preview must be explicitly declared")
        elif production and package["preview"]:
            reject("preview package cannot pass production acceptance")
        signing = SIGNING.get(package["target"])
        if signing is None:
            reject("unsupported target")
            continue
        claims = package.get("claims")
        if not isinstance(claims, list) or not claims:
            reject("no protocol/mode/Always-on claims")
            continue
        required = set()
        for claim in claims:
            if not isinstance(claim, dict):
                reject("capability claim must be an object")
                continue
            if (set(claim) != {"protocol", "mode", "always_on"}
                    or claim["protocol"] not in {"trusttunnel", "http3", "hysteria2", "amneziawg"}
                    or claim["mode"] not in {"split", "full", "proxy"}
                    or type(claim["always_on"]) is not bool):
                reject("invalid capability claim")
                continue
            for scenario in SCENARIOS:
                required.add((scenario, claim["protocol"], claim["mode"], claim["always_on"]))
        required.update((name, None, None, None) for name in signing)
        checked = set()
        checks = package.get("checks", [])
        if not isinstance(checks, list):
            reject("checks must be a list")
            continue
        for check in checks:
            if not isinstance(check, dict):
                reject("check must be an object")
                continue
            key = tuple(check.get(k) for k in ("scenario", "protocol", "mode", "always_on"))
            if any(type(v) not in (str, bool, type(None)) for v in key):
                reject("invalid scenario identity")
                continue
            if key not in required or key in checked:
                reject("unexpected or duplicate scenario")
                continue
            checked.add(key)
            status = check.get("status")
            if status not in STATUSES:
                reject(f"{key[0]}: invalid status")
                continue
            if status != "passed":
                if not all(isinstance(check.get(k), str) and check[k].strip() for k in ("owner", "dependency")):
                    reject(f"{key[0]}: missing owner/dependency")
                if production:
                    reject(f"{key[0]}: {status}")
                continue
            evidence = check.get("evidence", {})
            try:
                path = base / evidence["path"]
                if digest(path) != evidence["sha256"]:
                    reject(f"{key[0]}: evidence checksum mismatch")
                    continue
                report = json.loads(path.read_text())
                if not isinstance(report, dict):
                    reject(f"{key[0]}: report must be an object")
                    continue
                expected = {k: package[k] for k in IDENTITY}
                expected.update(zip(("scenario", "protocol", "mode", "always_on"), key))
                expected["status"] = "passed"
                if any(report.get(k) != v or type(report.get(k)) is not type(v) for k, v in expected.items()):
                    reject(f"{key[0]}: evidence belongs to a different package/scenario")
                recorded = datetime.datetime.fromisoformat(report.get("recorded_at", ""))
                if recorded.tzinfo is None:
                    reject(f"{key[0]}: evidence timestamp has no timezone")
                if key[0] in {"recovery_budget", "soak"}:
                    metrics = report.get("metrics", {})
                    if not isinstance(metrics, dict):
                        reject(f"{key[0]}: metrics must be an object")
                        continue
                    for field in ("limits", "measured"):
                        values = metrics.get(field, {})
                        if not isinstance(values, dict) or not values:
                            reject(f"{key[0]}: missing {field} metrics")
                    limits, measured = metrics.get("limits", {}), metrics.get("measured", {})
                    if isinstance(limits, dict) and isinstance(measured, dict):
                        for name, limit in limits.items():
                            value = measured.get(name)
                            if (type(limit) not in (int, float) or type(value) not in (int, float)
                                    or not math.isfinite(limit) or not math.isfinite(value)
                                    or limit < 0 or value < 0 or not value <= limit):
                                reject(f"{key[0]}: measurement exceeds or lacks criterion {name}")
            except (OSError, ValueError, KeyError, TypeError):
                reject(f"{key[0]}: evidence unavailable or invalid")
        for key in sorted(required - checked, key=str):
            reject(f"missing {key}")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=pathlib.Path)
    parser.add_argument("--production", action="store_true", help="require passed evidence for every claim")
    parser.add_argument("--target", choices=SIGNING, help="require the publication target")
    parser.add_argument("--artifact-sha256", help="validate one exact artifact in the matrix")
    args = parser.parse_args()
    try:
        failures = validate(json.loads(args.matrix.read_text()), args.matrix.resolve().parent,
                            args.production, args.artifact_sha256, args.target)
    except (OSError, ValueError, TypeError) as error:
        print(f"Acceptance rejected: {error}", file=sys.stderr)
        return 1
    if failures:
        print("Acceptance rejected:\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print("Production acceptance recorded" if args.production else "Matrix valid; statuses remain as recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
