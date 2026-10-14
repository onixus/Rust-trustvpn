"""Android signing wrapper tests use a stub apksigner and synthetic secrets."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/sign-android.py"
spec = importlib.util.spec_from_file_location("sign_android", SCRIPT)
sign_android = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sign_android)

# Stands in for `java -jar apksigner.jar`: records argv/env and prints a certificate.
STUB = r'''
import json, os, sys
args = sys.argv[3:]
log = os.environ["STUB_LOG"]
with open(log, "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "ks": os.environ.get("RTRUST_ANDROID_KS_PASS"),
                        "key": os.environ.get("RTRUST_ANDROID_KEY_PASS")}) + "\n")
if args[0] == "sign":
    open(args[args.index("--out") + 1], "wb").write(b"signed")
else:
    print("Verifies")
    print("Signer #1 certificate SHA-256 digest: " + os.environ["STUB_CERT"])
'''


class SignAndroid(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.dir)]))
        self.stub = self.dir / "stub.py"
        self.stub.write_text(STUB)
        self.java = self.dir / "java"
        self.java.write_text(f"#!/bin/sh\nexec {sys.executable} {self.stub} \"$@\"\n")
        self.java.chmod(0o700)
        (self.dir / "unsigned.apk").write_bytes(b"unsigned")
        self.key = self.dir / "release.jks"
        self.key.write_bytes(b"synthetic")
        self.key.chmod(0o600)
        self.props = self.dir / "keystore.properties"
        self.props.write_text("# synthetic\nstoreFile=release.jks\nstorePassword=store-secret\n"
                              "keyAlias=Release\nkeyPassword=key-secret\n")
        self.props.chmod(0o600)
        self.log = self.dir / "log"

    def run_script(self, cert):
        env = dict(os.environ, STUB_LOG=str(self.log), STUB_CERT=cert)
        return subprocess.run([sys.executable, str(SCRIPT), "--input", str(self.dir / "unsigned.apk"),
                               "--output", str(self.dir / "out/signed.apk"), "--keystore-properties", str(self.props),
                               "--apksigner-jar", "apksigner.jar", "--java", str(self.java)],
                              env=env, capture_output=True, text=True)

    def test_signs_with_properties_and_passes_passwords_only_by_env(self):
        result = self.run_script(sign_android.RELEASE_CERT_SHA256)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        sign = calls[0]["argv"]
        self.assertEqual(sign[sign.index("--ks") + 1], str(self.key))
        self.assertEqual(sign[sign.index("--ks-key-alias") + 1], "Release")
        self.assertEqual((calls[0]["ks"], calls[0]["key"]), ("store-secret", "key-secret"))
        for secret in ("store-secret", "key-secret"):
            self.assertNotIn(secret, " ".join(sign))
            self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertTrue((self.dir / "out/signed.apk.sha256").exists())

    def test_rejects_retired_or_unexpected_certificate(self):
        result = self.run_script("74b16206" + "0" * 56)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.dir / "out/signed.apk").exists())
        self.assertFalse((self.dir / "out/signed.apk.sha256").exists())

    def test_rejects_group_readable_secrets_and_missing_fields(self):
        self.key.chmod(0o640)
        self.assertNotEqual(self.run_script(sign_android.RELEASE_CERT_SHA256).returncode, 0)
        self.key.chmod(0o600)
        self.props.write_text("storeFile=release.jks\nkeyAlias=Release\n")
        result = self.run_script(sign_android.RELEASE_CERT_SHA256)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("storePassword", result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
