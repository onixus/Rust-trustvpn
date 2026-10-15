#!/usr/bin/env python3
"""Run Android intent lifecycle, link-change and recovery-status regressions with an existing JDK only."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA_ROOT = ROOT / "apps/android/app/src"
JDK_BIN = Path(os.environ["JAVA_HOME"]) / "bin" if os.environ.get("JAVA_HOME") else None

def tool(name):
    return str(JDK_BIN / name) if JDK_BIN else name

with tempfile.TemporaryDirectory(prefix="rtrust-lifecycle-test-") as output:
    subprocess.run([tool("javac"), "-d", output,
        str(JAVA_ROOT / "main/java/org/rtrusttunnel/android/TunnelLifecycle.java"),
        str(JAVA_ROOT / "test/java/org/rtrusttunnel/android/TunnelLifecycleTest.java"),
        str(JAVA_ROOT / "main/java/org/rtrusttunnel/android/LinkChange.java"),
        str(JAVA_ROOT / "test/java/org/rtrusttunnel/android/LinkChangeTest.java"),
        str(JAVA_ROOT / "main/java/org/rtrusttunnel/android/RecoveryStatus.java"),
        str(JAVA_ROOT / "test/java/org/rtrusttunnel/android/RecoveryStatusTest.java")], check=True, timeout=30)
    for test in ("TunnelLifecycleTest", "LinkChangeTest", "RecoveryStatusTest"):
        subprocess.run([tool("java"), "-cp", output, "org.rtrusttunnel.android." + test], check=True, timeout=30)
