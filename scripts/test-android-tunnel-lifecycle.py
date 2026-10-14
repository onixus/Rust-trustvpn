#!/usr/bin/env python3
"""Run Android intent lifecycle regression with an existing JDK only."""
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
        str(JAVA_ROOT / "test/java/org/rtrusttunnel/android/TunnelLifecycleTest.java")], check=True, timeout=30)
    subprocess.run([tool("java"), "-cp", output, "org.rtrusttunnel.android.TunnelLifecycleTest"], check=True, timeout=30)
