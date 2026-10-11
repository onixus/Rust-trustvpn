#!/usr/bin/env python3
"""Run injected Android kernel-clock regression with an existing JDK only."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA_ROOT = ROOT / "apps/android/app/src"
JDK_BIN = Path(os.environ["JAVA_HOME"]) / "bin" if os.environ.get("JAVA_HOME") else None

def tool(name):
    return str(JDK_BIN / name) if JDK_BIN else name

with tempfile.TemporaryDirectory(prefix="rtrust-sleep-test-") as output:
    subprocess.run([tool("javac"), "-d", output,
        str(JAVA_ROOT / "main/java/org/rtrusttunnel/android/DeepSleepObserver.java"),
        str(JAVA_ROOT / "test/java/org/rtrusttunnel/android/DeepSleepObserverTest.java")], check=True, timeout=30)
    subprocess.run([tool("java"), "-cp", output, "org.rtrusttunnel.android.DeepSleepObserverTest"], check=True, timeout=30)
