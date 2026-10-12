#!/usr/bin/env python3
"""Offline JVM sync sequence tests: real org.json, injected transport/parser, no vault/JNI."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA_ROOT = ROOT / 'apps/android/app/src'
JDK_BIN = Path(os.environ['JAVA_HOME']) / 'bin' if os.environ.get('JAVA_HOME') else None
JSON_JAR = Path(os.environ.get('RTRUST_JSON_JAR', '/usr/share/java/com.android.json.jar'))
if not JSON_JAR.is_file():
    raise SystemExit('Set RTRUST_JSON_JAR to an existing org.json runtime JAR (Debian: libandroid-json-java)')


def tool(name):
    return str(JDK_BIN / name) if JDK_BIN else name


with tempfile.TemporaryDirectory(prefix='rtrust-portal-test-') as output:
    stub = Path(output) / 'ProfileVault.java'
    stub.write_text('''package org.rtrusttunnel.android;
final class ProfileVault {
 static byte[] readBounded(java.io.InputStream input, int limit) {
  throw new AssertionError("Network path unused in sequence fixture");
 }
}
''')
    subprocess.run([tool('javac'), '-cp', str(JSON_JAR), '-d', output,
        str(JAVA_ROOT / 'main/java/org/rtrusttunnel/android/PortalClient.java'),
        str(JAVA_ROOT / 'main/java/org/rtrusttunnel/android/NativeCore.java'),
        str(JAVA_ROOT / 'test/java/org/rtrusttunnel/android/PortalClientTest.java'), str(stub)],
        check=True, timeout=30)
    subprocess.run([tool('java'), '-cp', output + os.pathsep + str(JSON_JAR),
                    'org.rtrusttunnel.android.PortalClientTest'], check=True, timeout=30)
