#!/usr/bin/env python3
"""Offline JVM sync sequence tests: real org.json, injected transport/parser, no vault/JNI/Android runtime."""
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
    stubs = Path(output) / 'stubs'
    # Minimal platform/app stubs: the fixture uses no Context, so no lease, recovery network,
    # Keystore or JNI is reached; any unexpected use fails loudly.
    sources = {
        'org/rtrusttunnel/android/ProfileVault.java': '''package org.rtrusttunnel.android;
final class ProfileVault {
 static byte[] readBounded(java.io.InputStream input, int limit) {
  throw new AssertionError("Network path unused in sequence fixture");
 }
}
''',
        'org/rtrusttunnel/android/OfflineLease.java': '''package org.rtrusttunnel.android;
final class OfflineLease {
 static org.json.JSONObject issue(android.content.Context c, org.json.JSONObject s, long w, long e) {
  throw new AssertionError("Lease path unused without Context");
 }
}
''',
        'org/rtrusttunnel/android/TunnelService.java': '''package org.rtrusttunnel.android;
final class TunnelService {
 static android.net.Network portalRecoveryNetwork() { throw new AssertionError("Recovery network unused without Context"); }
}
''',
        'android/content/Context.java': '''package android.content;
public abstract class Context { public abstract Context getApplicationContext(); }
''',
        'android/net/Network.java': '''package android.net;
public class Network {
 public java.net.URLConnection openConnection(java.net.URL url) { throw new AssertionError("Network unused"); }
}
''',
        'android/os/SystemClock.java': '''package android.os;
public final class SystemClock { public static long elapsedRealtime() { return System.nanoTime() / 1000000L; } }
''',
    }
    stub_files = []
    for name, text in sources.items():
        path = stubs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        stub_files.append(str(path))
    subprocess.run([tool('javac'), '-cp', str(JSON_JAR), '-d', output,
        str(JAVA_ROOT / 'main/java/org/rtrusttunnel/android/PortalClient.java'),
        str(JAVA_ROOT / 'main/java/org/rtrusttunnel/android/NativeCore.java'),
        str(JAVA_ROOT / 'test/java/org/rtrusttunnel/android/PortalClientTest.java'), *stub_files],
        check=True, timeout=30)
    subprocess.run([tool('java'), '-cp', output + os.pathsep + str(JSON_JAR),
                    'org.rtrusttunnel.android.PortalClientTest'], check=True, timeout=30)
