#!/usr/bin/env python3
"""Sign an unsigned Android release APK with the externally managed release key.

The key is described by the same owner-only `keystore.properties` file that Gradle
uses (storeFile, storePassword, keyAlias, keyPassword). Passwords reach apksigner
through its environment, never through argv or command output. The signed APK must
carry the expected release certificate, so a build signed with a retired key cannot
be published as an update. This script does not create or replace signing keys.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess

# Release certificate since 0.6.0. Releases up to 0.5.x used a retired key;
# APKs signed with it cannot update installations of 0.6.0 or later.
RELEASE_CERT_SHA256 = '4aa431cd89387e969da006b0a76288ac725fa17e952a83641df80d4b977306af'
REQUIRED = ('storeFile', 'storePassword', 'keyAlias', 'keyPassword')


def owner_only(path, parser):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        parser.error('Signing key and properties must be regular owner-only files')


def read_properties(path):
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line[0] in '#!':
            continue
        match = re.match(r'([^=:\s]+)\s*[=:]\s*(.*)$', line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def signer_digests(output):
    return re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})$', output, re.MULTILINE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--keystore-properties', type=Path, required=True,
                        help='Gradle keystore.properties; storeFile is relative to its directory')
    parser.add_argument('--expected-cert-sha256', default=RELEASE_CERT_SHA256)
    parser.add_argument('--apksigner-jar', type=Path, required=True)
    parser.add_argument('--java', default='java')
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error('Keep the original unsigned build as separate evidence')
    owner_only(args.keystore_properties, parser)
    properties = read_properties(args.keystore_properties)
    missing = [name for name in REQUIRED if not properties.get(name)]
    if missing:
        parser.error('keystore.properties lacks ' + ', '.join(missing))
    keystore = args.keystore_properties.parent / properties['storeFile']
    owner_only(keystore, parser)
    env = dict(os.environ, RTRUST_ANDROID_KS_PASS=properties['storePassword'],
               RTRUST_ANDROID_KEY_PASS=properties['keyPassword'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    signer = [args.java, '-jar', str(args.apksigner_jar)]
    subprocess.run([*signer, 'sign', '--ks', str(keystore), '--ks-key-alias', properties['keyAlias'],
                    '--ks-pass', 'env:RTRUST_ANDROID_KS_PASS', '--key-pass', 'env:RTRUST_ANDROID_KEY_PASS',
                    '--v4-signing-enabled', 'false', '--out', str(args.output), str(args.input)],
                   check=True, env=env)
    verified = subprocess.run([*signer, 'verify', '--verbose', '--print-certs', str(args.output)],
                              check=True, capture_output=True, text=True)
    print(verified.stdout, end='')
    if signer_digests(verified.stdout) != [args.expected_cert_sha256.lower()]:
        args.output.unlink()
        raise SystemExit('Signed APK does not carry the expected release certificate; output removed')
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + '.sha256').write_text(digest + '  ' + args.output.name + '\n')
    print('Verified APK SHA256: ' + digest)

if __name__ == '__main__': main()
