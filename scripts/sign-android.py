#!/usr/bin/env python3
"""Sign an unsigned Android release APK with an externally managed PKCS12 key.

The password is read by apksigner from a private file, never from command output
or a command-line password. This script does not create or replace signing keys.
"""
import argparse
import hashlib
from pathlib import Path
import stat
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--keystore', type=Path, required=True)
    parser.add_argument('--password-file', type=Path, required=True)
    parser.add_argument('--alias', default='rtrust-android')
    parser.add_argument('--apksigner-jar', type=Path, required=True)
    parser.add_argument('--java', default='java')
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error('Keep the original unsigned build as separate evidence')
    for path in (args.keystore, args.password_file):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            parser.error('Signing key and password must be regular owner-only files')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    signer = [args.java, '-jar', str(args.apksigner_jar)]
    subprocess.run([*signer, 'sign', '--ks', str(args.keystore), '--ks-key-alias', args.alias,
                    '--ks-pass', 'file:' + str(args.password_file), '--v4-signing-enabled', 'false',
                    '--out', str(args.output), str(args.input)], check=True)
    subprocess.run([*signer, 'verify', '--verbose', '--print-certs', str(args.output)], check=True)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + '.sha256').write_text(digest + '  ' + args.output.name + '\n')
    print('Verified APK SHA256: ' + digest)

if __name__ == '__main__': main()
