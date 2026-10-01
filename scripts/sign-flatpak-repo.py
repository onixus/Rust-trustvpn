#!/usr/bin/env python3
"""Sign an existing candidate repository and write GUI-installable remote metadata.
The caller supplies a private GPG home; no key is generated or copied into artifacts.
"""
import argparse
import base64
import pathlib
import re
import subprocess
import urllib.parse

parser=argparse.ArgumentParser()
parser.add_argument('--repo',type=pathlib.Path,required=True)
parser.add_argument('--gpg-home',type=pathlib.Path,required=True)
parser.add_argument('--key',required=True,help='Full signing-key fingerprint')
parser.add_argument('--url',required=True,help='Public HTTPS URL of this OSTree repository')
parser.add_argument('--arch',action='append',choices=['x86_64','aarch64'],required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
args=parser.parse_args()
url=urllib.parse.urlsplit(args.url)
assert url.scheme=='https' and url.hostname and not url.username and not url.password and not url.query and not url.fragment
assert not any(c in args.url for c in '\r\n\x00')
assert re.fullmatch(r'[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}',args.key),'Use the complete GPG fingerprint'
assert args.repo.is_dir() and args.gpg_home.is_dir()
repo=args.repo.resolve();gpg=args.gpg_home.resolve();output=args.output.resolve()
assert not gpg.is_relative_to(repo) and not gpg.is_relative_to(output),'Private keys must remain outside published artifacts'
public=subprocess.check_output(['gpg','--homedir',str(gpg),'--batch','--export-options','export-minimal','--export',args.key])
assert public,'Signing public key not found'
signing=['--gpg-sign='+args.key,'--gpg-homedir='+str(gpg)]
for arch in sorted(set(args.arch)):
    subprocess.run(['flatpak','build-sign',*signing,'--arch='+arch,str(repo),'org.rtrusttunnel.Native','master'],check=True)
subprocess.run(['flatpak','build-update-repo',*signing,'--generate-static-deltas',str(repo)],check=True)
key=base64.b64encode(public).decode()
output.mkdir(parents=True,exist_ok=True)
(output/'rtrusttunnel.gpg').write_bytes(public)
(output/'R-TrustTunnel.flatpakrepo').write_text('[Flatpak Repo]\nTitle=R-TrustTunnel\nUrl='+args.url+'\nGPGKey='+key+'\n')
(output/'R-TrustTunnel.flatpakref').write_text('[Flatpak Ref]\nTitle=R-TrustTunnel\nName=org.rtrusttunnel.Native\nBranch=master\nIsRuntime=false\nUrl='+args.url+'\nSuggestRemoteName=rtrusttunnel\nRuntimeRepo=https://flathub.org/repo/flathub.flatpakrepo\nGPGKey='+key+'\n')
print('Signed repository and GUI installation metadata:',output)
