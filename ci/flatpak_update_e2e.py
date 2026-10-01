"""Signed Flatpak install/update/rollback in a private installation with temporary CI keys.
Never touches the desktop user's installed application or profile directory.
"""
import argparse
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--repo',type=pathlib.Path,required=True);args=p.parse_args()
arch=platform.machine();assert arch in ('x86_64','aarch64')
ref='app/org.rtrusttunnel.Native/'+arch+'/master'
with tempfile.TemporaryDirectory(prefix='rtrust-flatpak-update-') as directory:
    work=pathlib.Path(directory);repo=work/'repo';shutil.copytree(args.repo,repo)
    gpg=work/'private-keys';gpg.mkdir(mode=0o700)
    env=dict(os.environ,FLATPAK_USER_DIR=str(work/'installation'),XDG_DATA_HOME=str(work/'data'),XDG_CONFIG_HOME=str(work/'config'),XDG_CACHE_HOME=str(work/'cache'))
    def run(*command,success=True):
        r=subprocess.run(command,env=env,text=True,capture_output=True,timeout=180)
        assert (r.returncode==0)==success, ' '.join(command)+': '+r.stdout[-1200:]+r.stderr[-1200:]
        return r.stdout.strip()
    def flatpak(*command,success=True):return run('flatpak','--user',*command,success=success)
    try:
        flatpak('info','org.rtrusttunnel.Native',success=False)
        run('gpg','--homedir',str(gpg),'--batch','--pinentry-mode','loopback','--passphrase','','--quick-gen-key','R-TrustTunnel isolated CI <ci@example.invalid>','ed25519','sign','1d')
        listing=run('gpg','--homedir',str(gpg),'--with-colons','--list-keys')
        key=next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        def sign():
            run(sys.executable,str(ROOT/'scripts/sign-flatpak-repo.py'),'--repo',str(repo),'--gpg-home',str(gpg),'--key',key,'--url','https://downloads.example.invalid/flatpak','--arch',arch,'--output',str(work/'public'))
        def head():return run('ostree','--repo='+str(repo),'rev-parse',ref)
        def installed():return flatpak('info','--show-commit','org.rtrusttunnel.Native')
        sign();old=head()
        flatpak('remote-add','--gpg-import='+str(work/'public/rtrusttunnel.gpg'),'rtrust-ci',repo.as_uri())
        flatpak('install','--noninteractive','--no-deps','--no-related','rtrust-ci',ref)
        assert installed()==old
        print('PASS signed Flatpak install in private installation',flush=True)
        run('flatpak','build-commit-from','--force','--src-ref='+ref,'--subject=CI update',str(repo),ref)
        sign();new=head();assert new!=old
        flatpak('update','--noninteractive','--no-deps','--no-related','org.rtrusttunnel.Native')
        assert installed()==new
        flatpak('update','--noninteractive','--no-deps','--no-related','--commit='+old,'org.rtrusttunnel.Native')
        assert installed()==old
        print('PASS signed Flatpak update and explicit rollback',flush=True)
        # The summary is trusted, but the new application commit is not signed.
        run('flatpak','build-commit-from','--force','--src-ref='+ref,'--subject=CI unsigned rejection',str(repo),ref)
        unsigned=head();assert unsigned not in (old,new)
        run('flatpak','build-update-repo','--gpg-sign='+key,'--gpg-homedir='+str(gpg),str(repo))
        flatpak('update','--noninteractive','--no-deps','--no-related','org.rtrusttunnel.Native',success=False)
        assert installed()==old
        print('PASS unsigned application update rejected; previous installation retained',flush=True)
        flatpak('uninstall','--noninteractive','org.rtrusttunnel.Native')
        flatpak('info','org.rtrusttunnel.Native',success=False)
        print('PASS private Flatpak uninstall',flush=True)
    finally:
        subprocess.run(['gpgconf','--homedir',str(gpg),'--kill','all'],capture_output=True,timeout=10)
