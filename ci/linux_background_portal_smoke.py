"""Real KDE Background portal round trip; refuse to alter an existing login entry."""
import os
import pathlib
import subprocess

entry = pathlib.Path.home()/'.config/autostart/org.rtrusttunnel.Native.desktop'
assert not entry.exists() and not entry.is_symlink(), 'Existing autostart entry: leave user settings unchanged'
env = dict(os.environ)
def request(mode):
    subprocess.run(['flatpak','run','--user','org.rtrusttunnel.Native','--ci-autostart-'+mode],
                   env=env,check=True,timeout=130)
try:
    request('enable')
    text=entry.read_text()
    assert 'X-Flatpak=org.rtrusttunnel.Native' in text
    assert 'rtrust-native' in text and '--autostart' in text
finally:
    request('disable')
assert not entry.exists()
print('PASS Background portal enable/disable and real desktop login entry')
