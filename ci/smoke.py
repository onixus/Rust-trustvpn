"""Run packaged native GUI without touching the real vault; test CLI validation."""
import pathlib,platform,subprocess,tempfile
suffix='.exe' if platform.system()=='Windows' else ''
root=pathlib.Path(__file__).resolve().parents[1]
bin=root/'target/release'
subprocess.run([str(bin/('rtrust-native'+suffix)),'--ci-smoke'],check=True,timeout=30)
subprocess.run([str(bin/('rtrust-native'+suffix)),'--ci-portal-smoke'],check=True,timeout=30)
subprocess.run([str(bin/('rtrust-native'+suffix)),'--ci-tray-smoke'],check=True,timeout=30)
subprocess.run([str(bin/('rtrust-native'+suffix)),'--ci-settings-smoke'],check=True,timeout=30)
subprocess.run([str(bin/('rtrust-inspect'+suffix)),str(root/'examples/demo.endpoint.toml')],check=True,timeout=10)
with tempfile.TemporaryDirectory() as d:
    bad=pathlib.Path(d)/'invalid.toml';bad.write_text('not a profile')
    r=subprocess.run([str(bin/('rtrust-inspect'+suffix)),str(bad)],capture_output=True,timeout=10)
    assert r.returncode!=0
print('PASS native GUI event loop starts/exits; profile import works; invalid input rejected')
