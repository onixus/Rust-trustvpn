"""Exercise bundled UI/IPC and hide/restore without reading the user's vault."""
import pathlib,platform,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
binary=root/'target/release'/('rtrust-webview.exe' if platform.system()=='Windows' else 'rtrust-webview')
result=subprocess.run([str(binary),'--ci-smoke'],text=True,capture_output=True,timeout=35)
assert result.returncode==0,result.stderr[-3000:]
assert 'PASS WebView local assets' in result.stdout,result.stderr[-3000:]
print(result.stdout.strip())
