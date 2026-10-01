"""Start a real headless Wayland compositor; never fall back to X11/XWayland."""
import os
import pathlib
import subprocess
import sys
import tempfile
import time

features = subprocess.check_output(["cargo", "tree", "-p", "rtrust-native", "-e", "features", "--locked"], text=True)
assert 'winit feature "x11"' not in features and "clipboard_x11" not in features and "x11-dl" not in features, "X11 backend unexpectedly enabled"

with tempfile.TemporaryDirectory(prefix="rtrust-wayland-") as directory:
    runtime = pathlib.Path(directory)
    runtime.chmod(0o700)
    env = os.environ.copy()
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_SOCKET", None)
    env.update(XDG_RUNTIME_DIR=str(runtime), WAYLAND_DISPLAY="rtrust-ci", XDG_SESSION_TYPE="wayland", WINIT_UNIX_BACKEND="wayland")
    log = runtime / "weston.log"
    compositor = subprocess.Popen(["weston", "--backend=headless-backend.so", "--use-pixman", "--socket=rtrust-ci", "--idle-time=0", "--no-config", "--log=" + str(log)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while not (runtime / "rtrust-ci").exists():
            if compositor.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(log.read_text() if log.exists() else "Weston did not start")
            time.sleep(.05)
        subprocess.run([sys.executable, "ci/smoke.py"], env=env, check=True, timeout=45)
        subprocess.run(["dbus-run-session", "--", sys.executable, "ci/linux_tray_smoke.py"], env=env, check=True, timeout=30)
        protocol_env = dict(env, WAYLAND_DEBUG="1")
        result = subprocess.run(["target/release/rtrust-native", "--ci-smoke"], env=protocol_env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr[-2000:]
        assert 'set_app_id("org.rtrusttunnel.Native")' in result.stderr, "Wrong/missing Wayland app ID"
        print("PASS Wayland xdg_toplevel app ID matches org.rtrusttunnel.Native.desktop", flush=True)
        assert compositor.poll() is None, "Wayland compositor exited during smoke"
        print("PASS native GUI on Weston Wayland (DISPLAY unset, no XWayland)", flush=True)
    finally:
        compositor.terminate()
        try:
            compositor.wait(timeout=5)
        except subprocess.TimeoutExpired:
            compositor.kill(); compositor.wait(timeout=5)
        compositor.stderr.close()
