"""Export links using the official endpoint, including TLS trust settings."""
import subprocess
from . import config


def build_deeplink(username: str, password: str, host: str, port: int) -> str:
    result = subprocess.run(
        [config.ENDPOINT_BIN, "vpn.toml", "hosts.toml", "--client_config", username,
         "--address", f"{host}:{port}", "--format", "deeplink", "--name", "Onixus TrustTunnel"],
        cwd=config.ENDPOINT_WORKDIR, capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("TrustTunnel profile export failed")
    for line in result.stdout.splitlines():
        if line.startswith("tt://"):
            return line.strip()
    raise RuntimeError("TrustTunnel profile export returned no link")
