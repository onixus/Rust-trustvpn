"""Server tests in Linux; cache compilation on native Docker volumes, never macOS binds."""
import argparse
import hashlib
import pathlib
import secrets
import shutil
import signal
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, default=ROOT / '.ci-portal-upstream')
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    if not (upstream / 'app/main.py').is_file():
        parser.error('Provide the frozen private portal source with --upstream')
    digest = hashlib.sha256((ROOT / 'ci/portal.Dockerfile').read_bytes() +
                            (ROOT / 'server/test-environment/requirements.txt').read_bytes()).hexdigest()[:16]
    image = 'rtrust-portal-tests:' + digest
    with tempfile.TemporaryDirectory(prefix='rtrust-portal-ci-') as folder:
        shutil.copy2(ROOT / 'ci/portal.Dockerfile', pathlib.Path(folder) / 'Dockerfile')
        shutil.copy2(ROOT / 'server/test-environment/requirements.txt', pathlib.Path(folder) / 'requirements.txt')
        subprocess.run(['docker', 'build', '-t', image, folder], check=True)
    name = 'rtrust-portal-ci-' + secrets.token_hex(6)

    def cleanup(*_):
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def interrupted(signum, _frame):
        cleanup()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    common = ['docker', 'run', '--rm', '--name', name,
              '--mount', f'type=bind,src={ROOT},dst=/src,readonly',
              '--mount', f'type=bind,src={upstream},dst=/portal,readonly',
              '--mount', 'type=volume,src=rtrust-portal-target-v1,dst=/build-target',
              '--mount', 'type=volume,src=rtrust-portal-cargo-v1,dst=/cargo-cache',
              '-e', 'RTRUST_PORTAL_SRC=/portal']
    try:
        subprocess.run(common + [image, 'sh', '-ec', '''mkdir -p "$HOME"
cargo build --locked -p rtrust-codec
cargo build --locked -p rtrust-portal --examples
'''], check=True)
        # Test traffic stays on the container loopback; there is no external network.
        subprocess.run(common + ['--network', 'none', image, 'sh', '-ec', '''mkdir -p "$HOME"
python server/tests/test_publication.py
python server/tests/test_exchange.py
python server/tests/native_exchange.py
python server/tests/routing_exchange.py
'''], check=True)
    finally:
        cleanup()


if __name__ == '__main__':
    main()
