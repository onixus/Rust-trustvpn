#!/usr/bin/env python3
"""Exact-commit H2/H3/failover/route-explain evidence in disposable Docker namespaces.

Run locally with --sha, --host and --endpoint-archive. Never installs a service,
uses host networking, or runs packet harnesses outside a disposable container.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request

BASE_IMAGE = 'rust@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e'
ENDPOINT_SHA = '91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7'
CLIPPY_SHA = 'e167f333be24e1d5eea56ea563c7def0aa0bd613f5ce3445976c93b0288799d1'
CLIPPY_URL = 'https://static.rust-lang.org/dist/2026-09-03/clippy-1.98.1-x86_64-unknown-linux-gnu.tar.xz'
RECIPE = f'''FROM {BASE_IMAGE}
COPY clippy.tar.xz /usr/local/rustup/downloads/{CLIPPY_SHA}
RUN rustup component add clippy
RUN apt-get -o Acquire::http::Timeout=20 update -qq && apt-get install -y -qq --no-install-recommends iproute2 iputils-ping curl python3 libdbus-1-dev pkg-config nftables systemd-resolved dbus openssl util-linux ca-certificates && rm -rf /var/lib/apt/lists/*
'''
LANES = [('service', ['scripts/service-interop.py']), ('h2', ['scripts/full-tunnel-interop.py']),
         ('h3', ['scripts/full-tunnel-interop.py', '--http3']),
         ('failover', ['scripts/failover-interop.py']),
         ('recovery', ['scripts/recovery-interop.py']),
         ('explain', ['scripts/route-explain-interop.py'])]
# Per-lane deadlines; recovery waits through real backoff, hysteresis and
# handoff, route explain runs one desktop service and two mobile flow sessions.
LANE_TIMEOUT = 420
LANE_TIMEOUTS = {'recovery': 720, 'explain': 600}
# Tool image (600 s) + build (900 s) + kill waits, cleanup and transfers (220 s).
SSH_OVERHEAD = 1720


def ssh_budget():
    return SSH_OVERHEAD + sum(LANE_TIMEOUTS.get(label, LANE_TIMEOUT) for label, _ in LANES)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def checked(args, timeout=30, **kwargs):
    return subprocess.run(args, check=True, timeout=timeout, **kwargs)


def json_write(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')


def docker_names(run_id):
    if not re.fullmatch(r'[0-9a-f]{12}', run_id):
        raise ValueError('Invalid laboratory run ID')
    return ['rtrust-lab-' + run_id + '-' + name for name in ['build'] + [label for label, _ in LANES]]


def worker(run_dir, endpoint_archive):
    """Invoked only inside the VM by this immutable archived runner."""
    run_dir = Path(run_dir).resolve()
    if run_dir.parent != Path('/tmp') or not re.fullmatch(r'rtrust-lab-[0-9a-f]{12}', run_dir.name):
        raise ValueError('Worker requires its own /tmp laboratory directory')
    run_id = run_dir.name.removeprefix('rtrust-lab-')
    names = docker_names(run_id)
    out = run_dir / 'evidence'
    out.mkdir()
    (out / 'bin').mkdir()
    (run_dir / 'worker.pid').write_text(str(os.getpid()))
    manifest = json.loads((run_dir / 'request.json').read_text())
    manifest.update(started_at=time.time(), lanes={}, base_image=BASE_IMAGE,
                    tool_recipe_sha256=hashlib.sha256(RECIPE.encode()).hexdigest(),
                    boundary='isolated Docker/network namespaces; not installed-package/device acceptance')
    image = 'rtrust-lab-tools:' + run_id
    target_volume = 'rtrust-lab-' + run_id + '-target'
    active = None
    build_image = False

    def cleanup():
        failures = []
        for name in names:
            try:
                result = subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=20)
                # Missing container is already clean; inspect distinguishes it.
                if result.returncode and subprocess.run(['docker', 'inspect', name], stdout=subprocess.DEVNULL,
                                                        stderr=subprocess.DEVNULL, timeout=10).returncode == 0:
                    failures.append(name)
            except (OSError, subprocess.TimeoutExpired):
                failures.append(name)
        try:
            result = subprocess.run(['docker', 'volume', 'rm', target_volume], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=30)
            if result.returncode and subprocess.run(['docker', 'volume', 'inspect', target_volume], stdout=subprocess.DEVNULL,
                                                    stderr=subprocess.DEVNULL, timeout=10).returncode == 0:
                failures.append(target_volume)
        except (OSError, subprocess.TimeoutExpired):
            failures.append(target_volume)
        if build_image:
            try:
                result = subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=30)
                if result.returncode and subprocess.run(['docker', 'image', 'inspect', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0:
                    failures.append(image)
            except (OSError, subprocess.TimeoutExpired):
                failures.append(image)
        return failures

    def interrupted(signum, _frame):
        if active is not None:
            active.terminate()
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)

    def logged(label, args, timeout):
        nonlocal active
        started = time.time()
        print('START ' + label, flush=True)
        with (out / (label + '.log')).open('wb') as stream:
            active = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT)
            try:
                code = active.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                active.kill()
                active.wait(timeout=10)
                manifest['lanes'][label] = {'timeout': True, 'seconds': round(time.time() - started, 2)}
                raise
            finally:
                active = None
        manifest['lanes'][label] = {'exit_code': code, 'seconds': round(time.time() - started, 2)}
        json_write(out / 'manifest.json', manifest)
        print(('PASS ' if code == 0 else 'FAIL ') + label, flush=True)
        if code:
            raise subprocess.CalledProcessError(code, args)

    failure = None
    try:
        if digest(run_dir / 'source.tar.gz') != manifest['source_sha256']:
            raise ValueError('Source archive checksum mismatch')
        shutil.copy2(run_dir / 'source.tar.gz', out / 'source.tar.gz')
        source = run_dir / 'source'
        with tarfile.open(run_dir / 'source.tar.gz') as archive:
            archive.extractall(source, filter='data')
        archived_runner = source / 'ci/linux_lab.py'
        if digest(archived_runner) != manifest['runner_sha256']:
            raise ValueError('Archived runner differs from invoked exact-commit runner')
        # Git archives preserve commit mtimes, which can predate a shared build
        # cache. Refresh only this disposable copy's regular-file timestamps so
        # Cargo cannot mistake changed archived source for older cached inputs.
        for path in source.rglob('*'):
            if path.is_file() and not path.is_symlink():
                path.touch()
        manifest['source_cache_fence'] = 'fresh regular-file timestamps after verified archive extraction'
        manifest['script_sha256'] = {str(path.relative_to(source)): digest(path) for path in
                                     [archived_runner, source / 'scripts/full-tunnel-interop.py',
                                      source / 'scripts/failover-interop.py', source / 'scripts/recovery-interop.py',
                                      source / 'scripts/service-interop.py', source / 'scripts/route-explain-interop.py']}
        fixture = run_dir / 'fixture'
        fixture.mkdir()
        endpoint_archive = Path(endpoint_archive)
        if endpoint_archive.stat().st_size > 32 * 1024 * 1024 or digest(endpoint_archive) != ENDPOINT_SHA:
            raise ValueError('Cached official v1.1.0 x86_64 endpoint checksum mismatch')
        with tarfile.open(endpoint_archive) as archive:
            members = [m for m in archive if m.isfile() and Path(m.name).name == 'trusttunnel_endpoint']
            if len(members) != 1 or members[0].size > 32 * 1024 * 1024:
                raise ValueError('Invalid official endpoint archive')
            endpoint = fixture / 'trusttunnel_endpoint'
            with archive.extractfile(members[0]) as stream, endpoint.open('wb') as target:
                shutil.copyfileobj(stream, target)
            endpoint.chmod(0o755)
        manifest['endpoint_archive_sha256'] = ENDPOINT_SHA
        manifest['endpoint_binary_sha256'] = digest(endpoint)
        architecture = checked(['docker', 'info', '--format', '{{.Architecture}}'], capture_output=True, text=True).stdout.strip()
        if architecture != 'x86_64':
            raise ValueError('Pinned fixture/tool image requires x86_64 Docker')
        # No pulls or mutable image tags. A cache miss is explicit failure.
        checked(['docker', 'image', 'inspect', BASE_IMAGE], stdout=subprocess.DEVNULL)
        # Feed the bounded, fixed Dockerfile separately to retain its exact bytes.
        (out / 'Dockerfile').write_text(RECIPE)
        context = run_dir / 'tool-context'
        context.mkdir()
        (context / 'Dockerfile').write_text(RECIPE)
        clippy = context / 'clippy.tar.xz'
        cached_clippy = endpoint_archive.parent / CLIPPY_SHA
        if cached_clippy.exists() and cached_clippy.stat().st_size <= 8 * 1024 * 1024 and digest(cached_clippy) == CLIPPY_SHA:
            shutil.copy2(cached_clippy, clippy)
        else:
            with urllib.request.urlopen(CLIPPY_URL, timeout=30) as response:
                data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != CLIPPY_SHA:
                raise ValueError('Official Clippy archive checksum/size mismatch')
            clippy.write_bytes(data)
        manifest['clippy_archive_sha256'] = CLIPPY_SHA
        build_image = True
        logged('tool-image', ['docker', 'build', '--pull=false', '-t', image, str(context)], 600)
        manifest['tool_image_id'] = checked(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], capture_output=True, text=True).stdout.strip()
        (source / 'target/debug').mkdir(parents=True)
        manifest['build_target_volume'] = target_volume
        build = '''set -eu
rustc --version; cargo --version; cargo clippy --version; dpkg-query -W
cargo test --locked --offline -p rtrust-tun -p rtrust-control --quiet
cargo clippy --locked --offline -p rtrust-tun -p rtrust-control --all-targets -- -D warnings
cargo build --locked --offline -p rtrust-tun -p rtrust-inspect
cargo build --locked --offline -p rtrust-tun --example flow-lab
cp target/debug/rtrust-service target/debug/rtrust-tun target/debug/rtrust-inspect target/debug/examples/flow-lab /out/bin/
chmod 755 /out/bin/*
'''
        logged('build', ['docker', 'run', '--rm', '--name', names[0], '--network', 'none',
                        '--security-opt', 'label=disable', '-v', f'{source}:/work:ro',
                        '-v', f'{target_volume}:/work/target',
                        '-v', 'rtrust-linux-cargo:/usr/local/cargo/registry',
                        '-v', f'{out}:/out', '-w', '/work', manifest['tool_image_id'], 'sh', '-c', build], 900)
        manifest['binary_sha256'] = {p.name: digest(p) for p in (out / 'bin').iterdir()}
        # The harness modifies only its container's namespaces, /etc and /run.
        # No host filesystem, D-Bus/socket, PID namespace or networking mounts.
        for (label, arguments), name in zip(LANES, names[1:]):
            script, *flags = arguments
            logged(label, ['docker', 'run', '--rm', '--name', name, '--network', 'none',
                           '--cap-add', 'NET_ADMIN', '--cap-add', 'SYS_ADMIN', '--security-opt', 'label=disable',
                           '--device', '/dev/net/tun', '--stop-timeout', '5',
                           '-v', f'{source}:/work:ro', '-v', f'{out / "bin"}:/work/target/debug:ro',
                           '-v', f'{fixture}:/fixture:ro', '-w', '/work', manifest['tool_image_id'],
                           'python3', script, '/fixture/trusttunnel_endpoint', *flags],
                       LANE_TIMEOUTS.get(label, LANE_TIMEOUT))
    except BaseException as error:
        failure = error
        manifest['failure'] = type(error).__name__ + ': ' + str(error)
    finally:
        manifest['cleanup_failures'] = cleanup()
        manifest['finished_at'] = time.time()
        manifest['passed'] = failure is None and not manifest['cleanup_failures']
        json_write(out / 'manifest.json', manifest)
        # Hashes bind the collected stdout, source archive and build binaries.
        json_write(out / 'artifact_sha256.json', {str(p.relative_to(out)): digest(p)
                   for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'artifact_sha256.json' and 'bin' not in p.relative_to(out).parts})
        with tarfile.open(run_dir / 'evidence.tar.gz', 'w:gz') as archive:
            # Binary hashes retained; binaries remain isolated and are discarded.
            for path in sorted(out.iterdir()):
                if path.name != 'bin':
                    archive.add(path, arcname=path.name)
    if failure is not None:
        raise failure
    if not manifest['passed']:
        raise RuntimeError('Laboratory cleanup incomplete')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sha')
    parser.add_argument('--host')
    parser.add_argument('--endpoint-archive', required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker, args.endpoint_archive)
    if not args.sha or not re.fullmatch(r'[0-9a-f]{40}', args.sha) or not args.host or args.host.startswith('-'):
        parser.error('--sha requires a full immutable commit SHA and --host a configured SSH destination')
    root = Path(__file__).resolve().parents[1]
    commit = checked(['git', 'cat-file', '-t', args.sha], cwd=root, capture_output=True, text=True).stdout.strip()
    if commit != 'commit':
        parser.error('--sha must identify a commit')
    archived_runner = checked(['git', 'show', args.sha + ':ci/linux_lab.py'], cwd=root, capture_output=True).stdout
    if hashlib.sha256(archived_runner).hexdigest() != digest(__file__):
        parser.error('Run the runner from the requested commit; live runner differs')
    run_id = secrets.token_hex(6)
    remote = '/tmp/rtrust-lab-' + run_id
    output = (args.output or root / 'dist/lab' / (args.sha + '-' + run_id)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    archive = output / 'source.tar.gz'
    checked(['git', 'archive', '--format=tar.gz', '-o', str(archive), args.sha], cwd=root)
    manifest = {'commit': args.sha, 'source_sha256': digest(archive), 'runner_sha256': digest(__file__), 'run_id': run_id}
    json_write(output / 'request.json', manifest)
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.host]
    checked([*ssh, 'mkdir -m 700 ' + shlex.quote(remote)])
    try:
        checked(['scp', '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', str(archive), str(output / 'request.json'), str(Path(__file__).resolve()), args.host + ':' + remote + '/'], timeout=120)
        command = 'exec python3 ' + shlex.quote(remote + '/linux_lab.py') + ' --worker ' + shlex.quote(remote) + ' --endpoint-archive ' + shlex.quote(args.endpoint_archive)
        result = subprocess.run([*ssh, command], timeout=ssh_budget())
        checked(['scp', '-q', '-o', 'BatchMode=yes', args.host + ':' + remote + '/evidence.tar.gz', str(output / 'evidence.tar.gz')], timeout=120)
        print('Evidence: ' + str(output / 'evidence.tar.gz'), flush=True)
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, command)
    finally:
        # Explicitly fence a lost/cancelled SSH connection. Terminate only this
        # runner's recorded process if /proc still identifies this exact path.
        stop_code = """import os,pathlib,signal,time
p=pathlib.Path(PATH+'/worker.pid')
pid=int(p.read_text()) if p.exists() else 0
cmd=pathlib.Path('/proc/'+str(pid)+'/cmdline')
def owned():
    try: return pid and (PATH+'/linux_lab.py').encode() in cmd.read_bytes()
    except FileNotFoundError: return False
if owned(): os.kill(pid,signal.SIGTERM)
end=time.monotonic()+60
while owned() and time.monotonic()<end: time.sleep(.2)
if owned(): os.kill(pid,signal.SIGKILL)
""".replace('PATH', repr(remote))
        try:
            subprocess.run([*ssh, 'python3 -c ' + shlex.quote(stop_code)], timeout=75)
            if not (output / 'evidence.tar.gz').exists():
                subprocess.run(['scp', '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.host + ':' + remote + '/evidence.tar.gz', str(output / 'evidence.tar.gz')], timeout=120)
        finally:
            remove = 'docker rm -f ' + ' '.join(docker_names(run_id)) + ' >/dev/null 2>&1; docker image rm rtrust-lab-tools:' + run_id + ' >/dev/null 2>&1; docker volume rm rtrust-lab-' + run_id + '-target >/dev/null 2>&1; rm -rf -- ' + shlex.quote(remote)
            subprocess.run([*ssh, remove], timeout=90)


if __name__ == '__main__':
    main()
