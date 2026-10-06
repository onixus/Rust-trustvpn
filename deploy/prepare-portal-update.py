#!/usr/bin/env python3
"""Build and check an additive exchange update; never replace running containers."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=300).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.stderr[-8000:] or 'Docker command failed') from error


def require_unused_tag(tag):
    # A successful empty listing means absent; daemon failures must abort.
    if run('docker', 'image', 'ls', '--quiet', '--filter', 'reference=' + tag):
        raise RuntimeError('Output image tag already exists; choose a new release tag')


def prepare(base, tag):
    # Resolve mutable tags before building. No environment or credential inspection.
    image = run('docker', 'image', 'inspect', '--format', '{{.Id}}', base)
    if not image.startswith('sha256:') or len(image) != 71:
        raise RuntimeError('Expected a local Docker image digest')
    require_unused_tag(tag)
    # BuildKit treats bare sha256 IDs in FROM as registry image names.
    # Give the resolved local image a content-derived tag before building.
    pinned = 'rtrust-portal-base:' + image.removeprefix('sha256:')
    run('docker', 'tag', image, pinned)
    # Pass only the public overlay and patcher to Docker, never the working tree/data.
    with tempfile.TemporaryDirectory(prefix='rtrust-portal-build-') as folder:
        import shutil
        context = Path(folder)
        shutil.copytree(ROOT / 'server/overlay/app', context / 'server/overlay/app',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        (context / 'deploy').mkdir()
        for name in ('portal_patch.py', 'portal-update.Dockerfile'):
            shutil.copy2(ROOT / 'deploy' / name, context / 'deploy' / name)
        image_file = context / 'candidate.iid'
        run('docker', 'build', '--build-arg', 'BASE_IMAGE=' + pinned,
            '-f', str(context / 'deploy/portal-update.Dockerfile'),
            '--iidfile', str(image_file), str(context))
        candidate = image_file.read_text(encoding='utf-8').strip()
        if not candidate.startswith('sha256:') or len(candidate) != 71:
            raise RuntimeError('Expected a candidate image ID')
    # Disposable database, no live mounts, no network and no endpoint startup.
    check = '''from app import db, rtrust_profiles as exchange
from app.main import app
import json
from pathlib import Path
db.init_db()
exchange.init()
exchange.init()
assert json.loads(exchange.capabilities().body)['routing'] == 1
paths = app.openapi()['paths']
assert 'get' in paths['/portal/v2/routing']
assert {'get', 'post'} <= paths['/portal/v2/route-groups'].keys()
assert 'route-groups' in Path('/app/app/static/rtrust-profiles.js').read_text(encoding='utf-8')
print('PASS route API, UI and repeatable schema initialization')
'''
    run('docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
        '--workdir', '/app', '-e', 'DATA_DIR=/tmp/portal',
        '-e', 'DB_PATH=/tmp/portal/test.db', '-e', 'CONSOLE_DATA=/tmp/console',
        '-e', 'SECRET_KEY=isolated-build-check-not-a-production-secret',
        '--entrypoint', 'python', candidate, '-c', check)
    # Publish only the exact checked image, and recheck after the lengthy build.
    require_unused_tag(tag)
    run('docker', 'tag', candidate, tag)
    return {'base_image': image, 'image': candidate,
            'tag': tag, 'running_containers_changed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-image', required=True, help='Exact installed portal/console image or local tag')
    parser.add_argument('--tag', required=True, help='New output image tag (do not reuse the live tag)')
    args = parser.parse_args()
    if args.base_image == args.tag:
        parser.error('Use a new output tag to preserve rollback')
    print(json.dumps(prepare(args.base_image, args.tag), indent=2))
