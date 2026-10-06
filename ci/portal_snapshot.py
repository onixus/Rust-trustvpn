"""Freeze committed private portal sources for Linux Jenkins agents."""
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

source = Path(os.environ.get('RTRUST_PORTAL_REPO', '/Users/onixus/Git/tunnel'))
revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
archive = subprocess.check_output(['git', '-C', str(source), 'archive', revision + ':server/upstream'])
destination = Path('.ci-portal-upstream')
destination.mkdir(exist_ok=False)
with tarfile.open(fileobj=io.BytesIO(archive)) as files:
    files.extractall(destination, filter='data')
Path('portal-source-manifest.json').write_text(json.dumps({'revision': revision, 'path': 'server/upstream'}) + '\n', encoding='utf-8')
