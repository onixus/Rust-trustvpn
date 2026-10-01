#!/usr/bin/env python3
"""Render checked-in Flow SVG assets. Requires Node sharp and Python Pillow.

Pass --node-modules for a nonstandard Sharp installation. Generated assets are
committed so release builders do not need graphics tooling.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
from PIL import Image

root = Path(__file__).resolve().parents[1]
b = root / 'packaging/branding'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--node', default='node')
p.add_argument('--node-modules')
a = p.parse_args()
env = os.environ.copy()
if a.node_modules:
    env['NODE_PATH'] = a.node_modules
js = "const sharp=require('sharp'); sharp(process.argv[1]).resize(Number(process.argv[3])).png().toFile(process.argv[2]).catch(e=>{console.error(e);process.exit(1)});"
for svg, size, name in [('icon.svg',1024,'icon.png'), ('tray.svg',32,'tray-32.png')]:
    subprocess.run([a.node,'-e',js,str(b/svg),str(b/name),str(size)],env=env,check=True)
image = Image.open(b/'icon.png').convert('RGBA')
image.save(b/'icon.ico',sizes=[(s,s) for s in (16,24,32,48,64,128,256)])
image.save(b/'icon.icns')
(b/'icon-128.rgba').write_bytes(image.resize((128,128),Image.Resampling.LANCZOS).tobytes())
(b/'tray-32.rgba').write_bytes(Image.open(b/'tray-32.png').convert('RGBA').tobytes())
for name in ('icon.png','icon.ico','icon.icns'):
    shutil.copy2(b/name,root/'apps/webview/icons'/name)
print('Rendered Flow icons for desktop apps, packages and tray')
