"""Run as root on the existing portal host; retain config rollback before reload."""
import pathlib,shutil,subprocess,time,urllib.request
root=pathlib.Path('/opt/rtrust-updates');root.mkdir(mode=0o755,exist_ok=True)
(root/'health.txt').write_text('rtrust-updates-ready\n')
config=pathlib.Path('/opt/rtrust-releases/20260930-portal/portal-nginx.conf')
old=config.read_text();backup=config.with_name('portal-nginx.before-updates-'+str(int(time.time()))+'.conf');shutil.copy2(config,backup)
image='nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236'
exists=subprocess.run(['docker','inspect','rtrust-updates'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
if exists:raise SystemExit('Update container already exists; inspect before changing it')
subprocess.run(['docker','run','-d','--name','rtrust-updates','--network','trusttunnel-web_default','--read-only','--tmpfs','/var/cache/nginx:rw,noexec,nosuid,size=16m','--tmpfs','/var/run:rw,noexec,nosuid,size=1m','--security-opt','no-new-privileges','--restart','unless-stopped','--mount','type=bind,src=/opt/rtrust-updates,dst=/usr/share/nginx/html,readonly',image,'nginx','-g','daemon off;'],check=True)
location='''    location ^~ /rtrust/releases/ {
        proxy_pass http://rtrust-updates/;
        proxy_set_header Host $host;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options "nosniff" always;
        proxy_read_timeout 120s;
    }
'''
try:
    assert old.count('    location / {')==1 and '/rtrust/releases/' not in old
    config.write_text(old.replace('    location / {',location+'    location / {',1))
    subprocess.run(['docker','exec','rtrust-portal-https','nginx','-t'],check=True)
    subprocess.run(['docker','exec','rtrust-portal-https','nginx','-s','reload'],check=True)
    for _ in range(20):
        try:
            with urllib.request.urlopen('https://onixus-rf.duckdns.org/rtrust/releases/health.txt',timeout=10) as r:
                assert r.read()==b'rtrust-updates-ready\n';break
        except Exception:time.sleep(.5)
    else:raise RuntimeError('HTTPS update path did not become ready')
    with urllib.request.urlopen('https://onixus-rf.duckdns.org/profiles',timeout=10) as r:assert r.status==200
    print('PASS HTTPS feed and existing portal; backup:',backup)
except BaseException:
    config.write_text(old)
    subprocess.run(['docker','exec','rtrust-portal-https','nginx','-t'],check=True)
    subprocess.run(['docker','exec','rtrust-portal-https','nginx','-s','reload'],check=True)
    subprocess.run(['docker','rm','-f','rtrust-updates'],check=True)
    raise
