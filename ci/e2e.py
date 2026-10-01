"""Real native client ↔ official TrustTunnel endpoint, TCP/UDP/TLS/auth/tt import."""
import json,pathlib,platform,sys,tempfile
from datetime import datetime,timezone
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from interop import run,socks_proxy,check_socks
root=pathlib.Path(__file__).resolve().parents[1]
inspect=str(root/'target/release'/('rtrust-inspect.exe' if platform.system()=='Windows' else 'rtrust-inspect'))
fixture=json.loads(pathlib.Path(sys.argv[1]).read_text())
skew=(datetime.now(timezone.utc)-datetime.fromisoformat(fixture['created_at'])).total_seconds()
if abs(skew)>300:print(f'WARNING: node UTC differs from fixture creation by {skew:.0f}s; test certificate is valid for a 48-hour window; OS clock was not changed')
with tempfile.TemporaryDirectory(prefix='rtrust-e2e-') as directory:
    d=pathlib.Path(directory);profile=d/'profile.json'
    for protocol in ['http2','http3']:
        config=dict(fixture['base'],upstream_protocol=protocol);profile.write_text(json.dumps(config))
        target='127.0.0.1:'+str(fixture['http_port'])
        run([inspect,str(profile),'--probe-http',target],d)
        run([inspect,str(profile),'--probe-udp',':'.join(map(str,fixture['udp']))],d)
        with socks_proxy(inspect,profile,d) as proxy:
            body=run(['curl.exe' if platform.system()=='Windows' else 'curl','--silent','--show-error','--max-time','15','--noproxy','','--socks5-hostname',proxy,'http://localhost:'+str(fixture['http_port'])+'/'],d)
            assert body=='OK'
            check_socks(proxy,fixture['udp'])
        config['password']='incorrect';profile.write_text(json.dumps(config))
        run([inspect,str(profile),'--probe-http',target],d,success=False)
        config.update(password=fixture['base']['password'],hostname='wrong.invalid');profile.write_text(json.dumps(config))
        run([inspect,str(profile),'--probe-http',target],d,success=False)
        print('PASS '+protocol+': HTTP, UDP, SOCKS TCP/UDP, rejected fragments/spoofing, rejected wrong password/TLS identity')
    (d/'official.tt').write_text(fixture['link'])
    run([inspect,str(d/'official.tt')],d)
    print('PASS official tt export import')
