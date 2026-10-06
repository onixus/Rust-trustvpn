"""Live split-tunnel and mixed-proxy check against an installed RTrustTunnel service.

Usage: windows_split_e2e.py FIXTURE_JSON INSPECT_EXE
Needs ci/windows_fixture.py running and a service built from this checkout.
Leaves no lease: every Start is stopped, and pipe EOF releases routes anyway.
"""
import json,pathlib,subprocess,sys,time,urllib.request
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import windows_service_e2e as e2e
FIXTURE=e2e.FIXTURE;TARGET=e2e.TARGET
INSPECT=sys.argv[2]
LAN_HOST=FIXTURE['base']['addresses'][0].rsplit(':',1)[0]
EXCLUDED='203.0.113.0/24'
def start(**extra):
    pipe=e2e.Pipe()
    profile=dict(schema_version=1,name='Split E2E',endpoint=FIXTURE['base'])
    return pipe,pipe.request(dict(op='Start',profile=profile,networks=['0.0.0.0/0'],**extra))
def interface(ip):
    return e2e.ps(f"(Find-NetRoute -RemoteIPAddress {ip} | Where-Object InterfaceAlias | Select-Object -First 1).InterfaceAlias")
def tunnel_routes():
    return json.loads(e2e.ps("ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 -InterfaceAlias RTrustTunnel -ErrorAction SilentlyContinue | ForEach-Object DestinationPrefix)"))
def proxy_checks():
    profile=pathlib.Path('split-profile.json')
    profile.write_text(json.dumps(dict(schema_version=1,name='Proxy E2E',endpoint=FIXTURE['base'])))
    server=subprocess.Popen([INSPECT,str(profile),'--serve-socks','1080'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        for _ in range(100):
            line=server.stdout.readline()
            if 'SOCKS5' in line:break
        else:raise RuntimeError('proxy did not start: '+server.stderr.read())
        url=f'http://{TARGET}:8080/'
        def curl(*args):
            p=subprocess.run(['curl.exe','-sS','-o','NUL','-w','%{http_code} %{size_download}','--max-time','30',*args,url],capture_output=True,text=True)
            return p.stdout.strip()+(' '+p.stderr.strip() if p.returncode else '')
        expected=f'200 {len(e2e.BODY)}'
        results={
            'socks5':curl('--socks5-hostname','127.0.0.1:1080'),
            'http absolute-form':curl('-x','http://127.0.0.1:1080'),
            'http CONNECT':curl('-p','-x','http://127.0.0.1:1080'),
        }
        # Windows PowerShell 5.1 follows the WinINet system proxy (ProxyServer=127.0.0.1:1080).
        results['system proxy (WinINet)']=e2e.ps(f"$r=Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 '{url}'; '{{0}} {{1}}' -f $r.StatusCode,$r.RawContentLength")
        for name,result in results.items():
            assert result==expected,(name,result)
            print('PASS proxy',name,result)
    finally:
        server.kill();server.wait();profile.unlink(missing_ok=True)
def main():
    before=e2e.routes()
    pipe,answer=start()
    pipe.close()
    assert answer['state']=='Error' and 'маршрутом' in answer['message'],answer
    print('PASS 0.0.0.0/0 without LAN exclusion is refused:',answer['message'])
    pipe,answer=start(exclude=[EXCLUDED],exclude_lan=True)
    try:
        assert answer['state']=='Connected',answer
        routes=tunnel_routes()
        print('PASS connected; Wintun IPv4 routes:',len(routes))
        assert 0<len(routes)<=512
        expect={TARGET:'RTrustTunnel','1.1.1.1':'RTrustTunnel','8.8.8.8':'RTrustTunnel',LAN_HOST:None,'203.0.113.9':None}
        for ip,alias in expect.items():
            got=interface(ip)
            assert (got=='RTrustTunnel')==(alias=='RTrustTunnel'),(ip,got)
            print(f'PASS {ip} -> {got}')
        e2e.verify_traffic()
        assert pipe.request(dict(op='Status'))['state']=='Connected'
        assert pipe.request(dict(op='Stop'))['state']=='Idle'
    finally:
        pipe.close()
    for _ in range(60):
        if not tunnel_routes():break
        time.sleep(.25)
    else:raise AssertionError('Wintun routes remain')
    after=e2e.routes()
    assert sorted(set(before)-set(after))==[] and sorted(set(after)-set(before))==[],(set(before)^set(after))
    print('PASS routes restored exactly')
    proxy_checks()
    print('SPLIT AND PROXY E2E PASSED')
if __name__=='__main__':main()
