"""Rollback-guarded selected-route acceptance on an idle installed Windows service.
Run only through windows_authorized_full.py --worker windows_selected_e2e.py.
Uses disposable endpoint credentials; leaves production profiles untouched.
"""
import json, os, pathlib, socket, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import windows_service_e2e as fixture
ROOT = pathlib.Path(__file__).resolve().parent
pipe = None
before = fixture.routes()

def dns_state():
    return json.loads(fixture.ps("ConvertTo-Json -Compress -InputObject @(Get-DnsClientServerAddress | ForEach-Object { '{0}|{1}|{2}' -f $_.InterfaceIndex,$_.AddressFamily,($_.ServerAddresses -join ',') } | Sort-Object)"))

original_dns = dns_state()

def interface(ip):
    return fixture.ps(f"(Find-NetRoute -RemoteIPAddress {ip} | Where-Object InterfaceAlias | Select-Object -First 1).InterfaceAlias")

def main():
    global pipe
    profile = dict(schema_version=1, name='Selected acceptance', endpoint=fixture.FIXTURE['base'])
    pipe = fixture.Pipe()
    response = pipe.request(dict(op='Start', profile=profile, networks=[fixture.NETWORK], dns=fixture.TARGET))
    assert response['state'] == 'Connected', response
    assert interface(fixture.TARGET) == 'RTrustTunnel'
    assert interface('1.1.1.1') != 'RTrustTunnel', 'Unselected destination captured'
    fixture.verify_traffic()
    assert socket.gethostbyname('rtrust-' + os.urandom(8).hex() + '.fixture.test') == fixture.TARGET
    print('PASS selected route, unselected direct route, system DNS and real TCP/UDP', flush=True)
    fixture.control('pause')
    fixture.wait_state(pipe, 'Blocked', timeout=90)
    assert interface(fixture.TARGET) == 'RTrustTunnel', 'Outage released selected route'
    try:
        fixture.http()
    except (OSError, TimeoutError):
        pass
    else:
        raise AssertionError('Traffic succeeded during endpoint outage')
    fixture.control('resume')
    fixture.wait_state(pipe, 'Connected', timeout=90)
    fixture.verify_traffic()
    print('PASS selected endpoint outage, retained route and automatic recovery', flush=True)
    assert pipe.request(dict(op='Stop'))['state'] == 'Idle'
    pipe.close(); pipe = None
    assert fixture.routes() == before, 'Selected Stop changed baseline routes'
    assert dns_state() == original_dns, 'Selected Stop changed baseline DNS'
    print('PASS selected Stop restores exact route and DNS state', flush=True)

result = {'success': False}
try:
    main()
    result = {'success': True, 'mode': 'selected', 'protocol': fixture.FIXTURE['base']['upstream_protocol']}
except Exception as error:
    import traceback
    traceback.print_exc()
    result = {'success': False, 'error': str(error)}
finally:
    try:
        fixture.control('resume')
        if pipe is not None:
            response = pipe.request(dict(op='Stop'))
            assert response['state'] == 'Idle', response
    except Exception as error:
        result = {'success': False, 'error': 'Selected cleanup failed: ' + str(error)}
    finally:
        if pipe is not None:
            pipe.close()
    (ROOT / 'result.json').write_text(json.dumps(result))
    print(json.dumps(result), flush=True)
if not result['success']:
    raise SystemExit(1)
