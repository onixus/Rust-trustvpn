"""Authorized physical Windows sleep/wake E2E with a production profile.

Run through windows_authorized_full.py --worker windows_sleep_e2e.py --sleep-minutes N.
Keeps a full-tunnel session (or, with --always-on, the service-owned always-on
tunnel) across S3 sleep, then checks that the WFP guard held, the service
reconnected on its own and traffic flows. A resume-capable waitable
timer wakes the host; the System event log proves that it actually slept.
The fixture JSON (never committed) holds "profiles" like windows_production_e2e.py
and "sleep_minutes" from the runner.
"""
import ctypes, json, os, pathlib, socket, struct, subprocess, sys, time, urllib.request
from ctypes import wintypes
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import windows_service_e2e as fixture
ROOT = pathlib.Path(__file__).resolve().parent
SERVICE = pathlib.Path(os.environ['ProgramFiles']) / 'RTrustTunnel Service/rtrust-service.exe'
K = ctypes.WinDLL('kernel32', use_last_error=True)
K.CreateWaitableTimerW.restype = wintypes.HANDLE
K.SetThreadExecutionState.restype = wintypes.DWORD
POWER = ctypes.WinDLL('powrprof', use_last_error=True)
ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
pipe = None
before = fixture.routes()

def log(message):
    print(time.strftime('%H:%M:%S ') + message, flush=True)

def blocked(host, port):
    try:
        with socket.create_connection((host, port), timeout=2): pass
    except OSError: return
    raise AssertionError('Application escaped WFP endpoint protection')

def traffic(label):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url, status in [('https://www.google.com/generate_204', 204), ('https://example.com/', 200), ('https://api.ipify.org/', 200)]:
        with opener.open(url, timeout=25) as r:
            assert r.status == status, (label, url, r.status)
            data = r.read(65536)
            if 'ipify' in url: log(label + ' egress: ' + data.decode().strip())
    tx = os.urandom(2); question = b''.join(bytes([len(s)]) + s.encode() for s in 'www.google.com'.split('.')) + b'\0' + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(15); udp.sendto(tx + struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0) + question, ('1.1.1.1', 53))
        response, peer = udp.recvfrom(4096)
        assert peer == ('1.1.1.1', 53) and response[:2] == tx and struct.unpack('!H', response[6:8])[0] > 0
    log('PASS ' + label + ': TLS Google/example, egress and UDP DNS through the tunnel')

def status():
    return pipe.request(dict(op='Status'))['state']

def sleep_for(minutes):
    """Suspends to S3 and returns after the resume timer fires."""
    timer = K.CreateWaitableTimerW(None, True, None)
    assert timer, ctypes.WinError(ctypes.get_last_error())
    due = ctypes.c_longlong(-int(minutes * 60 * 10_000_000))
    assert K.SetWaitableTimer(timer, ctypes.byref(due), 0, None, None, True), ctypes.WinError(ctypes.get_last_error())
    # ERROR_NOT_SUPPORTED: the timer is set but cannot wake the machine.
    assert ctypes.get_last_error() != 50, 'Resume timers are not supported on this host'
    K.SetThreadExecutionState(ES_CONTINUOUS)
    started = time.time()
    log(f'Suspending for {minutes} minutes')
    if not POWER.SetSuspendState(False, False, False):
        raise ctypes.WinError(ctypes.get_last_error())
    K.WaitForSingleObject(timer, (minutes + 10) * 60 * 1000)
    # An unattended timer wake would otherwise sleep again after ~2 minutes.
    K.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
    K.CloseHandle(timer)
    elapsed = time.time() - started
    # Windows records the wake event a few seconds after resume; only an event
    # written after this resume counts, never one from an earlier sleep.
    events = ''
    for _ in range(24):
        events = fixture.ps(f"try {{ Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='Microsoft-Windows-Power-Troubleshooter';Id=1;StartTime=(Get-Date).AddSeconds(-180)}} -MaxEvents 1 | Select-Object -ExpandProperty Message }} catch {{ '' }}")
        if events: break
        time.sleep(5)
    log(f'Resumed after {elapsed / 60:.1f} minutes: ' + ' '.join(events.split())[:300])
    assert elapsed >= minutes * 60 - 30, f'Woke too early after {elapsed:.0f} s'
    assert events, 'No Power-Troubleshooter wake event: the host did not sleep'

def compare_routes(after, label, endpoint):
    """Sleep can renew DHCP or IPv6 routes. Only service-owned leftovers fail."""
    gone, added = sorted(set(before) - set(after)), sorted(set(after) - set(before))
    if not gone and not added: return
    for route in gone: log(label + ' route missing: ' + route)
    for route in added: log(label + ' route added: ' + route)
    wintun = fixture.ps("@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object InterfaceDescription -match 'Wintun' | Select-Object -ExpandProperty ifIndex) -join ','")
    owned = {i for i in wintun.split(',') if i}
    def service(route):
        prefix, index, _, metric = route.split('|')
        return (metric == '21076' or index in owned or prefix in ('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')
                or prefix == endpoint + '/32')
    leaked = [r for r in gone + added if service(r)]
    assert not leaked, label + ' left service routes: ' + str(leaked)
    log(label + ': only non-service routes changed across sleep')

def ipc(op, **values):
    p = fixture.Pipe()
    try: return p.request(dict(op=op, **values))
    finally: p.close()

def always_on_connected(host, canary, label):
    """Polls the service-owned always-on state; the guard must hold throughout."""
    states = []; until = time.monotonic() + 180
    while time.monotonic() < until:
        state = ipc('AlwaysOnStatus')['state']
        if not states or states[-1] != state: states.append(state); log(label + ' always-on state: ' + state)
        if state == 'Connected': return states
        assert state in ('Blocked', 'Connecting', 'Reconnecting'), state
        blocked(host, canary); time.sleep(1)
    raise AssertionError(states)

def always_on(profile, host, canary, minutes):
    """Always-on survives sleep without any client session or lease."""
    response = ipc('EnableAlwaysOn', profile=profile, dns='1.1.1.1')
    assert response['state'] in ('Blocked', 'Connected'), response
    always_on_connected(host, canary, 'Before sleep')
    traffic('always-on before sleep'); blocked(host, canary)
    sleep_for(minutes)
    blocked(host, canary)
    states = always_on_connected(host, canary, 'After wake')
    traffic('always-on after sleep'); blocked(host, canary)
    response = ipc('DisableAlwaysOn'); assert response['state'] == 'Idle', response
    compare_routes(fixture.routes(), 'Always-on disabled', socket.gethostbyname(host))
    with socket.create_connection((host, canary), timeout=10): pass
    return states

def main():
    global pipe
    minutes = int(fixture.FIXTURE['sleep_minutes'])
    profile = next(p for p in fixture.FIXTURE['profiles'] if p.get('protocol') == 'hysteria2')
    # Probe by IP, resolved before the guard: a hostname would fail DNS while the
    # tunnel is down and make blocked() pass without WFP doing anything.
    host = socket.gethostbyname(profile['endpoint']['addresses'][0].rsplit(':', 1)[0])
    canary = 8443
    with socket.create_connection((host, canary), timeout=10): pass
    if fixture.FIXTURE.get('sleep_always_on'):
        return always_on(dict(profile, name='Always-on sleep E2E'), host, canary, minutes)
    pipe = fixture.Pipe(); answer = pipe.request(dict(op='StartFull', profile=profile, dns='1.1.1.1'))
    assert answer['state'] == 'Connected', answer
    traffic('before sleep'); blocked(host, canary)
    sleep_for(minutes)
    # The guard must already hold before the tunnel recovers.
    blocked(host, canary)
    states = []; until = time.monotonic() + 180
    while time.monotonic() < until:
        state = status()
        if not states or states[-1] != state: states.append(state); log('State after wake: ' + state)
        if state == 'Connected': break
        assert state in ('Connected', 'Connecting', 'Reconnecting', 'Blocked'), state
        blocked(host, canary); time.sleep(1)
    assert states[-1] == 'Connected', states
    traffic('after sleep'); blocked(host, canary)
    # Let the service finish releasing the session lease, as the production worker does.
    pipe.close(); pipe = None; time.sleep(2)
    p = fixture.Pipe(); response = p.request(dict(op='Recover')); p.close()
    assert response['state'] == 'Idle', response
    compare_routes(fixture.routes(), 'Recovered', socket.gethostbyname(host))
    with socket.create_connection((host, canary), timeout=10): pass
    return states

result = {'success': False}
try:
    result = {'success': True, 'states_after_wake': main()}
except Exception as e:
    import traceback; traceback.print_exc(); result = {'success': False, 'error': str(e)}
finally:
    if pipe is not None: pipe.close()
    try:
        fixture.ps("Stop-Service RTrustTunnel -ErrorAction SilentlyContinue; (Get-Service RTrustTunnel).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(25))")
        subprocess.run([str(SERVICE), '--disable-always-on'], check=True, timeout=45)
        fixture.ps('Start-Service RTrustTunnel')
    except Exception as e: result = {'success': False, 'error': 'Recovery failed: ' + str(e)}
    (ROOT / 'result.json').write_text(json.dumps(result)); print(json.dumps(result), flush=True)
if not result['success']: raise SystemExit(1)
