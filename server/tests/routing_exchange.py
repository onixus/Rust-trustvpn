"""Owner UI API -> device assignment -> real Rust client, through verified HTTPS."""
import json
import pathlib
import select
import socket
import subprocess
import threading
import time

from test_exchange import ExchangeTests, ROOT, SANDBOX, TARGET
import uvicorn

case = ExchangeTests()
case.setUp()
with case.client:
    work = pathlib.Path(SANDBOX.name)
    cert, key = work / 'routes.pem', work / 'routes.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(case.client.app, host='127.0.0.1', port=port,
                            ssl_certfile=str(cert), ssl_keyfile=str(key), access_log=False, log_level='error'))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    process = None
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(.05)
        assert server.started
        fixture = work / 'route-fixture.json'
        fixture.write_text(json.dumps({'url': f'https://localhost:{port}', 'ca': cert.read_text(),
                            'code': case.post('enrollment-codes', {}).json()['code']}))
        fixture.chmod(0o600)
        process = subprocess.Popen([str(TARGET / 'debug/examples/routing_e2e'), str(fixture)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

        def wait(expected):
            assert select.select([process.stdout], [], [], 30)[0], 'Rust client timed out'
            assert process.stdout.readline().strip() == expected, 'Rust publication check failed'

        def check(expected):
            process.stdin.write(json.dumps(expected) + '\n')
            process.stdin.flush()
            wait('checked')

        wait('ready')
        device = case.client.get('/portal/v2/devices').json()['devices'][0]['id']
        check(None)
        group = case.group(include=['0.0.0.0/0'], exclude=['10.1.0.0/16'], exclude_lan=True)

        def publish(group):
            result = case.post('route-groups/' + str(group['id']) + '/members', {'device_id': device, 'member': True})
            assert result.status_code == 200, result.text

        def policy(group):
            return {'group': group['name'], 'revision': f"{group['id']}:{group['revision']}",
                    **{k: group[k] for k in ('include', 'exclude', 'exclude_lan')}}

        publish(group)
        check(policy(group))
        path = '/portal/v2/route-groups/' + str(group['id'])
        update = {'name': 'Updated office', 'include': ['192.0.2.0/24'], 'exclude': [],
                  'exclude_lan': False, 'revision': group['revision']}
        response = case.client.put(path, json=update, headers=case.headers)
        assert response.status_code == 200, response.text
        updated = response.json()
        check(policy(updated))
        assert case.client.put(path, json=update, headers=case.headers).status_code == 409
        check(policy(updated))
        second = case.group(name='Second group', include=['198.51.100.0/24'], exclude=[], exclude_lan=False)
        publish(second)
        check(policy(second))
        response = case.client.delete('/portal/v2/route-groups/' + str(second['id']),
                                      headers={**case.headers, 'If-Match': str(second['revision'])})
        assert response.status_code == 200, response.text
        check(None)
        publish(updated)
        check(policy(updated))
        assert case.client.delete('/portal/v2/devices/' + str(device), headers=case.headers).status_code == 200
        check({'error': True})
        process.stdin.close()
        assert process.wait(timeout=10) == 0
        print('PASS route publication: assign, edit, stale revision, move, delete, reassign, revoke; real Rust client over TLS')
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        server.should_exit = True
        thread.join(10)
