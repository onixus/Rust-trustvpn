"""Real Rust portal client against the real FastAPI overlay over verified TLS."""
import json,os,pathlib,socket,subprocess,threading,time
from test_exchange import ExchangeTests,ROOT,SANDBOX
import uvicorn
case=ExchangeTests();case.setUp()
with case.client:
    response=case.post('enrollment-codes',{})
    assert response.status_code==200
    work=pathlib.Path(SANDBOX.name)
    cert=work/'tls.pem';key=work/'tls.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    config=uvicorn.Config(case.client.app,host='127.0.0.1',port=port,ssl_certfile=str(cert),ssl_keyfile=str(key),access_log=False,log_level='error')
    server=uvicorn.Server(config);thread=threading.Thread(target=server.run,daemon=True);thread.start()
    try:
        for _ in range(100):
            if server.started:break
            time.sleep(.05)
        assert server.started
        manifest=work/'fixture.json';manifest.write_text(json.dumps({'private_ca':True,'url':f'https://localhost:{port}','code':response.json()['code'],'ca':cert.read_text(),'profile':case.content}));manifest.chmod(0o600)
        binary=ROOT/'target/debug/examples'/('portal_e2e.exe' if os.name=='nt' else 'portal_e2e')
        subprocess.run([str(binary),str(manifest)],check=True,timeout=60)
    finally:
        server.should_exit=True;thread.join(10)
