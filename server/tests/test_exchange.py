"""Real Rust codec + isolated SQLite; never opens a production profile/database."""
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SANDBOX = tempfile.TemporaryDirectory(prefix='rtrust-portal-tests-')
os.environ.update(DATA_DIR=SANDBOX.name, SECRET_KEY=secrets.token_urlsafe(48), ADMIN_PASSWORD=secrets.token_urlsafe(32), RTRUST_CODEC=str(ROOT/'target/debug/rtrust-codec'))
PORTAL = Path(os.environ.get('RTRUST_PORTAL_SRC', str(ROOT.parent/'tunnel/server/upstream')))
if not (PORTAL/'app').is_dir():
    raise SystemExit('Set RTRUST_PORTAL_SRC to server/upstream of a tunnel checkout (the portal source)')
sys.path.insert(0, str(PORTAL))
import app
app.__path__.append(str(ROOT/'server/overlay/app'))
from app import db, config, security, rtrust_profiles as exchange
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

class ExchangeTests(unittest.TestCase):
    def setUp(self):
        config.DB_PATH = str(Path(SANDBOX.name)/(secrets.token_hex(8)+'.db'))
        db.init_db(); exchange.init()
        self.owner = db.create_user('owner@example.invalid', 'unused')
        self.other = db.create_user('other@example.invalid', 'unused')
        exchange.templates = Jinja2Templates(directory=str(ROOT/'server/overlay/app/templates'))
        api = FastAPI(); exchange.install(api)
        api.mount('/static', StaticFiles(directory=ROOT/'server/overlay/app/static'), name='static')
        self.client = TestClient(api)
        self.login(self.owner)
        self.content = (ROOT/'examples/demo.endpoint.toml').read_text()

    def login(self, owner):
        cookie = security.create_session_token(str(owner), 'user')
        self.client.cookies.set('user_token', cookie)
        self.headers = {'x-csrf-token': hmac.new(config.SECRET_KEY.encode(), ('rtrust-csrf:'+cookie).encode(), hashlib.sha256).hexdigest()}

    def post(self, path, data):
        return self.client.post('/portal/v2/'+path, json=data, headers=self.headers)

    def preview(self):
        response = self.post('profile-imports/preview', {'content':self.content,'intent':'external_stored'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn('content', response.json())
        return response.json()['preview_id']

    def imported(self):
        preview = self.preview()
        response = self.post('profile-imports/'+preview+'/commit', {'action':'create','consent':True})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_page_and_assets_have_real_routes(self):
        response=self.client.get('/profiles')
        self.assertEqual(response.status_code,200,response.text)
        self.assertIn('csrf-token',response.text)
        self.assertIn('rtrust-profiles.js',response.text)
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertEqual(self.client.get('/static/rtrust-profiles.js').status_code,200)
        self.assertEqual(self.client.get('/static/rtrust-profiles.css').status_code,200)
        self.client.cookies.clear()
        self.assertEqual(self.client.get('/profiles',follow_redirects=False).status_code,302)

    def test_roundtrip_encryption_and_idempotency(self):
        preview = self.preview()
        body = {'action':'create','consent':True}
        first = self.post('profile-imports/'+preview+'/commit', body)
        second = self.post('profile-imports/'+preview+'/commit', body)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json(),second.json())
        item = first.json()
        response = self.post('profiles/'+item['id']+'/export', {'format':'profile_json','revision':item['revision'],'include_secrets':True})
        self.assertEqual(response.status_code,200,response.text)
        exported = response.json()['content']
        with db.connect() as c:
            stored = c.execute('SELECT payload FROM rtrust_profiles').fetchone()[0]
            self.assertNotIn(exported.encode(),stored)
            self.assertEqual(exchange.unseal(self.owner,stored),exported)
            with self.assertRaises(Exception): exchange.unseal(self.other,stored)
        self.assertEqual(self.post('profiles/'+item['id']+'/export', {'revision':'wrong','include_secrets':True}).status_code,409)
        self.assertEqual(self.post('profiles/'+item['id']+'/export', {'revision':'1'}).status_code,422)

    def test_owner_isolation_and_csrf(self):
        item = self.imported(); preview=self.preview()
        denied = self.client.post('/portal/v2/enrollment-codes')
        self.assertEqual(denied.status_code,403)
        self.assertEqual(denied.headers['cache-control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", denied.headers['content-security-policy'])
        self.login(self.other)
        self.assertEqual(self.client.get('/portal/v2/profiles').json()['profiles'],[])
        self.assertEqual(self.post('profiles/'+item['id']+'/export', {'revision':'1','include_secrets':True}).status_code,404)
        self.assertEqual(self.post('profile-imports/'+preview+'/commit', {'action':'create','consent':True}).status_code,404)

    def test_device_grants_revocation_and_code_reuse(self):
        item=self.imported()
        code=self.post('enrollment-codes',{}).json()['code']
        data={'code':code,'name':'CI device','platform':'windows'}
        registered=self.post('enroll',data)
        self.assertEqual(registered.status_code,200,registered.text)
        device=registered.json()
        self.assertEqual(self.post('enroll',data).status_code,401)
        auth={'Authorization':'Bearer '+device['token']}
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).json()['profiles'],[])
        self.assertEqual(self.post('profiles/'+item['id']+'/grants', {'device_id':device['device_id'],'allow':True}).status_code,200)
        self.assertEqual(len(self.client.get('/portal/v2/profiles',headers=auth).json()['profiles']),1)
        revoked=self.client.delete('/portal/v2/devices/'+str(device['device_id']),headers=self.headers)
        self.assertEqual(revoked.status_code,200,revoked.text)
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).status_code,401)
        self.assertEqual(self.client.get('/portal/v2/profiles',headers={'Authorization':'Bearer invalid'}).status_code,401)

    def test_replace_revision_and_expired_preview(self):
        item=self.imported(); first=self.preview(); stale=self.preview()
        data={'action':'replace','target_id':item['id'],'base_revision':'1','consent':True}
        result=self.post('profile-imports/'+first+'/commit',data)
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['revision'],'2')
        self.assertEqual(self.post('profile-imports/'+stale+'/commit',data).status_code,409)
        expired=self.preview()
        with db.connect() as c:c.execute('UPDATE rtrust_imports SET expires=0 WHERE id=?',(expired,))
        self.assertEqual(self.post('profile-imports/'+expired+'/commit',{'action':'create','consent':True}).status_code,410)

    def test_managed_profile_uses_codec_and_cannot_be_replaced(self):
        with db.connect() as c:
            c.execute("UPDATE settings SET value='endpoint.example.invalid' WHERE key='panel_domain'")
            identifier=c.execute('INSERT INTO configs(user_id,tt_username,tt_password,label) VALUES(?,?,?,?)',(self.owner,'fixture-user',secrets.token_urlsafe(24),'Managed fixture')).lastrowid
        items=self.client.get('/portal/v2/profiles')
        self.assertEqual(items.status_code,200,items.text)
        item=items.json()['profiles'][0]
        self.assertEqual(item['id'],'managed-'+str(identifier))
        self.assertEqual(item['summary']['hostname'],'endpoint.example.invalid')
        for fmt in ['profile_json','endpoint_toml','cli_toml','tt']:
            response=self.post('profiles/'+item['id']+'/export',{'revision':item['revision'],'include_secrets':True,'format':fmt,'accept_losses':True})
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(exchange.codec(response.json()['content'])['summary']['hostname'],'endpoint.example.invalid')
        preview=self.preview()
        self.assertEqual(self.post('profile-imports/'+preview+'/commit',{'action':'replace','target_id':item['id'],'base_revision':item['revision'],'consent':True}).status_code,403)

    def test_invalid_import_cannot_commit_and_body_limit(self):
        self.assertEqual(self.post('profile-imports/preview', {'content':'not a profile','intent':'external_stored'}).status_code,422)
        self.assertEqual(self.post('profile-imports/preview', {'content':'x'*(exchange.LIMIT+1),'intent':'external_stored'}).status_code,413)
        self.assertEqual(self.post('profile-imports/preview', {'content':self.content,'intent':'provision'}).status_code,422)
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_profiles').fetchone()[0],0)

if __name__=='__main__': unittest.main()
