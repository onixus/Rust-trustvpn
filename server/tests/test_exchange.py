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
TARGET = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT/'target')))
SANDBOX = tempfile.TemporaryDirectory(prefix='rtrust-portal-tests-')
os.environ.update(DATA_DIR=SANDBOX.name, SECRET_KEY=secrets.token_urlsafe(48), ADMIN_PASSWORD=secrets.token_urlsafe(32), RTRUST_CODEC=str(TARGET/'debug/rtrust-codec'))
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

    def test_ios_enrollment_is_accepted(self):
        code = self.post('enrollment-codes', {}).json()['code']
        response = self.post('enroll', {'code': code, 'name': 'iPhone fixture', 'platform': 'ios'})
        self.assertEqual(response.status_code, 200, response.text)
        devices = self.client.get('/portal/v2/devices').json()['devices']
        self.assertEqual(devices[0]['platform'], 'ios')

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

    def enrolled(self, name='Route device'):
        code=self.post('enrollment-codes',{}).json()['code']
        response=self.post('enroll',{'code':code,'name':name,'platform':'linux'})
        self.assertEqual(response.status_code,200,response.text)
        return response.json()['device_id'],{'Authorization':'Bearer '+response.json()['token']}

    def group(self, **extra):
        data={'name':'Офис','include':['10.0.0.0/8','192.168.10.0/24'],'exclude':['10.1.0.0/16'],'exclude_lan':True,**extra}
        response=self.post('route-groups',data)
        self.assertEqual(response.status_code,200,response.text)
        return response.json()

    def test_route_group_crud_and_validation(self):
        self.assertEqual(self.client.get('/portal/v2/capabilities').json()['routing'],1)
        self.assertEqual(self.client.get('/portal/v2/route-groups').json(),{'groups':[]})
        created=self.group(include=['10.0.0.0/8',' 10.0.0.0/255.0.0.0 ','0.0.0.0/0'])
        self.assertEqual(created,{'id':created['id'],'name':'Офис','include':['10.0.0.0/8','0.0.0.0/0'],'exclude':['10.1.0.0/16'],'exclude_lan':True,'revision':1,'devices':[]})
        self.assertEqual(self.client.get('/portal/v2/route-groups').json()['groups'],[created])
        base={'name':'x','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':False}
        for bad in [{'include':['10.0.0.1/8']},{'include':['10.0.0.0/33']},{'include':['fd00::/8']},{'include':['10.0.0.0']},{'include':[]},{'include':'10.0.0.0/8'},
                    {'include':[f'10.{i}.0.0/16' for i in range(17)]},{'exclude':[f'10.{i}.0.0/16' for i in range(65)]},{'exclude':[167772160]},
                    {'exclude_lan':1},{'name':''},{'name':'x'*81},{'name':'a\nb'},{'unknown':True}]:
            self.assertEqual(self.post('route-groups',{**base,**bad}).status_code,422,bad)
        self.assertEqual(self.post('route-groups',{k:v for k,v in base.items() if k!='exclude'}).status_code,422)
        self.assertEqual(self.post('route-groups',{**base,'include':[f'10.{i}.0.0/16' for i in range(16)],'exclude':[f'11.{i}.0.0/16' for i in range(64)]}).status_code,200)
        path='/portal/v2/route-groups/'+str(created['id'])
        updated=self.client.put(path,json={**base,'name':'Склад','revision':1},headers=self.headers)
        self.assertEqual(updated.status_code,200,updated.text)
        self.assertEqual((updated.json()['name'],updated.json()['revision'],updated.json()['include']),('Склад',2,['10.0.0.0/8']))
        self.assertEqual(self.client.put(path,json={**base,'revision':1},headers=self.headers).status_code,409)
        self.assertEqual(self.client.put(path,json={**base,'revision':'2'},headers=self.headers).status_code,422)
        self.assertEqual(self.client.put(path,json={**base,'revision':2,'extra':1},headers=self.headers).status_code,422)
        self.assertEqual(self.client.put('/portal/v2/route-groups/999999',json={**base,'revision':1},headers=self.headers).status_code,404)
        self.assertEqual(self.client.delete(path,headers=self.headers).status_code,409)
        self.assertEqual(self.client.delete(path,headers={**self.headers,'If-Match':'1'}).status_code,409)
        self.assertEqual(self.client.delete(path,headers={**self.headers,'If-Match':'2'}).status_code,200)
        self.assertEqual(len(self.client.get('/portal/v2/route-groups').json()['groups']),1)
        with db.connect() as c:
            actions=[r[0] for r in c.execute("SELECT action FROM rtrust_audit WHERE action LIKE 'route_%' ORDER BY id")]
        self.assertEqual(actions,['route_group_create','route_group_create','route_group_update','route_group_delete'])

    def test_route_group_limit_and_csrf(self):
        data={'name':'g','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':False}
        self.assertEqual(self.client.post('/portal/v2/route-groups',json=data).status_code,403)
        self.assertEqual(self.client.post('/portal/v2/route-groups',json=data,headers={'x-csrf-token':'0'*64}).status_code,403)
        created=self.group()
        path='/portal/v2/route-groups/'+str(created['id'])
        self.assertEqual(self.client.put(path,json={**data,'revision':1}).status_code,403)
        self.assertEqual(self.client.delete(path,headers={'If-Match':'1'}).status_code,403)
        self.assertEqual(self.client.post(path+'/members',json={'device_id':1,'member':True}).status_code,403)
        with db.connect() as c:
            for i in range(49):c.execute('INSERT INTO rtrust_route_groups(owner,name,policy,revision) VALUES(?,?,?,1)',(self.owner,'g'+str(i),'{"include":["10.0.0.0/8"],"exclude":[],"exclude_lan":false}'))
        self.assertEqual(self.post('route-groups',data).status_code,409)
        self.login(self.other)
        self.assertEqual(self.post('route-groups',data).status_code,200)

    def test_route_group_owner_isolation(self):
        created=self.group();device,_=self.enrolled()
        path='/portal/v2/route-groups/'+str(created['id'])
        self.login(self.other)
        own=self.group(name='Чужая');other_device,_=self.enrolled('Other device')
        self.assertEqual([g['id'] for g in self.client.get('/portal/v2/route-groups').json()['groups']],[own['id']])
        data={'name':'x','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':False,'revision':1}
        self.assertEqual(self.client.put(path,json=data,headers=self.headers).status_code,404)
        self.assertEqual(self.client.delete(path,headers={**self.headers,'If-Match':'1'}).status_code,404)
        self.assertEqual(self.post('route-groups/'+str(created['id'])+'/members',{'device_id':other_device,'member':True}).status_code,404)
        self.assertEqual(self.post('route-groups/'+str(own['id'])+'/members',{'device_id':device,'member':True}).status_code,404)
        self.login(self.owner)
        self.assertEqual(self.post('route-groups/'+str(created['id'])+'/members',{'device_id':other_device,'member':True}).status_code,404)
        self.assertEqual(self.client.get('/portal/v2/route-groups').json()['groups'],[created])

    def test_device_routing_policy_membership(self):
        first=self.group();second=self.group(name='Дом',include=['0.0.0.0/0'],exclude=[],exclude_lan=False)
        device,auth=self.enrolled()
        self.assertEqual(self.client.get('/portal/v2/routing').status_code,403)
        self.assertEqual(self.client.get('/portal/v2/routing',headers={'Authorization':'Bearer invalid'}).status_code,401)
        response=self.client.get('/portal/v2/routing',headers=auth)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json(),{'policy':None})
        self.assertEqual(response.headers['cache-control'],'no-store')
        for method,path in [('GET','route-groups'),('POST','route-groups'),('PUT','route-groups/'+str(first['id'])),('DELETE','route-groups/'+str(first['id'])),('POST','route-groups/'+str(first['id'])+'/members')]:
            self.assertEqual(self.client.request(method,'/portal/v2/'+path,json={'device_id':device,'member':True},headers={**auth,'If-Match':'1'}).status_code,403,path)
        members='route-groups/'+str(first['id'])+'/members'
        for bad in [{'device_id':str(device),'member':True},{'device_id':device,'member':1},{'device_id':device},{'device_id':device,'member':True,'x':1}]:
            self.assertEqual(self.post(members,bad).status_code,422,bad)
        self.assertEqual(self.post(members,{'device_id':999999,'member':True}).status_code,404)
        added=self.post(members,{'device_id':device,'member':True})
        self.assertEqual(added.status_code,200,added.text)
        self.assertEqual(added.json()['devices'],[device])
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json(),{'policy':{'group':'Офис','revision':str(first['id'])+':1','include':['10.0.0.0/8','192.168.10.0/24'],'exclude':['10.1.0.0/16'],'exclude_lan':True}})
        self.client.put('/portal/v2/route-groups/'+str(first['id']),json={'name':'Офис','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':True,'revision':1},headers=self.headers)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy']['revision'],str(first['id'])+':2')
        moved=self.post('route-groups/'+str(second['id'])+'/members',{'device_id':device,'member':True})
        self.assertEqual(moved.json()['devices'],[device])
        groups={g['id']:g['devices'] for g in self.client.get('/portal/v2/route-groups').json()['groups']}
        self.assertEqual(groups,{first['id']:[],second['id']:[device]})
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy'],{'group':'Дом','revision':str(second['id'])+':1','include':['0.0.0.0/0'],'exclude':[],'exclude_lan':False})
        self.assertEqual(self.post(members,{'device_id':device,'member':False}).status_code,200)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy']['group'],'Дом')
        self.assertEqual(self.post('route-groups/'+str(second['id'])+'/members',{'device_id':device,'member':False}).json()['devices'],[])
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json(),{'policy':None})
        self.post(members,{'device_id':device,'member':True})
        self.assertEqual(self.client.delete('/portal/v2/devices/'+str(device),headers=self.headers).status_code,200)
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_route_members').fetchone()[0],0)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).status_code,401)
        self.assertEqual(self.post(members,{'device_id':device,'member':True}).status_code,404)
        latest=self.client.get('/portal/v2/route-groups').json()['groups'][0]
        self.assertEqual(self.client.delete('/portal/v2/route-groups/'+str(first['id']),headers={**self.headers,'If-Match':str(latest['revision'])}).status_code,200)

    def test_deleting_group_clears_device_policy(self):
        created=self.group();device,auth=self.enrolled()
        self.post('route-groups/'+str(created['id'])+'/members',{'device_id':device,'member':True})
        self.assertEqual(self.client.delete('/portal/v2/route-groups/'+str(created['id']),headers={**self.headers,'If-Match':'1'}).status_code,200)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json(),{'policy':None})
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_route_members').fetchone()[0],0)

if __name__=='__main__': unittest.main()
