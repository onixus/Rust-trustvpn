"""Isolated identities, real SQLite, fake transport. Never sends messages or touches live VPNs."""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
TMP=tempfile.TemporaryDirectory(prefix='vpn-console-tests-')
os.environ.update(DATA_DIR=TMP.name,SECRET_KEY=secrets.token_hex(32),ADMIN_PASSWORD=secrets.token_hex(24),CONSOLE_DATA=TMP.name+'/console')
sys.path.insert(0,str(ROOT/'server/upstream')); sys.path.insert(0,str(ROOT/'server/console'))
import app
app.__path__.append(str(ROOT/'server/overlay/app'))
os.environ['RTRUST_CODEC']=str(ROOT/'target/debug/rtrust-codec')
from app import db,config,security
import console_app as ui
import agent
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

class ConsoleTests(unittest.TestCase):
    def setUp(self):
        ui.STATE=Path(TMP.name)/secrets.token_hex(8); ui.init()
        config.DB_PATH=str(Path(TMP.name)/(secrets.token_hex(8)+'.db'));db.init_db()
        self.client=TestClient(ui.app)
        with db.connect() as c:self.admin=c.execute('SELECT id FROM admins LIMIT 1').fetchone()[0]
        self.cookie=security.create_session_token(str(self.admin),'admin');self.client.cookies.set('admin_token',self.cookie)
        self.csrf=hmac.new(config.SECRET_KEY.encode(),('console:'+self.cookie).encode(),hashlib.sha256).hexdigest()
        self.user=db.create_user('test@example.invalid','unused')
        self.mock=patch.object(ui,'agent',return_value={'hysteria_users':[],'routing':{'selected':'reserve'}});self.mock.start();self.addCleanup(self.mock.stop)
    def post(self,path,data):return self.client.post('/console/api/'+path,json=data,headers={'X-CSRF-Token':self.csrf})
    def job(self,action,data,key=None):return self.post('jobs',{'action':action,'data':data,'confirm':True,'request_id':key or secrets.token_hex(16)})
    def test_auth_csrf_origin_and_redaction(self):
        db.create_config(self.user,'test-key','secret-not-in-state','test')
        s=self.client.get('/console/api/state');self.assertEqual(s.status_code,200);self.assertNotIn('secret-not-in-state',s.text);self.assertNotIn('password_hash',s.text)
        self.assertEqual(s.headers['cache-control'],'no-store')
        self.assertEqual(self.client.post('/console/api/jobs',json={}).status_code,403)
        self.assertEqual(self.client.post('/console/api/jobs',json={},headers={'X-CSRF-Token':self.csrf,'Origin':'https://evil.invalid'}).status_code,403)
        self.client.cookies.clear();self.assertEqual(self.client.get('/console/api/state').status_code,401)
        self.client.cookies.set('admin_token',security.create_session_token(str(self.user),'user'));self.assertEqual(self.client.get('/console/api/state').status_code,401)
    def test_real_templates_assets_and_logout_state(self):
        r=self.client.get('/console');self.assertEqual(r.status_code,200);self.assertIn('csrf-token',r.text)
        for asset in ['console.css','console.js','icon.svg']:self.assertEqual(self.client.get('/console/static/'+asset).status_code,200)
        self.client.cookies.clear();self.assertEqual(self.client.get('/console',follow_redirects=False).headers['location'],'/admin/login')
    def test_job_idempotence_and_no_automatic_replay(self):
        key=secrets.token_hex(16);data={'id':self.user}
        self.assertEqual(self.job('trusttunnel.block',data,key).status_code,200)
        self.assertEqual(self.job('trusttunnel.block',data,key).status_code,200)
        self.assertEqual(self.job('trusttunnel.unblock',data,key).status_code,409)
        with patch.object(ui,'perform',return_value={'message':'done'}) as perform:
            self.assertTrue(ui.work_once());self.assertFalse(ui.work_once());perform.assert_called_once()
        with ui.connect() as c:c.execute("UPDATE jobs SET state='running'")
        ui.init()
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM jobs').fetchone()[0],'unknown')
        self.assertFalse(ui.work_once())
    def test_deleted_admin_cannot_execute_queued_job(self):
        self.job('routes.check',{})
        with db.connect() as c:c.execute('DELETE FROM admins')
        with patch.object(ui,'perform') as p:ui.work_once();p.assert_not_called()
    def test_contact_consent_preview_no_send_and_single_delivery(self):
        self.assertEqual(self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':True}).status_code,200)
        payload={'channel':'email','subject':'Maintenance','body':'Hello','recipients':[{'source':'trusttunnel','id':self.user}]}
        with patch.object(ui.mailer,'send_mail') as send:
            draft=self.post('campaigns',payload);self.assertEqual(draft.status_code,200);send.assert_not_called()
            id=draft.json()['id'];self.assertEqual(self.job('campaign.send',{'id':id}).status_code,200)
            self.assertEqual(self.job('campaign.send',{'id':id}).status_code,409)
            ui.work_once();send.assert_called_once_with('test@example.invalid','Maintenance','Hello')
            self.assertEqual(self.job('campaign.send',{'id':id}).status_code,409)
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM deliveries').fetchone()[0],'accepted')
    def test_revoked_consent_and_failed_send_not_retried(self):
        self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':True})
        payload={'channel':'email','subject':'Maintenance','body':'Hello','recipients':[{'source':'trusttunnel','id':self.user}]}
        id=self.post('campaigns',payload).json()['id']
        self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':False})
        self.job('campaign.send',{'id':id})
        with patch.object(ui.mailer,'send_mail') as send:ui.work_once();send.assert_not_called()
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM deliveries').fetchone()[0],'skipped')
    def test_export_requires_consent_and_audits_without_secret(self):
        id=db.create_config(self.user,'test-key','only-in-export','test')
        self.assertEqual(self.post('export',{'source':'trusttunnel','id':id}).status_code,422)
        db.set_settings({'conn_address':'vpn.example.invalid','conn_port':'8443','panel_domain':'vpn.example.invalid'})
        r=self.post('export',{'source':'trusttunnel','id':id,'consent':True});self.assertEqual(r.status_code,200,r.text);self.assertTrue(r.json()['content'].startswith('tt://'))
        with ui.connect() as c:self.assertNotIn('only-in-export',str(c.execute('SELECT * FROM audit').fetchall()))
    def test_device_revocation_removes_only_its_keys(self):
        device=db.create_device(self.user,'test device',secrets.token_hex(32))
        key=db.create_device_config(self.user,device,'device-key','not-logged','device')
        other=db.create_config(self.user,'other-key','other-secret','other')
        self.assertEqual(self.job('trusttunnel.device-revoke',{'id':device}).status_code,200)
        with patch.object(ui,'legacy',return_value={'message':'reconciled'}):ui.work_once()
        self.assertTrue(db.get_device(device)['revoked_at'])
        self.assertTrue(db.get_config(key)['revoked_at'])
        self.assertIsNone(db.get_config(other)['revoked_at'])

    def test_create_retry_uses_canonical_payload_after_execution(self):
        key=secrets.token_hex(16)
        data={'username':'fixture-user'}
        first=self.job('hysteria.create',data,key)
        self.assertEqual(first.status_code,200)
        with patch.object(ui,'perform',return_value={'message':'created'}):ui.work_once()
        retry=self.job('hysteria.create',data,key)
        self.assertEqual(retry.status_code,200,retry.text)
        self.assertEqual(retry.json()['state'],'success')
        with ui.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM jobs').fetchone()[0],1)

    def test_campaign_does_not_borrow_another_identity_consent(self):
        other=db.create_user('another@example.invalid','unused')
        for id in (self.user,other):
            self.post('contacts',{'source':'trusttunnel','id':id,'email':'shared@example.invalid','consent':True})
        draft=self.post('campaigns',{'channel':'email','subject':'Maintenance','body':'Hello',
            'recipients':[{'source':'trusttunnel','id':self.user}]}).json()['id']
        self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'shared@example.invalid','consent':False})
        self.job('campaign.send',{'id':draft})
        with patch.object(ui.mailer,'send_mail') as send:ui.work_once();send.assert_not_called()
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM deliveries').fetchone()[0],'skipped')

    def test_pre_upgrade_draft_without_identity_bindings_is_not_sent(self):
        self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':True})
        draft=self.post('campaigns',{'channel':'email','subject':'Maintenance','body':'Hello',
            'recipients':[{'source':'trusttunnel','id':self.user}]}).json()['id']
        with ui.connect() as c:c.execute('DROP TABLE delivery_contacts')
        ui.init()
        self.job('campaign.send',{'id':draft})
        with patch.object(ui.mailer,'send_mail') as send:ui.work_once();send.assert_not_called()
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM deliveries').fetchone()[0],'skipped')

    def test_validation_rejects_injection_and_nonexistent_contacts(self):
        self.assertEqual(self.job('system.shell',{'cmd':'id'}).status_code,422)
        self.assertEqual(self.job('trusttunnel.block',{'id':'1/../../'}).status_code,422)
        self.assertEqual(self.job('hysteria.create',{'username':'x; touch /tmp/foo'}).status_code,422)
        self.assertEqual(self.post('contacts',{'source':'trusttunnel','id':999999,'email':'x@y.invalid'}).status_code,404)

class AgentTests(unittest.TestCase):
    def test_fixed_allowlist(self):
        with self.assertRaises(agent.Rejected):agent.dispatch('system.shell',{'command':'id'})
    def test_rules_preserve_grammar(self):
        self.assertEqual(agent.validate_rules([{'target':'reserve','kind':'suffix','value':'hostkey.ru'}]),[('reserve','suffix:hostkey.ru')])
        for rule in [{'target':'root','kind':'suffix','value':'x.ru'},{'target':'local','kind':'suffix','value':'ru)\nlocal(all)'},{'target':'reserve','kind':'cidr','value':'10.0.0.1/8'},{'target':'local','kind':'geoip','value':'private'}]:
            with self.assertRaises(agent.Rejected):agent.validate_rules([rule])
    def test_feed_signature_hash_and_downgrade(self):
        root=Path(TMP.name)/secrets.token_hex(8);root.mkdir();key=Ed25519PrivateKey.generate();pub=root/'root.pub';pub.write_bytes(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
        def release(seq,data=b'installer'):
            p=root/str(seq)/'windows-x86_64';p.mkdir(parents=True);(p/'setup.exe').write_bytes(data)
            m={'schema':1,'sequence':seq,'version':'0.3.2','target':'windows-x86_64','min_ipc':1,'max_ipc':1,'published':int(time.time())-10,'expires':int(time.time())+3600,'url':f'https://onixus-rf.duckdns.org/rtrust/releases/{seq}/windows-x86_64/setup.exe','size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            raw=json.dumps(m).encode();env=json.dumps({'payload':base64.b64encode(raw).decode(),'signature':base64.b64encode(key.sign(raw)).decode()}).encode();(p/'manifest.json').write_bytes(env);return p,env
        p1,e1=release(1);p2,e2=release(2);active=root/'windows-x86_64';active.mkdir();(active/'latest.json').write_bytes(e1)
        with patch.object(agent,'FEED',root),patch.object(agent,'ROOT_KEY',pub),patch.object(agent,'PACKAGES',root/'backups'):
            agent.promote({'sequence':2});self.assertEqual((active/'latest.json').read_bytes(),e2)
            with self.assertRaises(agent.Rejected):agent.promote({'sequence':1})
            (p2/'setup.exe').write_bytes(b'bad-file!')
            with self.assertRaises(agent.Rejected):agent.verify_manifest(p2/'manifest.json',True)
            tampered=json.loads(e1);tampered['signature']=base64.b64encode(bytes(64)).decode();(p1/'manifest.json').write_text(json.dumps(tampered))
            with self.assertRaises(Exception):agent.verify_manifest(p1/'manifest.json',True)
    def test_limits_validation_and_api_mapping(self):
        with patch.object(agent,'account',return_value={'id':1,'username':'fixture'}),patch.object(agent,'hui') as hui:
            agent.dispatch('hysteria.update',{'id':1,'days':10,'devices':2,'quota_gb':5})
            self.assertEqual(hui.call_args.args[2]['quota'],5*1024**3)
            with self.assertRaises(agent.Rejected):agent.dispatch('hysteria.update',{'id':1,'days':0,'devices':2,'quota_gb':5})

    def test_route_probe_failure_restores_and_disarms_watchdog(self):
        from unittest.mock import MagicMock, mock_open
        prefix=['local(10.254.77.1, tcp/18082, 127.0.0.1)','local(10.254.77.1, tcp/8081, 127.0.0.1)','reject(geoip:private)']
        old=json.dumps({'acl':{'inline':prefix+['reserve(all)']}})
        m=MagicMock();m.get_config.return_value=old;m.probe_hysteria.side_effect=RuntimeError('probe failed')
        temp=Path(TMP.name)/secrets.token_hex(8);temp.mkdir();exits=temp/'exits.json'
        exits.write_text(json.dumps({'primary':{'outbound':{'name':'primary'},'expected_ip':'192.0.2.1'}}))
        with patch('builtins.open',mock_open()),patch.object(agent.fcntl,'flock'),patch.object(agent,'route_snapshot',return_value={'revision':'known'}),patch.object(agent,'module_switch',return_value=m),patch.object(agent,'EXITS',exits),patch.object(agent,'BACKUPS',temp/'backups'),patch.object(agent,'run') as run:
            with self.assertRaises(RuntimeError):agent.apply_routes({'exit':'primary','rules':[],'revision':'known'})
            m.restore.assert_called_once()
            self.assertEqual(m.restore.call_args.args[0].read_text(),old)
            self.assertTrue(any(c.args[0][0]=='systemd-run' for c in run.call_args_list))
            self.assertTrue(any(c.args[0][-1].endswith('.timer') for c in run.call_args_list))

    def test_route_revision_conflict_never_stops_service(self):
        from unittest.mock import mock_open
        with patch('builtins.open',mock_open()),patch.object(agent.fcntl,'flock'),patch.object(agent,'route_snapshot',return_value={'revision':'new'}),patch.object(agent,'run') as run:
            with self.assertRaises(agent.Rejected):agent.apply_routes({'exit':'primary','rules':[],'revision':'old'})
            run.assert_not_called()

if __name__=='__main__':unittest.main(verbosity=2)
