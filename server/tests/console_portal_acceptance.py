"""Run only inside an ephemeral console image with a tmpfs /data and local portal.

Exercises the actual legacy HTTP routes and codec, without mounting live data.
"""
import os
import secrets
from app import db, security, config
from pathlib import Path
import console_app as ui

if os.environ.get('CONSOLE_ISOLATED_ACCEPTANCE')!='1':
    raise SystemExit('Refusing to run outside explicitly isolated acceptance container')
Path(config.ENDPOINT_WORKDIR).mkdir(parents=True,exist_ok=True)
ui.PORTAL='http://127.0.0.1:8000'
with db.connect() as c:admin=c.execute('SELECT id FROM admins LIMIT 1').fetchone()[0]
email='fixture-'+secrets.token_hex(8)+'@example.invalid'
ui.perform('trusttunnel.create',{'email':email},admin)
u=db.get_user_by_email(email);assert u and u['status']=='active'
ui.legacy(admin,f"users/{u['id']}/password",{'password':'fixture-'+secrets.token_hex(24)})
ui.perform('trusttunnel.block',{'id':u['id']},admin);assert db.get_user(u['id'])['status']=='blocked'
ui.perform('trusttunnel.unblock',{'id':u['id']},admin);assert db.get_user(u['id'])['status']=='active'
ui.perform('trusttunnel.key',{'id':u['id']},admin)
key=db.list_user_configs(u['id'])[0];before=key['tt_password']
ui.perform('trusttunnel.rotate',{'id':key['id']},admin);assert db.get_config(key['id'])['tt_password']!=before
# A public fixture hostname, no endpoint is started and no traffic is attempted.
db.set_settings({'panel_domain':'vpn.example.invalid','conn_address':'vpn.example.invalid'})
from app.rtrust_profiles import managed_document, codec
export=codec(managed_document(db.get_config(key['id']))['content'],'tt')['content'];assert export.startswith('tt://')
ui.perform('trusttunnel.revoke',{'id':key['id']},admin);assert db.get_config(key['id'])['revoked_at']
device=db.create_device(u['id'],'fixture',secrets.token_hex(32))
device_key=db.create_device_config(u['id'],device,'fixture-device',secrets.token_hex(24),'fixture')
ui.perform('trusttunnel.device-revoke',{'id':device},admin)
assert db.get_device(device)['revoked_at'] and db.get_config(device_key)['revoked_at']
print('PASS real portal HTTP create/password/block/unblock/key/rotate/revoke/device + real Rust export')
