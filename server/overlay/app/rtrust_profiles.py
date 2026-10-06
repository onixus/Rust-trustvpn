"""Additive v2 profile exchange. Shared Rust codec; no endpoint mutation on import."""
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import stat
import subprocess
import time
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
import tempfile
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from . import config, db, security, webauth
from .templating import templates

router = APIRouter()
LIMIT = 1024 * 1024
CODEC = os.environ.get('RTRUST_CODEC', '/usr/local/bin/rtrust-codec')
HEADERS = {'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'}
SCHEMA = '''
CREATE TABLE IF NOT EXISTS rtrust_profiles(id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,revision INTEGER NOT NULL,payload BLOB,summary TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS rtrust_imports(id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,actor TEXT NOT NULL,payload BLOB NOT NULL,expires INTEGER NOT NULL,result TEXT);
CREATE TABLE IF NOT EXISTS rtrust_grants(profile TEXT NOT NULL,device INTEGER NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,PRIMARY KEY(profile,device));
CREATE TABLE IF NOT EXISTS rtrust_tokens(hash TEXT PRIMARY KEY,device INTEGER NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_rates(bucket TEXT PRIMARY KEY,count INTEGER NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,object TEXT NOT NULL,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_route_groups(id INTEGER PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,policy TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_route_members(device INTEGER PRIMARY KEY REFERENCES app_devices(id) ON DELETE CASCADE,grp INTEGER NOT NULL REFERENCES rtrust_route_groups(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS rtrust_route_groups_owner ON rtrust_route_groups(owner);
CREATE INDEX IF NOT EXISTS rtrust_route_members_grp ON rtrust_route_members(grp);
'''

def init():
    with db.connect() as c: c.executescript(SCHEMA)
    cipher()

def install(application):
    """Call once from the existing portal main module, after constructing its app."""
    previous = application.router.lifespan_context
    @asynccontextmanager
    async def lifespan(app):
        async with previous(app) as state:
            init()
            yield state
    application.router.lifespan_context = lifespan
    application.include_router(router)
    @application.middleware('http')
    async def private_responses(request, call_next):
        response = await call_next(request)
        if request.url.path == '/profiles' or request.url.path.startswith('/portal/v2/'):
            response.headers.update(HEADERS)
            response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        return response

def cipher():
    path = Path(config.DATA_DIR) / '.rtrust-profile-key'
    if not path.exists():
        # Publish a complete key atomically; concurrent workers cannot read half a key.
        fd, temporary = tempfile.mkstemp(prefix='.rtrust-key-',dir=config.DATA_DIR)
        try:
            with os.fdopen(fd,'wb') as f:
                f.write(Fernet.generate_key()); f.flush(); os.fsync(f.fileno())
            try: os.link(temporary,path)
            except FileExistsError: pass
        finally: os.unlink(temporary)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise RuntimeError('Unsafe profile encryption key')
    key=path.read_bytes()
    if len(key)!=44: raise RuntimeError('Invalid profile encryption key')
    return Fernet(key)

def seal(owner, document):
    return cipher().encrypt(json.dumps({'owner':owner,'document':document},ensure_ascii=False).encode())

def unseal(owner, payload):
    try:
        value=json.loads(cipher().decrypt(payload))
        if value['owner']!=owner: raise ValueError()
        return value['document']
    except (InvalidToken,ValueError,KeyError): raise HTTPException(503,'Encrypted profile unavailable')

def codec(content, fmt='profile_json'):
    if not isinstance(content,str) or len(content.encode())>LIMIT: raise HTTPException(413,'Profile too large')
    if fmt not in ('profile_json','endpoint_toml','cli_toml','tt'): raise HTTPException(422,'Unknown format')
    try:
        r=subprocess.run([CODEC],input=json.dumps({'content':content,'format':fmt}).encode(),capture_output=True,timeout=5)
    except (OSError,subprocess.TimeoutExpired): raise HTTPException(503,'Profile codec unavailable')
    if r.returncode or len(r.stdout)>8*LIMIT: raise HTTPException(422,'Invalid or unsupported profile')
    try:return json.loads(r.stdout)
    except ValueError:raise HTTPException(503,'Invalid codec response')

def csrf(request):
    cookie=request.cookies.get(webauth.USER_COOKIE,'')
    return hmac.new(config.SECRET_KEY.encode(),('rtrust-csrf:'+cookie).encode(),hashlib.sha256).hexdigest()

def actor(request, mutate=False):
    auth=request.headers.get('authorization')
    if auth is not None:
        if not auth.startswith('Bearer ') or not 40<=len(auth[7:])<=128: raise HTTPException(401,'Invalid device token')
        with db.connect() as c:
            row=c.execute('SELECT d.id,d.user_id,u.status FROM rtrust_tokens t JOIN app_devices d ON d.id=t.device JOIN users u ON u.id=d.user_id WHERE t.hash=? AND t.expires>? AND d.revoked_at IS NULL',(security.hash_api_token(auth[7:]),int(time.time()))).fetchone()
        if row is None or row['status']!='active':raise HTTPException(401,'Device expired or revoked')
        return row['user_id'],f'd:{row["id"]}',row['id']
    user=webauth.current_user(request)
    if not user:raise HTTPException(401,'Login required')
    if mutate and not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf(request)):
        raise HTTPException(403,'CSRF check failed')
    session=hashlib.sha256(request.cookies[webauth.USER_COOKIE].encode()).hexdigest()
    return user['id'],f'u:{user["id"]}:{session}',None

def rate(bucket, limit=30):
    now=int(time.time())
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('DELETE FROM rtrust_rates WHERE expires<=?',(now,))
        r=c.execute('SELECT count FROM rtrust_rates WHERE bucket=?',(bucket,)).fetchone()
        if r and r['count']>=limit:raise HTTPException(429,'Rate limit',headers={'Retry-After':'60'})
        c.execute('INSERT INTO rtrust_rates VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1',(bucket,now+60))

def audit(c, identity, action, obj):
    c.execute('INSERT INTO rtrust_audit(actor,action,object,created) VALUES(?,?,?,?)',(identity,action,obj,int(time.time())))

async def body(request, allowed):
    data=bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data)>2*LIMIT:raise HTTPException(413,'Request too large')
    try: value=json.loads(data)
    except ValueError:raise HTTPException(422,'Invalid JSON')
    if not isinstance(value,dict) or set(value)-set(allowed):raise HTTPException(422,'Unknown request fields')
    return value

def managed_document(cfg):
    # Freeze settings once, then use the same Rust serializer for every format.
    from . import endpoint
    settings=db.get_settings()
    hostname=endpoint.effective_domain(settings)
    address=(settings.get('conn_address') or '').strip() or hostname or config.PUBLIC_ADDRESS
    port=int(settings.get('conn_port') or '8443')
    if ':' in address and not address.startswith('['):address='['+address+']'
    raw={'schema_version':1,'name':cfg['label'] or cfg['tt_username'],'endpoint':{'hostname':hostname,'addresses':[f'{address}:{port}'],'username':cfg['tt_username'],'password':cfg['tt_password'],'custom_sni':settings.get('conn_sni') or '', 'has_ipv6':False,'anti_dpi':False,'upstream_protocol':'http3' if settings.get('conn_protocol')=='QUIC' else 'http2'}}
    return codec(json.dumps(raw))

def accessible(c, owner, device, identifier):
    if device is not None and not c.execute('SELECT 1 FROM rtrust_grants WHERE profile=? AND device=?',(identifier,device)).fetchone():
        raise HTTPException(404,'Profile not found')
    if identifier.startswith('managed-'):
        try: number=int(identifier[8:])
        except ValueError:raise HTTPException(404,'Profile not found')
        row=c.execute('SELECT * FROM configs WHERE id=? AND user_id=? AND revoked_at IS NULL',(number,owner)).fetchone()
        if row is None:raise HTTPException(404,'Profile not found')
        result=managed_document(row)
        revision=hashlib.sha256(result['content'].encode()).hexdigest()
        return {'id':identifier,'revision':revision,'summary':result['summary'],'origin':'portal_managed'},result['content']
    row=c.execute('SELECT * FROM rtrust_profiles WHERE id=? AND owner=? AND revoked=0',(identifier,owner)).fetchone()
    if row is None:raise HTTPException(404,'Profile not found')
    return {'id':identifier,'revision':str(row['revision']),'summary':json.loads(row['summary']),'origin':'external_stored'},unseal(owner,row['payload'])

@router.get('/portal/v2/capabilities')
def capabilities():return JSONResponse({'version':2,'formats':['profile_json','endpoint_toml','cli_toml','tt'],'enrollment':['one_time_code'],'max_profile_bytes':LIMIT,'routing':1},headers=HEADERS)

@router.get('/profiles',response_class=HTMLResponse)
def page(request:Request):
    user=webauth.current_user(request)
    if not user:return RedirectResponse('/login',302)
    return templates.TemplateResponse(request,'rtrust_profiles.html',{'user':user,'brand':db.get_setting('brand_name'),'csrf':csrf(request)},headers=HEADERS)

@router.post('/portal/v2/enrollment-codes')
def enrollment_code(request:Request):
    owner,identity,device=actor(request,True)
    if device is not None:raise HTTPException(403,'Browser login required')
    rate(identity)
    raw=secrets.token_urlsafe(24)
    db.create_enroll_code(owner,security.hash_api_token(raw),180)
    return JSONResponse({'code':raw,'expires_in':180},headers=HEADERS)

@router.post('/portal/v2/enroll')
async def enroll(request:Request):
    rate('enroll:'+str(request.client.host if request.client else 'unknown'),10)
    data=await body(request,['code','name','platform'])
    code=data.get('code');name=data.get('name');platform=data.get('platform')
    if not isinstance(code,str) or not 20<=len(code)<=128 or not isinstance(name,str) or not 1<=len(name)<=80 or platform not in ('windows','linux','macos','android','ios'):
        raise HTTPException(422,'Invalid enrollment')
    raw=secrets.token_urlsafe(32);now=int(time.time());hashed=security.hash_api_token(code)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT e.* FROM enroll_codes e JOIN users u ON e.user_id=u.id WHERE e.code_hash=? AND e.used_at IS NULL AND e.expires_at>datetime('now') AND u.status='active'",(hashed,)).fetchone()
        if row is None:raise HTTPException(401,'Enrollment code invalid or expired')
        device=c.execute('INSERT INTO app_devices(user_id,name,token_hash,platform) VALUES(?,?,?,?)',(row['user_id'],name,security.hash_api_token(secrets.token_urlsafe(32)),platform)).lastrowid
        c.execute("UPDATE enroll_codes SET used_at=datetime('now'),device_id=? WHERE id=?",(device,row['id']))
        c.execute('INSERT INTO rtrust_tokens VALUES(?,?,?)',(security.hash_api_token(raw),device,now+30*86400))
        audit(c,f'd:{device}','enroll',str(device))
    return JSONResponse({'token':raw,'device_id':device,'expires_in':30*86400},headers=HEADERS)

@router.get('/portal/v2/devices')
def devices(request:Request):
    owner,_,device=actor(request)
    if device is not None:raise HTTPException(403,'Browser login required')
    with db.connect() as c: rows=c.execute('SELECT DISTINCT d.id,d.name,d.platform FROM app_devices d JOIN rtrust_tokens t ON t.device=d.id WHERE d.user_id=? AND d.revoked_at IS NULL AND t.expires>?',(owner,int(time.time()))).fetchall()
    return JSONResponse({'devices':[dict(r) for r in rows]},headers=HEADERS)

@router.delete('/portal/v2/devices/{identifier}')
def revoke_device(identifier:int,request:Request):
    owner,identity,device=actor(request,True)
    if device is not None:raise HTTPException(403,'Browser login required')
    with db.connect() as c:
        if not c.execute('SELECT 1 FROM app_devices WHERE id=? AND user_id=?',(identifier,owner)).fetchone():raise HTTPException(404,'Device not found')
        c.execute('DELETE FROM rtrust_tokens WHERE device=?',(identifier,));c.execute('DELETE FROM rtrust_grants WHERE device=?',(identifier,))
        c.execute('DELETE FROM rtrust_route_members WHERE device=?',(identifier,))
        c.execute("UPDATE app_devices SET revoked_at=datetime('now') WHERE id=?",(identifier,))
        audit(c,identity,'revoke_device',str(identifier))
    return JSONResponse({'revoked':True},headers=HEADERS)

@router.get('/portal/v2/profiles')
def profiles(request:Request):
    owner,_,device=actor(request)
    with db.connect() as c:
        if device is None:
            ids=[r[0] for r in c.execute('SELECT id FROM rtrust_profiles WHERE owner=? AND revoked=0 ORDER BY id LIMIT 100',(owner,))]
            ids += ['managed-'+str(r[0]) for r in c.execute('SELECT id FROM configs WHERE user_id=? AND revoked_at IS NULL ORDER BY id LIMIT 100',(owner,))]
        else:ids=[r[0] for r in c.execute('SELECT profile FROM rtrust_grants WHERE device=? ORDER BY profile LIMIT 100',(device,))]
        result=[]
        for identifier in ids:
            try:meta,_=accessible(c,owner,device,identifier);result.append(meta)
            except HTTPException as e:
                if e.status_code!=404:raise
    return JSONResponse({'profiles':result},headers=HEADERS)

@router.post('/portal/v2/profiles/{identifier}/export')
async def export(identifier:str,request:Request):
    owner,identity,device=actor(request,True)
    data=await body(request,['format','revision','include_secrets','accept_losses'])
    if data.get('include_secrets') is not True:raise HTTPException(422,'Explicit secret export consent required')
    with db.connect() as c:
        meta,document=accessible(c,owner,device,identifier)
        if str(data.get('revision'))!=meta['revision']:raise HTTPException(409,'Profile revision changed')
        result=codec(document,data.get('format','profile_json'))
        if result['losses'] and data.get('accept_losses') is not True:
            return JSONResponse({'losses':result['losses'],'error':'Explicit format-loss consent required'},status_code=409,headers=HEADERS)
        audit(c,identity,'export',identifier)
    return JSONResponse(result,headers=HEADERS)

@router.post('/portal/v2/profile-imports/preview')
async def preview(request:Request):
    owner,identity,_=actor(request,True);rate(identity)
    data=await body(request,['content','intent'])
    if data.get('intent')!='external_stored':raise HTTPException(422,'Only external storage import is supported; endpoint credentials are unchanged')
    result=codec(data.get('content'))
    identifier=str(uuid.uuid4())
    with db.connect() as c:
        c.execute('DELETE FROM rtrust_imports WHERE expires<?',(int(time.time()),))
        c.execute('INSERT INTO rtrust_imports VALUES(?,?,?,?,?,NULL)',(identifier,owner,identity,seal(owner,result['content']),int(time.time())+600))
    return JSONResponse({'preview_id':identifier,'summary':result['summary'],'expires_in':600,'origin':'external_stored','secrets_present':True},headers=HEADERS)

@router.post('/portal/v2/profile-imports/{identifier}/commit')
async def commit(identifier:str,request:Request):
    owner,identity,device=actor(request,True)
    data=await body(request,['action','target_id','base_revision','consent'])
    if data.get('consent') is not True or data.get('action') not in ('create','replace'):raise HTTPException(422,'Explicit import consent and action required')
    signature=hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM rtrust_imports WHERE id=? AND owner=? AND actor=?',(identifier,owner,identity)).fetchone()
        if row is None:raise HTTPException(404,'Preview not found')
        if row['result']:
            result=json.loads(row['result'])
            if result.pop('signature')!=signature:raise HTTPException(409,'Preview already committed with another action')
            return JSONResponse(result,headers=HEADERS)
        if row['expires']<=int(time.time()):raise HTTPException(410,'Preview expired')
        document=unseal(owner,row['payload']);summary=codec(document)['summary']
        if data['action']=='replace':
            target=data.get('target_id','')
            if not isinstance(target,str) or target.startswith('managed-'):raise HTTPException(403,'Managed credentials cannot be replaced')
            meta,_=accessible(c,owner,device,target)
            if str(data.get('base_revision'))!=meta['revision']:raise HTTPException(409,'Profile revision changed')
            revision=int(meta['revision'])+1
            c.execute('UPDATE rtrust_profiles SET revision=?,payload=?,summary=? WHERE id=?',(revision,seal(owner,document),json.dumps(summary),target))
        else:
            if c.execute('SELECT count(*) FROM rtrust_profiles WHERE owner=? AND revoked=0',(owner,)).fetchone()[0]>=100:raise HTTPException(409,'Profile limit reached')
            target=str(uuid.uuid4());revision=1
            c.execute('INSERT INTO rtrust_profiles VALUES(?,?,?,?,?,0)',(target,owner,revision,seal(owner,document),json.dumps(summary)))
            if device is not None:c.execute('INSERT INTO rtrust_grants VALUES(?,?)',(target,device))
        result={'id':target,'revision':str(revision),'signature':signature}
        c.execute('UPDATE rtrust_imports SET result=?,payload=? WHERE id=?',(json.dumps(result),b'',identifier))
        audit(c,identity,data['action'],target)
    result.pop('signature')
    return JSONResponse(result,headers=HEADERS)

@router.post('/portal/v2/profiles/{identifier}/grants')
async def grant(identifier:str,request:Request):
    owner,identity,device=actor(request,True)
    if device is not None:raise HTTPException(403,'Browser login required')
    data=await body(request,['device_id','allow'])
    if type(data.get('device_id')) is not int or type(data.get('allow')) is not bool:raise HTTPException(422,'Invalid grant')
    with db.connect() as c:
        accessible(c,owner,None,identifier)
        if not c.execute('SELECT 1 FROM app_devices WHERE id=? AND user_id=? AND revoked_at IS NULL',(data['device_id'],owner)).fetchone():raise HTTPException(404,'Device not found')
        if data['allow']:c.execute('INSERT OR IGNORE INTO rtrust_grants VALUES(?,?)',(identifier,data['device_id']))
        else:c.execute('DELETE FROM rtrust_grants WHERE profile=? AND device=?',(identifier,data['device_id']))
        audit(c,identity,'grant' if data['allow'] else 'ungrant',identifier)
    return JSONResponse({'updated':True},headers=HEADERS)

@router.delete('/portal/v2/profiles/{identifier}')
def delete(identifier:str,request:Request):
    owner,identity,device=actor(request,True)
    if device is not None or identifier.startswith('managed-'):raise HTTPException(403,'Only owner can delete an external profile')
    with db.connect() as c:
        meta,_=accessible(c,owner,None,identifier)
        if request.headers.get('if-match')!=meta['revision']:raise HTTPException(409,'Profile revision changed')
        c.execute('UPDATE rtrust_profiles SET revoked=1,payload=NULL WHERE id=?',(identifier,))
        c.execute('DELETE FROM rtrust_grants WHERE profile=?',(identifier,))
        audit(c,identity,'delete',identifier)
    return JSONResponse({'revoked':True},headers=HEADERS)

# Split-tunnel routing for the desktop TUN mode, assigned to devices through owner-scoped groups.
def networks(value, low, high):
    if not isinstance(value,list) or not low<=len(value)<=high:raise HTTPException(422,f'Expected {low}..{high} IPv4 networks')
    result=[]
    for item in value:
        if not isinstance(item,str) or len(item)>32 or '/' not in item:raise HTTPException(422,'Invalid IPv4 network')
        try:network=str(ipaddress.IPv4Network(item.strip(),strict=True))
        except ValueError:raise HTTPException(422,'Invalid IPv4 network (host bits set or malformed): '+item[:32])
        if network not in result:result.append(network)
    return result

def route_policy(data):
    name=data.get('name')
    if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(ch)<32 or ord(ch)==127 for ch in name):raise HTTPException(422,'Group name must be 1..80 characters')
    if type(data.get('exclude_lan')) is not bool:raise HTTPException(422,'exclude_lan must be a boolean')
    return name.strip(),{'include':networks(data.get('include'),1,16),'exclude':networks(data.get('exclude'),0,64),'exclude_lan':data['exclude_lan']}

def browser(request, mutate=False):
    owner,identity,device=actor(request,mutate)
    if device is not None:raise HTTPException(403,'Browser login required')
    return owner,identity

def route_group(c, owner, identifier):
    row=c.execute('SELECT * FROM rtrust_route_groups WHERE id=? AND owner=?',(identifier,owner)).fetchone()
    if row is None:raise HTTPException(404,'Route group not found')
    return row

def route_groups(c, owner, identifier=None):
    rows=c.execute('SELECT * FROM rtrust_route_groups WHERE owner=? AND (? IS NULL OR id=?) ORDER BY id',(owner,identifier,identifier)).fetchall()
    members={}
    for r in c.execute('SELECT m.grp,m.device FROM rtrust_route_members m JOIN rtrust_route_groups g ON g.id=m.grp JOIN app_devices d ON d.id=m.device WHERE g.owner=? AND d.user_id=? AND d.revoked_at IS NULL ORDER BY m.device',(owner,owner)):
        members.setdefault(r['grp'],[]).append(r['device'])
    return [{'id':r['id'],'name':r['name'],**json.loads(r['policy']),'revision':r['revision'],'devices':members.get(r['id'],[])} for r in rows]

@router.get('/portal/v2/route-groups')
def list_route_groups(request:Request):
    owner,_=browser(request)
    with db.connect() as c:return JSONResponse({'groups':route_groups(c,owner)},headers=HEADERS)

@router.post('/portal/v2/route-groups')
async def create_route_group(request:Request):
    owner,identity=browser(request,True);rate('routes:'+identity,60)
    name,policy=route_policy(await body(request,['name','include','exclude','exclude_lan']))
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT count(*) FROM rtrust_route_groups WHERE owner=?',(owner,)).fetchone()[0]>=50:raise HTTPException(409,'Route group limit reached')
        identifier=c.execute('INSERT INTO rtrust_route_groups(owner,name,policy,revision) VALUES(?,?,?,1)',(owner,name,json.dumps(policy))).lastrowid
        audit(c,identity,'route_group_create',str(identifier))
        return JSONResponse(route_groups(c,owner,identifier)[0],headers=HEADERS)

@router.put('/portal/v2/route-groups/{identifier}')
async def update_route_group(identifier:int,request:Request):
    owner,identity=browser(request,True);rate('routes:'+identity,60)
    data=await body(request,['name','include','exclude','exclude_lan','revision'])
    name,policy=route_policy(data)
    if type(data.get('revision')) is not int:raise HTTPException(422,'Revision required')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=route_group(c,owner,identifier)
        if row['revision']!=data['revision']:raise HTTPException(409,'Route group revision changed')
        c.execute('UPDATE rtrust_route_groups SET name=?,policy=?,revision=? WHERE id=?',(name,json.dumps(policy),row['revision']+1,identifier))
        audit(c,identity,'route_group_update',str(identifier))
        return JSONResponse(route_groups(c,owner,identifier)[0],headers=HEADERS)

@router.delete('/portal/v2/route-groups/{identifier}')
def delete_route_group(identifier:int,request:Request):
    owner,identity=browser(request,True)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=route_group(c,owner,identifier)
        if request.headers.get('if-match')!=str(row['revision']):raise HTTPException(409,'Route group revision changed')
        c.execute('DELETE FROM rtrust_route_members WHERE grp=?',(identifier,))
        c.execute('DELETE FROM rtrust_route_groups WHERE id=?',(identifier,))
        audit(c,identity,'route_group_delete',str(identifier))
    return JSONResponse({'deleted':True},headers=HEADERS)

@router.post('/portal/v2/route-groups/{identifier}/members')
async def route_group_member(identifier:int,request:Request):
    owner,identity=browser(request,True);rate('routes:'+identity,60)
    data=await body(request,['device_id','member'])
    if type(data.get('device_id')) is not int or type(data.get('member')) is not bool:raise HTTPException(422,'Invalid membership')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        route_group(c,owner,identifier)
        if not c.execute('SELECT 1 FROM app_devices WHERE id=? AND user_id=? AND revoked_at IS NULL',(data['device_id'],owner)).fetchone():raise HTTPException(404,'Device not found')
        if data['member']:c.execute('INSERT INTO rtrust_route_members(device,grp) VALUES(?,?) ON CONFLICT(device) DO UPDATE SET grp=excluded.grp',(data['device_id'],identifier))
        else:c.execute('DELETE FROM rtrust_route_members WHERE device=? AND grp=?',(data['device_id'],identifier))
        audit(c,identity,'route_member_add' if data['member'] else 'route_member_remove',f'{identifier}:{data["device_id"]}')
        return JSONResponse(route_groups(c,owner,identifier)[0],headers=HEADERS)

@router.get('/portal/v2/routing')
def routing(request:Request):
    owner,_,device=actor(request)
    if device is None:raise HTTPException(403,'Device token required')
    with db.connect() as c:row=c.execute('SELECT g.* FROM rtrust_route_members m JOIN rtrust_route_groups g ON g.id=m.grp WHERE m.device=? AND g.owner=?',(device,owner)).fetchone()
    if row is None:return JSONResponse({'policy':None},headers=HEADERS)
    return JSONResponse({'policy':{'group':row['name'],'revision':f'{row["id"]}:{row["revision"]}',**json.loads(row['policy'])}},headers=HEADERS)
