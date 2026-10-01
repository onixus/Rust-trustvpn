"""Unified console sidecar. Reuses the portal identity; never starts a VPN endpoint."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from urllib.parse import urlsplit, parse_qs, urlencode
import http.client
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app import config, db, security, webauth, mailer, conninfo

BASE=Path(__file__).parent
STATE=Path(os.environ.get('CONSOLE_DATA','/console-data'))
AGENT=os.environ.get('CONSOLE_SOCKET','/run/vpn-console/agent.sock')
PORTAL=os.environ.get('CONSOLE_PORTAL','http://trusttunnel-web:8000')
STOP=threading.Event()
WRITE_LOCK=threading.Lock()

@contextmanager
def connect():
    c=sqlite3.connect(STATE/'console.db',timeout=15); c.row_factory=sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')
    try:
        with c: yield c
    finally: c.close()

def init():
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT DEFAULT CURRENT_TIMESTAMP, actor INTEGER, action TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, actor INTEGER, action TEXT, payload TEXT, state TEXT, result TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP, updated TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS contacts(source TEXT, user_id INTEGER, email TEXT, chat_id INTEGER, consent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(source,user_id));
        CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, actor INTEGER, channel TEXT, subject TEXT, body TEXT, state TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS deliveries(campaign TEXT, recipient TEXT, state TEXT, error TEXT, PRIMARY KEY(campaign,recipient));
        CREATE TABLE IF NOT EXISTS delivery_contacts(campaign TEXT, recipient TEXT, source TEXT, user_id INTEGER, PRIMARY KEY(campaign,recipient,source,user_id));
        ''')
        c.execute("UPDATE jobs SET state='unknown',result=? WHERE state='running'",(json.dumps({'message':'Сервис перезапущен. Проверьте состояние перед повтором.'}),))
        c.execute("UPDATE deliveries SET state='unknown',error='Прервано; автоматический повтор отключён' WHERE state='sending'")
        c.execute("UPDATE campaigns SET state='unknown' WHERE state='sending'")

def audit(actor,action,detail=''):
    with connect() as c: c.execute('INSERT INTO audit(actor,action,detail) VALUES(?,?,?)',(actor,action,detail))

def agent(op,data=None):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(240); sock.connect(AGENT); sock.sendall(json.dumps({'op':op,'data':data or {}}).encode()+b'\n')
        with sock.makefile('rb') as f: raw=f.readline(2*1024*1024)
    result=json.loads(raw)
    if not result.get('ok'): raise RuntimeError(result.get('error','Ошибка агента'))
    return result['result']

def actor(request,write=False):
    try: admin=webauth.current_admin(request)
    except (ValueError,KeyError,TypeError): admin=None
    if admin is None: raise HTTPException(401,'Войдите под администратором TrustTunnel')
    if write:
        csrf=hmac.new(config.SECRET_KEY.encode(),('console:'+request.cookies.get(webauth.ADMIN_COOKIE,'')).encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf): raise HTTPException(403,'Недействительный CSRF-токен')
        origin=request.headers.get('origin')
        if origin and origin!=os.environ.get('CONSOLE_ORIGIN','https://onixus-rf.duckdns.org'): raise HTTPException(403,'Недопустимый Origin')
    return admin['id']

async def body(request):
    raw=await request.body()
    if len(raw)>32768: raise HTTPException(413,'Слишком большой запрос')
    try: value=json.loads(raw)
    except (ValueError,UnicodeError): raise HTTPException(422,'Некорректный JSON')
    if not isinstance(value,dict): raise HTTPException(422,'Ожидается объект')
    return value

def legacy(actor_id,path,data):
    # Fixed paths constructed from checked integer IDs, session never saved in jobs.
    token=security.create_session_token(str(actor_id),'admin')
    origin=urlsplit(PORTAL)
    if origin.scheme!='http' or origin.hostname not in ('trusttunnel-web','127.0.0.1'):
        raise RuntimeError('Недопустимый внутренний адрес панели')
    client=http.client.HTTPConnection(origin.hostname,origin.port or 80,timeout=30)
    try:
        client.request('POST','/admin/'+path,body=urlencode(data),headers={'Cookie':webauth.ADMIN_COOKIE+'='+token,'Content-Type':'application/x-www-form-urlencoded'})
        r=client.getresponse(); dest=r.getheader('Location',''); r.read(1048576)
        query=parse_qs(urlsplit(dest).query)
        if r.status not in (302,303) or 'err' in query or '/login' in dest:
            raise RuntimeError('Панель TrustTunnel не подтвердила изменение')
    finally: client.close()
    return {'message':'Изменение TrustTunnel применено'}

def source_user(source,id):
    if source=='trusttunnel':
        u=db.get_user(id)
        if not u: raise HTTPException(404,'Пользователь не найден')
        return dict(u)
    if source=='hysteria':
        users=agent('snapshot').get('hysteria_users',[])
        if isinstance(users,list):
            for u in users:
                if u['id']==id: return u
        raise HTTPException(404,'Пользователь не найден')
    raise HTTPException(422,'Неизвестный источник')

def perform(action,data,admin):
    if action.startswith(('routes.','updates.','hysteria.')): return agent(action,data)
    if action=='trusttunnel.create':
        # Password is generated at execution, never stored in the job or audit.
        return legacy(admin,'users/create',{'email':data['email'],'password':secrets.token_urlsafe(24)})
    if action=='trusttunnel.password':
        u=source_user('trusttunnel',data['id'])
        # Admin supplies password only via a synchronous route; not job payload.
        raise RuntimeError('Используйте отдельную форму пароля')
    if action in ('trusttunnel.block','trusttunnel.unblock'):
        source_user('trusttunnel',data['id'])
        return legacy(admin,f"users/{data['id']}/status",{'status':'blocked' if action.endswith('.block') else 'active'})
    if action=='trusttunnel.device-revoke':
        with db.connect() as c: device=c.execute('SELECT * FROM app_devices WHERE id=?',(data['id'],)).fetchone()
        if not device: raise RuntimeError('Устройство не найдено')
        db.revoke_device(device['id']); user=db.get_user(device['user_id'])
        return legacy(admin,f"users/{user['id']}/status",{'status':user['status']})
    if action=='trusttunnel.key':
        source_user('trusttunnel',data['id'])
        return legacy(admin,f"users/{data['id']}/configs",{'label':'Unified console'})
    if action in ('trusttunnel.rotate','trusttunnel.revoke'):
        cfg=db.get_config(data['id'])
        if not cfg or cfg['revoked_at']: raise RuntimeError('Ключ не найден или уже отозван')
        # Persist desired state first; if endpoint reload fails, job reports failure.
        with db.connect() as c:
            if action.endswith('.rotate'): c.execute('UPDATE configs SET tt_password=? WHERE id=?',(secrets.token_urlsafe(24),cfg['id']))
            else: c.execute("UPDATE configs SET revoked_at=datetime('now') WHERE id=?",(cfg['id'],))
        u=db.get_user(cfg['user_id'])
        return legacy(admin,f"users/{cfg['user_id']}/status",{'status':u['status']})
    if action=='campaign.send': return send_campaign(data['id'])
    raise RuntimeError('Операция не поддерживается')

def work_once():
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job=c.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created,id LIMIT 1").fetchone()
        if job is None: return False
        c.execute("UPDATE jobs SET state='running',updated=CURRENT_TIMESTAMP WHERE id=?",(job['id'],))
    try:
        with db.connect() as c:
            exists=c.execute('SELECT id FROM admins WHERE id=?',(job['actor'],)).fetchone()
        if not exists: raise RuntimeError('Администратор удалён; выполнение отменено')
        result=perform(job['action'],json.loads(job['payload']),job['actor']); state='success'
    except Exception as exc:
        # Do not persist arbitrary upstream exceptions, which can contain credentials.
        result={'message':str(exc) if isinstance(exc,RuntimeError) else 'Ошибка выполнения. Проверьте состояние перед повтором.'}; state='failed'
    with connect() as c: c.execute('UPDATE jobs SET state=?,result=?,updated=CURRENT_TIMESTAMP WHERE id=?',(state,json.dumps(result,ensure_ascii=False),job['id']))
    audit(job['actor'],job['action'],state)
    return True

def worker():
    while not STOP.is_set():
        if not work_once(): STOP.wait(.5)

@asynccontextmanager
async def lifespan(app):
    init(); STOP.clear(); t=threading.Thread(target=worker,daemon=True); t.start()
    yield
    STOP.set(); t.join(timeout=2)

app=FastAPI(title='VPN Console',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
app.mount('/console/static',StaticFiles(directory=BASE/'static'),name='static')
templates=Jinja2Templates(directory=BASE/'templates')

@app.middleware('http')
async def headers(request,call_next):
    if request.method=='POST':
        try:
            if int(request.headers.get('content-length','0'))>32768:
                return HTMLResponse('Request too large',413)
        except ValueError: return HTMLResponse('Invalid length',400)
    response=await call_next(request)
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
        'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    return response

@app.get('/console',response_class=HTMLResponse)
@app.get('/console/',response_class=HTMLResponse)
def index(request:Request):
    try: actor(request)
    except HTTPException: return RedirectResponse('/admin/login',302)
    token=hmac.new(config.SECRET_KEY.encode(),('console:'+request.cookies.get(webauth.ADMIN_COOKIE,'')).encode(),hashlib.sha256).hexdigest()
    return templates.TemplateResponse(request,'index.html',{'csrf':token})

@app.get('/console/api/state')
def state(request:Request):
    actor(request)
    try: snapshot=agent('snapshot')
    except Exception: snapshot={'error':'Агент недоступен. Операции с узлами недоступны.'}
    with db.connect() as c:
        users=[dict(r) for r in c.execute('SELECT id,email,status,created_at FROM users ORDER BY id')]
        keys=[dict(r) for r in c.execute('SELECT c.id,c.user_id,c.tt_username,c.label,c.created_at,c.revoked_at,u.email FROM configs c JOIN users u ON u.id=c.user_id ORDER BY c.id')]
        devices=[dict(r) for r in c.execute('SELECT id,user_id,name,platform,last_seen_at,revoked_at FROM app_devices ORDER BY id')]
    with connect() as c:
        snapshot.update(users=users,keys=keys,devices=devices,contacts=[dict(r) for r in c.execute('SELECT * FROM contacts')],
            jobs=[dict(r) for r in c.execute('SELECT id,action,state,result,created,updated FROM jobs ORDER BY created DESC,rowid DESC LIMIT 40')],
            campaigns=[dict(r) for r in c.execute('SELECT id,channel,subject,state,created FROM campaigns ORDER BY created DESC')],
            audit=[dict(r) for r in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 60')],smtp=mailer.is_configured())
    snapshot['observed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    return snapshot

ACTIONS={'routes.check','routes.apply','updates.promote','updates.server','hysteria.create','hysteria.block','hysteria.unblock','hysteria.rotate',
         'trusttunnel.create','trusttunnel.block','trusttunnel.unblock','trusttunnel.key','trusttunnel.rotate','trusttunnel.revoke','trusttunnel.device-revoke','hysteria.update','campaign.send'}

def validate_action(action,data,check_state=True):
    if not isinstance(action,str) or action not in ACTIONS: raise HTTPException(422,'Неизвестная операция')
    if action.endswith(('.block','.unblock','.rotate','.key','.revoke','.device-revoke')):
        if type(data.get('id')) is not int or data['id']<=0: raise HTTPException(422,'Некорректный ID')
        return {'id':data['id']}
    if action=='trusttunnel.create':
        if not isinstance(data.get('email'),str): raise HTTPException(422,'Некорректный e-mail')
        email=data['email'].strip().lower()
        if not re.fullmatch(r'[^\s@<>\r\n]{1,100}@[^\s@<>\r\n]{1,150}\.[^\s@<>\r\n]{2,30}',email): raise HTTPException(422,'Некорректный e-mail')
        if check_state and db.get_user_by_email(email): raise HTTPException(409,'E-mail уже существует')
        return {'email':email}
    if action=='hysteria.create':
        if not isinstance(data.get('username'),str) or not re.fullmatch('[A-Za-z0-9_-]{6,32}',data['username']): raise HTTPException(422,'Логин Hysteria: 6–32 латинских символа')
        return {'username':data['username'],'days':365,'devices':3}
    if action=='hysteria.update':
        if set(data)!={'id','days','devices','quota_gb'} or any(type(data[k]) is not int for k in data): raise HTTPException(422,'Проверьте параметры')
        if data['id']<=0 or not 1<=data['days']<=3650 or not 1<=data['devices']<=100 or not -1<=data['quota_gb']<=100000: raise HTTPException(422,'Недопустимые лимиты')
        return data
    if action=='campaign.send':
        if not isinstance(data.get('id'),str) or not re.fullmatch('[a-f0-9]{32}',data['id']): raise HTTPException(422,'Некорректный ID рассылки')
        if check_state:
            with connect() as c: row=c.execute('SELECT state FROM campaigns WHERE id=?',(data['id'],)).fetchone()
            if not row or row['state']!='draft': raise HTTPException(409,'Рассылка уже отправлялась или не существует')
        return {'id':data['id']}
    if action=='routes.check': return {}
    # Agent repeats validation at the privilege boundary.
    allowed={'routes.apply':{'exit','rules','revision'},'updates.promote':{'sequence'},'updates.server':{'package'}}[action]
    if set(data)!=allowed: raise HTTPException(422,'Некорректные параметры')
    return data

@app.post('/console/api/jobs')
async def enqueue(request:Request):
    admin=actor(request,True); q=await body(request)
    if q.get('confirm') is not True: raise HTTPException(422,'Требуется подтверждение действия')
    action=q.get('action'); key=q.get('request_id',''); data=q.get('data',{})
    if not isinstance(key,str) or not re.fullmatch('[a-zA-Z0-9-]{16,80}',key) or not isinstance(data,dict): raise HTTPException(422,'Некорректный идентификатор запроса')
    with WRITE_LOCK:
        with connect() as c: existing=c.execute('SELECT * FROM jobs WHERE id=?',(key,)).fetchone()
        if existing:
            if existing['actor']!=admin or existing['action']!=action or json.loads(existing['payload'])!=validate_action(action,data,check_state=False): raise HTTPException(409,'Идентификатор уже используется')
            return {'id':key,'state':existing['state']}
        clean=validate_action(action,data)
        with connect() as c:
            if action=='campaign.send':
                if c.execute("SELECT 1 FROM jobs WHERE action='campaign.send' AND json_extract(payload,'$.id')=?",(clean['id'],)).fetchone(): raise HTTPException(409,'Рассылка уже поставлена в очередь')
            c.execute('INSERT INTO jobs(id,actor,action,payload,state) VALUES(?,?,?,?,?)',(key,admin,action,json.dumps(clean,sort_keys=True),'queued'))
    audit(admin,action,'queued')
    return {'id':key,'state':'queued'}

@app.post('/console/api/export')
async def export(request:Request):
    admin=actor(request,True); q=await body(request)
    if q.get('consent') is not True or type(q.get('id')) is not int: raise HTTPException(422,'Подтвердите раскрытие ключа')
    if q.get('source')=='hysteria': result=agent('hysteria.export',{'id':q['id']})
    elif q.get('source')=='trusttunnel':
        cfg=db.get_config(q['id'])
        if not cfg or cfg['revoked_at']: raise HTTPException(404,'Ключ не найден')
        from app.rtrust_profiles import managed_document, codec
        document=managed_document(cfg)
        result=codec(document['content'],'tt')
    else: raise HTTPException(422,'Неизвестный источник')
    audit(admin,'key.export',q['source']+':'+str(q['id'])); return result

@app.post('/console/api/password')
async def password(request:Request):
    admin=actor(request,True); q=await body(request)
    if type(q.get('id')) is not int or not isinstance(q.get('password'),str) or not 12<=len(q['password'])<=128: raise HTTPException(422,'Пароль: от 12 до 128 символов')
    source_user('trusttunnel',q['id']); result=legacy(admin,f"users/{q['id']}/password",{'password':q['password']})
    audit(admin,'user.password',str(q['id'])); return result

@app.post('/console/api/contacts')
async def contacts(request:Request):
    admin=actor(request,True); q=await body(request); source=q.get('source'); id=q.get('id')
    if type(id) is not int: raise HTTPException(422,'Некорректный ID')
    source_user(source,id); email=q.get('email','').strip(); chat=q.get('chat_id')
    if email and not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+',email): raise HTTPException(422,'Некорректный e-mail')
    if chat is not None and (type(chat) is not int or not 0<chat<2**53): raise HTTPException(422,'Нужен положительный Telegram user ID')
    with connect() as c: c.execute('INSERT OR REPLACE INTO contacts VALUES(?,?,?,?,?)',(source,id,email,chat,1 if q.get('consent') is True else 0))
    audit(admin,'contact.update',source+':'+str(id)); return {'message':'Контакт сохранён'}

@app.post('/console/api/campaigns')
async def campaign(request:Request):
    admin=actor(request,True); q=await body(request)
    channel=q.get('channel'); subject=q.get('subject','').strip(); text=q.get('body','').strip()
    if channel not in ('email','telegram') or not 1<=len(subject)<=160 or '\n' in subject or '\r' in subject or not 1<=len(text)<=3500: raise HTTPException(422,'Проверьте канал, тему и текст')
    recipients=q.get('recipients')
    if not isinstance(recipients,list) or not 1<=len(recipients)<=500: raise HTTPException(422,'Выберите от 1 до 500 контактов')
    id=secrets.token_hex(16); selected=set(); bindings=set()
    with connect() as c:
        for item in recipients:
            if not isinstance(item,dict) or type(item.get('id')) is not int: raise HTTPException(422,'Некорректный контакт')
            r=c.execute('SELECT * FROM contacts WHERE source=? AND user_id=? AND consent=1',(item.get('source'),item['id'])).fetchone()
            if not r or not r['email' if channel=='email' else 'chat_id']: raise HTTPException(422,'Нет адреса или согласия получателя')
            recipient=str(r['email' if channel=='email' else 'chat_id']); selected.add(recipient)
            bindings.add((id,recipient,r['source'],r['user_id']))
        c.execute('INSERT INTO campaigns(id,actor,channel,subject,body,state) VALUES(?,?,?,?,?,?)',(id,admin,channel,subject,text,'draft'))
        c.executemany('INSERT INTO deliveries(campaign,recipient,state) VALUES(?,?,?)',[(id,r,'pending') for r in selected])
        c.executemany('INSERT INTO delivery_contacts VALUES(?,?,?,?)',sorted(bindings))
    audit(admin,'campaign.draft',id)
    return {'id':id,'recipients':sorted(selected),'subject':subject,'body':text,'state':'draft'}

@app.get('/console/api/campaigns/{id}')
def campaign_detail(id:str,request:Request):
    actor(request)
    with connect() as c:
        row=c.execute('SELECT * FROM campaigns WHERE id=?',(id,)).fetchone()
        if not row: raise HTTPException(404,'Рассылка не найдена')
        return dict(row,deliveries=[dict(r) for r in c.execute('SELECT recipient,state,error FROM deliveries WHERE campaign=?',(id,))])

def send_campaign(id):
    with connect() as c:
        c.execute('BEGIN IMMEDIATE'); campaign=c.execute('SELECT * FROM campaigns WHERE id=?',(id,)).fetchone()
        if not campaign or campaign['state']!='draft': raise RuntimeError('Повторная отправка запрещена')
        c.execute("UPDATE campaigns SET state='sending' WHERE id=?",(id,))
        rows=c.execute('SELECT * FROM deliveries WHERE campaign=?',(id,)).fetchall()
    for row in rows:
        with connect() as c:
            field='email' if campaign['channel']=='email' else 'chat_id'
            # Consent belongs to an explicitly selected protocol identity, not
            # every account that happens to share the destination address.
            consent=c.execute(f'''SELECT 1 FROM delivery_contacts d JOIN contacts c
                ON c.source=d.source AND c.user_id=d.user_id
                WHERE d.campaign=? AND d.recipient=? AND c.{field}=? AND c.consent=1''',
                (id,row['recipient'],row['recipient'])).fetchone()
            if not consent:
                c.execute("UPDATE deliveries SET state='skipped',error='Нет действующего согласия выбранного контакта' WHERE campaign=? AND recipient=?",(id,row['recipient'])); continue
            c.execute("UPDATE deliveries SET state='sending' WHERE campaign=? AND recipient=?",(id,row['recipient']))
        try:
            if campaign['channel']=='email': mailer.send_mail(row['recipient'],campaign['subject'],campaign['body'])
            else: agent('telegram.send',{'chat_id':int(row['recipient']),'text':campaign['subject']+'\n\n'+campaign['body']})
            state,error='accepted',None
        except Exception: state,error='unknown','Доставка не подтверждена; автоматический повтор отключён'
        with connect() as c: c.execute('UPDATE deliveries SET state=?,error=? WHERE campaign=? AND recipient=?',(state,error,id,row['recipient']))
    with connect() as c:
        uncertain=c.execute("SELECT 1 FROM deliveries WHERE campaign=? AND state!='accepted'",(id,)).fetchone()
        c.execute('UPDATE campaigns SET state=? WHERE id=?',('partial' if uncertain else 'accepted',id))
    return {'message':'Обработка завершена. Проверьте статусы получателей; accepted означает принятие провайдером.'}

@app.get('/console/healthz')
def healthz():
    with connect() as c: c.execute('SELECT 1').fetchone()
    return {'status':'ok'}
