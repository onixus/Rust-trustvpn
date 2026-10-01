#!/usr/bin/env python3
"""Local privileged adapter. Only a Unix socket, fixed operations, no shell input."""
import base64
import fcntl
import hashlib
import hmac
import http.client
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import socketserver
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HUI_DB = Path('/var/lib/h-ui/data/h_ui.db')
EXITS = Path('/etc/hysteria/exits.json')
FEED = Path('/opt/rtrust-updates')
PACKAGES = Path('/opt/vpn-console/packages')
BACKUPS = Path('/root/hysteria-route-backups')
TG = Path('/etc/vpn-telegram/config.json')
ROOT_KEY = Path('/opt/vpn-console/root.pub')
SOCKET = '/run/vpn-console/agent.sock'
LOCK = threading.Lock()
ORIGIN = 'https://onixus-rf.duckdns.org'

class Rejected(Exception):
    pass

def run(args, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise Rejected('Операция не завершена: ' + Path(args[0]).name)
    return p.stdout.strip()

def read_db(sql, args=()):
    c=sqlite3.connect(f'file:{HUI_DB}?mode=ro', uri=True)
    try:
        c.row_factory=sqlite3.Row
        return [dict(r) for r in c.execute(sql,args)]
    finally: c.close()

def hui_config():
    return yaml.safe_load(read_db('SELECT value FROM config WHERE key=?', ('HYSTERIA2_CONFIG',))[0]['value'])

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def hui(method, path, payload=None):
    admin = read_db("SELECT id,username FROM account WHERE role='admin' AND deleted=0 LIMIT 1")[0]
    key = read_db('SELECT value FROM config WHERE key=?', ('JWT_SECRET',))[0]['value']
    claims = {'account': dict(admin, roles=['admin'], deleted=0), 'iss':'h-ui', 'exp': int(time.time())+60}
    token = b64(b'{"alg":"HS256","typ":"JWT"}')+'.'+b64(json.dumps(claims).encode())
    token += '.'+b64(hmac.new(key.encode(), token.encode(), hashlib.sha256).digest())
    context = read_db('SELECT value FROM config WHERE key=?', ('H_UI_WEB_CONTEXT',))[0]['value'].rstrip('/')
    if context and not re.fullmatch(r'/[a-zA-Z0-9/_-]*', context):
        raise Rejected('Некорректный путь H UI')
    con = http.client.HTTPConnection('127.0.0.1',8081,timeout=15)
    try:
        con.request(method, context+'/hui/'+path, body=json.dumps(payload).encode() if payload is not None else None,
                    headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        r=con.getresponse(); result=json.loads(r.read(2*1024*1024))
        if r.status != 200 or result.get('code') != 20000:
            raise Rejected('H UI отклонил операцию')
        return result.get('data')
    finally:
        con.close()

def account(id):
    rows=read_db("SELECT * FROM account WHERE id=? AND role='user'", (int(id),))
    if not rows: raise Rejected('Пользователь Hysteria не найден')
    return rows[0]

def route_snapshot():
    c=hui_config(); profiles=json.loads(EXITS.read_text()); rules=c.get('acl',{}).get('inline',[])
    names={p['outbound']['name']:k for k,p in profiles.items()}
    return {'selected':names.get(rules[-1].split('(')[0],'custom') if rules else 'custom',
            'rules':rules,'revision':hashlib.sha256(json.dumps(c,sort_keys=True).encode()).hexdigest(),
            'exits':[{'id':k,'name':p['outbound']['name'],'host':p.get('expected_host',p.get('expected_ip','')),
                      'via':p['outbound']['socks5']['addr']} for k,p in profiles.items()],
            'trusttunnel':'direct','host':'direct'}

def module_switch():
    loader=importlib.machinery.SourceFileLoader('route_switch','/usr/local/sbin/hysteria-exit-switch')
    spec=importlib.util.spec_from_loader(loader.name,loader); mod=importlib.util.module_from_spec(spec); loader.exec_module(mod)
    return mod

def validate_rules(items):
    if not isinstance(items,list) or len(items)>128: raise Rejected('Не более 128 правил')
    rules=[]
    for item in items:
        if set(item) != {'target','kind','value'}: raise Rejected('Некорректное правило')
        target,kind,value=item['target'],item['kind'],item['value']
        if target not in ('local','primary','reserve','reject'): raise Rejected('Неизвестный выход')
        if not isinstance(value,str): raise Rejected('Некорректное значение')
        if kind=='suffix':
            value=value.encode('idna').decode('ascii').lower()
            if len(value)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',v) for v in value.split('.')):
                raise Rejected('Некорректный домен')
            match='suffix:'+value
        elif kind=='cidr':
            try: match=str(ipaddress.ip_network(value,strict=True))
            except ValueError: raise Rejected('Некорректная подсеть')
        elif kind=='geoip' and value in ('ru','by','kz','kg','tj','uz','am','az','md','tm'):
            match='geoip:'+value
        else: raise Rejected('Неизвестный тип правила')
        rules.append((target,match))
    return rules

def apply_routes(data):
    target=data.get('exit'); rules=validate_rules(data.get('rules',[]))
    if target not in ('primary','reserve'): raise Rejected('Неизвестный выход')
    # Same lock as the existing Telegram/CLI route switch.
    with open('/run/hysteria-exit-switch.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        snap=route_snapshot()
        if data.get('revision')!=snap['revision']: raise Rejected('Маршруты изменились. Обновите страницу.')
        m=module_switch(); profiles=json.loads(EXITS.read_text())
        for p in profiles.values():
            if p.get('expected_host'): p['expected_ip']=socket.gethostbyname(p['expected_host'])
        used={target}|{t for t,_ in rules if t in profiles}
        for t in used: m.check_exit(profiles[t])
        old=m.get_config(); c=yaml.safe_load(old)
        original=c['acl']['inline']
        # Never let the UI remove panel access or private-network rejection.
        prefix=['local(10.254.77.1, tcp/18082, 127.0.0.1)','local(10.254.77.1, tcp/8081, 127.0.0.1)','reject(geoip:private)']
        if original[:3]!=prefix: raise Rejected('Защищённые правила изменились; требуется проверка оператора')
        names={k:p['outbound']['name'] for k,p in profiles.items()}
        c['acl']['inline']=prefix+[f'{names.get(t,t)}({v})' for t,v in rules]+[names[target]+'(all)']
        BACKUPS.mkdir(mode=0o700,exist_ok=True)
        backup=BACKUPS/(time.strftime('%Y%m%d-%H%M%S')+'-console-'+secrets.token_hex(4)+'.yaml')
        backup.write_text(old); backup.chmod(0o600)
        watchdog='vpn-console-rollback-'+secrets.token_hex(4)
        run(['systemd-run','--quiet','--unit='+watchdog,'--on-active=180s','/usr/local/sbin/hysteria-exit-switch','_restore',str(backup)])
        try:
            run(['systemctl','stop','h-ui'])
            if m.get_config()!=old:
                backup.write_text(m.get_config())
                raise Rejected('Конфигурация изменилась во время применения')
            m.write_config(yaml.safe_dump(c,sort_keys=False)); run(['systemctl','start','h-ui'])
            ip=m.probe_hysteria(profiles[target]['expected_ip'])
        except BaseException:
            m.restore(backup); run(['systemctl','stop',watchdog+'.timer']); raise
        run(['systemctl','stop',watchdog+'.timer'])
        return {'message':'Маршруты применены; Hysteria egress '+ip,'backup':backup.name}

def verify_manifest(path, artifact=False, fresh=True):
    if path.stat().st_size>16384: raise Rejected('Слишком большой манифест')
    raw=path.read_bytes(); env=json.loads(raw)
    payload=base64.b64decode(env['payload'],validate=True)
    Ed25519PublicKey.from_public_bytes(ROOT_KEY.read_bytes()).verify(base64.b64decode(env['signature'],validate=True),payload)
    m=json.loads(payload); now=int(time.time())
    if m['schema']!=1 or m['target']!='windows-x86_64' or not m['min_ipc']<=1<=m['max_ipc']:
        raise Rejected('Несовместимый релиз')
    if fresh and not (m['published']<=now+300 and now<m['expires']<=m['published']+31*86400): raise Rejected('Манифест истёк')
    url=urllib.parse.urlsplit(m['url'])
    expected=f"/rtrust/releases/{m['sequence']}/{m['target']}/setup.exe"
    if url.scheme!='https' or url.netloc!='onixus-rf.duckdns.org' or url.path!=expected or url.query or url.fragment:
        raise Rejected('Неверный адрес артефакта')
    pkg=FEED/str(m['sequence'])/m['target']/'setup.exe'
    if not pkg.is_file() or not 0<m['size']<=256*1024*1024 or pkg.stat().st_size!=m['size']: raise Rejected('Артефакт отсутствует или повреждён')
    if artifact:
        with pkg.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
        if not hmac.compare_digest(digest,m['sha256']): raise Rejected('Хеш артефакта не совпадает')
    return m,raw

def updates():
    result=[]
    active=FEED/'windows-x86_64'/'latest.json'
    active_seq=None
    try: active_seq=json.loads(base64.b64decode(json.loads(active.read_bytes())['payload']))['sequence']
    except (OSError,ValueError,KeyError): pass
    for p in sorted(FEED.glob('[0-9]*/windows-x86_64/manifest.json')):
        item={'id':p.parent.parent.name,'component':'rtrust','active':False}
        try:
            m,_=verify_manifest(p); item.update(version=m['version'],sequence=m['sequence'],target=m['target'],valid=True,active=m['sequence']==active_seq)
        except Exception: item.update(valid=False,reason='Подпись, срок или артефакт не прошли проверку')
        result.append(item)
    return {'releases':result,'active_sequence':active_seq,'server_packages':server_packages()}

def promote(data):
    seq=str(data.get('sequence',''))
    if not re.fullmatch('[1-9][0-9]{0,9}',seq): raise Rejected('Некорректный номер релиза')
    p=FEED/seq/'windows-x86_64'/'manifest.json'; m,raw=verify_manifest(p,True)
    active=FEED/'windows-x86_64'/'latest.json'; current,_=verify_manifest(active,fresh=False)
    if m['sequence']<current['sequence']: raise Rejected('Понижение sequence запрещено')
    if m['sequence']!=int(seq): raise Rejected('Несоответствие каталога релиза')
    backup=PACKAGES/('feed-before-'+str(int(time.time()))+'.bak')
    backup.parent.mkdir(mode=0o700,exist_ok=True); shutil.copy2(active,backup)
    temp=active.with_name('.console-channel-'+secrets.token_hex(6)); temp.write_bytes(raw); temp.chmod(0o644); temp.replace(active)
    return {'message':'Канал Windows переключён на '+m['version']}

def server_packages():
    items=[]
    for p in sorted(PACKAGES.glob('*.json')):
        try:
            m=json.loads(p.read_text())
            if m.get('component') in ('hysteria','trusttunnel'):
                items.append({'id':p.stem,'component':m['component'],'version':str(m.get('version',''))})
        except (ValueError,OSError): continue
    return items

def server_update(data):
    name=data.get('package','')
    if not re.fullmatch('[a-zA-Z0-9_-]{1,80}',name): raise Rejected('Неверный пакет')
    # Operator-staged, root-owned recipes only. No executable uploads or URLs from UI.
    path=PACKAGES/(name+'.json'); st=path.stat()
    if st.st_uid!=0 or st.st_mode&0o022: raise Rejected('Небезопасные права пакета')
    m=json.loads(path.read_text()); component=m.get('component')
    if component=='hysteria':
        binary=PACKAGES/(name+'.bin'); st=binary.stat()
        if binary.is_symlink() or st.st_uid!=0 or st.st_mode&0o022: raise Rejected('Небезопасный бинарник')
        with binary.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
        if digest!=m.get('sha256'): raise Rejected('Хеш пакета не совпадает')
        # H UI uses its own managed binary: require exact operator-discovered path.
        dest=Path('/var/lib/h-ui/bin/hysteria-linux-amd64')
        if not dest.is_file(): raise Rejected('Путь Hysteria требует сверки с текущим H UI')
        old=PACKAGES/(name+'.rollback'); shutil.copy2(dest,old)
        try:
            run(['systemctl','stop','h-ui']); shutil.copy2(binary,dest); dest.chmod(0o755)
            run(['systemctl','start','h-ui']); time.sleep(2)
            snap=route_snapshot(); mod=module_switch(); p=json.loads(EXITS.read_text())[snap['selected']]
            if p.get('expected_host'): p['expected_ip']=socket.gethostbyname(p['expected_host'])
            mod.probe_hysteria(p['expected_ip'])
        except BaseException:
            run(['systemctl','stop','h-ui']); shutil.copy2(old,dest); run(['systemctl','start','h-ui']); raise
    elif component=='trusttunnel':
        probe=Path('/opt/vpn-console/probes/trusttunnel')
        if not probe.is_file() or probe.stat().st_uid!=0 or probe.stat().st_mode&0o022:
            raise Rejected('Не установлен проверенный протокольный probe TrustTunnel')
        image=m.get('image','')
        if not re.fullmatch(r'(?:[a-zA-Z0-9./:_-]+@)?sha256:[0-9a-f]{64}',image): raise Rejected('Нужен образ, закреплённый digest')
        run(['docker','image','inspect',image])  # must already be loaded by the operator
        compose=Path('/opt/trusttunnel-web/compose.yaml'); old=compose.read_text()
        cfg=yaml.safe_load(old); cfg['services']['trusttunnel-web']['image']=image
        backup=PACKAGES/(name+'-'+str(int(time.time()))+'.compose.bak'); backup.write_text(old); backup.chmod(0o600)
        dbpath=Path('/opt/trusttunnel-web/data/trusttunnel-web.db')
        with sqlite3.connect(dbpath) as src, sqlite3.connect(PACKAGES/(name+'-'+str(int(time.time()))+'.db.bak')) as dst: src.backup(dst)
        def up(): run(['docker','compose','-f',str(compose),'up','-d','--no-deps','trusttunnel-web'],90)
        try:
            compose.write_text(yaml.safe_dump(cfg,sort_keys=False)); up()
            for _ in range(20):
                try:
                    run(['docker','exec','trusttunnel-web','python','-c',"import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3).status==200"])
                    break
                except Rejected: time.sleep(2)
            else: raise Rejected('Проверка новой панели не пройдена')
            # A root-owned protocol probe is mandatory for server upgrades.
            probe=Path('/opt/vpn-console/probes/trusttunnel')
            if not probe.is_file() or probe.stat().st_uid!=0 or probe.stat().st_mode&0o022:
                raise Rejected('Не установлен проверенный протокольный probe TrustTunnel')
            run([str(probe)],60)
        except BaseException:
            compose.write_text(old); up(); raise
    else: raise Rejected('Неизвестный компонент')
    return {'message':'Обновление проверено и применено'}

def telegram(data):
    cfg=json.loads(TG.read_text()); chat=data.get('chat_id'); text=data.get('text')
    if not isinstance(chat,int) or chat<=0 or not isinstance(text,str) or not 1<=len(text)<=3500:
        raise Rejected('Неверный получатель или сообщение')
    req=urllib.request.Request('https://api.telegram.org/bot'+cfg['token']+'/sendMessage',
        data=json.dumps({'chat_id':chat,'text':text,'disable_web_page_preview':True}).encode(),headers={'Content-Type':'application/json'})
    # No redirects: the bot token must never leave Telegram.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args): return None
    with urllib.request.build_opener(NoRedirect).open(req,timeout=20) as r: result=json.load(r)
    if not result.get('ok'): raise Rejected('Telegram отклонил сообщение')
    return {'message_id':result['result']['message_id']}

def dispatch(op,data):
    if op=='snapshot':
        result={}
        for key,fn in [('routing',route_snapshot),('updates',updates),('hysteria_users',lambda:read_db("SELECT id,username,quota,download,upload,expire_time,device_no,deleted,remark FROM account WHERE role='user' ORDER BY id")),
                       ('telegram',lambda:{'configured':TG.is_file(),'owner':json.loads(TG.read_text())['owner'],'running':run(['systemctl','is-active','vpn-telegram'])=='active'}),
                       ('services',lambda:{'hysteria':run(['systemctl','is-active','h-ui']),'trusttunnel':run(['docker','inspect','trusttunnel-web','--format','{{.State.Status}}']),'hysteria_version':run(['/var/lib/h-ui/bin/hysteria-linux-amd64','version'])[:200]})]:
            try: result[key]=fn()
            except Exception: result[key]={'error':'Источник временно недоступен'}
        return result
    if op=='routes.check':
        return {'message':run(['/usr/local/sbin/hysteria-exit-switch','check'],60)}
    if op=='routes.apply': return apply_routes(data)
    if op=='updates.promote': return promote(data)
    if op=='updates.server': return server_update(data)
    if op=='telegram.send': return telegram(data)
    if op=='hysteria.create':
        name=data.get('username','')
        if not re.fullmatch('[a-zA-Z0-9_-]{6,32}',name): raise Rejected('Логин: 6–32 латинских символа')
        days=int(data.get('days',365)); devices=int(data.get('devices',3))
        if not 1<=days<=3650 or not 1<=devices<=100: raise Rejected('Неверный срок или лимит устройств')
        hui('POST','account/saveAccount',{'username':name,'pass':secrets.token_hex(16),'conPass':secrets.token_hex(16),'quota':-1,'expireTime':int((time.time()+days*86400)*1000),'deviceNo':devices,'deleted':0,'remark':'VPN Console'})
        return {'message':'Пользователь Hysteria создан'}
    if op=='hysteria.update':
        a=account(data.get('id'))
        days=data.get('days'); devices=data.get('devices'); quota=data.get('quota_gb')
        if type(days) is not int or not 1<=days<=3650 or type(devices) is not int or not 1<=devices<=100 or type(quota) is not int or not -1<=quota<=100000:
            raise Rejected('Некорректный срок, лимит устройств или квота')
        hui('POST','account/updateAccount',{'id':a['id'],'username':a['username'],'deviceNo':devices,'quota':quota*1024**3 if quota>=0 else -1,'expireTime':int((time.time()+days*86400)*1000)})
        return {'message':'Срок и лимиты Hysteria обновлены'}
    if op in ('hysteria.block','hysteria.unblock','hysteria.rotate','hysteria.export'):
        a=account(data.get('id'))
        if op=='hysteria.export':
            c=hui_config(); query={'sni':'onixus-rf.duckdns.org'}
            if c.get('obfs',{}).get('type')=='salamander': query.update(obfs='salamander',**{'obfs-password':c['obfs']['salamander']['password']})
            return {'content':'hysteria2://'+urllib.parse.quote(a['con_pass'],safe='')+'@onixus-rf.duckdns.org:443/?'+urllib.parse.urlencode(query)+'#'+urllib.parse.quote(a['username'])}
        payload={'id':a['id'],'username':a['username']}
        if op=='hysteria.rotate': payload['conPass']=secrets.token_hex(16)
        else: payload['deleted']=1 if op=='hysteria.block' else 0
        hui('POST','account/updateAccount',payload)
        if op in ('hysteria.block','hysteria.rotate'):
            hui('POST','hysteria2/hysteria2Kick',{'ids':[a['id']],'kickUtilTime':0})
        return {'message':'Изменение Hysteria применено'}
    raise Rejected('Операция запрещена')

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(240)
        try:
            raw=self.rfile.readline(65537)
            if len(raw)>65536 or not raw.endswith(b'\n'): raise Rejected('Слишком большой запрос')
            q=json.loads(raw)
            if q['op']=='snapshot': result=dispatch(q['op'],q.get('data',{}))
            else:
                with LOCK: result=dispatch(q['op'],q.get('data',{}))
            response={'ok':True,'result':result}
        except Rejected as e: response={'ok':False,'error':str(e)}
        except Exception: response={'ok':False,'error':'Операция не завершена; проверьте состояние перед повтором'}
        self.wfile.write(json.dumps(response).encode()+b'\n')

if __name__=='__main__':
    os.umask(0o077)
    Path(SOCKET).parent.mkdir(mode=0o750,exist_ok=True)
    Path(SOCKET).unlink(missing_ok=True)
    with socketserver.ThreadingUnixStreamServer(SOCKET,Handler) as server:
        os.chown(Path(SOCKET).parent,0,10001); os.chmod(Path(SOCKET).parent,0o750)
        os.chown(SOCKET,0,10001); os.chmod(SOCKET,0o660)
        server.serve_forever()
