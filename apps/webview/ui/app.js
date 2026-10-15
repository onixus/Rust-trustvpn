'use strict';
const $=id=>document.getElementById(id),invoke=window.__TAURI__.core.invoke,M=window.RTModel;
// The view model carries no credentials; Rust keeps vault, tokens and portal baselines.
let state,notice='',noticeBase,noticeTimer=null,busy=false,selected=0,phase=null,connectError=null,unavailable=false,armedDelete=null,lastListKey='',actionGen=0,polling=false;

/* ---------- Copy (RU/EN by system language) ---------- */
const LANG=String(navigator.language||'en').toLowerCase().startsWith('ru')?'ru':'en';
const T={en:{
 'nav.sections':'Sections','nav.home':'Home','nav.profiles':'Profiles','nav.checks':'Checks','nav.network':'Network','nav.sync':'Sync','nav.settings':'Settings',
 'common.back':'Back','working':'Working…','connected':'Connected','disconnected':'Disconnected',
 'line.vpn':'VPN','line.tunnel':'Tunnel','line.off':'is off','line.connecting':'connecting','line.reconnecting':'reconnecting','line.disconnecting':'disconnecting','line.running':'is up','line.verified':'verified','line.warning1':'Needs','line.warning2':'attention','line.error1':'Not','line.error2':'connected','line.status':'Status','line.unavailable':'unavailable',
 'short.off':'VPN off','short.connecting':'Connecting…','short.reconnecting':'Reconnecting…','short.disconnecting':'Disconnecting…','short.running':'Tunnel is up','short.proxy':'Proxy is up','short.verified':'Tunnel verified','short.warning':'Needs attention','short.error':'Not connected','short.unavailable':'Status unavailable',
 'desc.off':'No tunnel from this app is running. Connect the selected profile “{name}”.','desc.off_none':'Add a profile to connect.',
 'desc.connecting':'Connecting to {host}.','desc.disconnecting':'Stopping the tunnel.',
 'desc.running':'The tunnel is running. No fresh result yet for: {checks}. This does not mean they fail.',
 'desc.running_partial':'Every check passed, but only for the networks sent through the VPN; other traffic is not covered, so the status stays blue.',
 'desc.running_confirm':'The checks passed; waiting for the service to confirm them.',
 'desc.reconnecting':'Reconnecting to check the path again.',
 'desc.fallback':'The service switched from “{requested}” to a backup profile.',
 'tag.backup':'backup','live.backup':'Backup profile','home.active_backup':'Backup in use','row.requested':'requested',
 'checks.sub_nohost':'{name} · results expire after {ttl} s',
 'mode.tun_managed':'server routes','net.managed':'The server assigns the routes for this device; the local network list is not used while that policy applies.',
 'notice.conflict':'Profiles or settings changed elsewhere (sync or another window). The view is refreshed; repeat the action.',
 'desc.running_proxy':'The local SOCKS5 proxy is running. Only apps configured to use it go through the tunnel; the system path is not checked.',
 'desc.verified':'All five checks passed in the last few seconds. Results expire; the status returns to blue unless they are repeated.',
 'desc.warning':'The tunnel is running, but these checks failed: {checks}. Open Checks to see details.',
 'desc.error':'The connection did not start. Check the profile and network, then retry.','desc.unavailable':'The app cannot read the connection state right now.',
 'action.connect':'Connect “{name}”','action.add':'Add a profile first','action.connecting':'Connecting…','action.reconnecting':'Reconnecting…','action.disconnecting':'Disconnecting…','action.disconnect':'Disconnect','action.retry':'Retry connection',
 'checks.eyebrow':'Checks','checks.open':'Open checks','checks.hint':'Checks come from the connection service. A check without a result shows “no data”, never “passed”. Results expire after a few seconds.',
 'checks.sub':'{name} · {host} · results expire after {ttl} s','checks.sub_none':'No active session',
 'check.transport':'Transport','check.route':'Route','check.dns':'DNS','check.guard':'Guard','check.connectivity':'Connectivity',
 'note.transport':'connection to the server','note.route':'VPN routes match the profile','note.dns':'resolver answers through the tunnel','note.guard':'traffic blocked if the VPN drops','note.connectivity':'one address through the VPN network',
 'val.passed':'verified','val.failed':'failed','val.configured':'running','val.stale':'stale','val.unsupported':'check unsupported','val.na':'not checked','val.guard_off':'off','val.unknown':'no data','val.off':'off','val.connecting':'connecting…','val.error':'failed',
 'detail.passed':'Passed {age} s ago.','detail.failed':'The service reported a failure for this check.','detail.configured':'Started by the service; not verified yet.',
 'detail.stale':'The last result expired or the network changed, so it no longer counts.','detail.unsupported':'Not available for this mode on this platform.','detail.na':'Selected networks only: system DNS is not checked in this mode.','detail.guard_off':'Selected networks only: no blocking when the VPN drops.',
 'detail.unknown':'No result from this check yet.','detail.off':'No session.','detail.connecting':'Waiting for the service.','detail.error':'The last connection attempt failed.',
 'home.profile':'Profile','home.default':'Default profile','home.backup':'Backup',
 'tile.mode':'Mode','tile.dns_sub':'DNS server','tile.sync':'Sync','tile.auto':'Autoconnect','tile.auto_sub':'when the app starts','tile.on':'On','tile.off':'Off','tile.unregistered':'not registered',
 'mode.full':'Whole device','mode.full_sub':'All IPv4, IPv6 and DNS through the tunnel','mode.tun':'Selected networks','mode.tun_sub':'Only the IPv4 networks you list','mode.socks':'Local proxy','mode.socks_sub':'SOCKS5 for apps you configure',
 'mode.full_tile':'all traffic','mode.tun_tile':'{n} IPv4 networks','mode.socks_tile':'port {port}',
 'profiles.search':'Name, server or protocol','profiles.add':'Add profile','profiles.col_profile':'Profile','profiles.col_protocol':'Protocol','profiles.col_state':'State',
 'profiles.hint':'Select a profile to see its actions. Connect uses the selected profile; automatic connection uses the default.',
 'profiles.empty':'No profiles yet. Add a file or link to get started.','profiles.no_match':'Nothing found.',
 'row.active':'active','row.selected':'selected','row.idle':'not active','badge.default':'Default','badge.backup':'Backup',
 'detail.server':'Server','detail.protocol':'Protocol','detail.role':'Role','detail.connection':'Connection','role.default':'default','role.backup':'backup','role.none':'—',
 'detail.select':'Use for Connect','detail.selected':'Selected for Connect','detail.make_default':'Make default','detail.is_default':'Default profile',
 'detail.export':'Export…','detail.export_note':'The exported file includes VPN credentials.','detail.upload':'Upload to server…',
 'detail.delete':'Delete…','detail.confirm_delete':'Delete: click again','detail.none':'Select a profile.',
 'add.title':'New profile','add.file_title':'Open a profile file','add.file_detail':'TrustTunnel, Hysteria 2 or AmneziaWG: TOML, YAML, JSON or .conf','add.file':'Choose file…',
 'add.paste_title':'Link or configuration text','add.paste_hint':'tt://, hy2:// or TOML / YAML / JSON','add.preview':'Preview import',
 'add.paste_note':'First we show what will be imported. A link never connects automatically.',
 'add.portal':'Connect to a server','add.portal_detail':'One-time code from the panel; profiles arrive by sync',
 'add.preview_title':'Import preview','add.preview_empty':'Choose a file or paste a link to see what will be imported.','add.import':'Import','add.name':'Name',
 'add.pending':'Confirm pending import','add.pending_note':'For a link opened from another app: its name is shown in the status line.',
 'add.vault':'Credentials are kept in the encrypted vault on this computer.',
 'diag.title':'Why does a service not open?','diag.target':'Hostname or IP (no URL or port)',
 'diag.note':'Uses the system resolver and sends one HTTPS HEAD request through the active VPN interface. No direct comparison or automatic upload. The result applies to one destination.',
 'diag.run':'Check current VPN path','diag.cancel':'Cancel','diag.endpoint':'Check VPN endpoint','diag.reconnect':'Reconnect and check again',
 'diag.rules_title':'Why the route is like this','diag.rules_detail':'The routing policy used by the last check: profile rules, exclusions or administrator routes.','diag.rules':'Review rules',
 'diag.report':'Preview and redact report','diag.report_note':'User additions are saved as entered. Remove sensitive details before export.','diag.replace':'Replace edits with latest report','diag.export':'Save locally…',
 'diag.none':'No check yet.','diag.checking':'Checking…','diag.historical':'Historical result · ','diag.age':'{s} seconds old',
 'net.lead':'Choose which traffic goes through the tunnel. Disconnect before changing settings.','net.mode':'Connection mode','net.port':'SOCKS port','net.networks':'IPv4 networks','net.dns':'DNS server','net.auto':'Connect on launch','net.save':'Save settings',
 'sync.lead':'Register this device with your server to download and upload profiles.','sync.address':'Portal HTTPS address','sync.code':'Enrollment code or invitation JSON','sync.name':'Device name',
 'sync.enroll':'Register device','sync.now':'Sync profiles now','sync.renew':'Renew portal access','sync.auto':'Background synchronization','sync.registration':'Registration',
 'sync.forget_note':'Forget this local registration. Downloaded VPN credentials have independent access; this does not revoke them on the server.','sync.forget':'Forget registration',
 'prefs.theme':'Theme','prefs.system':'System','prefs.system_sub':'Follows the system appearance','prefs.dark':'Dark','prefs.dark_sub':'Black background','prefs.light':'Light','prefs.light_sub':'Frosted glass',
 'prefs.language':'Language follows the system: Russian or English. Messages from the connection service may be in English.',
 'prefs.native':'Boot policy, updates, backup profiles and recovery controls are in the Native app.'
},ru:{
 'nav.sections':'Разделы','nav.home':'Главная','nav.profiles':'Профили','nav.checks':'Проверки','nav.network':'Сеть','nav.sync':'Синхронизация','nav.settings':'Настройки',
 'common.back':'Назад','working':'Выполняется…','connected':'Подключено','disconnected':'Отключено',
 'line.vpn':'VPN','line.tunnel':'Туннель','line.off':'выключен','line.connecting':'подключается','line.reconnecting':'переподключается','line.disconnecting':'отключается','line.running':'работает','line.verified':'проверен','line.warning1':'Нужно','line.warning2':'внимание','line.error1':'Нет','line.error2':'подключения','line.status':'Состояние','line.unavailable':'недоступно',
 'short.off':'VPN выключен','short.connecting':'Подключение…','short.reconnecting':'Переподключение…','short.disconnecting':'Отключение…','short.running':'Туннель работает','short.proxy':'Прокси работает','short.verified':'Туннель проверен','short.warning':'Нужно внимание','short.error':'Нет подключения','short.unavailable':'Состояние недоступно',
 'desc.off':'Туннель этого приложения не запущен. Подключите выбранный профиль «{name}».','desc.off_none':'Добавьте профиль, чтобы подключиться.',
 'desc.connecting':'Подключаемся к {host}.','desc.disconnecting':'Останавливаем туннель.',
 'desc.running':'Туннель работает. Пока нет свежего результата: {checks}. Это не значит, что они не работают.',
 'desc.running_partial':'Все проверки пройдены, но только для сетей, идущих через VPN; остальной трафик не охвачен, поэтому значок остаётся синим.',
 'desc.running_confirm':'Проверки пройдены; ждём подтверждения службы.',
 'desc.reconnecting':'Переподключаемся, чтобы проверить путь снова.',
 'desc.fallback':'Служба перешла с «{requested}» на резервный профиль.',
 'tag.backup':'резерв','live.backup':'Резервный профиль','home.active_backup':'Используется резерв','row.requested':'запрошен',
 'checks.sub_nohost':'{name} · результаты устаревают через {ttl} с',
 'mode.tun_managed':'маршруты сервера','net.managed':'Маршруты для этого устройства задаёт сервер; локальный список сетей не используется, пока действует эта политика.',
 'notice.conflict':'Профили или настройки изменились в другом месте (синхронизация или другое окно). Экран обновлён; повторите действие.',
 'desc.running_proxy':'Локальный прокси SOCKS5 запущен. Через туннель идут только приложения, настроенные на него; системный путь не проверяется.',
 'desc.verified':'Все пять проверок пройдены в последние секунды. Результаты устаревают — значок вернётся к синему, если их не повторить.',
 'desc.warning':'Туннель работает, но не пройдены проверки: {checks}. Откройте «Проверки», чтобы увидеть подробности.',
 'desc.error':'Подключение не установлено. Проверьте профиль и сеть, затем повторите.','desc.unavailable':'Приложение сейчас не может прочитать состояние подключения.',
 'action.connect':'Подключить «{name}»','action.add':'Сначала добавьте профиль','action.connecting':'Подключение…','action.reconnecting':'Переподключение…','action.disconnecting':'Отключение…','action.disconnect':'Отключить','action.retry':'Повторить подключение',
 'checks.eyebrow':'Проверки','checks.open':'Открыть проверки','checks.hint':'Проверки выполняет служба подключения. Проверка без результата показывается как «нет данных», а не «пройдено». Результаты устаревают через несколько секунд.',
 'checks.sub':'{name} · {host} · результаты устаревают через {ttl} с','checks.sub_none':'Нет активного сеанса',
 'check.transport':'Транспорт','check.route':'Маршрут','check.dns':'DNS','check.guard':'Защита','check.connectivity':'Доступность',
 'note.transport':'соединение с сервером','note.route':'маршруты VPN совпадают с профилем','note.dns':'ответы резолвера через туннель','note.guard':'блокировка трафика без VPN','note.connectivity':'один адрес через сеть VPN',
 'val.passed':'проверено','val.failed':'сбой','val.configured':'запущен','val.stale':'устарело','val.unsupported':'проверка не поддерживается','val.na':'не проверяется','val.guard_off':'не включена','val.unknown':'нет данных','val.off':'выключен','val.connecting':'подключение…','val.error':'сбой',
 'detail.passed':'Пройдено {age} с назад.','detail.failed':'Служба сообщила о сбое этой проверки.','detail.configured':'Запущено службой, ещё не проверено.',
 'detail.stale':'Последний результат устарел или сеть изменилась, поэтому он больше не учитывается.','detail.unsupported':'Недоступно для этого режима на этой платформе.','detail.na':'Только выбранные сети: системный DNS в этом режиме не проверяется.','detail.guard_off':'Только выбранные сети: блокировки при обрыве VPN нет.',
 'detail.unknown':'Результата этой проверки пока нет.','detail.off':'Нет сеанса.','detail.connecting':'Ждём службу.','detail.error':'Последняя попытка подключения не удалась.',
 'home.profile':'Профиль','home.default':'Профиль по умолчанию','home.backup':'Резерв',
 'tile.mode':'Режим','tile.dns_sub':'DNS-сервер','tile.sync':'Синхронизация','tile.auto':'Автоподключение','tile.auto_sub':'при запуске приложения','tile.on':'Включено','tile.off':'Выключено','tile.unregistered':'устройство не зарегистрировано',
 'mode.full':'Всё устройство','mode.full_sub':'Весь IPv4, IPv6 и DNS через туннель','mode.tun':'Выбранные сети','mode.tun_sub':'Только перечисленные сети IPv4','mode.socks':'Локальный прокси','mode.socks_sub':'SOCKS5 для настроенных приложений',
 'mode.full_tile':'весь трафик','mode.tun_tile':'сетей IPv4: {n}','mode.socks_tile':'порт {port}',
 'profiles.search':'Имя, сервер или протокол','profiles.add':'Добавить профиль','profiles.col_profile':'Профиль','profiles.col_protocol':'Протокол','profiles.col_state':'Состояние',
 'profiles.hint':'Выберите профиль, чтобы увидеть действия. «Подключить» использует выбранный профиль, автоподключение — профиль по умолчанию.',
 'profiles.empty':'Профилей пока нет. Добавьте файл или ссылку.','profiles.no_match':'Ничего не найдено.',
 'row.active':'активен','row.selected':'выбран','row.idle':'не активен','badge.default':'По умолчанию','badge.backup':'Резерв',
 'detail.server':'Сервер','detail.protocol':'Протокол','detail.role':'Роль','detail.connection':'Подключение','role.default':'по умолчанию','role.backup':'резерв','role.none':'—',
 'detail.select':'Выбрать для подключения','detail.selected':'Выбран для подключения','detail.make_default':'Сделать профилем по умолчанию','detail.is_default':'Профиль по умолчанию',
 'detail.export':'Экспортировать…','detail.export_note':'Экспортированный файл содержит учётные данные VPN.','detail.upload':'Загрузить на сервер…',
 'detail.delete':'Удалить…','detail.confirm_delete':'Удалить — нажмите ещё раз','detail.none':'Выберите профиль.',
 'add.title':'Новый профиль','add.file_title':'Открыть файл профиля','add.file_detail':'TrustTunnel, Hysteria 2 или AmneziaWG: TOML, YAML, JSON или .conf','add.file':'Выбрать файл…',
 'add.paste_title':'Ссылка или текст конфигурации','add.paste_hint':'tt://, hy2:// или TOML / YAML / JSON','add.preview':'Показать импорт',
 'add.paste_note':'Сначала покажем, что будет импортировано. Ссылка никогда не подключает автоматически.',
 'add.portal':'Подключить к серверу','add.portal_detail':'Одноразовый код из панели — профили приходят синхронизацией',
 'add.preview_title':'Предпросмотр импорта','add.preview_empty':'Выберите файл или вставьте ссылку, чтобы увидеть, что будет импортировано.','add.import':'Импортировать','add.name':'Имя',
 'add.pending':'Подтвердить ожидающий импорт','add.pending_note':'Для ссылки, открытой из другого приложения: её имя показано в строке состояния.',
 'add.vault':'Учётные данные хранятся в зашифрованном хранилище на этом компьютере.',
 'diag.title':'Почему не открывается сервис?','diag.target':'Имя хоста или IP (без URL и порта)',
 'diag.note':'Использует системный резолвер и отправляет один HTTPS-запрос HEAD через активный интерфейс VPN. Без прямого сравнения и автоматической отправки. Результат относится к одному адресу.',
 'diag.run':'Проверить текущий путь VPN','diag.cancel':'Отмена','diag.endpoint':'Проверить сервер VPN','diag.reconnect':'Переподключить и проверить снова',
 'diag.rules_title':'Почему маршрут такой','diag.rules_detail':'Политика маршрутизации последней проверки: правила профиля, исключения или маршруты администратора.','diag.rules':'Показать правила',
 'diag.report':'Предпросмотр и обезличивание отчёта','diag.report_note':'Ваши дополнения сохраняются как есть. Удалите чувствительные данные перед экспортом.','diag.replace':'Заменить правки последним отчётом','diag.export':'Сохранить локально…',
 'diag.none':'Проверок ещё не было.','diag.checking':'Проверяем…','diag.historical':'Прошлый результат · ','diag.age':'{s} с назад',
 'net.lead':'Выберите, какой трафик идёт через туннель. Перед изменением настроек отключитесь.','net.mode':'Режим подключения','net.port':'Порт SOCKS','net.networks':'Сети IPv4','net.dns':'DNS-сервер','net.auto':'Подключаться при запуске','net.save':'Сохранить настройки',
 'sync.lead':'Зарегистрируйте устройство на своём сервере, чтобы загружать и выгружать профили.','sync.address':'HTTPS-адрес портала','sync.code':'Код регистрации или JSON приглашения','sync.name':'Имя устройства',
 'sync.enroll':'Зарегистрировать устройство','sync.now':'Синхронизировать сейчас','sync.renew':'Продлить доступ к порталу','sync.auto':'Фоновая синхронизация','sync.registration':'Регистрация',
 'sync.forget_note':'Забыть локальную регистрацию. Загруженные учётные данные VPN действуют независимо; на сервере они не отзываются.','sync.forget':'Забыть регистрацию',
 'prefs.theme':'Тема','prefs.system':'Как в системе','prefs.system_sub':'Следует оформлению системы','prefs.dark':'Тёмная','prefs.dark_sub':'Чёрный фон','prefs.light':'Светлая','prefs.light_sub':'Матовое стекло',
 'prefs.language':'Язык следует системе: русский или английский. Сообщения службы подключения могут быть на английском.',
 'prefs.native':'Политика загрузки, обновления, резервные профили и восстановление настраиваются в приложении Native.'
}};
function t(key,vars){let s=T[LANG][key]??T.en[key]??key;if(vars)for(const[k,v]of Object.entries(vars))s=s.split('{'+k+'}').join(String(v));return s;}
function applyCopy(){
 document.documentElement.lang=LANG;
 document.querySelectorAll('[data-i18n]').forEach(e=>{e.textContent=t(e.dataset.i18n)});
 document.querySelectorAll('[data-i18n-ph]').forEach(e=>{e.placeholder=t(e.dataset.i18nPh)});
 document.querySelectorAll('[data-i18n-aria]').forEach(e=>{e.setAttribute('aria-label',t(e.dataset.i18nAria))});
 document.querySelectorAll('.nav-item').forEach(b=>{const label=b.querySelector('.nav-label');if(label)b.title=label.textContent});
}

/* ---------- Theme: system by default, optional local override ---------- */
function readTheme(){try{const v=localStorage.getItem('rt-theme');return v==='dark'||v==='light'?v:'system'}catch{return 'system'}}
function applyTheme(choice){
 if(choice==='dark'||choice==='light')document.documentElement.dataset.theme=choice;else delete document.documentElement.dataset.theme;
 document.querySelectorAll('[name=theme-choice]').forEach(r=>{r.checked=r.value===choice});
}
document.querySelectorAll('[name=theme-choice]').forEach(r=>r.onchange=()=>{try{localStorage.setItem('rt-theme',r.value)}catch{}applyTheme(r.value)});

/* ---------- Helpers ---------- */
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
function button(text,action,cls){const b=el('button',cls||'btn',text);b.type='button';b.onclick=()=>run(action);return b;}
function code(p){const s=String(p?.protocol||'');return /hysteria/i.test(s)?'H2':/amnezia|wireguard/i.test(s)?'AW':'TT';}
function avatarClass(p){return {H2:'violet',AW:'orange',TT:'blue'}[code(p)];}
function setAvatar(node,p){node.textContent=p?code(p):'—';node.className='avatar '+(p?avatarClass(p):'');}
// The profile the session really runs on: after failover the service may use a backup.
function live(){
 const profiles=state?.profiles||[];
 if(!state?.connected){const p=profiles[selected];return {p,name:p?.name||'',host:p?.hostname||'',fallback:false,requested:null};}
 const requested=profiles[state.connected_profile]||null,fallback=state.on_fallback===true;
 if(Number.isInteger(state.active_profile)){const p=profiles[state.active_profile];if(p)return {p,name:p.name,host:p.hostname,fallback,requested};}
 if(fallback)return {p:null,name:t('live.backup'),host:'',fallback,requested};
 return {p:requested,name:requested?.name||'',host:requested?.hostname||'',fallback,requested};
}
function backupNames(){return Array.isArray(state?.connection?.fallback_profiles)?state.connection.fallback_profiles:[];}
function snapshotInput(){return {connected:!!state?.connected,verified:state?.verified===true,full:state?.connection?.mode==='Full',snapshot:state?.observations,phase,error:connectError,unavailable,now:Date.now()};}
// The last action's error or notice stays visible on every page until the next
// action or navigation; the background poll does not overwrite it.
function setNotice(text,expire){
 clearTimeout(noticeTimer);noticeTimer=null;notice=text;noticeBase=undefined;
 if(text&&expire)noticeTimer=setTimeout(clearNotice,expire);
}
function clearNotice(){
 clearTimeout(noticeTimer);noticeTimer=null;
 if(notice&&$('status').textContent===notice)$('status').textContent='';
 notice='';noticeBase=undefined;
}
function goto(page){
 clearNotice();
 // Leaving a page discards unsaved Network/Sync edits so every page shows stored values.
 if(dirty.size){dirty.clear();if(state)fillForms();}
 document.querySelectorAll('main>section').forEach(s=>{s.hidden=s.id!==page});
 const nav=page==='add-page'?'profiles-page':page;
 document.querySelectorAll('.nav-item').forEach(b=>{if(b.dataset.page===nav)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')});
 document.querySelector('main').scrollTop=0;
}
document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>goto(b.dataset.page));
document.querySelectorAll('[data-goto]').forEach(b=>b.onclick=()=>goto(b.dataset.goto));

/* ---------- Status ---------- */
function renderStatus(){
 const input=snapshotInput(),key=M.derive(input),tone=M.TONE[key];
 document.body.dataset.state=key;document.body.dataset.tone=tone;
 const profiles=state?.profiles||[],L=live(),name=L.name,host=L.host,reconnecting=phase==='reconnecting';
 const proxy=state?.connection?.mode==='Socks';
 const lines={off:['line.vpn','line.off'],connecting:['line.tunnel',reconnecting?'line.reconnecting':'line.connecting'],disconnecting:['line.tunnel','line.disconnecting'],running:['line.tunnel','line.running'],verified:['line.tunnel','line.verified'],warning:['line.warning1','line.warning2'],error:unavailable?['line.status','line.unavailable']:['line.error1','line.error2']}[key];
 $('line1').textContent=t(lines[0]);$('line2').textContent=t(lines[1]);
 const short=unavailable?t('short.unavailable'):key==='running'&&proxy?t('short.proxy'):key==='connecting'&&reconnecting?t('short.reconnecting'):t('short.'+key);
 $('state-tag').textContent=key==='off'||!name?short:`${name}${L.fallback&&L.p?' · '+t('tag.backup'):''} · ${short}`;
 $('side-state').textContent=short;$('checks-short').textContent=short;
 let desc;
 if(key==='off')desc=profiles.length?t('desc.off',{name}):t('desc.off_none');
 else if(key==='connecting')desc=reconnecting?t('desc.reconnecting'):t('desc.connecting',{host});
 else if(key==='running'){
  const missing=M.pending(state?.observations,input.now);
  desc=proxy?t('desc.running_proxy'):missing.length?t('desc.running',{checks:missing.map(k=>t('check.'+k)).join(', ')}):!input.full?t('desc.running_partial'):t('desc.running_confirm');
 }
 else if(key==='warning')desc=t('desc.warning',{checks:M.failed(state?.observations,input.now).map(k=>t('check.'+k)).join(', ')});
 else if(key==='error')desc=unavailable?t('desc.unavailable'):t('desc.error');
 else desc=t('desc.'+key);
 if(L.fallback&&['running','verified','warning'].includes(key)&&L.requested)desc+=' '+t('desc.fallback',{requested:L.requested.name});
 $('state-desc').textContent=desc;
 const connected=!!state?.connected;
 $('connect-label').textContent=key==='connecting'?t(reconnecting?'action.reconnecting':'action.connecting'):key==='disconnecting'?t('action.disconnecting'):connected?t('action.disconnect'):!profiles.length?t('action.add'):key==='error'?t('action.retry'):t('action.connect',{name});
 $('connect').classList.toggle('is-connected',connected);
 $('checks-sub').textContent=!connected?t('checks.sub_none'):host?t('checks.sub',{name,host,ttl:M.ttlLabel(input.snapshot)}):t('checks.sub_nohost',{name,ttl:M.ttlLabel(input.snapshot)});
 renderChecks(input,key);
}
function checkValue(value){return t('val.'+value);}
function renderChecks(input,key){
 const rows=M.rows(input,key),home=$('home-checks'),detail=$('checks-detail');home.replaceChildren();detail.replaceChildren();
 for(const r of rows){
  const tone=M.ROW_TONE[r.value]||'ring';
  const a=el('div','check-row');a.append(el('span','cdot '+tone),el('b','check-name',t('check.'+r.key)),el('span','check-note',t('note.'+r.key)),el('span','check-value v-'+tone,checkValue(r.value)));home.append(a);
  const b=el('div','check-row');const body=el('div','check-body'),head=el('div','check-head');head.append(el('b','check-name',t('check.'+r.key)),el('span','check-value v-'+tone,checkValue(r.value)));
  let extra=t('detail.'+r.value);
  if(r.value==='passed'){const at=state?.observations?.[r.key]?.observed_at_ms;extra=t('detail.passed',{age:Math.max(0,Math.round((input.now-at)/1000))});}
  body.append(head,el('small','',`${t('note.'+r.key)}. ${extra}`));b.append(el('span','cdot '+tone),body);detail.append(b);
 }
}

/* ---------- Home cards ---------- */
function renderHome(){
 if(!state)return;
 const profiles=state.profiles,L=live(),p=L.p;
 setAvatar($('profile-code'),p);
 $('profile-eyebrow').textContent=L.fallback?t('home.active_backup'):p?.default?t('home.default'):t('home.profile');
 $('default-name').textContent=p?.name||(L.fallback?L.name:t('desc.off_none'));
 $('profile-sub').textContent=p?`${p.protocol} · ${p.hostname}`:'';
 const backupName=backupNames().find(n=>n!==p?.name&&n!==L.requested?.name),backup=profiles.find(x=>x.name===backupName);
 $('backup-card').hidden=!backup;
 if(backup){setAvatar($('backup-code'),backup);$('backup-name').textContent=backup.name;$('backup-sub').textContent=`${backup.protocol} · ${backup.hostname}`;}
 const c=state.connection;
 $('tile-mode').textContent=t({Full:'mode.full',Tun:'mode.tun',Socks:'mode.socks'}[c.mode]||'mode.full');
 $('tile-mode-sub').textContent=c.mode==='Socks'?t('mode.socks_tile',{port:c.socks_port}):c.mode==='Tun'?(c.managed_routes?t('mode.tun_managed'):t('mode.tun_tile',{n:(c.networks||[]).length})):t('mode.full_tile');
 $('tile-dns').textContent=String(c.dns||'—');
 $('tile-sync').textContent=c.sync?.enabled?t('tile.on'):t('tile.off');
 let origin='';try{origin=c.sync?.origin?new URL(c.sync.origin).host:''}catch{origin=''}
 $('tile-sync-sub').textContent=origin||t('tile.unregistered');
 $('tile-auto').textContent=c.auto_connect?t('tile.on'):t('tile.off');
}

/* ---------- Profiles ---------- */
function rowStatus(index){
 if(state.connected&&state.active_profile===index)return ['active',t('row.active')];
 if(state.connected&&state.on_fallback&&state.connected_profile===index)return ['idle',t('row.requested')];
 if(!state.connected&&index===selected)return ['selected',t('row.selected')];
 return ['idle',t('row.idle')];
}
function renderProfiles(){
 if(!state)return;
 const list=$('profiles'),q=$('profile-search').value.trim().toLowerCase(),backups=backupNames();list.replaceChildren();
 if(!state.profiles.length){list.append(el('p','empty',t('profiles.empty')));renderDetail();return;}
 let shown=0;
 state.profiles.forEach((p,index)=>{
  if(q&&![p.name,p.hostname,p.protocol].some(s=>String(s).toLowerCase().includes(q)))return;
  shown++;
  const row=el('button','prow');row.type='button';if(index===selected)row.setAttribute('aria-current','true');
  const av=el('span','avatar');setAvatar(av,p);
  const info=el('span','prow-info'),title=el('b');title.append(el('span','',p.name));
  if(p.default)title.append(el('span','badge',t('badge.default')));
  if(backups.includes(p.name))title.append(el('span','badge soft',t('badge.backup')));
  info.append(title,el('small','',p.hostname));
  const [kind,label]=rowStatus(index),st=el('span','prow-state '+kind);st.append(el('span','dot'),el('span','',label));
  row.append(av,info,el('span','prow-proto',p.protocol),st);
  row.onclick=()=>{selected=index;disarm();renderProfiles();renderHome();renderStatus();};
  list.append(row);
 });
 if(!shown)list.append(el('p','empty',t('profiles.no_match')));
 renderDetail();
}
function disarm(){if(armedDelete){clearTimeout(armedDelete.timer);armedDelete=null;}}
function deleteButton(index){
 const armed=armedDelete?.index===index;
 const b=el('button','btn danger wide',armed?t('detail.confirm_delete'):t('detail.delete'));b.type='button';
 b.onclick=()=>{
  if(armedDelete?.index!==index){disarm();armedDelete={index,timer:setTimeout(()=>{armedDelete=null;renderDetail()},5000)};renderDetail();return;}
  disarm();
  run(async()=>{await invoke('edit_profile',{revision:state.revision,index,action:'delete'});if(index<selected)selected--;else if(index===selected)selected=0});
 };
 return b;
}
function renderDetail(){
 const box=$('profile-detail');box.replaceChildren();
 const p=state?.profiles?.[selected];
 if(!p){box.append(el('p','muted',t('detail.none')));return;}
 const index=selected,head=el('div','detail-head'),av=el('span','avatar big');setAvatar(av,p);
 const names=el('div','detail-names');names.append(el('b','detail-title',p.name),el('small','',p.default?t('home.default'):backupNames().includes(p.name)?t('role.backup'):''));
 head.append(av,names);
 const rows=el('div','kv');
 const role=p.default?t('role.default'):backupNames().includes(p.name)?t('role.backup'):t('role.none');
 for(const [k,v] of [[t('detail.server'),p.hostname],[t('detail.protocol'),p.protocol],[t('detail.role'),role],[t('detail.connection'),rowStatus(index)[1]]]){const r=el('div','kv-row');r.append(el('span','muted',k),el('b','',v));rows.append(r);}
 const actions=el('div','detail-actions');
 const select=el('button','btn wide',t(index===selected?'detail.selected':'detail.select'));select.type='button';select.dataset.off=index===selected?'1':'0';
 select.onclick=()=>{selected=index;renderProfiles();renderHome();renderStatus();};
 const makeDefault=button(p.default?t('detail.is_default'):t('detail.make_default'),async()=>{await invoke('edit_profile',{revision:state.revision,index,action:'default'});selected=selected===index?0:selected<index?selected+1:selected},'btn wide');
 makeDefault.dataset.off=p.default?'1':'0';
 const exp=button(t('detail.export'),()=>invoke('export_profile',{revision:state.revision,index}),'btn wide');
 const upload=button(t('detail.upload'),()=>invoke('portal_upload',{revision:state.revision,index}),'btn wide');
 actions.append(select,makeDefault,exp,el('small','muted',t('detail.export_note')),upload,deleteButton(index));
 box.append(head,rows,actions);
 applyDisabled();
}

/* ---------- Import ---------- */
function preview(p){
 const box=$('preview');box.replaceChildren();
 if(!p){box.append(el('p','muted',t('add.preview_empty')));return;}
 const rows=el('div','kv');
 for(const [k,v] of [[t('add.name'),p.name],[t('detail.server'),p.hostname],[t('detail.protocol'),p.protocol]]){const r=el('div','kv-row');r.append(el('span','muted',k),el('b','',v));rows.append(r);}
 const row=el('div','row');row.append(button(t('add.import'),async()=>{await invoke('commit_import',{revision:state.revision});preview(null)},'btn primary'));
 box.append(rows,row);
}

/* ---------- Actions ---------- */
// Fields the user edited keep their values across refreshes (including a
// revision-conflict reload) until their own form is saved successfully.
const NETWORK_FIELDS=['mode','port','networks','dns','auto'],SYNC_FIELDS=['address'];
const dirty=new Set();
for(const id of ['port','networks','dns','auto','address'])$(id).addEventListener('input',()=>dirty.add(id));
$('auto').addEventListener('change',()=>dirty.add('auto'));
function clean(ids){ids.forEach(id=>dirty.delete(id));}
function fillForms(){
 const c=state.connection,set=(id,fn)=>{if(!dirty.has(id))fn();};
 set('auto',()=>{$('auto').checked=c.auto_connect});
 $('syncauto').checked=c.sync.enabled;
 set('mode',()=>{$('mode').value=c.mode;document.querySelectorAll('[name=mode-choice]').forEach(r=>r.checked=r.value===c.mode)});
 set('port',()=>{$('port').value=c.socks_port});
 set('networks',()=>{$('networks').value=c.networks.join(', ')});
 set('dns',()=>{$('dns').value=c.dns});
 set('address',()=>{$('address').value=c.sync.origin});
 $('networks-managed').hidden=!c.managed_routes;modeFields();
}
async function refresh(){
 state=await invoke('view',{russian:LANG==='ru'});unavailable=false;
 selected=Math.min(selected,Math.max(0,state.profiles.length-1));
 lastListKey=listKey();
 fillForms();renderAll();
}
function renderAll(){renderStatus();renderHome();renderProfiles();renderDiagnostics();applyDisabled();}
function setButtons(disabled){document.querySelectorAll('main button').forEach(b=>{if(!b.dataset.goto)b.disabled=disabled})}
function applyDisabled(){
 if(busy)return;
 $('connect').disabled=!state||(!state.connected&&!state.profiles.length);
 document.querySelectorAll('main [data-off]').forEach(b=>{b.disabled=b.dataset.off==='1'});
 renderDiagnostics();
}
async function run(action,opts={}){
 if(busy)return;busy=true;actionGen++;clearNotice();phase=opts.phase||null;document.body.classList.add('is-busy');setButtons(true);
 $('status').textContent=t('working');renderStatus();
 try{
  await action();
  phase=null;
  if(opts.phase)connectError=null;
  await refresh();
  $('status').textContent=state.status||(state.connected?t('connected'):t('disconnected'));
 }catch(e){
  phase=null;
  if(/^Profiles changed/.test(String(e))){
   // Another frontend or background sync bumped the revision: reload, do not show a failure state.
   try{await refresh();setNotice(t('notice.conflict'),15000);$('status').textContent=notice;}catch(r){setNotice(String(r));$('status').textContent=notice;}
  }else{
   if(opts.phase==='connecting'||opts.phase==='reconnecting')connectError=String(e);
   setNotice(String(e));$('status').textContent=notice;
  }
 }finally{
  phase=null;busy=false;document.body.classList.remove('is-busy');setButtons(false);
  if(state)renderStatus();applyDisabled();
 }
}
$('connect').onclick=()=>{
 if(!state)return;
 if(state.connected)run(()=>invoke('disconnect'),{phase:'disconnecting'});
 else run(()=>invoke('connect',{revision:state.revision,index:selected}),{phase:'connecting'});
};
$('paste').onclick=()=>run(async()=>{let input=$('input').value;$('input').value='';preview(await invoke('preview',{input}));input=''});
$('file').onclick=()=>run(async()=>preview(await invoke('pick_import')));
$('pending').onclick=()=>run(()=>invoke('commit_import',{revision:state.revision}));
$('save').onclick=()=>run(async()=>{await invoke('save_settings',{revision:state.revision,settings:{...state.connection,auto_connect:$('auto').checked,mode:$('mode').value,socks_port:Number($('port').value),networks:$('networks').value.split(',').map(s=>s.trim()).filter(Boolean),dns:$('dns').value}});clean(NETWORK_FIELDS)});
$('enroll').onclick=()=>run(async()=>{const code=$('code').value;$('code').value='';await invoke('portal_enroll',{revision:state.revision,address:$('address').value,code,name:$('name').value});clean(SYNC_FIELDS)});
$('sync').onclick=()=>run(()=>invoke('portal_sync',{revision:state.revision}));
$('forget').onclick=()=>run(async()=>{await invoke('portal_forget',{revision:state.revision});clean(SYNC_FIELDS)});
$('renew').onclick=()=>run(()=>invoke('portal_renew',{revision:state.revision}));
$('syncauto').onchange=()=>run(()=>invoke('portal_auto',{revision:state.revision,enabled:$('syncauto').checked}));
$('profile-search').oninput=()=>renderProfiles();
function modeFields(){$('port-field').hidden=$('mode').value!=='Socks';$('networks-field').hidden=$('mode').value!=='Tun';}
document.querySelectorAll('[name=mode-choice]').forEach(r=>r.onchange=()=>{dirty.add('mode');$('mode').value=r.value;modeFields();});

applyCopy();applyTheme(readTheme());preview(null);
run(async()=>{}).then(()=>{if(state)invoke('ui_ready').catch(e=>{$('status').textContent=String(e)})});

// Refresh evidence without replacing editable settings, profile inputs or the revision.
function listKey(){return `${state?.connected}|${state?.connected_profile}|${state?.active_profile}|${state?.on_fallback}`;}
setInterval(async()=>{
 if(!state)return;
 // While an action runs, do not fetch, but let results decay by the clock.
 if(busy||polling){renderStatus();return;}
 // A reply that was in flight when an action started is older than that action's refresh.
 const gen=actionGen;polling=true;
 try{
  const next=await invoke('view',{russian:LANG==='ru'});
  if(busy||gen!==actionGen)return;
  state.connected=next.connected;state.verified=next.verified;state.observations=next.observations;state.status=next.status;state.diagnostics=next.diagnostics;state.connected_profile=next.connected_profile;state.active_profile=next.active_profile;state.on_fallback=next.on_fallback;
  unavailable=false;if(state.connected)connectError=null;
  const line=M.statusLine({notice,noticeBase,status:state.status,connected:state.connected,connectError});
  if(line.keepNotice)noticeBase=line.noticeBase;else if(notice)clearNotice();
  $('status').textContent=line.text;
  const key=listKey();if(key!==lastListKey){lastListKey=key;renderHome();renderProfiles();}
 }catch{if(busy||gen!==actionGen)return;unavailable=true;}
 finally{polling=false;}
 renderStatus();applyDisabled();
},2000);

/* ---------- Diagnostics ---------- */
function renderDiagnostics(){
 const d=state?.diagnostics;if(!d)return;
 $('diagnostic-result').textContent=d.running?t('diag.checking'):d.summary?`${d.historical?t('diag.historical'):''}${t('diag.age',{s:Math.floor((d.age_ms||0)/1000)})} · ${d.verdict?.cause||''} · ${d.summary}`:t('diag.none');
 if(busy)return;
 $('diagnostic-endpoint').disabled=d.running||d.historical||!d.verdict?.actions.includes('check_endpoint');
 $('diagnostic-run').disabled=d.running||!state.connected||state.connection.mode==='Socks';
 $('diagnostic-reconnect').disabled=d.running||d.historical||!d.verdict?.actions.includes('reconnect');
 $('diagnostic-rules').disabled=!d.report?.policy;
 if(document.activeElement!==$('diagnostic-preview'))$('diagnostic-preview').value=d.export||'';
}
$('diagnostic-run').onclick=()=>run(()=>invoke('diagnostic_start',{target:$('diagnostic-target').value,action:'recheck'}));
$('diagnostic-endpoint').onclick=()=>run(()=>invoke('diagnostic_start',{target:$('diagnostic-target').value,action:'check_endpoint'}));
$('diagnostic-reconnect').onclick=()=>run(()=>invoke('diagnostic_start',{target:$('diagnostic-target').value,action:'reconnect'}),{phase:'reconnecting'});
$('diagnostic-cancel').onclick=()=>run(()=>invoke('diagnostic_cancel'));
$('diagnostic-target').oninput=()=>invoke('diagnostic_cancel').catch(e=>{$('diagnostic-result').textContent=String(e)});
$('diagnostic-preview').onchange=()=>invoke('diagnostic_edit',{text:$('diagnostic-preview').value}).catch(e=>{$('diagnostic-result').textContent=String(e)});
$('diagnostic-replace').onclick=()=>run(()=>invoke('diagnostic_replace'));
$('diagnostic-export').onclick=()=>run(async()=>{await invoke('diagnostic_edit',{text:$('diagnostic-preview').value});await invoke('diagnostic_export')});
$('diagnostic-rules').onclick=()=>{$('diagnostic-policy').textContent=JSON.stringify(state?.diagnostics?.report?.policy,null,2)};
