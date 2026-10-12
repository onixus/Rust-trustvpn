'use strict';
const $=id=>document.getElementById(id),invoke=window.__TAURI__.core.invoke;let state,busy=false,selected=0;
function button(text,action){const b=document.createElement('button');b.textContent=text;b.onclick=()=>run(action);return b;}
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
// Rust supplies the evidence verdict; connection lifecycle alone is not proof.
function setConnected(on){const mode=state?.connection?.mode,full=mode==='Full';$('connect').textContent=on?'Disconnect':'Connect';$('connect').classList.toggle('connected',on);document.body.classList.toggle('is-connected',on&&full&&state.verified);document.body.classList.toggle('is-partial',on&&(!full||!state.verified));$('state-label').textContent=!on?'Disconnected':state.verified?'Checks passed':mode==='Socks'?'Proxy active · system path unchecked':'Transport active · checks incomplete';}
async function refresh(){state=await invoke('view');selected=Math.min(selected,Math.max(0,state.profiles.length-1));setConnected(state.connected);$('default-name').textContent=state.profiles[selected]?.name||'Add your first profile';$('profiles').replaceChildren();if(!state.profiles.length){const empty=document.createElement('p');empty.textContent='No profiles yet. Add a file or link to get started.';$('profiles').append(empty);$('import-panel').open=true;}state.profiles.forEach((p,index)=>{const row=el('div','profile'+(index===selected?' selected':''));const hy2=/hysteria/i.test(p.protocol);const avatar=el('div','avatar'+(hy2?' hy2':''),(p.name.trim()[0]||'?').toUpperCase());const title=el('strong'),host=el('small');title.append(el('span','',p.name));if(p.default)title.append(el('span','badge','Default'));host.append(el('span','badge proto',p.protocol),el('span','',p.hostname));const info=el('div','profile-info'),actions=el('div','profile-actions');info.append(title,host);const makeDefault=button(p.default?'Default':'Make default',async()=>{await invoke('edit_profile',{revision:state.revision,index,action:'default'});selected=selected===index?0:selected<index?selected+1:selected});if(p.default)makeDefault.classList.add('is-default');actions.append(button(index===selected?'Selected':'Select',async()=>{selected=index}),makeDefault,button('Export',()=>invoke('export_profile',{revision:state.revision,index})),button('Upload',()=>invoke('portal_upload',{revision:state.revision,index})),deleteButton(index));row.append(avatar,info,actions);$('profiles').append(row)});const c=state.connection;$('auto').checked=c.auto_connect;$('syncauto').checked=c.sync.enabled;$('mode').value=c.mode;document.querySelectorAll('[name=mode-choice]').forEach(r=>r.checked=r.value===c.mode);$('port').value=c.socks_port;$('networks').value=c.networks.join(', ');$('dns').value=c.dns;$('address').value=c.sync.origin;modeFields();renderDiagnostics();}
async function run(action){if(busy)return;busy=true;document.body.classList.add('is-busy');document.querySelectorAll('button').forEach(b=>b.disabled=true);$('status').textContent='Working…';try{await action();await refresh();$('status').textContent=state.status||(state.connected?'Connected':'Disconnected');}catch(e){$('status').textContent=String(e)}finally{busy=false;document.body.classList.remove('is-busy');document.querySelectorAll('button').forEach(b=>b.disabled=false);$('connect').disabled=!state||(!state.connected&&!state.profiles.length);renderDiagnostics()}}
function preview(p){$('preview').replaceChildren();if(!p)return;const text=document.createElement('p');text.textContent=`Import ${p.name} (${p.hostname})?`;$('preview').append(text,button('Confirm import',async()=>{await invoke('commit_import',{revision:state.revision});$('preview').replaceChildren()}));}
$('connect').onclick=()=>run(()=>invoke(state.connected?'disconnect':'connect',{revision:state.revision,index:selected}));
$('paste').onclick=()=>run(async()=>{let input=$('input').value;$('input').value='';preview(await invoke('preview',{input}));input=''});
$('file').onclick=()=>run(async()=>preview(await invoke('pick_import')));
$('save').onclick=()=>run(()=>invoke('save_settings',{revision:state.revision,settings:{...state.connection,auto_connect:$('auto').checked,mode:$('mode').value,socks_port:Number($('port').value),networks:$('networks').value.split(',').map(s=>s.trim()).filter(Boolean),dns:$('dns').value}}));
$('enroll').onclick=()=>run(async()=>{const code=$('code').value;$('code').value='';await invoke('portal_enroll',{revision:state.revision,address:$('address').value,code,name:$('name').value})});
$('sync').onclick=()=>run(()=>invoke('portal_sync',{revision:state.revision}));$('forget').onclick=()=>run(()=>invoke('portal_forget',{revision:state.revision}));
$('renew').onclick=()=>run(()=>invoke('portal_renew',{revision:state.revision}));
run(async()=>{}).then(()=>{if(state)invoke('ui_ready').catch(e=>{$('status').textContent=String(e)})});

$('pending').onclick=()=>run(()=>invoke('commit_import',{revision:state.revision}));
$('syncauto').onchange=()=>run(()=>invoke('portal_auto',{revision:state.revision,enabled:$('syncauto').checked}));

function modeFields(){ $('port-field').hidden=$('mode').value!=='Socks';$('networks-field').hidden=$('mode').value!=='Tun'; }
document.querySelectorAll('[name=mode-choice]').forEach(r=>r.onchange=()=>{$('mode').value=r.value;modeFields();});
document.querySelectorAll('[data-page]').forEach(tab=>tab.onclick=()=>{
 document.querySelectorAll('main>section').forEach(page=>page.hidden=page.id!==tab.dataset.page);
 document.querySelectorAll('[data-page]').forEach(other=>{if(other===tab)other.setAttribute('aria-current','page');else other.removeAttribute('aria-current');});
});

function deleteButton(index){const b=el('button','danger','Delete…');let armed=false;b.onclick=()=>{if(!armed){armed=true;b.textContent='Confirm delete';setTimeout(()=>{armed=false;b.textContent='Delete…'},5000);return;}run(async()=>{await invoke('edit_profile',{revision:state.revision,index,action:'delete'});if(index<selected)selected--;else if(index===selected)selected=0});};return b;}

// Refresh evidence without replacing editable settings or profile inputs.
setInterval(async()=>{if(busy||!state)return;try{const next=await invoke('view');state.connected=next.connected;state.verified=next.verified;state.observations=next.observations;state.status=next.status;state.diagnostics=next.diagnostics;renderDiagnostics();setConnected(state.connected);$('status').textContent=state.status;}catch{$('state-label').textContent='Status unavailable';document.body.classList.remove('is-connected');}},2000);

function renderDiagnostics(){
 const d=state?.diagnostics;if(!d)return;
 $('diagnostic-result').textContent=d.running?'Checking…':d.summary?`${d.historical?'Historical result · ':''}${Math.floor((d.age_ms||0)/1000)} seconds old · ${d.verdict?.cause||''} · ${d.summary}`:'No check yet.';
 $('diagnostic-endpoint').disabled=d.running||d.historical||!d.verdict?.actions.includes('check_endpoint');
 $('diagnostic-run').disabled=d.running||!state.connected||state.connection.mode==='Socks';
 $('diagnostic-reconnect').disabled=d.running||d.historical||!d.verdict?.actions.includes('reconnect');
 $('diagnostic-rules').disabled=!d.report?.policy;
 if(document.activeElement!==$('diagnostic-preview'))$('diagnostic-preview').value=d.export||'';
}
$('diagnostic-run').onclick=()=>run(()=>invoke('diagnostic_start',{target:$('diagnostic-target').value,action:'recheck'}));
$('diagnostic-endpoint').onclick=()=>run(()=>invoke('diagnostic_start',{target:$('diagnostic-target').value,action:'check_endpoint'}));
$('diagnostic-cancel').onclick=()=>run(()=>invoke('diagnostic_cancel'));
$('diagnostic-target').oninput=()=>invoke('diagnostic_cancel').catch(e=>{$('diagnostic-result').textContent=String(e)});
$('diagnostic-preview').onchange=()=>invoke('diagnostic_edit',{text:$('diagnostic-preview').value}).catch(e=>{$('diagnostic-result').textContent=String(e)});
$('diagnostic-replace').onclick=()=>run(()=>invoke('diagnostic_replace'));
$('diagnostic-export').onclick=()=>run(async()=>{await invoke('diagnostic_edit',{text:$('diagnostic-preview').value});await invoke('diagnostic_export')});
$('diagnostic-rules').onclick=()=>{$('diagnostic-policy').textContent=JSON.stringify(state?.diagnostics?.report?.policy,null,2)};

$('diagnostic-reconnect').onclick=()=>run(()=>invoke('diagnostic_start',{target:$('diagnostic-target').value,action:'reconnect'}));
