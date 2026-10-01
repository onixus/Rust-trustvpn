'use strict';
const $=id=>document.getElementById(id),invoke=window.__TAURI__.core.invoke;let state,busy=false;
function button(text,action){const b=document.createElement('button');b.textContent=text;b.onclick=()=>run(action);return b;}
async function refresh(){state=await invoke('view');$('connect').textContent=state.connected?'Disconnect':'Connect';$('connect').classList.toggle('connected',state.connected);$('default-name').textContent=state.profiles.find(p=>p.default)?.name||'Add your first profile';$('profiles').replaceChildren();if(!state.profiles.length){const empty=document.createElement('p');empty.textContent='No profiles yet. Add a file or link to get started.';$('profiles').append(empty);$('import-panel').open=true;}state.profiles.forEach((p,index)=>{const row=document.createElement('div');row.className='profile'+(p.default?' default':'');const title=document.createElement('strong'),host=document.createElement('small');title.textContent=(p.default?'★ ':'')+p.name;host.textContent=p.hostname+" · "+p.protocol;const info=document.createElement('div'),actions=document.createElement('div');info.className='profile-info';actions.className='profile-actions';info.append(title,host);actions.append(button(p.default?'Default profile':'Use as default',()=>invoke('edit_profile',{revision:state.revision,index,action:'default'})),button('Export',()=>invoke('export_profile',{revision:state.revision,index})),button('Upload',()=>invoke('portal_upload',{revision:state.revision,index})),deleteButton(index));row.append(info,actions);$('profiles').append(row)});const c=state.connection;$('auto').checked=c.auto_connect;$('syncauto').checked=c.sync.enabled;$('mode').value=c.mode;$('port').value=c.socks_port;$('networks').value=c.networks.join(', ');$('dns').value=c.dns;$('address').value=c.sync.origin;modeFields();}
async function run(action){if(busy)return;busy=true;document.querySelectorAll('button').forEach(b=>b.disabled=true);$('status').textContent='Working…';try{await action();await refresh();$('status').textContent=state.status||(state.connected?'Connected':'Disconnected');}catch(e){$('status').textContent=String(e)}finally{busy=false;document.querySelectorAll('button').forEach(b=>b.disabled=false);$('connect').disabled=!state||(!state.connected&&!state.profiles.length)}}
function preview(p){$('preview').replaceChildren();if(!p)return;const text=document.createElement('p');text.textContent=`Import ${p.name} (${p.hostname})?`;$('preview').append(text,button('Confirm import',async()=>{await invoke('commit_import',{revision:state.revision});$('preview').replaceChildren()}));}
$('connect').onclick=()=>run(()=>invoke(state.connected?'disconnect':'connect',{revision:state.revision}));
$('paste').onclick=()=>run(async()=>{let input=$('input').value;$('input').value='';preview(await invoke('preview',{input}));input=''});
$('file').onclick=()=>run(async()=>preview(await invoke('pick_import')));
$('save').onclick=()=>run(()=>invoke('save_settings',{revision:state.revision,settings:{...state.connection,auto_connect:$('auto').checked,mode:$('mode').value,socks_port:Number($('port').value),networks:$('networks').value.split(',').map(s=>s.trim()).filter(Boolean),dns:$('dns').value}}));
$('enroll').onclick=()=>run(async()=>{const code=$('code').value;$('code').value='';await invoke('portal_enroll',{revision:state.revision,address:$('address').value,code,name:$('name').value})});
$('sync').onclick=()=>run(()=>invoke('portal_sync',{revision:state.revision}));$('forget').onclick=()=>run(()=>invoke('portal_forget',{revision:state.revision}));
run(async()=>{}).then(()=>{if(state)invoke('ui_ready').catch(e=>{$('status').textContent=String(e)})});

$('pending').onclick=()=>run(()=>invoke('commit_import',{revision:state.revision}));
$('syncauto').onchange=()=>run(()=>invoke('portal_auto',{revision:state.revision,enabled:$('syncauto').checked}));

// Poll connection health without replacing form edits or profile revisions.
setInterval(async()=>{if(busy)return;try{const current=await invoke('view');$('connect').textContent=current.connected?'Disconnect':'Connect';$('connect').classList.toggle('connected',current.connected);if(state)state.connected=current.connected;$('status').textContent=current.status||(current.connected?'Connected':'Disconnected');}catch(e){$('status').textContent=String(e)}},3000);

function modeFields(){ $('port-field').hidden=$('mode').value!=='Socks';$('networks-field').hidden=$('mode').value!=='Tun'; }
$('mode').onchange=modeFields;
document.querySelectorAll('[data-page]').forEach(tab=>tab.onclick=()=>{
 document.querySelectorAll('main>section').forEach(page=>page.hidden=page.id!==tab.dataset.page);
 document.querySelectorAll('[data-page]').forEach(other=>{if(other===tab)other.setAttribute('aria-current','page');else other.removeAttribute('aria-current');});
});

function deleteButton(index){const b=document.createElement('button');b.textContent='Delete…';b.className='danger';let armed=false;b.onclick=()=>{if(!armed){armed=true;b.textContent='Confirm delete';setTimeout(()=>{armed=false;b.textContent='Delete…'},5000);return;}run(()=>invoke('edit_profile',{revision:state.revision,index,action:'delete'}));};return b;}
