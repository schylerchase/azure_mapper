// #region TIMELINE & ANNOTATIONS
// === TIME-SERIES SNAPSHOTS ===
const _SNAP_KEY=SNAP_KEY;
const _MAX_SNAPSHOTS=timelineDesktopAvailable()?5:MAX_SNAPSHOTS;
let _snapshots=[];
let _viewingHistory=false;
let _currentSnapshot=null;// saved current state when viewing history

function timelineRuntimeContext(){
  var contextFactory = typeof AppRenderContext !== 'undefined' ? AppRenderContext : null;
  return contextFactory ? contextFactory.createRenderContext() : null;
}

function timelineRuntimeData(){
  var ctx = timelineRuntimeContext();
  return ctx ? ctx.rlCtx : null;
}

function timelineMapGroup(){
  var ctx = timelineRuntimeContext();
  return ctx ? ctx.mapG : null;
}

function timelineComplianceFindings(){
  var ctx = timelineRuntimeContext();
  return ctx ? ctx.complianceFindings || [] : [];
}

function timelineStorage(){
  var storage = typeof AppBrowserStorage !== 'undefined' ? AppBrowserStorage : null;
  return storage || null;
}

function timelineStorageGet(key){
  var storage = timelineStorage();
  return storage ? storage.get(key) : null;
}

function timelineStorageSet(key, value){
  var storage = timelineStorage();
  return storage ? storage.set(key, value) : false;
}

function timelineNotify(message, type){
  var notifications = typeof AppNotifications !== 'undefined' ? AppNotifications : null;
  if(notifications && typeof notifications.show === 'function') notifications.show(message, type);
}

function timelineDesktopAvailable(){
  var desktop = typeof DesktopAzureAdapter !== 'undefined' ? DesktopAzureAdapter : null;
  return !!(desktop && typeof desktop.isAvailable === 'function' && desktop.isAvailable());
}

function timelineEsc(s){
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function timelineAttrValue(value){
  return String(value||'').replace(/\\/g,'\\\\').replace(/"/g,'\\"');
}

function timelineResourceSelector(resourceId){
  var q = timelineAttrValue(resourceId);
  return '[data-vnet-id="'+q+'"],[data-subnet-id="'+q+'"],[data-gwid="'+q+'"],[data-id="'+q+'"]';
}

function timelineZoomToResource(resourceId){
  var viewport = typeof MapViewport !== 'undefined' ? MapViewport : null;
  if(viewport && typeof viewport.zoomToResource === 'function') return viewport.zoomToResource(resourceId);
  return null;
}

try{const s=timelineStorageGet(_SNAP_KEY);if(s)_snapshots=JSON.parse(s)}catch(e){_snapshots=[]}
function _saveSnapshots(){if(!timelineStorageSet(_SNAP_KEY,JSON.stringify(_snapshots))){
  // If storage full, trim oldest half
  if(_snapshots.length>4){_snapshots=_snapshots.slice(Math.floor(_snapshots.length/2));timelineStorageSet(_SNAP_KEY,JSON.stringify(_snapshots))}
}}
function _computeChecksum(textareas){
  const s=JSON.stringify(Object.keys(textareas).sort().map(k=>[k,textareas[k]]));
  let h=0;for(let i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0}return h;
}
function takeSnapshot(label,auto){
  const textareas={};
  document.querySelectorAll('.ji').forEach(el=>{const v=el.value.trim();if(v)textareas[el.id]=v});
  if(!Object.keys(textareas).length)return null;
  const checksum=_computeChecksum(textareas);
  // Skip if identical to last snapshot
  if(_snapshots.length>0){const last=_snapshots[_snapshots.length-1];if(JSON.stringify(last.textareas)===JSON.stringify(textareas))return null}
  const snap={
    id:'snap-'+Date.now(),
    timestamp:new Date().toISOString(),
    label:label||(auto?'Auto':'Manual'),
    auto:!!auto,
    checksum:checksum,
    accountLabel:(document.getElementById('accountLabel')||{}).value||'',
    layout:(document.getElementById('layoutMode')||{}).value||'grid',
    textareas:textareas,
    annotations:structuredClone(_annotations||{})
  };
  _snapshots.push(snap);
  while(_snapshots.length>_MAX_SNAPSHOTS)_snapshots.shift();
  _saveSnapshots();
  _renderTimeline();
  if(!auto)timelineNotify('Snapshot saved: '+(label||'Manual'));
  return snap;
}
function _renderTimeline(){
  const container=document.getElementById('timelineDots');if(!container)return;
  container.textContent='';
  if(!_snapshots.length){document.getElementById('timelineLabel').textContent='No snapshots';return}
  document.getElementById('timelineLabel').textContent=_snapshots.length+' snap'+((_snapshots.length!==1)?'s':'');
  const w=container.clientWidth||400;
  if(_snapshots.length===1){
    _addTimelineDot(container,_snapshots[0],w/2,0);
    return;
  }
  const t0=new Date(_snapshots[0].timestamp).getTime();
  const t1=new Date(_snapshots[_snapshots.length-1].timestamp).getTime();
  const span=t1-t0||1;
  _snapshots.forEach((snap,i)=>{
    const t=new Date(snap.timestamp).getTime();
    const x=((t-t0)/span)*(w-20)+10;
    _addTimelineDot(container,snap,x,i);
  });
}
function _addTimelineDot(container,snap,x,idx){
  const dot=document.createElement('div');
  dot.className='timeline-dot'+(snap.auto?' auto':'');
  dot.style.left=x+'px';
  const d=new Date(snap.timestamp);
  const timeStr=d.toLocaleDateString()+' '+d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  dot.innerHTML='<div class="timeline-tooltip">'+esc(snap.label)+' - '+timeStr+'</div>';
  dot.addEventListener('click',()=>_viewSnapshot(idx));
  dot.addEventListener('contextmenu',function(ev){ev.preventDefault();if(typeof _compareWithSnapshot==='function')_compareWithSnapshot(snap)});
  dot.title='Click: view | Right-click: compare with current';
  container.appendChild(dot);
}
function _viewSnapshot(idx){
  const snap=_snapshots[idx];if(!snap)return;
  _ensureNotesLoaded();
  if(!_viewingHistory){
    // Save current state
    _currentSnapshot={};
    document.querySelectorAll('.ji').forEach(el=>{_currentSnapshot[el.id]=el.value});
    _currentSnapshot._accountLabel=(document.getElementById('accountLabel')||{}).value||'';
    _currentSnapshot._layout=(document.getElementById('layoutMode')||{}).value||'grid';
    _currentSnapshot._annotations=structuredClone(_annotations||{});
    _currentSnapshot._mergeSession={mode:_multiViewMode,contexts:_loadedContexts,backup:_singleCtxBackup};
    _currentSnapshot._designSession=typeof _designMode!=='undefined'&&_designMode?{
      baseline:_designBaseline,changes:_designChanges,validation:_lastDesignValidation,
      pending:!!_designDebounce,sidebarWasCollapsed:_sidebarWasCollapsed
    }:null;
  }
  if(typeof _designMode!=='undefined'&&(_designMode||_designBaseline||_designDebounce))exitDesignMode({restore:false,render:false});
  if(_multiViewMode)exitMultiView({render:false});
  _loadedContexts=[];_mergedCtx=null;_singleCtxBackup=null;_prebuiltCtx=null;
  _renderAccountPanel();
  _viewingHistory=true;
  // Load snapshot data
  document.querySelectorAll('.ji').forEach(el=>{el.value='';el.className='ji'});
  Object.entries(snap.textareas||{}).forEach(([id,val])=>{
    const el=document.getElementById(id);
    if(el){el.value=val;try{JSON.parse(val);el.className='ji valid'}catch(e){el.className='ji invalid'}}
  });
  const al=document.getElementById('accountLabel');if(al)al.value=snap.accountLabel||'';
  const lm=document.getElementById('layoutMode');if(lm)lm.value=snap.layout||'grid';
  _annotations=structuredClone(snap.annotations||{});
  renderMap();
  // Show history banner
  const d=new Date(snap.timestamp);
  document.getElementById('historyLabel').textContent='VIEWING: '+snap.label+' - '+d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  document.getElementById('historyBanner').style.display='flex';
  // Highlight active dot
  document.querySelectorAll('.timeline-dot').forEach((d,i)=>d.classList.toggle('active',i===idx));
  // Disable inputs
  document.querySelectorAll('.ji').forEach(el=>el.readOnly=true);
  _renderNotesPanel();
}
function _returnToCurrent(){
  if(!_viewingHistory||!_currentSnapshot)return;
  if(typeof _designMode!=='undefined'&&(_designMode||_designBaseline||_designDebounce))exitDesignMode({restore:false,render:false});
  _viewingHistory=false;
  document.querySelectorAll('.ji').forEach(el=>{
    el.value=_currentSnapshot[el.id]||'';
    el.readOnly=false;
    if(el.value.trim()){try{JSON.parse(el.value);el.className='ji valid'}catch(e){el.className='ji invalid'}}else{el.className='ji'}
  });
  const al=document.getElementById('accountLabel');if(al)al.value=_currentSnapshot._accountLabel||'';
  const lm=document.getElementById('layoutMode');if(lm)lm.value=_currentSnapshot._layout||'grid';
  if(_currentSnapshot._annotations)_annotations=structuredClone(_currentSnapshot._annotations);
  _saveAnnotations();
  _renderNotesPanel();
  document.getElementById('historyBanner').style.display='none';
  document.querySelectorAll('.timeline-dot').forEach(d=>d.classList.remove('active'));
  const mergeSession=_currentSnapshot._mergeSession;
  const designSession=_currentSnapshot._designSession;
  _currentSnapshot=null;
  if(designSession){
    enterDesignMode();
    _designBaseline=designSession.baseline;_designChanges=designSession.changes;
    _lastDesignValidation=designSession.validation;_sidebarWasCollapsed=designSession.sidebarWasCollapsed;
    renderChangeLog();
    if(designSession.pending)_designDebounce=setTimeout(()=>applyDesignChanges(),300);
  }
  if(mergeSession){_loadedContexts=mergeSession.contexts||[];_renderAccountPanel()}
  if(mergeSession?.mode){enterMultiView();_singleCtxBackup=mergeSession.backup}
  else renderMap();
}
function _discardHistoryView(options){
  if(_viewingHistory&&typeof _designMode!=='undefined'&&(_designMode||_designBaseline||_designDebounce))exitDesignMode({restore:false,render:false});
  if(_viewingHistory&&options?.restoreAnnotations!==false&&_currentSnapshot?._annotations){
    _annotations=structuredClone(_currentSnapshot._annotations);
    _saveAnnotations();
  }
  _viewingHistory=false;
  _currentSnapshot=null;
  document.getElementById('historyBanner').style.display='none';
  document.querySelectorAll('.ji').forEach(el=>el.readOnly=false);
  document.querySelectorAll('.timeline-dot').forEach(d=>d.classList.remove('active'));
  _renderNotesPanel();
}
function _restoreSnapshot(){
  if(!_viewingHistory)return;
  _discardHistoryView({restoreAnnotations:false});
  _saveAnnotations();
  timelineNotify('Snapshot restored as current state');
  renderMap(()=>_autoSaveSession(true));
}
function openTimeline(){document.getElementById('timelineBar').classList.add('open');_renderTimeline()}
function closeTimeline(){document.getElementById('timelineBar').classList.remove('open')}
// Auto-snapshot on render (with 2-min minimum interval)
let _lastAutoSnap=0;
const _origRenderMap=typeof renderMap==='function'?null:null;// renderMap defined elsewhere, hook via event
// Hook: take auto-snapshot after successful render
// We add this at the end of the stats bar rendering

// === ANNOTATIONS / NOTES SYSTEM ===
const _NOTES_KEY=NOTES_KEY;
let _annotations={};// {resourceId: [{text,category,author,created,updated,pinned}]}
let _annotationAuthor='';
let _notesLoaded=false;
function _ensureNotesLoaded(){if(_notesLoaded)return;_notesLoaded=true;try{const s=timelineStorageGet(_NOTES_KEY);if(s)_annotations=JSON.parse(s)}catch(e){}try{_annotationAuthor=timelineStorageGet('azureMapper_note_author')||''}catch(e){}}
const _NOTE_CATEGORIES=['owner','status','incident','todo','info','warning'];
function _noteCategory(category){return _NOTE_CATEGORIES.includes(category)?category:'info'}
function _saveAnnotations(){timelineStorageSet(_NOTES_KEY,JSON.stringify(_annotations))}
function _noteKey(resourceId,accountId){return accountId&&accountId!=='default'?accountId+':'+resourceId:resourceId}
function _getAllNotes(){
  _ensureNotesLoaded();
  const all=[];
  Object.entries(_annotations).forEach(([rid,notes])=>{
    (Array.isArray(notes)?notes:[notes]).forEach((n,i)=>{if(n&&n.text)all.push({...n,category:_noteCategory(n.category),resourceId:rid,noteIndex:i})});
  });
  return all.sort((a,b)=>new Date(b.updated||b.created||0)-new Date(a.updated||a.created||0));
}
function addAnnotation(resourceId,text,category,pinned){
  if(_viewingHistory)return;
  _ensureNotesLoaded();
  if(!text||!text.trim())return;
  const note={text:text.trim(),category:_noteCategory(category),author:_annotationAuthor||'',created:new Date().toISOString(),updated:new Date().toISOString(),pinned:!!pinned};
  if(!_annotations[resourceId])_annotations[resourceId]=[];
  if(!Array.isArray(_annotations[resourceId]))_annotations[resourceId]=[_annotations[resourceId]];
  _annotations[resourceId].push(note);
  _saveAnnotations();_renderNoteBadges();_renderNotesPanel();
  return note;
}
function updateAnnotation(resourceId,noteIndex,text,category,pinned){
  if(_viewingHistory)return;
  if(!_annotations[resourceId]||!_annotations[resourceId][noteIndex])return;
  const n=_annotations[resourceId][noteIndex];
  if(text!==undefined)n.text=text;
  if(category!==undefined)n.category=_noteCategory(category);
  if(pinned!==undefined)n.pinned=pinned;
  n.updated=new Date().toISOString();
  _saveAnnotations();_renderNoteBadges();_renderNotesPanel();
}
function deleteAnnotation(resourceId,noteIndex){
  if(_viewingHistory)return;
  if(!_annotations[resourceId])return;
  _annotations[resourceId].splice(noteIndex,1);
  if(_annotations[resourceId].length===0)delete _annotations[resourceId];
  _saveAnnotations();_renderNoteBadges();_renderNotesPanel();
}
function _getResourceName(rid){
  const ctx=timelineRuntimeData();
  if(!ctx)return rid;
  const v=(ctx.vnets||[]).find(x=>x.VpcId===rid);if(v)return gn(v,rid);
  const s=(ctx.subnets||[]).find(x=>x.SubnetId===rid);if(s)return gn(s,rid);
  const i=(ctx.vms||[]).find(x=>x.InstanceId===rid);if(i)return gn(i,rid);
  const r=(ctx.sqlServers||[]).find(x=>x.DBInstanceIdentifier===rid);if(r)return rid;
  const l=(ctx.functionApps||[]).find(x=>x.FunctionName===rid);if(l)return rid;
  const sg=(ctx.nsgs||[]).find(x=>x.GroupId===rid);if(sg)return sg.GroupName||rid;
  return rid;
}
function _isOrphaned(rid){
  const ctx=timelineRuntimeData();
  if(!ctx)return false;
  if(rid.startsWith('canvas:'))return false;
  const all=[...(ctx.vnets||[]).map(x=>x.VpcId),...(ctx.subnets||[]).map(x=>x.SubnetId),...(ctx.vms||[]).map(x=>x.InstanceId),...(ctx.firewalls||[]).map(x=>x.InternetGatewayId),...(ctx.natGateways||[]).map(x=>x.NatGatewayId),...(ctx.privateEndpoints||[]).map(x=>x.VpcEndpointId),...(ctx.sqlServers||[]).map(x=>x.DBInstanceIdentifier),...(ctx.functionApps||[]).map(x=>x.FunctionName),...(ctx.nsgs||[]).map(x=>x.GroupId),...(ctx.appGateways||[]).map(x=>x.LoadBalancerName),...(ctx.redisCaches||[]).map(x=>x.CacheClusterId),...(ctx.synapseWorkspaces||[]).map(x=>x.ClusterIdentifier)];
  return !all.includes(rid);
}
function _relTime(iso){
  if(!iso)return '';
  const ms=Date.now()-new Date(iso).getTime();
  const s=Math.floor(ms/1000),m=Math.floor(s/60),h=Math.floor(m/60),d=Math.floor(h/24);
  if(d>30)return Math.floor(d/30)+'mo ago';if(d>0)return d+'d ago';if(h>0)return h+'h ago';if(m>0)return m+'m ago';return 'just now';
}
function _renderNotesPanel(){
  const body=document.getElementById('notesPanelBody');if(!body)return;
  const createBtn=document.getElementById('notesAddBtn');
  if(createBtn)createBtn.disabled=_viewingHistory;
  const catFilter=document.getElementById('notesCatFilter').value;
  const searchQ=(document.getElementById('notesSearch').value||'').toLowerCase().trim();
  let all=_getAllNotes();
  if(catFilter!=='all')all=all.filter(n=>n.category===catFilter);
  if(searchQ)all=all.filter(n=>(n.text||'').toLowerCase().includes(searchQ)||(n.resourceId||'').toLowerCase().includes(searchQ)||(_getResourceName(n.resourceId)||'').toLowerCase().includes(searchQ));
  document.getElementById('noteCount').textContent=Object.keys(_annotations).length>0?_getAllNotes().length+' note(s)':'';
  let h='<div class="note-form" id="noteAddForm" style="display:none"><textarea id="noteNewText" placeholder="Add a note..."></textarea><div class="note-form-row"><select id="noteNewCat">'+_NOTE_CATEGORIES.map(c=>'<option value="'+c+'">'+c+'</option>').join('')+'</select><label style="font-size:10px;color:var(--text-muted);display:flex;align-items:center;gap:4px"><input type="checkbox" id="noteNewPinned"> Pin</label><input type="text" id="noteNewAuthor" placeholder="Your name" value="'+(_annotationAuthor||'').replace(/"/g,'&quot;')+'" style="width:100px"><button class="btn-save" id="noteAddSave">Add</button><button class="btn-cancel" id="noteAddCancel">Cancel</button></div><select id="noteNewResource" style="margin-top:6px;width:100%"><option value="">-- Select resource --</option></select></div>';
  if(_viewingHistory)h+='<div style="padding:12px;color:var(--text-muted);font-size:12px">Historical notes are read-only. Return to current or restore this snapshot before editing notes.</div>';
  if(!all.length&&!Object.keys(_annotations).length){h+='<div style="padding:40px 20px;text-align:center;color:var(--text-muted);font-size:12px">No annotations yet.<br>Click Add Note above, choose a resource, and enter your note.</div>';
  }else if(!all.length){h+='<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:12px">No notes match filters</div>';
  }else{
    all.forEach(n=>{
      const orphaned=_isOrphaned(n.resourceId);
      const rName=_getResourceName(n.resourceId);
      h+='<div class="note-card'+(orphaned?' note-orphaned':'')+'" data-rid="'+timelineEsc(n.resourceId)+'" data-ni="'+n.noteIndex+'">';
      const category=_noteCategory(n.category);
      h+='<div class="note-card-hdr"><span class="note-cat-badge cat-'+category+'">'+category+'</span>';
      if(n.pinned)h+='<span style="font-size:8px;color:var(--accent-orange)">PINNED</span>';
      if(orphaned)h+='<span style="font-size:8px;color:var(--accent-orange)">ORPHANED</span>';
      h+='<span class="note-resource" title="'+timelineEsc(n.resourceId)+'">'+timelineEsc(rName)+'</span></div>';
      h+='<div class="note-text">'+timelineEsc(n.text)+'</div>';
      h+='<div class="note-meta"><span>'+timelineEsc(n.author||'Anonymous')+'</span><span>'+_relTime(n.updated||n.created)+'</span></div>';
      const disabled=_viewingHistory?' disabled':'';
      h+='<div class="note-actions"><button class="note-zoom-btn" data-rid="'+timelineEsc(n.resourceId)+'" title="Zoom to resource">Zoom</button><button class="note-edit-btn" data-rid="'+timelineEsc(n.resourceId)+'" data-ni="'+n.noteIndex+'" title="Edit note"'+disabled+'>Edit</button><button class="note-del-btn" data-rid="'+timelineEsc(n.resourceId)+'" data-ni="'+n.noteIndex+'" title="Delete note"'+disabled+'>Del</button></div>';
      h+='</div>';
    });
  }
  body.innerHTML=h;
  body.querySelectorAll('.note-zoom-btn').forEach(btn=>{btn.addEventListener('click',function(e){e.stopPropagation();const rid=this.dataset.rid;closeNotesPanel();timelineZoomToResource(rid)})});
  body.querySelectorAll('.note-edit-btn').forEach(btn=>{btn.addEventListener('click',function(e){e.stopPropagation();_showEditNote(this.dataset.rid,parseInt(this.dataset.ni))})});
  body.querySelectorAll('.note-del-btn').forEach(btn=>{btn.addEventListener('click',function(e){e.stopPropagation();deleteAnnotation(this.dataset.rid,parseInt(this.dataset.ni))})});
  const addBtn=document.getElementById('noteAddSave');
  if(addBtn){addBtn.addEventListener('click',()=>{
    if(_viewingHistory)return;
    const text=document.getElementById('noteNewText').value;
    const cat=document.getElementById('noteNewCat').value;
    const pinned=document.getElementById('noteNewPinned').checked;
    const author=document.getElementById('noteNewAuthor').value.trim();
    const rid=document.getElementById('noteNewResource').value;
    if(!text.trim()||!rid){timelineNotify('Select a resource and enter note text');return}
    if(author){_annotationAuthor=author;timelineStorageSet('azureMapper_note_author',author)}
    addAnnotation(rid,text,cat,pinned);
    document.getElementById('noteAddForm').style.display='none';
  })}
  const cancelBtn=document.getElementById('noteAddCancel');
  if(cancelBtn){cancelBtn.addEventListener('click',()=>{document.getElementById('noteAddForm').style.display='none'})}
  _populateResourceSelect();
}
function _populateResourceSelect(){
  const sel=document.getElementById('noteNewResource');const ctx=timelineRuntimeData();if(!sel||!ctx)return;
  let opts='<option value="">-- Select resource --</option>';
  (ctx.vnets||[]).forEach(v=>opts+='<option value="'+timelineEsc(v.VpcId)+'">VNet: '+gn(v,v.VpcId)+'</option>');
  (ctx.subnets||[]).forEach(s=>opts+='<option value="'+timelineEsc(s.SubnetId)+'">Subnet: '+gn(s,s.SubnetId)+'</option>');
  (ctx.vms||[]).forEach(i=>opts+='<option value="'+timelineEsc(i.InstanceId)+'">VM: '+gn(i,i.InstanceId)+'</option>');
  (ctx.sqlServers||[]).forEach(d=>opts+='<option value="'+timelineEsc(d.DBInstanceIdentifier)+'">SQL: '+timelineEsc(d.DBInstanceIdentifier)+'</option>');
  (ctx.functionApps||[]).forEach(f=>opts+='<option value="'+timelineEsc(f.FunctionName)+'">Function App: '+timelineEsc(f.FunctionName)+'</option>');
  (ctx.nsgs||[]).forEach(s=>opts+='<option value="'+timelineEsc(s.GroupId)+'">NSG: '+timelineEsc(s.GroupName||s.GroupId)+'</option>');
  sel.innerHTML=opts;
}
function _showEditNote(rid,ni){
  if(_viewingHistory)return;
  const notes=_annotations[rid];if(!notes||!notes[ni])return;
  const n=notes[ni];
  const card=Array.from(document.querySelectorAll('.note-card')).find(el=>el.dataset.rid===rid&&el.dataset.ni===String(ni));if(!card)return;
  card.innerHTML='<div class="note-form" style="display:block"><textarea id="noteEditText" style="width:100%">'+timelineEsc(n.text)+'</textarea><div class="note-form-row"><select id="noteEditCat">'+_NOTE_CATEGORIES.map(c=>'<option value="'+c+'"'+(c===n.category?' selected':'')+'>'+c+'</option>').join('')+'</select><label style="font-size:10px;color:var(--text-muted);display:flex;align-items:center;gap:4px"><input type="checkbox" id="noteEditPinned" '+(n.pinned?'checked':'')+'> Pin</label><button class="btn-save" id="noteEditSave">Save</button><button class="btn-cancel" id="noteEditCancel">Cancel</button></div></div>';
  document.getElementById('noteEditSave').addEventListener('click',()=>{updateAnnotation(rid,ni,document.getElementById('noteEditText').value,document.getElementById('noteEditCat').value,document.getElementById('noteEditPinned').checked)});
  document.getElementById('noteEditCancel').addEventListener('click',()=>{_renderNotesPanel()});
}
function _renderNoteBadges(){
  const mapG=timelineMapGroup();
  if(!mapG)return;
  mapG.selectAll('.note-badge').remove();
  const nodesLayer=mapG.select('.nodes-layer');if(nodesLayer.empty())return;
  Object.entries(_annotations).forEach(([rid,notes])=>{
    if(!Array.isArray(notes)||!notes.length)return;
    if(rid.startsWith('canvas:'))return;
    const el=mapG.node().querySelector(timelineResourceSelector(rid));
    if(!el)return;
    const bb=el.getBBox();
    const topCat=notes.reduce((best,n)=>{const pri={incident:0,warning:1,todo:2,status:3,owner:4,info:5};const category=_noteCategory(n.category);return pri[category]<pri[best]?category:best},_noteCategory(notes[0].category));
    const badge=nodesLayer.append('g').attr('class','note-badge cat-'+topCat).attr('transform','translate('+(bb.x+bb.width-4)+','+(bb.y+4)+')').style('cursor','pointer');
    badge.append('circle').attr('r',6);
    badge.append('text').attr('text-anchor','middle').attr('dy','2.5').text(notes.length>1?notes.length:'N');
    badge.on('click',()=>{openNotesPanel();const f=document.getElementById('notesSearch');if(f){f.value=rid;f.dispatchEvent(new Event('input'))}});
  });
}
// Build a lookup: resourceId → {worst severity, count, findings[]}
function _buildComplianceLookup(){
  const lookup={};
  const findings=timelineComplianceFindings();
  if(!findings.length)return lookup;
  const sevOrder={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4};
  findings.forEach(f=>{
    if(_isMuted(f))return;
    const rid=f.resourceId||f.resource;if(!rid||rid==='Multiple')return;
    if(!lookup[rid])lookup[rid]={worst:'LOW',count:0,findings:[]};
    lookup[rid].count++;
    lookup[rid].findings.push(f);
    if((sevOrder[f.severity]||9)<(sevOrder[lookup[rid].worst]||9))lookup[rid].worst=f.severity;
  });
  return lookup;
}
function _renderComplianceBadges(){
  const mapG=timelineMapGroup();
  const findings=timelineComplianceFindings();
  const ctx=timelineRuntimeData();
  if(!mapG)return;
  mapG.selectAll('.comp-badge').remove();
  if(!findings.length)return;
  const nodesLayer=mapG.select('.nodes-layer');if(nodesLayer.empty())return;
  const lookup=_buildComplianceLookup();
  // For SGs/NACLs that aren't rendered as map nodes, roll up to their VPC
  const vpcRollup={};
  Object.entries(lookup).forEach(([rid,data])=>{
    const el=mapG.node().querySelector(timelineResourceSelector(rid));
    if(el)return; // Has its own node: badge goes directly on it
    // Try to find VNet for this resource
    let vpcId=null;
    if(ctx){
      const sg=(ctx.nsgs||[]).find(s=>s.GroupId===rid);if(sg){vpcId=sg.VpcId}
      if(!vpcId){const nacl=(ctx.subnetNsgs||[]).find(n=>n.NetworkAclId===rid);if(nacl)vpcId=nacl.VpcId}
      if(!vpcId){const rt=(ctx.udrs||[]).find(r=>r.RouteTableId===rid);if(rt)vpcId=rt.VpcId}
    }
    if(vpcId){
      if(!vpcRollup[vpcId])vpcRollup[vpcId]={worst:'LOW',count:0};
      const sevOrder={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4};
      vpcRollup[vpcId].count+=data.count;
      if((sevOrder[data.worst]||9)<(sevOrder[vpcRollup[vpcId].worst]||9))vpcRollup[vpcId].worst=data.worst;
    }
  });
  const sevOrder={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4};
  // Render badges on elements that exist on map
  Object.entries(lookup).forEach(([rid,data])=>{
    const el=mapG.node().querySelector(timelineResourceSelector(rid));
    if(!el)return;
    const bb=el.getBBox();
    // Offset from note badges: place on opposite corner (top-left)
    const badge=nodesLayer.append('g').attr('class','comp-badge sev-'+data.worst).attr('transform','translate('+(bb.x+8)+','+(bb.y+4)+')').style('cursor','pointer');
    badge.node()._compRid=rid;
    badge.append('circle').attr('r',7);
    badge.append('text').attr('text-anchor','middle').attr('dy','2').text(data.count>9?'9+':data.count);
    badge.on('click',()=>{
      if(findings.length){
        renderCompliancePanel(findings,{search:rid});
      }
    });
  });
  // Render VNet rollup badges for NSGs/subnet NSGs/UDRs
  Object.entries(vpcRollup).forEach(([vpcId,data])=>{
    // Merge with existing VNet badge if present
    if(lookup[vpcId]){
      const existing=lookup[vpcId];
      data.count+=existing.count;
      if((sevOrder[existing.worst]||9)<(sevOrder[data.worst]||9))data.worst=existing.worst;
      // Remove the direct badge we already placed: we'll replace with merged
      mapG.selectAll('.comp-badge').filter(function(){return d3.select(this).attr('transform')&&this._compRid===vpcId}).remove();
    }
    const el=mapG.node().querySelector('[data-vnet-id="'+timelineAttrValue(vpcId)+'"]');
    if(!el)return;
    const bb=el.getBBox();
    const badge=nodesLayer.append('g').attr('class','comp-badge sev-'+data.worst).attr('transform','translate('+(bb.x+8)+','+(bb.y+4)+')').style('cursor','pointer');
    badge.node()._compRid=vpcId;
    badge.append('circle').attr('r',7);
    badge.append('text').attr('text-anchor','middle').attr('dy','2').text(data.count>9?'9+':data.count);
    badge.on('click',()=>{
      if(findings.length){
        renderCompliancePanel(findings,{search:vpcId});
      }
    });
  });
}
function _closeAllDashboards(except){
  var ids=['udash','diffDash','notesPanel'];
  ids.forEach(function(id){
    if(id===except)return;
    var el=document.getElementById(id);
    if(el&&el.classList.contains('open'))el.classList.remove('open');
  });
  if(except!=='udash'&&typeof DashboardState!=='undefined')DashboardState.setTab(null);
}
function openNotesPanel(){
  _closeAllDashboards('notesPanel');
  document.getElementById('notesPanel').classList.add('open');
  _renderNotesPanel();
}
function closeNotesPanel(){
  document.getElementById('notesPanel').classList.remove('open');
}
function openNoteFormForResource(resourceId){
  if(_viewingHistory){timelineNotify('Return to current or restore this snapshot before editing notes');return}
  openNotesPanel();
  const form=document.getElementById('noteAddForm');if(form)form.style.display='block';
  const sel=document.getElementById('noteNewResource');
  if(sel){sel.value=resourceId;if(!sel.value)_populateResourceSelect();sel.value=resourceId}
  const ta=document.getElementById('noteNewText');if(ta)ta.focus();
}
document.getElementById('notesBtn').addEventListener('click',openNotesPanel);
document.getElementById('notesAddBtn').addEventListener('click',()=>{
  document.getElementById('notesCatFilter').value='all';
  document.getElementById('notesSearch').value='';
  openNoteFormForResource('');
});
document.getElementById('notesPanelClose').addEventListener('click',closeNotesPanel);
document.getElementById('notesCatFilter').addEventListener('change',()=>_renderNotesPanel());
document.getElementById('notesSearch').addEventListener('input',()=>_renderNotesPanel());
// Timeline events
document.getElementById('timelineBtn').addEventListener('click',()=>{const tb=document.getElementById('timelineBar');if(tb.classList.contains('open'))closeTimeline();else openTimeline()});
document.getElementById('timelineClose').addEventListener('click',closeTimeline);
document.getElementById('snapBtn').addEventListener('click',()=>takeSnapshot());
document.getElementById('historyReturn').addEventListener('click',_returnToCurrent);
document.getElementById('historyRestore').addEventListener('click',_restoreSnapshot);

// #endregion TIMELINE & ANNOTATIONS

