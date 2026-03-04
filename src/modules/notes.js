// Annotations and notes system
// Allows users to add notes, tags, and annotations to resources
// Extracted from index.html for modularization

// === ANNOTATIONS / NOTES SYSTEM ===
const _NOTES_KEY='azureMapper_annotations';
let _annotations={};// {resourceId: [{text,category,author,created,updated,pinned}]}
let _annotationAuthor='';
try{const s=localStorage.getItem(_NOTES_KEY);if(s)_annotations=JSON.parse(s)}catch(e){}
try{_annotationAuthor=localStorage.getItem('azureMapper_note_author')||''}catch(e){}
const _NOTE_CATEGORIES=['owner','status','incident','todo','info','warning'];
function _saveAnnotations(){try{localStorage.setItem(_NOTES_KEY,JSON.stringify(_annotations))}catch(e){}}
function _noteKey(resourceId,accountId){return accountId&&accountId!=='default'?accountId+':'+resourceId:resourceId}
function _getAllNotes(){
  const all=[];
  Object.entries(_annotations).forEach(([rid,notes])=>{
    (Array.isArray(notes)?notes:[notes]).forEach((n,i)=>{if(n&&n.text)all.push({...n,resourceId:rid,noteIndex:i})});
  });
  return all.sort((a,b)=>new Date(b.updated||b.created||0)-new Date(a.updated||a.created||0));
}
function addAnnotation(resourceId,text,category,pinned){
  if(!text||!text.trim())return;
  const note={text:text.trim(),category:category||'info',author:_annotationAuthor||'',created:new Date().toISOString(),updated:new Date().toISOString(),pinned:!!pinned};
  if(!_annotations[resourceId])_annotations[resourceId]=[];
  if(!Array.isArray(_annotations[resourceId]))_annotations[resourceId]=[_annotations[resourceId]];
  _annotations[resourceId].push(note);
  _saveAnnotations();_renderNoteBadges();_renderNotesPanel();
  return note;
}
function updateAnnotation(resourceId,noteIndex,text,category,pinned){
  if(!_annotations[resourceId]||!_annotations[resourceId][noteIndex])return;
  const n=_annotations[resourceId][noteIndex];
  if(text!==undefined)n.text=text;
  if(category!==undefined)n.category=category;
  if(pinned!==undefined)n.pinned=pinned;
  n.updated=new Date().toISOString();
  _saveAnnotations();_renderNoteBadges();_renderNotesPanel();
}
function deleteAnnotation(resourceId,noteIndex){
  if(!_annotations[resourceId])return;
  _annotations[resourceId].splice(noteIndex,1);
  if(_annotations[resourceId].length===0)delete _annotations[resourceId];
  _saveAnnotations();_renderNoteBadges();_renderNotesPanel();
}
function _getResourceName(rid){
  if(!_rlCtx)return rid;
  // Lazy-build name map for O(1) lookups
  if(!_rlCtx._resourceNameMap){
    const m=new Map();
    (_rlCtx.vnets||[]).forEach(x=>m.set(x.id,gn(x,x.id)));
    (_rlCtx.subnets||[]).forEach(x=>m.set(x.id,gn(x,x.id)));
    (_rlCtx.vms||[]).forEach(x=>m.set(x.id,gn(x,x.id)));
    (_rlCtx.sqlServers||[]).forEach(x=>m.set(x.id||x.name,x.name));
    (_rlCtx.functionApps||[]).forEach(x=>m.set(x.id||x.name,x.name));
    (_rlCtx.nsgs||[]).forEach(x=>m.set(x.id,x.name||x.id));
    _rlCtx._resourceNameMap=m;
  }
  return _rlCtx._resourceNameMap.get(rid)||rid;
}
function _isOrphaned(rid){
  if(!_rlCtx)return false;
  if(rid.startsWith('canvas:'))return false;
  // Lazy-build resource ID Set for O(1) lookups
  if(!_rlCtx._allResourceIds){
    const s=new Set();
    (_rlCtx.vnets||[]).forEach(x=>s.add(x.id));
    (_rlCtx.subnets||[]).forEach(x=>s.add(x.id));
    (_rlCtx.vms||[]).forEach(x=>s.add(x.id));
    (_rlCtx.firewalls||[]).forEach(x=>s.add(x.id));
    (_rlCtx.nats||[]).forEach(x=>s.add(x.id));
    (_rlCtx.privateEndpoints||[]).forEach(x=>s.add(x.id));
    (_rlCtx.sqlServers||[]).forEach(x=>s.add(x.id||x.name));
    (_rlCtx.functionApps||[]).forEach(x=>s.add(x.id||x.name));
    (_rlCtx.nsgs||[]).forEach(x=>s.add(x.id));
    (_rlCtx.albs||[]).forEach(x=>s.add(x.id||x.name));
    (_rlCtx.ecacheClusters||[]).forEach(x=>s.add(x.id||x.name));
    (_rlCtx.redshiftClusters||[]).forEach(x=>s.add(x.id||x.name));
    _rlCtx._allResourceIds=s;
  }
  return !_rlCtx._allResourceIds.has(rid);
}
function _relTime(iso){
  if(!iso)return '';
  const ms=Date.now()-new Date(iso).getTime();
  const s=Math.floor(ms/1000),m=Math.floor(s/60),h=Math.floor(m/60),d=Math.floor(h/24);
  if(d>30)return Math.floor(d/30)+'mo ago';if(d>0)return d+'d ago';if(h>0)return h+'h ago';if(m>0)return m+'m ago';return 'just now';
}
function _renderNotesPanel(){
  const body=document.getElementById('notesPanelBody');if(!body)return;
  const catFilter=document.getElementById('notesCatFilter').value;
  const searchQ=(document.getElementById('notesSearch').value||'').toLowerCase().trim();
  let all=_getAllNotes();
  if(catFilter!=='all')all=all.filter(n=>n.category===catFilter);
  if(searchQ)all=all.filter(n=>(n.text||'').toLowerCase().includes(searchQ)||(n.resourceId||'').toLowerCase().includes(searchQ)||(_getResourceName(n.resourceId)||'').toLowerCase().includes(searchQ));
  document.getElementById('noteCount').textContent=Object.keys(_annotations).length>0?_getAllNotes().length+' note(s)':'';
  let h='<div class="note-form" id="noteAddForm" style="display:none"><textarea id="noteNewText" placeholder="Add a note..."></textarea><div class="note-form-row"><select id="noteNewCat">'+_NOTE_CATEGORIES.map(c=>'<option value="'+c+'">'+c+'</option>').join('')+'</select><label style="font-size:10px;color:var(--text-muted);display:flex;align-items:center;gap:4px"><input type="checkbox" id="noteNewPinned"> Pin</label><input type="text" id="noteNewAuthor" placeholder="Your name" value="'+(_annotationAuthor||'').replace(/"/g,'&quot;')+'" style="width:100px"><button class="btn-save" id="noteAddSave">Add</button><button class="btn-cancel" id="noteAddCancel">Cancel</button></div><select id="noteNewResource" style="margin-top:6px;width:100%"><option value="">-- Select resource --</option></select></div>';
  if(!all.length&&!Object.keys(_annotations).length){h+='<div style="padding:40px 20px;text-align:center;color:var(--text-muted);font-size:12px">No annotations yet.<br>Click a resource on the map, then use "Add Note" in the detail panel.<br>Or click the + button above.</div>';
  }else if(!all.length){h+='<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:12px">No notes match filters</div>';
  }else{
    all.forEach(n=>{
      const orphaned=_isOrphaned(n.resourceId);
      const rName=_getResourceName(n.resourceId);
      h+='<div class="note-card'+(orphaned?' note-orphaned':'')+'" data-rid="'+_escHtml(n.resourceId)+'" data-ni="'+n.noteIndex+'">';
      h+='<div class="note-card-hdr"><span class="note-cat-badge cat-'+n.category+'">'+n.category+'</span>';
      if(n.pinned)h+='<span style="font-size:8px;color:var(--accent-orange)">PINNED</span>';
      if(orphaned)h+='<span style="font-size:8px;color:var(--accent-orange)">ORPHANED</span>';
      h+='<span class="note-resource" title="'+_escHtml(n.resourceId)+'">'+_escHtml(rName)+'</span></div>';
      h+='<div class="note-text">'+_escHtml(n.text)+'</div>';
      h+='<div class="note-meta"><span>'+_escHtml(n.author||'Anonymous')+'</span><span>'+_relTime(n.updated||n.created)+'</span></div>';
      h+='<div class="note-actions"><button class="note-zoom-btn" data-rid="'+_escHtml(n.resourceId)+'" title="Zoom to resource">Zoom</button><button class="note-edit-btn" data-rid="'+_escHtml(n.resourceId)+'" data-ni="'+n.noteIndex+'" title="Edit note">Edit</button><button class="note-del-btn" data-rid="'+_escHtml(n.resourceId)+'" data-ni="'+n.noteIndex+'" title="Delete note">Del</button></div>';
      h+='</div>';
    });
  }
  body.innerHTML=h;
  body.querySelectorAll('.note-zoom-btn').forEach(btn=>{btn.addEventListener('click',function(e){e.stopPropagation();const rid=this.dataset.rid;closeNotesPanel();_zoomToElement(rid)})});
  body.querySelectorAll('.note-edit-btn').forEach(btn=>{btn.addEventListener('click',function(e){e.stopPropagation();_showEditNote(this.dataset.rid,parseInt(this.dataset.ni))})});
  body.querySelectorAll('.note-del-btn').forEach(btn=>{btn.addEventListener('click',function(e){e.stopPropagation();deleteAnnotation(this.dataset.rid,parseInt(this.dataset.ni))})});
  const addBtn=document.getElementById('noteAddSave');
  if(addBtn){addBtn.addEventListener('click',()=>{
    const text=document.getElementById('noteNewText').value;
    const cat=document.getElementById('noteNewCat').value;
    const pinned=document.getElementById('noteNewPinned').checked;
    const author=document.getElementById('noteNewAuthor').value.trim();
    const rid=document.getElementById('noteNewResource').value;
    if(!text.trim()||!rid){_showToast('Select a resource and enter note text');return}
    if(author){_annotationAuthor=author;try{localStorage.setItem('azureMapper_note_author',author)}catch(e){}}
    addAnnotation(rid,text,cat,pinned);
    document.getElementById('noteAddForm').style.display='none';
  })}
  const cancelBtn=document.getElementById('noteAddCancel');
  if(cancelBtn){cancelBtn.addEventListener('click',()=>{document.getElementById('noteAddForm').style.display='none'})}
  _populateResourceSelect();
}
function _populateResourceSelect(){
  const sel=document.getElementById('noteNewResource');if(!sel||!_rlCtx)return;
  let opts='<option value="">-- Select resource --</option>';
  (_rlCtx.vnets||[]).forEach(v=>opts+='<option value="'+esc(v.id)+'">VNet: '+gn(v,v.id)+'</option>');
  (_rlCtx.subnets||[]).forEach(s=>opts+='<option value="'+esc(s.id)+'">Subnet: '+gn(s,s.id)+'</option>');
  (_rlCtx.vms||[]).forEach(i=>opts+='<option value="'+esc(i.id)+'">VM: '+gn(i,i.id)+'</option>');
  (_rlCtx.sqlServers||[]).forEach(d=>opts+='<option value="'+esc(d.id||d.name)+'">SQL: '+esc(d.name)+'</option>');
  (_rlCtx.functionApps||[]).forEach(f=>opts+='<option value="'+esc(f.id||f.name)+'">Function App: '+esc(f.name)+'</option>');
  (_rlCtx.nsgs||[]).forEach(s=>opts+='<option value="'+esc(s.id)+'">NSG: '+esc(s.name||s.id)+'</option>');
  sel.innerHTML=opts;
}
function _showEditNote(rid,ni){
  const notes=_annotations[rid];if(!notes||!notes[ni])return;
  const n=notes[ni];
  const card=document.querySelector('.note-card[data-rid="'+rid+'"][data-ni="'+ni+'"]');if(!card)return;
  card.innerHTML='<div class="note-form" style="display:block"><textarea id="noteEditText" style="width:100%">'+_escHtml(n.text)+'</textarea><div class="note-form-row"><select id="noteEditCat">'+_NOTE_CATEGORIES.map(c=>'<option value="'+c+'"'+(c===n.category?' selected':'')+'>'+c+'</option>').join('')+'</select><label style="font-size:10px;color:var(--text-muted);display:flex;align-items:center;gap:4px"><input type="checkbox" id="noteEditPinned" '+(n.pinned?'checked':'')+'> Pin</label><button class="btn-save" id="noteEditSave">Save</button><button class="btn-cancel" id="noteEditCancel">Cancel</button></div></div>';
  document.getElementById('noteEditSave').addEventListener('click',()=>{updateAnnotation(rid,ni,document.getElementById('noteEditText').value,document.getElementById('noteEditCat').value,document.getElementById('noteEditPinned').checked)});
  document.getElementById('noteEditCancel').addEventListener('click',()=>{_renderNotesPanel()});
}
function _escHtml(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function _renderNoteBadges(){
  if(!_mapG)return;
  _mapG.selectAll('.note-badge').remove();
  const nodesLayer=_mapG.select('.nodes-layer');if(nodesLayer.empty())return;
  Object.entries(_annotations).forEach(([rid,notes])=>{
    if(!Array.isArray(notes)||!notes.length)return;
    if(rid.startsWith('canvas:'))return;
    const el=_mapG.node().querySelector('[data-vnet-id="'+rid+'"],[data-subnet-id="'+rid+'"],[data-gwid="'+rid+'"],[data-id="'+rid+'"]');
    if(!el)return;
    const bb=el.getBBox();
    const topCat=notes.reduce((best,n)=>{const pri={incident:0,warning:1,todo:2,status:3,owner:4,info:5};return(pri[n.category]||5)<(pri[best]||5)?n.category:best},notes[0].category);
    const badge=nodesLayer.append('g').attr('class','note-badge cat-'+topCat).attr('transform','translate('+(bb.x+bb.width-4)+','+(bb.y+4)+')').style('cursor','pointer');
    badge.append('circle').attr('r',6);
    badge.append('text').attr('text-anchor','middle').attr('dy','2.5').text(notes.length>1?notes.length:'N');
    badge.on('click',()=>{openNotesPanel();const f=document.getElementById('notesSearch');if(f){f.value=rid;f.dispatchEvent(new Event('input'))}});
  });
}
// Build a lookup: resourceId -> {worst severity, count, findings[]}
function _buildComplianceLookup(){
  const lookup={};
  if(!_complianceFindings||!_complianceFindings.length)return lookup;
  const sevOrder={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4};
  _complianceFindings.forEach(f=>{
    if(_isMuted(f))return;
    const rid=f.resource;if(!rid||rid==='Multiple')return;
    if(!lookup[rid])lookup[rid]={worst:'LOW',count:0,findings:[]};
    lookup[rid].count++;
    lookup[rid].findings.push(f);
    if((sevOrder[f.severity]||9)<(sevOrder[lookup[rid].worst]||9))lookup[rid].worst=f.severity;
  });
  return lookup;
}
function _renderComplianceBadges(){
  if(!_mapG)return;
  _mapG.selectAll('.comp-badge').remove();
  if(!_complianceFindings||!_complianceFindings.length)return;
  const nodesLayer=_mapG.select('.nodes-layer');if(nodesLayer.empty())return;
  const lookup=_buildComplianceLookup();
  // For NSGs/UDRs that aren't rendered as map nodes, roll up to their VNet
  const vnetRollup={};
  Object.entries(lookup).forEach(([rid,data])=>{
    const el=_mapG.node().querySelector('[data-vnet-id="'+rid+'"],[data-subnet-id="'+rid+'"],[data-gwid="'+rid+'"],[data-id="'+rid+'"]');
    if(el)return; // Has its own node — badge goes directly on it
    // Try to find VNet for this resource
    let vnetId=null;
    if(_rlCtx){
      const nsg=(_rlCtx.nsgs||[]).find(s=>s.id===rid);if(nsg){vnetId=_nsgVnetId(nsg)}
      if(!vnetId){const udr=(_rlCtx.udrs||[]).find(r=>r.id===rid);if(udr){
        // Derive VNet from UDR's subnet associations
        var udrSubs=udr.properties&&udr.properties.subnets;
        if(udrSubs&&udrSubs.length) vnetId=_vnetIdFromSubnetId(udrSubs[0].id);
      }}
    }
    if(vnetId){
      if(!vnetRollup[vnetId])vnetRollup[vnetId]={worst:'LOW',count:0};
      const sevOrder={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4};
      vnetRollup[vnetId].count+=data.count;
      if((sevOrder[data.worst]||9)<(sevOrder[vnetRollup[vnetId].worst]||9))vnetRollup[vnetId].worst=data.worst;
    }
  });
  const sevOrder={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4};
  // Render badges on elements that exist on map
  Object.entries(lookup).forEach(([rid,data])=>{
    const el=_mapG.node().querySelector('[data-vnet-id="'+rid+'"],[data-subnet-id="'+rid+'"],[data-gwid="'+rid+'"],[data-id="'+rid+'"]');
    if(!el)return;
    const bb=el.getBBox();
    // Offset from note badges — place on opposite corner (top-left)
    const badge=nodesLayer.append('g').attr('class','comp-badge sev-'+data.worst).attr('transform','translate('+(bb.x+8)+','+(bb.y+4)+')').style('cursor','pointer');
    badge.node()._compRid=rid;
    badge.append('circle').attr('r',7);
    badge.append('text').attr('text-anchor','middle').attr('dy','2').text(data.count>9?'9+':data.count);
    badge.on('click',()=>{
      if(_complianceFindings.length){
        renderCompliancePanel(_complianceFindings,{search:rid});
      }
    });
  });
  // Render VNet rollup badges for NSGs/UDRs
  Object.entries(vnetRollup).forEach(([vnetId,data])=>{
    // Merge with existing VNet badge if present
    if(lookup[vnetId]){
      const existing=lookup[vnetId];
      data.count+=existing.count;
      if((sevOrder[existing.worst]||9)<(sevOrder[data.worst]||9))data.worst=existing.worst;
      // Remove the direct badge we already placed — we'll replace with merged
      _mapG.selectAll('.comp-badge').filter(function(){return d3.select(this).attr('transform')&&this._compRid===vnetId}).remove();
    }
    const el=_mapG.node().querySelector('[data-vnet-id="'+vnetId+'"]');
    if(!el)return;
    const bb=el.getBBox();
    const badge=nodesLayer.append('g').attr('class','comp-badge sev-'+data.worst).attr('transform','translate('+(bb.x+8)+','+(bb.y+4)+')').style('cursor','pointer');
    badge.node()._compRid=vnetId;
    badge.append('circle').attr('r',7);
    badge.append('text').attr('text-anchor','middle').attr('dy','2').text(data.count>9?'9+':data.count);
    badge.on('click',()=>{
      if(_complianceFindings.length){
        renderCompliancePanel(_complianceFindings,{search:vnetId});
      }
    });
  });
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
  openNotesPanel();
  const form=document.getElementById('noteAddForm');if(form)form.style.display='block';
  setTimeout(()=>{
    const sel=document.getElementById('noteNewResource');
    if(sel){sel.value=resourceId;if(!sel.value)_populateResourceSelect();sel.value=resourceId}
    const ta=document.getElementById('noteNewText');if(ta)ta.focus();
  },50);
}
document.getElementById('notesBtn').addEventListener('click',openNotesPanel);
document.getElementById('notesPanelClose').addEventListener('click',closeNotesPanel);
document.getElementById('notesCatFilter').addEventListener('change',()=>_renderNotesPanel());
document.getElementById('notesSearch').addEventListener('input',()=>_renderNotesPanel());
// Timeline events
document.getElementById('timelineBtn').addEventListener('click',()=>{const tb=document.getElementById('timelineBar');if(tb.classList.contains('open'))closeTimeline();else openTimeline()});
document.getElementById('timelineClose').addEventListener('click',closeTimeline);
document.getElementById('snapBtn').addEventListener('click',()=>takeSnapshot());
document.getElementById('historyReturn').addEventListener('click',_returnToCurrent);
document.getElementById('historyRestore').addEventListener('click',_restoreSnapshot);
