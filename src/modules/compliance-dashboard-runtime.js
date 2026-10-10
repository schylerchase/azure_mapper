// #region COMPLIANCE DASHBOARD
let _compDashState={sevFilter:'ALL',fwFilter:'all',search:'',sort:'severity',showMuted:false,execSummary:false,view:'action'};

function compDashboardRuntimeContext(){
  if(typeof AppRenderContext!=='undefined'&&AppRenderContext.createRenderContext){
    return AppRenderContext.createRenderContext();
  }
  return null;
}

function compDashboardFindings(){
  var context=compDashboardRuntimeContext();
  return context?context.complianceFindings:[];
}

function compDashboardEsc(value){
  var html=typeof AppHtml!=='undefined'?AppHtml:null;
  if(html&&html.escape)return html.escape(value);
  return esc(value);
}

function compDashboardDownload(blob,name){
  var downloads=typeof AppDownloads!=='undefined'?AppDownloads:null;
  if(downloads&&downloads.saveBlob)return downloads.saveBlob(blob,name);
}

function compDashboardOpenResourceDetail(rid){
  if(!rid||rid==='Multiple')return;
  closeUnifiedDash();
  setTimeout(function(){
    if(typeof ResourceNavigation!=='undefined'&&ResourceNavigation.zoomAndOpenDetail){
      ResourceNavigation.zoomAndOpenDetail(rid);
    }
  },250);
}

function compDashboardActiveTab(){
  return typeof DashboardState!=='undefined'&&DashboardState.getTab?DashboardState.getTab():null;
}

function renderCompliancePanel(findings,opts){
  _compDashState={sevFilter:'ALL',fwFilter:'all',search:'',sort:'severity',showMuted:false,execSummary:false,view:_compDashState.view||'action'};
  if(opts&&opts.search)_compDashState.search=opts.search;
  if(opts&&opts.sevFilter)_compDashState.sevFilter=opts.sevFilter;
  _compToolbarTab=null;
  if(compDashboardActiveTab()==='compliance'){
    _renderCompDash();
  } else {
    openUnifiedDash('compliance');
  }
}
function _renderCompDash(bodyOnly){
  var findings=_udashFilterByAccount(compDashboardFindings());
  var tb=document.getElementById('udashToolbar');
  var body=document.getElementById('udashBody');
  var footer=document.getElementById('udashFooter');
  footer.textContent='';
  if(!bodyOnly)body.scrollTop=0;
  // Toolbar: only rebuild on tab switch
  if(_compToolbarTab!=='compliance'){
    _compToolbarTab='compliance';
    var th='<div id="compSevPills" style="display:inline-flex;gap:4px;margin-right:12px"></div>';
    th+='<input id="compSearch" type="text" placeholder="Search findings..." value="'+compDashboardEsc(_compDashState.search||'')+'" style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:11px;padding:4px 8px;width:180px">';
    th+='<select id="compFwFilter" style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:10px;padding:4px 6px">';
    th+='<option value="all">All Frameworks</option>';
    ['CIS','WAF','IAM','ARCH','SOC2','PCI','BUDR'].forEach(function(fw){th+='<option value="'+fw+'"'+(_compDashState.fwFilter===fw?' selected':'')+'>'+(_FW_LABELS[fw]||fw)+'</option>'});
    th+='</select>';
    th+='<select id="compSort" style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:10px;padding:4px 6px">';
    ['severity','framework','control','resource'].forEach(function(v){th+='<option value="'+v+'"'+(_compDashState.sort===v?' selected':'')+'>Sort: '+v.charAt(0).toUpperCase()+v.slice(1)+'</option>'});
    th+='</select>';
    th+='<label style="display:inline-flex;align-items:center;gap:4px;font-size:10px;color:var(--text-muted);cursor:pointer"><input type="checkbox" id="compShowMuted"'+(_compDashState.showMuted?' checked':'')+'>Show muted</label>';
    th+='<div id="compViewToggle" style="display:inline-flex;gap:2px;margin-left:8px">';
    th+='<button class="comp-view-btn'+(_compDashState.view==='action'?' active':'')+'" data-view="action" style="font-size:9px;padding:3px 8px;border:1px solid var(--border);border-radius:3px;cursor:pointer;font-family:Segoe UI,system-ui,sans-serif;background:'+(_compDashState.view==='action'?'var(--accent-cyan)':'none')+';color:'+(_compDashState.view==='action'?'#000':'var(--text-muted)')+'">Action Plan</button>';
    th+='<button class="comp-view-btn'+(_compDashState.view==='table'?' active':'')+'" data-view="table" style="font-size:9px;padding:3px 8px;border:1px solid var(--border);border-radius:3px;cursor:pointer;font-family:Segoe UI,system-ui,sans-serif;background:'+(_compDashState.view==='table'?'var(--accent-cyan)':'none')+';color:'+(_compDashState.view==='table'?'#000':'var(--text-muted)')+'">Table</button>';
    th+='</div>';
    th+='<span id="compMutedCount" style="font-size:9px;color:var(--text-muted);margin-left:8px"></span>';
    th+='<button id="compToggleSummary" style="margin-left:auto;background:rgba(34,211,238,.1);border:1px solid var(--accent-cyan);color:var(--accent-cyan);padding:4px 10px;border-radius:4px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">'+(_compDashState.execSummary?'Hide Summary':'Executive Summary')+'</button>';
    th+='<button id="compExportBtn" style="background:rgba(34,211,238,.1);border:1px solid var(--accent-cyan);color:var(--accent-cyan);padding:4px 10px;border-radius:4px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">Export</button>';
    tb.innerHTML=th;
    // Attach toolbar event listeners
    document.getElementById('compSearch').addEventListener('input',function(){_compDashState.search=this.value;_compDashState._cachedView=null;_renderCompDash()});
    document.getElementById('compFwFilter').addEventListener('change',function(){_compDashState.fwFilter=this.value;_compDashState._cachedView=null;_renderCompDash()});
    document.getElementById('compSort').addEventListener('change',function(){_compDashState.sort=this.value;_renderCompDash(true)});
    document.getElementById('compShowMuted').addEventListener('change',function(){_compDashState.showMuted=this.checked;_compDashState._cachedView=null;_renderCompDash()});
    document.querySelectorAll('#compViewToggle .comp-view-btn').forEach(function(btn){btn.addEventListener('click',function(){_compDashState.view=this.dataset.view;_renderCompDash()})});
    document.getElementById('compToggleSummary').addEventListener('click',function(){
      _compDashState.execSummary=!_compDashState.execSummary;
      this.textContent=_compDashState.execSummary?'Hide Summary':'Executive Summary';
      _compDashState._cachedView=null;
      _renderCompDash();
    });
    document.getElementById('compExportBtn').addEventListener('click',function(){
      _openCompExportModal();
    });
  }
  // Build unified compliance view: cache to avoid redundant computation
  var view=_compDashState._cachedView;
  if(!view){
    view=_buildComplianceView({
      findings:findings,
      frameworks:_compDashState.fwFilter,
      severity:_compDashState.sevFilter,
      search:_compDashState.search,
      includeMuted:_compDashState.showMuted
    });
    view._lastSevFilter=_compDashState.sevFilter;
    _compDashState._cachedView=view;
  } else if(view._lastSevFilter!==_compDashState.sevFilter){
    // Severity pill changed: re-filter from cached base without full rebuild
    var sevF=_compDashState.sevFilter;
    view.filtered=(sevF!=='ALL')?view.base.filter(function(f){return f.severity===sevF}):view.base;
    var ftc={crit:0,high:0,med:0,low:0};var fsc={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    view.filtered.forEach(function(f){ftc[f._tier]++;fsc[f.severity]++});
    view.filteredTierCounts=ftc;view.filteredSevCounts=fsc;
    view.tiers=_getTierGroups(view.filtered);
    view.sevGroups=_getSeverityGroups(view.filtered);
    view._lastSevFilter=_compDashState.sevFilter;
  }
  var filtered=view.filtered.slice();
  // Severity pills: counts from view.sevCounts (base, before severity pill filter)
  var sc=view.sevCounts;
  var pillBox=document.getElementById('compSevPills');if(pillBox){pillBox.textContent='';
  [{sev:'ALL',label:'All ('+view.base.length+')'},{sev:'CRITICAL',label:'Critical ('+sc.CRITICAL+')'},{sev:'HIGH',label:'High ('+sc.HIGH+')'},{sev:'MEDIUM',label:'Medium ('+sc.MEDIUM+')'},{sev:'LOW',label:'Low ('+sc.LOW+')'}].forEach(function(p){
    var btn=document.createElement('span');btn.className='comp-sev-pill'+(_compDashState.sevFilter===p.sev?' active':'');
    btn.dataset.sev=p.sev;btn.textContent=p.label;
    btn.addEventListener('click',function(){_compDashState.sevFilter=p.sev;_renderCompDash(true)});pillBox.appendChild(btn);
  });}
  // Update view toggle active state
  document.querySelectorAll('#compViewToggle .comp-view-btn').forEach(function(b){
    var isActive=b.dataset.view===_compDashState.view;
    b.classList.toggle('active',isActive);
    b.style.background=isActive?'var(--accent-cyan)':'none';
    b.style.color=isActive?'#000':'var(--text-muted)';
  });
  var mcEl=document.getElementById('compMutedCount');if(mcEl)mcEl.textContent=view.mutedCount>0?view.mutedCount+' finding(s) muted':'';
  // Sort filtered findings for display
  filtered.sort(function(a,b){if(_compDashState.sort==='severity')return(_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9);if(_compDashState.sort==='framework')return(a.framework||'').localeCompare(b.framework||'');if(_compDashState.sort==='control')return(a.control||'').localeCompare(b.control||'');if(_compDashState.sort==='resource')return(a.resourceName||a.resource||'').localeCompare(b.resourceName||b.resource||'');return 0});
  // Render body content: shell + rows split for performance
  if(_compDashState.view==='action'){
    _renderCompShellAction(view);
  } else {
    _renderCompShellTable(view,filtered);
  }
  var previousGap=body.querySelector('.comp-assessment-gaps');
  if(previousGap)previousGap.remove();
  var runtime=compDashboardRuntimeContext();
  var gaps=Object.keys(runtime&&runtime.rlCtx&&runtime.rlCtx.assessmentGaps||{});
  if(gaps.length){
    var gapNotice=document.createElement('div');
    gapNotice.className='comp-assessment-gaps';
    gapNotice.style.cssText='padding:10px;margin-bottom:10px;border:1px solid var(--border);color:var(--text-muted)';
    gapNotice.textContent='Not assessed (data unavailable): '+gaps.join(', ')+'. These controls are excluded from failure counts.';
    body.prepend(gapNotice);
  }
}
// Table view: separate shell (thead, exec summary) from row data (tbody).
// Shell is only rebuilt when switching views or toggling exec summary;
// on severity/sort/mute changes only the tbody rows are swapped.
function _renderCompShellTable(view,filtered){
  var body=document.getElementById('udashBody');
  var needShell=!body.querySelector('.comp-table')||body.querySelector('.comp-action-summary');
  if(needShell){
    var h='';
    if(_compDashState.execSummary)h+='<div id="compExecSummary"></div>';
    h+='<table class="comp-table"><thead><tr><th data-col="severity">Sev</th><th data-col="framework">Framework</th><th data-col="control">Control</th><th data-col="resource">Resource</th><th>Finding</th><th style="width:90px">Actions</th></tr></thead><tbody id="compTbody"></tbody></table>';
    body.innerHTML=h;
    if(_compDashState.execSummary)_renderExecSummary(view);
    body.querySelectorAll('th[data-col]').forEach(function(th){th.addEventListener('click',function(){_compDashState.sort=th.dataset.col;_renderCompDash(true)})});
  }
  _renderCompTableRows(filtered);
}
const _compChunkSize=100;
function _buildCompRow(f,i){
  // NOTE: All values are pre-escaped via esc(): data comes from internal compliance engine, not user input
  var muted=_isMuted(f);var ref=_complianceRefs[f.control];
  var h='<tr class="'+(muted?'muted':'')+'">';
  h+='<td><span class="sev-badge sev-'+f.severity+'">'+f.severity+'</span></td>';
  h+='<td style="color:var(--text-muted);font-size:10px">'+esc(f.framework)+'</td>';
  h+='<td style="color:var(--accent-cyan);font-size:11px">'+esc(f.control)+(f.ckv?' <span style="color:var(--text-muted);font-size:9px">('+esc(f.ckv)+')</span>':'')+(ref?' <a href="'+esc(ref.url)+'" target="_blank" style="color:var(--accent-blue);font-size:9px;text-decoration:none" title="'+esc(ref.ref)+'">[docs]</a>':'')+'</td>';
  h+='<td style="font-size:11px">'+(f.resource&&f.resource!=='Multiple'?'<a class="comp-res-link" data-rid="'+esc(f.resource)+'" style="color:var(--accent-cyan);cursor:pointer;text-decoration:none;border-bottom:1px dashed var(--accent-cyan)" title="Jump to resource">'+esc(f.resourceName||f.resource)+'</a>':'<span style="color:var(--text-muted)">'+esc(f.resourceName||f.resource)+'</span>')+'</td>';
  h+='<td><span style="color:var(--text-secondary)">'+esc(f.message)+'</span>'+(f.remediation?'<div class="comp-remediation"><strong style="color:var(--accent-cyan);font-weight:600">Remediation:</strong> '+esc(f.remediation)+'</div>':'')+'</td>';
  h+='<td><button class="comp-jump-btn" data-rid="'+esc(f.resource)+'" title="Zoom to resource on map">Jump</button><button class="comp-mute-btn '+(muted?'muted':'')+'" data-fi="'+i+'">'+(muted?'Unmute':'Mute')+'</button></td></tr>';
  return h;
}
function _attachCompRowListeners(container,filtered){
  container.querySelectorAll('.comp-mute-btn').forEach(function(btn){btn.addEventListener('click',function(e){e.stopPropagation();_toggleMute(filtered[parseInt(this.dataset.fi)]);_compDashState._cachedView=null;_renderCompDash(true)})});
  container.querySelectorAll('.comp-jump-btn').forEach(function(btn){btn.addEventListener('click',function(e){
    e.stopPropagation();compDashboardOpenResourceDetail(this.dataset.rid);
  })});
  container.querySelectorAll('.comp-res-link').forEach(function(a){a.addEventListener('click',function(e){
    e.stopPropagation();compDashboardOpenResourceDetail(this.dataset.rid);
  })});
}
function _renderCompTableRows(filtered){
  var tbody=document.getElementById('compTbody');if(!tbody)return;
  if(!filtered.length){tbody.textContent='';var emptyRow=document.createElement('tr');var emptyTd=document.createElement('td');emptyTd.setAttribute('colspan','6');emptyTd.style.cssText='text-align:center;padding:40px;color:var(--text-muted)';emptyTd.textContent='No findings match current filters';emptyRow.appendChild(emptyTd);tbody.appendChild(emptyRow);return}
  // Render first chunk immediately, defer rest via requestIdleCallback for large datasets
  var first=Math.min(_compChunkSize,filtered.length);
  var h='';for(let i=0;i<first;i++)h+=_buildCompRow(filtered[i],i);
  tbody.textContent='';var tmp=document.createElement('tbody');tmp.innerHTML=h; // safe: esc() applied to all values
  _attachCompRowListeners(tmp,filtered);
  while(tmp.firstChild)tbody.appendChild(tmp.firstChild);
  if(filtered.length<=_compChunkSize)return;
  var rendered=first;
  function renderNextChunk(){
    if(rendered>=filtered.length)return;
    var end=Math.min(rendered+_compChunkSize,filtered.length);
    var chunk='';for(let j=rendered;j<end;j++)chunk+=_buildCompRow(filtered[j],j);
    var t2=document.createElement('tbody');t2.innerHTML=chunk; // safe: esc() applied
    _attachCompRowListeners(t2,filtered);
    while(t2.firstChild)tbody.appendChild(t2.firstChild);
    rendered=end;
    if(rendered<filtered.length)(typeof requestIdleCallback==='function'?requestIdleCallback:setTimeout)(renderNextChunk);
  }
  (typeof requestIdleCallback==='function'?requestIdleCallback:setTimeout)(renderNextChunk);
}
// Action plan view: full body rebuild (complex nested DOM with expand/collapse state)
function _renderCompShellAction(view){
  var body=document.getElementById('udashBody');
  var summaryHtml='';
  if(_compDashState.execSummary)summaryHtml='<div id="compExecSummary"></div>';
  body.innerHTML=summaryHtml;
  if(_compDashState.execSummary)_renderExecSummary(view);
  _renderActionPlan(view);
}
function _renderActionPlan(view){
  var body=document.getElementById('udashBody');
  var sevColors={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#3b82f6'};
  // Determine grouping mode: severity-based when Sort: Severity, tier-based otherwise
  var bySev=_compDashState.sort==='severity';
  var _SEV_META={CRITICAL:{name:'Critical',color:'#ef4444',bg:'rgba(239,68,68,.08)',border:'rgba(239,68,68,.3)'},HIGH:{name:'High',color:'#f97316',bg:'rgba(249,115,22,.08)',border:'rgba(249,115,22,.3)'},MEDIUM:{name:'Medium',color:'#eab308',bg:'rgba(234,179,8,.08)',border:'rgba(234,179,8,.3)'},LOW:{name:'Low',color:'#3b82f6',bg:'rgba(59,130,246,.08)',border:'rgba(59,130,246,.3)'}};
  var keys=bySev?['CRITICAL','HIGH','MEDIUM','LOW']:_PRIORITY_KEYS;
  var groups=bySev?view.sevGroups:view.tiers;
  var counts=bySev?view.filteredSevCounts:view.filteredTierCounts;
  var metaMap=bySev?_SEV_META:_TIER_META;
  var h='';
  // Action summary cards
  h+='<div class="comp-action-summary">';
  keys.forEach(function(t){
    var meta=metaMap[t];var rgs=groups[t];
    var findingCount=counts[t];
    var effort=_estimateTotalEffort(rgs);
    h+='<div class="comp-action-card" style="background:'+meta.bg+';border-color:'+meta.border+';color:'+meta.color+'">';
    h+='<div class="ac-count">'+findingCount+'</div>';
    h+='<div class="ac-label">'+esc(meta.name)+'</div>';
    h+='<div class="ac-effort">'+esc(effort)+' effort</div>';
    h+='<div class="ac-resources">'+rgs.length+' resource'+(rgs.length!==1?'s':'')+'</div>';
    h+='</div>';
  });
  h+='</div>';
  // Sections: severity-grouped or tier-grouped
  keys.forEach(function(t){
    var meta=metaMap[t];var rgs=groups[t];
    if(!rgs.length)return;
    var sevFindings=counts[t];
    var effort=_estimateTotalEffort(rgs);
    var collapsed=(bySev?t==='LOW':t==='low');
    h+='<div class="comp-tier-section" data-tier="'+t+'">';
    h+='<div class="comp-tier-header'+(collapsed?' collapsed':'')+'" data-tier="'+t+'">';
    h+='<span class="tier-chevron">&#9660;</span>';
    h+='<h3 style="color:'+meta.color+'">'+esc(meta.name)+'</h3>';
    h+='<span class="tier-count">'+sevFindings+' finding'+(sevFindings!==1?'s':'')+' across '+rgs.length+' resource'+(rgs.length!==1?'s':'')+'</span>';
    h+='<span class="tier-effort">'+esc(effort)+'</span>';
    h+='</div>';
    h+='<div class="comp-tier-body"'+(collapsed?' style="display:none"':'')+'>';
    rgs.forEach(function(rg,ri){
      var expanded=(bySev?t==='CRITICAL':t==='crit');
      var rid=rg.resource;
      var jumpable=rid&&rid!=='Multiple';
      h+='<div class="comp-resource-card'+(expanded?' expanded':'')+'" data-rc="'+t+'-'+ri+'">';
      h+='<div class="comp-rc-header">';
      h+='<span class="rc-sev" style="background:'+(sevColors[rg.worstSev]||'#3b82f6')+'"></span>';
      h+='<span class="rc-name" title="'+esc(rg.resourceName)+'" style="cursor:pointer">'+esc(rg.resourceName)+'</span>';
      if(rg._subscriptionId)h+=_acctPill(rg._subscriptionId);
      h+='<span class="rc-count">'+rg.findings.length+' finding'+(rg.findings.length!==1?'s':'')+'</span>';
      if(jumpable)h+='<button class="rc-jump" data-rid="'+esc(rid)+'">Jump</button>';
      h+='</div>';
      h+='<div class="comp-rc-body">';
      var sortedFindings=rg.findings.slice();
      var srt=_compDashState.sort;
      if(srt==='severity')sortedFindings.sort(function(a,b){return(_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9)});
      else if(srt==='framework')sortedFindings.sort(function(a,b){return(a.framework||'').localeCompare(b.framework||'')});
      else if(srt==='control')sortedFindings.sort(function(a,b){return(a.control||'').localeCompare(b.control||'')});
      sortedFindings.forEach(function(f,fi){
        var muted=_isMuted(f);
        var ref=_complianceRefs[f.control];
        var effortClass=f._effort||f.effort||_getEffort(f);
        var effortLabel=_EFFORT_LABELS[effortClass]||effortClass;
        var effortTime=_EFFORT_TIME[effortClass]||'';
        h+='<div class="comp-finding-row'+(muted?' muted':'')+'">';
        h+='<span class="fr-sev '+f.severity+'">'+f.severity+'</span>';
        h+='<span class="fr-control">'+esc(f.control)+(f.ckv?' <span style="color:var(--text-muted);font-size:8px">('+esc(f.ckv)+')</span>':'');
        if(ref)h+=' <a href="'+esc(ref.url)+'" target="_blank" style="color:var(--accent-blue);font-size:8px;text-decoration:none" title="'+esc(ref.ref)+'">[docs]</a>';
        h+='</span>';
        h+='<div class="fr-msg">'+esc(f.message);
        if(f.remediation)h+='<div class="fr-remediation" style="color:var(--text-muted);font-size:10px;margin-top:3px;line-height:1.4"><strong style="color:var(--accent-cyan);font-weight:600">Remediation:</strong> '+esc(f.remediation)+'</div>';
        h+='</div>';
        h+='<span class="fr-effort '+effortClass+'">'+esc(effortLabel)+' '+esc(effortTime)+'</span>';
        h+='<div class="fr-actions"><button class="comp-mute-btn'+(muted?' muted':'')+'" data-tier="'+t+'" data-ri="'+ri+'" data-fi="'+fi+'">'+(muted?'Unmute':'Mute')+'</button></div>';
        h+='</div>';
      });
      h+='</div></div>';
    });
    h+='</div></div>';
  });
  if(!view.filtered.length)h+='<div class="comp-no-findings">No findings match current filters</div>';
  body.insertAdjacentHTML('beforeend',h);
  // Tier header collapse/expand
  body.querySelectorAll('.comp-tier-header').forEach(function(hdr){
    hdr.addEventListener('click',function(){
      var sec=this.closest('.comp-tier-section');
      var bd=sec.querySelector('.comp-tier-body');
      if(this.classList.contains('collapsed')){this.classList.remove('collapsed');bd.style.display=''}
      else{this.classList.add('collapsed');bd.style.display='none'}
    });
  });
  // Resource card expand/collapse
  body.querySelectorAll('.comp-rc-header').forEach(function(hdr){
    hdr.addEventListener('click',function(e){
      if(e.target.classList.contains('rc-jump'))return;
      this.closest('.comp-resource-card').classList.toggle('expanded');
    });
  });
  // Jump buttons
  body.querySelectorAll('.rc-jump').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      compDashboardOpenResourceDetail(this.dataset.rid);
    });
  });
  // Mute buttons
  body.querySelectorAll('.comp-mute-btn').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var t=this.dataset.tier,ri=parseInt(this.dataset.ri),fi=parseInt(this.dataset.fi);
      var rg=groups[t]&&groups[t][ri];
      if(rg&&rg.findings[fi]){_toggleMute(rg.findings[fi]);_compDashState._cachedView=null;_renderCompDash()}
    });
  });
}
function _calcComplianceScore(findings){
  const active=findings.filter(f=>!_isMuted(f));if(!active.length)return{score:100,grade:'A',color:'#22c55e'};
  const w={CRITICAL:10,HIGH:5,MEDIUM:2,LOW:0.5};
  const penalty=active.reduce((s,f)=>s+(w[f.severity]||0),0);
  const maxPenalty=active.length*10; // worst case: all CRITICAL
  const score=Math.max(0,Math.round(100-(penalty/maxPenalty)*100));
  const grade=score>=90?'A':score>=80?'B':score>=70?'C':score>=50?'D':'F';
  const color=score>=90?'#22c55e':score>=70?'#eab308':score>=50?'#f97316':'#ef4444';
  return{score,grade,color};
}
function _aggregateTopResources(findings,limit){
  const map={};findings.forEach(f=>{
    const r=f.resourceName||f.resource;if(!r||r==='Multiple')return;
    if(!map[r])map[r]={count:0,worst:'LOW',sevs:{}};
    map[r].count++;map[r].sevs[f.severity]=(map[r].sevs[f.severity]||0)+1;
    if((_SEV_ORDER[f.severity]||9)<(_SEV_ORDER[map[r].worst]||9))map[r].worst=f.severity;
  });
  return Object.entries(map).sort((a,b)=>{const sd=(_SEV_ORDER[a[1].worst]||9)-(_SEV_ORDER[b[1].worst]||9);return sd!==0?sd:b[1].count-a[1].count}).slice(0,limit);
}
function _renderExecSummary(view){
  const el=document.getElementById('compExecSummary');if(!el)return;
  // Use view if provided (respects current filters), otherwise build fresh
  if(!view)view=_buildComplianceView({findings:compDashboardFindings(),includeMuted:false});
  const active=view.base;
  const overall=view.score;
  const crit=view.sevCounts.CRITICAL;
  const high=view.sevCounts.HIGH;
  const med=view.sevCounts.MEDIUM;
  const low=view.sevCounts.LOW;
  const fws=['CIS','WAF','IAM','ARCH','SOC2','PCI'];
  const fwScores=fws.map(fw=>{
    const ff=active.filter(x=>x.framework===fw);
    return{fw,count:ff.length,..._calcComplianceScore(ff)};
  });
  const sorted=_aggregateTopResources(active,8);
  // Build DOM
  el.textContent='';
  const wrap=document.createElement('div');wrap.style.cssText='display:flex;gap:20px;flex-wrap:wrap';
  // Overall score circle (SVG)
  const scoreDiv=document.createElement('div');scoreDiv.style.cssText='text-align:center;min-width:120px';
  const pct=overall.score/100,r=40,circ=2*Math.PI*r,off=circ*(1-pct);
  const ns='http://www.w3.org/2000/svg';
  const svg=document.createElementNS(ns,'svg');svg.setAttribute('width','100');svg.setAttribute('height','100');svg.setAttribute('viewBox','0 0 100 100');
  const bg=document.createElementNS(ns,'circle');bg.setAttribute('cx','50');bg.setAttribute('cy','50');bg.setAttribute('r',r);bg.setAttribute('fill','none');bg.setAttribute('stroke','rgba(255,255,255,.08)');bg.setAttribute('stroke-width','8');svg.appendChild(bg);
  const fg=document.createElementNS(ns,'circle');fg.setAttribute('cx','50');fg.setAttribute('cy','50');fg.setAttribute('r',r);fg.setAttribute('fill','none');fg.setAttribute('stroke',overall.color);fg.setAttribute('stroke-width','8');fg.setAttribute('stroke-dasharray',circ);fg.setAttribute('stroke-dashoffset',off);fg.setAttribute('stroke-linecap','round');fg.setAttribute('transform','rotate(-90 50 50)');svg.appendChild(fg);
  const t1=document.createElementNS(ns,'text');t1.setAttribute('x','50');t1.setAttribute('y','46');t1.setAttribute('text-anchor','middle');t1.setAttribute('fill',overall.color);t1.setAttribute('font-size','22');t1.setAttribute('font-weight','700');t1.setAttribute('font-family','Segoe UI,system-ui,sans-serif');t1.textContent=overall.score;svg.appendChild(t1);
  const t2=document.createElementNS(ns,'text');t2.setAttribute('x','50');t2.setAttribute('y','62');t2.setAttribute('text-anchor','middle');t2.setAttribute('fill','var(--text-muted)');t2.setAttribute('font-size','10');t2.setAttribute('font-family','Segoe UI,system-ui,sans-serif');t2.textContent='Grade: '+overall.grade;svg.appendChild(t2);
  scoreDiv.appendChild(svg);
  const scoreLabel=document.createElement('div');scoreLabel.style.cssText='color:var(--text-muted);font-size:10px;margin-top:4px';scoreLabel.textContent='Overall Score';scoreDiv.appendChild(scoreLabel);
  wrap.appendChild(scoreDiv);
  // Severity breakdown
  const sevDiv=document.createElement('div');sevDiv.style.cssText='flex:1;min-width:200px';
  const sevTitle=document.createElement('div');sevTitle.style.cssText='font-size:11px;font-weight:600;color:var(--text-primary);margin-bottom:8px';sevTitle.textContent='Severity Breakdown';sevDiv.appendChild(sevTitle);
  [{l:'Critical',n:crit,c:'#ef4444'},{l:'High',n:high,c:'#f97316'},{l:'Medium',n:med,c:'#eab308'},{l:'Low',n:low,c:'#3b82f6'}].forEach(s=>{
    const row=document.createElement('div');row.style.cssText='display:flex;align-items:center;gap:8px;margin:4px 0';
    const lbl=document.createElement('span');lbl.style.cssText='font-size:10px;color:'+s.c+';width:55px;font-weight:600';lbl.textContent=s.l;row.appendChild(lbl);
    const barWrap=document.createElement('div');barWrap.style.cssText='flex:1;height:6px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden';
    const bar=document.createElement('div');bar.style.cssText='width:'+(active.length?(s.n/active.length*100):0)+'%;height:100%;background:'+s.c+';border-radius:3px';barWrap.appendChild(bar);row.appendChild(barWrap);
    const cnt=document.createElement('span');cnt.style.cssText='font-size:10px;color:var(--text-muted);width:30px;text-align:right';cnt.textContent=s.n;row.appendChild(cnt);
    sevDiv.appendChild(row);
  });
  wrap.appendChild(sevDiv);
  // Framework scores
  const fwDiv=document.createElement('div');fwDiv.style.cssText='flex:1;min-width:280px';
  const fwTitle=document.createElement('div');fwTitle.style.cssText='font-size:11px;font-weight:600;color:var(--text-primary);margin-bottom:8px';fwTitle.textContent='Framework Scores';fwDiv.appendChild(fwTitle);
  const fwGrid=document.createElement('div');fwGrid.style.cssText='display:grid;grid-template-columns:repeat(3,1fr);gap:6px';
  fwScores.forEach(fs=>{
    const card=document.createElement('div');card.style.cssText='background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:6px;padding:8px;text-align:center';
    const cn=document.createElement('div');cn.style.cssText='font-size:9px;color:var(--text-muted);margin-bottom:4px';cn.textContent=_FW_LABELS[fs.fw]||fs.fw;card.appendChild(cn);
    const sc=document.createElement('div');sc.style.cssText='font-size:18px;font-weight:700;color:'+fs.color+';font-family:Segoe UI,system-ui,sans-serif';sc.textContent=fs.score;card.appendChild(sc);
    const fc=document.createElement('div');fc.style.cssText='font-size:8px;color:var(--text-muted)';fc.textContent=fs.count+' finding'+(fs.count!==1?'s':'');card.appendChild(fc);
    fwGrid.appendChild(card);
  });
  fwDiv.appendChild(fwGrid);wrap.appendChild(fwDiv);
  // Top risky resources
  const resDiv=document.createElement('div');resDiv.style.cssText='flex:1;min-width:220px';
  const resTitle=document.createElement('div');resTitle.style.cssText='font-size:11px;font-weight:600;color:var(--text-primary);margin-bottom:8px';resTitle.textContent='Top Risky Resources';resDiv.appendChild(resTitle);
  if(sorted.length){sorted.forEach(([name,data])=>{
    const row=document.createElement('div');row.style.cssText='display:flex;align-items:center;gap:6px;margin:3px 0;font-size:10px';
    const badge=document.createElement('span');badge.className='sev-badge sev-'+data.worst;badge.style.cssText='font-size:7px;padding:1px 4px';badge.textContent=data.worst;row.appendChild(badge);
    const nm=document.createElement('span');nm.style.cssText='color:var(--text-secondary);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';nm.textContent=name;row.appendChild(nm);
    const ct=document.createElement('span');ct.style.cssText='color:var(--text-muted)';ct.textContent=data.count;row.appendChild(ct);
    resDiv.appendChild(row);
  })}else{const none=document.createElement('div');none.style.cssText='color:var(--text-muted);font-size:10px';none.textContent='No findings';resDiv.appendChild(none);}
  wrap.appendChild(resDiv);el.appendChild(wrap);
}
function _exportComplianceCSV(){
  const view=_buildComplianceView({findings:compDashboardFindings(),includeMuted:true});
  const rows=[['Priority','Effort','Severity','Framework','Control','CKV','Resource','Resource Name','Message','Remediation']];
  const sorted=[...view.filtered].sort((a,b)=>{if(a._tier!==b._tier)return(_PRIORITY_ORDER[a._tier]||9)-(_PRIORITY_ORDER[b._tier]||9);return(_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9)});
  sorted.forEach(f=>{rows.push([_TIER_META[f._tier].name,_EFFORT_LABELS[f._effort],f.severity,f.framework,f.control,f.ckv||'',f.resource,f.resourceName||'',f.message,f.remediation])});
  const csv=rows.map(r=>r.map(c=>'"'+String(c).replace(/"/g,'""')+'"').join(',')).join('\n');
  compDashboardDownload(new Blob([csv],{type:'text/csv'}),'compliance-report.csv');
}
function _exportComplianceExcel(findings,options){
  const view=_buildComplianceView({findings:findings||compDashboardFindings(),frameworks:options.frameworks,severities:options.severities,includeMuted:options.includeMuted});
  const filtered=view.filtered;
  const esc=s=>String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const sevBg={CRITICAL:'#fecaca',HIGH:'#fee2e2',MEDIUM:'#fef3c7',LOW:'#dbeafe'};
  const sevTxt={CRITICAL:'#991b1b',HIGH:'#b91c1c',MEDIUM:'#92400e',LOW:'#1e40af'};
  const tierBg={Critical:'#fecaca',High:'#fed7aa',Medium:'#fef3c7',Low:'#dbeafe'};
  const effortBg={Low:'#dcfce7',Med:'#fef3c7',High:'#fee2e2'};
  let h='<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">';
  h+='<head><meta charset="UTF-8">';
  h+='<!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets>';
  h+='<x:ExcelWorksheet><x:Name>Executive Summary</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>';
  h+='<x:ExcelWorksheet><x:Name>Action Plan</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>';
  h+='<x:ExcelWorksheet><x:Name>Findings Detail</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>';
  h+='<x:ExcelWorksheet><x:Name>By Framework</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>';
  h+='<x:ExcelWorksheet><x:Name>By Resource</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>';
  h+='</x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]-->';
  h+='<style>td,th{font-family:Calibri,sans-serif;font-size:11pt;border:1px solid #ddd;padding:4px 8px;vertical-align:top}th{background:#1e3a5f;color:#fff;font-weight:bold}</style>';
  h+='</head><body>';
  // Executive Summary sheet
  h+='<div id="Executive_x0020_Summary"><table>';
  h+='<tr><th colspan="2" style="background:#0a0e17;color:#06b6d4;font-size:16pt">Azure Compliance Report</th></tr>';
  h+='<tr><td><b>Generated</b></td><td>'+new Date().toISOString().slice(0,19).replace('T',' ')+'</td></tr>';
  h+='<tr><td><b>Total Findings</b></td><td><b>'+filtered.length+'</b></td></tr>';
  h+='<tr><td colspan="2"></td></tr>';
  h+='<tr><th colspan="2" style="text-align:left">By Priority</th></tr>';
  const tiers=view.tiers;
  _PRIORITY_KEYS.forEach(t=>{
    const meta=_TIER_META[t];const rgs=tiers[t];
    const cnt=view.filteredTierCounts[t];
    const eff=_estimateTotalEffort(rgs);
    h+='<tr><td style="background:'+(tierBg[meta.name]||'#f1f5f9')+';font-weight:bold;color:'+meta.color+'">'+meta.name+'</td><td>'+cnt+' findings &bull; '+eff+'</td></tr>';
  });
  h+='<tr><td colspan="2"></td></tr>';
  h+='<tr><th colspan="2" style="text-align:left">By Severity</th></tr>';
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(sev=>{
    h+='<tr><td style="background:'+sevBg[sev]+';color:'+sevTxt[sev]+';font-weight:bold">'+sev+'</td><td>'+view.sevCounts[sev]+'</td></tr>';
  });
  h+='<tr><td colspan="2"></td></tr>';
  h+='<tr><th colspan="2" style="text-align:left">By Framework</th></tr>';
  const fws=[...new Set(filtered.map(f=>f.framework))].sort();
  fws.forEach(fw=>{h+='<tr><td><b>'+esc(fw)+'</b></td><td>'+filtered.filter(f=>f.framework===fw).length+'</td></tr>'});
  h+='</table></div>';
  // Action Plan sheet: tier-grouped resource summaries
  h+='<div id="Action_x0020_Plan"><table>';
  h+='<tr><th>Priority</th><th>Resource</th><th>Findings</th><th>Worst Severity</th><th>Est. Effort</th><th>Controls</th></tr>';
  _PRIORITY_KEYS.forEach(t=>{
    const meta=_TIER_META[t];const rgs=tiers[t];
    rgs.forEach(rg=>{
      const controls=rg.findings.map(f=>f.control).join(', ');
      const effort=_estimateTotalEffort([rg]);
      h+='<tr>';
      h+='<td style="background:'+(tierBg[meta.name]||'#f1f5f9')+';color:'+meta.color+';font-weight:bold">'+meta.name+'</td>';
      h+='<td>'+esc(rg.resourceName)+'</td>';
      h+='<td style="text-align:center">'+rg.findings.length+'</td>';
      h+='<td style="background:'+sevBg[rg.worstSev]+';color:'+sevTxt[rg.worstSev]+';font-weight:bold">'+rg.worstSev+'</td>';
      h+='<td>'+esc(effort)+'</td>';
      h+='<td>'+esc(controls)+'</td>';
      h+='</tr>';
    });
  });
  h+='</table></div>';
  // Findings Detail sheet: now with Priority and Effort columns
  h+='<div id="Findings_x0020_Detail"><table>';
  h+='<tr><th>Priority</th><th>Effort</th><th>Severity</th><th>Framework</th><th>Control</th><th>Resource</th><th>Resource Name</th><th>Finding</th>';
  if(options.includeRemediation)h+='<th>Remediation</th>';
  h+='</tr>';
  const sorted=[...filtered].sort((a,b)=>{const ta=a._tier,tb=b._tier;if(ta!==tb)return(_PRIORITY_ORDER[ta]||9)-(_PRIORITY_ORDER[tb]||9);return(_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9)});
  sorted.forEach(f=>{
    const tier=f._tier;const tm=_TIER_META[tier];
    const efLabel=_EFFORT_LABELS[f._effort];
    h+='<tr>';
    h+='<td style="background:'+(tierBg[tm.name]||'#f1f5f9')+';color:'+tm.color+';font-weight:bold">'+tm.name+'</td>';
    h+='<td style="background:'+(effortBg[efLabel]||'#f1f5f9')+'">'+esc(efLabel)+'</td>';
    h+='<td style="background:'+sevBg[f.severity]+';color:'+sevTxt[f.severity]+';font-weight:bold">'+f.severity+'</td>';
    h+='<td>'+esc(f.framework)+'</td><td>'+esc(f.control)+(f.ckv?' ('+esc(f.ckv)+')':'')+'</td><td>'+esc(f.resource)+'</td><td>'+esc(f.resourceName||'')+'</td><td>'+esc(f.message)+'</td>';
    if(options.includeRemediation)h+='<td>'+esc(f.remediation)+'</td>';
    h+='</tr>';
  });
  h+='</table></div>';
  // Pre-compute counts in maps (O(n) instead of O(n²))
  const fwCounts={},resCounts={};
  filtered.forEach(f=>{
    const fw=f.framework,sev=f.severity,res=f.resourceName||f.resource;
    if(!fwCounts[fw])fwCounts[fw]={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,total:0};
    fwCounts[fw][sev]++;fwCounts[fw].total++;
    if(!resCounts[res])resCounts[res]={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,total:0};
    resCounts[res][sev]++;resCounts[res].total++;
  });
  // By Framework sheet
  h+='<div id="By_x0020_Framework"><table>';
  h+='<tr><th>Framework</th><th style="background:#991b1b">CRITICAL</th><th style="background:#b91c1c">HIGH</th><th style="background:#92400e">MEDIUM</th><th style="background:#1e40af">LOW</th><th>Total</th></tr>';
  fws.forEach(fw=>{
    const fc=fwCounts[fw]||{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,total:0};
    h+='<tr><td style="font-weight:bold">'+esc(fw)+'</td>';
    ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(sev=>{
      const c=fc[sev];
      h+='<td style="text-align:center;'+(c>0?'background:'+sevBg[sev]+';color:'+sevTxt[sev]+';font-weight:bold':'')+'">'+c+'</td>';
    });
    h+='<td style="font-weight:bold;text-align:center">'+fc.total+'</td></tr>';
  });
  h+='</table></div>';
  // By Resource sheet
  h+='<div id="By_x0020_Resource"><table>';
  h+='<tr><th>Resource</th><th style="background:#991b1b">CRITICAL</th><th style="background:#b91c1c">HIGH</th><th style="background:#92400e">MEDIUM</th><th style="background:#1e40af">LOW</th><th>Total</th></tr>';
  const resources=Object.keys(resCounts).sort();
  resources.forEach(res=>{
    const rc=resCounts[res];
    h+='<tr><td>'+esc(res)+'</td>';
    ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(sev=>{
      const c=rc[sev];
      h+='<td style="text-align:center;'+(c>0?'background:'+sevBg[sev]+';color:'+sevTxt[sev]+';font-weight:bold':'')+'">'+c+'</td>';
    });
    h+='<td style="font-weight:bold;text-align:center">'+rc.total+'</td></tr>';
  });
  h+='</table></div>';
  h+='</body></html>';
  compDashboardDownload(new Blob([h],{type:'text/html'}),'compliance-report.html');
}
function _exportFilteredCSV(findings,options){
  const view=_buildComplianceView({findings:findings||compDashboardFindings(),frameworks:options.frameworks,severities:options.severities,includeMuted:options.includeMuted});
  const filtered=view.filtered;
  const cols=['Priority','Effort','Severity','Framework','Control','CKV','Resource','Resource Name','Message'];
  if(options.includeRemediation)cols.push('Remediation');
  const rows=[cols];
  const sorted=[...filtered].sort((a,b)=>{if(a._tier!==b._tier)return(_PRIORITY_ORDER[a._tier]||9)-(_PRIORITY_ORDER[b._tier]||9);return(_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9)});
  sorted.forEach(f=>{
    const r=[_TIER_META[f._tier].name,_EFFORT_LABELS[f._effort],f.severity,f.framework,f.control,f.ckv||'',f.resource,f.resourceName||'',f.message];
    if(options.includeRemediation)r.push(f.remediation);
    rows.push(r);
  });
  const csv=rows.map(r=>r.map(c=>'"'+String(c).replace(/"/g,'""')+'"').join(',')).join('\n');
  compDashboardDownload(new Blob([csv],{type:'text/csv'}),'compliance-report.csv');
}
function _exportComplianceHTML(findings,options){
  const view=_buildComplianceView({findings:findings||compDashboardFindings(),frameworks:options.frameworks,severities:options.severities,includeMuted:options.includeMuted});
  const filtered=view.filtered;
  const esc=s=>String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const now=new Date().toISOString().slice(0,19).replace('T',' ');
  const overall=view.score;
  const sevColors={CRITICAL:{bg:'#fecaca',text:'#991b1b',bar:'#dc2626'},HIGH:{bg:'#fee2e2',text:'#b91c1c',bar:'#ef4444'},MEDIUM:{bg:'#fef3c7',text:'#92400e',bar:'#f59e0b'},LOW:{bg:'#dbeafe',text:'#1e40af',bar:'#3b82f6'}};
  const sevCounts=view.sevCounts;let maxSev=0;
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s=>{if(sevCounts[s]>maxSev)maxSev=sevCounts[s]});
  const fwScores=['CIS','WAF','IAM','ARCH','SOC2','PCI'].map(fw=>{
    const ff=filtered.filter(f=>f.framework===fw);
    const sc=_calcComplianceScore(ff);
    return{fw,label:_FW_LABELS[fw],count:ff.length,...sc};
  });
  const tiers=view.tiers;
  let h='<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Azure Compliance Report: Action Plan</title>';
  h+='<style>';
  h+='*{margin:0;padding:0;box-sizing:border-box}';
  h+='body{font-family:"Segoe UI",system-ui,-apple-system,sans-serif;color:#1e293b;background:#fff;max-width:1100px;margin:0 auto;padding:40px 32px;line-height:1.5}';
  h+='h1{font-size:28px;font-weight:700;color:#0f172a;margin-bottom:4px}';
  h+='.subtitle{font-size:13px;color:#64748b;margin-bottom:32px}';
  h+='h2{font-size:18px;font-weight:600;color:#0f172a;margin:36px 0 16px;padding-bottom:8px;border-bottom:2px solid #e2e8f0}';
  h+='h3{font-size:14px;font-weight:600;color:#475569;margin-bottom:12px}';
  h+='.exec-grid{display:grid;grid-template-columns:200px 1fr;gap:32px;align-items:start}';
  h+='.score-ring{width:160px;height:160px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto}';
  h+='.score-inner{width:120px;height:120px;border-radius:50%;background:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center}';
  h+='.score-inner .score-val{font-size:48px;font-weight:800;line-height:1}';
  h+='.score-inner .score-grade{font-size:20px;font-weight:700;margin-top:2px}';
  h+='.score-inner .score-lbl{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px}';
  h+='.sev-bars{margin:8px 0 0}';
  h+='.sev-bar-row{display:flex;align-items:center;margin-bottom:8px}';
  h+='.sev-bar-label{width:72px;font-size:12px;font-weight:600;text-transform:uppercase}';
  h+='.sev-bar-track{flex:1;height:22px;background:#f1f5f9;border-radius:4px;overflow:hidden}';
  h+='.sev-bar-fill{height:100%;border-radius:4px}';
  h+='.sev-bar-count{width:40px;text-align:right;font-size:13px;font-weight:700;margin-left:8px}';
  h+='.meta-row{display:flex;gap:24px;margin-top:16px;font-size:13px;color:#64748b}';
  // Action summary cards
  h+='.action-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:24px 0 32px}';
  h+='.action-card{border-radius:10px;padding:20px 24px;text-align:center;border:1px solid}';
  h+='.action-card .ac-count{font-size:36px;font-weight:800;line-height:1}';
  h+='.action-card .ac-label{font-size:14px;font-weight:700;margin-top:4px;text-transform:uppercase;letter-spacing:0.5px}';
  h+='.action-card .ac-effort{font-size:12px;margin-top:6px;opacity:.8}';
  h+='.action-card .ac-resources{font-size:11px;margin-top:2px;opacity:.6}';
  // Tier sections
  h+='.tier-section{margin-bottom:32px;page-break-inside:avoid}';
  h+='.tier-header{display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:8px;margin-bottom:16px}';
  h+='.tier-header h3{margin:0;font-size:16px;font-weight:700}';
  h+='.tier-header .th-stats{font-size:12px;opacity:.7;margin-left:auto}';
  // Resource cards
  h+='.resource-card{border:1px solid #e2e8f0;border-radius:8px;margin-bottom:12px;overflow:hidden;page-break-inside:avoid}';
  h+='.rc-header{display:flex;align-items:center;gap:10px;padding:12px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0}';
  h+='.rc-sev-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}';
  h+='.rc-name{font-family:"SF Mono",Consolas,monospace;font-size:12px;font-weight:600;color:#334155}';
  h+='.rc-count{margin-left:auto;font-size:11px;color:#64748b}';
  h+='.rc-body{padding:0}';
  h+='.finding-row{display:grid;grid-template-columns:72px 72px 1fr 90px;gap:8px;padding:10px 16px;border-bottom:1px solid #f1f5f9;align-items:start;font-size:12px}';
  h+='.finding-row:last-child{border-bottom:none}';
  h+='.fr-remediation{color:#64748b;font-size:11px;margin-top:4px;line-height:1.4}';
  h+='.effort-tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;letter-spacing:0.3px}';
  h+='.effort-low{background:#dcfce7;color:#166534}';
  h+='.effort-med{background:#fef3c7;color:#92400e}';
  h+='.effort-high{background:#fee2e2;color:#991b1b}';
  // Severity badges
  h+='.sev-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:0.5px}';
  // Framework grid
  h+='.fw-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}';
  h+='.fw-card{border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center}';
  h+='.fw-card .fw-score{font-size:32px;font-weight:800;line-height:1}';
  h+='.fw-card .fw-grade{font-size:14px;font-weight:700;margin-top:2px}';
  h+='.fw-card .fw-name{font-size:12px;color:#64748b;margin-top:6px;text-transform:uppercase;letter-spacing:0.5px}';
  h+='.fw-card .fw-count{font-size:11px;color:#94a3b8;margin-top:2px}';
  // Appendix table
  h+='table{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:24px}';
  h+='thead th{background:#f8fafc;color:#475569;font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:0.5px;padding:8px 10px;text-align:left;border-bottom:2px solid #e2e8f0}';
  h+='tbody td{padding:6px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}';
  h+='.resource-name{font-family:"SF Mono",Consolas,monospace;font-size:11px;color:#334155;word-break:break-all}';
  h+='.text-muted{color:#94a3b8;font-style:italic}';
  h+='@media print{';
  h+='body{padding:20px;max-width:100%;font-size:11px}';
  h+='h1{font-size:22px}h2{font-size:16px;margin-top:24px;page-break-after:avoid}';
  h+='.exec-grid{grid-template-columns:180px 1fr;gap:24px}';
  h+='.action-summary{grid-template-columns:repeat(3,1fr)}';
  h+='.fw-grid{grid-template-columns:repeat(3,1fr)}';
  h+='.tier-section{page-break-before:auto}';
  h+='table{font-size:9px;page-break-inside:auto}';
  h+='thead{display:table-header-group}';
  h+='tr{page-break-inside:avoid;page-break-after:auto}';
  h+='thead th{background:#f0f0f0 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}';
  h+='.sev-badge,.sev-bar-fill,.score-ring,.fw-card,.action-card,.tier-header,.effort-tag,.rc-sev-dot{-webkit-print-color-adjust:exact;print-color-adjust:exact}';
  h+='}';
  h+='</style></head><body>';
  // Header
  h+='<h1>Azure Compliance Report</h1>';
  h+='<p class="subtitle">Generated '+esc(now)+' &bull; '+filtered.length+' findings across '+options.frameworks.length+' frameworks</p>';
  // Executive summary
  h+='<h2>Executive Summary</h2>';
  h+='<div class="exec-grid"><div>';
  const ringBg='conic-gradient('+overall.color+' '+(overall.score*3.6)+'deg, #e2e8f0 '+(overall.score*3.6)+'deg)';
  h+='<div class="score-ring" style="background:'+ringBg+'">';
  h+='<div class="score-inner">';
  h+='<div class="score-val" style="color:'+overall.color+'">'+overall.score+'</div>';
  h+='<div class="score-grade" style="color:'+overall.color+'">'+overall.grade+'</div>';
  h+='<div class="score-lbl">Score</div>';
  h+='</div></div></div><div>';
  h+='<h3>Severity Breakdown</h3><div class="sev-bars">';
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s=>{
    const pct=maxSev>0?Math.round((sevCounts[s]/maxSev)*100):0;
    const c=sevColors[s];
    h+='<div class="sev-bar-row">';
    h+='<div class="sev-bar-label" style="color:'+c.text+'">'+s+'</div>';
    h+='<div class="sev-bar-track"><div class="sev-bar-fill" style="width:'+pct+'%;background:'+c.bar+'"></div></div>';
    h+='<div class="sev-bar-count" style="color:'+c.text+'">'+sevCounts[s]+'</div>';
    h+='</div>';
  });
  h+='</div>';
  h+='<div class="meta-row">';
  h+='<span><strong>Total:</strong> '+filtered.length+'</span>';
  h+='<span><strong>Active:</strong> '+filtered.filter(f=>!_isMuted(f)).length+'</span>';
  h+='<span><strong>Muted:</strong> '+filtered.filter(f=>_isMuted(f)).length+'</span>';
  h+='</div>';
  h+='</div></div>';
  // Action Plan Summary
  h+='<h2>Action Plan</h2>';
  h+='<div class="action-summary">';
  _PRIORITY_KEYS.forEach(t=>{
    const meta=_TIER_META[t];const rgs=tiers[t];
    const fCount=view.filteredTierCounts[t];
    const effort=_estimateTotalEffort(rgs);
    h+='<div class="action-card" style="background:'+meta.bg+';border-color:'+meta.border+';color:'+meta.color+'">';
    h+='<div class="ac-count">'+fCount+'</div>';
    h+='<div class="ac-label">'+esc(meta.name)+'</div>';
    h+='<div class="ac-effort">'+esc(effort)+' estimated</div>';
    h+='<div class="ac-resources">'+rgs.length+' resource'+(rgs.length!==1?'s':'')+'</div>';
    h+='</div>';
  });
  h+='</div>';
  // Tier sections with resource cards
  const sevDotColors={CRITICAL:'#dc2626',HIGH:'#ef4444',MEDIUM:'#f59e0b',LOW:'#3b82f6'};
  _PRIORITY_KEYS.forEach(t=>{
    const meta=_TIER_META[t];const rgs=tiers[t];
    if(!rgs.length)return;
    const sevFindings=view.filteredTierCounts[t];
    const effort=_estimateTotalEffort(rgs);
    h+='<div class="tier-section">';
    h+='<div class="tier-header" style="background:'+meta.bg+';border-left:4px solid '+meta.color+'">';
    h+='<h3 style="color:'+meta.color+';margin:0">'+esc(meta.name)+'</h3>';
    h+='<div class="th-stats" style="color:'+meta.color+'">'+sevFindings+' finding'+(sevFindings!==1?'s':'')+' &bull; '+rgs.length+' resource'+(rgs.length!==1?'s':'')+' &bull; '+esc(effort)+'</div>';
    h+='</div>';
    rgs.forEach((rg,ri)=>{
      h+='<div class="resource-card">';
      h+='<div class="rc-header">';
      h+='<span class="rc-sev-dot" style="background:'+(sevDotColors[rg.worstSev]||'#3b82f6')+'"></span>';
      h+='<span class="rc-name">'+esc(rg.resourceName)+'</span>';
      h+='<span class="rc-count">'+rg.findings.length+' finding'+(rg.findings.length!==1?'s':'')+'</span>';
      h+='</div>';
      h+='<div class="rc-body">';
      rg.findings.forEach((f,fi)=>{
        const sc=sevColors[f.severity]||sevColors.LOW;
        const effortClass=f._effort||f.effort||_getEffort(f);
        const effortLabel=_EFFORT_LABELS[effortClass]||effortClass;
        h+='<div class="finding-row">';
        h+='<span class="sev-badge" style="background:'+sc.bg+';color:'+sc.text+'">'+f.severity+'</span>';
        h+='<span style="font-size:11px;font-weight:600;color:#475569">'+esc(f.control)+(f.ckv?' <span style="font-weight:400;opacity:.5;font-size:9px">('+esc(f.ckv)+')</span>':'')+'</span>';
        h+='<div><span>'+esc(f.message)+'</span>';
        if(f.remediation)h+='<div class="fr-remediation"><strong>Fix:</strong> '+esc(f.remediation)+'</div>';
        h+='</div>';
        h+='<span class="effort-tag effort-'+effortClass+'">'+esc(effortLabel)+'</span>';
        h+='</div>';
      });
      h+='</div></div>';
    });
    h+='</div>';
  });
  // Framework Scorecard
  h+='<h2>Framework Scores</h2><div class="fw-grid">';
  fwScores.forEach(fw=>{
    h+='<div class="fw-card" style="border-top:3px solid '+fw.color+'">';
    h+='<div class="fw-score" style="color:'+fw.color+'">'+fw.score+'</div>';
    h+='<div class="fw-grade" style="color:'+fw.color+'">'+fw.grade+'</div>';
    h+='<div class="fw-name">'+esc(fw.label)+'</div>';
    h+='<div class="fw-count">'+fw.count+' finding'+(fw.count!==1?'s':'')+'</div>';
    h+='</div>';
  });
  h+='</div>';
  // Appendix: Full Findings Table
  h+='<h2>Appendix: Full Findings</h2>';
  h+='<table><thead><tr><th>Priority</th><th>Effort</th><th>Severity</th><th>Framework</th><th>Control</th><th>Resource</th><th>Finding</th>';
  if(options.includeRemediation)h+='<th>Remediation</th>';
  h+='</tr></thead><tbody>';
  const sortedFindings=[...filtered].sort((a,b)=>{
    const ta=_classifyTier(a),tb=_classifyTier(b);
    if(ta!==tb)return(_PRIORITY_ORDER[ta]||9)-(_PRIORITY_ORDER[tb]||9);
    return(_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9);
  });
  sortedFindings.forEach(f=>{
    const c=sevColors[f.severity]||sevColors.LOW;
    const tier=_classifyTier(f);const tm=_TIER_META[tier];
    const effortClass=_getEffort(f);
    h+='<tr>';
    h+='<td><span style="color:'+tm.color+';font-weight:700;font-size:10px">'+esc(tm.name)+'</span></td>';
    h+='<td><span class="effort-tag effort-'+effortClass+'" style="font-size:9px">'+esc(_EFFORT_LABELS[effortClass])+'</span></td>';
    h+='<td><span class="sev-badge" style="background:'+c.bg+';color:'+c.text+'">'+f.severity+'</span></td>';
    h+='<td>'+esc(f.framework)+'</td>';
    h+='<td>'+esc(f.control)+(f.ckv?' <span style="opacity:.5;font-size:9px">('+esc(f.ckv)+')</span>':'')+'</td>';
    h+='<td class="resource-name">'+esc(f.resourceName||f.resource)+'</td>';
    h+='<td>'+esc(f.message)+'</td>';
    if(options.includeRemediation)h+='<td>'+esc(f.remediation||'')+'</td>';
    h+='</tr>';
  });
  if(!sortedFindings.length)h+='<tr><td colspan="'+(options.includeRemediation?8:7)+'" class="text-muted" style="text-align:center;padding:24px">No findings match the selected filters.</td></tr>';
  h+='</tbody></table>';
  h+='<p style="text-align:center;color:#94a3b8;font-size:11px;margin-top:32px;border-top:1px solid #e2e8f0;padding-top:16px">Azure Mapper Compliance Report &bull; '+esc(now)+'</p>';
  h+='</body></html>';
  compDashboardDownload(new Blob([h],{type:'text/html'}),'compliance-report.html');
}
function _openCompExportModal(){
  document.getElementById('compExportModal').classList.add('open');
  _updateCompExpPreview();
}
function _updateCompExpPreview(){
  var isFull=document.getElementById('compExpScopeFull')&&document.getElementById('compExpScopeFull').checked;
  if(isFull){
    var parts=[];
    if(GovernanceClassification.data.length) parts.push(GovernanceClassification.data.length+' classified');
    var allFindings=compDashboardFindings();
    if(allFindings.length) parts.push(allFindings.length+' findings');
    if(_iamReviewData&&_iamReviewData.length) parts.push(_iamReviewData.length+' IAM principals');
    if(_inventoryData&&_inventoryData.length) parts.push(_inventoryData.length+' resources');
    document.getElementById('compExpPreview').textContent=parts.length?'Full assessment: '+parts.join(', '):'No data loaded';
    document.getElementById('compExpDownload').disabled=!parts.length;
    return;
  }
  var fws=[...document.querySelectorAll('#compExportModal [data-comp-fw]:checked')].map(el=>el.dataset.compFw);
  var sevs=[...document.querySelectorAll('#compExportModal [data-comp-sev]:checked')].map(el=>el.dataset.compSev);
  var inclMuted=document.getElementById('compExpMuted').checked;
  var count=compDashboardFindings().filter(f=>
    fws.includes(f.framework)&&sevs.includes(f.severity)&&
    (inclMuted||!_isMuted(f))
  ).length;
  document.getElementById('compExpPreview').textContent=count+' findings will be exported';
  document.getElementById('compExpDownload').disabled=count===0;
}
function addComplianceChip(sb2,findings){
  const c=document.createElement('div');
  // OPTIMIZED: Single pass to count severities instead of multiple filter() calls
  const counts=findings.reduce((acc,f)=>{acc[f.severity]=(acc[f.severity]||0)+1;return acc},{});
  const crit=counts.CRITICAL||0;const high=counts.HIGH||0;
  c.className='compliance-chip '+(crit>0?'critical':high>0?'warn':'clean');
  c.innerHTML=`<b>${findings.length}</b> Compliance`;
  c.addEventListener('click',()=>renderCompliancePanel(findings));
  sb2.appendChild(c);
}
function _addBUDRChip(sb2){
  if(!_budrAssessments.length)return;
  const counts=_getBUDRTierCounts();
  const c=document.createElement('div');
  const cls=counts.at_risk>0?'critical':counts.partial>0?'warn':'clean';
  c.className='compliance-chip '+cls;
  c.innerHTML='<b>'+_budrAssessments.length+'</b> BUDR';
  c.title=counts.protected+' protected, '+counts.partial+' partial, '+counts.at_risk+' at risk';
  c.addEventListener('click',openBUDRDash);
  sb2.appendChild(c);
}

// #endregion COMPLIANCE DASHBOARD

