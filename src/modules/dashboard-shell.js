// #region UNIFIED DASHBOARD
// === UNIFIED DASHBOARD TAB REGISTRY ===
function dashboardRuntimeContext(){
  return AppRenderContext.createRenderContext();
}

function dashboardRlCtx(){
  return dashboardRuntimeContext().rlCtx;
}

function dashboardFindings(){
  return dashboardRuntimeContext().complianceFindings || [];
}

function dashboardRequireMapData(){
  var ctx = dashboardRlCtx();
  if(!ctx) dashboardNotify('Render map data first','warn');
  return ctx;
}

function dashboardNotify(message,type){
  AppNotifications.show(message,type);
}

function dashboardDownload(blob,name){
  AppDownloads.saveBlob(blob,name);
}

function dashboardEsc(value){
  return String(value||'')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function dashboardOpenResourceDetail(rid){
  if(!rid)return;
  closeUnifiedDash();
  setTimeout(function(){
    if(typeof ResourceNavigation!=='undefined'&&ResourceNavigation.zoomAndOpenDetail){
      ResourceNavigation.zoomAndOpenDetail(rid);
    }
  },250);
}

const DASHBOARD_TABS = [
  {id:'classification', label:'Classification', color:'#a78bfa', icon:'', prereq:function(){
    var ctx=dashboardRequireMapData();if(!ctx)return false;
    GovernanceClassification.ensure(ctx);
    return true;
  }, render:function(){ _renderClassificationTab(); }},
  {id:'appsummary', label:'App Summary', color:'#34d399', icon:'', prereq:function(){
    if(_importedReportData&&_appRegistry.length) return true;
    var ctx=dashboardRequireMapData();if(!ctx)return false;
    GovernanceClassification.ensure(ctx);
    return true;
  }, render:function(){ _renderAppSummaryTab(); }},
  {id:'iam', label:'IAM Review', color:'#f472b6', icon:'', prereq:function(){
    if(_importedReportData&&_iamReviewData.length) return true;
    var ctx=dashboardRequireMapData();if(!ctx)return false;
    if(!_iamReviewData.length){
      try{var iamRaw=safeParse(gv('in_rbac'));
      if(iamRaw){var p=parseIAMData(iamRaw);if(p)prepareIAMReviewData(p)}}catch(e){console.warn('IAM parse error in prereq:',e)}
    }
    return true;
  }, render:function(){ _renderIAMTab(); }},
  {id:'compliance', label:'Compliance', color:'#22d3ee', icon:'', prereq:function(){
    if(_importedReportData&&dashboardFindings().length) return true;
    if(!dashboardRequireMapData())return false;
    return true;
  }, render:function(){ _renderCompDash(); }},
  {id:'firewall', label:'Firewall', color:'#f59e0b', icon:'', prereq:function(){
    if(!dashboardRequireMapData())return false;
    return true;
  }, render:function(){ _renderFirewallTab(); }},
  {id:'budr', label:'BUDR', color:'#10b981', icon:'', prereq:function(){
    if(_importedReportData&&_budrAssessments.length) return true;
    var ctx=dashboardRequireMapData();if(!ctx)return false;
    if(!_budrAssessments||!_budrAssessments.length) runBUDRChecks(ctx);
    if(!_budrAssessments.length){dashboardNotify('No resources to assess');return false}
    return true;
  }, render:function(){ _renderBUDRDash(); }},
  {id:'inventory', label:'Inventory', color:'#f97316', icon:'', prereq:function(){
    if(_importedReportData&&_inventoryData.length) return true;
    if(!dashboardRequireMapData())return false;
    if(!_inventoryData.length) _buildInventoryData();
    return _inventoryData.length>0;
  }, render:function(){ _renderInventoryTab(); }},
  {id:'reports', label:'Reports', color:'#6366f1', icon:'', prereq:function(){ return true; }, render:function(){ _renderReportsTab(); }}
];

function openUnifiedDash(tabId){
  var tab=DASHBOARD_TABS.find(function(t){return t.id===tabId});
  if(!tab) return;
  if(!tab.prereq()) return;
  var el=document.getElementById('udash');
  var wasOpen=el.classList.contains('open');
  if(wasOpen&&tabId===DashboardState.getTab()) return;
  DashboardState.setTab(tabId);
  // Clean shared areas (prevents stale layout classes, hidden toolbars, wrong footers)
  document.getElementById('udashToolbar').textContent='';
  document.getElementById('udashBody').textContent='';
  document.getElementById('udashBody').className='udash-body';
  document.getElementById('udashFooter').textContent='';
  document.getElementById('udashToolbar').style.display='';
  _govToolbarTab=null;
  _compToolbarTab=null;
  _invToolbarRendered=false;
  el.classList.add('open');
  if(!wasOpen) el.offsetHeight; // force reflow only on first open
  _renderUdashTabs();
  tab.render();
}

function _switchUdashTab(tabId){
  if(tabId===DashboardState.getTab()) return;
  var tab=DASHBOARD_TABS.find(function(t){return t.id===tabId});
  if(!tab||!tab.prereq()) return;
  DashboardState.setTab(tabId);
  _renderUdashTabs();
  invalidateParseCache();
  // Close firewall full panel if open
  document.getElementById('fwFullPanel').classList.remove('open');
  // Clear shared areas
  document.getElementById('udashBody').onclick=null;
  document.getElementById('udashToolbar').textContent='';
  document.getElementById('udashBody').textContent='';
  document.getElementById('udashBody').className='udash-body';
  document.getElementById('udashFooter').textContent='';
  document.getElementById('udashToolbar').style.display='';
  // Reset toolbar tab guards
  _govToolbarTab=null;
  _compToolbarTab=null;
  _invToolbarRendered=false;
  tab.render();
}

function _renderUdashTabs(){
  var c=document.getElementById('udashTabs');
  c.textContent='';
  DASHBOARD_TABS.forEach(function(t){
    var btn=document.createElement('button');
    btn.className='udash-tab'+(t.id===DashboardState.getTab()?' active':'');
    btn.style.setProperty('--tab-color',t.color);
    btn.textContent=t.label;
    btn.addEventListener('click',function(){_switchUdashTab(t.id)});
    c.appendChild(btn);
  });
  // Account filter bar
  var bar=document.getElementById('udashAcctBar');
  var accts=typeof _rptUniqueAccounts==='function'?_rptUniqueAccounts():[];
  if(accts.length<2){bar.style.display='none';DashboardState.setAccountFilter('all');return}
  bar.style.display='flex';
  bar.textContent='';
  // "All" button
  var allBtn=document.createElement('button');
  allBtn.className='udash-acct-btn'+(DashboardState.getAccountFilter()==='all'?' active':'');
  allBtn.textContent='All';
  allBtn.addEventListener('click',function(){
    if(DashboardState.getAccountFilter()==='all') return;
    DashboardState.setAccountFilter('all');_renderUdashTabs();_refreshCurrentTab();
  });
  bar.appendChild(allBtn);
  // Per-account buttons
  accts.forEach(function(a){
    var btn=document.createElement('button');
    var color=typeof getAccountColor==='function'?getAccountColor(a.id):'';
    btn.className='udash-acct-btn'+(DashboardState.getAccountFilter()===a.id?' active':'');
    if(color){
      btn.style.setProperty('--acct-bg',color+'22');
      btn.style.setProperty('--acct-fg',color);
    }
    var dot=document.createElement('span');
    dot.className='acct-dot';
    dot.style.background=color||'var(--text-muted)';
    btn.appendChild(dot);
    btn.appendChild(document.createTextNode(a.label||a.id));
    btn.addEventListener('click',function(){
      DashboardState.setAccountFilter(DashboardState.getAccountFilter()===a.id?'all':a.id);
      _renderUdashTabs();_refreshCurrentTab();
    });
    bar.appendChild(btn);
  });
}

function _refreshCurrentTab(){
  var tab=DASHBOARD_TABS.find(function(t){return t.id===DashboardState.getTab()});
  if(!tab) return;
  document.getElementById('udashToolbar').textContent='';
  document.getElementById('udashBody').textContent='';
  document.getElementById('udashBody').className='udash-body';
  document.getElementById('udashFooter').textContent='';
  _govToolbarTab=null;_compToolbarTab=null;_invToolbarRendered=false;if(_compDashState)_compDashState._cachedView=null;
  tab.render();
}

function closeUnifiedDash(){
  document.getElementById('udash').classList.remove('open');
  document.getElementById('fwFullPanel').classList.remove('open');
  DashboardState.setTab(null);
  DashboardState.setAccountFilter('all');
  invalidateParseCache();
}

document.getElementById('udashClose').addEventListener('click',closeUnifiedDash);

// === COMPLIANCE DASHBOARD CONTROLS ===
// (Toolbar event listeners are now attached dynamically inside _renderCompDash)

// Inventory button
document.getElementById('inventoryBtn').addEventListener('click',function(){openUnifiedDash('inventory')});

// === GOVERNANCE DASHBOARD ===
function _closeAllDashboardsExcept(keep){_closeAllDashboards(keep)}

function openGovernanceDashboard(tab){
  if(tab==='iam') openUnifiedDash('iam');
  else openUnifiedDash('classification');
}

var _govToolbarTab=null;
var _compToolbarTab=null;

function _renderClassificationTab(){
  var tb=document.getElementById('udashToolbar');
  var body=document.getElementById('udashBody');
  var footer=document.getElementById('udashFooter');
  var st=_govDashState;
  // Toolbar: only rebuild on tab switch
  if(_govToolbarTab!=='classification'){
    _govToolbarTab='classification';
    var th='<label>Search</label>';
    th+='<input id="govSearch" type="text" placeholder="Filter by name, type, VNet..." value="'+dashboardEsc(st.search)+'">';
    th+='<label>Tier</label>';
    th+='<select id="govFilter">';
    ['all','critical','high','medium','low'].forEach(function(v){th+='<option value="'+v+'"'+(st.filter===v?' selected':'')+'>'+v.charAt(0).toUpperCase()+v.slice(1)+'</option>'});
    th+='</select>';
    th+='<label>Per page</label>';
    th+='<select id="govPerPage">';
    [25,50,100,0].forEach(function(v){th+='<option value="'+v+'"'+(st.perPage===v?' selected':'')+'>'+(v||'All')+'</option>'});
    th+='</select>';
    th+='<button id="govRulesBtn" style="margin-left:auto;background:rgba(139,92,246,.1);border:1px solid #8b5cf6;color:#8b5cf6;padding:4px 12px;border-radius:4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">Configure Rules</button>';
    tb.innerHTML=th;
    document.getElementById('govSearch').addEventListener('input',function(){st.search=this.value;st.page=1;_renderClassificationTab()});
    document.getElementById('govFilter').addEventListener('change',function(){st.filter=this.value;st.page=1;_renderClassificationTab()});
    document.getElementById('govPerPage').addEventListener('change',function(){st.perPage=parseInt(this.value)||0;st.page=1;_renderClassificationTab()});
    document.getElementById('govRulesBtn').addEventListener('click',_openRulesEditor);
  }
  // Summary cards (account-filtered)
  var classificationRows=GovernanceClassification.data;
  var _clasFiltered=_udashFilterByAccount(classificationRows);
  var counts={critical:0,high:0,medium:0,low:0};
  _clasFiltered.forEach(function(r){counts[r.tier]=(counts[r.tier]||0)+1});
  var bh='<div class="gov-tier-cards">';
  [{t:'critical',l:'Critical'},{t:'high',l:'High'},{t:'medium',l:'Medium'},{t:'low',l:'Low'}].forEach(function(d){
    var meta=GovernanceClassification.tierMeta(d.t);
    bh+='<div class="gov-tier-card" data-gov-tier="'+d.t+'" style="border-color:'+meta.color+'">';
    bh+='<h3 style="color:'+meta.color+'">'+d.l+'</h3>';
    bh+='<div class="gov-tier-count" style="color:'+meta.color+'">'+(counts[d.t]||0)+'</div>';
    bh+='<div class="gov-tier-meta">RPO: '+meta.rpo+' · RTO: '+meta.rto+'</div>';
    bh+='</div>';
  });
  bh+='</div>';
  // Build resource→app lookup from registry
  var _resAppMap={};
  _appRegistry.forEach(function(app){
    if(!app.pattern) return;
    var re=GovernanceClassification.safeRegex(app.pattern);if(!re) return;
    _clasFiltered.forEach(function(r){
      if(_resAppMap[r.id]) return;
      var text=(r.name||'')+' '+(r.type||'')+' '+(r.vpcName||'')+' '+Object.values(r.tags||{}).join(' ');
      if(re.test(text)) _resAppMap[r.id]=app.name;
    });
  });
  // Filter + sort
  var items=_clasFiltered.slice();
  if(st.filter!=='all') items=items.filter(function(r){return r.tier===st.filter});
  if(st.search){var q=st.search.toLowerCase();items=items.filter(function(r){return(r.name||'').toLowerCase().indexOf(q)!==-1||(r.type||'').toLowerCase().indexOf(q)!==-1||(r.id||'').toLowerCase().indexOf(q)!==-1||(r.vpcName||'').toLowerCase().indexOf(q)!==-1||(_resAppMap[r.id]||'').toLowerCase().indexOf(q)!==-1})}
  var sortKey=st.sort;var dir=st.sortDir==='asc'?1:-1;
  items.sort(function(a,b){
    if(sortKey==='tier') return(GovernanceClassification.tierMeta(a.tier).priority-GovernanceClassification.tierMeta(b.tier).priority)*dir;
    if(sortKey==='app'){var av=(_resAppMap[a.id]||'').toLowerCase();var bv=(_resAppMap[b.id]||'').toLowerCase();return av<bv?-dir:av>bv?dir:0}
    var av=(a[sortKey]||'').toLowerCase();var bv=(b[sortKey]||'').toLowerCase();
    return av<bv?-dir:av>bv?dir:0;
  });
  // Paginate
  var perPage=st.perPage<=0?items.length:st.perPage;
  var totalPages=Math.max(1,Math.ceil(items.length/perPage));
  st.page=Math.min(Math.max(1,st.page),totalPages);
  var start=(st.page-1)*perPage;
  var pageItems=items.slice(start,start+perPage);
  // Table
  var hasMultiAcct=items.some(function(r){return!!r._subscriptionId})&&new Set(items.map(function(r){return r._subscriptionId}).filter(Boolean)).size>1;
  var cols=[{key:'name',label:'Resource'},{key:'type',label:'Type'}];
  if(hasMultiAcct) cols.push({key:'_subscriptionId',label:'Account'});
  cols.push({key:'app',label:'App'},{key:'tier',label:'Tier'},{key:'rpo',label:'RPO',nosort:true},{key:'rto',label:'RTO',nosort:true},{key:'vpcName',label:'VNet'},{key:'auto',label:'Source',nosort:true},{key:'actions',label:'',nosort:true});
  bh+='<table class="gov-table"><thead><tr>';
  cols.forEach(function(c){
    var cls='';if(!c.nosort&&st.sort===c.key) cls=st.sortDir==='asc'?' sort-asc':' sort-desc';
    bh+='<th'+(c.nosort?'':' data-sort-col="'+c.key+'"')+' class="'+cls+'">'+c.label+'</th>';
  });
  bh+='</tr></thead><tbody>';
  if(!pageItems.length) bh+='<tr><td colspan="'+cols.length+'" style="text-align:center;padding:30px;color:var(--text-muted)">No resources match filters</td></tr>';
  pageItems.forEach(function(r){
    bh+='<tr>';
    bh+='<td><span class="gov-res-link" data-rid="'+dashboardEsc(r.id)+'" style="color:var(--accent-cyan);cursor:pointer">'+dashboardEsc(r.name)+'</span></td>';
    bh+='<td>'+dashboardEsc(r.type)+'</td>';
    if(hasMultiAcct) bh+='<td>'+_acctPill(r._subscriptionId)+'</td>';
    var appName=_resAppMap[r.id]||'';
    bh+='<td style="font-size:10px">'+(appName?'<span style="background:rgba(52,211,153,.12);color:#34d399;padding:1px 6px;border-radius:3px;font-size:9px">'+dashboardEsc(appName)+'</span>':'<span style="color:var(--text-muted)">—</span>')+'</td>';
    bh+='<td><span class="gov-tier-badge '+r.tier+'">'+r.tier+'</span></td>';
    bh+='<td>'+dashboardEsc(r.rpo)+'</td>';
    bh+='<td>'+dashboardEsc(r.rto)+'</td>';
    bh+='<td style="font-size:10px;color:var(--text-muted)">'+dashboardEsc(r.vpcName||'—')+'</td>';
    bh+='<td style="font-size:9px;color:var(--text-muted)">'+(r.auto?'Auto':'<span style="color:#8b5cf6">Manual</span>')+'</td>';
    bh+='<td><select class="gov-override-select" data-res-id="'+dashboardEsc(r.id)+'">';
    ['critical','high','medium','low'].forEach(function(t){bh+='<option value="'+t+'"'+(r.tier===t?' selected':'')+'>'+t+'</option>'});
    bh+='</select></td>';
    bh+='</tr>';
  });
  bh+='</tbody></table>';
  body.innerHTML=bh;
  body.scrollTop=0;
  // Footer
  var fh='<button id="govExportCSV">Export CSV</button>';
  fh+='<button id="govExportJSON">Export JSON</button>';
  fh+='<span style="margin-left:auto;font-size:10px;color:var(--text-muted)">'+items.length+' of '+classificationRows.length+'</span>';
  if(totalPages>1){
    fh+='<button id="govPrev"'+(st.page<=1?' disabled':'')+'>← Prev</button>';
    fh+='<span style="font-size:10px;color:var(--text-muted)">Page '+st.page+' of '+totalPages+'</span>';
    fh+='<button id="govNext"'+(st.page>=totalPages?' disabled':'')+'>Next →</button>';
  }
  footer.innerHTML=fh;
  // Wire body/footer events (these get recreated each render)
  if(document.getElementById('govPrev')) document.getElementById('govPrev').addEventListener('click',function(){st.page--;_renderClassificationTab()});
  if(document.getElementById('govNext')) document.getElementById('govNext').addEventListener('click',function(){st.page++;_renderClassificationTab()});
  // Sort headers
  body.querySelectorAll('th[data-sort-col]').forEach(function(th){
    th.addEventListener('click',function(){
      var col=this.dataset.sortCol;
      if(st.sort===col) st.sortDir=st.sortDir==='asc'?'desc':'asc';
      else{st.sort=col;st.sortDir='asc'}
      st.page=1;_renderClassificationTab();
    });
  });
  // Tier card clicks
  body.querySelectorAll('.gov-tier-card[data-gov-tier]').forEach(function(card){
    card.addEventListener('click',function(){
      var tier=this.dataset.govTier;
      st.filter=st.filter===tier?'all':tier;
      document.getElementById('govFilter').value=st.filter;
      st.page=1;_renderClassificationTab();
    });
  });
  // Override selects
  body.querySelectorAll('.gov-override-select').forEach(function(sel){
    sel.addEventListener('change',function(){
      var resId=this.dataset.resId;var newTier=this.value;
      GovernanceClassification.setOverride(resId,newTier);
      _renderClassificationTab();
    });
  });
  // Resource name clicks → jump to resource on map and open detail panel
  body.querySelectorAll('.gov-res-link').forEach(function(el){el.addEventListener('click',function(e){
    e.stopPropagation();dashboardOpenResourceDetail(this.dataset.rid);
  })});
  // Export
  document.getElementById('govExportCSV').addEventListener('click',function(){
    var rows=[['Resource','Type','App','Tier','RPO','RTO','Classification','VNet']];
    items.forEach(function(r){rows.push([r.name,r.type,_resAppMap[r.id]||'',r.tier,r.rpo,r.rto,r.auto?'Auto':'Manual',r.vpcName||''])});
    var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')}).join('\n');
    dashboardDownload(new Blob([csv],{type:'text/csv'}),'asset-classification.csv');
  });
  document.getElementById('govExportJSON').addEventListener('click',function(){
    dashboardDownload(new Blob([JSON.stringify(items,null,2)],{type:'application/json'}),'asset-classification.json');
  });
}

// === APP SUMMARY TAB ===
function _autoDiscoverApps(){
  if(_appAutoDiscovered) return;
  if(!GovernanceClassification.data.length) return;
  _appAutoDiscovered=true;
  var seen={};
  var candidates=['Application','app','App','Service','service','Product','product','Component','component','Project','project'];
  GovernanceClassification.data.forEach(function(r){
    if(!r.tags) return;
    candidates.forEach(function(tk){
      var val=r.tags[tk];
      if(!val) return;
      var key=val.toLowerCase();
      if(seen[key]) return;
      seen[key]=true;
      _appRegistry.push({name:val,pattern:val.replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/[\s_-]+/g,'[\\s_-]+'),type:'',tier:'',auto:true});
    });
  });
}

function _matchAppResources(app){
  if(!app.pattern) return[];
  var matched=[];
  var re=GovernanceClassification.safeRegex(app.pattern);if(!re) return[];
  GovernanceClassification.data.forEach(function(r){
    var text=(r.name||'')+' '+(r.type||'')+' '+(r.vpcName||'')+' '+Object.values(r.tags||{}).join(' ');
    if(re.test(text)) matched.push(r);
  });
  return matched;
}

function _buildAppRows(){
  var tierPri={critical:1,high:2,medium:3,low:4};
  return _appRegistry.map(function(app,idx){
    var matched=_udashFilterByAccount(_matchAppResources(app));
    var bestTier='low';
    var types={};var vpcs={};var accts={};
    matched.forEach(function(r){
      if((tierPri[r.tier]||99)<(tierPri[bestTier]||99)) bestTier=r.tier;
      types[r.type]=true;
      if(r.vpcName) vpcs[r.vpcName]=true;
      if(r._subscriptionId){var _al=typeof _rptAccountLabel==='function'?(_rptAccountLabel(r._subscriptionId)||r._subscriptionId):r._subscriptionId;accts[_al]=true}
    });
    var tier=app.tier||bestTier;
    var meta=GovernanceClassification.tierMeta(tier);
    return{idx:idx,name:app.name,pattern:app.pattern,type:app.type||'',tier:tier,autoTier:!app.tier,rpo:meta.rpo,rto:meta.rto,count:matched.length,types:Object.keys(types).join(', '),vpcs:Object.keys(vpcs).join(', '),accounts:Object.keys(accts),auto:app.auto};
  });
}

function _renderAppSummaryTab(){
  var tb=document.getElementById('udashToolbar');
  var body=document.getElementById('udashBody');
  var footer=document.getElementById('udashFooter');
  var st=_appSummaryState;
  _autoDiscoverApps();
  // Toolbar
  var th='<label>Search</label>';
  th+='<input id="appSearch" type="text" placeholder="Filter apps..." value="'+dashboardEsc(st.search)+'">';
  th+='<span style="margin-left:auto;display:flex;gap:6px">';
  th+='<button id="appDelSelBtn" style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#ef4444;padding:4px 12px;border-radius:4px;font-size:11px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer;display:none">Delete Selected</button>';
  th+='<button id="appClearAutoBtn" style="background:none;border:1px solid var(--border);color:var(--text-muted);padding:4px 12px;border-radius:4px;font-size:11px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">Clear Auto</button>';
  th+='<button id="appAddBtn" style="background:rgba(52,211,153,.15);border:1px solid #34d399;color:#34d399;padding:4px 14px;border-radius:4px;font-size:11px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">+ Add App</button>';
  th+='</span>';
  tb.innerHTML=th;
  document.getElementById('appSearch').addEventListener('input',function(){st.search=this.value;_renderAppSummaryTab()});
  document.getElementById('appAddBtn').addEventListener('click',function(){st.adding=true;st.editing=-1;_renderAppSummaryTab()});
  document.getElementById('appClearAutoBtn').addEventListener('click',function(){_appRegistry=_appRegistry.filter(function(a){return!a.auto});_renderAppSummaryTab()});
  // Build rows
  var apps=_buildAppRows();
  if(st.search){var q=st.search.toLowerCase();apps=apps.filter(function(a){return a.name.toLowerCase().indexOf(q)!==-1||(a.type||'').toLowerCase().indexOf(q)!==-1||a.types.toLowerCase().indexOf(q)!==-1})}
  // Sort
  var tierPri={critical:1,high:2,medium:3,low:4};
  var dir=st.sortDir==='asc'?1:-1;
  apps.sort(function(a,b){
    if(st.sort==='tier') return((tierPri[a.tier]||99)-(tierPri[b.tier]||99))*dir;
    if(st.sort==='count') return(a.count-b.count)*dir;
    var av=(a[st.sort]||'').toLowerCase();var bv=(b[st.sort]||'').toLowerCase();
    return av<bv?-dir:av>bv?dir:0;
  });
  // Tier summary cards
  var tierCounts={critical:0,high:0,medium:0,low:0};
  apps.forEach(function(a){tierCounts[a.tier]=(tierCounts[a.tier]||0)+1});
  var bh='<div class="gov-tier-cards">';
  [{t:'critical',l:'Critical'},{t:'high',l:'High'},{t:'medium',l:'Medium'},{t:'low',l:'Low'}].forEach(function(d){
    var meta=GovernanceClassification.tierMeta(d.t);
    bh+='<div class="gov-tier-card" style="border-color:'+meta.color+'">';
    bh+='<h3 style="color:'+meta.color+'">'+d.l+'</h3>';
    bh+='<div class="gov-tier-count" style="color:'+meta.color+'">'+(tierCounts[d.t]||0)+'</div>';
    bh+='</div>';
  });
  bh+='</div>';
  // Add/Edit form
  if(st.adding||st.editing>=0){
    var ed=st.editing>=0?_appRegistry[st.editing]:null;
    bh+='<div style="background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.25);border-radius:8px;padding:12px 16px;margin-bottom:12px;display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">';
    bh+='<div style="display:flex;flex-direction:column;gap:2px"><label style="font-size:9px;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif">App Name</label>';
    bh+='<input id="appFormName" type="text" placeholder="e.g. Quark" value="'+dashboardEsc(ed?ed.name:'')+'" style="width:140px;padding:4px 8px;font-size:11px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif"></div>';
    bh+='<div style="display:flex;flex-direction:column;gap:2px"><label style="font-size:9px;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif">Match Pattern <span style="opacity:.5">(regex)</span></label>';
    bh+='<input id="appFormPattern" type="text" placeholder="auto from name" value="'+dashboardEsc(ed?ed.pattern:'')+'" style="width:140px;padding:4px 8px;font-size:11px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:monospace"></div>';
    bh+='<div style="display:flex;flex-direction:column;gap:2px"><label style="font-size:9px;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif">Type</label>';
    bh+='<input id="appFormType" list="appTypeSuggestions" type="text" placeholder="e.g. Web App" value="'+dashboardEsc(ed?ed.type:'')+'" style="width:120px;padding:4px 8px;font-size:11px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif">';
    bh+='<datalist id="appTypeSuggestions">';
    _APP_TYPE_SUGGESTIONS.forEach(function(t){bh+='<option value="'+t+'">'});
    bh+='</datalist></div>';
    bh+='<div style="display:flex;flex-direction:column;gap:2px"><label style="font-size:9px;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif">Criticality</label>';
    bh+='<select id="appFormTier" style="width:110px;padding:4px 8px;font-size:11px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif">';
    bh+='<option value=""'+((!ed||!ed.tier)?' selected':'')+'>(auto)</option>';
    ['critical','high','medium','low'].forEach(function(t){bh+='<option value="'+t+'"'+((ed&&ed.tier===t)?' selected':'')+'>'+t.charAt(0).toUpperCase()+t.slice(1)+'</option>'});
    bh+='</select></div>';
    bh+='<button id="appFormSave" style="padding:4px 16px;font-size:11px;background:#34d399;border:none;border-radius:4px;color:#000;cursor:pointer;font-weight:600;font-family:Segoe UI,system-ui,sans-serif">'+(ed?'Update':'Add')+'</button>';
    bh+='<button id="appFormCancel" style="padding:4px 12px;font-size:11px;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text-muted);cursor:pointer;font-family:Segoe UI,system-ui,sans-serif">Cancel</button>';
    bh+='</div>';
  }
  // Table
  var appHasMultiAcct=apps.some(function(a){return a.accounts&&a.accounts.length>0})&&new Set(apps.reduce(function(s,a){return s.concat(a.accounts||[])},[]).filter(Boolean)).size>1;
  var cols=[{key:'name',label:'Application'},{key:'type',label:'Type'}];
  if(appHasMultiAcct) cols.push({key:'accounts',label:'Accounts',nosort:true});
  cols.push({key:'tier',label:'Criticality'},{key:'count',label:'Resources'},{key:'rpo',label:'RPO',nosort:true},{key:'rto',label:'RTO',nosort:true},{key:'actions',label:'',nosort:true});
  bh+='<table class="gov-table"><thead><tr>';
  bh+='<th style="width:28px"><input type="checkbox" id="appSelAll" style="cursor:pointer"></th>';
  cols.forEach(function(c){
    var cls='';if(!c.nosort&&st.sort===c.key) cls=st.sortDir==='asc'?' sort-asc':' sort-desc';
    bh+='<th'+(c.nosort?'':' data-sort-col="'+c.key+'"')+' class="'+cls+'">'+c.label+'</th>';
  });
  bh+='</tr></thead><tbody>';
  if(!apps.length) bh+='<tr><td colspan="'+(cols.length+1)+'" style="text-align:center;padding:30px;color:var(--text-muted)">No apps defined: click <b>+ Add App</b> to get started</td></tr>';
  apps.forEach(function(a){
    bh+='<tr data-app-idx="'+a.idx+'">';
    bh+='<td><input type="checkbox" class="app-sel-cb" data-idx="'+a.idx+'" style="cursor:pointer"></td>';
    bh+='<td><span style="font-weight:500">'+dashboardEsc(a.name)+'</span>'+(a.auto?' <span style="font-size:8px;color:var(--text-muted);opacity:.6">auto</span>':'')+'<br><span style="font-size:9px;color:var(--text-muted);font-family:monospace">'+dashboardEsc(a.pattern)+'</span></td>';
    bh+='<td style="font-size:10px">'+dashboardEsc(a.type||'—')+'</td>';
    if(appHasMultiAcct) bh+='<td>'+(a.accounts||[]).map(function(id){return _acctPill(id)}).join(' ')+'</td>';
    bh+='<td><span class="gov-tier-badge '+a.tier+'">'+a.tier+'</span>'+(a.autoTier&&a.auto?' <span style="font-size:8px;color:var(--text-muted)">auto</span>':'')+'</td>';
    bh+='<td style="text-align:center">'+a.count+'</td>';
    bh+='<td style="font-size:10px;color:var(--text-muted)">'+a.rpo+'</td>';
    bh+='<td style="font-size:10px;color:var(--text-muted)">'+a.rto+'</td>';
    bh+='<td><button class="app-edit-btn" data-idx="'+a.idx+'" style="font-size:9px;padding:2px 8px;cursor:pointer;background:none;border:1px solid var(--border);border-radius:3px;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif;margin-right:4px">Edit</button>';
    bh+='<button class="app-del-btn" data-idx="'+a.idx+'" style="font-size:9px;padding:2px 8px;cursor:pointer;background:none;border:1px solid rgba(239,68,68,.3);border-radius:3px;color:#ef4444;font-family:Segoe UI,system-ui,sans-serif">Del</button></td>';
    bh+='</tr>';
  });
  bh+='</tbody></table>';
  body.innerHTML=bh;
  body.scrollTop=0;
  // Footer
  var fh='<button id="appExportCSV">Export CSV</button>';
  fh+='<button id="appExportJSON">Export JSON</button>';
  fh+='<span style="margin-left:auto;font-size:10px;color:var(--text-muted)">'+_appRegistry.length+' apps · '+GovernanceClassification.data.length+' total resources</span>';
  footer.innerHTML=fh;
  // Wire form events
  if(st.adding||st.editing>=0){
    document.getElementById('appFormCancel').addEventListener('click',function(){st.adding=false;st.editing=-1;_renderAppSummaryTab()});
    document.getElementById('appFormSave').addEventListener('click',function(){
      var name=document.getElementById('appFormName').value.trim();
      if(!name){dashboardNotify('App name is required','warn');return}
      var pattern=document.getElementById('appFormPattern').value.trim()||name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/[\s_-]+/g,'[\\s_-]+');
      var type=document.getElementById('appFormType').value.trim();
      var tier=document.getElementById('appFormTier').value;
      if(st.editing>=0){
        _appRegistry[st.editing].name=name;
        _appRegistry[st.editing].pattern=pattern;
        _appRegistry[st.editing].type=type;
        _appRegistry[st.editing].tier=tier;
        _appRegistry[st.editing].auto=false;
      }else{
        _appRegistry.push({name:name,pattern:pattern,type:type,tier:tier,auto:false});
      }
      st.adding=false;st.editing=-1;
      _renderAppSummaryTab();
    });
  }
  // Wire table events
  body.querySelectorAll('th[data-sort-col]').forEach(function(hdr){
    hdr.addEventListener('click',function(){
      var col=this.dataset.sortCol;
      if(st.sort===col) st.sortDir=st.sortDir==='asc'?'desc':'asc';
      else{st.sort=col;st.sortDir='asc'}
      _renderAppSummaryTab();
    });
  });
  body.querySelectorAll('.app-edit-btn').forEach(function(btn){
    btn.addEventListener('click',function(){st.editing=parseInt(this.dataset.idx);st.adding=false;_renderAppSummaryTab()});
  });
  body.querySelectorAll('.app-del-btn').forEach(function(btn){
    btn.addEventListener('click',function(){
      var idx=parseInt(this.dataset.idx);
      _appRegistry.splice(idx,1);
      st.editing=-1;
      _renderAppSummaryTab();
    });
  });
  // Checkbox select-all + delete selected
  var delSelBtn=document.getElementById('appDelSelBtn');
  function _updateDelBtn(){
    var checked=body.querySelectorAll('.app-sel-cb:checked').length;
    delSelBtn.style.display=checked?'':'none';
    delSelBtn.textContent='Delete Selected ('+checked+')';
  }
  var selAll=document.getElementById('appSelAll');
  if(selAll) selAll.addEventListener('change',function(){
    var checked=this.checked;
    body.querySelectorAll('.app-sel-cb').forEach(function(cb){cb.checked=checked});
    _updateDelBtn();
  });
  body.querySelectorAll('.app-sel-cb').forEach(function(cb){cb.addEventListener('change',_updateDelBtn)});
  delSelBtn.addEventListener('click',function(){
    var toDelete={};
    body.querySelectorAll('.app-sel-cb:checked').forEach(function(cb){toDelete[cb.dataset.idx]=true});
    _appRegistry=_appRegistry.filter(function(_,i){return!toDelete[i]});
    st.editing=-1;
    _renderAppSummaryTab();
  });
  document.getElementById('appExportCSV').addEventListener('click',function(){
    var rows=[['Application','Type','Criticality','RPO','RTO','Resources','Resource Types','VNets']];
    apps.forEach(function(a){rows.push([a.name,a.type,a.tier,a.rpo,a.rto,a.count,a.types,a.vpcs])});
    var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')}).join('\n');
    dashboardDownload(new Blob([csv],{type:'text/csv'}),'app-summary.csv');
  });
  document.getElementById('appExportJSON').addEventListener('click',function(){
    dashboardDownload(new Blob([JSON.stringify(apps,null,2)],{type:'application/json'}),'app-summary.json');
  });
}

function _renderIAMTab(){
  var tb=document.getElementById('udashToolbar');
  var body=document.getElementById('udashBody');
  var footer=document.getElementById('udashFooter');
  var st=_iamDashState;
  // Toolbar: only rebuild on tab switch
  if(_govToolbarTab!=='iam'){
    _govToolbarTab='iam';
    var th='<label>Search</label>';
    th+='<input id="govSearch" type="text" placeholder="Filter by name, ARN, type..." value="'+dashboardEsc(st.search)+'">';
    th+='<label>Filter</label>';
    th+='<select id="govFilter">';
    [{v:'all',l:'All'},{v:'roles',l:'Roles Only'},{v:'users',l:'Users Only'},{v:'admin',l:'Admin Access'},{v:'findings',l:'With Findings'}].forEach(function(o){
      th+='<option value="'+o.v+'"'+(st.filter===o.v?' selected':'')+'>'+o.l+'</option>';
    });
    th+='</select>';
    th+='<label>Per page</label>';
    th+='<select id="govPerPage">';
    [25,50,100,0].forEach(function(v){th+='<option value="'+v+'"'+(st.perPage===v?' selected':'')+'>'+(v||'All')+'</option>'});
    th+='</select>';
    tb.innerHTML=th;
    document.getElementById('govSearch').addEventListener('input',function(){st.search=this.value;st.page=1;_renderIAMTab()});
    document.getElementById('govFilter').addEventListener('change',function(){st.filter=this.value;st.page=1;_renderIAMTab()});
    document.getElementById('govPerPage').addEventListener('change',function(){st.perPage=parseInt(this.value)||0;st.page=1;_renderIAMTab()});
  }
  if(!_iamReviewData.length){
    body.innerHTML='<div style="text-align:center;padding:60px;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif"><p style="font-size:14px">No IAM data loaded</p><p style="font-size:11px">Paste RBAC role assignment details (from <code>az role assignment list</code>) in the IAM section of the left panel, then re-render.</p></div>';
    footer.textContent='';
    return;
  }
  // Filter + sort (account filter applied first)
  var items=_udashFilterByAccount(_iamReviewData).slice();
  if(st.filter==='roles') items=items.filter(function(r){return r.type==='Role'});
  else if(st.filter==='users') items=items.filter(function(r){return r.type==='User'});
  else if(st.filter==='admin') items=items.filter(function(r){return r.isAdmin});
  else if(st.filter==='findings') items=items.filter(function(r){return r.findings.length>0});
  if(st.search){var q=st.search.toLowerCase();items=items.filter(function(r){return(r.name||'').toLowerCase().indexOf(q)!==-1||(r.arn||'').toLowerCase().indexOf(q)!==-1||(r.type||'').toLowerCase().indexOf(q)!==-1})}
  var sortKey=st.sort;var dir=st.sortDir==='asc'?1:-1;
  items.sort(function(a,b){
    if(sortKey==='lastUsed'||sortKey==='created'){return((a[sortKey]||0)-(b[sortKey]||0))*dir}
    var av=(a[sortKey]||'').toString().toLowerCase();var bv=(b[sortKey]||'').toString().toLowerCase();
    return av<bv?-dir:av>bv?dir:0;
  });
  // Paginate
  var perPage=st.perPage<=0?items.length:st.perPage;
  var totalPages=Math.max(1,Math.ceil(items.length/perPage));
  st.page=Math.min(Math.max(1,st.page),totalPages);
  var start=(st.page-1)*perPage;
  var pageItems=items.slice(start,start+perPage);
  // Summary (from account-filtered set)
  var _iamAll=_udashFilterByAccount(_iamReviewData);
  var roleCt=_iamAll.filter(function(r){return r.type==='Role'}).length;
  var userCt=_iamAll.filter(function(r){return r.type==='User'}).length;
  var adminCt=_iamAll.filter(function(r){return r.isAdmin}).length;
  var findCt=_iamAll.filter(function(r){return r.findings.length>0}).length;
  var bh='<div class="gov-tier-cards" style="margin-bottom:16px">';
  [{l:'Roles',c:roleCt,color:'#8b5cf6'},{l:'Users',c:userCt,color:'#22d3ee'},{l:'Admin',c:adminCt,color:'#ef4444'},{l:'With Findings',c:findCt,color:'#f59e0b'}].forEach(function(d){
    bh+='<div class="gov-tier-card" style="border-color:'+d.color+'"><h3 style="color:'+d.color+'">'+d.l+'</h3><div class="gov-tier-count" style="color:'+d.color+'">'+d.c+'</div></div>';
  });
  bh+='</div>';
  // Table
  var iamHasMultiAcct=new Set(items.map(function(r){return r._subscriptionId}).filter(Boolean)).size>1;
  var cols=[{key:'name',label:'Name'},{key:'type',label:'Type'}];
  if(iamHasMultiAcct) cols.push({key:'_subscriptionId',label:'Account'});
  cols.push({key:'created',label:'Created'},{key:'lastUsed',label:'Last Used'},{key:'policies',label:'Policies',nosort:true},{key:'admin',label:'Admin',nosort:true},{key:'findings',label:'Findings',nosort:true},{key:'cross',label:'Cross-Acct',nosort:true});
  bh+='<table class="gov-table"><thead><tr>';
  cols.forEach(function(c){
    var cls='';if(!c.nosort&&st.sort===c.key) cls=st.sortDir==='asc'?' sort-asc':' sort-desc';
    bh+='<th'+(c.nosort?'':' data-sort-col="'+c.key+'"')+' class="'+cls+'">'+c.label+'</th>';
  });
  bh+='</tr></thead><tbody>';
  if(!pageItems.length) bh+='<tr><td colspan="'+cols.length+'" style="text-align:center;padding:30px;color:var(--text-muted)">No IAM entities match filters</td></tr>';
  pageItems.forEach(function(r,idx){
    var rowId='iam-r-'+idx;
    bh+='<tr data-iam-row="'+rowId+'" style="cursor:pointer">';
    bh+='<td style="color:var(--accent-cyan)">'+dashboardEsc(r.name)+'</td>';
    bh+='<td>'+dashboardEsc(r.type)+'</td>';
    if(iamHasMultiAcct) bh+='<td>'+_acctPill(r._subscriptionId)+'</td>';
    bh+='<td style="font-size:10px">'+(r.created?r.created.toISOString().split('T')[0]:'—')+'</td>';
    bh+='<td style="font-size:10px">'+(r.lastUsed?r.lastUsed.toISOString().split('T')[0]:r.provider==='azure'?'Unknown':'Never')+'</td>';
    bh+='<td style="text-align:center">'+r.policies+'</td>';
    bh+='<td>'+(r.isAdmin?'<span class="gov-admin-badge">Admin</span>':'—')+'</td>';
    bh+='<td>'+(r.findings.length>0?'<span class="gov-finding-badge">'+r.findings.length+'</span>':'—')+'</td>';
    bh+='<td>'+(r.crossAccounts.length>0?'<span style="color:#f59e0b">'+r.crossAccounts.length+'</span>':'—')+'</td>';
    bh+='</tr>';
    // Expandable detail row
    bh+='<tr><td colspan="'+cols.length+'" class="gov-iam-expand" id="'+rowId+'-exp">';
    bh+='<div style="margin-bottom:6px"><b>ARN:</b> <code style="font-size:10px;background:var(--bg-input);padding:2px 6px;border-radius:3px">'+dashboardEsc(r.arn)+'</code></div>';
    if(r.policyNames&&r.policyNames.length) bh+='<div style="margin-bottom:6px"><b>Policies:</b> '+r.policyNames.map(function(p){return '<code style="font-size:9px;background:var(--bg-input);padding:1px 4px;border-radius:2px;margin-right:3px">'+dashboardEsc(p)+'</code>'}).join('')+'</div>';
    if(r.permBoundary) bh+='<div style="margin-bottom:6px"><b>Permission Boundary:</b> <code style="font-size:9px">'+dashboardEsc(r.permBoundary)+'</code></div>';
    if(r.crossAccounts.length) bh+='<div style="margin-bottom:6px"><b>Cross-Account Trusts:</b> '+r.crossAccounts.map(function(a){return '<code style="font-size:10px;background:rgba(245,158,11,.1);padding:1px 4px;border-radius:2px;margin-right:3px">'+dashboardEsc(a)+'</code>'}).join('')+'</div>';
    if(r.provider==='azure')bh+='<div style="margin-bottom:6px"><b>Assessment limits:</b> MFA, sign-in history, and credentials were not collected.</div>';
    if(r.type==='User'&&r.provider!=='azure'){
      bh+='<div style="margin-bottom:6px"><b>MFA:</b> '+(r.hasMFA?'<span style="color:#10b981">✓ Enabled</span>':'<span style="color:#ef4444">✗ Disabled</span>')+'</div>';
      if(r.hasConsole) bh+='<div style="margin-bottom:6px"><b>Console Access:</b> <span style="color:#f59e0b">Enabled</span></div>';
      if(r.activeKeys) bh+='<div style="margin-bottom:6px"><b>Active Access Keys:</b> '+r.activeKeys+'</div>';
    }
    if(r.findings.length){
      bh+='<div><b>Findings ('+r.findings.length+'):</b><ul style="margin:4px 0 0;padding-left:20px;list-style:none">';
      r.findings.forEach(function(f){
        var sColor=f.severity==='CRITICAL'?'#ef4444':f.severity==='HIGH'?'#f97316':f.severity==='MEDIUM'?'#eab308':'#3b82f6';
        bh+='<li style="font-size:10px;color:var(--text-secondary);margin:3px 0"><span style="font-size:8px;font-weight:700;padding:1px 4px;border-radius:2px;background:rgba(0,0,0,.2);color:'+sColor+';margin-right:4px">'+f.severity+'</span>'+dashboardEsc(f.message)+'</li>';
      });
      bh+='</ul></div>';
    }
    bh+='</td></tr>';
  });
  bh+='</tbody></table>';
  body.innerHTML=bh;
  body.scrollTop=0;
  // Footer
  var fh='<button id="govExportCSV">Export CSV</button>';
  fh+='<button id="govExportJSON">Export JSON</button>';
  fh+='<span style="margin-left:auto;font-size:10px;color:var(--text-muted)">'+items.length+' of '+_iamReviewData.length+'</span>';
  if(totalPages>1){
    fh+='<button id="govPrev"'+(st.page<=1?' disabled':'')+'>← Prev</button>';
    fh+='<span style="font-size:10px;color:var(--text-muted)">Page '+st.page+' of '+totalPages+'</span>';
    fh+='<button id="govNext"'+(st.page>=totalPages?' disabled':'')+'>Next →</button>';
  }
  footer.innerHTML=fh;
  // Wire body/footer events (these get recreated each render)
  if(document.getElementById('govPrev')) document.getElementById('govPrev').addEventListener('click',function(){st.page--;_renderIAMTab()});
  if(document.getElementById('govNext')) document.getElementById('govNext').addEventListener('click',function(){st.page++;_renderIAMTab()});
  // Sort headers
  body.querySelectorAll('th[data-sort-col]').forEach(function(th){
    th.addEventListener('click',function(){
      var col=this.dataset.sortCol;
      if(st.sort===col) st.sortDir=st.sortDir==='asc'?'desc':'asc';
      else{st.sort=col;st.sortDir='asc'}
      st.page=1;_renderIAMTab();
    });
  });
  // Row expand/collapse
  body.querySelectorAll('tr[data-iam-row]').forEach(function(tr){
    tr.addEventListener('click',function(){
      var rowId=this.dataset.iamRow;
      var exp=document.getElementById(rowId+'-exp');
      if(!exp)return;
      var isOpen=exp.classList.contains('open');
      body.querySelectorAll('.gov-iam-expand').forEach(function(e){e.classList.remove('open')});
      body.querySelectorAll('tr[data-iam-row]').forEach(function(r){r.classList.remove('expanded')});
      if(!isOpen){exp.classList.add('open');this.classList.add('expanded')}
    });
  });
  // Export
  document.getElementById('govExportCSV').addEventListener('click',function(){
    var rows=[['Name','Type','ARN','Created','Last Used','Policies','Admin','Findings','Cross-Account']];
    items.forEach(function(r){rows.push([r.name,r.type,r.arn,r.created?r.created.toISOString():'',r.lastUsed?r.lastUsed.toISOString():'',r.policies,r.isAdmin?'Yes':'No',r.findings.length,r.crossAccounts.join(';')])});
    var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')}).join('\n');
    dashboardDownload(new Blob([csv],{type:'text/csv'}),'iam-review.csv');
  });
  document.getElementById('govExportJSON').addEventListener('click',function(){
    dashboardDownload(new Blob([JSON.stringify(items.map(function(r){return{name:r.name,type:r.type,arn:r.arn,created:r.created,lastUsed:r.lastUsed,isAdmin:r.isAdmin,policies:r.policies,policyNames:r.policyNames,crossAccounts:r.crossAccounts,findingCount:r.findings.length}}),null,2)],{type:'application/json'}),'iam-review.json');
  });
}

// Collect unique tag values for a given tag key from classification data
function _collectTagValues(tagKey){
  var vals={};
  GovernanceClassification.data.forEach(function(res){
    var v=(res.tags||{})[tagKey];
    if(v) vals[v]=(vals[v]||0)+1;
  });
  return Object.keys(vals).map(function(v){return{val:v,ct:vals[v]}}).sort(function(a,b){return b.ct-a.ct});
}

// Rules editor overlay
function _openRulesEditor(){
  var existing=document.getElementById('govRulesOverlay');
  if(existing) existing.remove();
  // Working copy of rules
  var workRules=structuredClone(GovernanceClassification.rules);
  workRules.forEach(function(r){if(r.enabled===undefined) r.enabled=true});
  var groupCollapsed={any:false,vpc:false,type:false,name:false};
  var scopeLabels={any:'Any (Name + Tags + VNet)',vpc:'VNet Name Rules',type:'Resource Type Rules',name:'Resource Name Rules'};
  var scopeOrder=['any','vpc','type','name'];
  // Discover tag scopes from rules + data
  var disc=GovernanceClassification.discoveredTags||{};
  var tagScopes={};
  workRules.forEach(function(r){if(r.scope&&r.scope.indexOf('tag:')===0) tagScopes[r.scope]=true});
  Object.keys(disc).forEach(function(k){tagScopes['tag:'+k]=true});
  var sortedTagScopes=Object.keys(tagScopes).sort(function(a,b){
    var ac=(disc[a.substring(4)]||{}).count||0,bc=(disc[b.substring(4)]||{}).count||0;return bc-ac;
  });
  sortedTagScopes.forEach(function(ts){
    var tk=ts.substring(4);var info=disc[tk];
    scopeOrder.push(ts);
    scopeLabels[ts]='Tag: '+tk+(info?' ('+info.count+' resources)':'');
    groupCollapsed[ts]=true;
  });
  var overlay=document.createElement('div');
  overlay.id='govRulesOverlay';
  overlay.className='gov-rules-overlay';

  function readRulesFromDom(){
    var rules=[];
    overlay.querySelectorAll('.gov-rule-row[data-rule-idx]').forEach(function(row){
      var idx=parseInt(row.dataset.ruleIdx);
      var r=workRules[idx];if(!r) return;
      r.pattern=row.querySelector('[data-field="pattern"]').value;
      r.scope=row.querySelector('[data-field="scope"]').value;
      r.tier=row.querySelector('[data-field="tier"]').value;
      r.weight=parseInt(row.querySelector('[data-field="weight"]').value)||0;
    });
    return workRules;
  }
  function countMatches(rule){
    if(!rule.pattern||rule.enabled===false) return 0;
    var re=GovernanceClassification.safeRegex(rule.pattern);if(!re) return -1;
    var ct=0;
    GovernanceClassification.data.forEach(function(res){
      var text='';
      if(rule.scope==='any') text=(res.name||'')+' '+(res.type||'')+' '+(res.vpcName||'')+' '+Object.values(res.tags||{}).join(' ');
      else if(rule.scope==='vpc') text=res.vpcName||'';
      else if(rule.scope==='type') text=res.type||'';
      else if(rule.scope==='name') text=res.name||'';
      else if(rule.scope.indexOf('tag:')===0) text=(res.tags||{})[rule.scope.substring(4)]||'';
      if(re.test(text)) ct++;
    });
    return ct;
  }
  function buildPreview(rules){
    var ctx=dashboardRlCtx();
    if(!ctx) return {critical:0,high:0,medium:0,low:0,samples:[]};
    var counts={critical:0,high:0,medium:0,low:0};
    var samples=[];
    var vpcNameMap={};
    (ctx.vnets||[]).forEach(function(v){vpcNameMap[v.VpcId]=gn(v,v.VpcId)});
    function classify(name,type,vpcName,id,obj){
      var tm=GovernanceClassification.tagMap(obj||{});
      var tier=(GovernanceClassification.overrides[id]||GovernanceClassification.score(name,type,vpcName,rules,tm).tier);
      counts[tier]=(counts[tier]||0)+1;
      if(samples.length<12) samples.push({name:name,type:type,tier:tier});
    }
    (ctx.vms||[]).forEach(function(inst){
      var name=inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId;
      classify(name,'instance',vpcNameMap[inst.VpcId]||'',inst.InstanceId,inst);
    });
    (ctx.sqlServers||[]).forEach(function(db){classify(db.DBInstanceIdentifier,'rds',vpcNameMap[(db.DBSubnetGroup||{}).VpcId]||'',db.DBInstanceIdentifier,db)});
    (ctx.redisCaches||[]).forEach(function(ec){classify(ec.CacheClusterId,'elasticache','',ec.CacheClusterId,ec)});
    (ctx.appGateways||[]).forEach(function(alb){classify(alb.LoadBalancerName||'','alb',vpcNameMap[alb.VpcId]||'',alb.LoadBalancerName||'',alb)});
    (ctx.functionApps||[]).forEach(function(fn){classify(fn.FunctionName,'lambda',vpcNameMap[(fn.VpcConfig||{}).VpcId]||'',fn.FunctionName,fn)});
    (ctx.containerInstances||[]).forEach(function(svc){classify(svc.serviceName||'','ecs','',svc.serviceName||'',svc)});
    (ctx.synapseWorkspaces||[]).forEach(function(rs){classify(rs.ClusterIdentifier,'redshift',vpcNameMap[rs.VpcId]||'',rs.ClusterIdentifier,rs)});
    (ctx.nsgs||[]).forEach(function(sg){classify(gn(sg,sg.GroupId),'security-group',vpcNameMap[sg.VpcId]||'',sg.GroupId,sg)});
    (ctx.vnets||[]).forEach(function(v){var n=gn(v,v.VpcId);classify(n,'vpc',n,v.VpcId,v)});
    (ctx.subnets||[]).forEach(function(s){classify(gn(s,s.SubnetId),'subnet',vpcNameMap[s.VpcId]||'',s.SubnetId,s)});
    (ctx.firewalls||[]).forEach(function(gw){var vid=(gw.Attachments&&gw.Attachments[0])?gw.Attachments[0].VpcId:'';classify(gn(gw,gw.InternetGatewayId),'igw',vpcNameMap[vid]||'',gw.InternetGatewayId,gw)});
    (ctx.natGateways||[]).forEach(function(ng){classify(gn(ng,ng.NatGatewayId),'nat-gateway',vpcNameMap[ng.VpcId]||'',ng.NatGatewayId,ng)});
    (ctx.privateEndpoints||[]).forEach(function(ve){classify(ve.ServiceName||ve.VpcEndpointId,'vpc-endpoint',vpcNameMap[ve.VpcId]||'',ve.VpcEndpointId,ve)});
    (ctx.s3bk||[]).forEach(function(b){classify(b.Name||'','s3','',b.Name||'',b)});
    return {critical:counts.critical,high:counts.high,medium:counts.medium,low:counts.low,total:counts.critical+counts.high+counts.medium+counts.low,samples:samples};
  }
  function renderPreview(){
    var el=document.getElementById('govRulesPreview');if(!el) return;
    var rules=readRulesFromDom();
    var p=buildPreview(rules);
    var total=p.total||1;
    var cur={critical:0,high:0,medium:0,low:0};
    GovernanceClassification.data.forEach(function(r){cur[r.tier]=(cur[r.tier]||0)+1});
    var ph='<div class="gov-preview-card"><h5>Classification Distribution</h5><div class="gov-preview-bars">';
    [{k:'critical',l:'Critical',c:'#ef4444'},{k:'high',l:'High',c:'#f59e0b'},{k:'medium',l:'Medium',c:'#22d3ee'},{k:'low',l:'Low',c:'#64748b'}].forEach(function(d){
      var pct=Math.round((p[d.k]/total)*100);
      ph+='<div class="gov-preview-bar"><span class="gov-preview-bar-label" style="color:'+d.c+'">'+d.l+'</span>';
      ph+='<div class="gov-preview-bar-track"><div class="gov-preview-bar-fill" style="width:'+pct+'%;background:'+d.c+'"></div></div>';
      ph+='<span class="gov-preview-bar-ct">'+p[d.k]+'</span></div>';
    });
    ph+='</div></div>';
    // Delta from current
    var deltas=[];
    [{k:'critical',l:'Critical',c:'#ef4444'},{k:'high',l:'High',c:'#f59e0b'},{k:'medium',l:'Medium',c:'#22d3ee'},{k:'low',l:'Low',c:'#64748b'}].forEach(function(d){
      var diff=p[d.k]-(cur[d.k]||0);
      if(diff!==0) deltas.push('<span style="color:'+d.c+'">'+d.l+': <span class="'+(diff>0?'up':'down')+'">'+(diff>0?'+':'')+diff+'</span></span>');
    });
    if(deltas.length) ph+='<div class="gov-preview-delta">'+deltas.join(' &nbsp; ')+'</div>';
    else ph+='<div class="gov-preview-delta"><span class="same">No changes from current</span></div>';
    // Sample
    ph+='<div class="gov-preview-card" style="margin-top:10px"><h5>Sample Resources</h5><div class="gov-preview-sample">';
    p.samples.forEach(function(s){
      var tc=GovernanceClassification.tierMeta(s.tier);
      ph+='<div class="gov-preview-sample-row"><span class="name">'+dashboardEsc(s.name)+'</span><span class="type">'+dashboardEsc(s.type)+'</span><span class="gov-tier-badge '+s.tier+'" style="font-size:8px;padding:1px 5px">'+s.tier+'</span></div>';
    });
    ph+='</div></div>';
    el.innerHTML=ph;
  }
  function renderRules(){
    var list=document.getElementById('govRulesList');if(!list) return;
    var h='';
    scopeOrder.forEach(function(scope){
      var rules=[];workRules.forEach(function(r,i){if(r.scope===scope) rules.push({rule:r,idx:i})});
      if(!rules.length&&scope!=='vpc') return;
      var collapsed=groupCollapsed[scope];
      h+='<div class="gov-rule-group" data-scope="'+scope+'">';
      h+='<div class="gov-rule-group-hdr" data-toggle-scope="'+scope+'"><span class="gov-rule-group-arrow'+(collapsed?' collapsed':'')+'">▼</span>';
      h+='<span class="gov-rule-group-label">'+(scopeLabels[scope]||scope)+'</span>';
      h+='<span class="gov-rule-group-count">'+rules.length+' rule'+(rules.length!==1?'s':'')+'</span></div>';
      h+='<div class="gov-rule-group-body'+(collapsed?' collapsed':'')+'" style="'+(collapsed?'max-height:0':'max-height:9999px')+'">';
      // Show tag value chips once at group level for tag-scoped rules
      if(scope.indexOf('tag:')===0){
        var tagKey=scope.substring(4);var tagVals=_collectTagValues(tagKey);
        if(tagVals.length){
          h+='<div class="gov-tag-vals" style="display:flex;flex-wrap:wrap;gap:3px;padding:6px 10px 8px 34px;border-bottom:1px solid var(--border)">';
          h+='<span style="font-size:10px;color:var(--text-muted);margin-right:4px">Values:</span>';
          tagVals.slice(0,16).forEach(function(tv){
            h+='<span class="gov-tag-val-chip" data-val="'+dashboardEsc(tv.val)+'" style="font-size:10px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.25);padding:2px 6px;border-radius:3px;color:#a78bfa;cursor:pointer" title="Click to add: '+dashboardEsc(tv.val)+' ('+tv.ct+' resources)">'+dashboardEsc(tv.val.length>25?tv.val.substring(0,23)+'..':tv.val)+' <span style="color:var(--text-muted)">'+tv.ct+'</span></span>';
          });
          if(tagVals.length>16) h+='<span style="font-size:10px;color:var(--text-muted)">+'+(tagVals.length-16)+' more</span>';
          h+='</div>';
        }
      }
      rules.forEach(function(d){
        var r=d.rule;var i=d.idx;
        var isValid=true;try{if(r.pattern) new RegExp(r.pattern,'i')}catch(e){isValid=false}
        var mc=countMatches(r);
        h+='<div class="gov-rule-row'+(r.enabled===false?' disabled':'')+((!isValid)?' invalid':'')+'" data-rule-idx="'+i+'">';
        h+='<span class="gov-rule-drag" title="Drag to reorder">⠿</span>';
        h+='<div class="gov-rule-toggle'+(r.enabled!==false?' on':'')+'" data-toggle-idx="'+i+'" title="'+(r.enabled!==false?'Enabled: click to disable':'Disabled: click to enable')+'"></div>';
        h+='<input class="pattern'+((!isValid)?' invalid-pattern':'')+'" type="text" value="'+dashboardEsc(r.pattern)+'" data-field="pattern" placeholder="regex pattern…" title="'+((!isValid)?'Invalid regex!':'Regex pattern')+'">';
        h+='<select data-field="scope" class="gov-scope-sel" title="Match scope: what this pattern is tested against"><option value="any"'+(r.scope==='any'?' selected':'')+'>Any</option><option value="vpc"'+(r.scope==='vpc'?' selected':'')+'>VNet</option><option value="type"'+(r.scope==='type'?' selected':'')+'>Type</option><option value="name"'+(r.scope==='name'?' selected':'')+'>Name</option>';
        sortedTagScopes.forEach(function(ts){h+='<option value="'+ts+'"'+(r.scope===ts?' selected':'')+'>tag:'+ts.substring(4)+'</option>'});
        h+='</select>';
        h+='<select data-field="tier"><option value="critical"'+(r.tier==='critical'?' selected':'')+'>Critical</option><option value="high"'+(r.tier==='high'?' selected':'')+'>High</option><option value="medium"'+(r.tier==='medium'?' selected':'')+'>Medium</option><option value="low"'+(r.tier==='low'?' selected':'')+'>Low</option></select>';
        h+='<input class="weight" type="number" value="'+r.weight+'" data-field="weight" title="Weight (higher wins)">';
        h+='<span class="gov-rule-match-ct'+(mc>0?' has-matches':'')+'" title="'+(mc<0?'Invalid regex':mc+' resources match')+'">'+((mc<0)?'!':mc)+'</span>';
        h+='<button class="gov-rule-del" data-del-idx="'+i+'" title="Delete rule">✕</button>';
        h+='</div>';
      });
      h+='<div style="padding:4px 0 8px 34px"><button class="gov-rule-add-scope" data-add-scope="'+scope+'" style="background:none;border:1px dashed var(--border);border-radius:3px;padding:3px 10px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif;color:var(--text-muted);cursor:pointer;transition:all .15s">+ Add '+((scopeLabels[scope]||scope).replace(' Rules',''))+' Rule</button></div>';
      h+='</div></div>';
    });
    list.innerHTML=h;
    wireRuleEvents();
  }
  function wireRuleEvents(){
    // Toggle enable/disable
    overlay.querySelectorAll('[data-toggle-idx]').forEach(function(el){
      el.addEventListener('click',function(){
        var idx=parseInt(this.dataset.toggleIdx);
        workRules[idx].enabled=workRules[idx].enabled===false?true:false;
        renderRules();renderPreview();
      });
    });
    // Delete
    overlay.querySelectorAll('[data-del-idx]').forEach(function(btn){
      btn.addEventListener('click',function(){
        var idx=parseInt(this.dataset.delIdx);
        workRules.splice(idx,1);
        renderRules();renderPreview();
      });
    });
    // Group toggle
    overlay.querySelectorAll('[data-toggle-scope]').forEach(function(hdr){
      hdr.addEventListener('click',function(){
        var scope=this.dataset.toggleScope;
        groupCollapsed[scope]=!groupCollapsed[scope];
        renderRules();
      });
    });
    // Add rule per scope
    overlay.querySelectorAll('[data-add-scope]').forEach(function(btn){
      btn.addEventListener('click',function(){
        var sc=this.dataset.addScope;
        var dw=sc==='any'?130:sc.indexOf('tag:')===0?120:sc==='name'?100:sc==='type'?80:60;
        workRules.push({pattern:'',scope:sc,tier:'medium',weight:dw,enabled:true});
        renderRules();renderPreview();
      });
    });
    // Live preview on input change (debounced)
    var previewTimer;
    overlay.querySelectorAll('.gov-rule-row input,.gov-rule-row select').forEach(function(el){
      el.addEventListener('input',function(){
        var row=this.closest('.gov-rule-row');
        var idx=parseInt(row.dataset.ruleIdx);
        var field=this.dataset.field;
        if(field==='pattern'){
          workRules[idx].pattern=this.value;
          var valid=true;try{if(this.value) new RegExp(this.value,'i')}catch(e){valid=false}
          this.classList.toggle('invalid-pattern',!valid);
          row.classList.toggle('invalid',!valid);
          // Update match count inline
          var mc=countMatches(workRules[idx]);
          var mcEl=row.querySelector('.gov-rule-match-ct');
          if(mcEl){mcEl.textContent=mc<0?'!':mc;mcEl.classList.toggle('has-matches',mc>0)}
        } else if(field==='tier'){
          workRules[idx].tier=this.value;
        } else if(field==='weight'){
          workRules[idx].weight=parseInt(this.value)||0;
        }
        clearTimeout(previewTimer);
        previewTimer=setTimeout(renderPreview,300);
      });
      el.addEventListener('change',function(){
        var row=this.closest('.gov-rule-row');
        var idx=parseInt(row.dataset.ruleIdx);
        var field=this.dataset.field;
        if(field==='scope'){
          workRules[idx].scope=this.value;
          groupCollapsed[this.value]=false;
          renderRules();renderPreview();return;
        }
        if(field==='tier') workRules[idx].tier=this.value;
        else if(field==='weight') workRules[idx].weight=parseInt(this.value)||0;
        clearTimeout(previewTimer);
        previewTimer=setTimeout(renderPreview,150);
      });
    });
    // Tag value chip click → populate pattern field
    overlay.querySelectorAll('.gov-tag-val-chip').forEach(function(chip){
      chip.addEventListener('click',function(e){
        e.stopPropagation();
        var val=this.dataset.val;
        var row=this.closest('.gov-rule-row');
        if(row){
          var inp=row.querySelector('input.pattern');
          if(inp){
            var cur=inp.value;
            inp.value=cur?(cur+'|'+val):val;
            inp.dispatchEvent(new Event('input',{bubbles:true}));
          }
        }
      });
    });
  }

  // Build shell
  var h='<div class="gov-rules-panel">';
  h+='<div class="gov-rules-hdr"><h3>Classification Rules</h3>';
  h+='<div class="gov-rules-hdr-actions">';
  h+='<button id="govRulesImport" title="Import rules from JSON">Import</button>';
  h+='<button id="govRulesExport" title="Export rules as JSON">Export</button>';
  h+='<button id="govRulesClose">Close</button>';
  h+='</div></div>';
  h+='<div class="gov-rules-content">';
  h+='<div class="gov-rules-left"><p style="font-size:10px;color:var(--text-muted);margin:0 0 12px;line-height:1.5">Regex patterns matched against scope. Higher weight wins when multiple rules match. Toggle rules on/off to test without deleting.</p>';
  // Tag discovery chips
  var dKeys=Object.keys(disc).sort(function(a,b){return (disc[b].count||0)-(disc[a].count||0)});
  if(dKeys.length){
    h+='<div class="gov-tag-discovery"><div style="font-size:9px;color:var(--text-muted);margin:0 0 6px;text-transform:uppercase;letter-spacing:.5px;font-weight:600">Discovered Tags</div><div class="gov-tag-chips">';
    dKeys.forEach(function(k){
      var d=disc[k];var hasRules=workRules.some(function(r){return r.scope==='tag:'+k});
      h+='<button class="gov-tag-chip'+(hasRules?' active':'')+'" data-tag-key="'+dashboardEsc(k)+'" title="'+d.count+' resources across '+d.types.join(', ')+'\nSamples: '+d.samples.join(', ')+'">';
      h+=dashboardEsc(k)+' <span class="ct">'+d.count+'</span></button>';
    });
    h+='</div></div>';
  }
  h+='<div id="govRulesList"></div></div>';
  h+='<div class="gov-rules-right"><h4>Live Preview</h4><div id="govRulesPreview"></div></div>';
  h+='</div>';
  h+='<div class="gov-rules-foot">';
  h+='<button id="govRuleReset">Reset to Defaults</button>';
  h+='<button class="gov-rules-apply" id="govRuleApply">Apply & Re-classify</button>';
  h+='</div></div>';
  overlay.innerHTML=h;
  document.body.appendChild(overlay);
  // Render initial state
  renderRules();
  renderPreview();
  // Shell events
  document.getElementById('govRulesClose').addEventListener('click',function(){overlay.remove()});
  overlay.addEventListener('click',function(e){if(e.target===overlay) overlay.remove()});
  // Tag chip clicks: create starter rule for tag scope
  overlay.querySelectorAll('.gov-tag-chip').forEach(function(chip){
    chip.addEventListener('click',function(){
      var chip=this;var tk=chip.dataset.tagKey;var scope='tag:'+tk;
      var hasRules=workRules.some(function(r){return r.scope===scope});
      if(!hasRules){
        workRules.push({pattern:'',scope:scope,tier:'critical',weight:120,enabled:true});
        groupCollapsed[scope]=false;
        chip.classList.add('active');
      } else {
        groupCollapsed[scope]=!groupCollapsed[scope];
        chip.classList.toggle('active',!groupCollapsed[scope]);
      }
      renderRules();renderPreview();
      if(!groupCollapsed[scope]){
        var grp=overlay.querySelector('[data-scope="'+scope+'"]');
        if(grp) grp.scrollIntoView({behavior:'smooth',block:'start'});
      }
    });
  });
  document.getElementById('govRuleReset').addEventListener('click',function(){
    workRules=structuredClone(_DEFAULT_CLASS_RULES);
    workRules.forEach(function(r){r.enabled=true});
    renderRules();renderPreview();
  });
  document.getElementById('govRulesExport').addEventListener('click',function(){
    readRulesFromDom();
    var json=JSON.stringify(workRules,null,2);
    dashboardDownload(new Blob([json],{type:'application/json'}),'classification-rules.json');
    dashboardNotify('Rules exported');
  });
  document.getElementById('govRulesImport').addEventListener('click',function(){
    var inp=document.createElement('input');inp.type='file';inp.accept='.json';
    inp.addEventListener('change',function(){
      if(!this.files[0]){inp.remove();return}
      var reader=new FileReader();
      reader.onload=function(e){
        try{
          var imported=JSON.parse(e.target.result);
          if(!Array.isArray(imported)){dashboardNotify('Invalid rules file','warn');inp.remove();return}
          workRules=imported;
          workRules.forEach(function(r){if(r.enabled===undefined) r.enabled=true});
          renderRules();renderPreview();
          dashboardNotify(imported.length+' rules imported');
        }catch(err){dashboardNotify('Failed to parse JSON','warn')}
        inp.remove();
      };
      reader.readAsText(this.files[0]);
    });
    inp.addEventListener('cancel',()=>inp.remove());
    inp.click();
  });
  document.getElementById('govRuleApply').addEventListener('click',function(){
    readRulesFromDom();
    var ctx=dashboardRlCtx();
    var classificationRows=GovernanceClassification.applyRules(workRules,ctx);
    _govToolbarTab=null;
    overlay.remove();
    _renderClassificationTab();
    dashboardNotify('Rules applied: '+classificationRows.length+' resources re-classified');
  });
}

// Governance event listeners
document.getElementById('govBtn').addEventListener('click',function(){openUnifiedDash('classification')});

// #endregion UNIFIED DASHBOARD

