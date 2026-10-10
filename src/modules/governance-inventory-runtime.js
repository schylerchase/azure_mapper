// #region GOVERNANCE & INVENTORY
// === GOVERNANCE: INVENTORY RUNTIME ===
let _govDashState={tab:'classification',filter:'all',search:'',sort:'tier',sortDir:'asc',page:1,perPage:50};
let _inventoryData=[];
let _invState={typeFilter:'all',regionFilter:'all',accountFilter:'all',vpcFilter:'all',viewMode:'flat',search:'',sort:'type',sortDir:'asc',page:1,perPage:50};
let _appRegistry=[];
let _appAutoDiscovered=false;
let _appSummaryState={search:'',sort:'tier',sortDir:'asc',adding:false,editing:-1};
const _APP_TYPE_SUGGESTIONS=['Web App','Database','Monitoring','CI/CD','Security','Analytics','Storage','Infrastructure'];

function governanceRuntimeContext(){
  var contextFactory = typeof AppRenderContext !== 'undefined' ? AppRenderContext : null;
  return contextFactory ? contextFactory.createRenderContext() : null;
}

function governanceRuntimeData(){
  var ctx = governanceRuntimeContext();
  return ctx ? ctx.rlCtx : null;
}

function governanceFindings(){
  var ctx = governanceRuntimeContext();
  return ctx ? ctx.complianceFindings || [] : [];
}

function governanceNotify(message, type){
  var notifications = typeof AppNotifications !== 'undefined' ? AppNotifications : null;
  if(notifications && typeof notifications.show === 'function') notifications.show(message, type);
}

function governanceDownload(blob, name){
  var downloads = typeof AppDownloads !== 'undefined' ? AppDownloads : null;
  if(downloads && typeof downloads.saveBlob === 'function') return downloads.saveBlob(blob, name);
}

function governanceEsc(value){
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function governanceOpenResourceDetail(rid){
  if(!rid)return;
  closeUnifiedDash();
  setTimeout(function(){
    if(typeof ResourceNavigation!=='undefined'&&ResourceNavigation.zoomAndOpenDetail){
      ResourceNavigation.zoomAndOpenDetail(rid);
    }
  },250);
}

function _buildInventoryData(){
  _inventoryData=GovernanceInventoryModel.buildInventoryData(governanceRuntimeData(), {
    classificationData: GovernanceClassification.data,
    budrAssessments: typeof _budrAssessments !== 'undefined' ? _budrAssessments : [],
    complianceFindings: governanceFindings(),
    nameForResource: gn
  });
}

// === INVENTORY TAB RENDERER (Tasks 4-5) ===
var _invToolbarRendered=false;

const _INV_TYPE_COLORS={
  'VNet':'#7C3AED','Subnet':'#6366f1','VM':'#f97316','SQL':'#22d3ee',
  'Function App':'#f59e0b','Container':'#10b981','App Gateway':'#ec4899','Redis Cache':'#8b5cf6',
  'Synapse':'#06b6d4','NSG':'#64748b','UDR':'#64748b','Route Table':'#64748b',
  'Azure Firewall':'#34d399','NAT GW':'#34d399','Private Endpoint':'#34d399','NIC':'#94a3b8',
  'Managed Disk':'#fb923c','Snapshot':'#a78bfa','Storage Account':'#f472b6',
  'DNS Zone':'#38bdf8','WAF':'#fbbf24','Front Door':'#818cf8',
  'VNet Peering':'#c084fc','VPN':'#2dd4bf','vWAN':'#67e8f9',
  'Load Balancer':'#f9a8d4'
};

const _INV_NO_MAP_TYPES={'Storage Account':1,'DNS Zone':1,'WAF':1,'Front Door':1,'Snapshot':1,'vWAN':1,'Backend Pool':1};

function _filterInventory(){
  return GovernanceInventoryModel.filterInventory(_inventoryData, _invState, _udashFilterByAccount);
}

function _renderInventoryTab(){
  var tb=document.getElementById('udashToolbar');
  var body=document.getElementById('udashBody');
  var footer=document.getElementById('udashFooter');
  var st=_invState;
  if(!_invToolbarRendered){
    _invToolbarRendered=true;
    // Collect unique values for filter dropdowns
    var types={},regions={},accounts={},vpcs={};
    _inventoryData.forEach(function(r){
      if(r.type) types[r.type]=1;
      if(r.region) regions[r.region]=1;
      if(r.account) accounts[r.account]=1;
      if(r.vpcId) vpcs[r.vpcId]=r.vpcName||r.vpcId;
    });
    var typeKeys=Object.keys(types).sort();
    var regionKeys=Object.keys(regions).sort();
    var accountKeys=Object.keys(accounts).sort();
    var vpcKeys=Object.keys(vpcs).sort();
    var th='<label>Search</label>';
    th+='<input id="invSearch" type="text" placeholder="Filter resources..." value="'+governanceEsc(st.search)+'" style="width:180px">';
    th+='<label>Type</label>';
    th+='<select id="invTypeFilter"><option value="all">All Types</option>';
    typeKeys.forEach(function(t){th+='<option value="'+governanceEsc(t)+'"'+(st.typeFilter===t?' selected':'')+'>'+governanceEsc(t)+'</option>'});
    th+='</select>';
    th+='<label>Region</label>';
    th+='<select id="invRegionFilter"><option value="all">All Regions</option>';
    regionKeys.forEach(function(r){th+='<option value="'+governanceEsc(r)+'"'+(st.regionFilter===r?' selected':'')+'>'+governanceEsc(r)+'</option>'});
    th+='</select>';
    if(accountKeys.length>1){
      th+='<label>Account</label>';
      th+='<select id="invAccountFilter"><option value="all">All Accounts</option>';
      accountKeys.forEach(function(a){th+='<option value="'+governanceEsc(a)+'"'+(st.accountFilter===a?' selected':'')+'>'+governanceEsc(a)+'</option>'});
      th+='</select>';
    }
    th+='<label>VNet</label>';
    th+='<select id="invVpcFilter"><option value="all">All VNets</option>';
    vpcKeys.forEach(function(v){th+='<option value="'+governanceEsc(v)+'"'+(st.vpcFilter===v?' selected':'')+'>'+governanceEsc(vpcs[v])+'</option>'});
    th+='</select>';
    th+='<div style="margin-left:auto;display:flex;gap:2px">';
    th+='<button id="invViewFlat" style="padding:4px 10px;border-radius:4px 0 0 4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer;border:1px solid var(--border);'+(st.viewMode==='flat'?'background:#f97316;color:#fff;border-color:#f97316':'background:var(--bg-tertiary);color:var(--text-muted)')+'">Flat</button>';
    th+='<button id="invViewTree" style="padding:4px 10px;border-radius:0 4px 4px 0;font-size:10px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer;border:1px solid var(--border);'+(st.viewMode==='tree'?'background:#f97316;color:#fff;border-color:#f97316':'background:var(--bg-tertiary);color:var(--text-muted)')+'">Tree</button>';
    th+='</div>';
    tb.innerHTML=th;
    // Wire toolbar events
    document.getElementById('invSearch').addEventListener('input',function(){st.search=this.value;st.page=1;_renderInventoryBody()});
    document.getElementById('invTypeFilter').addEventListener('change',function(){st.typeFilter=this.value;st.page=1;_renderInventoryBody()});
    document.getElementById('invRegionFilter').addEventListener('change',function(){st.regionFilter=this.value;st.page=1;_renderInventoryBody()});
    if(document.getElementById('invAccountFilter')){
      document.getElementById('invAccountFilter').addEventListener('change',function(){st.accountFilter=this.value;st.page=1;_renderInventoryBody()});
    }
    document.getElementById('invVpcFilter').addEventListener('change',function(){st.vpcFilter=this.value;st.page=1;_renderInventoryBody()});
    document.getElementById('invViewFlat').addEventListener('click',function(){
      if(st.viewMode==='flat') return;
      st.viewMode='flat';st.page=1;_invToolbarRendered=false;_renderInventoryTab();
    });
    document.getElementById('invViewTree').addEventListener('click',function(){
      if(st.viewMode==='tree') return;
      st.viewMode='tree';st.page=1;_invToolbarRendered=false;_renderInventoryTab();
    });
  }
  _renderInventoryBody();
}

var _invFilterCache=null;var _invFilterKey='';
function _renderInventoryBody(){
  var body=document.getElementById('udashBody');
  var footer=document.getElementById('udashFooter');
  var st=_invState;
  // Tree view
  if(st.viewMode==='tree'){
    _renderInventoryTree(body,footer);
    return;
  }
  // Cache filtered/sorted results: only recompute when filters or sort change
  var fk=st.typeFilter+'|'+st.regionFilter+'|'+st.accountFilter+'|'+st.vpcFilter+'|'+st.search+'|'+st.sort+'|'+st.sortDir+'|'+_inventoryData.length;
  if(fk!==_invFilterKey){_invFilterCache=_filterInventory();_invFilterKey=fk}
  var items=_invFilterCache;
  // Summary cards: total + top 5 types
  var typeCounts={};
  items.forEach(function(r){typeCounts[r.type]=(typeCounts[r.type]||0)+1});
  var topTypes=Object.keys(typeCounts).map(function(t){return{type:t,count:typeCounts[t]}})
    .sort(function(a,b){return b.count-a.count}).slice(0,5);
  var bh='<div class="gov-tier-cards" style="margin-bottom:16px">';
  bh+='<div class="gov-tier-card" style="border-color:#f97316"><h3 style="color:#f97316">Total Resources</h3><div class="gov-tier-count" style="color:#f97316">'+items.length+'</div></div>';
  topTypes.forEach(function(d){
    var tc=_INV_TYPE_COLORS[d.type]||'var(--border)';
    bh+='<div class="gov-tier-card" style="border-color:'+tc+'"><h3 style="color:'+tc+'">'+governanceEsc(d.type)+'</h3><div class="gov-tier-count" style="color:'+tc+'">'+d.count+'</div></div>';
  });
  bh+='</div>';
  // Tag summary panel: show tag keys and unique values for filtered set
  var tagSummary={};
  items.forEach(function(r){
    var tk=Object.keys(r.tags||{});
    tk.forEach(function(k){
      if(!tagSummary[k]) tagSummary[k]={};
      var v=r.tags[k];if(v) tagSummary[k][v]=(tagSummary[k][v]||0)+1;
    });
  });
  var tagKeys=Object.keys(tagSummary).sort(function(a,b){return Object.keys(tagSummary[b]).length-Object.keys(tagSummary[a]).length});
  if(tagKeys.length){
    var showTags=_invState._showTags;
    bh+='<div style="margin-bottom:12px">';
    bh+='<button id="invToggleTags" style="font-size:11px;background:transparent;border:1px solid var(--border);color:var(--text-muted);padding:5px 12px;border-radius:4px;cursor:pointer;font-family:inherit">'+(showTags?'▼':'▶')+' Tag Explorer ('+tagKeys.length+' keys)</button>';
    if(showTags){
      bh+='<div style="margin-top:10px;display:flex;flex-direction:column;gap:8px">';
      tagKeys.forEach(function(k){
        var vals=tagSummary[k];var vKeys=Object.keys(vals).sort(function(a,b){return vals[b]-vals[a]});
        bh+='<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px 12px">';
        bh+='<div style="font-size:12px;font-weight:700;color:var(--text-primary);margin-bottom:6px">'+governanceEsc(k)+' <span style="font-weight:400;color:var(--text-muted)">('+vKeys.length+' unique values)</span></div>';
        bh+='<div style="display:flex;flex-wrap:wrap;gap:4px">';
        vKeys.slice(0,20).forEach(function(v){
          bh+='<span style="font-size:11px;background:var(--bg-input);padding:3px 8px;border-radius:3px;color:var(--text-secondary);border:1px solid var(--border);white-space:nowrap;cursor:pointer" class="inv-tag-val" data-tag-val="'+governanceEsc(v)+'" title="'+governanceEsc(k+'='+v)+' ('+vals[v]+')">'+governanceEsc(v.length>30?v.substring(0,28)+'..':v)+' <span style="color:var(--text-muted)">'+vals[v]+'</span></span>';
        });
        if(vKeys.length>20) bh+='<span style="font-size:11px;color:var(--text-muted)">+'+(vKeys.length-20)+' more</span>';
        bh+='</div></div>';
      });
      bh+='</div>';
    }
    bh+='</div>';
  }
  // Columns
  var hasMultiAcct=new Set(items.map(function(r){return r.account}).filter(Boolean)).size>1;
  var cols=[
    {key:'type',label:'Type'},
    {key:'name',label:'Name'}
  ];
  if(hasMultiAcct) cols.push({key:'account',label:'Account'});
  cols.push(
    {key:'config',label:'Config'},
    {key:'state',label:'State'},
    {key:'vpcName',label:'VNet'},
    {key:'region',label:'Region'},
    {key:'tags',label:'Tags'},
    {key:'classificationTier',label:'Classification'},
    {key:'budrTier',label:'BUDR'},
    {key:'complianceFail',label:'Compliance'}
  );
  // Paginate
  var perPage=st.perPage;
  var totalPages=Math.max(1,Math.ceil(items.length/perPage));
  st.page=Math.min(Math.max(1,st.page),totalPages);
  var start=(st.page-1)*perPage;
  var pageItems=items.slice(start,start+perPage);
  // Table
  bh+='<table class="gov-table"><thead><tr>';
  cols.forEach(function(c){
    var cls='';if(st.sort===c.key) cls=st.sortDir==='asc'?' sort-asc':' sort-desc';
    bh+='<th data-sort-col="'+c.key+'" class="'+cls+'">'+c.label+'</th>';
  });
  bh+='</tr></thead><tbody>';
  if(!pageItems.length){
    bh+='<tr><td colspan="'+cols.length+'" style="text-align:center;padding:30px;color:var(--text-muted)">No resources match filters</td></tr>';
  }
  pageItems.forEach(function(r,idx){
    var rowId='inv-r-'+(start+idx);
    var tc=_INV_TYPE_COLORS[r.type]||'#64748b';
    bh+='<tr data-inv-row="'+rowId+'" style="cursor:pointer">';
    // Type badge
    bh+='<td><span style="font-size:8px;font-weight:700;padding:2px 6px;border-radius:3px;background:rgba(0,0,0,.2);color:'+tc+';border:1px solid '+tc+'30;white-space:nowrap">'+governanceEsc(r.type)+'</span></td>';
    // Name
    bh+='<td style="color:var(--accent-cyan);font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+governanceEsc(r.name)+'</td>';
    // Account (multi-account only)
    if(hasMultiAcct) bh+='<td>'+_acctPill(r.account)+'</td>';
    // Config
    bh+='<td style="font-size:9px;color:var(--text-muted);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+governanceEsc(r.config||'\u2014')+'</td>';
    // State
    var stColor=(r.state||'').match(/running|available|active/i)?'#10b981':(r.state||'').match(/stopped|terminated/i)?'#ef4444':'var(--text-muted)';
    bh+='<td style="font-size:9px;color:'+stColor+'">'+governanceEsc(r.state||'\u2014')+'</td>';
    // VNet
    bh+='<td style="font-size:9px;color:var(--text-muted)">'+governanceEsc(r.vpcName||'\u2014')+'</td>';
    // Region
    bh+='<td style="font-size:9px;color:var(--text-muted)">'+governanceEsc(r.region||'\u2014')+'</td>';
    // Tags
    var tKeys=Object.keys(r.tags||{});
    if(tKeys.length){
      bh+='<td style="max-width:280px;overflow:hidden"><div style="display:flex;flex-wrap:wrap;gap:3px">';
      tKeys.slice(0,4).forEach(function(k){
        bh+='<span style="font-size:9px;background:var(--bg-input);padding:2px 5px;border-radius:3px;color:var(--text-secondary);border:1px solid var(--border);white-space:nowrap;max-width:140px;overflow:hidden;text-overflow:ellipsis" title="'+governanceEsc(k+'='+r.tags[k])+'">'+governanceEsc(k)+'='+governanceEsc(r.tags[k])+'</span>';
      });
      if(tKeys.length>4) bh+='<span style="font-size:9px;color:var(--text-muted)">+'+(tKeys.length-4)+'</span>';
      bh+='</div></td>';
    } else {
      bh+='<td style="font-size:9px;color:var(--text-muted)">\u2014</td>';
    }
    // Classification tier
    if(r.classificationTier){
      bh+='<td><span class="gov-tier-badge '+r.classificationTier+'">'+r.classificationTier+'</span></td>';
    } else {
      bh+='<td style="font-size:9px;color:var(--text-muted)">\u2014</td>';
    }
    // BUDR tier
    if(r.budrTier && _BUDR_TIER_META[r.budrTier]){
      var bm=_BUDR_TIER_META[r.budrTier];
      bh+='<td><span style="font-size:8px;font-weight:600;padding:2px 6px;border-radius:3px;background:rgba(0,0,0,.2);color:'+bm.color+';border:1px solid '+bm.color+'30">'+governanceEsc(bm.name)+'</span></td>';
    } else {
      bh+='<td style="font-size:9px;color:var(--text-muted)">\u2014</td>';
    }
    // Compliance mini-bar
    var cp=r.compliancePass||0;var cf=r.complianceFail||0;var ctot=cp+cf;
    if(ctot>0){
      var pw=Math.round(cp/ctot*100);var fw=100-pw;
      bh+='<td><div style="display:flex;align-items:center;gap:4px"><div style="width:40px;height:6px;border-radius:3px;overflow:hidden;display:flex;background:var(--bg-tertiary)">';
      if(cp>0) bh+='<div style="width:'+pw+'%;background:#10b981"></div>';
      if(cf>0) bh+='<div style="width:'+fw+'%;background:#ef4444"></div>';
      bh+='</div><span style="font-size:8px;color:var(--text-muted)">'+cp+'/'+ctot+'</span></div></td>';
    } else {
      bh+='<td style="font-size:9px;color:var(--text-muted)">\u2014</td>';
    }
    bh+='</tr>';
    // Expandable detail row (lazy: populated on first expand)
    bh+='<tr><td colspan="'+cols.length+'" class="gov-iam-expand" id="'+rowId+'-exp" data-inv-idx="'+(start+idx)+'"></td></tr>';
  });
  bh+='</tbody></table>';
  body.innerHTML=bh;
  body.scrollTop=0;
  // Footer
  var fh='<button id="invExportCSV">Export CSV</button>';
  fh+='<button id="invExportJSON">Export JSON</button>';
  fh+='<span style="margin-left:auto;font-size:10px;color:var(--text-muted)">'+items.length+' of '+_inventoryData.length+' resources</span>';
  if(totalPages>1){
    fh+='<button id="invPrev"'+(st.page<=1?' disabled':'')+'>&#8592; Prev</button>';
    // Page number buttons with window
    var winSize=2,startP=Math.max(1,st.page-winSize),endP=Math.min(totalPages,st.page+winSize);
    if(startP>1){fh+='<button class="inv-page-num" data-p="1" style="font-size:10px;padding:2px 6px;border-radius:3px;border:1px solid #1e2d4a;background:transparent;color:#60a5fa;cursor:pointer">1</button>';if(startP>2)fh+='<span style="font-size:10px;color:var(--text-muted)">&hellip;</span>'}
    for(let p=startP;p<=endP;p++){
      var active=p===st.page;
      fh+='<button class="inv-page-num" data-p="'+p+'" style="font-size:10px;padding:2px 6px;border-radius:3px;border:1px solid '+(active?'#f97316':'#1e2d4a')+';background:'+(active?'rgba(249,115,22,.2)':'transparent')+';color:'+(active?'#f97316':'#60a5fa')+';cursor:pointer;font-weight:'+(active?'700':'400')+'">'+p+'</button>';
    }
    if(endP<totalPages){if(endP<totalPages-1)fh+='<span style="font-size:10px;color:var(--text-muted)">&hellip;</span>';fh+='<button class="inv-page-num" data-p="'+totalPages+'" style="font-size:10px;padding:2px 6px;border-radius:3px;border:1px solid #1e2d4a;background:transparent;color:#60a5fa;cursor:pointer">'+totalPages+'</button>'}
    fh+='<button id="invNext"'+(st.page>=totalPages?' disabled':'')+'>Next &#8594;</button>';
  }
  footer.innerHTML=fh;
  _wireInventoryEvents(body,footer,items,cols);
}

function _buildInvExpandedDetail(r){
  var h='';
  // ID: hyperlinked to Azure Portal
  var idUrl=_azurePortalUrl(r.type,r.id,r.region);
  if(idUrl){
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">ID:</b> <a href="'+governanceEsc(idUrl)+'" target="_blank" rel="noopener" style="font-size:10px;background:var(--bg-input);padding:2px 6px;border-radius:3px;color:var(--accent-cyan);text-decoration:underline dotted;text-underline-offset:2px;font-family:monospace" title="Open in Azure Portal">'+governanceEsc(r.id)+'</a></div>';
  } else {
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">ID:</b> <code style="font-size:10px;background:var(--bg-input);padding:2px 6px;border-radius:3px;color:var(--text-primary)">'+governanceEsc(r.id)+'</code></div>';
  }
  // Account / Region / AZ
  var locParts=[];
  if(r.account) locParts.push('Account: '+governanceEsc(r.account));
  if(r.region) locParts.push('Region: '+governanceEsc(r.region));
  if(r.az) locParts.push('AZ: '+governanceEsc(r.az));
  if(locParts.length){
    h+='<div style="margin-bottom:6px;font-size:10px;color:var(--text-secondary)">'+locParts.join(' &middot; ')+'</div>';
  }
  // Related resources: hyperlinked
  if(r._related && r._related.length){
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">Related:</b> ';
    var prefixTypeMap={'sg-':'NSG','i-':'VM','subnet-':'Subnet','vpc-':'VNet','vol-':'Managed Disk','igw-':'Azure Firewall','nat-':'NAT GW','eni-':'NIC','rtb-':'UDR','acl-':'NSG','pcx-':'VNet Peering','vpce-':'Private Endpoint'};
    r._related.forEach(function(rid){
      var relType='';for(var px in prefixTypeMap){if(rid.indexOf(px)===0){relType=prefixTypeMap[px];break}}
      var relUrl=relType?_azurePortalUrl(relType,rid,r.region):'';
      if(relUrl){
        h+='<a href="'+governanceEsc(relUrl)+'" target="_blank" rel="noopener" style="font-size:9px;background:var(--bg-input);padding:1px 4px;border-radius:2px;margin-right:3px;color:var(--accent-cyan);text-decoration:underline dotted;text-underline-offset:2px;font-family:monospace" title="Open in Azure Portal">'+governanceEsc(rid)+'</a>';
      } else {
        h+='<code style="font-size:9px;background:var(--bg-input);padding:1px 4px;border-radius:2px;margin-right:3px;color:var(--accent-cyan)">'+governanceEsc(rid)+'</code>';
      }
    });
    h+='</div>';
  }
  // BUDR detail
  if(r.budrTier){
    var bm=_BUDR_TIER_META[r.budrTier];
    var budrColor=bm?bm.color:'var(--text-muted)';
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">BUDR:</b> ';
    h+='<span style="font-size:9px;color:'+budrColor+';font-weight:600">'+(bm?governanceEsc(bm.name):governanceEsc(r.budrTier))+'</span>';
    if(r.budrStrategy) h+=' <span style="font-size:9px;color:var(--text-muted)">Strategy: '+governanceEsc(r.budrStrategy)+'</span>';
    if(r.rto) h+=' <span style="font-size:9px;color:var(--text-muted)">RTO: '+governanceEsc(r.rto)+'</span>';
    if(r.rpo) h+=' <span style="font-size:9px;color:var(--text-muted)">RPO: '+governanceEsc(r.rpo)+'</span>';
    h+='</div>';
  }
  // Encryption
  if(r.encrypted!=null){
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">Encryption:</b> ';
    if(r.encrypted){
      h+='<span style="font-size:10px;color:#10b981">&#128274; Encrypted</span>';
    } else {
      h+='<span style="font-size:10px;color:#ef4444">&#128275; Not Encrypted</span>';
    }
    h+='</div>';
  }
  // Security Groups
  if(r.sgCount>0){
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">Security Groups:</b> <span style="font-size:10px;color:var(--text-secondary)">'+r.sgCount+'</span></div>';
  }
  // Compliance findings
  var cp=r.compliancePass||0;var cf=r.complianceFail||0;
  if(cp+cf>0){
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">Compliance:</b> <span style="font-size:9px;color:#10b981">'+cp+' pass</span> / <span style="font-size:9px;color:#ef4444">'+cf+' fail</span>';
    // Show individual findings (up to 10)
    var resFindings=(governanceFindings()||[]).filter(function(f){return f.resource===r.id}).slice(0,10);
    if(resFindings.length){
      h+='<ul style="margin:4px 0 0;padding-left:16px;list-style:none">';
      resFindings.forEach(function(f){
        var sColor=f.severity==='CRITICAL'?'#ef4444':f.severity==='HIGH'?'#f97316':f.severity==='MEDIUM'?'#eab308':'#3b82f6';
        h+='<li style="font-size:9px;color:var(--text-secondary);margin:2px 0"><span style="font-size:7px;font-weight:700;padding:1px 4px;border-radius:2px;background:rgba(0,0,0,.2);color:'+sColor+';margin-right:4px">'+governanceEsc(f.severity||'')+'</span>'+governanceEsc(f.message||f.control||'')+'</li>';
      });
      h+='</ul>';
    }
    h+='</div>';
  }
  // Tags
  var tagKeys=Object.keys(r.tags||{});
  if(tagKeys.length){
    h+='<div style="margin-bottom:6px"><b style="color:var(--text-muted);font-size:9px">Tags:</b> <div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:2px">';
    tagKeys.forEach(function(k){
      h+='<span style="font-size:8px;background:var(--bg-input);padding:1px 5px;border-radius:2px;color:var(--text-secondary);border:1px solid var(--border)">'+governanceEsc(k)+'='+governanceEsc(r.tags[k])+'</span>';
    });
    h+='</div></div>';
  }
  // Go to Map button: only for types with SVG representation
  if(!_INV_NO_MAP_TYPES[r.type]){
    h+='<div style="margin-top:8px"><button class="inv-goto-map" data-rid="'+governanceEsc(r.id)+'" style="background:rgba(34,211,238,.1);border:1px solid #22d3ee;color:#22d3ee;padding:4px 12px;border-radius:4px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">Go to Map</button></div>';
  }
  return h;
}

function _wireInventoryEvents(body,footer,items,cols){
  // Tag explorer toggle
  var tagToggle=document.getElementById('invToggleTags');
  if(tagToggle) tagToggle.addEventListener('click',function(){_invState._showTags=!_invState._showTags;_renderInventoryBody()});
  // Tag value click → search
  body.querySelectorAll('.inv-tag-val').forEach(function(chip){
    chip.addEventListener('click',function(e){
      e.stopPropagation();
      var v=this.dataset.tagVal||'';
      var searchEl=document.getElementById('invSearch');
      if(searchEl){searchEl.value=v;_invState.search=v;_invState.page=1;_renderInventoryBody()}
    });
  });
  // Pagination
  if(document.getElementById('invPrev')){
    document.getElementById('invPrev').addEventListener('click',function(){_invState.page--;_renderInventoryBody()});
  }
  if(document.getElementById('invNext')){
    document.getElementById('invNext').addEventListener('click',function(){_invState.page++;_renderInventoryBody()});
  }
  // Page number buttons
  footer.querySelectorAll('.inv-page-num').forEach(function(btn){
    btn.addEventListener('click',function(){_invState.page=parseInt(this.getAttribute('data-p'));_renderInventoryBody()});
  });
  // Sort headers
  body.querySelectorAll('th[data-sort-col]').forEach(function(th){
    th.addEventListener('click',function(){
      var col=this.dataset.sortCol;
      if(_invState.sort===col) _invState.sortDir=_invState.sortDir==='asc'?'desc':'asc';
      else{_invState.sort=col;_invState.sortDir='asc'}
      _invState.page=1;_renderInventoryBody();
    });
  });
  // Row expand/collapse (lazy detail rendering)
  body.querySelectorAll('tr[data-inv-row]').forEach(function(tr){
    tr.addEventListener('click',function(){
      var rowId=this.dataset.invRow;
      var exp=document.getElementById(rowId+'-exp');
      if(!exp) return;
      var isOpen=exp.classList.contains('open');
      body.querySelectorAll('.gov-iam-expand.open').forEach(function(e){e.classList.remove('open')});
      body.querySelectorAll('tr[data-inv-row].expanded').forEach(function(r){r.classList.remove('expanded')});
      if(!isOpen){
        // Lazy: populate detail on first expand
        if(!exp.dataset.loaded){
          var idx=parseInt(exp.dataset.invIdx);
          exp.innerHTML=_buildInvExpandedDetail(items[idx]);
          exp.dataset.loaded='1';
          // Wire Go to Map button inside this detail
          var mapBtn=exp.querySelector('.inv-goto-map');
          if(mapBtn) mapBtn.addEventListener('click',function(e){
            e.stopPropagation();governanceOpenResourceDetail(this.dataset.rid);
          });
        }
        exp.classList.add('open');this.classList.add('expanded');
      }
    });
  });
  // CSV export: all filtered items
  document.getElementById('invExportCSV').addEventListener('click',function(){
    var rows=[['Type','Name','ID','Config','State','VNet','Region','Account','AZ','Classification','BUDR','Compliance Pass','Compliance Fail','Encrypted','SG Count']];
    items.forEach(function(r){
      rows.push([r.type,r.name,r.id,r.config,r.state,r.vpcName||'',r.region,r.account,r.az||'',r.classificationTier||'',r.budrTier||'',r.compliancePass||0,r.complianceFail||0,r.encrypted!=null?r.encrypted:'',r.sgCount||0]);
    });
    var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')}).join('\n');
    governanceDownload(new Blob([csv],{type:'text/csv'}),'inventory-export.csv');
  });
  // JSON export: all filtered items minus _raw
  document.getElementById('invExportJSON').addEventListener('click',function(){
    var clean=items.map(function(r){
      var o={};for(let k in r){if(k!=='_raw') o[k]=r[k]}return o;
    });
    governanceDownload(new Blob([JSON.stringify(clean,null,2)],{type:'application/json'}),'inventory-export.json');
  });
}

function _renderInventoryTree(body,footer){
  var items=_filterInventory();
  var st=_invState;
  var h='';
  // Performance warning
  if(items.length>500&&st.typeFilter==='all'){
    h+='<div style="padding:8px 14px;margin-bottom:10px;background:rgba(249,115,22,.1);border:1px solid rgba(249,115,22,.3);border-radius:6px;font-size:10px;color:#f97316;font-family:Segoe UI,system-ui,sans-serif">Showing all '+items.length+' resources. Use filters to narrow results for better performance.</div>';
  }
  // Build nested tree: account -> region -> VNet -> resources
  var tree={};
  var accountSet={};
  items.forEach(function(r){
    var acct=r.account||'Unknown';
    var rgn=r.region||'Unknown';
    var vpc=r.vpcName||'Global / Non-VNet';
    accountSet[acct]=1;
    if(!tree[acct]) tree[acct]={};
    if(!tree[acct][rgn]) tree[acct][rgn]={};
    if(!tree[acct][rgn][vpc]) tree[acct][rgn][vpc]=[];
    tree[acct][rgn][vpc].push(r);
  });
  var accountKeys=Object.keys(tree).sort();
  var multiAccount=accountKeys.length>1;
  var grpIdx=0;
  accountKeys.forEach(function(acct){
    var acctId='inv-tree-a-'+(grpIdx++);
    if(multiAccount){
      h+='<div class="inv-tree-group">';
      h+='<div class="inv-tree-hdr" data-inv-toggle="'+acctId+'" style="padding:6px 10px;cursor:pointer;font-size:12px;font-weight:700;color:#f97316;font-family:Segoe UI,system-ui,sans-serif;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;user-select:none">';
      h+='<span class="inv-tree-arrow" style="font-size:10px">\u25BC</span>'+governanceEsc(acct);
      h+='</div>';
      h+='<div class="inv-tree-body" id="'+acctId+'">';
    }
    var regionKeys=Object.keys(tree[acct]).sort();
    regionKeys.forEach(function(rgn){
      var rgnId='inv-tree-r-'+(grpIdx++);
      h+='<div class="inv-tree-group" style="margin-left:'+(multiAccount?'12':'0')+'px">';
      h+='<div class="inv-tree-hdr" data-inv-toggle="'+rgnId+'" style="padding:5px 10px;cursor:pointer;font-size:11px;font-weight:700;color:#22d3ee;font-family:Segoe UI,system-ui,sans-serif;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;user-select:none">';
      h+='<span class="inv-tree-arrow" style="font-size:10px">\u25BC</span>'+governanceEsc(rgn);
      h+='</div>';
      h+='<div class="inv-tree-body" id="'+rgnId+'">';
      var vpcKeys=Object.keys(tree[acct][rgn]).sort();
      vpcKeys.forEach(function(vpc){
        var vpcId='inv-tree-v-'+(grpIdx++);
        var vpcItems=tree[acct][rgn][vpc];
        h+='<div class="inv-tree-group" style="margin-left:12px">';
        h+='<div class="inv-tree-hdr" data-inv-toggle="'+vpcId+'" style="padding:4px 10px;cursor:pointer;font-size:10px;font-weight:700;color:#a78bfa;font-family:Segoe UI,system-ui,sans-serif;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;user-select:none">';
        h+='<span class="inv-tree-arrow" style="font-size:10px">\u25BC</span>'+governanceEsc(vpc);
        h+='<span style="font-size:9px;font-weight:400;color:var(--text-muted);margin-left:4px">('+vpcItems.length+')</span>';
        h+='</div>';
        h+='<div class="inv-tree-body" id="'+vpcId+'" style="margin-left:12px">';
        vpcItems.forEach(function(r){
          var tc=_INV_TYPE_COLORS[r.type]||'#64748b';
          h+='<div style="padding:4px 10px;border-bottom:1px solid rgba(255,255,255,.03);display:flex;align-items:center;gap:8px;font-family:Segoe UI,system-ui,sans-serif">';
          // Type badge
          h+='<span style="font-size:8px;font-weight:700;padding:2px 6px;border-radius:3px;background:rgba(0,0,0,.2);color:'+tc+';border:1px solid '+tc+'30;white-space:nowrap;flex-shrink:0">'+governanceEsc(r.type)+'</span>';
          // Name
          h+='<span style="font-size:10px;color:var(--accent-cyan);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px">'+governanceEsc(r.name)+'</span>';
          // Config
          if(r.config){
            h+='<span style="font-size:9px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:140px">'+governanceEsc(r.config)+'</span>';
          }
          // Classification badge
          if(r.classificationTier){
            h+='<span class="gov-tier-badge '+r.classificationTier+'" style="font-size:7px;padding:1px 5px;flex-shrink:0">'+governanceEsc(r.classificationTier)+'</span>';
          }
          // BUDR badge
          if(r.budrTier&&_BUDR_TIER_META[r.budrTier]){
            var bm=_BUDR_TIER_META[r.budrTier];
            h+='<span style="font-size:7px;font-weight:600;padding:1px 5px;border-radius:3px;background:rgba(0,0,0,.2);color:'+bm.color+';border:1px solid '+bm.color+'30;flex-shrink:0">'+governanceEsc(bm.name)+'</span>';
          }
          h+='</div>';
        });
        h+='</div></div>'; // close vpc body + group
      });
      h+='</div></div>'; // close region body + group
    });
    if(multiAccount){
      h+='</div></div>'; // close account body + group
    }
  });
  if(!items.length){
    h+='<div style="padding:40px;text-align:center;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif;font-size:11px">No resources match filters</div>';
  }
  body.innerHTML=h;
  body.scrollTop=0;
  // Wire collapse/expand
  body.querySelectorAll('[data-inv-toggle]').forEach(function(hdr){
    hdr.addEventListener('click',function(){
      var targetId=this.dataset.invToggle;
      var target=document.getElementById(targetId);
      if(!target) return;
      var arrow=this.querySelector('.inv-tree-arrow');
      if(target.style.display==='none'){
        target.style.display='';
        if(arrow) arrow.textContent='\u25BC';
      } else {
        target.style.display='none';
        if(arrow) arrow.textContent='\u25B6';
      }
    });
  });
  // Footer
  var fh='<button id="invExportCSV">Export CSV</button>';
  fh+='<button id="invExportJSON">Export JSON</button>';
  fh+='<span style="margin-left:auto;font-size:10px;color:var(--text-muted)">'+items.length+' of '+_inventoryData.length+' resources</span>';
  footer.innerHTML=fh;
  // Wire export listeners
  document.getElementById('invExportCSV').addEventListener('click',function(){
    var rows=[['Type','Name','ID','Config','State','VNet','Region','Account','AZ','Classification','BUDR','Compliance Pass','Compliance Fail','Encrypted','SG Count']];
    items.forEach(function(r){
      rows.push([r.type,r.name,r.id,r.config,r.state,r.vpcName||'',r.region,r.account,r.az||'',r.classificationTier||'',r.budrTier||'',r.compliancePass||0,r.complianceFail||0,r.encrypted!=null?r.encrypted:'',r.sgCount||0]);
    });
    var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')}).join('\n');
    governanceDownload(new Blob([csv],{type:'text/csv'}),'inventory-export.csv');
  });
  document.getElementById('invExportJSON').addEventListener('click',function(){
    var clean=items.map(function(r){
      var o={};for(let k in r){if(k!=='_raw') o[k]=r[k]}return o;
    });
    governanceDownload(new Blob([JSON.stringify(clean,null,2)],{type:'application/json'}),'inventory-export.json');
  });
}

// Classification state and scoring live in governance-classification.js.

// #endregion GOVERNANCE & INVENTORY
