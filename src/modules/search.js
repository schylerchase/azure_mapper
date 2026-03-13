// Search overlay and resource search functionality
// Handles global search across all Azure resources
// Extracted from index.html for modularization

// === SEARCH INDEX ===
// Pre-built flat index of all searchable resources. Rebuilt when _rlCtx changes.
var _searchIndex=null;
var _searchIndexCtx=null;

function _buildSearchIndex(ctx){
  var idx=[];
  (ctx.vnets||[]).forEach(function(v){
    var n=v.name||v.id;
    var prefixes=((v.properties&&v.properties.addressSpace&&v.properties.addressSpace.addressPrefixes)||[]).join(', ');
    idx.push({type:'VNet',name:n,id:v.id,extra:prefixes,
      acct:v._accountLabel||v._accountId||'',
      searchStr:('vnet virtualnetwork '+n+' '+v.id+' '+prefixes).toLowerCase()});
  });
  (ctx.subnets||[]).forEach(function(s){
    var n=s.name||s.id;
    var prefix=(s.properties&&s.properties.addressPrefix)||'';
    idx.push({type:'Subnet',name:n,id:s.id,extra:prefix,
      acct:s._accountLabel||s._accountId||'',
      searchStr:('subnet '+n+' '+s.id+' '+prefix+' '+(s.location||'')).toLowerCase()});
  });
  (ctx.vms||[]).forEach(function(i){
    var n=i.name||i.id;
    var vmSize=(i.properties&&i.properties.hardwareProfile&&i.properties.hardwareProfile.vmSize)||'';
    idx.push({type:'VM',name:n,id:i.id,extra:vmSize,
      acct:i._accountLabel||i._accountId||'',
      searchStr:('vm virtualmachine '+n+' '+i.id+' '+vmSize).toLowerCase()});
  });
  (ctx.natGateways||[]).forEach(function(g){
    var n=g.name||g.id;
    idx.push({type:'NAT Gateway',name:n,id:g.id,extra:'',
      acct:g._accountLabel||g._accountId||'',
      searchStr:('nat gateway '+n+' '+g.id).toLowerCase()});
  });
  (ctx.sqlServers||[]).forEach(function(d){
    var n=d.name||d.id;
    idx.push({type:'SQL Server',name:n,id:d.id,
      extra:(d.properties&&d.properties.version)||'',acct:d._accountLabel||d._accountId||'',
      searchStr:('sql server '+n+' '+d.id).toLowerCase()});
  });
  (ctx.functionApps||[]).forEach(function(f){
    var n=f.name||f.id;
    idx.push({type:'Function App',name:n,id:f.id,
      extra:'',acct:f._accountLabel||f._accountId||'',
      searchStr:('function app '+n+' '+f.id).toLowerCase()});
  });
  (ctx.nsgs||[]).forEach(function(s){
    var n=s.name||s.id;
    idx.push({type:'NSG',name:n,id:s.id,extra:'',
      acct:s._accountLabel||s._accountId||'',
      searchStr:('nsg network security group '+n+' '+s.id).toLowerCase()});
  });
  (ctx.appGateways||[]).forEach(function(a){
    var n=a.name||a.id;
    idx.push({type:'App Gateway',name:n,id:a.id,extra:'',
      acct:a._accountLabel||a._accountId||'',
      searchStr:('app gateway application gateway '+n+' '+a.id).toLowerCase()});
  });
  (ctx.redisCaches||[]).forEach(function(r){
    var n=r.name||r.id;
    idx.push({type:'Redis Cache',name:n,id:r.id,extra:'',
      acct:r._accountLabel||r._accountId||'',
      searchStr:('redis cache '+n+' '+r.id).toLowerCase()});
  });
  (ctx.storageAccounts||[]).forEach(function(s){
    var n=s.name||s.id;
    var sku=(s.properties&&s.properties.sku&&s.properties.sku.name)||'';
    idx.push({type:'Storage Account',name:n,id:s.id,extra:sku,
      acct:s._accountLabel||s._accountId||'',
      searchStr:('storage account '+n+' '+s.id+' '+sku).toLowerCase()});
  });
  (ctx.aksCluster||[]).forEach(function(k){
    var n=k.name||k.id;
    idx.push({type:'AKS',name:n,id:k.id,extra:'',
      acct:k._accountLabel||k._accountId||'',
      searchStr:('aks kubernetes cluster '+n+' '+k.id).toLowerCase()});
  });
  (ctx.firewalls||[]).forEach(function(fw){
    var n=fw.name||fw.id;
    idx.push({type:'Firewall',name:n,id:fw.id,extra:'',
      acct:fw._accountLabel||fw._accountId||'',
      searchStr:('firewall azure firewall '+n+' '+fw.id).toLowerCase()});
  });
  (ctx.bastions||[]).forEach(function(b){
    var n=b.name||b.id;
    idx.push({type:'Bastion',name:n,id:b.id,extra:'',
      acct:b._accountLabel||b._accountId||'',
      searchStr:('bastion azure bastion '+n+' '+b.id).toLowerCase()});
  });
  return idx;
}

function _invalidateSearchIndex(){_searchIndex=null;_searchIndexCtx=null}

// === SEARCH ===
function openSearch(){const ov=document.getElementById('searchOverlay');ov.style.display='block';
  const inp=document.getElementById('searchInput');inp.value='';inp.focus();document.getElementById('searchResults').innerHTML=''}
function closeSearch(){document.getElementById('searchOverlay').style.display='none'}
var _searchTimer=null;
// Defer DOM wiring until DOMContentLoaded to avoid parse-time errors
(function _wireSearchEvents(){
  function wire(){
    document.getElementById('searchBtn').addEventListener('click',openSearch);
    document.getElementById('searchBackdrop').addEventListener('click',closeSearch);
    document.getElementById('searchInput').addEventListener('input',_onSearchInput);
  }
  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',wire)}else{wire()}
})();
function _onSearchInput(e){
  clearTimeout(_searchTimer);var input=e&&e.target||document.getElementById('searchInput');_searchTimer=setTimeout(function(){
  const q=input.value.toLowerCase().trim();const res=document.getElementById('searchResults');
  if(!q||!_rlCtx){res.innerHTML='';return}
  // Rebuild index if ctx changed
  if(_searchIndexCtx!==_rlCtx){_searchIndex=_buildSearchIndex(_rlCtx);_searchIndexCtx=_rlCtx}
  // Filter cached index in a single pass (cap at 30)
  var matches=[];
  for(var si=0;si<_searchIndex.length&&matches.length<30;si++){
    if(_searchIndex[si].searchStr.includes(q))matches.push(_searchIndex[si]);
  }
  // Notes are dynamic — search them live (typically small set)
  _getAllNotes().forEach(function(n){if(matches.length>=30)return;if((n.text||'').toLowerCase().includes(q)||(_getResourceName(n.resourceId)||'').toLowerCase().includes(q))matches.push({type:'Note',name:(n.text||'').slice(0,50),id:n.resourceId,extra:n.category||'',acct:''})});
  const isMA=_rlCtx._multiAccount;
  let h='';matches.forEach(m=>{const acctBadge=isMA&&m.acct&&m.acct!=='default'?'<span style="font-size:8px;padding:1px 5px;border-radius:3px;background:'+( getAccountColor(m.acct)||'var(--bg-tertiary)')+';color:#000;font-weight:600;white-space:nowrap">'+esc(m.acct)+'</span>':'';h+='<div class="search-result-item" style="padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px" data-rid="'+esc(m.id)+'" data-rtype="'+esc(m.type)+'"><span style="font-size:9px;color:var(--accent-cyan);font-weight:600;width:70px">'+esc(m.type)+'</span><span style="flex:1;font-size:12px;color:var(--text-primary)">'+esc(m.name)+'</span>'+acctBadge+'<span style="font-size:10px;color:var(--text-muted)">'+esc(m.extra)+'</span></div>'});
  if(!matches.length)h='<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:12px">No results</div>';
  res.innerHTML=h;
  // Delegated click handler — replaces inline onclick attributes (CSP-safe)
  res.querySelectorAll('.search-result-item').forEach(function(el){
    el.addEventListener('click',function(){
      closeSearch();
      _zoomToElement(this.dataset.rid);
      _openDetailForSearch(this.dataset.rtype,this.dataset.rid);
    });
  });
});
function _zoomToElement(id){
  if(!_mapSvg||!_mapZoom||!_mapG)return;
  var el=_mapG.node().querySelector('[data-vnet-id="'+id+'"],[data-subnet-id="'+id+'"],[data-gwid="'+id+'"],[data-id="'+id+'"]');
  // Fallback: NSGs don't have SVG nodes — zoom to their VNet instead
  if(!el&&id&&_rlCtx){
    var nsg=(_rlCtx.nsgs||[]).find(function(s){return s.id===id});
    if(nsg&&nsg.properties&&nsg.properties.vnetId) el=_mapG.node().querySelector('[data-vnet-id="'+nsg.properties.vnetId+'"]');
  }
  if(!el)return;const bb=el.getBBox();const cx=bb.x+bb.width/2,cy=bb.y+bb.height/2;
  const svgW=_mapSvg.node().clientWidth,svgH=_mapSvg.node().clientHeight;
  const scale=Math.min(svgW/(bb.width+200),svgH/(bb.height+200),2.5);
  _mapSvg.transition().duration(750).call(_mapZoom.transform,d3.zoomIdentity.translate(svgW/2-cx*scale,svgH/2-cy*scale).scale(scale));
  // Highlight the target element with a pulsing outline
  _highlightElement(el,bb);
}
function _highlightElement(el,bb){
  // Remove any previous highlight
  _mapG.selectAll('.zoom-highlight').remove();
  const pad=8;
  const rect=_mapG.append('rect').attr('class','zoom-highlight')
    .attr('x',bb.x-pad).attr('y',bb.y-pad)
    .attr('width',bb.width+pad*2).attr('height',bb.height+pad*2)
    .attr('rx',6).attr('ry',6)
    .attr('fill','none').attr('stroke','#22d3ee').attr('stroke-width',3)
    .attr('stroke-dasharray','8,4').attr('opacity',0)
    .attr('pointer-events','none');
  // Fade in, pulse 3 times, then fade out
  rect.transition().duration(300).attr('opacity',1)
    .transition().duration(400).attr('stroke-width',5).attr('stroke','#06b6d4')
    .transition().duration(400).attr('stroke-width',3).attr('stroke','#22d3ee')
    .transition().duration(400).attr('stroke-width',5).attr('stroke','#06b6d4')
    .transition().duration(400).attr('stroke-width',3).attr('stroke','#22d3ee')
    .transition().duration(400).attr('stroke-width',5).attr('stroke','#06b6d4')
    .transition().duration(1500).attr('opacity',0)
    .on('end',function(){d3.select(this).remove()});
}

// === RESOLVE RESOURCE TYPE FROM ID ===
function _resolveResourceType(rid){
  if(!rid||!_rlCtx) return null;
  // Azure ARM resource IDs use path segments to identify type
  const low=rid.toLowerCase();
  if(low.includes('/virtualnetworks/')&&!low.includes('/subnets/')) return 'VNet';
  if(low.includes('/subnets/')) return 'Subnet';
  if(low.includes('/virtualmachines/')) return 'VM';
  if(low.includes('/networksecuritygroups/')) return 'NSG';
  if(low.includes('/natgateways/')) return 'NAT Gateway';
  if(low.includes('/privateendpoints/')) return 'Private Endpoint';
  if(low.includes('/virtualnetworkgateways/')) return 'VPN Gateway';
  if(low.includes('/applicationgateways/')) return 'App Gateway';
  if(low.includes('/loadbalancers/')) return 'Load Balancer';
  if(low.includes('/virtualnetworkpeerings/')) return 'VNet Peering';
  if(low.includes('/routetables/')) return 'UDR';
  if(low.includes('/networkinterfaces/')) return 'NIC';
  if(low.includes('/disks/')) return 'Managed Disk';
  if(low.includes('/storageaccounts/')) return 'Storage Account';
  if(low.includes('/dnszones/')) return 'DNS Zone';
  if(low.includes('/managedclusters/')) return 'AKS';
  if(low.includes('/azurefirewalls/')) return 'Firewall';
  if(low.includes('/bastionhosts/')) return 'Bastion';
  // Check by lookup in context
  if((_rlCtx.sqlServers||[]).find(function(d){return d.id===rid})) return 'SQL Server';
  if((_rlCtx.functionApps||[]).find(function(f){return f.id===rid})) return 'Function App';
  if((_rlCtx.containerInstances||[]).find(function(e){return e.id===rid})) return 'Container Instance';
  if((_rlCtx.redisCaches||[]).find(function(c){return c.id===rid})) return 'Redis Cache';
  if((_rlCtx.synapseWorkspaces||[]).find(function(s){return s.id===rid})) return 'Synapse Workspace';
  if((_rlCtx.nsgs||[]).find(function(s){return s.id===rid})) return 'NSG';
  return null;
}

// === ZOOM TO RESOURCE AND OPEN DETAIL PANEL ===
function _zoomAndShowDetail(rid){
  if(!rid||rid==='Multiple') return;
  _zoomToElement(rid);
  var type=_resolveResourceType(rid);
  if(type){
    setTimeout(function(){_openDetailForSearch(type,rid)},400);
  }
}

// === RESOURCE SPOTLIGHT (animated zoom window) ===
var _spotlightActive=false;
function _closeSpotlight(){
  _spotlightActive=false;
  var card=document.getElementById('spotlightCard');
  var backdrop=document.getElementById('spotlightBackdrop');
  if(card){card.style.opacity='0';card.style.transform='translateY(20px) scale(.95)';setTimeout(function(){card.remove()},300)}
  if(backdrop){backdrop.classList.remove('active');setTimeout(function(){backdrop.remove()},400)}
  _mapG&&_mapG.selectAll('.spotlight-ring').remove();
}
function _openResourceSpotlight(rid){
  if(!rid||!_rlCtx)return;
  _closeSpotlight();
  _spotlightActive=true;
  // Find the SVG element
  var el=_mapG.node().querySelector('[data-vnet-id="'+rid+'"],[data-subnet-id="'+rid+'"],[data-gwid="'+rid+'"],[data-id="'+rid+'"]');
  if(!el)return;
  var bb=el.getBBox();
  var cx=bb.x+bb.width/2,cy=bb.y+bb.height/2;
  var svgW=_mapSvg.node().clientWidth,svgH=_mapSvg.node().clientHeight;
  // Animated zoom - tighter zoom than normal
  var scale=Math.min(svgW/(bb.width+300),svgH/(bb.height+300),3.5);
  _mapSvg.transition().duration(900).ease(d3.easeCubicInOut)
    .call(_mapZoom.transform,d3.zoomIdentity.translate(svgW/2-cx*scale,svgH/2-cy*scale).scale(scale));
  // Add animated ring around resource in SVG
  _mapG.selectAll('.spotlight-ring').remove();
  var pad=12;
  var ring=_mapG.append('rect').attr('class','spotlight-ring')
    .attr('x',bb.x-pad).attr('y',bb.y-pad)
    .attr('width',bb.width+pad*2).attr('height',bb.height+pad*2)
    .attr('rx',8).attr('ry',8)
    .attr('fill','none').attr('stroke','#22d3ee').attr('stroke-width',2.5)
    .attr('stroke-dasharray','6,3').attr('opacity',0).attr('pointer-events','none')
    .style('animation','spotlightRingPulse 2s ease-in-out infinite');
  ring.transition().duration(500).delay(400).attr('opacity',1);
  // Gather resource info
  var info=_gatherResourceInfo(rid);
  if(!info)return;
  // Create backdrop
  var backdrop=document.createElement('div');
  backdrop.id='spotlightBackdrop';
  backdrop.className='spotlight-backdrop';
  backdrop.addEventListener('click',_closeSpotlight);
  document.body.appendChild(backdrop);
  requestAnimationFrame(function(){backdrop.classList.add('active')});
  // Build the card
  var card=document.createElement('div');
  card.id='spotlightCard';
  card.className='spotlight-card';
  var typeColors={'VM':'#f97316','SQL Server':'#a78bfa','Function App':'#10b981','App Gateway':'#3b82f6','Container Instance':'#06b6d4','Redis Cache':'#ef4444','Synapse Workspace':'#ec4899','Subnet':'#22d3ee','VNet':'#60a5fa','NSG':'#f59e0b','NAT Gateway':'#f97316','VPN Gateway':'#8b5cf6','Private Endpoint':'#06b6d4','VNet Peering':'#a78bfa','UDR':'#64748b','Storage Account':'#f472b6','AKS':'#818cf8','Firewall':'#ef4444','Bastion':'#34d399'};
  var tc=typeColors[info.type]||'#22d3ee';
  // Header
  var h='<div class="spotlight-header">';
  h+='<button class="spotlight-close" onclick="_closeSpotlight()">&times;</button>';
  h+='<span class="sl-type-badge" style="background:'+tc+'22;color:'+tc+';border:1px solid '+tc+'44">'+_escHtml(info.type)+'</span>';
  h+='<h3>'+_escHtml(info.name)+'</h3>';
  h+='<span class="sl-id" title="Click to copy" onclick="navigator.clipboard&&navigator.clipboard.writeText(\''+_escHtml(rid)+'\')">'+_escHtml(rid)+'</span>';
  h+='</div>';
  // Body
  h+='<div class="spotlight-body">';
  // Details section
  if(info.details&&info.details.length){
    h+='<div class="spotlight-section"><div class="spotlight-section-title">Details</div>';
    h+='<dl class="spotlight-kv">';
    info.details.forEach(function(d){h+='<dt>'+_escHtml(d[0])+'</dt><dd>'+_escHtml(d[1])+'</dd>'});
    h+='</dl></div>';
  }
  // Compliance findings
  if(info.findings&&info.findings.length){
    h+='<div class="spotlight-section"><div class="spotlight-section-title">Compliance ('+info.findings.length+')</div>';
    info.findings.slice(0,5).forEach(function(f){
      var sc={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#3b82f6'}[f.severity]||'#64748b';
      h+='<div style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:10px">';
      h+='<span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:'+sc+';flex-shrink:0"></span>';
      h+='<span style="color:'+sc+';font-weight:600;width:55px;flex-shrink:0">'+_escHtml(f.severity)+'</span>';
      h+='<span style="color:var(--text-secondary);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+_escHtml(f.message)+'</span>';
      h+='</div>';
    });
    if(info.findings.length>5) h+='<div style="font-size:9px;color:var(--text-muted);padding-top:4px">+'+(info.findings.length-5)+' more findings</div>';
    h+='</div>';
  }
  // Related resources
  if(info.related&&info.related.length){
    h+='<div class="spotlight-section"><div class="spotlight-section-title">Related Resources</div>';
    h+='<div class="spotlight-nearby">';
    info.related.forEach(function(r){
      var rc=typeColors[r.type]||'#64748b';
      h+='<div class="spotlight-nearby-item" data-spotlight-rid="'+_escHtml(r.id)+'">';
      h+='<span class="sn-badge" style="background:'+rc+'"></span>';
      h+='<span class="sn-name">'+_escHtml(r.name)+'</span>';
      h+='<span class="sn-type">'+_escHtml(r.type)+'</span>';
      h+='</div>';
    });
    h+='</div></div>';
  }
  // Nearby resources
  if(info.nearby&&info.nearby.length){
    h+='<div class="spotlight-section"><div class="spotlight-section-title">Nearby Resources</div>';
    h+='<div class="spotlight-nearby">';
    info.nearby.forEach(function(r){
      var rc=typeColors[r.type]||'#64748b';
      h+='<div class="spotlight-nearby-item" data-spotlight-rid="'+_escHtml(r.id)+'">';
      h+='<span class="sn-badge" style="background:'+rc+'"></span>';
      h+='<span class="sn-name">'+_escHtml(r.name)+'</span>';
      h+='<span class="sn-type">'+_escHtml(r.type)+'</span>';
      h+='</div>';
    });
    h+='</div></div>';
  }
  h+='</div>';
  // Actions
  h+='<div class="spotlight-actions">';
  h+='<button class="primary" data-spotlight-detail="'+_escHtml(rid)+'">Full Details</button>';
  h+='<button data-spotlight-deps="'+_escHtml(rid)+'">Dependencies</button>';
  h+='</div>';
  card.innerHTML=h;
  document.body.appendChild(card);
  // Wire events
  card.querySelectorAll('[data-spotlight-rid]').forEach(function(el){
    el.addEventListener('click',function(){
      var nrid=this.dataset.spotlightRid;
      _openResourceSpotlight(nrid);
    });
  });
  card.querySelector('[data-spotlight-detail]').addEventListener('click',function(){
    var drid=this.dataset.spotlightDetail;
    _closeSpotlight();
    var type=_resolveResourceType(drid);
    if(type) _openDetailForSearch(type,drid);
  });
  var depsBtn=card.querySelector('[data-spotlight-deps]');
  if(depsBtn) depsBtn.addEventListener('click',function(){
    var drid=this.dataset.spotlightDeps;
    _closeSpotlight();
    if(typeof showDependencies==='function') showDependencies(drid);
  });
}

function _gatherResourceInfo(rid){
  if(!_rlCtx) return null;
  var info={id:rid,name:rid,type:'Unknown',details:[],findings:[],related:[],nearby:[]};
  const low=rid.toLowerCase();
  // Determine type and gather details using ARM ID path segments
  if(low.includes('/virtualnetworks/')&&!low.includes('/subnets/')){
    var vnet=(_rlCtx.vnets||[]).find(function(v){return v.id===rid});
    if(!vnet) return null;
    info.type='VNet';info.name=vnet.name||rid;
    var vnetSubs=(_rlCtx.subnets||[]).filter(function(s){return s.properties&&s.properties.vnetId===rid});
    var prefixes=((vnet.properties&&vnet.properties.addressSpace&&vnet.properties.addressSpace.addressPrefixes)||[]).join(', ');
    info.details=[['Address Space',prefixes||'—'],['Location',vnet.location||'—'],['Subnets',''+vnetSubs.length],['VMs',''+(_rlCtx.vms||[]).filter(function(i){return i.properties&&vnetSubs.some(function(s){return s.id===i.properties.subnetId})}).length]];
    vnetSubs.slice(0,8).forEach(function(s){info.nearby.push({id:s.id,name:s.name||s.id,type:'Subnet'})});
  } else if(low.includes('/subnets/')){
    var sub=(_rlCtx.subnets||[]).find(function(s){return s.id===rid});
    if(!sub) return null;
    info.type='Subnet';info.name=sub.name||rid;
    var addressPrefix=(sub.properties&&sub.properties.addressPrefix)||'';
    info.details=[['Address Prefix',addressPrefix||'—'],['Location',sub.location||'—'],['VNet',(sub.properties&&sub.properties.vnetId)||'—']];
    (_rlCtx.vms||[]).filter(function(i){return i.properties&&i.properties.subnetId===rid}).slice(0,8).forEach(function(i){info.nearby.push({id:i.id,name:i.name||i.id,type:'VM'})});
    if(sub.properties&&sub.properties.vnetId) info.related.push({id:sub.properties.vnetId,name:sub.properties.vnetId,type:'VNet'});
  } else if(low.includes('/virtualmachines/')){
    var inst=(_rlCtx.vms||[]).find(function(i){return i.id===rid});
    if(!inst) return null;
    info.type='VM';info.name=inst.name||rid;
    var vmSize=(inst.properties&&inst.properties.hardwareProfile&&inst.properties.hardwareProfile.vmSize)||'';
    var subnetId=(inst.properties&&inst.properties.subnetId)||'';
    var vnetId=(inst.properties&&inst.properties.vnetId)||'';
    info.details=[['VM Size',vmSize||'—'],['State',(inst.properties&&inst.properties.provisioningState)||'—'],['Location',inst.location||'—'],['Subnet',subnetId||'—'],['VNet',vnetId||'—']];
    if(subnetId){var subObj=(_rlCtx.subnets||[]).find(function(s){return s.id===subnetId});if(subObj) info.related.push({id:subObj.id,name:subObj.name||subObj.id,type:'Subnet'})}
    if(vnetId) info.related.push({id:vnetId,name:vnetId,type:'VNet'});
    (_rlCtx.vms||[]).filter(function(i){return i.properties&&i.properties.subnetId===subnetId&&i.id!==rid}).slice(0,6).forEach(function(i){info.nearby.push({id:i.id,name:i.name||i.id,type:'VM'})});
    (_rlCtx.sqlServers||[]).forEach(function(db){if((db.properties&&db.properties.subnetId)===subnetId) info.nearby.push({id:db.id,name:db.name||db.id,type:'SQL Server'})});
  } else if(low.includes('/networksecuritygroups/')){
    var nsg=(_rlCtx.nsgs||[]).find(function(s){return s.id===rid});
    if(!nsg) return null;
    info.type='NSG';info.name=nsg.name||rid;
    var rules=(nsg.properties&&nsg.properties.securityRules)||[];
    var inbound=rules.filter(function(r){return(r.properties&&r.properties.direction)==='Inbound'}).length;
    var outbound=rules.filter(function(r){return(r.properties&&r.properties.direction)==='Outbound'}).length;
    info.details=[['ID',rid],['Location',nsg.location||'—'],['Inbound Rules',''+inbound],['Outbound Rules',''+outbound]];
    if(nsg.properties&&nsg.properties.vnetId) info.related.push({id:nsg.properties.vnetId,name:nsg.properties.vnetId,type:'VNet'});
    (_rlCtx.vms||[]).filter(function(i){return i.properties&&i.properties.nsgId===rid}).slice(0,6).forEach(function(i){info.nearby.push({id:i.id,name:i.name||i.id,type:'VM'})});
  } else if(low.includes('/natgateways/')){
    var nat=(_rlCtx.natGateways||[]).find(function(g){return g.id===rid});
    if(!nat) return null;
    info.type='NAT Gateway';info.name=nat.name||rid;
    info.details=[['ID',rid],['State',(nat.properties&&nat.properties.provisioningState)||'—'],['Location',nat.location||'—']];
    if(nat.properties&&nat.properties.vnetId) info.related.push({id:nat.properties.vnetId,name:nat.properties.vnetId,type:'VNet'});
  } else {
    // Try SQL Server, Function App, etc. by id lookup
    var sql=(_rlCtx.sqlServers||[]).find(function(d){return d.id===rid});
    if(sql){
      info.type='SQL Server';info.name=sql.name||rid;
      info.details=[['Version',(sql.properties&&sql.properties.version)||'—'],['State',(sql.properties&&sql.properties.state)||'—'],['Location',sql.location||'—'],['Zone Redundant',(sql.properties&&sql.properties.zoneRedundant)?'Yes':'No'],['Backup Retention',((sql.properties&&sql.properties.backupRetentionDays)||'?')+' days'],['Geo Redundant',(sql.properties&&sql.properties.geoRedundantBackup)==='Enabled'?'Yes':'No']];
      var sqlVnet=(sql.properties&&sql.properties.vnetId)||'';
      if(sqlVnet) info.related.push({id:sqlVnet,name:sqlVnet,type:'VNet'});
    } else {
      var fn=(_rlCtx.functionApps||[]).find(function(f){return f.id===rid});
      if(fn){
        info.type='Function App';info.name=fn.name||rid;
        info.details=[['State',(fn.properties&&fn.properties.state)||'—'],['Location',fn.location||'—']];
        var fnVnet=(fn.properties&&fn.properties.vnetId)||'';
        if(fnVnet) info.related.push({id:fnVnet,name:fnVnet,type:'VNet'});
      } else {
        return null;
      }
    }
  }
  // Gather compliance findings for this resource
  (_complianceFindings||[]).forEach(function(f){
    if(f.resource===rid&&!_isMuted(f)) info.findings.push(f);
  });
  return info;
}


