// Resource detail panel and spotlight system
// Displays detailed information for selected resources
// Extracted from index.html for modularization
//
// TODO: _zoomAndShowDetail, _closeSpotlight, _openResourceSpotlight, _gatherResourceInfo
// are duplicated in search.js. Consolidate into a single module and import from there.
// The typeColors map also differs slightly between the two files.

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
  var typeColors={VM:'#f97316',SQL:'#a78bfa','Function App':'#10b981',LB:'#3b82f6',ContainerService:'#06b6d4',Redis:'#ef4444',Synapse:'#ec4899',Subnet:'#22d3ee',VNet:'#60a5fa',NSG:'#f59e0b',FW:'#10b981',NAT:'#f97316',VGW:'#8b5cf6',PE:'#06b6d4',VHUB:'#6366f1'};
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

// Helper: extract VNet ID from an ARM subnet ID
// e.g. /subscriptions/.../virtualNetworks/myVnet/subnets/mySub → extract VNet ID
function _vnetIdFromSubnetId(subnetArmId){
  if(!subnetArmId||!_rlCtx)return '';
  // Walk up the ARM path: find the virtualNetworks segment
  var parts=(subnetArmId||'').split('/');
  var vnIdx=parts.indexOf('virtualNetworks');
  if(vnIdx!==-1&&vnIdx+1<parts.length){
    // Reconstruct VNet ARM ID
    return parts.slice(0,vnIdx+2).join('/');
  }
  return '';
}

// Helper: get private IP from VM's NIC config
function _vmPrivateIp(inst){
  var nicConfigs=inst.properties&&inst.properties.networkProfile&&inst.properties.networkProfile.networkInterfaces;
  if(!nicConfigs||!nicConfigs.length)return '';
  // Look up the NIC in _rlCtx.nics if available
  var nicRef=nicConfigs[0];
  var nicId=nicRef.id||'';
  if(_rlCtx.nics){
    var nic=(_rlCtx.nics||[]).find(function(n){return n.id===nicId});
    if(nic&&nic.properties&&nic.properties.ipConfigurations){
      var ipCfg=nic.properties.ipConfigurations[0];
      return ipCfg&&ipCfg.properties&&ipCfg.properties.privateIPAddress||'';
    }
  }
  return '';
}

// Helper: get public IP from VM's NIC config
function _vmPublicIp(inst){
  var nicConfigs=inst.properties&&inst.properties.networkProfile&&inst.properties.networkProfile.networkInterfaces;
  if(!nicConfigs||!nicConfigs.length)return '';
  var nicRef=nicConfigs[0];
  var nicId=nicRef.id||'';
  if(_rlCtx.nics){
    var nic=(_rlCtx.nics||[]).find(function(n){return n.id===nicId});
    if(nic&&nic.properties&&nic.properties.ipConfigurations){
      var ipCfg=nic.properties.ipConfigurations[0];
      var pubIpRef=ipCfg&&ipCfg.properties&&ipCfg.properties.publicIPAddress;
      if(pubIpRef&&pubIpRef.id&&_rlCtx.publicIps){
        var pip=(_rlCtx.publicIps||[]).find(function(p){return p.id===pubIpRef.id});
        return pip&&pip.properties&&pip.properties.ipAddress||'';
      }
    }
  }
  return '';
}

// Helper: get subnet ID from VM's NIC config
function _vmSubnetId(inst){
  var nicConfigs=inst.properties&&inst.properties.networkProfile&&inst.properties.networkProfile.networkInterfaces;
  if(!nicConfigs||!nicConfigs.length)return '';
  var nicRef=nicConfigs[0];
  var nicId=nicRef.id||'';
  if(_rlCtx.nics){
    var nic=(_rlCtx.nics||[]).find(function(n){return n.id===nicId});
    if(nic&&nic.properties&&nic.properties.ipConfigurations){
      var ipCfg=nic.properties.ipConfigurations[0];
      return ipCfg&&ipCfg.properties&&ipCfg.properties.subnet&&ipCfg.properties.subnet.id||'';
    }
  }
  return '';
}

// Helper: get NSG IDs from VM's NIC config
function _vmNsgIds(inst){
  var result=[];
  var nicConfigs=inst.properties&&inst.properties.networkProfile&&inst.properties.networkProfile.networkInterfaces;
  if(!nicConfigs||!nicConfigs.length)return result;
  if(_rlCtx.nics){
    nicConfigs.forEach(function(nicRef){
      var nic=(_rlCtx.nics||[]).find(function(n){return n.id===nicRef.id});
      if(nic&&nic.properties&&nic.properties.networkSecurityGroup){
        result.push(nic.properties.networkSecurityGroup.id);
      }
    });
  }
  return result;
}

// Helper: get image reference string from VM
function _vmImageRef(inst){
  var imgRef=inst.properties&&inst.properties.storageProfile&&inst.properties.storageProfile.imageReference;
  if(!imgRef)return '—';
  if(imgRef.exactVersion)return imgRef.publisher+'/'+imgRef.offer+'/'+imgRef.sku+'/'+imgRef.exactVersion;
  if(imgRef.publisher)return imgRef.publisher+'/'+imgRef.offer+'/'+imgRef.sku;
  return imgRef.id||'—';
}

// Helper: derive VNet ID for an NSG by checking subnet associations or resource group
function _nsgVnetId(sg){
  if(sg.properties&&sg.properties.subnets&&sg.properties.subnets.length){
    return _vnetIdFromSubnetId(sg.properties.subnets[0].id);
  }
  return '';
}

// Helper: calculate available IPs from CIDR (Azure reserves 5)
function _availableIpsFromCidr(cidr){
  if(!cidr)return 0;
  var parts=cidr.split('/');
  if(parts.length!==2)return 0;
  var prefix=parseInt(parts[1],10);
  if(isNaN(prefix)||prefix>30)return 0;
  return Math.pow(2,32-prefix)-5;
}

function _gatherResourceInfo(rid){
  if(!_rlCtx) return null;
  var info={id:rid,name:rid,type:'Unknown',details:[],findings:[],related:[],nearby:[]};
  var gn2=function(obj,fallback){return obj&&obj.name||obj&&obj.tags&&obj.tags.Name||fallback};
  // Determine type and gather details
  var inst=(_rlCtx.vms||[]).find(function(i){return i.id===rid||i.name===rid});
  if(inst){
    info.type='VM';info.name=gn2(inst,rid);
    var vmSubnet=_vmSubnetId(inst);
    var vmVnet=_vnetIdFromSubnetId(vmSubnet);
    var vmSize=inst.properties&&inst.properties.hardwareProfile&&inst.properties.hardwareProfile.vmSize||'—';
    var vmState=inst.properties&&inst.properties.provisioningState||'—';
    info.details=[['Size',vmSize],['State',vmState],['Private IP',_vmPrivateIp(inst)||'—'],['Public IP',_vmPublicIp(inst)||'—'],['Location',inst.zones&&inst.zones[0]?inst.location+' (zone '+inst.zones[0]+')':inst.location||'—'],['Subnet',vmSubnet||'—'],['VNet',vmVnet||'—']];
    // Related: NSGs, subnet, VNet
    _vmNsgIds(inst).forEach(function(nsgId){
      var nsg=(_rlCtx.nsgs||[]).find(function(s){return s.id===nsgId});
      info.related.push({id:nsgId,name:nsg&&nsg.name||nsgId,type:'NSG'});
    });
    if(vmSubnet){var sub=(_rlCtx.subnets||[]).find(function(s){return s.id===vmSubnet});if(sub) info.related.push({id:sub.id,name:gn2(sub,sub.id),type:'Subnet'})}
    // Nearby: other VMs in same subnet
    (_rlCtx.vms||[]).filter(function(i){return _vmSubnetId(i)===vmSubnet&&i.id!==rid}).slice(0,6).forEach(function(i){info.nearby.push({id:i.id,name:gn2(i,i.id),type:'VM'})});
    // Also add SQL servers in same VNet
    (_rlCtx.sqlServers||[]).forEach(function(db){
      if(db.properties&&db.properties.virtualNetworkRules){
        var matchesVnet=db.properties.virtualNetworkRules.some(function(r){return _vnetIdFromSubnetId(r.properties&&r.properties.virtualNetworkSubnetId)===vmVnet});
        if(matchesVnet) info.nearby.push({id:db.id||db.name,name:db.name,type:'SQL'});
      }
    });
  } else if((_rlCtx.subnets||[]).find(function(s){return s.id===rid||s.name===rid})){
    var sub=(_rlCtx.subnets||[]).find(function(s){return s.id===rid||s.name===rid});
    info.type='Subnet';info.name=gn2(sub,rid);
    var subVnetId=_vnetIdFromSubnetId(sub.id);
    var isPub=_rlCtx.pubSubs&&_rlCtx.pubSubs.has(sub.id);
    var cidr=sub.properties&&sub.properties.addressPrefix||'—';
    info.details=[['CIDR',cidr],['Type',isPub?'Public':'Private'],['VNet',subVnetId||'—'],['Available IPs',''+_availableIpsFromCidr(cidr)],['Location',sub.location||'—']];
    // Nearby: resources in this subnet
    (_rlCtx.vms||[]).filter(function(i){return _vmSubnetId(i)===sub.id}).slice(0,8).forEach(function(i){info.nearby.push({id:i.id,name:gn2(i,i.id),type:'VM'})});
    // Related: VNet
    if(subVnetId) info.related.push({id:subVnetId,name:subVnetId,type:'VNet'});
  } else if((_rlCtx.vnets||[]).find(function(v){return v.id===rid||v.name===rid})){
    var vnet=(_rlCtx.vnets||[]).find(function(v){return v.id===rid||v.name===rid});
    info.type='VNet';info.name=gn2(vnet,rid);
    var vnetSubs=(_rlCtx.subnets||[]).filter(function(s){return _vnetIdFromSubnetId(s.id)===vnet.id});
    var vnetCidr=vnet.properties&&vnet.properties.addressSpace&&vnet.properties.addressSpace.addressPrefixes&&vnet.properties.addressSpace.addressPrefixes[0]||'—';
    var vnetState=vnet.properties&&vnet.properties.provisioningState||'—';
    info.details=[['CIDR',vnetCidr],['State',vnetState],['Subnets',''+vnetSubs.length],['VMs',''+(_rlCtx.vms||[]).filter(function(i){return vnetSubs.some(function(s){return s.id===_vmSubnetId(i)})}).length]];
    vnetSubs.slice(0,8).forEach(function(s){info.nearby.push({id:s.id,name:gn2(s,s.id),type:'Subnet'})});
  } else if((_rlCtx.nsgs||[]).find(function(s){return s.id===rid||s.name===rid})){
    var sg=(_rlCtx.nsgs||[]).find(function(s){return s.id===rid||s.name===rid});
    info.type='NSG';info.name=sg.name||rid;
    var sgVnetId=_nsgVnetId(sg);
    var inRules=sg.properties&&sg.properties.securityRules?sg.properties.securityRules.filter(function(r){return r.properties&&r.properties.direction==='Inbound'}):[];
    var outRules=sg.properties&&sg.properties.securityRules?sg.properties.securityRules.filter(function(r){return r.properties&&r.properties.direction==='Outbound'}):[];
    info.details=[['NSG ID',rid],['Description',sg.properties&&sg.properties.description||'—'],['VNet',sgVnetId||'—'],['Inbound Rules',''+inRules.length],['Outbound Rules',''+outRules.length]];
    if(sgVnetId) info.related.push({id:sgVnetId,name:sgVnetId,type:'VNet'});
    // VMs using this NSG
    (_rlCtx.vms||[]).filter(function(i){return _vmNsgIds(i).indexOf(sg.id)!==-1}).slice(0,6).forEach(function(i){info.nearby.push({id:i.id,name:gn2(i,i.id),type:'VM'})});
  } else if((_rlCtx.nats||[]).find(function(g){return g.id===rid||g.name===rid})){
    var nat=(_rlCtx.nats||[]).find(function(g){return g.id===rid||g.name===rid});
    info.type='NAT';info.name=gn2(nat,rid);
    var natSubnet=nat.properties&&nat.properties.subnets&&nat.properties.subnets[0]&&nat.properties.subnets[0].id||'';
    var natVnet=_vnetIdFromSubnetId(natSubnet);
    var natState=nat.properties&&nat.properties.provisioningState||'—';
    info.details=[['Gateway ID',rid],['State',natState],['Subnet',natSubnet||'—'],['VNet',natVnet||'—']];
    if(natVnet) info.related.push({id:natVnet,name:natVnet,type:'VNet'});
    if(natSubnet) info.related.push({id:natSubnet,name:natSubnet,type:'Subnet'});
  } else {
    // Try SQL, Function App, etc. by name lookup
    var sql=(_rlCtx.sqlServers||[]).find(function(d){return d.name===rid||d.id===rid});
    if(sql){
      info.type='SQL';info.name=sql.name;
      var sqlState=sql.properties&&sql.properties.state||'—';
      var sqlVersion=sql.properties&&sql.properties.version||'—';
      var sqlFqdn=sql.properties&&sql.properties.fullyQualifiedDomainName||'—';
      info.details=[['Server Name',sql.name],['State',sqlState],['Version',sqlVersion],['FQDN',sqlFqdn],['Location',sql.location||'—']];
    } else {
      var pe=(_rlCtx.privateEndpoints||[]).find(function(p){return p.id===rid||p.name===rid});
      if(pe){
        info.type='PE';info.name=pe.name||rid;
        var peProps=pe.properties||pe._azure&&pe._azure.properties||{};
        var peConn=peProps.privateLinkServiceConnections&&peProps.privateLinkServiceConnections[0];
        var peConnProps=peConn&&peConn.properties||{};
        var peTarget=peConnProps.privateLinkServiceId||'—';
        var peGroupIds=(peConnProps.groupIds||[]).join(', ')||'—';
        var peState=peConnProps.privateLinkServiceConnectionState&&peConnProps.privateLinkServiceConnectionState.status||'—';
        var peSubId=peProps.subnet&&peProps.subnet.id||'';
        var peVnetId=_vnetIdFromSubnetId(peSubId);
        var peDns=peProps.customDnsConfigs&&peProps.customDnsConfigs[0];
        var peFqdn=peDns&&peDns.fqdn||'—';
        var peIp=peDns&&peDns.ipAddresses&&peDns.ipAddresses[0]||'—';
        info.details=[['Target Service',peTarget.split('/').pop()],['Group IDs',peGroupIds],['State',peState],['Private IP',peIp],['FQDN',peFqdn],['Subnet',peSubId?peSubId.split('/').pop():'—'],['VNet',peVnetId?peVnetId.split('/').pop():'—'],['Location',pe.location||'—']];
        if(peSubId) info.related.push({id:peSubId,name:peSubId.split('/').pop(),type:'Subnet'});
        if(peVnetId) info.related.push({id:peVnetId,name:peVnetId.split('/').pop(),type:'VNet'});
      } else {
        var func=(_rlCtx.functionApps||[]).find(function(f){return f.name===rid||f.id===rid});
        if(func){
          info.type='Function App';info.name=func.name;
          var fnState=func.properties&&func.properties.state||'—';
          var fnKind=func.kind||'—';
          var fnUrl=func.properties&&func.properties.defaultHostName||'—';
          info.details=[['Name',func.name],['Kind',fnKind],['State',fnState],['URL',fnUrl],['Location',func.location||'—']];
          var funcVnetId=func.properties&&func.properties.virtualNetworkSubnetId;
          if(funcVnetId){
            var fnVnet=_vnetIdFromSubnetId(funcVnetId);
            if(fnVnet) info.related.push({id:fnVnet,name:fnVnet,type:'VNet'});
          }
        } else {
          return null;
        }
      }
    }
  }
  // Gather compliance findings for this resource
  (_complianceFindings||[]).forEach(function(f){
    if(f.resource===rid&&!_isMuted(f)) info.findings.push(f);
  });
  return info;
}

// Wire back button handler for detail panel
function _wireDpBackButton(){
  const dp=document.getElementById('detailPanel');
  const backEl=document.getElementById('dpBack');
  if(backEl){backEl.addEventListener('click',()=>{
    const prev=_navStack.pop();
    if(prev&&prev.fn) prev.fn();
    else dp.classList.remove('open');
  })}
}
// Build back button HTML if nav stack has entries
function _dpBackBtnHtml(){
  return _navStack.length>0?'<span id="dpBack" style="cursor:pointer;color:var(--accent-blue);font-size:calc(10px * var(--txt-scale,1) * var(--dp-txt-scale,1));font-family:Segoe UI,system-ui,sans-serif;margin-right:8px" title="Back">&lt; Back</span>':'';
}
// Type badge colors for detail panel headers
var _dpTypeColors={VM:'#f97316',SQL:'#a78bfa','Function App':'#10b981',VNet:'#60a5fa',NSG:'#f59e0b',PE:'#a78bfa'};
function _dpTypeBadge(type){
  var tc=_dpTypeColors[type]||'#22d3ee';
  return '<span style="display:inline-block;font-size:9px;font-weight:600;padding:2px 8px;border-radius:4px;margin-right:8px;background:'+tc+'22;color:'+tc+';border:1px solid '+tc+'44;vertical-align:middle">'+esc(type)+'</span>';
}

// === SEARCH -> DETAIL PANEL DISPATCH ===
// NOTE: innerHTML usage here renders pre-escaped content via esc() and _escHtml() — no raw user input
var _dpSkipPush=false;
function _openDetailForSearch(type,id){
  if(!_rlCtx) return;
  const dp=document.getElementById('detailPanel');
  const dpTitle=document.getElementById('dpTitle');
  const dpSub=document.getElementById('dpSub');
  const dpBody=document.getElementById('dpBody');

  // If panel is already open, push current state for back navigation
  if(!_dpSkipPush&&dp.classList.contains('open')&&dpBody.textContent){
    const prevType=dp.dataset.dpType;const prevId=dp.dataset.dpId;
    if(prevType&&prevId){
      _navStack.push({fn:()=>{ _dpSkipPush=true;_openDetailForSearch(prevType,prevId);_dpSkipPush=false; }});
    }
  }
  dp.dataset.dpType=type;dp.dataset.dpId=id;
  _lastRlType=null;

  if(type==='Subnet'){
    const sub=(_rlCtx.subnets||[]).find(s=>s.id===id||s.name===id);
    if(sub){
      var subVnetId=_vnetIdFromSubnetId(sub.id);
      openSubnetPanel(sub,subVnetId,{pubSubs:_rlCtx.pubSubs,subRT:_rlCtx.subRT,subNacl:_rlCtx.subNacl,instBySub:_rlCtx.instBySub,eniBySub:_rlCtx.eniBySub,albBySub:_rlCtx.albBySub,sgByVpc:_rlCtx.sgByVpc,volByInst:_rlCtx.volByInst,enis:_rlCtx.enis,snapByVol:_rlCtx.snapByVol,tgByAlb:_rlCtx.tgByAlb,wafByAlb:_rlCtx.wafByAlb,rdsBySub:_rlCtx.rdsBySub,ecsBySub:_rlCtx.ecsBySub,lambdaBySub:_rlCtx.lambdaBySub,ecacheByVpc:_rlCtx.ecacheByVpc,redshiftByVpc:_rlCtx.redshiftByVpc,cfByAlb:_rlCtx.cfByAlb});
      return;
    }
  }
  if(type==='FW'||type==='NAT'||type==='VGW'||type==='PE'||type==='Private Endpoint'||type==='VHUB'){
    const gwType=(type==='Private Endpoint')?'PE':type;
    openGatewayPanel(id,gwType,{gwNames:gwNames,firewalls:_rlCtx.firewalls,nats:_rlCtx.nats,vpns:_rlCtx.vpns,vpces:_rlCtx.privateEndpoints,privateEndpoints:_rlCtx.privateEndpoints,peerings:_rlCtx.peerings,udrs:_rlCtx.udrs,subnets:_rlCtx.subnets,subRT:_rlCtx.subRT,pubSubs:_rlCtx.pubSubs,vnets:_rlCtx.vnets,vhubs:_rlCtx.vhubs||[],vhubConnections:_rlCtx.vhubConnections||[]});
    return;
  }

  // Generic detail panel for VNet, VM, SQL, Function App, NSG, Note
  const backBtn=_dpBackBtnHtml();
  let h='';
  if(type==='VNet'){
    const vnet=(_rlCtx.vnets||[]).find(v=>v.id===id||v.name===id);
    if(!vnet) return;
    const nm=gn(vnet,vnet.id);
    const subs=(_rlCtx.subnets||[]).filter(s=>_vnetIdFromSubnetId(s.id)===vnet.id);
    const pubCount=subs.filter(s=>_rlCtx.pubSubs&&_rlCtx.pubSubs.has(s.id)).length;
    const gws=[];
    (_rlCtx.firewalls||[]).forEach(g=>{if(_vnetIdFromSubnetId(g.properties&&g.properties.ipConfigurations&&g.properties.ipConfigurations[0]&&g.properties.ipConfigurations[0].properties&&g.properties.ipConfigurations[0].properties.subnet&&g.properties.ipConfigurations[0].properties.subnet.id)===vnet.id)gws.push({type:'FW',id:g.id,name:gn(g,g.id)})});
    (_rlCtx.nats||[]).forEach(g=>{var natSub=g.properties&&g.properties.subnets&&g.properties.subnets[0]&&g.properties.subnets[0].id||'';if(_vnetIdFromSubnetId(natSub)===vnet.id)gws.push({type:'NAT',id:g.id,name:gn(g,g.id)})});
    const nsgs=(_rlCtx.nsgs||[]).filter(s=>_nsgVnetId(s)===vnet.id);
    const vms=(_rlCtx.vms||[]).filter(i=>subs.some(s=>s.id===_vmSubnetId(i)));
    const vnetCidr=vnet.properties&&vnet.properties.addressSpace&&vnet.properties.addressSpace.addressPrefixes&&vnet.properties.addressSpace.addressPrefixes[0]||'';
    const vnetState=vnet.properties&&vnet.properties.provisioningState||'—';
    dpTitle.innerHTML=backBtn+_dpTypeBadge('VNet')+_escHtml(nm);
    dpSub.innerHTML='<span class="copyable" data-copy="'+esc(id)+'">'+esc(id)+'</span> &middot; '+esc(vnetCidr);
    h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Overview</span><span class="dp-sec-arr">&#9660;</span></div><div class="dp-sec-body">';
    h+='<table class="dp-kv"><tr><td>CIDR</td><td>'+esc(vnetCidr||'—')+'</td></tr>';
    h+='<tr><td>Subnets</td><td>'+subs.length+' ('+pubCount+' public, '+(subs.length-pubCount)+' private)</td></tr>';
    h+='<tr><td>Gateways</td><td>'+gws.length+'</td></tr>';
    h+='<tr><td>Network Security Groups</td><td>'+nsgs.length+'</td></tr>';
    h+='<tr><td>VMs</td><td>'+vms.length+'</td></tr>';
    h+='<tr><td>State</td><td>'+esc(vnetState)+'</td></tr></table></div></div>';
    if(subs.length){
      h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Subnets</span><span><span class="dp-sec-count">'+subs.length+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body">';
      subs.forEach(s=>{
        const sn=gn(s,s.id);const isPub=_rlCtx.pubSubs&&_rlCtx.pubSubs.has(s.id);
        const sCidr=s.properties&&s.properties.addressPrefix||'';
        h+='<div style="padding:4px 0;cursor:pointer;color:var(--accent-cyan);font-size:calc(11px * var(--dp-txt-scale,1))" onclick="_openDetailForSearch(\'Subnet\',\''+esc(s.id)+'\');_zoomToElement(\''+esc(s.id)+'\')">'+_escHtml(sn)+' <span style="color:var(--text-muted);font-size:9px">'+(isPub?'PUB':'PRV')+' '+esc(sCidr)+'</span></div>';
      });
      h+='</div></div>';
    }
    if(gws.length){
      h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Gateways</span><span><span class="dp-sec-count">'+gws.length+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body">';
      gws.forEach(g=>{
        h+='<div style="padding:4px 0;cursor:pointer;color:'+gcv(g.type)+';font-size:calc(11px * var(--dp-txt-scale,1))" onclick="_openDetailForSearch(\''+g.type+'\',\''+esc(g.id)+'\')">'+g.type+': '+_escHtml(g.name)+'</div>';
      });
      h+='</div></div>';
    }
  } else if(type==='VM'){
    const inst=(_rlCtx.vms||[]).find(i=>i.id===id||i.name===id);
    if(!inst) return;
    const nm=gn(inst,inst.id);
    const vmSize=inst.properties&&inst.properties.hardwareProfile&&inst.properties.hardwareProfile.vmSize||'—';
    const stateName=inst.properties&&inst.properties.provisioningState||'—';
    const stateColor=stateName==='Succeeded'?'var(--accent-green)':stateName==='Failed'?'var(--accent-red)':'var(--text-muted)';
    const vmSubnet=_vmSubnetId(inst);
    const vmVnet=_vnetIdFromSubnetId(vmSubnet);
    dpTitle.innerHTML=backBtn+_dpTypeBadge('VM')+_escHtml(nm);
    dpSub.innerHTML='<span class="copyable" data-copy="'+esc(id)+'">'+esc(id)+'</span> &middot; '+esc(vmSize);
    h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Details</span><span class="dp-sec-arr">&#9660;</span></div><div class="dp-sec-body">';
    h+='<table class="dp-kv">';
    h+='<tr><td>Size</td><td>'+esc(vmSize)+'</td></tr>';
    h+='<tr><td>State</td><td><span style="color:'+stateColor+'">'+esc(stateName)+'</span></td></tr>';
    h+='<tr><td>Location</td><td>'+esc(inst.zones&&inst.zones[0]?inst.location+' (zone '+inst.zones[0]+')':inst.location||'—')+'</td></tr>';
    h+='<tr><td>Private IP</td><td>'+esc(_vmPrivateIp(inst)||'—')+'</td></tr>';
    h+='<tr><td>Public IP</td><td>'+esc(_vmPublicIp(inst)||'—')+'</td></tr>';
    h+='<tr><td>Subnet</td><td><span style="cursor:pointer;color:var(--accent-cyan)" onclick="_openDetailForSearch(\'Subnet\',\''+esc(vmSubnet)+'\');_zoomToElement(\''+esc(vmSubnet)+'\')">'+esc(vmSubnet||'—')+'</span></td></tr>';
    h+='<tr><td>VNet</td><td><span style="cursor:pointer;color:var(--accent-cyan)" onclick="_openDetailForSearch(\'VNet\',\''+esc(vmVnet)+'\')">'+esc(vmVnet||'—')+'</span></td></tr>';
    h+='<tr><td>Image</td><td>'+esc(_vmImageRef(inst))+'</td></tr>';
    h+='</table></div></div>';
    const nsgIds=_vmNsgIds(inst);
    if(nsgIds.length){
      h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Network Security Groups</span><span><span class="dp-sec-count">'+nsgIds.length+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body">';
      nsgIds.forEach(nsgId=>{
        const nsg=(_rlCtx.nsgs||[]).find(s=>s.id===nsgId);
        const nsgName=nsg&&nsg.name||nsgId;
        h+='<div style="padding:4px 0;cursor:pointer;color:var(--accent-cyan);font-size:calc(11px * var(--dp-txt-scale,1))" onclick="_openDetailForSearch(\'NSG\',\''+esc(nsgId)+'\')">'+esc(nsgName)+' <span style="color:var(--text-muted);font-size:9px">'+esc(nsgId)+'</span></div>';
      });
      h+='</div></div>';
    }
  } else if(type==='SQL'){
    const db=(_rlCtx.sqlServers||[]).find(d=>d.name===id||d.id===id);
    if(!db) return;
    const sqlState=db.properties&&db.properties.state||'—';
    const sqlVersion=db.properties&&db.properties.version||'—';
    const sqlFqdn=db.properties&&db.properties.fullyQualifiedDomainName||'—';
    dpTitle.innerHTML=backBtn+_dpTypeBadge('SQL')+_escHtml(db.name);
    dpSub.innerHTML=esc(db.kind||'')+' &middot; '+esc(db.location||'');
    h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Details</span><span class="dp-sec-arr">&#9660;</span></div><div class="dp-sec-body">';
    h+='<table class="dp-kv">';
    h+='<tr><td>Server Name</td><td>'+esc(db.name||'—')+'</td></tr>';
    h+='<tr><td>State</td><td>'+esc(sqlState)+'</td></tr>';
    h+='<tr><td>Version</td><td>'+esc(sqlVersion)+'</td></tr>';
    h+='<tr><td>FQDN</td><td>'+esc(sqlFqdn)+'</td></tr>';
    h+='<tr><td>Location</td><td>'+esc(db.location||'—')+'</td></tr>';
    h+='<tr><td>Admin Login</td><td>'+esc(db.properties&&db.properties.administratorLogin||'—')+'</td></tr>';
    h+='</table></div></div>';
  } else if(type==='Function App'){
    const fn=(_rlCtx.functionApps||[]).find(f=>f.name===id||f.id===id);
    if(!fn) return;
    const fnState=fn.properties&&fn.properties.state||'—';
    const fnUrl=fn.properties&&fn.properties.defaultHostName||'—';
    dpTitle.innerHTML=backBtn+_dpTypeBadge('Function App')+_escHtml(fn.name);
    dpSub.innerHTML=esc(fn.kind||'')+ ' &middot; '+esc(fn.location||'');
    h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Details</span><span class="dp-sec-arr">&#9660;</span></div><div class="dp-sec-body">';
    h+='<table class="dp-kv">';
    h+='<tr><td>Name</td><td>'+esc(fn.name||'—')+'</td></tr>';
    h+='<tr><td>Kind</td><td>'+esc(fn.kind||'—')+'</td></tr>';
    h+='<tr><td>State</td><td>'+esc(fnState)+'</td></tr>';
    h+='<tr><td>URL</td><td>'+esc(fnUrl)+'</td></tr>';
    h+='<tr><td>Location</td><td>'+esc(fn.location||'—')+'</td></tr>';
    const funcVnetSubnet=fn.properties&&fn.properties.virtualNetworkSubnetId;
    if(funcVnetSubnet){
      const fnVnet=_vnetIdFromSubnetId(funcVnetSubnet);
      h+='<tr><td>VNet</td><td><span style="cursor:pointer;color:var(--accent-cyan)" onclick="_openDetailForSearch(\'VNet\',\''+esc(fnVnet)+'\')">'+esc(fnVnet)+'</span></td></tr>';
      h+='<tr><td>Subnet</td><td><span style="cursor:pointer;color:var(--accent-cyan)" onclick="_openDetailForSearch(\'Subnet\',\''+esc(funcVnetSubnet)+'\');_zoomToElement(\''+esc(funcVnetSubnet)+'\')">'+esc(funcVnetSubnet)+'</span></td></tr>';
    }
    h+='</table></div></div>';
  } else if(type==='NSG'){
    const sg=(_rlCtx.nsgs||[]).find(s=>s.id===id||s.name===id);
    if(!sg) return;
    const sgVnetId=_nsgVnetId(sg);
    dpTitle.innerHTML=backBtn+_dpTypeBadge('NSG')+_escHtml(sg.name||sg.id);
    dpSub.innerHTML='<span class="copyable" data-copy="'+esc(id)+'">'+esc(id)+'</span> &middot; '+esc(sgVnetId||'');
    h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Overview</span><span class="dp-sec-arr">&#9660;</span></div><div class="dp-sec-body">';
    h+='<table class="dp-kv"><tr><td>Description</td><td>'+esc(sg.properties&&sg.properties.description||'—')+'</td></tr>';
    h+='<tr><td>VNet</td><td><span style="cursor:pointer;color:var(--accent-cyan)" onclick="_openDetailForSearch(\'VNet\',\''+esc(sgVnetId)+'\')">'+esc(sgVnetId||'—')+'</span></td></tr></table></div></div>';
    const allRules=sg.properties&&sg.properties.securityRules||[];
    const inRules=allRules.filter(r=>r.properties&&r.properties.direction==='Inbound');
    const outRules=allRules.filter(r=>r.properties&&r.properties.direction==='Outbound');
    if(inRules.length){
      h+='<div class="dp-section"><div class="dp-sec-hdr" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Inbound Rules</span><span><span class="dp-sec-count">'+inRules.length+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body"><table class="dp-tbl"><tr><th>Priority</th><th>Access</th><th>Proto</th><th>Port</th><th>Source</th><th>Destination</th></tr>';
      inRules.sort((a,b)=>(a.properties.priority||0)-(b.properties.priority||0)).forEach(r=>{
        const p=r.properties||{};
        h+='<tr><td>'+esc(p.priority||'—')+'</td><td>'+esc(p.access||'—')+'</td><td>'+esc(p.protocol||'*')+'</td><td>'+esc(p.destinationPortRange||p.destinationPortRanges&&p.destinationPortRanges.join(',')||'*')+'</td><td>'+esc(p.sourceAddressPrefix||p.sourceAddressPrefixes&&p.sourceAddressPrefixes.join(',')||'*')+'</td><td>'+esc(p.destinationAddressPrefix||'*')+'</td></tr>';
      });
      h+='</table></div></div>';
    }
    if(outRules.length){
      h+='<div class="dp-section"><div class="dp-sec-hdr collapsed" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">Outbound Rules</span><span><span class="dp-sec-count">'+outRules.length+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body hidden"><table class="dp-tbl"><tr><th>Priority</th><th>Access</th><th>Proto</th><th>Port</th><th>Source</th><th>Destination</th></tr>';
      outRules.sort((a,b)=>(a.properties.priority||0)-(b.properties.priority||0)).forEach(r=>{
        const p=r.properties||{};
        h+='<tr><td>'+esc(p.priority||'—')+'</td><td>'+esc(p.access||'—')+'</td><td>'+esc(p.protocol||'*')+'</td><td>'+esc(p.destinationPortRange||p.destinationPortRanges&&p.destinationPortRanges.join(',')||'*')+'</td><td>'+esc(p.sourceAddressPrefix||p.sourceAddressPrefixes&&p.sourceAddressPrefixes.join(',')||'*')+'</td><td>'+esc(p.destinationAddressPrefix||'*')+'</td></tr>';
      });
      h+='</table></div></div>';
    }
  } else if(type==='Note'){
    // For notes, just zoom — no extra panel
    return;
  } else {
    return; // Unknown type, no panel
  }
  dpBody.innerHTML=h;
  dp.classList.add('open');
  _wireDpBackButton();
  applyDpScale();
}

// === TIME-SERIES SNAPSHOTS ===
const _SNAP_KEY='azureMapper_snapshots';
const _MAX_SNAPSHOTS=30;
let _snapshots=[];
let _viewingHistory=false;
let _currentSnapshot=null;// saved current state when viewing history
// TODO: deduplicate — canonical snapshot/timeline logic is in timeline.js
try{const s=localStorage.getItem(_SNAP_KEY);if(s)_snapshots=JSON.parse(s)}catch(e){_snapshots=[]}
function _saveSnapshots(){try{localStorage.setItem(_SNAP_KEY,JSON.stringify(_snapshots))}catch(e){
  // If storage full, trim oldest half
  if(_snapshots.length>4){_snapshots=_snapshots.slice(Math.floor(_snapshots.length/2));try{localStorage.setItem(_SNAP_KEY,JSON.stringify(_snapshots))}catch(e2){}}
}}
function _computeChecksum(textareas){
  let s='';Object.keys(textareas).sort().forEach(k=>s+=k+':'+String(textareas[k]).length+';');
  let h=0;for(let i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0}return h;
}
function takeSnapshot(label,auto){
  const textareas={};
  document.querySelectorAll('.ji').forEach(el=>{const v=el.value.trim();if(v)textareas[el.id]=v});
  if(!Object.keys(textareas).length)return null;
  const checksum=_computeChecksum(textareas);
  // Skip if identical to last snapshot
  if(_snapshots.length>0&&_snapshots[_snapshots.length-1].checksum===checksum)return null;
  const snap={
    id:'snap-'+Date.now(),
    timestamp:new Date().toISOString(),
    label:label||(auto?'Auto':'Manual'),
    auto:!!auto,
    checksum:checksum,
    accountLabel:(document.getElementById('accountLabel')||{}).value||'',
    layout:(document.getElementById('layoutMode')||{}).value||'grid',
    textareas:textareas,
    annotations:JSON.parse(JSON.stringify(_annotations||{}))
  };
  _snapshots.push(snap);
  while(_snapshots.length>_MAX_SNAPSHOTS)_snapshots.shift();
  _saveSnapshots();
  _renderTimeline();
  if(!auto)_showToast('Snapshot saved: '+(label||'Manual'));
  return snap;
}
function _renderTimeline(){
  const container=document.getElementById('timelineDots');if(!container)return;
  container.innerHTML='';
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
  if(!_viewingHistory){
    // Save current state
    _currentSnapshot={};
    document.querySelectorAll('.ji').forEach(el=>{_currentSnapshot[el.id]=el.value});
    _currentSnapshot._accountLabel=(document.getElementById('accountLabel')||{}).value||'';
    _currentSnapshot._layout=(document.getElementById('layoutMode')||{}).value||'grid';
    _currentSnapshot._annotations=JSON.parse(JSON.stringify(_annotations||{}));
  }
  _viewingHistory=true;
  // Load snapshot data
  document.querySelectorAll('.ji').forEach(el=>{el.value='';el.className='ji'});
  Object.entries(snap.textareas||{}).forEach(([id,val])=>{
    const el=document.getElementById(id);
    if(el){el.value=val;try{JSON.parse(val);el.className='ji valid'}catch(e){el.className='ji invalid'}}
  });
  if(snap.accountLabel){const al=document.getElementById('accountLabel');if(al)al.value=snap.accountLabel}
  if(snap.annotations)_annotations=JSON.parse(JSON.stringify(snap.annotations));
  renderMap();
  // Show history banner
  const d=new Date(snap.timestamp);
  document.getElementById('historyLabel').textContent='VIEWING: '+snap.label+' - '+d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  document.getElementById('historyBanner').style.display='flex';
  // Highlight active dot
  document.querySelectorAll('.timeline-dot').forEach((d,i)=>d.classList.toggle('active',i===idx));
  // Disable inputs
  document.querySelectorAll('.ji').forEach(el=>el.readOnly=true);
}
function _returnToCurrent(){
  if(!_viewingHistory||!_currentSnapshot)return;
  _viewingHistory=false;
  document.querySelectorAll('.ji').forEach(el=>{
    el.value=_currentSnapshot[el.id]||'';
    el.readOnly=false;
    if(el.value.trim()){try{JSON.parse(el.value);el.className='ji valid'}catch(e){el.className='ji invalid'}}else{el.className='ji'}
  });
  if(_currentSnapshot._accountLabel){const al=document.getElementById('accountLabel');if(al)al.value=_currentSnapshot._accountLabel}
  if(_currentSnapshot._annotations)_annotations=JSON.parse(JSON.stringify(_currentSnapshot._annotations));
  document.getElementById('historyBanner').style.display='none';
  document.querySelectorAll('.timeline-dot').forEach(d=>d.classList.remove('active'));
  _currentSnapshot=null;
  renderMap();
}
function _restoreSnapshot(){
  if(!_viewingHistory)return;
  _viewingHistory=false;
  _currentSnapshot=null;
  document.getElementById('historyBanner').style.display='none';
  document.querySelectorAll('.ji').forEach(el=>el.readOnly=false);
  document.querySelectorAll('.timeline-dot').forEach(d=>d.classList.remove('active'));
  _showToast('Snapshot restored as current state');
  renderMap();
}
function openTimeline(){document.getElementById('timelineBar').classList.add('open');_renderTimeline()}
function closeTimeline(){document.getElementById('timelineBar').classList.remove('open')}
// Auto-snapshot on render (with 2-min minimum interval)
let _lastAutoSnap=0;
const _origRenderMap=typeof renderMap==='function'?null:null;// renderMap defined elsewhere, hook via event
// Hook: take auto-snapshot after successful render
// We add this at the end of the stats bar rendering
