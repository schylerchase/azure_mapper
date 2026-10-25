// #region DIFF MODE
// === DIFF / CHANGE DETECTION ===
let _diffMode=false;
let _diffBaseline=null;
let _diffResults=null;
let _diffFilter='all'; // 'all'|'changes'
let _diffDashState={catFilter:'all',typeFilter:'all',vnetFilter:'all',kindFilter:'all',search:'',sort:'status',sortDir:'asc',page:1,perPage:50};
let _diffFlatRows=null; // [{category,type,key,name,vnetId,vnetName,fields,hasStructural,resource,baseline}]

function diffRuntimeContext(){
  var contextFactory = typeof AppRenderContext !== 'undefined' ? AppRenderContext : null;
  return contextFactory ? contextFactory.createRenderContext() : null;
}

function diffRuntimeData(){
  var ctx = diffRuntimeContext();
  return ctx ? ctx.rlCtx : null;
}

function diffMapGroup(){
  var ctx = diffRuntimeContext();
  return ctx ? ctx.mapG : null;
}

function diffNotify(message, type){
  var notifications = typeof AppNotifications !== 'undefined' ? AppNotifications : null;
  if(notifications && typeof notifications.show === 'function') notifications.show(message, type);
}

function diffDownload(blob, name){
  var downloads = typeof AppDownloads !== 'undefined' ? AppDownloads : null;
  if(downloads && typeof downloads.saveBlob === 'function') return downloads.saveBlob(blob, name);
}

function diffZoomToResource(resourceId){
  if(typeof ResourceNavigation !== 'undefined' && ResourceNavigation.zoomToResource){
    return ResourceNavigation.zoomToResource(resourceId);
  }
}

function diffEsc(value){
  var html = typeof AppHtml !== 'undefined' ? AppHtml : null;
  if(html && typeof html.escape === 'function') return html.escape(value);
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function _diffKeyToSelector(type,key){
  // Map resource types to their SVG data attributes
  if(type==='vnets'||type==='vpcs') return '[data-vnet-id="'+key+'"]';
  if(type==='subnets') return '[data-subnet-id="'+key+'"]';
  return '[data-gwid="'+key+'"],[data-id="'+key+'"]';
}

function enterDiffMode(baselineData){
  var runtimeData=diffRuntimeData();
  if(!runtimeData){diffNotify('Render a map first before comparing');return}
  var ctx=diffNormalizeSnapshot(runtimeData);
  let baseCtx=null;
  // Parse baseline - could be an azuremap project file or raw rlCtx
  if(baselineData._format==='azuremap'&&baselineData.textareas){
    // Re-parse textarea data to build an rlCtx-like object
    baseCtx=diffNormalizeSnapshot(_buildCtxFromTextareas(baselineData.textareas));
  } else if(baselineData.vnets||baselineData.vpcs||baselineData.subnets){
    baseCtx=diffNormalizeSnapshot(baselineData);
  } else {
    diffNotify('Unable to parse baseline data');return;
  }
  _diffBaseline=baseCtx;
  _diffBaseline._srcName=baselineData._srcName||baselineData.accountLabel||'baseline';
  _diffResults=computeDiff(baseCtx,ctx);
  _diffMode=true;
  _diffFilter='all';
  // Show banner
  const banner=document.getElementById('diffBanner');
  banner.style.display='flex';
  _getMain().classList.add('diff-active');
  const srcName=baselineData.accountLabel||baselineData._srcName||'baseline';
  document.getElementById('diffLabel').textContent='COMPARING: '+srcName+' vs current';
  document.getElementById('diffAdded').textContent='+'+_diffResults.total.added+' added';
  document.getElementById('diffRemoved').textContent='-'+_diffResults.total.removed+' removed';
  document.getElementById('diffModified').textContent='~'+_diffResults.total.modified+' modified';
  document.getElementById('diffToggleFilter').textContent='Changes Only';
  _applyDiffOverlay();
  // Open the compare dashboard
  _openDiffDash();
  diffNotify('Diff mode: '+(_diffResults.total.added+_diffResults.total.removed+_diffResults.total.modified)+' changes detected');
}

function exitDiffMode(){
  _diffMode=false;
  _diffBaseline=null;
  _diffResults=null;
  _diffFlatRows=null;
  _diffFilter='all';
  document.getElementById('diffBanner').style.display='none';
  _getMain().classList.remove('diff-active');
  document.getElementById('diffSummary').classList.remove('open');
  _closeDiffDash();
  // Remove all diff overlay classes
  var mapG=diffMapGroup();
  if(mapG&&mapG.node()){
    mapG.selectAll('.diff-added,.diff-removed,.diff-modified,.diff-unchanged').each(function(){
      d3.select(this).classed('diff-added',false).classed('diff-removed',false).classed('diff-modified',false).classed('diff-unchanged',false);
    });
  }
  // Remove injected ghost elements
  if(mapG&&mapG.node()){
    mapG.selectAll('.diff-ghost').remove();
  }
}

function _applyDiffOverlay(){
  var mapG=diffMapGroup();
  if(!_diffMode||!_diffResults||!mapG||!mapG.node()) return;
  const g=mapG.node();
  // Clear previous diff classes
  mapG.selectAll('.diff-added,.diff-removed,.diff-modified,.diff-unchanged,.diff-ghost').each(function(){
    d3.select(this).classed('diff-added',false).classed('diff-removed',false).classed('diff-modified',false).classed('diff-unchanged',false);
  });
  mapG.selectAll('.diff-ghost').remove();

  // Apply added overlay
  _diffResults.added.forEach(item=>{
    const sel=_diffKeyToSelector(item.type,item.key);
    const els=g.querySelectorAll(sel);
    els.forEach(el=>d3.select(el).classed('diff-added',true));
  });
  // Apply modified overlay
  _diffResults.modified.forEach(item=>{
    const sel=_diffKeyToSelector(item.type,item.key);
    const els=g.querySelectorAll(sel);
    els.forEach(el=>d3.select(el).classed('diff-modified',true));
  });
  // Apply unchanged overlay when filter is 'changes'
  if(_diffFilter==='changes'){
    _diffResults.unchanged.forEach(item=>{
      const sel=_diffKeyToSelector(item.type,item.key);
      const els=g.querySelectorAll(sel);
      els.forEach(el=>d3.select(el).classed('diff-unchanged',true));
    });
  }
  // For removed resources, try to find them: if not rendered, add ghost markers
  _diffResults.removed.forEach(item=>{
    const sel=_diffKeyToSelector(item.type,item.key);
    const els=g.querySelectorAll(sel);
    if(els.length){
      els.forEach(el=>d3.select(el).classed('diff-removed',true));
    }
  });
}

function _diffFmtVal(v){
  if(v===undefined) return '∅';
  if(v===null) return 'null';
  if(typeof v==='boolean') return v?'true':'false';
  if(typeof v==='number') return String(v);
  if(typeof v==='string') return v.length>40?v.slice(0,37)+'...':v;
  if(Array.isArray(v)){
    if(!v.length) return '[]';
    var s=diffJson(v);
    return s.length>50?'['+v.length+' items]':s;
  }
  var s=diffJson(v);
  return s.length>50?'{...}':s;
}

function _diffFmtValFull(v){
  if(v===undefined) return '∅';
  if(v===null) return 'null';
  if(typeof v==='boolean') return v?'true':'false';
  if(typeof v==='number') return String(v);
  if(typeof v==='string') return v;
  if(Array.isArray(v)) return diffJson(v,1);
  return diffJson(v,1);
}

// Type-aware property renderer for diff detail panel
// All values are escaped via esc() before insertion: safe for display
function _diffPropsHtml(type,res){
  if(!res) return '';
  var h='';
  function kv(label,val){
    if(val===undefined||val===null||val==='') return;
    h+='<div class="dp-kv"><span class="k">'+esc(label)+'</span><span class="v">'+esc(String(val))+'</span></div>';
  }
  function tags(r){
    var t=r.Tags||r.TagSet||[];
    if(!t.length) return;
    var th=t.map(function(tg){return '<span style="background:rgba(139,92,246,.15);border:1px solid rgba(139,92,246,.3);padding:1px 5px;border-radius:3px;margin:1px;color:#c4b5fd">'+esc(tg.Key)+'<span style="color:#a78bfa">=</span>'+esc(tg.Value)+'</span>'}).join(' ');
    h+='<div style="margin-top:6px;font-size:calc(9px * var(--txt-scale,1) * var(--dp-txt-scale,1));color:var(--text-muted);display:flex;flex-wrap:wrap;gap:2px;align-items:center"><span style="margin-right:4px;font-weight:600">Tags:</span> '+th+'</div>';
  }
  switch(type){
    case 'vnets':
    case 'vpcs':
      kv('VNet ID',res.id||res.VpcId);kv('CIDR Block',res.CidrBlock||(res.addressSpace&&res.addressSpace.addressPrefixes?res.addressSpace.addressPrefixes.join(', '):''));
      kv('Location',res.location);kv('State',res.provisioningState||res.State);kv('Is Default',res.IsDefault);
      kv('Tenancy',res.InstanceTenancy);
      kv('DHCP Options',res.DhcpOptionsId);
      if(res.CidrBlockAssociationSet){
        var cidrs=res.CidrBlockAssociationSet.map(function(c){return c.CidrBlock}).join(', ');
        kv('All CIDRs',cidrs);
      }
      tags(res);break;
    case 'subnets':
      kv('Subnet ID',res.SubnetId);kv('CIDR Block',res.CidrBlock);
      kv('VNet',res.VpcId);kv('Availability Zone',res.AvailabilityZone);
      kv('Available IPs',res.AvailableIpAddressCount);
      kv('Auto-assign Public IP',res.MapPublicIpOnLaunch);
      kv('Default For AZ',res.DefaultForAz);
      tags(res);break;
    case 'vms':
    case 'instances':
      kv('VM ID',res.id||res.InstanceId);kv('Type',res.InstanceType||(res.hardwareProfile&&res.hardwareProfile.vmSize));
      kv('State',res.powerState||(res.State?res.State.Name:'?'));
      kv('Private IP',res.PrivateIpAddress);kv('Public IP',res.PublicIpAddress);
      kv('AZ',res.Placement?res.Placement.AvailabilityZone:'');
      kv('AMI',res.ImageId);kv('Key Name',res.KeyName);
      kv('Subnet',res.SubnetId);kv('VNet',res.VpcId);
      if(res.IamInstanceProfile) kv('IAM Role',res.IamInstanceProfile.Arn||res.IamInstanceProfile.Id);
      var sgs=(res.SecurityGroups||[]).map(function(s){return s.GroupName||s.GroupId}).join(', ');
      if(sgs) kv('Security Groups',sgs);
      tags(res);break;
    case 'nsgs':
    case 'sgs':
      kv('NSG ID',res.id||res.GroupId);kv('NSG Name',res.name||res.GroupName);
      kv('Description',res.Description);kv('VNet',res.VpcId);
      kv('Inbound Rules',(res.IpPermissions||[]).length);
      kv('Outbound Rules',(res.IpPermissionsEgress||[]).length);
      if(res.IpPermissions&&res.IpPermissions.length){
        h+='<div style="margin-top:6px;font-size:calc(9px * var(--txt-scale,1) * var(--dp-txt-scale,1));font-weight:600;color:var(--accent-cyan);text-transform:uppercase;letter-spacing:.5px">Inbound Rules</div>';
        res.IpPermissions.forEach(function(p){
          var proto=p.IpProtocol==='-1'?'All':p.IpProtocol;
          var port=p.FromPort===p.ToPort?(p.FromPort||'All'):((p.FromPort||0)+'-'+(p.ToPort||0));
          var src=(p.IpRanges||[]).map(function(r){return r.CidrIp}).concat((p.UserIdGroupPairs||[]).map(function(g){return g.GroupId})).join(', ')||'N/A';
          h+='<div class="dp-row" style="border-left:3px solid var(--accent-green);padding-left:8px;margin:2px 0;font-size:calc(9px * var(--txt-scale,1) * var(--dp-txt-scale,1))"><span class="a">'+esc(proto)+':'+esc(String(port))+'</span> ← '+esc(src)+'</div>';
        });
      }
      tags(res);break;
    case 'udrs':
    case 'rts':
      kv('Route Table ID',res.id||res.RouteTableId);kv('VNet',res.VpcId);
      kv('Routes',(res.Routes||[]).length);
      kv('Associations',(res.Associations||[]).length);
      if(res.Routes&&res.Routes.length){
        h+='<div style="margin-top:6px;font-size:calc(9px * var(--txt-scale,1) * var(--dp-txt-scale,1));font-weight:600;color:var(--accent-cyan);text-transform:uppercase;letter-spacing:.5px">Routes</div>';
        res.Routes.forEach(function(r){
          var dest=r.DestinationCidrBlock||r.DestinationPrefixListId||'?';
          var tgt=r.GatewayId||r.NatGatewayId||r.VpcPeeringConnectionId||r.NetworkInterfaceId||r.TransitGatewayId||'local';
          h+='<div class="dp-row" style="border-left:3px solid var(--accent-blue);padding-left:8px;margin:2px 0;font-size:calc(9px * var(--txt-scale,1) * var(--dp-txt-scale,1))">'+esc(dest)+' → '+esc(tgt)+' <span class="k">'+esc(r.State||'')+'</span></div>';
        });
      }
      tags(res);break;
    case 'nacls':
      kv('NACL ID',res.NetworkAclId);kv('VNet',res.VpcId);
      kv('Is Default',res.IsDefault);
      var inbound=(res.Entries||[]).filter(function(e){return !e.Egress});
      var outbound=(res.Entries||[]).filter(function(e){return e.Egress});
      kv('Inbound Entries',inbound.length);kv('Outbound Entries',outbound.length);
      tags(res);break;
    case 'igws':
      kv('IGW ID',res.InternetGatewayId);
      var att=(res.Attachments||[])[0];
      if(att){kv('VNet',att.VpcId);kv('State',att.State);}
      tags(res);break;
    case 'firewalls':
      kv('Firewall ID',res.id);kv('Name',res.name);kv('Location',res.location);kv('State',res.provisioningState);
      tags(res);break;
    case 'bastions':
      kv('Bastion ID',res.id);kv('Name',res.name);kv('Location',res.location);kv('State',res.provisioningState);
      tags(res);break;
    case 'natGateways':
    case 'nats':
      kv('NAT Gateway ID',res.id||res.NatGatewayId);kv('VNet',res.VpcId);
      kv('Subnet',res.SubnetId);kv('State',res.State);
      kv('Connectivity',res.ConnectivityType);
      var eips=(res.NatGatewayAddresses||[]).map(function(a){return a.PublicIp}).filter(Boolean).join(', ');
      if(eips) kv('Elastic IPs',eips);
      tags(res);break;
    case 'privateEndpoints':
    case 'vpces':
      kv('Endpoint ID',res.id||res.VpcEndpointId);kv('VNet',res.VpcId);
      kv('Service',res.ServiceName);kv('Type',res.VpcEndpointType);
      kv('State',res.State);
      tags(res);break;
    case 'appGateways':
    case 'albs':
      kv('Name',res.name||res.LoadBalancerName);kv('Type',res.Type);
      kv('Scheme',res.Scheme);kv('DNS',res.DNSName);
      kv('State',res.State?res.State.Code:'');
      kv('VNet',res.VpcId);
      var azs=(res.AvailabilityZones||[]).map(function(a){return a.ZoneName}).join(', ');
      if(azs) kv('AZs',azs);
      tags(res);break;
    case 'sqlServers':
    case 'rdsInstances':
      kv('SQL Server',res.name||res.DBInstanceIdentifier);kv('Engine',res.Engine+' '+(res.EngineVersion||res.version||''));
      kv('Class',res.DBInstanceClass);kv('Storage',res.AllocatedStorage+'GB '+(res.StorageType||''));
      kv('Multi-AZ',res.MultiAZ);kv('Status',res.DBInstanceStatus);
      kv('AZ',res.AvailabilityZone);
      if(res.Endpoint) kv('Endpoint',res.Endpoint.Address+':'+(res.Endpoint.Port||''));
      kv('VNet',res.DBSubnetGroup?res.DBSubnetGroup.VpcId:'');
      tags(res);break;
    case 'functionApps':
    case 'lambdaFns':
      kv('Function',res.name||res.FunctionName);kv('Runtime',res.Runtime);
      kv('Memory',res.MemorySize+'MB');kv('Timeout',res.Timeout+'s');
      kv('Handler',res.Handler);kv('Code Size',Math.round((res.CodeSize||0)/1024)+'KB');
      kv('Last Modified',res.LastModified);
      if(res.VpcConfig&&res.VpcConfig.VpcId) kv('VNet',res.VpcConfig.VpcId);
      tags(res);break;
    case 'containerInstances':
    case 'ecsServices':
      kv('Container Group',res.name||res.serviceName);kv('Launch Type',res.launchType);
      kv('Desired',res.desiredCount);kv('Running',res.runningCount);
      kv('Task Definition',res.taskDefinition);kv('Status',res.status);
      tags(res);break;
    case 'redisCaches':
    case 'ecacheClusters':
      kv('Redis Cache',res.name||res.CacheClusterId);kv('Engine',res.Engine+' '+(res.EngineVersion||''));
      kv('Node Type',res.CacheNodeType);kv('Nodes',res.NumCacheNodes);
      kv('Status',res.CacheClusterStatus);
      kv('AZ',res.PreferredAvailabilityZone);
      tags(res);break;
    case 'aksCluster':
    case 'redshiftClusters':
      kv('Cluster',res.name||res.ClusterIdentifier);kv('Node Type',res.NodeType);
      kv('Nodes',res.NumberOfNodes);kv('Status',res.ClusterStatus);
      kv('DB Name',res.DBName);kv('VNet',res.VpcId);
      if(res.Endpoint) kv('Endpoint',res.Endpoint.Address+':'+(res.Endpoint.Port||''));
      tags(res);break;
    case 'synapseWorkspaces':
      kv('Workspace',res.name||res.id);kv('Location',res.location);kv('State',res.provisioningState);
      tags(res);break;
    case 'peerings':
      kv('Peering ID',res.id||res.VpcPeeringConnectionId);
      kv('Status',res.Status?res.Status.Code:'');
      if(res.RequesterVpcInfo) kv('Requester VNet',res.RequesterVpcInfo.VpcId+' ('+res.RequesterVpcInfo.CidrBlock+')');
      if(res.AccepterVpcInfo) kv('Accepter VNet',res.AccepterVpcInfo.VpcId+' ('+res.AccepterVpcInfo.CidrBlock+')');
      tags(res);break;
    case 'storageAccounts':
      kv('Storage Account',res.name||res.Name);kv('Location',res.location);kv('Kind',res.kind);kv('Tier',res.sku&&res.sku.name);
      tags(res);break;
    case 'loadBalancers':
      kv('Load Balancer',res.name||res.TargetGroupName);kv('Location',res.location);kv('SKU',res.sku&&res.sku.name);
      tags(res);break;
  }
  return h;
}

function _diffTypeLabel(type){
  var labels={vnets:'VNet',vpcs:'VNet',subnets:'Subnet',vms:'Virtual Machine',instances:'Virtual Machine',
    nsgs:'NSG',sgs:'NSG',udrs:'Route Table (UDR)',rts:'Route Table (UDR)',
    nacls:'NSG Rule',firewalls:'Azure Firewall',bastions:'Bastion',igws:'Internet Gateway',
    natGateways:'NAT Gateway',nats:'NAT Gateway',privateEndpoints:'Private Endpoint',
    vpces:'Private Endpoint',appGateways:'Application Gateway',albs:'Application Gateway',
    sqlServers:'SQL Server',rdsInstances:'SQL Server',functionApps:'Function App',
    lambdaFns:'Function App',containerInstances:'Container Instance',ecsServices:'Container Instance',
    redisCaches:'Redis Cache',ecacheClusters:'Redis Cache',aksCluster:'AKS Cluster',
    redshiftClusters:'AKS Cluster',synapseWorkspaces:'Synapse Workspace',
    peerings:'VNet Peering',storageAccounts:'Storage Account',loadBalancers:'Load Balancer'};
  return labels[type]||type;
}

// Opens the detail panel with full diff information for a resource
// All content is escaped before insertion for safe display
function _openDiffDetail(item,category){
  var dp=document.getElementById('detailPanel');
  var dpTitle=document.getElementById('dpTitle');
  var dpSub=document.getElementById('dpSub');
  var dpBody=document.getElementById('dpBody');
  var badgeCls=category;
  var badgeText=category.toUpperCase();
  var res=item.resource||item.baseline||null;
  var typeLabel=_diffTypeLabel(item.type);
  dpTitle.textContent='';
  dpTitle.appendChild(document.createTextNode(item.name+' '));
  var badge=document.createElement('span');badge.className='dp-diff-badge '+badgeCls;badge.textContent=badgeText;
  dpTitle.appendChild(badge);
  dpSub.textContent='';
  var copySpan=document.createElement('span');copySpan.className='copyable';copySpan.dataset.copy=item.key;copySpan.textContent=item.key;
  dpSub.appendChild(copySpan);dpSub.appendChild(document.createTextNode(' | '+typeLabel));
  var h='';
  function sec(title,count,bodyHtml,startOpen){
    return '<div class="dp-section"><div class="dp-sec-hdr'+(startOpen?'':' collapsed')+'" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">'+esc(title)+'</span><span><span class="dp-sec-count">'+esc(count)+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body'+(startOpen?'':' hidden')+'">'+bodyHtml+'</div></div>';
  }
  // CHANGES section (modified only)
  if(category==='modified'&&item.fields&&item.fields.length){
    var cb='';
    item.fields.forEach(function(f){
      cb+='<div class="dp-diff-change">';
      cb+='<span class="dc-field">'+diffEsc(f.field)+'</span>';
      cb+='<span class="dc-kind '+f.kind+'">'+f.kind+'</span>';
      cb+='<div class="dc-vals">';
      if(typeof f.old==='undefined'){
        cb+='<span class="dc-new">+ '+diffEsc(_diffFmtValFull(f.new))+'</span>';
      } else if(typeof f.new==='undefined'){
        cb+='<span class="dc-old">- '+diffEsc(_diffFmtValFull(f.old))+'</span>';
      } else {
        cb+='<span class="dc-old">'+diffEsc(_diffFmtValFull(f.old))+'</span>';
        cb+='<span class="dc-arrow">→</span>';
        cb+='<span class="dc-new">'+diffEsc(_diffFmtValFull(f.new))+'</span>';
      }
      cb+='</div></div>';
    });
    var structCount=item.fields.filter(function(f){return f.kind==='structural'}).length;
    var metaCount=item.fields.length-structCount;
    var countLabel=item.fields.length+' change'+(item.fields.length>1?'s':'')+' ('+structCount+' structural, '+metaCount+' metadata)';
    h+=sec('Changes',countLabel,cb,true);
  }
  // PROPERTIES section
  if(res){
    var propsHtml=_diffPropsHtml(item.type,res);
    if(propsHtml){
      var propLabel=category==='removed'?'Properties (baseline)':'Properties (current)';
      h+=sec(propLabel,'',propsHtml,category!=='modified');
    }
  }
  // BASELINE PROPERTIES (modified only: show old state)
  if(category==='modified'&&item.baseline){
    var baseProps=_diffPropsHtml(item.type,item.baseline);
    if(baseProps) h+=sec('Baseline Properties','',baseProps,false);
  }
  // RAW JSON section
  if(res){
    var jsonHtml='';
    if(category==='modified'&&item.baseline){
      jsonHtml='<div style="font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1));font-weight:600;color:#ef4444;margin-bottom:2px">BASELINE</div>';
      jsonHtml+='<div class="dp-diff-json" style="max-height:200px;margin-bottom:8px">'+diffEsc(diffJson(item.baseline,2))+'</div>';
      jsonHtml+='<div style="font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1));font-weight:600;color:#10b981;margin-bottom:2px">CURRENT</div>';
      jsonHtml+='<div class="dp-diff-json" style="max-height:200px">'+diffEsc(diffJson(item.resource,2))+'</div>';
    } else {
      jsonHtml='<div class="dp-diff-json">'+diffEsc(diffJson(res,2))+'</div>';
    }
    h+=sec('Raw JSON','',jsonHtml,false);
  }
  dpBody.textContent='';
  dpBody.insertAdjacentHTML('beforeend',h);
  dp.classList.add('open');
  if(typeof applyDpScale==='function') applyDpScale();
  // Copyable elements
  dpBody.querySelectorAll('.copyable').forEach(function(el){
    el.addEventListener('click',function(e){
      e.stopPropagation();navigator.clipboard.writeText(this.dataset.copy);
      var t=document.querySelector('.copy-toast');
      if(t){t.textContent='Copied!';t.classList.add('show');setTimeout(function(){t.classList.remove('show')},1200)}
    });
  });
}

function _renderDiffSummary(){
  // Legacy summary panel: no longer used, dashboard replaces it
  if(!_diffResults) return;
}

function _toggleDiffFilter(){
  if(!_diffMode) return;
  _diffFilter=_diffFilter==='all'?'changes':'all';
  const btn=document.getElementById('diffToggleFilter');
  btn.textContent=_diffFilter==='changes'?'Show All':'Changes Only';
  _applyDiffOverlay();
}

function _exportDiffReport(){
  if(!_diffResults) return;
  const report={
    generated:new Date().toISOString(),
    summary:{added:_diffResults.total.added,removed:_diffResults.total.removed,modified:_diffResults.total.modified,unchanged:_diffResults.total.unchanged},
    added:_diffResults.added.map(i=>({type:i.type,key:i.key,name:i.name})),
    removed:_diffResults.removed.map(i=>({type:i.type,key:i.key,name:i.name})),
    modified:_diffResults.modified.map(i=>({type:i.type,key:i.key,name:i.name,hasStructural:i.hasStructural,fields:i.fields.map(f=>({field:f.field,kind:f.kind}))}))
  };
  const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});
  diffDownload(blob,'diff-report-'+new Date().toISOString().slice(0,10)+'.json');
  diffNotify('Diff report exported');
}

// === COMPARE DASHBOARD ===

function _diffResVnet(item){
  var res=item.resource||item.baseline;
  if(!res) return {id:'',name:''};
  var vid=res.VpcId||res.vnetId||'';
  if(!vid&&res.subnet&&res.subnet.id) vid=res.subnet.id.split('/subnets/')[0]||'';
  if(!vid&&res.id&&res.id.indexOf('/subnets/')!==-1) vid=res.id.split('/subnets/')[0]||'';
  if(!vid&&(item.type==='vnets'||item.type==='vpcs')) vid=res.id||res.VpcId||item.key||'';
  if(!vid) return {id:'',name:''};
  var vn=vid;
  var ctx=diffRuntimeData();
  if(ctx&&ctx.vnets){
    var vnet=ctx.vnets.find(function(v){return (v.id||v.VpcId)===vid});
    if(vnet){
      var tags=vnet.Tags||[];
      var nt=tags.find(function(t){return t.Key==='Name'});
      if(vnet.name) vn=vnet.name;
      else if(nt&&nt.Value) vn=nt.Value;
    }
  }
  return {id:vid,name:vn};
}

function _buildDiffFlatRows(){
  if(!_diffResults) return [];
  var rows=[];
  _diffResults.added.forEach(function(item){
    var vnet=_diffResVnet(item);
    rows.push({category:'added',type:item.type,key:item.key,name:item.name,vnetId:vnet.id,vnetName:vnet.name,fields:[],hasStructural:false,resource:item.resource,baseline:null});
  });
  _diffResults.removed.forEach(function(item){
    var vnet=_diffResVnet(item);
    rows.push({category:'removed',type:item.type,key:item.key,name:item.name,vnetId:vnet.id,vnetName:vnet.name,fields:[],hasStructural:false,resource:null,baseline:item.resource});
  });
  _diffResults.modified.forEach(function(item){
    var vnet=_diffResVnet(item);
    rows.push({category:'modified',type:item.type,key:item.key,name:item.name,vnetId:vnet.id,vnetName:vnet.name,fields:item.fields||[],hasStructural:item.hasStructural,resource:item.resource,baseline:item.baseline});
  });
  _diffResults.unchanged.forEach(function(item){
    var vnet=_diffResVnet(item);
    rows.push({category:'unchanged',type:item.type,key:item.key,name:item.name,vnetId:vnet.id,vnetName:vnet.name,fields:[],hasStructural:false,resource:null,baseline:null});
  });
  return rows;
}

function _openDiffDash(){
  if(!_diffResults) return;
  _diffFlatRows=_buildDiffFlatRows();
  _diffDashState={catFilter:'all',typeFilter:'all',vnetFilter:'all',kindFilter:'all',search:'',sort:'status',sortDir:'asc',page:1,perPage:50};
  // Populate type filter
  var typeSet=new Set();
  _diffFlatRows.forEach(function(r){typeSet.add(r.type)});
  var typeSel=document.getElementById('diffTypeFilter');
  typeSel.innerHTML='<option value="all">All Types</option>';
  Array.from(typeSet).sort().forEach(function(t){
    var opt=document.createElement('option');opt.value=t;opt.textContent=_diffTypeLabel(t);
    typeSel.appendChild(opt);
  });
  // Populate VNet filter
  var vnetMap={};
  _diffFlatRows.forEach(function(r){if(r.vnetId)vnetMap[r.vnetId]=r.vnetName});
  var vnetSel=document.getElementById('diffVpcFilter');
  vnetSel.innerHTML='<option value="all">All VNets</option>';
  Object.keys(vnetMap).sort().forEach(function(vid){
    var opt=document.createElement('option');opt.value=vid;opt.textContent=vnetMap[vid];
    vnetSel.appendChild(opt);
  });
  // Populate snapshot picker
  _populateDiffSnapPicker();
  // Reset controls
  document.getElementById('diffDashSearch').value='';
  document.getElementById('diffKindFilter').value='all';
  document.getElementById('diffPerPage').value='50';
  // Source label
  var srcName=_diffBaseline?(_diffBaseline._srcName||_diffBaseline.accountLabel||'baseline'):'baseline';
  document.getElementById('diffDashLabel').textContent=srcName+' vs current';
  // Open
  _closeAllDashboards('diffDash');
  document.getElementById('diffDash').classList.add('open');
  _renderDiffDash();
}

function _closeDiffDash(){
  document.getElementById('diffDash').classList.remove('open');
}

function _populateDiffSnapPicker(){
  var sel=document.getElementById('diffSnapPicker');
  sel.innerHTML='<option value="">— pick snapshot —</option>';
  _snapshots.forEach(function(snap,i){
    var opt=document.createElement('option');
    opt.value=i;
    var d=new Date(snap.timestamp);
    opt.textContent=(snap.label||snap.accountLabel||'Snap '+(i+1))+': '+d.toLocaleDateString()+' '+d.toLocaleTimeString();
    sel.appendChild(opt);
  });
}

const _CAT_ORDER={added:0,removed:1,modified:2,unchanged:3};

function _renderDiffDash(){
  if(!_diffFlatRows) return;
  var db=document.getElementById('diffDashBody');if(db)db.scrollTop=0;
  var st=_diffDashState;
  // --- Pills ---
  var counts={all:_diffFlatRows.length,added:0,removed:0,modified:0,unchanged:0};
  _diffFlatRows.forEach(function(r){counts[r.category]++});
  var pillBox=document.getElementById('diffDashPills');
  pillBox.textContent='';
  [{cat:'all',label:'All'},{cat:'added',label:'Added'},{cat:'removed',label:'Removed'},{cat:'modified',label:'Modified'},{cat:'unchanged',label:'Unchanged'}].forEach(function(p){
    var pill=document.createElement('span');
    pill.className='diff-cat-pill'+(st.catFilter===p.cat?' active':'');
    pill.dataset.cat=p.cat;
    pill.textContent=p.label+' ('+counts[p.cat]+')';
    pill.addEventListener('click',function(){st.catFilter=p.cat;st.page=1;_renderDiffDash()});
    pillBox.appendChild(pill);
  });
  // --- Filter + Sort (shared with _getDiffFilteredRows) ---
  var filtered=_getDiffFilteredRows();
  // --- Row count ---
  document.getElementById('diffDashRowCount').textContent=filtered.length+' of '+_diffFlatRows.length;
  // --- Paginate ---
  var perPage=st.perPage<=0?filtered.length:st.perPage;
  var totalPages=Math.max(1,Math.ceil(filtered.length/perPage));
  st.page=Math.min(st.page,totalPages);
  var start=(st.page-1)*perPage;
  var pageRows=filtered.slice(start,start+perPage);
  // --- Pagination controls ---
  document.getElementById('diffPageInfo').textContent='Page '+st.page+' of '+totalPages+' ('+filtered.length+' rows)';
  document.getElementById('diffPagePrev').disabled=(st.page<=1);
  document.getElementById('diffPageNext').disabled=(st.page>=totalPages);
  // --- Footer meta ---
  document.getElementById('diffDashMeta').textContent='+'+counts.added+' added  -'+counts.removed+' removed  ~'+counts.modified+' modified  ='+counts.unchanged+' unchanged';
  // --- Build table ---
  var body=document.getElementById('diffDashBody');
  var cols=[{key:'status',label:'Status'},{key:'type',label:'Type'},{key:'name',label:'Name'},{key:'key',label:'Key'},{key:'vnet',label:'VNet'},{key:'changes',label:'Changes'},{key:'actions',label:'Actions',nosort:true}];
  var h='<table class="diff-dash-table"><thead><tr>';
  cols.forEach(function(c){
    var cls='';
    if(!c.nosort&&st.sort===c.key) cls=st.sortDir==='asc'?' dd-sort-asc':' dd-sort-desc';
    h+='<th'+(c.nosort?'':' data-sort-col="'+c.key+'"')+' class="'+cls+'">'+c.label+'</th>';
  });
  h+='</tr></thead><tbody>';
  if(!pageRows.length){
    h+='<tr><td colspan="7" class="dd-no-results">No resources match current filters</td></tr>';
  } else {
    pageRows.forEach(function(row,idx){
      var globalIdx=start+idx;
      var isModified=row.category==='modified'&&row.fields.length>0;
      h+='<tr data-dd-idx="'+globalIdx+'" data-dd-key="'+esc(row.key)+'" data-dd-cat="'+row.category+'">';
      // Status
      h+='<td>';
      if(isModified) h+='<span class="dd-expand-toggle" data-dd-toggle="'+globalIdx+'">▶</span>';
      h+='<span class="dd-status-badge '+row.category+'">'+row.category+'</span></td>';
      // Type
      h+='<td class="dd-type-label">'+esc(_diffTypeLabel(row.type))+'</td>';
      // Name
      h+='<td class="dd-name">'+esc(row.name)+'</td>';
      // Key
      h+='<td class="dd-key">'+esc(row.key)+'</td>';
      // VNet
      h+='<td class="dd-key">'+esc(row.vnetName||'—')+'</td>';
      // Changes
      if(isModified){
        var sc=row.fields.filter(function(f){return f.kind==='structural'}).length;
        var mc=row.fields.length-sc;
        var parts=[];
        if(sc) parts.push('<span class="dd-changes-structural">'+sc+' structural</span>');
        if(mc) parts.push('<span class="dd-changes-meta">'+mc+' metadata</span>');
        h+='<td class="dd-changes">'+parts.join(', ')+'</td>';
      } else {
        h+='<td class="dd-changes" style="color:var(--text-muted)">—</td>';
      }
      // Actions
      h+='<td class="dd-actions">';
      if(row.category!=='unchanged') h+='<button class="dd-jump-btn" data-dd-jump="'+esc(row.key)+'">Jump</button>';
      if(row.category!=='unchanged') h+='<button class="dd-detail-btn" data-dd-detail="'+globalIdx+'">Detail</button>';
      h+='</td></tr>';
      // Expandable row for field diffs
      if(isModified){
        h+='<tr class="dd-expand-row" data-dd-expand="'+globalIdx+'"><td colspan="7" class="dd-expand-cell">';
        row.fields.forEach(function(f){
          var oldVal=_diffFmtVal(f.old);
          var newVal=_diffFmtVal(f.new);
          h+='<div class="diff-field-row '+f.kind+'">';
          h+='<span class="diff-field-name">'+diffEsc(f.field)+'</span>';
          if(typeof f.old==='undefined'){
            h+='<span class="diff-field-added">+ '+diffEsc(newVal)+'</span>';
          } else if(typeof f.new==='undefined'){
            h+='<span class="diff-field-removed">- '+diffEsc(oldVal)+'</span>';
          } else {
            h+='<span class="diff-field-old">'+diffEsc(oldVal)+'</span>';
            h+='<span class="diff-field-arrow">→</span>';
            h+='<span class="diff-field-new">'+diffEsc(newVal)+'</span>';
          }
          h+='</div>';
        });
        h+='</td></tr>';
      }
    });
  }
  h+='</tbody></table>';
  body.innerHTML=h;
  // --- Wire handlers ---
  // Sort headers
  body.querySelectorAll('th[data-sort-col]').forEach(function(th){
    th.addEventListener('click',function(){
      var col=this.dataset.sortCol;
      if(st.sort===col){
        st.sortDir=st.sortDir==='asc'?'desc':'asc';
      } else {
        st.sort=col;st.sortDir='asc';
      }
      st.page=1;
      _renderDiffDash();
    });
  });
  // Expand toggles
  body.querySelectorAll('.dd-expand-toggle').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var idx=this.dataset.ddToggle;
      var expRow=body.querySelector('tr[data-dd-expand="'+idx+'"]');
      var parentRow=this.closest('tr');
      if(expRow){
        expRow.classList.toggle('open');
        this.classList.toggle('open');
        if(parentRow) parentRow.classList.toggle('dd-expanded');
      }
    });
  });
  // Jump buttons
  body.querySelectorAll('.dd-jump-btn').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var key=this.dataset.ddJump;
      if(!key) return;
      document.getElementById('diffDash').classList.remove('open');
      setTimeout(function(){diffZoomToResource(key)},250);
    });
  });
  // Detail buttons
  body.querySelectorAll('.dd-detail-btn').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var idx=parseInt(this.dataset.ddDetail);
      var allFiltered=_getDiffFilteredRows();
      var row=allFiltered[idx];
      if(!row) return;
      // Build item compatible with _openDiffDetail
      var item={type:row.type,key:row.key,name:row.name,fields:row.fields,hasStructural:row.hasStructural,resource:row.resource,baseline:row.baseline};
      document.getElementById('diffDash').classList.remove('open');
      _openDiffDetail(item,row.category);
      setTimeout(function(){diffZoomToResource(row.key)},250);
    });
  });
  // Row click → expand (for modified rows)
  body.querySelectorAll('tbody tr[data-dd-idx]').forEach(function(tr){
    tr.addEventListener('click',function(){
      var toggle=this.querySelector('.dd-expand-toggle');
      if(toggle) toggle.click();
    });
  });
}

function _getDiffFilteredRows(){
  if(!_diffFlatRows) return [];
  var st=_diffDashState;
  var filtered=_diffFlatRows.slice();
  if(st.catFilter!=='all') filtered=filtered.filter(function(r){return r.category===st.catFilter});
  if(st.typeFilter!=='all') filtered=filtered.filter(function(r){return r.type===st.typeFilter});
  if(st.vnetFilter!=='all') filtered=filtered.filter(function(r){return r.vnetId===st.vnetFilter});
  if(st.kindFilter!=='all'){
    filtered=filtered.filter(function(r){
      if(r.category!=='modified') return false;
      if(st.kindFilter==='structural') return r.fields.some(function(f){return f.kind==='structural'});
      if(st.kindFilter==='metadata') return r.fields.some(function(f){return f.kind==='metadata'});
      return true;
    });
  }
  if(st.search){
    var q=st.search.toLowerCase();
    filtered=filtered.filter(function(r){
      return r.name.toLowerCase().indexOf(q)!==-1||r.key.toLowerCase().indexOf(q)!==-1||r.type.toLowerCase().indexOf(q)!==-1||_diffTypeLabel(r.type).toLowerCase().indexOf(q)!==-1||r.vnetName.toLowerCase().indexOf(q)!==-1||r.fields.some(function(f){return f.field.toLowerCase().indexOf(q)!==-1});
    });
  }
  if(st.sort!=='none'){
    filtered.sort(function(a,b){
      var cmp=0;
      if(st.sort==='status') cmp=(_CAT_ORDER[a.category]||9)-(_CAT_ORDER[b.category]||9);
      else if(st.sort==='type') cmp=_diffTypeLabel(a.type).localeCompare(_diffTypeLabel(b.type));
      else if(st.sort==='name') cmp=(a.name||'').localeCompare(b.name||'');
      else if(st.sort==='key') cmp=(a.key||'').localeCompare(b.key||'');
      else if(st.sort==='vnet') cmp=(a.vnetName||'').localeCompare(b.vnetName||'');
      else if(st.sort==='changes') cmp=(a.fields.length||0)-(b.fields.length||0);
      return st.sortDir==='desc'?-cmp:cmp;
    });
  }
  return filtered;
}

async function _exportDiffXlsx(){
  if(!_diffResults) return;
  try{
    var XLSX=await _loadSheetJS();
    var wb=XLSX.utils.book_new();
    // Summary sheet
    var summaryData=[
      ['Compare Report','','',''],
      ['Generated',new Date().toISOString(),'',''],
      ['','','',''],
      ['Category','Count','',''],
      ['Added',_diffResults.total.added,'',''],
      ['Removed',_diffResults.total.removed,'',''],
      ['Modified',_diffResults.total.modified,'',''],
      ['Unchanged',_diffResults.total.unchanged,'',''],
      ['Total',_diffFlatRows?_diffFlatRows.length:0,'','']
    ];
    var ws1=XLSX.utils.aoa_to_sheet(summaryData);
    ws1['!cols']=[{wch:14},{wch:30},{wch:12},{wch:12}];
    // Style header
    if(ws1['A1']) ws1['A1'].s=_xlsxHeaderStyle();
    if(ws1['A4']) ws1['A4'].s=_xlsxHeaderStyle();
    if(ws1['B4']) ws1['B4'].s=_xlsxHeaderStyle();
    XLSX.utils.book_append_sheet(wb,ws1,'Summary');
    // Details sheet: all resources
    var detailRows=[['Status','Type','Name','Key','VNet','Changes','Fields Changed']];
    var rows=_diffFlatRows||_buildDiffFlatRows();
    rows.forEach(function(r){
      var fieldStr='';
      if(r.fields.length){
        fieldStr=r.fields.map(function(f){
          var parts=[f.field+' ('+f.kind+')'];
          if(typeof f.old!=='undefined') parts.push('old: '+_diffFmtVal(f.old));
          if(typeof f.new!=='undefined') parts.push('new: '+_diffFmtVal(f.new));
          return parts.join(' ');
        }).join('\n');
      }
      detailRows.push([r.category.toUpperCase(),_diffTypeLabel(r.type),r.name,r.key,r.vnetName||'',r.fields.length||'',fieldStr]);
    });
    var ws2=XLSX.utils.aoa_to_sheet(detailRows);
    ws2['!cols']=[{wch:12},{wch:18},{wch:28},{wch:28},{wch:20},{wch:10},{wch:60}];
    // Style header row
    var headerCols='ABCDEFG';
    for(let i=0;i<headerCols.length;i++){
      var addr=headerCols[i]+'1';
      if(ws2[addr]) ws2[addr].s=_xlsxHeaderStyle();
    }
    // Color status cells
    var statusColors={ADDED:{fg:'065F46',bg:'D1FAE5'},REMOVED:{fg:'991B1B',bg:'FEE2E2'},MODIFIED:{fg:'92400E',bg:'FEF3C7'},UNCHANGED:{fg:'6B7280',bg:'F3F4F6'}};
    for(let ri=1;ri<detailRows.length;ri++){
      var cellAddr='A'+(ri+1);
      var val=detailRows[ri][0];
      var sc=statusColors[val];
      if(ws2[cellAddr]&&sc){
        ws2[cellAddr].s={font:{bold:true,color:{rgb:sc.fg},name:'Calibri',sz:10},fill:{fgColor:{rgb:sc.bg}},alignment:{horizontal:'center'},border:_xlsxBorder()};
      }
    }
    XLSX.utils.book_append_sheet(wb,ws2,'All Resources');
    // Write
    XLSX.writeFile(wb,'compare-report-'+new Date().toISOString().slice(0,10)+'.xlsx');
    diffNotify('XLSX report exported');
  }catch(e){
    diffNotify('XLSX export failed: '+e.message,'error');
  }
}

// Compare button click -> open file picker
document.getElementById('compareBtn').addEventListener('click',function(){
  if(_diffMode){
    // Toggle dashboard; hold Shift to exit diff mode entirely
    var dash=document.getElementById('diffDash');
    if(dash.classList.contains('open')) dash.classList.remove('open');
    else _openDiffDash();
    return;
  }
  document.getElementById('diffFileInput').click();
});

// File picker -> parse and enter diff mode (supports single .azuremap or multiple .json)
document.getElementById('diffFileInput').addEventListener('change',async function(){
  var files=[].slice.call(this.files);
  if(!files.length) return;
  this.value='';
  // Single .azuremap file: use directly
  if(files.length===1&&/\.azuremap$/i.test(files[0].name)){
    try{
      var text=await files[0].text();
      var data=JSON.parse(text);
      data._srcName=files[0].name.replace(/\.[^.]+$/,'');
      enterDiffMode(data);
    }catch(ex){diffNotify('Failed to parse file: '+ex.message)}
    return;
  }
  // Single JSON that looks like it has multiple keys (pre-bundled export)
  if(files.length===1&&/\.json$/i.test(files[0].name)){
    try{
      var text=await files[0].text();
      var data=JSON.parse(text);
      // Check if it's already a full context.
      if(data.vnets||data.vpcs||data.subnets||data.textareas||data._format==='azuremap'){
        data._srcName=files[0].name.replace(/\.[^.]+$/,'');
        enterDiffMode(data);
        return;
      }
    }catch(ex){/* fall through to multi-file handling */}
  }
  // Multiple JSON files: match each to a textarea slot and build diff context
  var textareas={};
  var matched=0,skipped=[];
  for(let i=0;i<files.length;i++){
    try{
      var text=await files[i].text();
      JSON.parse(text); // validate
      var inputId=matchFile(files[i].name,text);
      if(!inputId){skipped.push(files[i].name);continue}
      textareas[inputId]=text;
      matched++;
    }catch(ex){skipped.push(files[i].name+' (invalid JSON)');continue}
  }
  if(!matched){diffNotify('No recognized Azure JSON files found');return}
  if(skipped.length) diffNotify(matched+' files matched, '+skipped.length+' skipped','info');
  var label=matched+' JSON files';
  if(files.length<=3) label=files.map(function(f){return f.name.replace(/\.json$/i,'')}).join(', ');
  enterDiffMode({_format:'azuremap',textareas:textareas,_srcName:label});
});

// Banner button listeners
document.getElementById('diffExitBtn').addEventListener('click',exitDiffMode);
document.getElementById('diffToggleFilter').addEventListener('click',_toggleDiffFilter);
document.getElementById('diffExportBtn').addEventListener('click',_exportDiffReport);
document.getElementById('diffShowSummary').addEventListener('click',function(){
  _openDiffDash();
});

// === Compare Dashboard event wiring ===
document.getElementById('diffDashClose').addEventListener('click',function(){_closeDiffDash()});
document.getElementById('diffDashSearch').addEventListener('input',function(){_diffDashState.search=this.value;_diffDashState.page=1;_renderDiffDash()});
document.getElementById('diffTypeFilter').addEventListener('change',function(){_diffDashState.typeFilter=this.value;_diffDashState.page=1;_renderDiffDash()});
document.getElementById('diffVpcFilter').addEventListener('change',function(){_diffDashState.vnetFilter=this.value;_diffDashState.page=1;_renderDiffDash()});
document.getElementById('diffKindFilter').addEventListener('change',function(){_diffDashState.kindFilter=this.value;_diffDashState.page=1;_renderDiffDash()});
document.getElementById('diffPerPage').addEventListener('change',function(){_diffDashState.perPage=parseInt(this.value)||50;_diffDashState.page=1;_renderDiffDash()});
document.getElementById('diffPagePrev').addEventListener('click',function(){if(_diffDashState.page>1){_diffDashState.page--;_renderDiffDash()}});
document.getElementById('diffPageNext').addEventListener('click',function(){
  var pp=_diffDashState.perPage<=0?(_diffFlatRows?_diffFlatRows.length:1):_diffDashState.perPage;
  var total=Math.max(1,Math.ceil((_getDiffFilteredRows().length)/pp));
  if(_diffDashState.page<total){_diffDashState.page++;_renderDiffDash()}
});
document.getElementById('diffDashExportJSON').addEventListener('click',_exportDiffReport);
document.getElementById('diffDashExportXLSX').addEventListener('click',_exportDiffXlsx);
document.getElementById('diffDashFileBtn').addEventListener('click',function(){document.getElementById('diffFileInput').click()});
document.getElementById('diffSnapPicker').addEventListener('change',function(){
  var idx=parseInt(this.value);
  if(isNaN(idx)||!_snapshots[idx]) return;
  this.value='';
  var snap=_snapshots[idx];
  var wasOpen=document.getElementById('diffDash').classList.contains('open');
  exitDiffMode();
  _compareWithSnapshot(snap);
  if(wasOpen) _openDiffDash();
});
// Esc to close diff dashboard
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'&&document.getElementById('diffDash').classList.contains('open')){
    _closeDiffDash();
    e.stopPropagation();
    e.preventDefault();
  }
},true);

// Snapshot integration: compare with a snapshot from timeline
function _compareWithSnapshot(snap){
  if(!snap||!snap.textareas) return;
  const data={_format:'azuremap',textareas:snap.textareas,accountLabel:snap.accountLabel||snap.label||'snapshot',_srcName:snap.label||('Snapshot '+new Date(snap.timestamp).toLocaleString())};
  enterDiffMode(data);
}

// #endregion DIFF MODE

