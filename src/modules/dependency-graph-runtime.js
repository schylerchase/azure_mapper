// #region DEPENDENCY GRAPH
// === DEPENDENCY GRAPH / BLAST RADIUS ===
let _depGraph=null;
let _blastActive=false;

function dependencyRuntimeContext(){
  if(typeof AppRenderContext!=='undefined'&&AppRenderContext.createRenderContext){
    return AppRenderContext.createRenderContext();
  }
  return {rlCtx:null,mapG:null};
}

function dependencyRuntimeData(){
  return dependencyRuntimeContext().rlCtx||null;
}

function dependencyMapGroup(){
  return dependencyRuntimeContext().mapG||null;
}

function dependencyNotify(message,type){
  if(typeof AppNotifications!=='undefined'&&AppNotifications.show){
    AppNotifications.show(message,type);
  }
}

function dependencyEsc(value){
  if(typeof AppHtml!=='undefined'&&AppHtml.escape) return AppHtml.escape(value);
  return String(value||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function dependencyAttr(value){
  return String(value||'').replace(/\\/g,'\\\\').replace(/"/g,'\\"');
}

function dependencySelect(element){
  if(typeof d3!=='undefined'&&d3.select) return d3.select(element);
  return null;
}

function dependencyZoomToResource(id){
  if(typeof MapViewport!=='undefined'&&MapViewport.zoomToResource){
    return MapViewport.zoomToResource(id);
  }
  return null;
}

function dependencyFindResource(ctx,id,collections){
  for(let i=0;i<collections.length;i++){
    const spec=collections[i];
    const rows=ctx[spec.name]||[];
    const found=rows.find(function(row){
      return spec.keys.some(function(key){return row&&row[key]===id});
    });
    if(found)return found;
  }
  return null;
}

function dependencyResourceName(resource,id){
  if(!resource)return id;
  const tags=resource.Tags||resource.tags;
  if(Array.isArray(tags)){
    const tag=tags.find(function(t){return t&&t.Key==='Name'});
    if(tag&&tag.Value)return tag.Value;
  }else if(tags&&tags.Name){
    return tags.Name;
  }
  return resource.name||resource.GroupName||resource.DisplayName||
    resource.LoadBalancerName||resource.FunctionName||resource.DBInstanceIdentifier||
    resource.serviceName||resource.CacheClusterId||resource.ClusterIdentifier||id;
}

function dependencyArray(ctx){
  for(let i=1;i<arguments.length;i++){
    const rows=ctx[arguments[i]];
    if(Array.isArray(rows)&&rows.length)return rows;
  }
  return [];
}

function dependencyProps(resource){
  return resource&&resource.properties||{};
}

function dependencyFirstValue(resource,keys){
  for(let i=0;i<keys.length;i++){
    const value=resource&&resource[keys[i]];
    if(value)return value;
  }
  return '';
}

function dependencyResourceId(resource,keys){
  return dependencyFirstValue(resource,keys||['id','name']);
}

function dependencyVnetId(resource){
  const props=dependencyProps(resource);
  if(resource&&resource.VpcId)return resource.VpcId;
  if(props.vnetId)return props.vnetId;
  if(props.virtualNetwork&&props.virtualNetwork.id)return props.virtualNetwork.id;
  if(resource&&resource.id&&resource.id.indexOf('/subnets/')>=0)return resource.id.split('/subnets/')[0];
  return resource&&resource.id||'';
}

function dependencySubnetId(resource){
  return dependencyFirstValue(resource,['SubnetId','id','name']);
}

function dependencyRowsBySubnet(ctx,mapName,subnet){
  const map=ctx[mapName]||{};
  const keys=[subnet&&subnet.SubnetId,subnet&&subnet.id,subnet&&subnet.name].filter(Boolean);
  for(let i=0;i<keys.length;i++){
    if(Array.isArray(map[keys[i]]))return map[keys[i]];
  }
  return [];
}

function buildDependencyGraph(ctx){
  if(!ctx)return {};
  const g={};
  const addEdge=(from,to,rel,strength)=>{if(!g[from])g[from]=[];g[from].push({id:to,rel,strength})};
  const vnets=dependencyArray(ctx,'vnets','vpcs');
  const subnets=ctx.subnets||[];
  const firewalls=dependencyArray(ctx,'firewalls','igws');
  const natGateways=dependencyArray(ctx,'natGateways','nats');
  const privateEndpoints=dependencyArray(ctx,'privateEndpoints','vpces');
  const routeTables=dependencyArray(ctx,'udrs','rts');
  const subnetNsgs=dependencyArray(ctx,'subnetNsgs','nacls');
  const nsgs=dependencyArray(ctx,'nsgs','sgs');
  const vms=dependencyArray(ctx,'vms','instances');
  const sqlServers=dependencyArray(ctx,'sqlServers','rdsInstances');
  const appGateways=dependencyArray(ctx,'appGateways','albs');

  // VNet -> subnets and network controls.
  vnets.forEach(v=>{
    const vnetId=dependencyResourceId(v,['VpcId','id','name']);
    if(!vnetId)return;
    subnets.filter(s=>dependencyVnetId(s)===vnetId).forEach(s=>addEdge(vnetId,dependencySubnetId(s),'contains','hard'));
    firewalls.forEach(ig=>{
      const attached=(ig.Attachments||[]).some(a=>a.VpcId===vnetId)||
        dependencyVnetId(ig)===vnetId;
      if(attached)addEdge(vnetId,dependencyResourceId(ig,['InternetGatewayId','id','name']),'attached','hard');
    });
    natGateways.filter(n=>dependencyVnetId(n)===vnetId).forEach(n=>addEdge(vnetId,dependencyResourceId(n,['NatGatewayId','id','name']),'contains','hard'));
    privateEndpoints.filter(e=>dependencyVnetId(e)===vnetId).forEach(e=>addEdge(vnetId,dependencyResourceId(e,['VpcEndpointId','id','name']),'contains','soft'));
    routeTables.filter(rt=>dependencyVnetId(rt)===vnetId).forEach(rt=>addEdge(vnetId,dependencyResourceId(rt,['RouteTableId','id','name']),'contains','config'));
    subnetNsgs.filter(n=>dependencyVnetId(n)===vnetId).forEach(n=>addEdge(vnetId,dependencyResourceId(n,['NetworkAclId','id','name']),'contains','config'));
    nsgs.filter(sg=>dependencyVnetId(sg)===vnetId).forEach(sg=>addEdge(vnetId,dependencyResourceId(sg,['GroupId','id','name']),'contains','config'));
  });
  // Subnet -> resources (hard)
  (ctx.subnets||[]).forEach(sub=>{
    const subId=dependencySubnetId(sub);
    dependencyRowsBySubnet(ctx,'instBySub',sub).forEach(i=>addEdge(subId,dependencyResourceId(i,['InstanceId','id','name']),'contains','hard'));
    dependencyRowsBySubnet(ctx,'rdsBySub',sub).forEach(r=>addEdge(subId,dependencyResourceId(r,['DBInstanceIdentifier','id','name']),'contains','hard'));
    dependencyRowsBySubnet(ctx,'ecsBySub',sub).forEach(e=>addEdge(subId,dependencyResourceId(e,['serviceName','id','name']),'contains','hard'));
    dependencyRowsBySubnet(ctx,'lambdaBySub',sub).forEach(l=>addEdge(subId,dependencyResourceId(l,['FunctionName','id','name']),'contains','hard'));
    dependencyRowsBySubnet(ctx,'albBySub',sub).forEach(a=>addEdge(subId,dependencyResourceId(a,['LoadBalancerName','id','name']),'contains','hard'));
    const rt=(ctx.subRT||{})[sub.SubnetId]||(ctx.subRT||{})[sub.id];
    if(rt)addEdge(subId,dependencyResourceId(rt,['RouteTableId','id','name']),'associated','config');
    const nacl=(ctx.subNacl||{})[sub.SubnetId]||(ctx.subNacl||{})[sub.id];
    if(nacl)addEdge(subId,dependencyResourceId(nacl,['NetworkAclId','id','name']),'associated','config');
  });
  // VMs -> NSGs and required managed storage.
  vms.forEach(inst=>{
    const vmId=dependencyResourceId(inst,['InstanceId','id','name']);
    (inst.SecurityGroups||[]).forEach(sg=>addEdge(vmId,dependencyResourceId(sg,['GroupId','id','name']),'secured_by','soft'));
    const diskIds=new Set((inst.BlockDeviceMappings||[]).map(b=>b.Ebs&&b.Ebs.VolumeId).filter(Boolean));
    const storage=inst.storageProfile||dependencyProps(inst).storageProfile||{};
    [storage.osDisk,...(storage.dataDisks||[])].filter(Boolean).forEach(d=>{if(d.managedDisk&&d.managedDisk.id)diskIds.add(d.managedDisk.id)});
    const disks=dependencyArray(ctx,'managedDisks','volumes','disks');
    const mapped=ctx.volByInst instanceof Map?ctx.volByInst.get(vmId):(ctx.volByInst||{})[vmId];
    (mapped||[]).concat(disks.filter(d=>{
      const props=dependencyProps(d);
      return String(d.managedBy||props.managedBy||'').toLowerCase()===String(vmId).toLowerCase()||
        (d.Attachments||[]).some(a=>String(a.InstanceId).toLowerCase()===String(vmId).toLowerCase());
    })).forEach(d=>{const id=dependencyResourceId(d,['VolumeId','id']);if(id)diskIds.add(id)});
    const attached=new Set();
    diskIds.forEach(id=>{
      const disk=disks.find(d=>String(dependencyResourceId(d,['VolumeId','id'])).toLowerCase()===String(id).toLowerCase());
      const canonical=disk?dependencyResourceId(disk,['VolumeId','id']):id;
      if(attached.has(canonical))return;
      attached.add(canonical);
      addEdge(vmId,canonical,'attached','hard');
      addEdge(canonical,vmId,'attached_to','hard');
    });
  });
  // RDS -> SGs
  sqlServers.forEach(db=>{
    const dbId=dependencyResourceId(db,['DBInstanceIdentifier','id','name']);
    (db.VpcSecurityGroups||[]).forEach(sg=>addEdge(dbId,sg.VpcSecurityGroupId,'secured_by','soft'));
  });
  // ALB -> SGs + target groups
  appGateways.forEach(alb=>{
    const albId=dependencyResourceId(alb,['LoadBalancerName','id','name']);
    (alb.SecurityGroups||[]).forEach(gid=>addEdge(albId,gid,'secured_by','soft'));
    const tgs=(ctx.tgByAlb||{})[alb.LoadBalancerArn]||[];
    tgs.forEach(tg=>{addEdge(albId,tg.TargetGroupName||tg.TargetGroupArn,'targets','soft')});
  });
  // SG -> SG references (config)
  nsgs.forEach(sg=>{
    const sgId=dependencyResourceId(sg,['GroupId','id','name']);
    const azureRules=(dependencyProps(sg).securityRules||sg.securityRules||[]).map(function(rule){return dependencyProps(rule)});
    [...(sg.IpPermissions||[]),...(sg.IpPermissionsEgress||[])].forEach(p=>{
      (p.UserIdGroupPairs||[]).forEach(pair=>{
        if(pair.GroupId&&pair.GroupId!==sgId)addEdge(sgId,pair.GroupId,'references','config');
      });
    });
    azureRules.forEach(function(rule){
      [rule.sourceAddressPrefix,rule.destinationAddressPrefix].forEach(function(ref){
        if(ref&&String(ref).indexOf('/subscriptions/')===0&&ref!==sgId)addEdge(sgId,ref,'references','config');
      });
    });
  });
  // Route table -> gateways (config)
  routeTables.forEach(rt=>{
    const rtId=dependencyResourceId(rt,['RouteTableId','id','name']);
    const routes=(rt.Routes||[]).concat(dependencyProps(rt).routes||rt.routes||[]);
    routes.forEach(r=>{
      const props=dependencyProps(r);
      if(r.GatewayId&&r.GatewayId!=='local')addEdge(rtId,r.GatewayId,'routes_through','config');
      if(r.NatGatewayId)addEdge(rtId,r.NatGatewayId,'routes_through','config');
      if(r.TransitGatewayId)addEdge(rtId,r.TransitGatewayId,'routes_through','config');
      if(r.VpcPeeringConnectionId)addEdge(rtId,r.VpcPeeringConnectionId,'routes_through','config');
      if(props.nextHopIpAddress&&props.nextHopType==='VirtualAppliance')addEdge(rtId,props.nextHopIpAddress,'routes_through','config');
    });
  });
  // Peering -> VNets (soft)
  (ctx.peerings||[]).forEach(p=>{
    const pId=dependencyResourceId(p,['VpcPeeringConnectionId','id','name']);
    const props=dependencyProps(p);
    if(p.RequesterVpcInfo)addEdge(pId,p.RequesterVpcInfo.VpcId,'connects','soft');
    if(p.AccepterVpcInfo)addEdge(pId,p.AccepterVpcInfo.VpcId,'connects','soft');
    if(props.localVnetId)addEdge(pId,props.localVnetId,'connects','soft');
    if(props.remoteVnetId)addEdge(pId,props.remoteVnetId,'connects','soft');
  });
  return g;
}
function getBlastRadius(resourceId,graph,maxDepth){
  maxDepth=maxDepth||5;
  const result={hard:[],soft:[],config:[],all:[]};
  const visited=new Set([resourceId]);
  const queue=[{id:resourceId,depth:0}];
  while(queue.length){
    const{id,depth}=queue.shift();
    if(depth>=maxDepth)continue;
    const edges=graph[id]||[];
    edges.forEach(e=>{
      if(visited.has(e.id))return;
      visited.add(e.id);
      const entry={id:e.id,rel:e.rel,strength:e.strength,depth:depth+1,parent:id};
      result[e.strength]=(result[e.strength]||[]);result[e.strength].push(entry);
      result.all.push(entry);
      queue.push({id:e.id,depth:depth+1});
    });
  }
  return result;
}
function _getResType(id){
  if(!id)return'Unknown';
  const ctx=dependencyRuntimeData();
  if(id.startsWith('vpc-'))return'VNet';if(id.startsWith('subnet-'))return'Subnet';
  if(id.startsWith('i-'))return'VM';if(id.startsWith('igw-'))return'Firewall';
  if(id.startsWith('nat-'))return'NAT';if(id.startsWith('vpce-'))return'VPCE';
  if(id.startsWith('sg-'))return'SG';if(id.startsWith('rtb-'))return'RT';
  if(id.startsWith('acl-'))return'Subnet NSG';if(id.startsWith('vol-'))return'Disk';
  if(id.startsWith('pcx-'))return'Peering';if(id.startsWith('tgw-'))return'TGW';
  if(id.startsWith('arn:'))return'ARN';
  if(ctx){
    if((ctx.sqlServers||[]).some(r=>r.DBInstanceIdentifier===id||r.id===id))return'SQL';
    if((ctx.functionApps||[]).some(f=>f.FunctionName===id||f.id===id))return'FuncApp';
    if((ctx.containerInstances||[]).some(e=>e.serviceName===id||e.id===id))return'Container';
    if((ctx.appGateways||[]).some(a=>a.LoadBalancerName===id||a.id===id))return'ALB';
    if((ctx.redisCaches||[]).some(c=>c.CacheClusterId===id||c.id===id))return'ElastiCache';
    if((ctx.synapseWorkspaces||[]).some(c=>c.ClusterIdentifier===id||c.id===id))return'Redshift';
  }
  return'Resource';
}
function _getResName(id){
  const ctx=dependencyRuntimeData();
  if(!ctx)return id;
  return dependencyResourceName(dependencyFindResource(ctx,id,[
    {name:'vnets',keys:['VpcId','id','name']},
    {name:'vpcs',keys:['VpcId','id','name']},
    {name:'subnets',keys:['SubnetId','id','name']},
    {name:'vms',keys:['InstanceId','id','name']},
    {name:'instances',keys:['InstanceId','id','name']},
    {name:'nsgs',keys:['GroupId','id','name']},
    {name:'sgs',keys:['GroupId','id','name']},
    {name:'sqlServers',keys:['DBInstanceIdentifier','id','name']},
    {name:'functionApps',keys:['FunctionName','id','name']},
    {name:'containerInstances',keys:['serviceName','id','name']},
    {name:'appGateways',keys:['LoadBalancerName','id','name']},
    {name:'redisCaches',keys:['CacheClusterId','id','name']},
    {name:'synapseWorkspaces',keys:['ClusterIdentifier','id','name']}
  ]),id);
}
function showDependencies(resourceId){
  const ctx=dependencyRuntimeData();
  if(!ctx)return;
  if(!_depGraph)_depGraph=buildDependencyGraph(ctx);
  const blast=getBlastRadius(resourceId,_depGraph);
  const resName=_getResName(resourceId);const resType=_getResType(resourceId);
  document.getElementById('depTitle').textContent='Dependencies: '+resType+' '+resName;
  const body=document.getElementById('depBody');
  let h='<div class="dep-summary">';
  h+='<div class="dep-stat dep-hard"><b>'+blast.hard.length+'</b><span>Hard (destroyed)</span></div>';
  h+='<div class="dep-stat dep-soft"><b>'+blast.soft.length+'</b><span>Soft (degraded)</span></div>';
  h+='<div class="dep-stat dep-config"><b>'+blast.config.length+'</b><span>Config (dangling)</span></div>';
  h+='<div class="dep-stat"><b>'+blast.all.length+'</b><span>Total affected</span></div>';
  h+='</div>';
  // Group by depth
  const byDepth={};blast.all.forEach(e=>{(byDepth[e.depth]=byDepth[e.depth]||[]).push(e)});
  h+='<div class="dep-tree">';
  h+='<div class="dep-node dep-depth-0" style="border-left-color:var(--accent-cyan);font-weight:600"><span class="dep-type">'+dependencyEsc(resType)+'</span>'+dependencyEsc(resName)+' <span style="color:var(--text-muted);font-size:9px">'+dependencyEsc(resourceId)+'</span></div>';
  Object.keys(byDepth).sort((a,b)=>a-b).forEach(d=>{
    byDepth[d].sort((a,b)=>{const o={hard:0,soft:1,config:2};return(o[a.strength]||3)-(o[b.strength]||3)}).forEach(e=>{
      const depCls=Math.min(parseInt(d),3);
      const name=_getResName(e.id);const type=_getResType(e.id);
      h+='<div class="dep-node dep-'+dependencyEsc(e.strength)+' dep-depth-'+depCls+'" data-id="'+dependencyAttr(e.id)+'" title="'+dependencyEsc(e.id)+'"><span class="dep-type">'+dependencyEsc(type)+'</span>'+dependencyEsc(name)+' <span class="dep-rel">'+dependencyEsc(e.rel)+'</span></div>';
    });
  });
  if(!blast.all.length)h+='<div style="padding:20px;color:var(--text-muted);font-size:12px;text-align:center">No dependencies found for this resource</div>';
  h+='</div>';
  body.innerHTML=h;
  // Click to zoom
  body.querySelectorAll('.dep-node[data-id]').forEach(el=>{el.addEventListener('click',()=>{
    document.getElementById('depOverlay').classList.remove('open');
    dependencyZoomToResource(el.dataset.id);
  })});
  document.getElementById('depOverlay').classList.add('open');
  // Store for blast highlighting
  document.getElementById('depBlastBtn').onclick=()=>{
    document.getElementById('depOverlay').classList.remove('open');
    _applyBlastRadius(resourceId,blast);
  };
}
function _applyBlastRadius(sourceId,blast){
  const mapG=dependencyMapGroup();
  if(!mapG)return;
  _blastActive=true;
  // Dim everything
  mapG.selectAll('.vpc-group,.subnet-node,.gw-node,.lz-gw-node,.lz-tgw-node').classed('blast-dimmed',true);
  // Un-dim + glow source
  const srcId=dependencyAttr(sourceId);
  const srcEl=mapG.node().querySelector('[data-vnet-id="'+srcId+'"],[data-subnet-id="'+srcId+'"],[data-gwid="'+srcId+'"],[data-id="'+srcId+'"]');
  const srcSel=srcEl&&dependencySelect(srcEl);
  if(srcSel)srcSel.classed('blast-dimmed',false).classed('blast-glow-hard',true);
  // Highlight dependents
  blast.all.forEach(e=>{
    const depId=dependencyAttr(e.id);
    const el=mapG.node().querySelector('[data-vnet-id="'+depId+'"],[data-subnet-id="'+depId+'"],[data-gwid="'+depId+'"],[data-id="'+depId+'"]');
    const sel=el&&dependencySelect(el);
    if(sel)sel.classed('blast-dimmed',false).classed('blast-glow-'+e.strength,true);
  });
  dependencyNotify('Blast radius active - click anywhere to clear');
}
function _clearBlastRadius(){
  const mapG=dependencyMapGroup();
  if(!_blastActive||!mapG)return;
  _blastActive=false;
  mapG.selectAll('.blast-dimmed,.blast-glow-hard,.blast-glow-soft,.blast-glow-config').classed('blast-dimmed',false).classed('blast-glow-hard',false).classed('blast-glow-soft',false).classed('blast-glow-config',false);
}
document.getElementById('depCloseBtn').addEventListener('click',()=>document.getElementById('depOverlay').classList.remove('open'));
document.getElementById('depBlastBtn').addEventListener('click',()=>{});// overridden in showDependencies

// === HELP ===
document.getElementById('helpBtn').addEventListener('click',()=>{document.getElementById('helpOverlay').style.display='flex'});
document.getElementById('helpClose').addEventListener('click',()=>{document.getElementById('helpOverlay').style.display='none'});

// #endregion DEPENDENCY GRAPH

