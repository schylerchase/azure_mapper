// #region MULTI-ACCOUNT
// === MULTI-ACCOUNT / MULTI-REGION VIEW ===
let _multiViewMode=false;
let _loadedContexts=[];  // [{accountId, accountLabel, region, textareas, rlCtx, color, visible}]
let _mergedCtx=null;
let _singleCtxBackup=null;  // backup of original render context before merge
let _mergeRenderGeneration=0;

function multiAccountRuntimeContext(){
  return typeof AppRenderContext!=='undefined'?AppRenderContext.createRenderContext():null;
}

function multiAccountData(){
  const adapter=multiAccountRuntimeContext();
  return adapter?adapter.rlCtx:null;
}

function setMultiAccountData(value){
  const adapter=multiAccountRuntimeContext();
  if(adapter)adapter.rlCtx=value;
}

function multiAccountNotify(message,type){
  if(typeof AppNotifications!=='undefined'&&AppNotifications.show){
    AppNotifications.show(message,type);
    return;
  }
  const adapter=multiAccountRuntimeContext();
  if(adapter&&typeof adapter.showToast==='function')adapter.showToast(message,type);
}

function multiAccountComplianceRows(){
  const adapter=multiAccountRuntimeContext();
  return adapter?adapter.complianceFindings:[];
}

function resetMultiAccountComplianceRows(){
  const adapter=multiAccountRuntimeContext();
  if(adapter)adapter.complianceFindings=[];
}

function _captureCurrentAsContext(){
  const current=multiAccountData();
  if(!current||!current.vnets||!current.vnets.length)return null;
  const textareas={};
  document.querySelectorAll('.ji').forEach(el=>{
    const v=el.value.trim();
    if(v)textareas[el.id]=v;
  });
  const label=(document.getElementById('accountLabel')||{}).value||'';
  const accts=current._accounts||new Set();
  const accountId=accts.size?[...accts][0]:(label||'current');
  const region=_detectRegionFromCtx(current);
  return {
    accountId:accountId,
    accountLabel:label||accountId,
    region:region,
    textareas:textareas,
    rlCtx:current,
    color:null,
    visible:true
  };
}

function _detectRegionFromCtx(ctx){
  if(!ctx)return 'unknown';
  const sub=(ctx.subnets||[])[0];
  if(sub&&sub.AvailabilityZone)return sub.AvailabilityZone;
  return 'unknown';
}

function addAccountContext(projectData, label){
  // Parse an .azuremap project or raw textarea object into a context
  const textareas=projectData.textareas||projectData.json_data||{};
  const acctLabel=label||projectData.accountLabel||'Account '+((_loadedContexts.length)+1);

  // PERF: Build rlCtx directly from data: no DOM round-trip
  const ctx=_buildRlCtxFromData(textareas, projectData.accountLabel||acctLabel);

  if(!ctx||!ctx.vpcs||!ctx.vpcs.length){
    multiAccountNotify('No VPC data found in loaded file');
    return;
  }

  const region=_detectRegionFromCtx(ctx);
  const accts=ctx._accounts||new Set();
  const accountId=accts.size?[...accts][0]:(acctLabel);
  const colorIdx=_loadedContexts.length%_accountColors.length;
  const color=_accountColors[colorIdx];
  // Sync color to _accountColorMap so VPC stripes match panel cards
  if(accountId&&accountId!=='default')_accountColorMap[accountId]=color;

  _loadedContexts.push({
    accountId:accountId,
    accountLabel:acctLabel,
    region:region,
    textareas:textareas,
    rlCtx:ctx,
    color:color,
    visible:true,
    _isRegion:!!(projectData._isRegion)
  });

  _renderAccountPanel();
  multiAccountNotify('Added account: '+acctLabel);
}

function _buildRlCtxFromTextareas(){
  // Minimal parse of textareas to build an rlCtx: mirrors _renderMapInner parse logic
  try{
    const userAccount=(document.getElementById('accountLabel')||{}).value.trim()||'';
    let vpcs=ext(safeParse(gv('in_vnets')),['value','VirtualNetworks']);
    let subnets=ext(safeParse(gv('in_subnets')),['value','Subnets']);
    let rts=ext(safeParse(gv('in_udrs')),['value','RouteTables']);
    let sgs=ext(safeParse(gv('in_nsgs')),['value','SecurityGroups']);
    let nacls=[];// NACLs not used in Azure: NSGs serve both purposes
    let enis=ext(safeParse(gv('in_nics')),['value','NetworkInterfaces']);
    let igwRaw=ext(safeParse(gv('in_azfws')),['value']);
    let natRaw=ext(safeParse(gv('in_nats')),['value','NatGateways']);
    let vpceRaw=ext(safeParse(gv('in_pvteps')),['value','PrivateEndpoints']);
    let instances=ext(safeParse(gv('in_vms')),['value']).flatMap(r=>r.properties?[r]:(r.Instances||[r]));
    let albs=ext(safeParse(gv('in_albs')),['value','LoadBalancers']);
    let tgs=ext(safeParse(gv('in_tgs')),['value','TargetGroups']);
    let peerings=ext(safeParse(gv('in_peer')),['value','VnetPeerings']);
    let vpns=ext(safeParse(gv('in_vpn')),['value','VpnConnections']);
    let volumes=ext(safeParse(gv('in_disks')),['value','Disks']);
    let snapshots=ext(safeParse(gv('in_snaps')),['value','Snapshots']);
    let rdsInstances=ext(safeParse(gv('in_sql')),['value','SqlServers']);
    let ecsServices=ext(safeParse(gv('in_containers')),['value','ContainerGroups']);
    let lambdaFns=ext(safeParse(gv('in_funcapps')),['value']).filter(f=>f.kind||f.name);
    let ecacheClusters=ext(safeParse(gv('in_elasticache')),['value','RedisCaches']);
    let redshiftClusters=ext(safeParse(gv('in_aks')),['value','AksClusters']).concat(ext(safeParse(gv('in_synapse')),['value','SynapseWorkspaces']));
    // Parse resources previously skipped (Storage, WAF, DNS, FrontDoor): needed for compliance accuracy
    let s3raw=safeParse(gv('in_storage'));let s3bk=s3raw?ext(s3raw,['value','StorageAccounts']):[];
    let zones=ext(safeParse(gv('in_dnsz')),['value','DnsZones']);
    let wafAcls=ext(safeParse(gv('in_waf')),['value','WafPolicies']);
    let cfDistributions=[];const cfRaw=safeParse(gv('in_cf'));
    if(cfRaw){const dl=cfRaw.value||cfRaw;cfDistributions=dl.Items||dl.FrontDoors||(Array.isArray(dl)?dl:[])}
    let tgwAttRaw=ext(safeParse(gv('in_tgwatt')),['value','VirtualWans']);
    // Parse RBAC data (replaces IAM)
    const iamRaw2=safeParse(gv('in_rbac'));
    _iamData=iamRaw2?parseIAMData(iamRaw2):null;
    const rbac=typeof parseRBACData==='function'?parseRBACData(iamRaw2):null;

    function tagAccount(resource){
      if(!resource)return resource;
      resource._subscriptionId=detectAccountId(resource)||userAccount||'default';
      return resource;
    }
    function tagRegion(resource){
      if(!resource)return resource;
      resource._region=detectRegion(resource)||'unknown';
      return resource;
    }
    [vpcs,subnets,igwRaw,natRaw,sgs,instances,albs,rdsInstances,ecsServices,lambdaFns,
     peerings,volumes,snapshots,enis,ecacheClusters,redshiftClusters,
     nacls,rts,vpceRaw,vpns,s3bk,zones,wafAcls,cfDistributions,tgs].forEach(function(arr){arr.forEach(function(r){tagAccount(r);tagRegion(r)})});
    // VPC→region fallback: derive from subnets' AZs, propagate to VPC-linked resources
    var vpcRegion={};
    subnets.forEach(function(s){if(s.VpcId&&s._region&&s._region!=='unknown')vpcRegion[s.VpcId]=s._region});
    var subVpcLookup={};subnets.forEach(function(s){if(s.SubnetId)subVpcLookup[s.SubnetId]=s.VpcId||''});
    function fillRegion(r){if(r&&r._region==='unknown'&&r.VpcId&&vpcRegion[r.VpcId])r._region=vpcRegion[r.VpcId]}
    [vpcs,sgs,nacls,rts,vpceRaw,igwRaw,natRaw,enis,ecacheClusters,redshiftClusters].forEach(function(arr){arr.forEach(fillRegion)});
    // IGW region fallback via attachment VpcId
    igwRaw.forEach(function(g){if(g._region==='unknown'){var att=(g.Attachments||[])[0];if(att&&att.VpcId&&vpcRegion[att.VpcId])g._region=vpcRegion[att.VpcId]}});
    // ECS region fallback via subnet→VPC→region
    ecsServices.forEach(function(svc){if(svc._region==='unknown'){var nc=svc.networkConfiguration&&svc.networkConfiguration.awsvpcConfiguration;var sid=nc&&nc.subnets&&nc.subnets[0];if(sid){var vid=subVpcLookup[sid];if(vid&&vpcRegion[vid])svc._region=vpcRegion[vid]}}});
    // VPN region fallback via VpnGatewayId→VPC (limited: VPN doesn't always carry VpcId)
    vpns.forEach(function(v){if(v._region==='unknown'){var vgw=v.VpnGatewayId;if(vgw){vpcs.forEach(function(vpc){if(vpc._region&&vpc._region!=='unknown'){var gws=(vpc.VpnGateways||[]);gws.forEach(function(g){if(g.VpnGatewayId===vgw)v._region=vpc._region})}})}}});
    // Peering region fallback via RequesterVpcInfo/AccepterVpcInfo
    peerings.forEach(function(p){if(p._region==='unknown'){var rv=p.RequesterVpcInfo&&p.RequesterVpcInfo.VpcId;var av=p.AccepterVpcInfo&&p.AccepterVpcInfo.VpcId;if(rv&&vpcRegion[rv])p._region=vpcRegion[rv];else if(av&&vpcRegion[av])p._region=vpcRegion[av]}});
    // Snapshot region fallback via volume→region
    var volRegion={};volumes.forEach(function(v){if(v.VolumeId&&v._region&&v._region!=='unknown')volRegion[v.VolumeId]=v._region});
    snapshots.forEach(function(s){if(s._region==='unknown'&&s.VolumeId&&volRegion[s.VolumeId])s._region=volRegion[s.VolumeId]});
    // WAF region fallback via associated ALB ARNs
    var albArnRegion={};albs.forEach(function(a){if(a.LoadBalancerArn&&a._region&&a._region!=='unknown')albArnRegion[a.LoadBalancerArn]=a._region});
    wafAcls.forEach(function(w){if(w._region==='unknown'){(w.ResourceArns||[]).some(function(arn){if(albArnRegion[arn]){w._region=albArnRegion[arn];return true}})}});
    // Global services: mark as "global" instead of "unknown"
    zones.forEach(function(z){if(z._region==='unknown')z._region='global'});
    cfDistributions.forEach(function(d){if(d._region==='unknown')d._region='global'});
    // Final account→region sweep: fill remaining "unknown" from account's primary region
    var acctRegion={};
    [vpcs,subnets,instances].forEach(function(arr){arr.forEach(function(r){if(r._subscriptionId&&r._region&&r._region!=='unknown'&&r._region!=='global'&&!acctRegion[r._subscriptionId])acctRegion[r._subscriptionId]=r._region})});
    [vpcs,sgs,nacls,rts,igwRaw,natRaw,vpceRaw,enis,s3bk,snapshots,wafAcls,vpns,peerings,volumes,tgs,ecacheClusters,redshiftClusters,ecsServices,lambdaFns,albs,rdsInstances].forEach(function(arr){arr.forEach(function(r){if(r._region==='unknown'&&r._subscriptionId&&acctRegion[r._subscriptionId])r._region=acctRegion[r._subscriptionId]})});

    const _accounts=new Set();
    vpcs.forEach(v=>{if(v._subscriptionId&&v._subscriptionId!=='default')_accounts.add(v._subscriptionId)});
    const _multiTenant=_accounts.size>1;
    const _regions=new Set();vpcs.forEach(v=>{if(v._region&&v._region!=='unknown')_regions.add(v._region)});
    const _multiRegion=_regions.size>1;

    // Build basic derived maps
    const vpcIds=new Set(vpcs.map(v=>v.VpcId));
    subnets=subnets.filter(s=>vpcIds.has(s.VpcId));
    const pubSubs=new Set();
    rts.forEach(rt=>{const hasIgw=rt.Routes&&rt.Routes.some(r=>_isIgwRoute(r.GatewayId)&&r.State!=='blackhole');if(hasIgw)(rt.Associations||[]).forEach(a=>{if(a.SubnetId)pubSubs.add(a.SubnetId)})});

    const igws=[],nats=[],vpces=[];
    igwRaw.forEach(g=>{(g.Attachments||[]).forEach(a=>{if(vpcIds.has(a.VpcId))igws.push(Object.assign({},g,{_vpcId:a.VpcId}))})});
    natRaw.forEach(g=>{if(vpcIds.has(g.VpcId))nats.push(g)});
    vpceRaw.forEach(g=>{if(vpcIds.has(g.VpcId))vpces.push(g)});

    const instBySub=new Map(),albBySub=new Map(),eniBySub=new Map();
    const rdsBySub=new Map(),ecsBySub=new Map(),lambdaBySub=new Map();
    instances.forEach(i=>{const s=i.SubnetId;if(s){if(!instBySub.has(s))instBySub.set(s,[]);instBySub.get(s).push(i)}});
    albs.forEach(a=>{(a.AvailabilityZones||[]).forEach(az=>{const s=az.SubnetId;if(s){if(!albBySub.has(s))albBySub.set(s,[]);albBySub.get(s).push(a)}})});
    enis.forEach(e=>{const s=e.SubnetId;if(s){if(!eniBySub.has(s))eniBySub.set(s,[]);eniBySub.get(s).push(e)}});
    rdsInstances.forEach(d=>{(d.DBSubnetGroup?.Subnets||[]).forEach(s=>{const sid2=s.SubnetIdentifier;if(sid2){if(!rdsBySub.has(sid2))rdsBySub.set(sid2,[]);rdsBySub.get(sid2).push(d)}})});
    ecsServices.forEach(svc=>{(svc.NetworkConfiguration?.awsvpcConfiguration?.Subnets||[]).forEach(s=>{if(!ecsBySub.has(s))ecsBySub.set(s,[]);ecsBySub.get(s).push(svc)})});
    lambdaFns.forEach(f=>{(f.VpcConfig?.SubnetIds||[]).forEach(s=>{if(!lambdaBySub.has(s))lambdaBySub.set(s,[]);lambdaBySub.get(s).push(f)})});

    const subRT=new Map(),subNacl=new Map(),nsgByVnet=new Map();
    rts.forEach(rt=>{(rt.Associations||[]).forEach(a=>{if(a.SubnetId)subRT.set(a.SubnetId,rt)})});
    nacls.forEach(n=>{(n.Associations||[]).forEach(a=>{if(a.SubnetId)subNacl.set(a.SubnetId,n)})});
    sgs.forEach(sg=>{const v=sg.VpcId;if(v){if(!nsgByVnet.has(v))nsgByVnet.set(v,[]);nsgByVnet.get(v).push(sg)}});

    const volByInst=new Map(),snapByVol=new Map();
    volumes.forEach(v=>{(v.Attachments||[]).forEach(a=>{if(a.InstanceId){if(!volByInst.has(a.InstanceId))volByInst.set(a.InstanceId,[]);volByInst.get(a.InstanceId).push(v)}})});
    snapshots.forEach(s=>{const vid=s.VolumeId;if(vid){if(!snapByVol.has(vid))snapByVol.set(vid,[]);snapByVol.get(vid).push(s)}});

    const ecacheByVpc=new Map(),redshiftByVpc=new Map();
    ecacheClusters.forEach(c=>{const vid=c.VpcId||(c.CacheNodes&&c.CacheNodes[0]&&c.CacheNodes[0].CustomerAvailabilityZone?'':'');if(vid){if(!ecacheByVpc.has(vid))ecacheByVpc.set(vid,[]);ecacheByVpc.get(vid).push(c)}});
    redshiftClusters.forEach(c=>{const v=c.VpcId;if(v){if(!redshiftByVpc.has(v))redshiftByVpc.set(v,[]);redshiftByVpc.get(v).push(c)}});

    function m2o(m){const o={};m.forEach((v,k)=>{o[k]=v});return o}
    // Build WAF/TG/CF lookup maps
    const wafByAlb={};wafAcls.forEach(acl=>{(acl.ResourceArns||[]).forEach(arn=>{(wafByAlb[arn]=wafByAlb[arn]||[]).push(acl)})});
    const tgByAlb={};tgs.forEach(tg=>{(tg.LoadBalancerArns||[]).forEach(arn=>{(tgByAlb[arn]=tgByAlb[arn]||[]).push(tg)})});
    const cfByAlb={};cfDistributions.forEach(d=>{(d.Origins?.Items||[]).forEach(o=>{const matchAlb=albs.find(a=>a.DNSName&&o.DomainName&&o.DomainName.includes(a.DNSName));if(matchAlb)(cfByAlb[matchAlb.LoadBalancerArn]=cfByAlb[matchAlb.LoadBalancerArn]||[]).push(d)})});
    const recsByZone={};
    const allRecSets=ext(safeParse(gv('in_r53records')),['ResourceRecordSets','RecordSets']);
    allRecSets.forEach(r=>{if(r.HostedZoneId)(recsByZone[r.HostedZoneId]=recsByZone[r.HostedZoneId]||[]).push(r)});
    // Merge explicit TGW attachments with route-derived ones
    const tgwAttachments2=[...tgwAttRaw];
    rts.forEach(rt=>{(rt.Routes||[]).forEach(r=>{if(r.TransitGatewayId){var vid=rt.VpcId||((rt.Associations||[])[0]||{}).VpcId;tgwAttachments2.push({TransitGatewayId:r.TransitGatewayId,VpcId:vid,_subscriptionId:rt._subscriptionId||'',_region:rt._region||(vid&&vpcRegion[vid])||'unknown'})}})});
    tgwAttRaw.forEach(function(t){tagAccount(t);tagRegion(t);fillRegion(t)});
    tgwAttachments2.forEach(function(t){if((!t._region||t._region==='unknown')&&t._subscriptionId&&acctRegion[t._subscriptionId])t._region=acctRegion[t._subscriptionId];if(!t._region||t._region==='unknown'){var vid=t.VpcId;if(vid&&vpcRegion[vid])t._region=vpcRegion[vid]}});
    return {vpcs,subnets,pubSubs,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,rbac,
      s3bk,zones,wafAcls,wafByAlb,tgByAlb,cfByAlb,
      rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,cfDistributions,
      instBySub:m2o(instBySub),albBySub:m2o(albBySub),eniBySub:m2o(eniBySub),rdsBySub:m2o(rdsBySub),ecsBySub:m2o(ecsBySub),lambdaBySub:m2o(lambdaBySub),
      subRT:m2o(subRT),subNacl:m2o(subNacl),nsgByVnet:m2o(nsgByVnet),volByInst:m2o(volByInst),snapByVol:m2o(snapByVol),ecacheByVpc:m2o(ecacheByVpc),redshiftByVpc:m2o(redshiftByVpc),
      tgwAttachments:tgwAttachments2,recsByZone,_multiTenant,_accounts,_regions,_multiRegion};
  }catch(e){
    console.warn('_buildRlCtxFromTextareas error:',e);
    return null;
  }
}

// PERF: Build rlCtx directly from a {id: value} map without DOM round-trip.
// Values can be strings (web) or pre-parsed objects (Electron).
function _buildRlCtxFromData(textareas, accountLabel){
  try{
    const parsed={};
    function _val(id){
      if(Object.prototype.hasOwnProperty.call(parsed,id))return parsed[id];
      const v=textareas[id];
      // Render normalization must never mutate the saved input payload.
      return parsed[id]=!v?null:typeof v==='string'?safeParse(v):structuredClone(v);
    }
    const userAccount=accountLabel||'';
    let vpcs=ext(_val('in_vnets'),['value','VirtualNetworks']);
    let subnets=ext(_val('in_subnets'),['value','Subnets']);
    let rts=ext(_val('in_udrs'),['value','RouteTables']);
    let sgs=ext(_val('in_nsgs'),['value','SecurityGroups']);
    let nacls=[];// NACLs not used in Azure
    let enis=ext(_val('in_nics'),['value','NetworkInterfaces']);
    let igwRaw=ext(_val('in_azfws'),['value']);
    let natRaw=ext(_val('in_nats'),['value','NatGateways']);
    let vpceRaw=ext(_val('in_pvteps'),['value','PrivateEndpoints']);
    let instances=ext(_val('in_vms'),['value']).flatMap(r=>r.properties?[r]:(r.Instances||[r]));
    let albs=ext(_val('in_albs'),['value','LoadBalancers']);
    let tgs=ext(_val('in_tgs'),['value','TargetGroups']);
    let peerings=ext(_val('in_peer'),['value','VnetPeerings']);
    let vpns=ext(_val('in_vpn'),['value','VpnConnections']);
    let volumes=ext(_val('in_disks'),['value','Disks']);
    let snapshots=ext(_val('in_snaps'),['value','Snapshots']);
    let rdsInstances=ext(_val('in_sql'),['value','SqlServers']);
    let ecsServices=ext(_val('in_containers'),['value','ContainerGroups']);
    let lambdaFns=ext(_val('in_funcapps'),['value']).filter(f=>f.kind||f.name);
    let ecacheClusters=ext(_val('in_elasticache'),['value','RedisCaches']);
    let redshiftClusters=ext(_val('in_aks'),['value','AksClusters']).concat(ext(_val('in_synapse'),['value','SynapseWorkspaces']));
    // Parse resources for compliance accuracy (Storage, WAF, FrontDoor, DNS, VWAN)
    let s3raw=_val('in_storage');let s3bk=s3raw?ext(s3raw,['value','StorageAccounts']):[];
    let zones=ext(_val('in_dnsz'),['value','DnsZones']);
    let wafAcls=ext(_val('in_waf'),['value','WafPolicies']);
    let cfDistributions=[];const cfRaw=_val('in_cf');
    if(cfRaw){const dl=cfRaw.value||cfRaw;cfDistributions=dl.FrontDoors||dl.Items||(Array.isArray(dl)?dl:[])}
    let tgwAttRaw=ext(_val('in_tgwatt'),['value','VirtualWans']);
    const iamRaw2=_val('in_rbac');
    _iamData=iamRaw2?parseIAMData(iamRaw2):null;
    const rbac=typeof parseRBACData==='function'?parseRBACData(iamRaw2):null;

    function tagResource(r){if(!r)return r;r._subscriptionId=detectAccountId(r)||userAccount||'default';r._region=detectRegion(r)||'unknown';return r}
    [vpcs,subnets,igwRaw,natRaw,sgs,instances,albs,rdsInstances,ecsServices,lambdaFns,
     peerings,volumes,snapshots,enis,ecacheClusters,redshiftClusters,
     nacls,rts,vpceRaw,vpns,s3bk,zones,wafAcls,cfDistributions,tgs].forEach(arr=>arr.forEach(tagResource));
    // Azure normalization (shared with _renderMapInner)
    _normalizeAzureResources({vpcs,subnets,rts,sgs,enis,igws:igwRaw,nats:natRaw,vpces:vpceRaw,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,wafAcls,rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments:tgwAttRaw,cfDistributions});
    // VPC→region fallback: derive from subnets' AZs, propagate to VPC-linked resources
    const vpcRegion={};
    subnets.forEach(s=>{if(s.VpcId&&s._region&&s._region!=='unknown')vpcRegion[s.VpcId]=s._region});
    function fillRegion(r){if(r&&r._region==='unknown'&&r.VpcId&&vpcRegion[r.VpcId])r._region=vpcRegion[r.VpcId]}
    [vpcs,sgs,nacls,rts,vpceRaw,igwRaw,natRaw,enis,ecacheClusters,redshiftClusters].forEach(arr=>arr.forEach(fillRegion));
    // IGWs use _vpcId from attachment
    igwRaw.forEach(g=>{if(g._region==='unknown'){const att=(g.Attachments||[])[0];if(att&&att.VpcId&&vpcRegion[att.VpcId])g._region=vpcRegion[att.VpcId]}});
    // ECS region fallback via subnet→VPC→region
    const subVpcLookup={};subnets.forEach(s=>{if(s.SubnetId)subVpcLookup[s.SubnetId]=s.VpcId||''});
    ecsServices.forEach(svc=>{if(svc._region==='unknown'){const nc=svc.networkConfiguration&&svc.networkConfiguration.awsvpcConfiguration;const sid=nc&&nc.subnets&&nc.subnets[0];if(sid){const vid=subVpcLookup[sid];if(vid&&vpcRegion[vid])svc._region=vpcRegion[vid]}}});
    // VPN region fallback
    vpns.forEach(v=>{if(v._region==='unknown'){const vgw=v.VpnGatewayId;if(vgw)vpcs.forEach(vpc=>{if(vpc._region&&vpc._region!=='unknown'){(vpc.VpnGateways||[]).forEach(g=>{if(g.VpnGatewayId===vgw)v._region=vpc._region})}})}});
    // Peering region fallback via RequesterVpcInfo/AccepterVpcInfo
    peerings.forEach(p=>{if(p._region==='unknown'){const rv=p.RequesterVpcInfo&&p.RequesterVpcInfo.VpcId;const av=p.AccepterVpcInfo&&p.AccepterVpcInfo.VpcId;if(rv&&vpcRegion[rv])p._region=vpcRegion[rv];else if(av&&vpcRegion[av])p._region=vpcRegion[av]}});
    // Snapshot region fallback via volume→region
    const volRegion={};volumes.forEach(v=>{if(v.VolumeId&&v._region&&v._region!=='unknown')volRegion[v.VolumeId]=v._region});
    snapshots.forEach(s=>{if(s._region==='unknown'&&s.VolumeId&&volRegion[s.VolumeId])s._region=volRegion[s.VolumeId]});
    // WAF region fallback via associated ALB ARNs
    const albArnRegion={};albs.forEach(a=>{if(a.LoadBalancerArn&&a._region&&a._region!=='unknown')albArnRegion[a.LoadBalancerArn]=a._region});
    wafAcls.forEach(w=>{if(w._region==='unknown'){(w.ResourceArns||[]).some(arn=>{if(albArnRegion[arn]){w._region=albArnRegion[arn];return true}})}});
    // Global services: mark as "global" instead of "unknown"
    zones.forEach(z=>{if(z._region==='unknown')z._region='global'});
    cfDistributions.forEach(d=>{if(d._region==='unknown')d._region='global'});
    // Final account→region sweep: fill remaining "unknown" from account's primary region
    const acctRegion={};
    [vpcs,subnets,instances].forEach(arr=>{arr.forEach(r=>{if(r._subscriptionId&&r._region&&r._region!=='unknown'&&r._region!=='global'&&!acctRegion[r._subscriptionId])acctRegion[r._subscriptionId]=r._region})});
    [vpcs,sgs,nacls,rts,igwRaw,natRaw,vpceRaw,enis,s3bk,snapshots,wafAcls,vpns,peerings,volumes,tgs,ecacheClusters,redshiftClusters,ecsServices,lambdaFns,albs,rdsInstances].forEach(arr=>{arr.forEach(r=>{if(r._region==='unknown'&&r._subscriptionId&&acctRegion[r._subscriptionId])r._region=acctRegion[r._subscriptionId]})});

    const _accounts=new Set();
    vpcs.forEach(v=>{if(v._subscriptionId&&v._subscriptionId!=='default')_accounts.add(v._subscriptionId)});
    // Replace 'default' fallback with the primary detected account ID
    if(_accounts.size>=1){var _prAcct=[..._accounts][0];[vpcs,subnets,sgs,nacls,rts,igwRaw,natRaw,vpceRaw,enis,instances,albs,rdsInstances,ecsServices,lambdaFns,peerings,ecacheClusters,redshiftClusters,volumes,snapshots,s3bk,tgs,wafAcls,vpns].forEach(function(arr){arr.forEach(function(r){if(r&&r._subscriptionId==='default')r._subscriptionId=_prAcct})})}
    const _multiTenant=_accounts.size>1;
    const _regions=new Set();vpcs.forEach(v=>{if(v._region&&v._region!=='unknown')_regions.add(v._region)});
    const _multiRegion=_regions.size>1;

    const vpcIds=new Set(vpcs.map(v=>v.VpcId));
    subnets=subnets.filter(s=>vpcIds.has(s.VpcId));
    const pubSubs=new Set();
    rts.forEach(rt=>{const hasIgw=rt.Routes&&rt.Routes.some(r=>_isIgwRoute(r.GatewayId)&&r.State!=='blackhole');if(hasIgw)(rt.Associations||[]).forEach(a=>{if(a.SubnetId)pubSubs.add(a.SubnetId)})});

    const igws=[],nats=[],vpces=[];
    igwRaw.forEach(g=>{(g.Attachments||[]).forEach(a=>{if(vpcIds.has(a.VpcId))igws.push(Object.assign({},g,{_vpcId:a.VpcId}))})});
    natRaw.forEach(g=>{if(vpcIds.has(g.VpcId))nats.push(g)});
    vpceRaw.forEach(g=>{if(vpcIds.has(g.VpcId))vpces.push(g)});

    const instBySub=new Map(),albBySub=new Map(),eniBySub=new Map();
    const rdsBySub=new Map(),ecsBySub=new Map(),lambdaBySub=new Map();
    instances.forEach(i=>{const s=i.SubnetId;if(s){if(!instBySub.has(s))instBySub.set(s,[]);instBySub.get(s).push(i)}});
    albs.forEach(a=>{(a.AvailabilityZones||[]).forEach(az=>{const s=az.SubnetId;if(s){if(!albBySub.has(s))albBySub.set(s,[]);albBySub.get(s).push(a)}})});
    enis.forEach(e=>{const s=e.SubnetId;if(s){if(!eniBySub.has(s))eniBySub.set(s,[]);eniBySub.get(s).push(e)}});
    rdsInstances.forEach(d=>{(d.DBSubnetGroup?.Subnets||[]).forEach(s=>{const sid2=s.SubnetIdentifier;if(sid2){if(!rdsBySub.has(sid2))rdsBySub.set(sid2,[]);rdsBySub.get(sid2).push(d)}})});
    ecsServices.forEach(svc=>{(svc.NetworkConfiguration?.awsvpcConfiguration?.Subnets||[]).forEach(s=>{if(!ecsBySub.has(s))ecsBySub.set(s,[]);ecsBySub.get(s).push(svc)})});
    lambdaFns.forEach(f=>{(f.VpcConfig?.SubnetIds||[]).forEach(s=>{if(!lambdaBySub.has(s))lambdaBySub.set(s,[]);lambdaBySub.get(s).push(f)})});

    const subRT=new Map(),subNacl=new Map(),nsgByVnet=new Map();
    rts.forEach(rt=>{(rt.Associations||[]).forEach(a=>{if(a.SubnetId)subRT.set(a.SubnetId,rt)})});
    nacls.forEach(n=>{(n.Associations||[]).forEach(a=>{if(a.SubnetId)subNacl.set(a.SubnetId,n)})});
    sgs.forEach(sg=>{const v=sg.VpcId;if(v){if(!nsgByVnet.has(v))nsgByVnet.set(v,[]);nsgByVnet.get(v).push(sg)}});

    const volByInst=new Map(),snapByVol=new Map();
    volumes.forEach(v=>{(v.Attachments||[]).forEach(a=>{if(a.InstanceId){if(!volByInst.has(a.InstanceId))volByInst.set(a.InstanceId,[]);volByInst.get(a.InstanceId).push(v)}})});
    snapshots.forEach(s=>{const vid=s.VolumeId;if(vid){if(!snapByVol.has(vid))snapByVol.set(vid,[]);snapByVol.get(vid).push(s)}});

    const ecacheByVpc=new Map(),redshiftByVpc=new Map();
    ecacheClusters.forEach(c=>{const vid=c.VpcId||(c.CacheNodes&&c.CacheNodes[0]&&c.CacheNodes[0].CustomerAvailabilityZone?'':'');if(vid){if(!ecacheByVpc.has(vid))ecacheByVpc.set(vid,[]);ecacheByVpc.get(vid).push(c)}});
    redshiftClusters.forEach(c=>{const v=c.VpcId;if(v){if(!redshiftByVpc.has(v))redshiftByVpc.set(v,[]);redshiftByVpc.get(v).push(c)}});

    // Merge explicit TGW attachments with route-derived ones
    const tgwAttachments=[...tgwAttRaw];
    rts.forEach(rt=>{(rt.Routes||[]).forEach(r=>{if(r.TransitGatewayId){const vid=rt.VpcId||((rt.Associations||[])[0]||{}).VpcId;tgwAttachments.push({TransitGatewayId:r.TransitGatewayId,VpcId:vid,_subscriptionId:rt._subscriptionId||'',_region:rt._region||(vid&&vpcRegion[vid])||'unknown'})}})});
    tgwAttRaw.forEach(t=>{tagResource(t);fillRegion(t)});
    tgwAttachments.forEach(t=>{if((!t._region||t._region==='unknown')&&t._subscriptionId&&acctRegion[t._subscriptionId])t._region=acctRegion[t._subscriptionId];if(!t._region||t._region==='unknown'){const vid=t.VpcId;if(vid&&vpcRegion[vid])t._region=vpcRegion[vid]}});

    // Build WAF/TG/CF lookup maps (mirrors _buildRlCtxFromTextareas)
    const wafByAlb={};wafAcls.forEach(acl=>{(acl.ResourceArns||[]).forEach(arn=>{(wafByAlb[arn]=wafByAlb[arn]||[]).push(acl)})});
    const tgByAlb={};tgs.forEach(tg=>{(tg.LoadBalancerArns||[]).forEach(arn=>{(tgByAlb[arn]=tgByAlb[arn]||[]).push(tg)})});
    const cfByAlb={};cfDistributions.forEach(d=>{(d.Origins?.Items||[]).forEach(o=>{const matchAlb=albs.find(a=>a.DNSName&&o.DomainName&&o.DomainName.includes(a.DNSName));if(matchAlb)(cfByAlb[matchAlb.LoadBalancerArn]=cfByAlb[matchAlb.LoadBalancerArn]||[]).push(d)})});
    const recsByZone={};
    const allRecSets=ext(_val('in_r53records'),['ResourceRecordSets','RecordSets']);
    allRecSets.forEach(r=>{if(r.HostedZoneId)(recsByZone[r.HostedZoneId]=recsByZone[r.HostedZoneId]||[]).push(r)});

    function m2o(m){const o={};m.forEach((v,k)=>{o[k]=v});return o}
    return {vpcs,subnets,pubSubs,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,rbac,
      s3bk,zones,wafAcls,wafByAlb,tgByAlb,cfByAlb,
      rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,cfDistributions,
      instBySub:m2o(instBySub),albBySub:m2o(albBySub),eniBySub:m2o(eniBySub),rdsBySub:m2o(rdsBySub),ecsBySub:m2o(ecsBySub),lambdaBySub:m2o(lambdaBySub),
      subRT:m2o(subRT),subNacl:m2o(subNacl),nsgByVnet:m2o(nsgByVnet),volByInst:m2o(volByInst),snapByVol:m2o(snapByVol),ecacheByVpc:m2o(ecacheByVpc),redshiftByVpc:m2o(redshiftByVpc),
      tgwAttachments,recsByZone,_multiTenant,_accounts,_regions,_multiRegion};
  }catch(e){
    console.warn('_buildRlCtxFromData error:',e);
    return null;
  }
}

function removeAccountContext(index){
  if(index<0||index>=_loadedContexts.length)return;
  const removed=_loadedContexts.splice(index,1)[0];
  multiAccountNotify('Removed: '+(removed.accountLabel||removed.accountId));
  if(_multiViewMode)_remergeAndRender();
  _renderAccountPanel();
}

function mergeContexts(contexts){
  const visible=contexts.filter(c=>c.visible);
  if(!visible.length)return null;
  // MEMORY: Lazily rebuild rlCtx from textareas if previously released
  visible.forEach(c=>{if(!c.rlCtx&&c.textareas)c.rlCtx=_buildRlCtxFromData(c.textareas,c.accountLabel)});
  if(visible.length===1)return visible[0].rlCtx;

  // Merge all rlCtx fields
  const merged={vpcs:[],subnets:[],pubSubs:new Set(),rts:[],sgs:[],nacls:[],enis:[],
    igws:[],nats:[],vpces:[],instances:[],albs:[],tgs:[],peerings:[],vpns:[],
    volumes:[],snapshots:[],s3bk:[],zones:[],wafAcls:[],
    wafByAlb:{},tgByAlb:{},cfByAlb:{},
    rdsInstances:[],ecsServices:[],lambdaFns:[],ecacheClusters:[],redshiftClusters:[],
    cfDistributions:[],rbac:{roleAssignments:[],roleDefinitions:[]},
    instBySub:{},albBySub:{},eniBySub:{},
    rdsBySub:{},ecsBySub:{},lambdaBySub:{},
    subRT:{},subNacl:{},nsgByVnet:{},
    volByInst:{},snapByVol:{},ecacheByVpc:{},redshiftByVpc:{},
    tgwAttachments:[],recsByZone:{},_multiTenant:true,_accounts:new Set(),_regions:new Set(),_multiRegion:false};

  visible.forEach(ctx=>{
    const c=ctx.rlCtx;if(!c)return;
    if(c.rbac){
      merged.rbac.roleAssignments.push(...(c.rbac.roleAssignments||[]));
      merged.rbac.roleDefinitions.push(...(c.rbac.roleDefinitions||[]));
    }
    const tag=(r)=>{if(r){r._subscriptionId=r._subscriptionId||ctx.accountId;r._accountLabel=ctx.accountLabel;r._ctxColor=ctx.color}return r};

    // Arrays: tag and concat
    const arrayKeys=['vpcs','subnets','rts','sgs','nacls','enis','igws','nats','vpces',
      'instances','albs','tgs','peerings','vpns','volumes','snapshots','s3bk','zones','wafAcls',
      'rdsInstances','ecsServices','lambdaFns','ecacheClusters','redshiftClusters','cfDistributions','tgwAttachments'];
    arrayKeys.forEach(k=>{
      if(c[k]&&Array.isArray(c[k]))c[k].forEach(r=>{tag(r);merged[k].push(r)});
    });

    // Sets
    if(c.pubSubs)c.pubSubs.forEach(s=>merged.pubSubs.add(s));
    if(c._accounts)c._accounts.forEach(a=>merged._accounts.add(a));
    merged._accounts.add(ctx.accountId);
    if(c._regions)c._regions.forEach(r=>merged._regions.add(r));
    if(ctx._isRegion&&ctx.region)merged._regions.add(ctx.region);

    // Object lookups: merge entries
    const mapKeys=['instBySub','albBySub','eniBySub','rdsBySub','ecsBySub','lambdaBySub',
      'subRT','subNacl','nsgByVnet','volByInst','snapByVol','ecacheByVpc','redshiftByVpc',
      'wafByAlb','tgByAlb','cfByAlb','recsByZone'];
    mapKeys.forEach(k=>{
      if(!c[k])return;
      const src=c[k];
      const keys=src instanceof Map?[...src.keys()]:Object.keys(src);
      keys.forEach(key=>{
        const val=src instanceof Map?src.get(key):src[key];
        if(Array.isArray(val)){
          if(!merged[k][key])merged[k][key]=[];
          val.forEach(v=>merged[k][key].push(v));
        }else{
          if(!merged[k][key])merged[k][key]=val;
        }
      });
    });
  });

  merged._multiRegion=merged._regions.size>1;
  if(typeof parseRBACData==='function')merged.rbac=parseRBACData(merged.rbac);
  return merged;
}

function enterMultiView(){
  if(_multiViewMode)return;
  if(!_loadedContexts.length){multiAccountNotify('No accounts loaded');return}
  _multiViewMode=true;
  _singleCtxBackup=multiAccountData();
  _remergeAndRender();
  document.getElementById('mergeBanner').style.display='flex';
  var mainEl=_getMain();if(mainEl)mainEl.classList.add('merge-active');
  document.getElementById('mergeViewBtn').textContent='Exit Merge';
  _renderAccountPanel();
}

function exitMultiView(options){
  if(!_multiViewMode)return;
  ++_mergeRenderGeneration;
  _multiViewMode=false;
  _mergedCtx=null;
  _prebuiltCtx=null;
  if(_singleCtxBackup){setMultiAccountData(_singleCtxBackup);_singleCtxBackup=null}
  document.getElementById('mergeBanner').style.display='none';
  var mainEl=_getMain();if(mainEl)mainEl.classList.remove('merge-active');
  document.getElementById('mergeViewBtn').textContent='Merge View';
  if(!options||options.render!==false)renderMap(()=>{_autoSaveSession();_parseCache={}});
  _renderAccountPanel();
}

function _mergeResourcePayloads(a,b){
  if(Array.isArray(a)&&Array.isArray(b))return a.concat(b);
  // Native CLI arrays and ARM value wrappers can appear in the same upload set.
  if(Array.isArray(a)&&b&&Array.isArray(b.value))return a.concat(b.value);
  if(a&&Array.isArray(a.value)&&Array.isArray(b))return a.value.concat(b);
  if(a&&b&&typeof a==='object'&&typeof b==='object'&&!Array.isArray(a)&&!Array.isArray(b)){
    const merged={...a};
    Object.keys(b).forEach(k=>{merged[k]=Array.isArray(a[k])&&Array.isArray(b[k])?a[k].concat(b[k]):b[k]});
    return merged;
  }
  return b;
}

function _remergeAndRender(){
  const generation=++_mergeRenderGeneration;
  const isCurrentMerge=()=>_multiViewMode&&generation===_mergeRenderGeneration;
  _mergedCtx=mergeContexts(_loadedContexts);
  if(!_mergedCtx){
    setMultiAccountData(null);_prebuiltCtx=null;_singleCtxBackup=null;
    _iamData=null;_iamReviewData=[];
    GovernanceClassification.reset();_budrAssessments=[];_budrFindings=[];
    _budrCachedAssessments=null;_budrCachedFindings=null;
    _complianceDataFP='';_complianceCachedFindings=null;
    if(typeof invalidateComplianceCache==='function')invalidateComplianceCache();
    resetMultiAccountComplianceRows();
    document.querySelectorAll('.ji').forEach(el=>{el.value='';el.className='ji'});
    document.getElementById('detailPanel').classList.remove('open');
    if(typeof _closeAllDashboardsExcept==='function')_closeAllDashboardsExcept(null);
    _renderMergeBannerChips();
    renderMap(()=>{
      if(!isCurrentMerge())return;
      ['statsBar','legend','bottomToolbar'].forEach(id=>document.getElementById(id).style.display='none');
      _autoSaveSession(true);_parseCache={};
    });
    return;
  }
  if(_mergedCtx){
    setMultiAccountData(_mergedCtx);
    // Clear dashboard caches so they re-run with merged context
    GovernanceClassification.reset();_budrAssessments=[];_iamData=null;_iamReviewData=[];
    _complianceDataFP='';_complianceCachedFindings=null;
    if(typeof invalidateComplianceCache==='function')invalidateComplianceCache();else{resetMultiAccountComplianceRows()}
    // PERF: Fill textareas for sidebar display: chunked via requestIdleCallback
    const _fillTextareasForDisplay=()=>{
      if(!isCurrentMerge())return;
      const mergedTA={};
      _loadedContexts.filter(c=>c.visible).forEach(c=>{
        Object.entries(c.textareas||{}).forEach(([id,val])=>{
          if(id==='in_iam')return; // IAM filled separately: skip to avoid serializing 100MB+
          const existing=mergedTA[id];
          if(existing){
            try{
              const a=typeof existing==='object'?existing:safeParse(existing);
              const b=typeof val==='object'?val:safeParse(val);
              mergedTA[id]=_mergeResourcePayloads(a,b);
            }catch(e2){mergedTA[id]=val}
          }else{mergedTA[id]=val}
        });
      });
      // Chunk DOM writes via requestIdleCallback to avoid blocking main thread
      const els=[...document.querySelectorAll('.ji')].filter(el=>el.id!=='in_iam');
      const CHUNK=8;
      let idx=0;
      const writeChunk=(deadline)=>{
        if(!isCurrentMerge())return;
        while(idx<els.length&&(typeof deadline==='undefined'||deadline.timeRemaining()>2)){
          const el=els[idx++];
          if(mergedTA[el.id]){
            el.value=typeof mergedTA[el.id]==='string'?mergedTA[el.id]:JSON.stringify(mergedTA[el.id]);
            el.className='ji valid';
          }else{el.value='';el.className='ji'}
          if(idx%CHUNK===0&&typeof deadline!=='undefined')break;
        }
        if(idx<els.length){
          if(typeof requestIdleCallback==='function')requestIdleCallback(writeChunk);
          else setTimeout(()=>writeChunk(),16);
        }else if(typeof _autoSaveSession==='function')_autoSaveSession(true);
      };
      if(typeof requestIdleCallback==='function')requestIdleCallback(writeChunk);
      else setTimeout(()=>writeChunk(),16);
    };
    // Merge IAM data directly into _iamData: avoids serializing 100MB+ to textarea
    let mergedIAM=null;
    _loadedContexts.filter(c=>c.visible).forEach(c=>{
      const val=c.textareas?.in_iam;if(!val)return;
      const b=typeof val==='object'?val:safeParse(val);if(!b||typeof b!=='object')return;
      if(!mergedIAM){mergedIAM=b;return}
      const allKeys=new Set([...Object.keys(mergedIAM),...Object.keys(b)]);
      allKeys.forEach(k=>{
        if(Array.isArray(mergedIAM[k])&&Array.isArray(b[k]))mergedIAM[k]=mergedIAM[k].concat(b[k]);
        else if(b[k]!==undefined)mergedIAM[k]=b[k];
      });
    });
    if(mergedIAM){
      _iamData=parseIAMData(mergedIAM);
      // Defer textarea fill: compliance engine uses _iamData directly
      const _iamTA=document.getElementById('in_iam');
      if(_iamTA){
        const fillIAM=()=>{if(isCurrentMerge()){_iamTA.value=JSON.stringify(mergedIAM);_iamTA.className='ji valid'}};
        if(typeof requestIdleCallback==='function')requestIdleCallback(fillIAM);
        else setTimeout(fillIAM,16);
      }
    }
    if(_mergedCtx.rbac)_iamData=parseIAMData(_mergedCtx.rbac);
    // PERF: Set prebuilt context so _renderMapInner skips textarea parsing
    _prebuiltCtx=_mergedCtx;
    // MEMORY: Release per-account rlCtx: merged copy has all data
    _loadedContexts.forEach(c=>{c.rlCtx=null});
    _renderMergeBannerChips();
    renderMap(()=>{if(!isCurrentMerge())return;_autoSaveSession();_parseCache={};_fillTextareasForDisplay()});
  }
}

function _renderMergeBannerChips(){
  const box=document.getElementById('mergeAcctChips');if(!box)return;
  box.textContent='';
  _loadedContexts.forEach((ctx,i)=>{
    const chip=document.createElement('span');
    chip.className='merge-acct-chip'+(ctx.visible?'':' hidden-chip');
    chip.title=(ctx.visible?'Click to hide':'Click to show')+': '+ctx.accountLabel;
    const dot=document.createElement('span');dot.className='mac-dot';dot.style.background=ctx.color||'var(--text-muted)';
    const lbl=document.createElement('span');lbl.style.color=ctx.visible?'var(--text-primary)':'var(--text-muted)';
    lbl.textContent=ctx.accountLabel;
    chip.appendChild(dot);chip.appendChild(lbl);
    chip.addEventListener('click',()=>{toggleAccountVisibility(i)});
    box.appendChild(chip);
  });
}

function toggleAccountVisibility(index){
  if(index<0||index>=_loadedContexts.length)return;
  _loadedContexts[index].visible=!_loadedContexts[index].visible;
  if(_multiViewMode)_remergeAndRender();
  _renderAccountPanel();
}

function _renderAccountPanel(){
  const body=document.getElementById('accountPanelBody');
  if(!_loadedContexts.length){
    body.innerHTML='<div style="text-align:center;padding:30px 10px;color:var(--text-muted);font-size:11px;font-family:Segoe UI,system-ui,sans-serif"><div style="font-size:24px;margin-bottom:10px;opacity:.4">&#128203;</div>No subscriptions loaded.<br>Click <b>+ Add</b> to load an .azuremap file<br>or <b>Capture Current</b> to add current data.</div>';
    return;
  }
  let h='';
  _loadedContexts.forEach((ctx,i)=>{
    const visClass=ctx.visible?'':'hidden-acct';
    h+='<div class="account-card" style="'+(ctx.visible?'':'opacity:.5')+'">';
    h+='<div class="ac-top">';
    h+='<div class="account-color-dot" style="background:'+(ctx.color||'var(--text-muted)')+'"></div>';
    h+='<span class="ac-label" title="'+esc(ctx.accountId)+'">'+esc(ctx.accountLabel)+'</span>';
    h+='<span class="ac-region"'+(ctx._isRegion?' style="color:#60a5fa"':'')+'>'+esc(ctx.region)+'</span>';
    h+='</div>';
    h+='<div class="ac-meta">';
    if(ctx.rlCtx){
      const vc=(ctx.rlCtx.vpcs||[]).length;
      const sc=(ctx.rlCtx.subnets||[]).length;
      const ic=(ctx.rlCtx.instances||[]).length;
      h+=vc+' VNet'+(vc!==1?'s':'')+' &middot; '+sc+' Subnet'+(sc!==1?'s':'')+' &middot; '+ic+' VM'+(ic!==1?'s':'');
    }else if(_importedReportData){
      var aid=ctx.accountId;
      var fc=multiAccountComplianceRows().filter(function(f){return(f._subscriptionId||'')===aid}).length;
      var bc=(_budrAssessments||[]).filter(function(a){return(a.account||'')===aid}).length;
      var nc=(_inventoryData||[]).filter(function(r){return(r.account||'')===aid}).length;
      var parts=[];
      if(fc)parts.push(fc+' finding'+(fc!==1?'s':''));
      if(bc)parts.push(bc+' BUDR');
      if(nc)parts.push(nc+' resource'+(nc!==1?'s':''));
      h+=parts.length?parts.join(' &middot; '):'Imported data';
    }else{
      h+='0 VNets &middot; 0 Subnets &middot; 0 VMs';
    }
    h+='</div>';
    h+='<div class="ac-actions">';
    h+='<button class="account-toggle '+visClass+'" onclick="toggleAccountVisibility('+i+')">'+(ctx.visible?'Hide':'Show')+'</button>';
    h+='<button class="account-toggle" onclick="removeAccountContext('+i+')" style="color:var(--accent-red);border-color:var(--accent-red)">Remove</button>';
    h+='</div>';
    h+='</div>';
  });
  body.innerHTML=h;
}

function openAccountPanel(){
  document.getElementById('accountPanel').classList.add('open');
}

function closeAccountPanel(){
  document.getElementById('accountPanel').classList.remove('open');
}

function _toggleAccountPanel(){
  const p=document.getElementById('accountPanel');
  if(p.classList.contains('open'))closeAccountPanel();
  else openAccountPanel();
}

// Account panel event listeners
document.getElementById('accountsBtn').addEventListener('click',_toggleAccountPanel);
document.getElementById('reportsBtn').addEventListener('click',function(){openReportBuilder()});
document.getElementById('compDashBtn').addEventListener('click',function(){
  const findings=multiAccountComplianceRows();
  if(findings.length)renderCompliancePanel(findings);
  else multiAccountNotify('No compliance data: run compliance scan first');
});
document.getElementById('accountPanelClose').addEventListener('click',closeAccountPanel);
document.getElementById('addAccountBtn').addEventListener('click',()=>document.getElementById('addAccountInput').click());
document.getElementById('addAccountInput').addEventListener('change',function(){
  if(!this.files[0])return;
  const file=this.files[0];
  const reader=new FileReader();
  reader.onload=function(e){
    try{
      const data=JSON.parse(e.target.result);
      if(!data.textareas&&!data._format&&!data.json_data){
        multiAccountNotify('Invalid .azuremap file');return;
      }
      // v2.0 multi-account file
      if(data._version==='2.0'&&data.accounts&&data.accounts.length){
        data.accounts.forEach(acct=>{
          addAccountContext({textareas:acct.textareas,accountLabel:acct.label||acct.id},acct.label||acct.id);
        });
      }else{
        // v1.0 single account
        addAccountContext(data,data.accountLabel||file.name.replace('.azuremap',''));
      }
    }catch(ex){multiAccountNotify('Failed to parse file: '+ex.message)}
  };
  reader.readAsText(file);
  this.value='';
});
document.getElementById('mergeViewBtn').addEventListener('click',function(){
  if(_multiViewMode)exitMultiView();
  else enterMultiView();
});
document.getElementById('mergeExitBtn').addEventListener('click',exitMultiView);
document.getElementById('mergeBannerCollapse').addEventListener('click',function(){
  var banner=document.getElementById('mergeBanner');
  var chips=document.getElementById('mergeAcctChips');
  var exitBtn=document.getElementById('mergeExitBtn');
  var label=document.getElementById('mergeBannerLabel');
  if(banner.classList.contains('collapsed')){
    banner.classList.remove('collapsed');chips.style.display='flex';exitBtn.style.display='';label.textContent='MULTI-ACCOUNT VIEW';this.textContent='▲';this.title='Collapse banner';
  }else{
    banner.classList.add('collapsed');chips.style.display='none';exitBtn.style.display='none';label.textContent='MERGE';this.textContent='▼';this.title='Expand banner';
  }
});
document.getElementById('captureCurrentBtn').addEventListener('click',function(){
  const ctx=_captureCurrentAsContext();
  if(!ctx){multiAccountNotify('Render map first before capturing');return}
  const colorIdx=_loadedContexts.length%_accountColors.length;
  ctx.color=_accountColors[colorIdx];
  if(ctx.accountId&&ctx.accountId!=='default')_accountColorMap[ctx.accountId]=ctx.color;
  _loadedContexts.push(ctx);
  _renderAccountPanel();
  multiAccountNotify('Captured current context as account: '+ctx.accountLabel);
});

// #endregion MULTI-ACCOUNT

