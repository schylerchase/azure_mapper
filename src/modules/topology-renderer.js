// #region TOPOLOGY RENDERER
// Landing Zone Hub-Spoke D3 Layout
var topologyLandingZoneUnlockHandler = null;
var topologyGridUnlockHandler = null;

function topologyRuntimeContext(){
  return AppRenderContext.createRenderContext();
}

function topologyPublishRuntimeContext(ctx){
  ctx=topologyAzureContext(ctx);
  topologyRuntimeContext().rlCtx = ctx;
  return ctx;
}

function topologyAzureContext(ctx){
  if(ctx.vnets!==undefined&&ctx.nsgs!==undefined&&ctx.vms!==undefined)return ctx;
  const result={...ctx};
  [['vnets','vpcs'],['udrs','rts'],['nsgs','sgs'],['subnetNsgs','nacls'],['nics','enis'],['firewalls','igws'],['natGateways','nats'],['privateEndpoints','vpces'],['vms','instances'],['appGateways','albs'],['sqlServers','rdsInstances'],['containerInstances','ecsServices'],['functionApps','lambdaFns'],['redisCaches','ecacheClusters'],['synapseWorkspaces','redshiftClusters'],['vhubs','tgwAttachments'],['recsByZone','recsByZoneMap']].forEach(([azure,legacy])=>{if(result[azure]===undefined)result[azure]=ctx[legacy]||[]});
  return result;
}

function topologyPublishSecurityGroups(groups){
  var lookup = new Map();
  (groups || []).forEach(function(group){
    if(group && group.GroupId) lookup.set(group.GroupId, group);
  });
  topologyRuntimeContext().securityGroupsById = lookup;
  return lookup;
}

function topologyComplianceFindings(ctx){
  return _runComplianceWithCache(topologyAzureContext(ctx)) || [];
}

function topologyNotify(message,type){
  AppNotifications.show(message,type);
}

function topologySetUnlockHandler(slot,handler){
  var previous = slot === 'landing-zone'
    ? topologyLandingZoneUnlockHandler
    : topologyGridUnlockHandler;
  if(previous) document.removeEventListener('hl-unlock', previous);
  if(slot === 'landing-zone') topologyLandingZoneUnlockHandler = handler;
  else topologyGridUnlockHandler = handler;
  document.addEventListener('hl-unlock', handler);
}

function topologySetGatewayHighlighter(handler){
  MapViewport.setGatewayHighlighter(handler);
}

function topologyOpenResourceSpotlight(resourceId){
  if(typeof ResourceNavigation!=='undefined'&&ResourceNavigation.openSpotlight){
    ResourceNavigation.openSpotlight(resourceId);
  }
}

function topologyCloseResourceSpotlight(){
  if(typeof ResourceNavigation!=='undefined'&&ResourceNavigation.closeSpotlight){
    ResourceNavigation.closeSpotlight();
  }
}

function topologyIsResourceSpotlightOpen(){
  return typeof ResourceNavigation!=='undefined'
    && ResourceNavigation.isSpotlightActive
    && ResourceNavigation.isSpotlightActive();
}

// Azure route helpers: detect internet/NAT/VPN routes from both AWS and Azure formats
function _isIgwRoute(gwId){return gwId&&(gwId.startsWith('igw-')||gwId==='Internet')}
function _isNatRoute(gwId){return gwId&&(gwId.startsWith('nat-')||gwId==='VirtualAppliance'||gwId==='NatGateway')}
function _isVpnRoute(gwId){return gwId&&(gwId.startsWith('vgw-')||gwId==='VirtualNetworkGateway')}
function _gwTypeLabel(gwId){if(_isIgwRoute(gwId))return'Internet';if(_isNatRoute(gwId))return'NAT/NVA';if(_isVpnRoute(gwId))return'VPN Gateway';if(gwId&&gwId.startsWith('tgw-'))return'Virtual WAN';if(gwId&&gwId.startsWith('pcx-'))return'VNet Peering';if(gwId==='VnetLocal')return'VNet Local';return gwId||'Unknown'}

// Shared Azure normalization — extracted to src/modules/normalization.js

var _renderMapTimer=null;
var _prebuiltCtx=null;
var _parseCache={};
function _quickHash(s){let h=5381;for(let i=0;i<s.length;i++){h=((h<<5)+h+s.charCodeAt(i))|0}return h}
function _cachedParse(id){
  const el=document.getElementById(id);
  const val=el?el.value:'';
  if(!val||!val.trim()){delete _parseCache[id];return null}
  const hash=_quickHash(val);
  if(_parseCache[id]&&_parseCache[id].hash===hash)return _parseCache[id].parsed;
  const parsed=safeParse(val);
  _parseCache[id]={hash:hash,parsed:parsed};
  return parsed;
}
function invalidateParseCache(){_parseCache={}}
function renderMap(cb){
  _importedReportData=null;
  if(_renderMapTimer){clearTimeout(_renderMapTimer);_renderMapTimer=null}
  // In merge mode, always use the prebuilt merged context (avoid textarea re-parse divergence)
  if(_multiViewMode&&_mergedCtx&&!_prebuiltCtx)_prebuiltCtx=_mergedCtx;
  const overlay=document.getElementById('loadingOverlay');
  overlay.style.display='flex';
  _renderMapTimer=setTimeout(()=>{
    _renderMapTimer=null;
    requestAnimationFrame(()=>{requestAnimationFrame(()=>{_renderMapInner();overlay.style.display='none';if(typeof cb==='function')cb()})});
  },50);
}
function _renderMapInner(){
  try{
  const svg=d3.select('#mapSvg');svg.selectAll('*').remove();svg.style('display','block');
  // SVG filter to prevent alpha stacking in route groups
  const defs=svg.append('defs');
  defs.append('filter').attr('id','alphaClamp')
    .append('feComponentTransfer')
    .append('feFuncA').attr('type','table').attr('tableValues','0 1 1 1');
  document.getElementById('emptyState').style.display='none';
  document.getElementById('landingDash').style.display='none';

  // PERF: If a prebuilt context exists (from merge), use it directly: skip all parsing
  let vpcs,subnets,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns;
  let volumes,snapshots,s3bk,zones,wafAcls,rdsInstances,ecsServices,lambdaFns;
  let ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions;
  let rbac=null;
  let recsByZoneMap={};
  const userAccount=(document.getElementById('accountLabel')||{}).value||'';
  let _pbMaps=null; // prebuilt index maps (skip rebuild when available)
  if(_prebuiltCtx){
    const pc=_prebuiltCtx;_prebuiltCtx=null;
    rbac=pc.rbac||null;
    vpcs=pc.vpcs||[];subnets=pc.subnets||[];rts=pc.rts||[];sgs=pc.sgs||[];
    nacls=pc.nacls||[];enis=pc.enis||[];igws=pc.igws||[];nats=pc.nats||[];
    vpces=pc.vpces||[];instances=pc.instances||[];albs=pc.albs||[];tgs=pc.tgs||[];
    peerings=pc.peerings||[];vpns=pc.vpns||[];volumes=pc.volumes||[];snapshots=pc.snapshots||[];
    s3bk=pc.s3bk||[];zones=pc.zones||[];wafAcls=pc.wafAcls||[];
    rdsInstances=pc.rdsInstances||[];ecsServices=pc.ecsServices||[];
    lambdaFns=pc.lambdaFns||[];ecacheClusters=pc.ecacheClusters||[];
    redshiftClusters=pc.redshiftClusters||[];tgwAttachments=pc.tgwAttachments||[];
    cfDistributions=pc.cfDistributions||[];recsByZoneMap=pc.recsByZone||{};
    _pbMaps={instBySub:pc.instBySub||{},albBySub:pc.albBySub||{},eniBySub:pc.eniBySub||{},
      rdsBySub:pc.rdsBySub||{},ecsBySub:pc.ecsBySub||{},lambdaBySub:pc.lambdaBySub||{},
      nsgByVnet:pc.nsgByVnet||{},volByInst:pc.volByInst||{},snapByVol:pc.snapByVol||{},
      ecacheByVpc:pc.ecacheByVpc||{},redshiftByVpc:pc.redshiftByVpc||{},
      wafByAlb:pc.wafByAlb||{},tgByAlb:pc.tgByAlb||{},cfByAlb:pc.cfByAlb||{}};
  }else{
  // parse all Azure inputs (cached: skips JSON.parse if textarea unchanged)
  vpcs=ext(_cachedParse('in_vnets'),['value','VirtualNetworks']);
  subnets=ext(_cachedParse('in_subnets'),['value','Subnets']);
  rts=ext(_cachedParse('in_udrs'),['value','RouteTables']);
  sgs=ext(_cachedParse('in_nsgs'),['value','SecurityGroups']);
  nacls=[];// NACLs not used in Azure
  enis=ext(_cachedParse('in_nics'),['value','NetworkInterfaces']);
  igws=ext(_cachedParse('in_azfws'),['value']);
  nats=ext(_cachedParse('in_nats'),['value','NatGateways']);
  vpces=ext(_cachedParse('in_pvteps'),['value','PrivateEndpoints']);
  instances=[];
  const eRaw=_cachedParse('in_vms');
  if(eRaw){
    const vmList=ext(eRaw,['value']);
    if(vmList.length){vmList.forEach(r=>{if(r.id||r.name)instances.push(r)})}
    else{const arr=Array.isArray(eRaw)?eRaw:[eRaw];arr.forEach(x=>{if(x.id||x.InstanceId)instances.push(x)})}
  }
  albs=ext(_cachedParse('in_albs'),['value','LoadBalancers']);
  tgs=ext(_cachedParse('in_tgs'),['value','TargetGroups']);
  peerings=ext(_cachedParse('in_peer'),['value','VnetPeerings']);
  vpns=ext(_cachedParse('in_vpn'),['value','VpnConnections']);
  volumes=ext(_cachedParse('in_disks'),['value','Disks']);
  snapshots=ext(_cachedParse('in_snaps'),['value','Snapshots']);
  let s3raw=_cachedParse('in_storage');s3bk=s3raw?ext(s3raw,['value','StorageAccounts']):[];
  zones=ext(_cachedParse('in_dnsz'),['value','DnsZones']);
  const allRecSets=ext(_cachedParse('in_r53records'),['value','RecordSets']);
  allRecSets.forEach(r=>{if(r.HostedZoneId||r.zoneId)(recsByZoneMap[r.HostedZoneId||r.zoneId]=recsByZoneMap[r.HostedZoneId||r.zoneId]||[]).push(r)});
  wafAcls=ext(_cachedParse('in_waf'),['value','WafPolicies']);
  rdsInstances=ext(_cachedParse('in_sql'),['value','SqlServers']);
  ecsServices=ext(_cachedParse('in_containers'),['value','ContainerGroups']);
  lambdaFns=(ext(_cachedParse('in_funcapps'),['value'])).filter(f=>f.kind||f.name);
  ecacheClusters=ext(_cachedParse('in_elasticache'),['value','RedisCaches']);
  redshiftClusters=ext(_cachedParse('in_aks'),['value','AksClusters']).concat(ext(_cachedParse('in_synapse'),['value','SynapseWorkspaces']));
  tgwAttachments=ext(_cachedParse('in_tgwatt'),['value','VirtualWans']);
  cfDistributions=[];
  const cfRaw=_cachedParse('in_cf');
  if(cfRaw){const dl=cfRaw.value||cfRaw;cfDistributions=dl.FrontDoors||dl.Items||(Array.isArray(dl)?dl:[]);}
  // Parse RBAC data
  const iamRaw=_cachedParse('in_rbac');
  _iamData=iamRaw?parseIAMData(iamRaw):null;
  rbac=typeof parseRBACData==='function'?parseRBACData(iamRaw):null;
  function tagResource(r){if(!r)return r;r._subscriptionId=detectAccountId(r)||userAccount||'default';r._region=detectRegion(r)||'unknown';return r}
  [vpcs,subnets,rts,sgs,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,wafAcls,rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions].forEach(arr=>arr.forEach(tagResource));
  // Azure normalization (shared with _buildRlCtxFromData)
  _normalizeAzureResources({vpcs,subnets,rts,sgs,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,wafAcls,rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions});
  } // end else (textarea parse path)
  const _regions=new Set();vpcs.forEach(v=>{if(v._region&&v._region!=='unknown')_regions.add(v._region)});
  const _multiRegion=_regions.size>1;
  // Deduplicate: if same VpcId from same account, keep last pasted
  const seenVpcs=new Map();const vpcDupes=[];
  vpcs.forEach(v=>{const key=v._subscriptionId+':'+v.VpcId;if(seenVpcs.has(key))vpcDupes.push(v.VpcId);seenVpcs.set(key,v)});
  if(vpcDupes.length)console.warn('Duplicate VPCs detected (kept latest):',vpcDupes);
  vpcs=[...seenVpcs.values()];
  // Collect unique accounts for rendering
  const _accounts=new Set();vpcs.forEach(v=>{if(v._subscriptionId&&v._subscriptionId!=='default')_accounts.add(v._subscriptionId)});
  // Replace 'default' fallback with the primary detected account ID
  if(_accounts.size===1){var _primaryAcct=[..._accounts][0];[vpcs,subnets,igws,nats,sgs,instances,albs,rdsInstances,ecsServices,lambdaFns,peerings].forEach(function(arr){arr.forEach(function(r){if(r&&r._subscriptionId==='default')r._subscriptionId=_primaryAcct})})}
  const _multiTenant=_accounts.size>1;

  if(!vpcs.length&&!subnets.length){
    if(_designMode){
      // Show design-aware empty state
      document.getElementById('landingDash').style.display='none';
      document.getElementById('emptyState').style.display='flex';
      document.getElementById('emptyTitle').textContent='Design Mode';
      document.getElementById('emptyDesc').textContent='No infrastructure loaded: create your first VPC to start designing';
      const eBtn=document.getElementById('emptyDesignBtn');
      eBtn.style.display='inline-block';
      eBtn.onclick=function(){showDesignForm('add_vpc',{})};
      svg.style('display','none');return;
    }
    document.getElementById('emptyTitle').textContent='No data loaded';
    document.getElementById('emptyDesc').textContent='Paste Azure CLI JSON exports and click Render Map';
    document.getElementById('emptyDesignBtn').style.display='none';
    document.getElementById('emptyState').style.display='none';document.getElementById('landingDash').style.display='flex';svg.style('display','none');return;
  }

  // lookups
  const subByVnet={};subnets.forEach(s=>(subByVnet[s.VpcId]=subByVnet[s.VpcId]||[]).push(s));
  const pubSubs=new Set(),subRT={},gwSet=new Map();

  // gateway name enrichment from dedicated JSON
  gwNames={};
  igws.forEach(g=>{gwNames[g.InternetGatewayId]=gn(g,g.InternetGatewayId)});
  nats.forEach(g=>{gwNames[g.NatGatewayId]=gn(g,g.NatGatewayId)});
  vpces.forEach(g=>{gwNames[g.VpcEndpointId]=gn(g,g.VpcEndpointId)});
  vpns.forEach(g=>{if(g.VpnGatewayId) gwNames[g.VpnGatewayId]=gn(g,g.VpnGatewayId)});
  peerings.forEach(g=>{gwNames[g.VpcPeeringConnectionId]=gn(g,g.VpcPeeringConnectionId)});
  tgwAttachments.forEach(g=>{if(g.TransitGatewayId&&!gwNames[g.TransitGatewayId]) gwNames[g.TransitGatewayId]=gn(g,g.TransitGatewayId)});

  // Build Main route table fallback per VPC
  const mainRT={};
  rts.forEach(rt=>{
    if((rt.Associations||[]).some(a=>a.Main)) mainRT[rt.VpcId]=rt;
  });

  // discover gateways from route tables
  rts.forEach(rt=>{
    const hasIgw=(rt.Routes||[]).some(r=>_isIgwRoute(r.GatewayId)&&r.State!=='blackhole');
    (rt.Associations||[]).forEach(a=>{if(a.SubnetId){subRT[a.SubnetId]=rt;if(hasIgw)pubSubs.add(a.SubnetId)}});
    (rt.Routes||[]).forEach(r=>{
      if(r.GatewayId&&r.GatewayId!=='local')gwSet.set(r.GatewayId,{type:clsGw(r.GatewayId),id:r.GatewayId,vpcId:rt.VpcId});
      if(r.NatGatewayId)gwSet.set(r.NatGatewayId,{type:'NAT',id:r.NatGatewayId,vpcId:rt.VpcId});
      if(r.TransitGatewayId)gwSet.set(r.TransitGatewayId,{type:'TGW',id:r.TransitGatewayId,vpcId:'shared'});
      if(r.VpcPeeringConnectionId)gwSet.set(r.VpcPeeringConnectionId,{type:'PCX',id:r.VpcPeeringConnectionId,vpcId:'shared'});
    });
  });

  // also pull gateways from dedicated JSON even if not in route tables
  igws.forEach(g=>{if(!gwSet.has(g.InternetGatewayId)){const v=(g.Attachments||[])[0];gwSet.set(g.InternetGatewayId,{type:'IGW',id:g.InternetGatewayId,vpcId:v?v.VpcId:'unk'})}});
  nats.forEach(g=>{if(!gwSet.has(g.NatGatewayId))gwSet.set(g.NatGatewayId,{type:'NAT',id:g.NatGatewayId,vpcId:g.VpcId||'unk'})});
  vpces.forEach(g=>{if(!gwSet.has(g.VpcEndpointId)){const t=g.VpcEndpointType==='Gateway'?'VPCE':'VPCE';gwSet.set(g.VpcEndpointId,{type:'VPCE',id:g.VpcEndpointId,vpcId:g.VpcId||'unk'})}});

  // Assign Main route table to subnets without explicit associations
  subnets.forEach(s=>{
    if(!subRT[s.SubnetId]&&mainRT[s.VpcId]){
      subRT[s.SubnetId]=mainRT[s.VpcId];
      const hasIgw=(mainRT[s.VpcId].Routes||[]).some(r=>_isIgwRoute(r.GatewayId)&&r.State!=='blackhole');
      if(hasIgw)pubSubs.add(s.SubnetId);
    }
  });

  const subNacl={};nacls.forEach(n=>(n.Associations||[]).forEach(a=>{if(a.SubnetId)subNacl[a.SubnetId]=n}));
  const nsgByVnet=_pbMaps?_pbMaps.nsgByVnet:(()=>{const m={};sgs.forEach(sg=>(m[sg.VpcId]=m[sg.VpcId]||[]).push(sg));return m})();
  // IAM role -> resource cross-references
  const iamRoleResources={};
  if(_iamData){
    (instances||[]).forEach(i=>{const pa=i.IamInstanceProfile?.Arn;if(pa){const rn=pa.split('/').pop();if(!iamRoleResources[rn])iamRoleResources[rn]={vms:[],functionApps:[],aks:[]};iamRoleResources[rn].vms.push(i)}});
    (lambdaFns||[]).forEach(fn=>{if(fn.Role){const rn=fn.Role.split('/').pop();if(!iamRoleResources[rn])iamRoleResources[rn]={vms:[],functionApps:[],aks:[]};iamRoleResources[rn].functionApps.push(fn)}});
    (ecsServices||[]).forEach(svc=>{const ra=svc.taskRoleArn||svc.executionRoleArn;if(ra){const rn=ra.split('/').pop();if(!iamRoleResources[rn])iamRoleResources[rn]={vms:[],functionApps:[],aks:[]};iamRoleResources[rn].aks.push(svc)}});
  }
  // PERF: reuse prebuilt indexes from merge context when available
  const instBySub=_pbMaps?_pbMaps.instBySub:(()=>{const m={};instances.forEach(i=>{if(i.SubnetId)(m[i.SubnetId]=m[i.SubnetId]||[]).push(i)});return m})();
  const eniByInst={};const eniBySub=_pbMaps?((()=>{enis.forEach(e=>{if(e.Attachment&&e.Attachment.InstanceId)(eniByInst[e.Attachment.InstanceId]=eniByInst[e.Attachment.InstanceId]||[]).push(e)});return _pbMaps.eniBySub})()):(()=>{const m={};enis.forEach(e=>{if(e.SubnetId)(m[e.SubnetId]=m[e.SubnetId]||[]).push(e);if(e.Attachment&&e.Attachment.InstanceId)(eniByInst[e.Attachment.InstanceId]=eniByInst[e.Attachment.InstanceId]||[]).push(e)});return m})();
  const albBySub=_pbMaps?_pbMaps.albBySub:(()=>{const m={};albs.forEach(lb=>{(lb.AvailabilityZones||[]).forEach(az=>{if(az.SubnetId)(m[az.SubnetId]=m[az.SubnetId]||[]).push(lb)})});return m})();
  const volByInst=_pbMaps?_pbMaps.volByInst:(()=>{const m={};volumes.forEach(v=>{(v.Attachments||[]).forEach(a=>{if(a.InstanceId)(m[a.InstanceId]=m[a.InstanceId]||[]).push(v)})});return m})();

  // volumes by subnet (always rebuild: needs eniByInst which is built above)
  const knownInstIds=new Set(instances.map(i=>i.InstanceId));
  const instSubFromEni={};enis.forEach(e=>{if(e.SubnetId&&e.Attachment&&e.Attachment.InstanceId)instSubFromEni[e.Attachment.InstanceId]=e.SubnetId});
  const volBySub={};volumes.forEach(v=>{
    const att=(v.Attachments||[])[0];
    if(att&&att.InstanceId){
      if(knownInstIds.has(att.InstanceId))return;
      const sid=instSubFromEni[att.InstanceId];
      if(sid)(volBySub[sid]=volBySub[sid]||[]).push(v);
    }
  });

  const snapByVol=_pbMaps?_pbMaps.snapByVol:(()=>{const m={};snapshots.forEach(s=>{if(s.VolumeId)(m[s.VolumeId]=m[s.VolumeId]||[]).push(s)});return m})();
  const tgByAlb=_pbMaps?_pbMaps.tgByAlb:(()=>{const m={};tgs.forEach(tg=>{(tg.LoadBalancerArns||[]).forEach(arn=>{(m[arn]=m[arn]||[]).push(tg)})});return m})();
  const wafByAlb=_pbMaps?_pbMaps.wafByAlb:(()=>{const m={};wafAcls.forEach(acl=>{(acl.ResourceArns||[]).forEach(arn=>{(m[arn]=m[arn]||[]).push(acl)})});return m})();
  const rdsBySub=_pbMaps?_pbMaps.rdsBySub:(()=>{const m={};rdsInstances.forEach(db=>{const sg=db.DBSubnetGroup;if(!sg)return;(sg.Subnets||[]).forEach(s=>{if(s.SubnetIdentifier)(m[s.SubnetIdentifier]=m[s.SubnetIdentifier]||[]).push(db)})});return m})();
  const ecsBySub=_pbMaps?_pbMaps.ecsBySub:(()=>{const m={};ecsServices.forEach(svc=>{const nc=svc.networkConfiguration?.awsvpcConfiguration;if(!nc)return;(nc.subnets||[]).forEach(sid=>{(m[sid]=m[sid]||[]).push(svc)})});return m})();
  const lambdaBySub=_pbMaps?_pbMaps.lambdaBySub:(()=>{const m={};lambdaFns.forEach(fn=>{(fn.VpcConfig?.SubnetIds||[]).forEach(sid=>{(m[sid]=m[sid]||[]).push(fn)})});return m})();
  const ecacheByVpc=_pbMaps?_pbMaps.ecacheByVpc:(()=>{const m={};ecacheClusters.forEach(c=>{if(c.VpcId)(m[c.VpcId]=m[c.VpcId]||[]).push(c)});return m})();
  const redshiftByVpc=_pbMaps?_pbMaps.redshiftByVpc:(()=>{const m={};redshiftClusters.forEach(c=>{if(c.VpcId)(m[c.VpcId]=m[c.VpcId]||[]).push(c)});return m})();
  const cfByAlb=_pbMaps?_pbMaps.cfByAlb:(()=>{const m={};cfDistributions.forEach(d=>{(d.Origins?.Items||[]).forEach(o=>{const matchAlb=albs.find(a=>a.DNSName&&o.DomainName&&o.DomainName.includes(a.DNSName));if(matchAlb)(m[matchAlb.LoadBalancerArn]=m[matchAlb.LoadBalancerArn]||[]).push(d)})});return m})();

  // separate per-VPC vs shared gateways; VPCEs always go to summary only
  const pvGws={},shGws=[],vpceByVpc={},vpceIds=new Set();
  [...gwSet.values()].forEach(gw=>{
    if(gw.type==='VPCE'){(vpceByVpc[gw.vpcId]=vpceByVpc[gw.vpcId]||[]).push(gw);vpceIds.add(gw.id);return}
    if(isShared(gw.type)){if(!shGws.find(g=>g.id===gw.id))shGws.push(gw)}
    else(pvGws[gw.vpcId]=pvGws[gw.vpcId]||[]).push(gw);
  });
  const storageTopology=_buildStorageTopology(s3bk,vpces);
  const storageBySub=storageTopology.bySub;

  // Check layout mode
  const layoutMode=document.getElementById('layoutMode')?.value||'grid';
  
  if(layoutMode==='landingzone'){
    // LANDING ZONE HUB-SPOKE LAYOUT
    renderLandingZoneMap({
      rbac,
      vpcs,subnets,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,
      subByVnet,pubSubs,subRT,gwSet,subNacl,nsgByVnet,instBySub,eniBySub,eniByInst,albBySub,volByInst,volBySub,pvGws,shGws,vpceByVpc,vpceIds,gwNames,
      snapByVol,tgByAlb,wafAcls,wafByAlb,
      rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions,
      rdsBySub,ecsBySub,lambdaBySub,ecacheByVpc,redshiftByVpc,cfByAlb,_multiTenant,_accounts,iamRoleResources
    });
    return;
  }
  
  if(layoutMode==='executive'){
    renderExecutiveOverview({
      rbac,_multiTenant,_accounts,
      _regions,_multiRegion,recsByZoneMap,iamRoleResources,eniByInst,storageTopology,storageBySub,
      vpcs,subnets,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,
      subByVnet,pubSubs,subRT,gwSet,subNacl,nsgByVnet,instBySub,eniBySub,albBySub,volByInst,pvGws,shGws,vpceByVpc,vpceIds,gwNames,
      snapByVol,tgByAlb,wafAcls,wafByAlb,
      rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions,
      rdsBySub,ecsBySub,lambdaBySub,ecacheByVpc,redshiftByVpc,cfByAlb
    });
    return;
  }

  renderGridTopologyMap({
    rbac,
    svg,
    vpcs,subnets,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,
    wafAcls,rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions,
    recsByZoneMap,subByVnet,pubSubs,subRT,gwSet,subNacl,nsgByVnet,iamRoleResources,
    instBySub,eniByInst,eniBySub,albBySub,volByInst,volBySub,snapByVol,tgByAlb,wafByAlb,rdsBySub,ecsBySub,lambdaBySub,
    ecacheByVpc,redshiftByVpc,cfByAlb,pvGws,shGws,vpceByVpc,vpceIds,gwNames,storageTopology,storageBySub,
    _regions,_multiRegion,_multiTenant,_accounts
  });
  }catch(e){console.error('renderMap error:',e);topologyNotify('Render error: '+e.message,'error');document.getElementById('loadingOverlay').style.display='none'}
}

document.getElementById('renderBtn').addEventListener('click',function(){
  renderMap(()=>{_autoSaveSession()});
});

// #endregion TOPOLOGY RENDERER

