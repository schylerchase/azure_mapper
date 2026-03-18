// Network topology visualization and D3 graph rendering
// Handles VNet diagram layout, subnet positioning, and resource visualization
// TODO: convert to ES module — export renderMap, _renderMapInner and import
// dependencies (d3, _rlCtx, _designMode, etc.) instead of reading globals

// --- Label collision detection & resolution utilities ---
function _rectsOverlap(a, b, pad) {
  pad = pad || 2;
  return !(a.x + a.w + pad < b.x || b.x + b.w + pad < a.x ||
           a.y + a.h + pad < b.y || b.y + b.h + pad < a.y);
}

function _resolveCollisions(labels, opts) {
  opts = opts || {};
  const strategy = opts.strategy || 'shift-y';
  const padding = opts.padding || 4;
  const maxIter = opts.maxIter || 8;

  for (let iter = 0; iter < maxIter; iter++) {
    let moved = false;
    for (let i = 0; i < labels.length; i++) {
      for (let j = i + 1; j < labels.length; j++) {
        const a = labels[i], b = labels[j];
        if (!_rectsOverlap(a, b, padding)) continue;
        if (strategy === 'shift-y') {
          const overlapY = (a.y + a.h + padding) - b.y;
          if (overlapY > 0) { b.y += overlapY; moved = true; }
        } else if (strategy === 'shift-x') {
          const overlapX = (a.x + a.w + padding) - b.x;
          if (overlapX > 0) { b.x += overlapX; moved = true; }
        }
      }
    }
    if (!moved) break;
  }
  return labels;
}

function _applyLabelPositions(labels) {
  labels.forEach(l => {
    if (l.rectNode) {
      l.rectNode.attr('x', l.x).attr('y', l.y);
      if (l.w) l.rectNode.attr('width', l.w);
    }
    if (l.textNode) {
      const tx = l.textAnchor === 'middle' ? l.x + l.w / 2 : l.x + (l.textPadX || 0);
      l.textNode.attr('x', tx).attr('y', l.y + (l.textOffY || 12));
    }
  });
}

function _dynamicResCols(subnetW) {
  const minIconW = 70;
  const padded = subnetW - 16;
  return Math.max(1, Math.floor(padded / (minIconW + 4)));
}

function renderMap(cb){
  if(_renderMapTimer){clearTimeout(_renderMapTimer);_renderMapTimer=null}
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

  // parse all Azure resource inputs (cached — skips JSON.parse if textarea unchanged)
  let vnets=ext(_cachedParse('in_vnets'),['value']);
  let subnets=ext(_cachedParse('in_subnets'),['value']);
  let udrs=ext(_cachedParse('in_udrs'),['value']);
  let nsgs=ext(_cachedParse('in_nsgs'),['value']);
  let nics=ext(_cachedParse('in_nics'),['value']);
  let firewalls=ext(_cachedParse('in_azfws'),['value']);
  let bastions=ext(_cachedParse('in_bastions'),['value']);
  let natGateways=ext(_cachedParse('in_nats'),['value']);
  let privateEndpoints=ext(_cachedParse('in_pvteps'),['value']);
  let vms=[];
  const vmRaw=_cachedParse('in_vms');
  if(vmRaw){
    const flat=ext(vmRaw,['value']);
    if(flat.length)vms=flat;
    else{const arr=Array.isArray(vmRaw)?vmRaw:[vmRaw];arr.forEach(x=>{if(x.id)vms.push(x)})}
  }
  let appGateways=ext(_cachedParse('in_albs'),['value']);
  let loadBalancers=ext(_cachedParse('in_tgs'),['value']);
  let peerings=ext(_cachedParse('in_peer'),['value']);
  let vpnConnections=ext(_cachedParse('in_vpn'),['value']);
  let managedDisks=ext(_cachedParse('in_disks'),['value']);
  let diskSnapshots=ext(_cachedParse('in_snaps'),['value']);
  let storageRaw=_cachedParse('in_storage');let storageAccounts=storageRaw?ext(storageRaw,['value']):[];
  let dnsZones=ext(_cachedParse('in_dnsz'),['value']);
  const allRecSets=ext(_cachedParse('in_r53records'),['value']);
  const recsByZoneMap={};
  allRecSets.forEach(r=>{const zid=r.id?.split('/')[r.id.split('/').indexOf('dnszones')+1];if(zid)(recsByZoneMap[zid]=recsByZoneMap[zid]||[]).push(r)});
  let wafPolicies=ext(_cachedParse('in_waf'),['value']);
  let sqlServers=ext(_cachedParse('in_sql'),['value']);
  let containerInstances=ext(_cachedParse('in_containers'),['value']);
  let functionApps=(ext(_cachedParse('in_funcapps'),['value'])).filter(f=>f.properties?.virtualNetworkSubnetId);
  let redisCaches=ext(_cachedParse('in_elasticache'),['value']);
  let synapseWorkspaces=ext(_cachedParse('in_synapse'),['value']);
  let vwans=ext(_cachedParse('in_tgwatt'),['value']);
  let frontDoors=[];
  const fdRaw=_cachedParse('in_cf');
  if(fdRaw){frontDoors=ext(fdRaw,['value']);}
  let aksClusters=ext(_cachedParse('in_aks'),['value']);
  // Parse RBAC / IAM data
  const iamRaw=_cachedParse('in_rbac');
  if(iamRaw&&!_iamData)_iamData=parseIAMData(iamRaw);

  // Multi-tenant: tag all resources with subscription/tenant ID
  const userSubscription=(document.getElementById('subscriptionLabel')||{}).value||'';
  function tagResource(r){if(!r)return r;r._subscriptionId=detectSubscriptionId(r)||userSubscription||'default';r._region=detectRegion(r)||'unknown';return r}
  [vnets,subnets,firewalls,bastions,natGateways,nsgs,vms,appGateways,loadBalancers,sqlServers,containerInstances,functionApps,peerings].forEach(arr=>arr.forEach(tagResource));
  const _regions=new Set();vnets.forEach(v=>{if(v._region&&v._region!=='unknown')_regions.add(v._region)});
  const _multiRegion=_regions.size>1;
  // Deduplicate: if same VNet id from same subscription, keep last pasted
  const seenVnets=new Map();const vnetDupes=[];
  vnets.forEach(v=>{const key=v._subscriptionId+':'+v.id;if(seenVnets.has(key))vnetDupes.push(v.id);seenVnets.set(key,v)});
  if(vnetDupes.length)console.warn('Duplicate VNets detected (kept latest):',vnetDupes);
  vnets=[...seenVnets.values()];
  // Collect unique subscriptions for rendering
  const _subscriptions=new Set();vnets.forEach(v=>{if(v._subscriptionId&&v._subscriptionId!=='default')_subscriptions.add(v._subscriptionId)});
  const _multiSubscription=_subscriptions.size>1;

  if(!vnets.length&&!subnets.length){
    if(_designMode){
      // Show design-aware empty state
      document.getElementById('landingDash').style.display='none';
      document.getElementById('emptyState').style.display='flex';
      document.getElementById('emptyTitle').textContent='Design Mode';
      document.getElementById('emptyDesc').textContent='No infrastructure loaded — create your first VNet to start designing';
      const eBtn=document.getElementById('emptyDesignBtn');
      eBtn.style.display='inline-block';
      eBtn.onclick=function(){showDesignForm('add_vnet',{})};
      svg.style('display','none');return;
    }
    document.getElementById('emptyTitle').textContent='No data loaded';
    document.getElementById('emptyDesc').textContent='Paste Azure CLI / ARM JSON exports and click Render Map';
    document.getElementById('emptyDesignBtn').style.display='none';
    document.getElementById('emptyState').style.display='none';document.getElementById('landingDash').style.display='flex';svg.style('display','none');return;
  }

  // lookups — map subnets to their parent VNet via ARM id hierarchy
  const subByVnet={};
  subnets.forEach(s=>{
    // Azure subnets have id like /subscriptions/.../virtualNetworks/{vnetName}/subnets/{subName}
    const parts=(s.id||'').split('/');
    const vnIdx=parts.findIndex(p=>p.toLowerCase()==='virtualnetworks');
    const vnetId=vnIdx>=0?parts.slice(0,vnIdx+2).join('/'):s._vnetId||'';
    s._vnetId=vnetId;
    (subByVnet[vnetId]=subByVnet[vnetId]||[]).push(s);
  });
  // Also map VNet objects by their id
  vnets.forEach(v=>{if(!subByVnet[v.id])subByVnet[v.id]=[]});
  const pubSubs=new Set(),subUDR={},gwSet=new Map();

  // gateway name enrichment from dedicated JSON
  gwNames={};
  firewalls.forEach(g=>{gwNames[g.id]=gn(g)});
  bastions.forEach(g=>{gwNames[g.id]=gn(g)});
  natGateways.forEach(g=>{gwNames[g.id]=gn(g)});
  privateEndpoints.forEach(g=>{gwNames[g.id]=gn(g)});
  vpnConnections.forEach(g=>{gwNames[g.id]=gn(g)});
  peerings.forEach(g=>{gwNames[g.id]=gn(g)});
  vwans.forEach(g=>{if(g.id&&!gwNames[g.id]) gwNames[g.id]=gn(g)});

  // Build UDR (route table) associations per subnet
  udrs.forEach(udr=>{
    const routes=udr.properties?.routes||[];
    const hasInternet=routes.some(r=>r.properties?.nextHopType==='Internet'&&r.properties?.addressPrefix==='0.0.0.0/0');
    (udr.properties?.subnets||[]).forEach(a=>{
      const subId=a.id||a;
      subUDR[subId]=udr;
      if(hasInternet)pubSubs.add(subId);
    });
  });

  // Classify subnets as public/private based on Azure conventions
  // Public: no UDR overriding default route, or has NAT gateway, or has public IP
  subnets.forEach(s=>{
    if(!subUDR[s.id]){
      // No UDR means default system route to Internet — public by convention
      pubSubs.add(s.id);
    }
    // Special subnet names for Azure services
    const subName=(s.name||'').toLowerCase();
    if(subName==='azurefirewallsubnet'||subName==='azurebastionsubnet'||subName==='gatewaysubnet'){
      pubSubs.delete(s.id); // these are infrastructure subnets, not public-facing
    }
  });

  // Discover gateways from Azure resources
  firewalls.forEach(g=>{
    const subId=g.properties?.ipConfigurations?.[0]?.properties?.subnet?.id;
    const vnetId=subId?subId.split('/subnets/')[0]:'unk';
    gwSet.set(g.id,{type:'fw',id:g.id,vnetId});
  });
  bastions.forEach(g=>{
    const subId=g.properties?.ipConfigurations?.[0]?.properties?.subnet?.id;
    const vnetId=subId?subId.split('/subnets/')[0]:'unk';
    gwSet.set(g.id,{type:'bastion',id:g.id,vnetId});
  });
  natGateways.forEach(g=>{
    // NAT gateway is attached to subnets; find VNet from first subnet
    const subIds=g.properties?.subnets||[];
    const firstSub=subIds[0]?.id||'';
    const vnetId=firstSub?firstSub.split('/subnets/')[0]:'unk';
    gwSet.set(g.id,{type:'nat',id:g.id,vnetId});
  });
  vpnConnections.forEach(g=>{
    const subId=g.properties?.ipConfigurations?.[0]?.properties?.subnet?.id;
    const vnetId=subId?subId.split('/subnets/')[0]:'unk';
    gwSet.set(g.id,{type:'vpn',id:g.id,vnetId});
  });
  vwans.forEach(g=>{
    gwSet.set(g.id,{type:'vwan',id:g.id,vnetId:'shared'});
  });

  // Private Endpoints — placed in subnets, tracked for summary nodes
  privateEndpoints.forEach(g=>{
    const subId=g.properties?.subnet?.id||'';
    const vnetId=subId?subId.split('/subnets/')[0]:'unk';
    gwSet.set(g.id,{type:'pe',id:g.id,vnetId,subId});
  });

  // PE grouped by subnet for detail-level rendering
  const peBySub={};
  privateEndpoints.forEach(pe=>{
    const subId=pe.properties?.subnet?.id||'';
    if(subId)(peBySub[subId]=peBySub[subId]||[]).push(pe);
  });

  // NSG associations per subnet
  const subNsg={};nsgs.forEach(n=>{(n.properties?.subnets||[]).forEach(a=>{const subId=a.id||a;subNsg[subId]=n})});
  // NSG by VNet
  const nsgByVnet={};nsgs.forEach(nsg=>{
    (nsg.properties?.subnets||[]).forEach(a=>{
      const subId=a.id||a;
      const vnetId=subId.split('/subnets/')[0];
      (nsgByVnet[vnetId]=nsgByVnet[vnetId]||[]).push(nsg);
    });
  });
  // RBAC role -> resource cross-references
  const iamRoleResources={};
  if(_iamData){
    (vms||[]).forEach(i=>{const mid=i.identity?.principalId;if(mid){if(!iamRoleResources[mid])iamRoleResources[mid]={vms:[],functions:[],containers:[]};iamRoleResources[mid].vms.push(i)}});
    (functionApps||[]).forEach(fn=>{const mid=fn.identity?.principalId;if(mid){if(!iamRoleResources[mid])iamRoleResources[mid]={vms:[],functions:[],containers:[]};iamRoleResources[mid].functions.push(fn)}});
    (containerInstances||[]).forEach(svc=>{const mid=svc.identity?.principalId;if(mid){if(!iamRoleResources[mid])iamRoleResources[mid]={vms:[],functions:[],containers:[]};iamRoleResources[mid].containers.push(svc)}});
  }
  // VMs by subnet (via NIC -> subnet mapping)
  const vmById = new Map(vms.map(v => [v.id, v]));
  const nicById = new Map(nics.map(n => [n.id, n]));
  const vmBySub={};const nicByVm={};
  nics.forEach(nic=>{
    const vmId=nic.properties?.virtualMachine?.id;
    const subId=nic.properties?.ipConfigurations?.[0]?.properties?.subnet?.id;
    if(vmId&&subId){
      const vm=vmById.get(vmId);
      if(vm)(vmBySub[subId]=vmBySub[subId]||[]).push(vm);
      (nicByVm[vmId]=nicByVm[vmId]||[]).push(nic);
    }
  });
  // Also directly place VMs by their NIC subnet
  vms.forEach(vm=>{
    const nicRefs=vm.properties?.networkProfile?.networkInterfaces||[];
    nicRefs.forEach(nr=>{
      const nic=nicById.get(nr.id);
      if(nic){
        const subId=nic.properties?.ipConfigurations?.[0]?.properties?.subnet?.id;
        if(subId&&!vmBySub[subId]?.some(v=>v.id===vm.id)){
          (vmBySub[subId]=vmBySub[subId]||[]).push(vm);
        }
      }
    });
  });
  const nicBySub={};nics.forEach(e=>{
    const subId=e.properties?.ipConfigurations?.[0]?.properties?.subnet?.id;
    if(subId)(nicBySub[subId]=nicBySub[subId]||[]).push(e);
  });
  // App Gateways by subnet
  const agwBySub={};appGateways.forEach(agw=>{
    (agw.properties?.gatewayIPConfigurations||[]).forEach(ipc=>{
      const subId=ipc.properties?.subnet?.id;
      if(subId)(agwBySub[subId]=agwBySub[subId]||[]).push(agw);
    });
  });
  // Load Balancers by subnet (via frontend IP configurations)
  const lbBySub={};loadBalancers.forEach(lb=>{
    (lb.properties?.frontendIPConfigurations||[]).forEach(fip=>{
      const subId=fip.properties?.subnet?.id;
      if(subId)(lbBySub[subId]=lbBySub[subId]||[]).push(lb);
    });
  });

  // Managed disks per VM
  const diskByVm={};managedDisks.forEach(d=>{
    const vmId=d.managedBy||d.properties?.managedBy;
    if(vmId)(diskByVm[vmId]=diskByVm[vmId]||[]).push(d);
  });

  // Disks by subnet (via NIC->VM->Disk for VMs not in direct data)
  const knownVmIds=new Set(vms.map(i=>i.id));
  const vmSubFromNic={};nics.forEach(e=>{
    const vmId=e.properties?.virtualMachine?.id;
    const subId=e.properties?.ipConfigurations?.[0]?.properties?.subnet?.id;
    if(vmId&&subId)vmSubFromNic[vmId]=subId;
  });
  const diskBySub={};managedDisks.forEach(d=>{
    const vmId=d.managedBy||d.properties?.managedBy;
    if(vmId){
      if(knownVmIds.has(vmId))return; // rendered as VM child
      const subId=vmSubFromNic[vmId];
      if(subId)(diskBySub[subId]=diskBySub[subId]||[]).push(d);
    }
  });

  // Snapshots per disk
  const snapByDisk={};diskSnapshots.forEach(s=>{
    const srcId=s.properties?.creationData?.sourceResourceId;
    if(srcId)(snapByDisk[srcId]=snapByDisk[srcId]||[]).push(s);
  });

  // WAF policies per App Gateway (by id)
  const wafByAgw={};wafPolicies.forEach(pol=>{
    (pol.properties?.applicationGateways||[]).forEach(ref=>{
      const agwId=ref.id;
      if(agwId)(wafByAgw[agwId]=wafByAgw[agwId]||[]).push(pol);
    });
  });

  // SQL Servers by subnet (via private endpoint or VNet rule)
  const peById = new Map((privateEndpoints || []).map(p => [p.id, p]));
  const sqlBySub={};sqlServers.forEach(db=>{
    (db.properties?.privateEndpointConnections||[]).forEach(pec=>{
      const peId=pec.properties?.privateEndpoint?.id;
      const pe=peById.get(peId);
      if(pe){
        const subId=pe.properties?.subnet?.id;
        if(subId)(sqlBySub[subId]=sqlBySub[subId]||[]).push(db);
      }
    });
  });

  // Containers (ACI) by subnet
  const containerBySub={};containerInstances.forEach(ci=>{
    const subId=ci.properties?.subnetIds?.[0]?.id||ci.properties?.ipAddress?.subnet?.id;
    if(subId)(containerBySub[subId]=containerBySub[subId]||[]).push(ci);
  });

  // Function Apps by subnet
  const fnBySub={};functionApps.forEach(fn=>{
    const subId=fn.properties?.virtualNetworkSubnetId;
    if(subId)(fnBySub[subId]=fnBySub[subId]||[]).push(fn);
  });

  // AKS clusters by subnet (via agent pool profiles)
  const aksBySub={};aksClusters.forEach(aks=>{
    (aks.properties?.agentPoolProfiles||[]).forEach(pool=>{
      const subId=pool.vnetSubnetID;
      if(subId)(aksBySub[subId]=aksBySub[subId]||[]).push(aks);
    });
  });

  // Redis Cache by VNet
  const redisByVnet={};redisCaches.forEach(c=>{
    const subId=c.properties?.subnetId;
    if(subId){const vnetId=subId.split('/subnets/')[0];(redisByVnet[vnetId]=redisByVnet[vnetId]||[]).push(c)}
  });

  // Synapse by VNet
  const synapseByVnet={};synapseWorkspaces.forEach(w=>{
    const subId=w.properties?.managedVirtualNetworkSettings?.subnetId||w.properties?.virtualNetworkProfile?.computeSubnetId;
    if(subId){const vnetId=subId.split('/subnets/')[0];(synapseByVnet[vnetId]=synapseByVnet[vnetId]||[]).push(w)}
  });

  // Front Door origins mapped to App Gateway IDs
  const agwByName = new Map((appGateways || []).map(a => [a.name, a]));
  const fdByAgw={};frontDoors.forEach(d=>{
    (d.properties?.backendPools||d.properties?.originGroups||[]).forEach(pool=>{
      (pool.properties?.backends||pool.properties?.origins||[]).forEach(o=>{
        let matchAgw=null;
        if(o.address){for(const [name,a] of agwByName){if(a.properties?.frontendIPConfigurations?.[0]?.properties?.publicIPAddress?.id&&o.address.includes(name)){matchAgw=a;break;}}}
        if(matchAgw)(fdByAgw[matchAgw.id]=fdByAgw[matchAgw.id]||[]).push(d);
      });
    });
  });

  // separate per-VNet vs shared gateways; PEs always go to summary only
  const pvGws={},shGws=[],peByVnet={},peIds=new Set();
  [...gwSet.values()].forEach(gw=>{
    if(gw.type==='pe'){(peByVnet[gw.vnetId]=peByVnet[gw.vnetId]||[]).push(gw);peIds.add(gw.id);return}
    if(isShared(gw.type)){if(!shGws.find(g=>g.id===gw.id))shGws.push(gw)}
    else(pvGws[gw.vnetId]=pvGws[gw.vnetId]||[]).push(gw);
  });

  // Check layout mode
  const layoutMode=document.getElementById('layoutMode')?.value||'grid';
  
  if(layoutMode==='landingzone'){
    // LANDING ZONE HUB-SPOKE LAYOUT
    renderLandingZoneMap({
      vnets,subnets,udrs,nsgs,nics,firewalls,bastions,natGateways,privateEndpoints,vms,appGateways,loadBalancers,peerings,vpnConnections,managedDisks,diskSnapshots,storageAccounts,dnsZones,
      subByVnet,pubSubs,subUDR,gwSet,subNsg,nsgByVnet,vmBySub,nicBySub,agwBySub,lbBySub,diskByVm,diskBySub,pvGws,shGws,peByVnet,peIds,peBySub,gwNames,
      snapByDisk,wafByAgw,wafPolicies,
      sqlServers,containerInstances,functionApps,redisCaches,synapseWorkspaces,vwans,frontDoors,aksClusters,
      sqlBySub,containerBySub,fnBySub,aksBySub,redisByVnet,synapseByVnet,fdByAgw,_multiSubscription,_subscriptions,iamRoleResources
    });
    return;
  }

  if(layoutMode==='executive'){
    renderExecutiveOverview({
      vnets,subnets,udrs,nsgs,nics,firewalls,bastions,natGateways,privateEndpoints,vms,appGateways,loadBalancers,peerings,vpnConnections,managedDisks,diskSnapshots,storageAccounts,dnsZones,
      subByVnet,pubSubs,subUDR,gwSet,subNsg,nsgByVnet,vmBySub,nicBySub,agwBySub,lbBySub,diskByVm,pvGws,shGws,peByVnet,peIds,gwNames,
      snapByDisk,wafByAgw,wafPolicies,
      sqlServers,containerInstances,functionApps,redisCaches,synapseWorkspaces,vwans,frontDoors,aksClusters,
      sqlBySub,containerBySub,fnBySub,aksBySub,redisByVnet,synapseByVnet,fdByAgw
    });
    return;
  }

  // GRID LAYOUT (original)

  // layout constants
  const SH_BASE=52,SG=12,VP=30,VH=40,GR=20,MSW=240,CW=6.5;
  const RES_ICON=26,RES_CHILD_H=11,RES_GAP=4,RES_COLS=2,RES_TOP=36,RES_BOT=12;
  
  // Tree context for buildResTree
  const treeCtx={vmBySub,agwBySub,lbBySub,sqlBySub,containerBySub,fnBySub,aksBySub,diskByVm,diskBySub,nics,nicByVm,wafByAgw,fdByAgw,snapByDisk,nicBySub,peBySub};

  // Pre-calc resource tree per subnet for sizing
  const subTrees={};
  subnets.forEach(s=>{
    subTrees[s.id]=buildResTree(s.id,treeCtx);
  });
  function subHeight(sid2, sw){
    if(_detailLevel===0) return SH_BASE;
    const tree=subTrees[sid2]||[];
    if(!tree.length) return SH_BASE;
    const maxCh=Math.max(0,...tree.map(r=>(r.children||[]).length));
    const tallest=RES_ICON+maxCh*RES_CHILD_H;
    const rowH=tallest+6;
    const cols=sw?_dynamicResCols(sw):RES_COLS;
    const rows=Math.ceil(tree.length/cols);
    return Math.max(SH_BASE, RES_TOP+rows*rowH+RES_BOT+4);
  }

  const vSW={};
  vnets.forEach(v=>{
    const ss=subByVnet[v.id]||[];
    const vnetNameLen=(gn(v).length+2)*CW+30;
    const addrPrefixes=v.properties?.addressSpace?.addressPrefixes||[];
    const cidrStr=addrPrefixes[0]||'';
    const cidrLen=(cidrStr.length+15)*CW+20;
    let mx=Math.max(MSW,vnetNameLen+cidrLen);
    ss.forEach(s=>{
      const nameW=gn(s).length*CW+100;
      if(_detailLevel>0){
        const resCols=Math.min((subTrees[s.id]||[]).length, RES_COLS);
        const resW=resCols*(RES_ICON+RES_GAP+80)+50;
        mx=Math.max(mx,nameW,resW);
      } else {
        mx=Math.max(mx,nameW);
      }
    });
    vSW[v.id]=Math.min(mx,600);
  });

  const getVnetRegion=(v)=>{
    return v.location||v._region||'unknown';
  };
  const knownVnets=vnets.filter(v=>getVnetRegion(v)!=='unknown');
  const unknownVnets=vnets.filter(v=>getVnetRegion(v)==='unknown');

  knownVnets.sort((a,b)=>{
    const rc=getVnetRegion(a).localeCompare(getVnetRegion(b));
    if(rc!==0)return rc;
    const ac=(a._subscriptionId||'').localeCompare(b._subscriptionId||'');
    if(ac!==0)return ac;
    return (a.id||'').localeCompare(b.id||'');
  });

  const GC_BASE=140;
  const vL=[];let cx=60;
  
  // Calculate VNet height with dynamic subnet sizes
  const AZ_HDR=16; // height for location separator label
  function sortByLocation(ss){return ss.slice().sort((a,b)=>(a.name||'').localeCompare(b.name||''))}
  function calcVnetHeight(ss,sw){
    let ih=0;
    const sorted=sortByLocation(ss);
    sorted.forEach((s,i)=>{ih+=subHeight(s.id,sw)+(i<sorted.length-1?SG:0)});
    return Math.max(ih+VP*2+VH+30,150);
  }

  // Build subnet layout with cumulative Y positions
  function buildSubLayouts(ss,baseX,baseY,sw){
    const layouts=[];
    const sorted=sortByLocation(ss);
    let cy=baseY+VH+VP;
    sorted.forEach(s=>{
      const sh=subHeight(s.id,sw);
      layouts.push({sub:s,x:baseX+VP,y:cy,w:sw,h:sh,pub:pubSubs.has(s.id)});
      cy+=sh+SG;
    });
    return layouts;
  }
  
  const REGION_GAP=120;
  let _prevLayoutRegion=null;
  knownVnets.forEach((vnet,idx)=>{
    const _vnetRegion=getVnetRegion(vnet);
    if(_prevLayoutRegion&&_vnetRegion!==_prevLayoutRegion&&_multiRegion)cx+=REGION_GAP;
    _prevLayoutRegion=_vnetRegion;
    const ss=subByVnet[vnet.id]||[];
    const sw=vSW[vnet.id]||MSW;
    const vw=sw+VP*2,vh=calcVnetHeight(ss,sw);
    const routingGws=(pvGws[vnet.id]||[]);
    let maxGwNameW=0;
    routingGws.forEach(gw=>{
      const nm=gwNames[gw.id]||sid(gw.id);
      maxGwNameW=Math.max(maxGwNameW,nm.length*6+40);
    });
    const chanW=Math.max(GC_BASE,routingGws.length*55+50,maxGwNameW+60);
    const isLast=idx===knownVnets.length-1&&knownVnets.length>1;
    const gwSide=isLast?'left':'right';

    if(isLast){
      // Last VNet: put channel to the LEFT (gateways between this and previous VNet)
      vL.push({vnet,x:cx+chanW,y:80,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,cx+chanW,80,sw)
      });
      cx+=chanW+vw;
    }else{
      vL.push({vnet,x:cx,y:80,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,cx,80,sw)
      });
      cx+=vw+chanW;
    }
  });
  
  // Calculate row 2 Y position for unknown VNets (below all known VNets + shared gateways area)
  const maxKnownH=vL.length>0?vL.reduce((max,v)=>Math.max(max,v.h),0):0;
  const unknownRowY=80+maxKnownH+320;
  let ux=60;

  unknownVnets.forEach((vnet,idx)=>{
    const ss=subByVnet[vnet.id]||[];
    const sw=vSW[vnet.id]||MSW;
    const vw=sw+VP*2,vh=calcVnetHeight(ss,sw);
    const routingGws=(pvGws[vnet.id]||[]);
    let maxGwNameW=0;
    routingGws.forEach(gw=>{
      const nm=gwNames[gw.id]||sid(gw.id);
      maxGwNameW=Math.max(maxGwNameW,nm.length*6+40);
    });
    const chanW=Math.max(GC_BASE,routingGws.length*55+50,maxGwNameW+60);
    const isLast=idx===unknownVnets.length-1&&unknownVnets.length>1;
    const gwSide=isLast?'left':'right';

    if(isLast){
      vL.push({vnet,x:ux+chanW,y:unknownRowY,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,ux+chanW,unknownRowY,sw)
      });
      ux+=chanW+vw;
    }else{
      vL.push({vnet,x:ux,y:unknownRowY,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,ux,unknownRowY,sw)
      });
      ux+=vw+chanW;
    }
  });

  const W=document.querySelector('.main').clientWidth,H=document.querySelector('.main').clientHeight;
  
  // Center known VNets (row 1)
  const knownVL=vL.filter(v=>getVnetRegion(v.vnet)!=='unknown');
  const unknownVL=vL.filter(v=>getVnetRegion(v.vnet)==='unknown');
  
  if(knownVL.length>0){
    const knownWidth=cx-60-GC_BASE;
    const offX=Math.max(0,(W-knownWidth)/2-60);
    knownVL.forEach(v=>{v.x+=offX;v.subs.forEach(s=>s.x+=offX)});
  }
  
  // Center unknown VNets (row 2) independently
  if(unknownVL.length>0){
    const unknownWidth=ux-60-GC_BASE;
    const offX2=Math.max(0,(W-unknownWidth)/2-60);
    unknownVL.forEach(v=>{v.x+=offX2;v.subs.forEach(s=>s.x+=offX2)});
  }

  // Pre-pass: determine which subnets connect to each per-VNet gateway
  // This lets us position gateways near their connected subnets instead of at VNet bottom
  const gwSubnetYs=new Map(); // gwId -> [subnet Y midpoints]
  const preAllS=vL.flatMap(v=>v.subs).filter(sl=>sl.sub);
  preAllS.forEach(sl=>{
    const udr=subUDR[sl.sub.id];if(!udr)return;
    (udr.properties?.routes||[]).forEach(r=>{
      const tid=r.properties?.nextHopIpAddress||r.id;
      if(!tid||peIds.has(tid))return;
      if(!gwSubnetYs.has(tid))gwSubnetYs.set(tid,[]);
      gwSubnetYs.get(tid).push(sl.y+sl.h/2);
    });
    // Also connect to gateway resources in the same VNet
    const vnetId=sl.sub._vnetId;
    (pvGws[vnetId]||[]).forEach(gw=>{
      if(!gwSubnetYs.has(gw.id))gwSubnetYs.set(gw.id,[]);
      gwSubnetYs.get(gw.id).push(sl.y+sl.h/2);
    });
  });

  // per-VNet gateways positioned near connected subnet centroid
  const gwP=new Map();
  const gwOrder={fw:0,bastion:1,nat:2,vpn:3,appgw:4};
  vL.forEach(vl=>{
    const gs=[...(pvGws[vl.vnet.id]||[])].sort((a,b)=>{const oa=gwOrder[a.type]??9,ob=gwOrder[b.type]??9;return oa-ob;});
    const gwOff=Math.max(60,Math.min(vl.chanW*0.7,120));
    const gx=vl.gwSide==='left'?(vl.x-gwOff):(vl.x+vl.w+gwOff);
    const minGap=GR*2+30; // minimum vertical gap between gateway circles (room for label below)

    // Compute ideal Y for each gateway at centroid of its connected subnets
    const gwYs=gs.map(gw=>{
      const subYs=gwSubnetYs.get(gw.id);
      if(subYs&&subYs.length>0){
        const avgY=subYs.reduce((a,b)=>a+b,0)/subYs.length;
        let gy=avgY;
        gy=Math.min(gy, vl.y+vl.h-GR-10);
        gy=Math.max(gy, vl.y+GR+20);
        return {gw,gy};
      }
      return {gw,gy:vl.y+vl.h-GR-10}; // fallback: near bottom
    });

    // Resolve overlaps: push later gateways down if too close
    for(let i=1;i<gwYs.length;i++){
      if(gwYs[i].gy-gwYs[i-1].gy<minGap){
        gwYs[i].gy=gwYs[i-1].gy+minGap;
      }
    }
    // Final clamp to VNet bounds (don't let pushed gateways escape VNet)
    gwYs.forEach(g=>{
      g.gy=Math.min(g.gy, vl.y+vl.h-GR-10);
      g.gy=Math.max(g.gy, vl.y+GR+20);
    });

    gwYs.forEach(({gw,gy})=>gwP.set(gw.id,{x:gx,y:gy,gw}));
  });

  // shared gateways below KNOWN VNets only (not disconnected)
  const knownVnetBot=knownVL.length>0?knownVL.reduce((max,v)=>Math.max(max,v.y+v.h),0):80;
  const lE=knownVL[0]?.x||0,rE=knownVL.length?knownVL[knownVL.length-1].x+knownVL[knownVL.length-1].w:W;
  const sCX=(lE+rE)/2,sY=knownVnetBot+80;
  const ssX=sCX-((shGws.length-1)*80)/2;
  shGws.forEach((gw,i)=>{gwP.set(gw.id,{x:ssX+i*80,y:sY,gw})});
  
  // Track the lowest Y used by routing elements (gateways, bus lanes, peering)
  let routingBottomY=shGws.length>0?(sY+GR+20):(knownVnetBot+20);

  // Disconnected VNets will be repositioned after all routing is computed

  // internet node positioned far left, anchoring the NET bus bar
  // Firewalls connect to NET bus bar; NAT Gateways have their own subnet route lines
  const fwGwList=[...gwP.values()].filter(p=>p.gw.type==='fw');
  const allVnetRight=vL.reduce((max,v)=>Math.max(max,v.gwSide==='left'?(v.x+v.w):(v.x+v.w+v.chanW)),0);
  const allVnetLeft=vL.reduce((min,v)=>Math.min(min,v.x),Infinity);
  const allVnetTop=vL.reduce((min,v)=>Math.min(min,v.y),Infinity);
  const allVnetBottom=vL.reduce((max,v)=>Math.max(max,v.y+v.h),0);
  // Position NET node left of all VNets
  const iX=allVnetLeft-80;
  const iY=allVnetTop-100;

  const allS=vL.flatMap(v=>v.subs).filter(sl=>sl.sub);

  // trunk groups -- connect subnets to their VNet's gateways
  const tG={};
  allS.forEach(sl=>{
    const ov=vL.find(v=>v.subs.includes(sl));if(!ov)return;
    const vnetId=ov.vnet.id;
    // Connect each subnet to all gateways in its VNet
    (pvGws[vnetId]||[]).forEach(gw=>{
      if(!gwP.has(gw.id)||peIds.has(gw.id))return;
      const k=gw.id+'|'+vnetId;
      const addrPrefix=sl.sub.properties?.addressPrefix||'?';
      (tG[k]=tG[k]||[]).push({sl,sid:sl.sub.id,dst:addrPrefix,gid:gw.id,vid:vnetId});
    });
    // Also connect via UDR routes to shared gateways
    const udr=subUDR[sl.sub.id];
    if(udr){
      (udr.properties?.routes||[]).forEach(r=>{
        const nextHop=r.properties?.nextHopIpAddress;
        if(nextHop&&gwP.has(nextHop)&&!peIds.has(nextHop)){
          const k=nextHop+'|'+vnetId;
          (tG[k]=tG[k]||[]).push({sl,sid:sl.sub.id,dst:r.properties?.addressPrefix||'?',gid:nextHop,vid:vnetId});
        }
      });
    }
  });

  // SVG
  const g=svg.append('g').attr('class','map-root');
  const zB=d3.zoom().scaleExtent([.08,5]).on('zoom',e=>{g.attr('transform',e.transform);document.getElementById('zoomLevel').textContent=Math.round(e.transform.k*100)+'%'});svg.call(zB);
  _mapSvg=svg;_mapZoom=zB;_mapG=g;
  bindZoomButtons();

  const lnL=g.append('g').attr('class','lines-layer'); // Routes first (bottom)
  const ndL=g.append('g').attr('class','nodes-layer'); // Nodes on top of routes
  const routeG=lnL.append('g').attr('class','route-group');
  const structG=lnL.append('g').attr('class','struct-group'); // structural route lines at full opacity
  const allLb=[];
  const olL=g.append('g').attr('class','highlight-overlay');
  const labelL=g.append('g').attr('class','label-layer'); // Labels on top of everything

  // Highlight lock state for click-to-toggle
  let _hlLocked=false, _hlKey=null, _hlType=null;
  const lockInd=document.getElementById('hlLockInd');
  function showLockInd(v){lockInd.style.display=v?'block':'none'}
  function setGwHl(gid){
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    if(gid) ndL.selectAll('.gw-node').each(function(){
      const el=d3.select(this);
      if(el.datum&&el.datum()===gid) el.classed('gw-hl',true);
    });
  }
  
  function clonePathToOl(srcEl){
    const s=d3.select(srcEl);
    const op=olL.append('path')
      .attr('d',s.attr('d'))
      .style('stroke',s.attr('stroke'))
      .style('fill',s.attr('fill')||'none')
      .style('stroke-width','4px')
      .style('opacity','1')
      .style('stroke-dasharray','8 5')
      .style('pointer-events','none');
    // Preserve solid style for L-bends, connectors, junctions
    const srcDash=s.style('stroke-dasharray');
    if(srcDash==='none'||s.classed('route-junction')){
      op.style('stroke-dasharray','none').style('stroke-width','3px');
    }
    return op;
  }

  function hlGw(gid){
    olL.selectAll('*').remove();
    routeG.style('opacity','0.03');structG.style('opacity','0.03');
    g.classed('hl-active',true);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.vnet-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
    ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);

    // Find all VNets connected to this gateway and highlight them
    const gwVids=new Set();
    structG.node().querySelectorAll('[data-gid="'+gid+'"][data-vid]').forEach(el=>{
      gwVids.add(el.getAttribute('data-vid'));
    });
    gwVids.forEach(vid=>ndL.selectAll('.vnet-group[data-vnet-id="'+vid+'"]').each(function(){d3.select(this).select('rect').style('stroke-width','3px').style('filter','drop-shadow(0 0 8px rgba(99,180,255,.7))');}));

    // Clone ALL structural paths for this gateway into overlay
    let hasNet=false;
    const sNode=structG.node();
    sNode.querySelectorAll('[data-gid="'+gid+'"]').forEach(el=>{
      if(el.hasAttribute('data-net-vert')) hasNet=true;
      clonePathToOl(el);
    });
    // Also clone paths with just data-gid (no data-vid) — e.g. bus-bar-to-gateway verticals
    // (already included above since querySelectorAll matches all with data-gid)

    if(hasNet){
      // Clone NET-vert segments: same X column (above this gateway) + intermediate X columns
      const gp=gwP.get(gid);
      if(gp){
        const gwX=gp.x;
        const gwBotY=gp.y-GR-4;
        sNode.querySelectorAll('[data-net-vert]').forEach(el=>{
          if(el.getAttribute('data-gid')===gid) return; // already cloned above
          const dm=el.getAttribute('d').match(/^M([\d.]+),([-\d.]+)\s*L\1,([-\d.]+)$/);
          if(dm){
            const segX=parseFloat(dm[1]);
            const segBot=Math.max(parseFloat(dm[2]),parseFloat(dm[3]));
            if(Math.abs(segX-gwX)<2){
              // Same X column: only segments above this gateway
              if(segBot<=gwBotY+2) clonePathToOl(el);
            }
          }
        });
      }
      const netLine=sNode.querySelector('[data-net-line]');
      if(netLine&&gp){
        // Trim NET horizontal line from Internet node to this gateway's X only
        const nlD=netLine.getAttribute('d');
        const nlM=nlD.match(/^M([-\d.]+),([-\d.]+)\s*L([-\d.]+),([-\d.]+)$/);
        if(nlM){
          const nlX1=parseFloat(nlM[1]),nlY=parseFloat(nlM[2]),nlX2=parseFloat(nlM[3]);
          const trimX=Math.min(Math.max(nlX1,nlX2),gp.x);
          const trimD=`M${Math.min(nlX1,nlX2)},${nlY} L${trimX},${nlY}`;
          const s=d3.select(netLine);
          olL.append('path').attr('d',trimD)
            .style('stroke',s.attr('stroke')).style('fill','none')
            .style('stroke-width','4px').style('opacity','1')
            .style('stroke-dasharray','8 5').style('pointer-events','none');
        }else{
          clonePathToOl(netLine);
        }
      }else if(netLine){
        clonePathToOl(netLine);
      }
      ndL.selectAll('.internet-node').style('opacity','1');
      // Highlight FW gateways in the same X column (shared trunk) as this gateway
      if(gp){
        const gwX=gp.x;
        ndL.selectAll('.gw-node').each(function(){
          const c=d3.select(this).select('circle');
          const t=d3.select(this).select('text');
          if(!c.node()||!t.node()) return;
          const cx=parseFloat(c.attr('cx'));
          if(t.text()==='FW'&&Math.abs(cx-gwX)<2) d3.select(this).classed('gw-hl',true);
        });
      }
    }
    allLb.forEach(l=>l.g.classed('visible',l.gid===gid));
  }
  
  function hlSub(sid){
    const subVnet=vL.find(v=>v.subs.some(s=>s.sub&&s.sub.id===sid));
    const subVid=subVnet?.vnet.id;
    const subLayout=subVnet?.subs.find(s=>s.sub&&s.sub.id===sid);
    const subMidY=subLayout?(subLayout.y+subLayout.h/2):null;

    const mg=new Set();
    Object.entries(tG).forEach(([key,cs])=>{
      if(cs.some(c=>c.sid===sid)) mg.add(cs[0].gid);
    });

    olL.selectAll('*').remove();
    routeG.style('opacity','0.03');structG.style('opacity','0.03');
    g.classed('hl-active',true);
    ndL.selectAll('.vnet-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
    if(subVid) ndL.selectAll('.vnet-group[data-vnet-id="'+subVid+'"]').each(function(){d3.select(this).select('rect').style('stroke-width','3px').style('filter','drop-shadow(0 0 8px rgba(99,180,255,.7))');});

    if(mg.size===0){
      allLb.forEach(l=>l.g.classed('visible',false));
      return;
    }

    ndL.selectAll('.gw-node').classed('gw-hl',false);
    const sNode=structG.node();

    mg.forEach(gid=>{
      ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);

      // Find the subnet's route-line Y for this gateway
      const subRouteEl=sNode.querySelector('[data-gid="'+gid+'"][data-sid="'+sid+'"].route-line');
      let subY=subMidY;
      if(subRouteEl){
        const rm=subRouteEl.getAttribute('d').match(/M[\d.]+,([\d.]+)/);
        if(rm) subY=parseFloat(rm[1]);
      }

      // Find the gateway Y (L-bend endpoint or connector point)
      const gp=gwP.get(gid);
      const gwY=gp?gp.y:subY;

      // 1. Clone this subnet's route-lines + junctions for this gateway
      sNode.querySelectorAll('[data-gid="'+gid+'"][data-sid="'+sid+'"]').forEach(el=>clonePathToOl(el));

      // 2. Clone trunk/L-bend/junction paths — but TRIM vertical trunks to subnet↔gateway range
      // First, find the L-bend/connector Y to use as trim target
      let bendY=gwY;
      sNode.querySelectorAll('[data-gid="'+gid+'"][data-vid="'+subVid+'"]:not([data-sid]):not([data-net-vert])').forEach(el=>{
        if(el.style.strokeDasharray==='none'&&!el.classList.contains('route-junction')){
          // This is the L-bend or L-connector — extract its Y
          const bm=el.getAttribute('d').match(/^M[\d.]+,([\d.]+)/);
          if(bm) bendY=parseFloat(bm[1]);
        }
      });
      sNode.querySelectorAll('[data-gid="'+gid+'"][data-vid="'+subVid+'"]:not([data-sid]):not([data-net-vert])').forEach(el=>{
        const s=d3.select(el);
        const d=el.getAttribute('d');
        const isDashed=el.style.strokeDasharray!=='none'&&!el.classList.contains('route-junction');
        // Detect vertical trunk: M{x},{y1} L{x},{y2} (same X)
        const vm=isDashed&&d.match(/^M([\d.]+),([\d.]+)\s*L\1,([\d.]+)$/);
        if(vm){
          // Trim vertical trunk to span only from subY to the L-bend/connector Y
          const tx=parseFloat(vm[1]);
          const trimTop=Math.min(subY,bendY);
          const trimBot=Math.max(subY,bendY);
          const trimD=`M${tx},${trimTop} L${tx},${trimBot}`;
          olL.append('path').attr('d',trimD)
            .style('stroke',s.attr('stroke')).style('fill','none')
            .style('stroke-width','4px').style('opacity','1')
            .style('stroke-dasharray','8 5').style('pointer-events','none');
        }else{
          clonePathToOl(el);
        }
      });

      // 3. Clone shared gateway paths with no vid (bus-bar-to-gateway verticals)
      sNode.querySelectorAll('[data-gid="'+gid+'"]:not([data-vid]):not([data-net-vert]):not([data-net-line])').forEach(el=>clonePathToOl(el));

      // 4. For Azure Firewall: show full path from gateway up to internet node
      // NET verticals are segmented per-gateway, so collect ALL segments
      // at this gateway's X from iY down to the gateway's Y,
      // PLUS intermediate NET-vert segments at other X columns between NET node and this gateway
      if(gp&&gp.gw.type==='fw'){
        const gwX=gp.x;
        const gwBotY=gp.y-GR-4; // top of gateway circle
        sNode.querySelectorAll('[data-net-vert]').forEach(el=>{
          const dm=el.getAttribute('d').match(/^M([\d.]+),([-\d.]+)\s*L\1,([-\d.]+)$/);
          if(dm){
            const segX=parseFloat(dm[1]);
            const segTop=Math.min(parseFloat(dm[2]),parseFloat(dm[3]));
            const segBot=Math.max(parseFloat(dm[2]),parseFloat(dm[3]));
            if(Math.abs(segX-gwX)<2){
              // Same X column: only segments above or touching the gateway
              if(segTop<=gwBotY+2 && segBot<=gwBotY+2) clonePathToOl(el);
            }
          }
        });
        const netLine=sNode.querySelector('[data-net-line]');
        if(netLine){
          // Trim NET horizontal line to only extend from Internet node to this gateway's X
          const nlD=netLine.getAttribute('d');
          const nlM=nlD.match(/^M([-\d.]+),([-\d.]+)\s*L([-\d.]+),([-\d.]+)$/);
          if(nlM){
            const nlX1=parseFloat(nlM[1]),nlY=parseFloat(nlM[2]),nlX2=parseFloat(nlM[3]);
            const trimX=Math.min(Math.max(nlX1,nlX2),gwX);
            const trimD=`M${Math.min(nlX1,nlX2)},${nlY} L${trimX},${nlY}`;
            const s=d3.select(netLine);
            olL.append('path').attr('d',trimD)
              .style('stroke',s.attr('stroke')).style('fill','none')
              .style('stroke-width','4px').style('opacity','1')
              .style('stroke-dasharray','8 5').style('pointer-events','none');
          }else{
            clonePathToOl(netLine);
          }
        }
        ndL.selectAll('.internet-node').style('opacity','1');
        // Highlight FW gateways in the same X column (shared trunk) as this gateway
        ndL.selectAll('.gw-node').each(function(){
          const c=d3.select(this).select('circle');
          const t=d3.select(this).select('text');
          if(!c.node()||!t.node()) return;
          const cx=parseFloat(c.attr('cx'));
          if(t.text()==='FW'&&Math.abs(cx-gwX)<2) d3.select(this).classed('gw-hl',true);
        });
      }
    });
    
    // Position labels based on gateway type
    let labelOffset=0;
    const visibleLabels=[];
    if(subVnet){
      allLb.forEach(l=>{
        const show=mg.has(l.gid)&&(l.shared||l.vid===subVid);
        l.g.classed('visible',show);
        if(show&&subMidY!=null){
          const ly=subMidY+labelOffset;
          let labelX;
          if(l.shared){
            if(subVnet.gwSide==='left'){
              labelX=subVnet.x-(subVnet.chanW||100)/2-40;
            }else{
              labelX=subVnet.x+subVnet.w+(subVnet.chanW||100)/2+40;
            }
          }else{
            const gp=gwP.get(l.gid);
            if(subVnet.gwSide==='left'){
              labelX=gp?gp.x-GR-50:subVnet.x-100;
            }else{
              labelX=gp?gp.x+GR+50:subVnet.x+subVnet.w+100;
            }
          }
          l.g.select('rect').attr('x',labelX-l.lw/2).attr('y',ly-8);
          l.g.select('text').attr('x',labelX).attr('y',ly+3);
          visibleLabels.push({g:l.g,lw:l.lw,x:labelX-l.lw/2,y:ly-8,h:16});
          labelOffset+=22;
        }
      });
      
      // Dynamic collision avoidance: shift labels right if any route lines pass through
      visibleLabels.forEach(vl=>{
        let lx=vl.x,ly=vl.y,lw=vl.lw,lh=vl.h;
        let shifted=false;
        for(let iter=0;iter<5;iter++){
          let maxCrossX=0;
          // Check all route paths (trunks and lines)
          structG.selectAll('.route-trunk,.route-line').each(function(){
            const d=d3.select(this).attr('d')||'';
            // Check vertical lines: M{x},{y1} L{x},{y2}
            const vm=d.match(/M([\d.]+),([\d.]+)\s*L\1,([\d.]+)/);
            if(vm){
              const tx=parseFloat(vm[1]);
              const ty1=Math.min(parseFloat(vm[2]),parseFloat(vm[3]));
              const ty2=Math.max(parseFloat(vm[2]),parseFloat(vm[3]));
              if(tx>=lx&&tx<=lx+lw&&ty1<=ly+lh&&ty2>=ly){
                if(tx>maxCrossX)maxCrossX=tx;
              }
            }
            // Check horizontal lines: M{x1},{y} L{x2},{y}
            const hm=d.match(/M([\d.]+),([\d.]+)\s*L([\d.]+),\2/);
            if(hm){
              const hx1=Math.min(parseFloat(hm[1]),parseFloat(hm[3]));
              const hx2=Math.max(parseFloat(hm[1]),parseFloat(hm[3]));
              const hy=parseFloat(hm[2]);
              if(hy>=ly&&hy<=ly+lh&&hx2>=lx&&hx1<=lx+lw){
                if(hx2>maxCrossX)maxCrossX=hx2;
              }
            }
          });
          if(maxCrossX>0){
            lx=maxCrossX+12;
            shifted=true;
          }else break;
        }
        if(shifted){
          vl.g.select('rect').attr('x',lx);
          vl.g.select('text').attr('x',lx+lw/2);
        }
      });
    }
  }
  function clr(){
    if(_hlLocked) return;
    olL.selectAll('*').remove();routeG.style('opacity',null);structG.style('opacity',null);allLb.forEach(l=>l.g.classed('visible',false));g.classed('hl-active',false);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.internet-node').style('opacity',null);
    ndL.selectAll('.vnet-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
  }
  function forceClr(){
    _hlLocked=false;_hlKey=null;_hlType=null;showLockInd(false);
    olL.selectAll('*').remove();routeG.style('opacity',null);structG.style('opacity',null);allLb.forEach(l=>l.g.classed('visible',false));g.classed('hl-active',false);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.internet-node').style('opacity',null);
    ndL.selectAll('.vnet-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
  }
  // Expose gateway highlight globally for panel link navigation
  window._hlGwGlobal=function(gid){
    forceClr();hlGw(gid);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);
    _hlLocked=true;_hlKey=gid;_hlType='gw';showLockInd(true);
  };
  if(window._hlUnlockHandler)document.removeEventListener('hl-unlock',window._hlUnlockHandler);
  window._hlUnlockHandler=forceClr;document.addEventListener('hl-unlock',forceClr);
  svg.on('click',function(event){
    if(!event.target.closest('.gw-node')&&!event.target.closest('.subnet-node')&&!event.target.closest('.res-node')&&!event.target.closest('.route-hitarea')&&!event.target.closest('.internet-node')){
      forceClr();
      if(_spotlightActive) _closeSpotlight();
    }
  });

  // Attach route-highlighting to subnet bodies and their resource nodes
  ndL.selectAll('.subnet-node').each(function(){
    const el=d3.select(this);
    const sid=el.attr('data-subnet-id');
    if(!sid)return;
    el.on('mouseenter.hl',function(){if(!_hlLocked)hlSub(sid)})
      .on('mouseleave.hl',function(){if(!_hlLocked)clr()})
      .on('click.hl',function(event){
        if(event.target.closest('.res-node'))return;
        event.stopPropagation();
        if(_hlLocked&&_hlKey===sid&&_hlType==='sub'){forceClr();return}
        forceClr();hlSub(sid);_hlLocked=true;_hlKey=sid;_hlType='sub';showLockInd(true);
      });
    el.selectAll('.res-node')
      .on('mouseenter.hl',function(){if(!_hlLocked)hlSub(sid)})
      .on('mouseleave.hl',function(){if(!_hlLocked)clr()})
      .on('click.hl',function(event){
        event.stopPropagation();
        var resEl=d3.select(this);
        var resId=resEl.attr('data-id');
        if(resId){
          forceClr();hlSub(sid);_hlLocked=true;_hlKey=sid;_hlType='sub';showLockInd(true);
          _openResourceSpotlight(resId);
          return;
        }
        if(_hlLocked&&_hlKey===sid&&_hlType==='sub'){forceClr();return}
        forceClr();hlSub(sid);_hlLocked=true;_hlKey=sid;_hlType='sub';showLockInd(true);
      });
  });

  // peering lines - horizontal connections between VNet edges, stacked by span
  const peeringG=lnL.append('g').attr('class','peering-group');

  const activePeerings = peerings
    .filter(p => {
      const state=(p.properties?.peeringState||'').toLowerCase();
      return !state || state === 'connected';
    })
    .map(p => {
      // Azure VNet peering: remoteVirtualNetwork.id references the peer VNet
      const localVnetId = p.id?.split('/virtualNetworkPeerings/')[0]||'';
      const remoteVnetId = p.properties?.remoteVirtualNetwork?.id||'';
      const v1 = vL.find(v => v.vnet.id === localVnetId), v2 = vL.find(v => v.vnet.id === remoteVnetId);
      if (!v1 || !v2) return null;
      const leftVnet = v1.x < v2.x ? v1 : v2;
      const rightVnet = v1.x < v2.x ? v2 : v1;
      const span = (rightVnet.x) - (leftVnet.x + leftVnet.w);
      return { peering: p, leftVnet, rightVnet, span };
    })
    .filter(p => p !== null)
    .sort((a, b) => a.span - b.span); // shortest first = closest to VNets

  const globalMinY = Math.min(...vL.map(v => v.y));
  const laneSpacing = 28;

  activePeerings.forEach((p, idx) => {
    const { peering, leftVnet, rightVnet } = p;
    const pn = gn(peering);

    // Each peering gets its own Y lane above VNets
    // Shortest spans closest to VNets, longest furthest away
    const y = globalMinY - 40 - idx * laneSpacing;

    const stubLen = 15;

    // Exit points on VNet tops
    const leftExitX = leftVnet.x + leftVnet.w - stubLen;
    const rightExitX = rightVnet.x + stubLen;
    const leftVnetTopY = leftVnet.y;
    const rightVnetTopY = rightVnet.y;

    // Complete path: down from left VNet, across, down to right VNet
    const d = `M${leftExitX},${leftVnetTopY} L${leftExitX},${y} L${rightExitX},${y} L${rightExitX},${rightVnetTopY}`;
    
    peeringG.append('path')
      .attr('class', 'peering-line animated')
      .attr('d', d)
      .attr('stroke', 'var(--pcx-color)');
    
    // Label at midpoint of horizontal segment
    const midX = (leftExitX + rightExitX) / 2;
    const pw = pn.length * 5.5 + 20;
    const pg = lnL.append('g').attr('class','peering-label-g');
    pg.append('rect')
      .attr('x', midX - pw / 2).attr('y', y - 9)
      .attr('width', pw).attr('height', 18).attr('rx', 3)
      .attr('class','note-label-bg').attr('fill', 'var(--panel-bg)').attr('stroke', '#fb923c').attr('stroke-width', .5);
    pg.append('text')
      .attr('x', midX).attr('y', y + 4)
      .attr('text-anchor', 'middle').attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(9px * var(--txt-scale,1))').attr('fill', '#fb923c').text(pn);
  });

  // VPN marker
  vpnConnections.forEach(vpn=>{
    const state=(vpn.properties?.provisioningState||'').toLowerCase();
    if(state&&state!=='succeeded')return;
    if(!vpn.id||!gwP.has(vpn.id))return;
    const pos=gwP.get(vpn.id);
    const vpnLbl='VPN: '+gn(vpn);const vpnLblY=pos.y-GR-12;const vpnTw=vpnLbl.length*5.2+14;
    ndL.append('rect').attr('x',pos.x-vpnTw/2).attr('y',vpnLblY-9).attr('width',vpnTw).attr('height',14).attr('rx',4).attr('class','gw-label-bg').attr('fill','var(--overlay-bg)').attr('stroke','rgba(249,115,22,.3)').attr('stroke-width',.5);
    ndL.append('text').attr('x',pos.x).attr('y',vpnLblY).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','#f97316').text(vpnLbl);
  });

  // route trunks
  const tpv={};
  // Count per-VNet and shared gateways separately for trunk spacing
  const tpvPerVnet={};
  const tpvShared={};
  Object.entries(tG).forEach(([k])=>{
    const parts=k.split('|');
    const gid=parts[0],vid=parts[1];
    const gp=gwP.get(gid);
    if(gp&&isShared(gp.gw.type)){
      tpvShared[vid]=(tpvShared[vid]||0)+1;
    }else{
      tpvPerVnet[vid]=(tpvPerVnet[vid]||0)+1;
    }
    tpv[vid]=(tpv[vid]||0)+1;
  });
  const vtcPerVnet={};
  const vtcPerVnetUp={}; // Counter for UP-going per-VNet gateways
  const vtcPerVnetDown={}; // Counter for DOWN-going per-VNet gateways
  const vtcShared={};
  const lsg=new Set();
  
  // Track bus Y levels per shared gateway for vertical connector
  const sharedGwBusY={};

  // Sort gateway entries by DIRECTION relative to subnets to prevent line crossings
  // Lines going UP (gateway above subnets) get trunk X further LEFT
  // Lines going DOWN (gateway below subnets) get trunk X further RIGHT
  const sortedTgEntries=Object.entries(tG).sort((a,b)=>{
    const connsA=a[1],connsB=b[1];
    const gpA=gwP.get(connsA[0].gid);
    const gpB=gwP.get(connsB[0].gid);
    const vidA=connsA[0].vid,vidB=connsB[0].vid;
    // Group by VNet first
    if(vidA!==vidB)return 0;
    if(!gpA||!gpB)return 0;
    // Calculate average subnet Y for each gateway's connections
    const avgSubYA=connsA.reduce((s,c)=>s+c.sl.y+c.sl.h/2,0)/connsA.length;
    const avgSubYB=connsB.reduce((s,c)=>s+c.sl.y+c.sl.h/2,0)/connsB.length;
    // Direction: negative = going UP, positive = going DOWN
    const dirA=gpA.y-avgSubYA;
    const dirB=gpB.y-avgSubYB;
    // Lines going UP (negative dir) should be LEFT (sorted first)
    // Lines going DOWN (positive dir) should be RIGHT (sorted later)
    return dirA-dirB;
  });

  // Per-subnet exit counter: stagger X origin when multiple gateways connect to same subnet
  const subExitCount={};

  sortedTgEntries.forEach(([key,conns])=>{
    const gid=conns[0].gid,vid=conns[0].vid;
    const gp=gwP.get(gid);if(!gp)return;
    const gi=gp.gw,col=gcv(gi.type),colH=gch(gi.type);
    const ov=vL.find(v=>v.vnet.id===vid);if(!ov)return;
    conns.sort((a,b)=>a.sl.y-b.sl.y);

    // Separate trunk X for per-VNet vs shared gateways - large gap to avoid visual collision
    const sh=isShared(gi.type);
    const gwLeft=ov.gwSide==='left'; // last VNet: gateways to the left
    const cl=gwLeft?(ov.x-8):(ov.x+ov.w+8);

    // Direction based on gateway type: per-VNet (FW/NAT) go UP to NET, shared (VWAN) go DOWN to bus
    conns.sort((a,b)=>a.sl.y-b.sl.y);
    const goingUp=!sh; // per-VNet gateways route UP, shared gateways route DOWN

    let tx;
    if(sh){
      // Shared gateways (VWAN) use trunks close to VNet edge
      const tn=vtcShared[vid]=(vtcShared[vid]||0)+1;
      const nt=tpvShared[vid]||1;
      const sp=Math.max(6,Math.min(10,(ov.chanW*0.1)/Math.max(nt,1)));
      tx=gwLeft?(cl-2-(tn-1)*sp):(cl+2+(tn-1)*sp);
    }else{
      // Per-VNet gateways: UP lines get inner trunks, DOWN lines get outer trunks
      const baseOffset=50;
      const perVnetCount=tpvPerVnet[vid]||1;
      const sp=Math.max(8,Math.min(14,(ov.chanW*0.25)/Math.max(perVnetCount,1)));

      // Separate counters for up vs down
      if(!vtcPerVnetUp[vid])vtcPerVnetUp[vid]=0;
      if(!vtcPerVnetDown[vid])vtcPerVnetDown[vid]=0;

      if(goingUp){
        const tn=++vtcPerVnetUp[vid];
        tx=gwLeft?(cl-baseOffset-(tn-1)*sp):(cl+baseOffset+(tn-1)*sp);
      }else{
        const tn=++vtcPerVnetDown[vid];
        const upCount=Object.keys(tG).filter(k=>{
          const c=tG[k][0];
          if(c.vid!==vid)return false;
          const g=gwP.get(c.gid);
          return g&&!isShared(g.gw.type)&&g.y<avgSubY;
        }).length;
        tx=gwLeft?(cl-baseOffset-(upCount)*sp-(tn-1)*sp):(cl+baseOffset+(upCount)*sp+(tn-1)*sp);
      }
    }

    // Deduplicate connections by subnet ID
    const seenSubs=new Set();
    const uniqueConns=conns.filter(c=>{
      if(seenSubs.has(c.sid))return false;
      seenSubs.add(c.sid);return true;
    });

    // Collect all per-VNet gateway positions for this VNet to avoid crossing them
    const vnetGwPositions=[];
    gwP.forEach((pos,id)=>{
      if(!isShared(pos.gw.type)){
        const ovGw=vL.find(v=>v.subs.some(s=>true)&&pvGws[v.vnet.id]?.some(g=>g.id===id));
        if(ovGw&&ovGw.vnet.id===vid) vnetGwPositions.push(pos);
      }
    });

    uniqueConns.forEach(c=>{
      // Exit from top of subnet if going UP, bottom if going DOWN
      const sy=goingUp?(c.sl.y+6):(c.sl.y+c.sl.h-6);

      // Stagger: 2nd+ connections get a visible step outside the subnet edge
      const exitIdx=subExitCount[c.sid]=(subExitCount[c.sid]||0)+1;
      const stepN=exitIdx-1; // 0 for first connection, 1+ for subsequent
      const stepX=10; // horizontal distance of notch past subnet edge
      const stepY=8;  // vertical shift per stagger level

      // Check if horizontal line would cross any gateway circle (not our own)
      let d,endY=sy;
      if(gwLeft){
        const subLeft=c.sl.x;
        const crossingGw=vnetGwPositions.find(g=>g!==gp&&Math.abs(g.y-sy)<GR+8&&g.x<subLeft&&g.x>tx);
        if(stepN>0){
          const notchX=subLeft-stepX;
          endY=sy+(goingUp?stepN*stepY:-stepN*stepY);
          d=`M${subLeft},${sy} L${notchX},${sy} L${notchX},${endY} L${tx},${endY}`;
        }else if(crossingGw){
          const jogY=sy<crossingGw.y?(crossingGw.y-GR-10):(crossingGw.y+GR+10);
          endY=sy;
          d=`M${subLeft},${sy} L${crossingGw.x+GR+6},${sy} L${crossingGw.x+GR+6},${jogY} L${tx},${jogY} L${tx},${sy}`;
        }else{
          d=`M${subLeft},${sy} L${tx},${sy}`;
        }
      }else{
        const subRight=c.sl.x+c.sl.w;
        const crossingGw=vnetGwPositions.find(g=>g!==gp&&Math.abs(g.y-sy)<GR+8&&g.x>subRight&&g.x<tx);
        if(stepN>0){
          const notchX=subRight+stepX;
          endY=sy+(goingUp?stepN*stepY:-stepN*stepY);
          d=`M${subRight},${sy} L${notchX},${sy} L${notchX},${endY} L${tx},${endY}`;
        }else if(crossingGw){
          const jogY=sy<crossingGw.y?(crossingGw.y-GR-10):(crossingGw.y+GR+10);
          endY=sy;
          d=`M${subRight},${sy} L${crossingGw.x-GR-6},${sy} L${crossingGw.x-GR-6},${jogY} L${tx},${jogY} L${tx},${sy}`;
        }else{
          d=`M${subRight},${sy} L${tx},${sy}`;
        }
      }
      const rl=structG.append('path').attr('class','route-line route-structural').attr('d',d).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vid).attr('data-sid',c.sid);
      if(gwLeft) rl.style('animation-direction','reverse');
      // Solid filled square at trunk junction to cover dash-pattern gaps
      const jd=`M${tx-3},${endY-3} L${tx+3},${endY-3} L${tx+3},${endY+3} L${tx-3},${endY+3} Z`;
      structG.append('path').attr('class','route-junction route-structural').attr('d',jd).attr('stroke',col).attr('fill',col).attr('stroke-width',1).style('stroke-dasharray','none').attr('data-gid',gid).attr('data-vid',vid).attr('data-sid',c.sid);
      lnL.append('path').attr('class','route-hitarea').attr('d',d)
        .on('mouseenter',()=>{if(!_hlLocked)hlSub(c.sid)}).on('mouseleave',clr)
        .on('click',function(event){event.stopPropagation();
          if(_hlLocked&&_hlKey===c.sid&&_hlType==='sub'){forceClr();return}
          forceClr();hlSub(c.sid);_hlLocked=true;_hlKey=c.sid;_hlType='sub';showLockInd(true);
        });
    });

    // Trunk Y matches horizontal line positions
    const topY=goingUp?(uniqueConns[0].sl.y+6):(uniqueConns[0].sl.y+uniqueConns[0].sl.h-6);
    const botY=goingUp?(uniqueConns[uniqueConns.length-1].sl.y+6):(uniqueConns[uniqueConns.length-1].sl.y+uniqueConns[uniqueConns.length-1].sl.h-6);
    let lx,ly;

    if(!sh){
      // Per-VNet gateway: trunk spans ALL connected subnets AND gateway, then L-connector
      const gwEdgeX=gwLeft?(gp.x+GR+4):(gp.x-GR-4);

      // Compute actual min/max Y across ALL connected subnets (not just first/last)
      const allSubYs=uniqueConns.map(c=>goingUp?(c.sl.y+6):(c.sl.y+c.sl.h-6));
      // Trunk must cover ALL subnet Ys AND the gateway Y
      const vertTop=Math.min(...allSubYs,gp.y);
      const vertBot=Math.max(...allSubYs,gp.y);

      // Vertical trunk covering full range + L-bend to gateway
      const fullPath=`M${tx},${vertTop} L${tx},${vertBot}`;
      const lbendPath=`M${tx},${gp.y} L${gwEdgeX},${gp.y}`;
      const combinedPath=`M${tx},${vertTop} L${tx},${vertBot} M${tx},${gp.y} L${gwEdgeX},${gp.y}`;
      // Dashed vertical trunk spanning all subnets
      structG.append('path').attr('class','route-trunk route-structural').attr('d',fullPath).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vid).attr('data-vert','1');
      // Solid L-bend connector from trunk to gateway
      const lb=structG.append('path').attr('class','route-trunk route-structural').attr('d',lbendPath).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vid);
      if(gwLeft) lb.style('animation-direction','reverse');
      // Solid patch at L-bend corner
      const bendPatch=`M${tx-3},${gp.y-3} L${tx+3},${gp.y-3} L${tx+3},${gp.y+3} L${tx-3},${gp.y+3} Z`;
      structG.append('path').attr('class','route-junction route-structural').attr('d',bendPatch).attr('stroke',col).attr('fill',col).style('stroke-dasharray','none').attr('data-gid',gid).attr('data-vid',vid);
      lnL.append('path').attr('class','route-hitarea').attr('d',combinedPath)
        .on('mouseenter',()=>{if(!_hlLocked){hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true)}}).on('mouseleave',()=>{clr()})
        .on('click',function(event){event.stopPropagation();
          if(_hlLocked&&_hlKey===gid&&_hlType==='gw'){forceClr();return}
          forceClr();hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);
          _hlLocked=true;_hlKey=gid;_hlType='gw';showLockInd(true);
        });

      // Route label between gateway and VNet (on the trunk-line side)
      ly=gp.y;
      lx=gwLeft?(gp.x+GR+8):(gp.x-GR-8);
    }else{
      // Shared gateway: collect for bus bar routing (drawn later)
      if(!sharedGwBusY[gid]){
        sharedGwBusY[gid]={vnets:[],col,gp};
      }
      sharedGwBusY[gid].vnets.push({tx,ov,conns:uniqueConns});

      // For shared gateways, label near the trunk line at the last connected subnet
      lx=gwLeft?(tx-4):(tx+4);ly=uniqueConns[uniqueConns.length-1].sl.y+uniqueConns[uniqueConns.length-1].sl.h+10;
    }

    let skip=false;
    if(sh){if(lsg.has(gid))skip=true;else lsg.add(gid)}
    if(!skip){
      const lt=uniqueConns[0].dst+' > '+gi.type,lw=lt.length*5.4+16;
      const lg=labelL.append('g').attr('class','route-label-g');
      const anchor=(!sh&&gwLeft)?'start':'end';
      const rx=anchor==='end'?(lx-lw):lx;
      const textX=rx+lw/2;
      lg.append('rect').attr('x',rx).attr('y',ly-8).attr('width',lw).attr('height',16).attr('rx',3).attr('class','route-label-bg').attr('fill','var(--panel-bg)').attr('stroke',colH).attr('stroke-width',.5);
      lg.append('text').attr('x',textX).attr('y',ly+3).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','500').attr('fill',colH).text(lt);
      allLb.push({gid,vid,shared:sh,lx:textX,lw,g:lg,baseY:ly});
    }
  });

  // Route label inter-collision resolution
  {
    const routeLabelRecs=allLb.map(lb=>{
      const bg=lb.g.select('.route-label-bg');
      const txt=lb.g.select('text');
      if(!bg.node()) return null;
      const bx=parseFloat(bg.attr('x')), by=parseFloat(bg.attr('y'));
      const bw=parseFloat(bg.attr('width')), bh=parseFloat(bg.attr('height'));
      return {x:bx,y:by,w:bw,h:bh,rectNode:bg,textNode:txt,textAnchor:'middle',textOffY:11,lb};
    }).filter(Boolean);
    if(routeLabelRecs.length>1){
      routeLabelRecs.sort((a,b)=>a.y-b.y||a.x-b.x);
      _resolveCollisions(routeLabelRecs,{strategy:'shift-y',padding:3});
      routeLabelRecs.forEach(r=>{
        r.rectNode.attr('y',r.y);
        r.textNode.attr('y',r.y+r.h-5);
        r.lb.baseY=r.y+8; // update base for hover-time avoidance
      });
    }
  }

  // Draw shared gateway bus routing AFTER all VNets processed
  Object.entries(sharedGwBusY).forEach(([gid,info])=>{
    const {vnets:vnetConns,col,gp}=info;
    if(!vnetConns.length)return;

    // Bus bar Y: just enough below VNets to clear, halfway to the gateway
    const allVnetBotForBus=Math.max(...vnetConns.map(v=>v.ov.y+v.ov.h));
    const busY=allVnetBotForBus+30;

    // Each VNet trunk: dashed trunk spanning subnets + solid connector to bus bar
    vnetConns.forEach(vc=>{
      const uniqueC=vc.conns.sort((a,b)=>a.sl.y-b.sl.y);
      const vnetId=vc.ov.vnet.id;
      const allSubYs=uniqueC.map(c=>c.sl.y+c.sl.h-6);
      const trunkTop=Math.min(...allSubYs);
      const trunkBot=Math.max(...allSubYs);

      // Dashed trunk spanning only connected subnet range
      if(trunkTop!==trunkBot){
        const trunkPath=`M${vc.tx},${trunkTop} L${vc.tx},${trunkBot}`;
        structG.append('path').attr('class','route-trunk route-structural').attr('d',trunkPath).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vnetId).attr('data-vert','1');
      }

      // Solid L-connector from bottom of trunk down to bus Y, then horizontal to shared gateway X
      const connPath=`M${vc.tx},${trunkBot} L${vc.tx},${busY} L${gp.x},${busY}`;
      structG.append('path').attr('class','route-trunk route-structural').attr('d',connPath).attr('stroke',col).style('stroke-dasharray','none').style('opacity',0.45).attr('data-gid',gid).attr('data-vid',vnetId);
      // Solid patch at trunk-to-connector junction
      const tgwJunc=`M${vc.tx-3},${trunkBot-3} L${vc.tx+3},${trunkBot-3} L${vc.tx+3},${trunkBot+3} L${vc.tx-3},${trunkBot+3} Z`;
      structG.append('path').attr('class','route-junction route-structural').attr('d',tgwJunc).attr('stroke',col).attr('fill',col).style('stroke-dasharray','none').attr('data-gid',gid).attr('data-vid',vnetId);

      // Hitarea covers full path
      const fullPath=`M${vc.tx},${trunkTop} L${vc.tx},${busY} L${gp.x},${busY}`;
      lnL.append('path').attr('class','route-hitarea').attr('d',fullPath)
        .on('mouseenter',()=>{if(!_hlLocked){hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true)}}).on('mouseleave',()=>{clr()})
        .on('click',function(event){event.stopPropagation();
          if(_hlLocked&&_hlKey===gid&&_hlType==='gw'){forceClr();return}
          forceClr();hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);
          _hlLocked=true;_hlKey=gid;_hlType='gw';showLockInd(true);
        });
    });

    // Single vertical from bus bar to gateway circle
    const gwConnect=`M${gp.x},${busY} L${gp.x},${gp.y-GR-4}`;
    structG.append('path').attr('class','route-trunk route-structural').attr('d',gwConnect).attr('stroke',col).style('stroke-dasharray','none').style('opacity',0.45).attr('data-gid',gid);
  });

  // (Per-VNet verticals to gateway drawn inline above)

  // Find edges for routing
  const allVnetBottomEdge=Math.max(...vL.map(v=>v.y+v.h));

  // FW/NAT to Internet lines are now drawn with the NET node for proper animation

  // Reposition disconnected VNets below all routing (gateways, bus lanes, peering)
  if(unknownVL.length>0){
    const newUnkY=routingBottomY+60;
    const oldUnkY=unknownVL[0].y;
    const dy=newUnkY-oldUnkY;
    if(dy!==0){
      unknownVL.forEach(v=>{v.y+=dy;v.subs.forEach(s=>{s.y+=dy})});
    }
    routingBottomY=Math.max(...unknownVL.map(v=>v.y+v.h))+20;
  }

  // Region labels above VNet groups - process known VNets (row 1) separately from unknown (row 2)
  const vnetRegionMap={};
  vL.forEach(vl=>{
    const region=vl.vnet.location||vl.vnet._region||'unknown';
    vnetRegionMap[vl.vnet.id]=region;
  });

  // group consecutive known VNets by region, draw region background
  let prevRegion='',regionStartX=0,regionVnets=[];
  const regionGroups=[];
  knownVL.forEach((vl,i)=>{
    const r=vnetRegionMap[vl.vnet.id];
    if(r!==prevRegion&&prevRegion&&regionVnets.length){
      regionGroups.push({region:prevRegion,vnets:[...regionVnets]});
      regionVnets=[];
    }
    if(regionVnets.length===0)regionStartX=vl.x;
    regionVnets.push(vl);
    prevRegion=r;
    if(i===knownVL.length-1&&regionVnets.length)regionGroups.push({region:r,vnets:[...regionVnets]});
  });
  
  // Add unknown VNets as separate group if any
  if(unknownVL.length>0){
    regionGroups.push({region:'DISCONNECTED',vnets:unknownVL});
  }
  
  regionGroups.forEach(rg=>{
    const first=rg.vnets[0],last=rg.vnets[rg.vnets.length-1];
    const ry=first.y-30;
    const lastRight=last.gwSide==='left'?(last.x+last.w):(last.x+last.w+last.chanW);
    const rx=first.x-10;
    const rw=lastRight-first.x+20;
    const rh=Math.max(...rg.vnets.map(v=>v.h))+50;
    const isDisconnected=rg.region==='DISCONNECTED';
    const mr=_multiRegion&&!isDisconnected;
    ndL.append('rect').attr('class','region-boundary').attr('x',rx).attr('y',ry).attr('width',rw).attr('height',rh)
      .attr('fill',isDisconnected?'rgba(239,68,68,.06)':mr?'rgba(59,130,246,.08)':'rgba(59,130,246,.06)')
      .attr('stroke',isDisconnected?'rgba(239,68,68,.3)':mr?'rgba(59,130,246,.25)':'rgba(59,130,246,.15)')
      .attr('stroke-width',mr?1.5:1)
      .attr('stroke-dasharray',isDisconnected?'4 2':'none')
      .attr('rx',12);
    if(mr){
      // Pill badge label centered at top
      const labelText=rg.region+' ('+rg.vnets.length+' VNet'+(rg.vnets.length>1?'s':'')+')';
      const pillW=labelText.length*6.5+16;
      const pillX=rx+rw/2-pillW/2;
      const pillY=ry-16;
      const pillRect=ndL.append('rect').attr('class','region-pill').attr('x',pillX).attr('y',pillY).attr('width',pillW).attr('height',18)
        .attr('rx',9).attr('fill','rgba(59,130,246,.12)').attr('stroke','rgba(59,130,246,.3)').attr('stroke-width',1);
      const pillText=ndL.append('text').attr('class','region-pill-text').attr('x',pillX+pillW/2).attr('y',pillY+12.5)
        .attr('text-anchor','middle').attr('fill','#60a5fa')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(9px * var(--txt-scale,1))')
        .attr('font-weight','600').text(labelText);
    }else{
      ndL.append('text').attr('class','region-label')
        .attr('x',rx+10).attr('y',ry-6)
        .attr('fill',isDisconnected?'var(--accent-red)':'var(--text-muted)')
        .text(rg.region);
    }
  });

  // Region pill collision resolution
  {
    const pillRecs=[];
    ndL.selectAll('.region-pill').each(function(){
      const r=d3.select(this);
      const px=parseFloat(r.attr('x')), py=parseFloat(r.attr('y'));
      const pw=parseFloat(r.attr('width')), ph=parseFloat(r.attr('height'));
      pillRecs.push({x:px,y:py,w:pw,h:ph,rectNode:r});
    });
    if(pillRecs.length>1){
      pillRecs.sort((a,b)=>a.x-b.x);
      _resolveCollisions(pillRecs,{strategy:'shift-x',padding:6});
      pillRecs.forEach(p=>{
        p.rectNode.attr('x',p.x);
        // Move corresponding text
        const nextSib=d3.select(p.rectNode.node().nextElementSibling);
        if(nextSib.classed('region-pill-text')){
          nextSib.attr('x',p.x+p.w/2);
        }
      });
    }
  }

  // VNet boxes
  const tt=document.getElementById('tooltip');
  vL.forEach(vl=>{
    const vG=ndL.append('g').attr('class','vnet-group').attr('data-vnet-id',vl.vnet.id);
    vG.append('rect').attr('x',vl.x).attr('y',vl.y).attr('width',vl.w).attr('height',vl.h).attr('fill','rgba(59,130,246,.03)').attr('stroke','var(--vnet-stroke)').attr('stroke-width',1.5);
    const _vnetName=gn(vl.vnet);
    const regionTag=vnetRegionMap[vl.vnet.id]||'';
    const addrPrefixes=vl.vnet.properties?.addressSpace?.addressPrefixes||[];
    const cidrStr=addrPrefixes[0]||'';
    let cidrFull=cidrStr+(regionTag?' '+regionTag:'');
    // Measure available width and allocate between name and CIDR
    const availW=vl.w-28; // 14px padding each side
    const cidrEstW=cidrFull.length*6.5;
    const nameAvail=Math.max(60, availW-cidrEstW-12);
    const nameMaxW=Math.min(_vnetName.length*8, nameAvail);
    // Truncate name if needed
    const nameMaxChars=Math.max(6, Math.floor(nameAvail/8));
    const truncVnetName=_vnetName.length>nameMaxChars?_vnetName.slice(0,nameMaxChars-1)+'\u2026':_vnetName;
    vG.append('text').attr('class','vnet-label').attr('x',vl.x+14).attr('y',vl.y+26)
      .attr('textLength',nameMaxW).attr('lengthAdjust','spacing').text(truncVnetName);
    // Truncate CIDR if still not enough room
    const cidrAvail=availW-nameMaxW-12;
    const cidrMaxChars=Math.max(8, Math.floor(cidrAvail/6));
    if(cidrFull.length>cidrMaxChars) cidrFull=cidrFull.slice(0,cidrMaxChars-1)+'\u2026';
    vG.append('text').attr('class','vnet-cidr').attr('x',vl.x+vl.w-14).attr('y',vl.y+26).attr('text-anchor','end').text(cidrFull);
    // Subscription color stripe for multi-subscription
    if(_multiSubscription&&vl.vnet._subscriptionId!=='default'){
      const acCol=vl.vnet._ctxColor||getAccountColor(vl.vnet._subscriptionId);
      if(acCol){
        vG.append('rect').attr('x',vl.x).attr('y',vl.y).attr('width',8).attr('height',vl.h).attr('fill',acCol).attr('rx',2).attr('opacity',.7);
        const acLbl=vl.vnet._subscriptionLabel||vl.vnet._subscriptionId;
        const maxChars=Math.floor(vl.h/7);
        vG.append('text').attr('x',vl.x+5).attr('y',vl.y+vl.h-6).attr('transform','rotate(-90,'+((vl.x+5))+','+((vl.y+vl.h-6))+')')
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','#fff').attr('font-weight','600').attr('letter-spacing','.5px')
          .text(acLbl.length>maxChars?acLbl.slice(0,maxChars-1)+'…':acLbl);
      }
    }
    // show indicator for VNets with no subnets
    if(vl.subs.length===0){
      vG.append('text').attr('x',vl.x+vl.w/2).attr('y',vl.y+vl.h/2+10).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text('No subnets');
    }
  });

  // subnets
  vL.forEach(vl=>{
    vl.subs.filter(sl=>sl.sub).forEach(sl=>{
    const sG=ndL.append('g').attr('class','subnet-node').attr('data-subnet-id',sl.sub.id);
    const col=sl.pub?'var(--subnet-public)':'var(--subnet-private)';
    sG.append('rect').attr('x',sl.x).attr('y',sl.y).attr('width',sl.w).attr('height',sl.h).attr('fill',sl.pub?'rgba(6,182,212,.15)':'rgba(139,92,246,.15)').attr('stroke',col).attr('stroke-width',1.2);
    const cid='c-'+sl.sub.id.replace(/[^a-zA-Z0-9]/g,'');
    const badgeText=sl.pub?'PUBLIC':'PRIVATE';
    const badgeW=badgeText.length*5+8;
    const clipW=Math.max(40, sl.w-badgeW-16);
    sG.append('clipPath').attr('id',cid).append('rect').attr('x',sl.x+6).attr('y',sl.y).attr('width',clipW).attr('height',sl.h);
    const tG2=sG.append('g').attr('clip-path',`url(#${cid})`);
    const subName=gn(sl.sub);
    const maxNameChars=Math.floor(clipW/CW);
    const truncName=subName.length>maxNameChars?subName.slice(0,maxNameChars-1)+'\u2026':subName;
    tG2.append('text').attr('class','subnet-label').attr('x',sl.x+8).attr('y',sl.y+18).text(truncName);
    const addrPrefix=sl.sub.properties?.addressPrefix||'';
    const maxCidrChars=Math.floor(clipW/5.5);
    const truncCidr=addrPrefix.length>maxCidrChars?addrPrefix.slice(0,maxCidrChars-1)+'\u2026':addrPrefix;
    tG2.append('text').attr('class','subnet-cidr').attr('x',sl.x+8).attr('y',sl.y+30).text(truncCidr);
    sG.append('text').attr('x',sl.x+sl.w-8).attr('y',sl.y+14).attr('text-anchor','end').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','600').attr('fill',col).text(badgeText);

    // resource icons inside subnet (tree-based with nesting)
    const tree=subTrees[sl.sub.id]||[];
    
    if(_detailLevel===0&&tree.length>0){
      // collapsed: show resource count summary
      const counts={};
      tree.forEach(r=>{counts[r.type]=(counts[r.type]||0)+1});
      const summary=Object.entries(counts).map(([t,c])=>c+' '+t).join(', ');
      sG.append('text').attr('x',sl.x+8).attr('y',sl.y+sl.h-6)
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))').attr('fill','var(--text-muted)').attr('opacity',.5).text(summary);
    } else if(tree.length>0){
      const effectiveCols=Math.min(_dynamicResCols(sl.w), tree.length);
      const iconW=Math.max(70,Math.floor((sl.w-16)/effectiveCols)-RES_GAP);
      const maxCh=Math.max(0,...tree.map(r=>(r.children||[]).length));
      const rowH=RES_ICON+maxCh*RES_CHILD_H+6;
      let rx=sl.x+6, ry=sl.y+RES_TOP, rci=0;
      tree.forEach((res,ri)=>{
        if(rci>=effectiveCols){rci=0;rx=sl.x+6;ry+=rowH;}
        const nCh=(res.children||[]).length;
        const iconH=RES_ICON+nCh*RES_CHILD_H;
        // wrap in interactive group
        const rG=sG.append('g').attr('class','res-node').style('cursor','pointer');
        if(res.rid) rG.attr('data-id',res.rid);
        const _rx=rx,_ry=ry;
        rG.on('mouseenter',function(event){
          event.stopPropagation();
          if(!_hlLocked) hlSub(sl.sub.id);
          tt.innerHTML=resTooltipHtml(res,sl.sub.id,subUDR);
          tt.style.display='block';
        }).on('mousemove',function(event){
          positionTooltip(event,tt);
        }).on('mouseleave',function(){
          tt.style.display='none';
        });
        // outer box
        rG.append('rect').attr('x',rx).attr('y',ry).attr('width',iconW).attr('height',iconH)
          .attr('rx',3).attr('fill',res.bg).attr('stroke',res.col).attr('stroke-width',.7);
        // type badge
        rG.append('rect').attr('x',rx).attr('y',ry).attr('width',24).attr('height',iconH)
          .attr('rx',3).attr('fill',res.col).attr('fill-opacity',.3);
        rG.append('text').attr('x',rx+12).attr('y',ry+13).attr('text-anchor','middle')
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7.5px * var(--txt-scale,1))').attr('font-weight','700')
          .attr('fill',res.col).text(res.type);
        // clip for text overflow
        const nameClip='rc-'+sl.sub.id.replace(/[^a-zA-Z0-9]/g,'')+'-'+ri;
        rG.append('clipPath').attr('id',nameClip).append('rect')
          .attr('x',rx+26).attr('y',ry).attr('width',iconW-28).attr('height',iconH);
        // name
        rG.append('text').attr('x',rx+28).attr('y',ry+10).attr('clip-path',`url(#${nameClip})`)
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600')
          .attr('fill','var(--text-primary)').text(res.name);
        // IP
        if(res.ip){
          rG.append('text').attr('x',rx+28).attr('y',ry+20).attr('clip-path',`url(#${nameClip})`)
            .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))')
            .attr('fill','var(--text-muted)').text(res.ip);
        }
        // state dot
        if(res.state){
          const sc=res.stateDot||(res.state==='running'?'#10b981':'#ef4444');
          rG.append('circle').attr('cx',rx+iconW-6).attr('cy',ry+6).attr('r',2.5).attr('fill',sc);
        }
        // nested children
        if(nCh>0){
          (res.children||[]).forEach((ch,ci)=>{
            const cy2=ry+RES_ICON-2+ci*RES_CHILD_H;
            const cx2=rx+26,cw=iconW-30,ch2=RES_CHILD_H-2;
            rG.append('rect').attr('x',cx2).attr('y',cy2).attr('width',cw).attr('height',ch2)
              .attr('rx',2).attr('fill',ch.bg).attr('stroke',ch.col).attr('stroke-width',.4);
            rG.append('text').attr('x',cx2+2).attr('y',cy2+ch2/2+2)
              .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))').attr('font-weight','600')
              .attr('fill',ch.col).text(ch.type);
            rG.append('text').attr('x',cx2+19).attr('y',cy2+ch2/2+2).attr('clip-path',`url(#${nameClip})`)
              .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))')
              .attr('fill','var(--text-secondary)').text(ch.name+(ch.detail?' '+ch.detail:''));
          });
        }
        rx+=iconW+RES_GAP;
        rci++;
      });
    } else {
      // empty subnet indicator
      sG.append('text').attr('x',sl.x+sl.w/2).attr('y',sl.y+sl.h/2+4).attr('text-anchor','middle')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','var(--text-muted)').attr('opacity',.4).text('No resources');
    }

    // click to open detail panel, hover for highlight only
    sG.on('mouseenter',function(){if(!_hlLocked)hlSub(sl.sub.id)})
    .on('mouseleave',()=>{clr()})
    .on('click',function(event){
      event.stopPropagation();
      const sid2=sl.sub.id;
      if(_hlLocked&&_hlKey===sid2&&_hlType==='sub'){
        // already locked on this subnet, just open panel
      } else {
        forceClr();hlSub(sid2);
        _hlLocked=true;_hlKey=sid2;_hlType='sub';showLockInd(true);
      }
      _lastRlType=null;_navStack=[];
      openSubnetPanel(sl.sub,vl.vnet.id,{pubSubs,subUDR,subNsg,vmBySub,nicBySub,agwBySub,lbBySub,nsgByVnet,diskByVm,nics,snapByDisk,wafByAgw,sqlBySub,containerBySub,fnBySub,aksBySub,redisByVnet,synapseByVnet,fdByAgw});
    });
  })});

  // gateway circles -- skip PEs (they get summary boxes instead)
  gwP.forEach((pos,id)=>{
    if(peIds.has(id))return;
    const gw=pos.gw,gG=ndL.append('g').attr('class','gw-node').attr('data-gwid',id),col=gcv(gw.type);
    gG.append('circle').attr('cx',pos.x).attr('cy',pos.y).attr('r',GR).attr('fill','var(--bg-primary)').attr('stroke',col).attr('stroke-width',2);
    gG.append('text').attr('class','gw-label').attr('x',pos.x).attr('y',pos.y+1).attr('text-anchor','middle').attr('dominant-baseline','middle').attr('fill',col).text(gw.type);
    const nm=gwNames[gw.id];
    const lblY=pos.y+GR+14;
    const lblTxt=nm&&nm!==gw.id?nm:sid(gw.id);
    const lblClass=nm&&nm!==gw.id?'gw-name':'gw-id';
    // Truncate long gateway names
    const maxGwLblChars=20;
    const truncGwLbl=lblTxt.length>maxGwLblChars?lblTxt.slice(0,maxGwLblChars-1)+'\u2026':lblTxt;
    const tw=truncGwLbl.length*6.2+16;
    gG.append('rect').attr('x',pos.x-tw/2).attr('y',lblY-9).attr('width',tw).attr('height',15).attr('rx',4).attr('class','gw-label-bg').attr('fill','var(--overlay-bg)').attr('stroke','var(--hover-bg)').attr('stroke-width',.5);
    gG.append('text').attr('class',lblClass).attr('x',pos.x).attr('y',lblY).attr('text-anchor','middle').text(truncGwLbl);
    gG.on('mouseenter',function(){
      if(_hlLocked) return;
      hlGw(id);
      ndL.selectAll('.gw-node').classed('gw-hl',false);
      gG.classed('gw-hl',true);
      let h=`<div class="tt-title">${nm||sid(gw.id)}</div><div class="tt-sub">${gw.type} | ${sid(gw.id)}</div>`;
      const natInfo=natGateways.find(n=>n.id===gw.id);
      if(natInfo){h+=`<div class="tt-sec"><div class="tt-sh">NAT Gateway</div><div class="tt-r">Subnets: <span class="i">${(natInfo.properties?.subnets||[]).map(s=>sid(s.id)).join(', ')||'N/A'}</span></div><div class="tt-r">State: ${natInfo.properties?.provisioningState||'N/A'}</div></div>`}
      tt.innerHTML=h;tt.style.display='block';
    }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none';clr()})
    .on('click',function(event){
      event.stopPropagation();
      if(_hlLocked&&_hlKey===id&&_hlType==='gw'){forceClr();return}
      forceClr();hlGw(id);
      ndL.selectAll('.gw-node').classed('gw-hl',false);gG.classed('gw-hl',true);
      _hlLocked=true;_hlKey=id;_hlType='gw';showLockInd(true);
      _lastRlType=null;_navStack=[];
      openGatewayPanel(gw.id,gw.type,{gwNames,firewalls,bastions,natGateways,vpnConnections,privateEndpoints,peerings,udrs,subnets,subUDR,pubSubs,vnets,vwans});
    });
  });

  // Gateway label collision resolution
  {
    const gwLabelRecs=[];
    ndL.selectAll('.gw-node').each(function(){
      const g=d3.select(this);
      const bg=g.select('.gw-label-bg');
      const txt=g.select('.gw-name, .gw-id');
      if(!bg.node()||!txt.node()) return;
      const bx=parseFloat(bg.attr('x')), by=parseFloat(bg.attr('y'));
      const bw=parseFloat(bg.attr('width')), bh=parseFloat(bg.attr('height'));
      gwLabelRecs.push({x:bx,y:by,w:bw,h:bh,rectNode:bg,textNode:txt,textAnchor:'middle',textOffY:9,textPadX:0});
    });
    if(gwLabelRecs.length>1){
      gwLabelRecs.sort((a,b)=>a.y-b.y||a.x-b.x);
      _resolveCollisions(gwLabelRecs,{strategy:'shift-y',padding:3});
      _applyLabelPositions(gwLabelRecs);
    }
  }

  // internet node - positioned at top-left (Azure Firewall connects to Internet)
  if(fwGwList.length){
    const iG=ndL.append('g').attr('class','internet-node');
    // Outer glow
    iG.append('circle').attr('cx',iX).attr('cy',iY).attr('r',42)
      .attr('fill','none').attr('stroke','var(--fw-color)').attr('stroke-width',1).attr('opacity',.15);
    // Main circle
    iG.append('circle').attr('cx',iX).attr('cy',iY).attr('r',36)
      .attr('fill','rgba(16,185,129,.06)').attr('stroke','var(--fw-color)').attr('stroke-width',2);
    // Globe effect
    iG.append('ellipse').attr('cx',iX).attr('cy',iY).attr('rx',22).attr('ry',36)
      .attr('fill','none').attr('stroke','var(--fw-color)').attr('stroke-width',1).attr('opacity',.25);
    iG.append('line').attr('x1',iX-36).attr('y1',iY).attr('x2',iX+36).attr('y2',iY)
      .attr('stroke','var(--fw-color)').attr('stroke-width',1).attr('opacity',.25);
    // Text inside circle
    iG.append('text').attr('x',iX).attr('y',iY+4).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(13px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','var(--fw-color)').text('NET');
    // Text below circle
    iG.append('text').attr('x',iX).attr('y',iY+50).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text('Internet');
    iG.append('text').attr('x',iX).attr('y',iY+62).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','var(--fw-color)').text(fwGwList.length+' Firewall'+(fwGwList.length>1?'s':''));
    
    // Draw NET connections: L-shaped paths from bus-bar to each Azure Firewall.
    // Each Firewall gets its own L-bend: horizontal from NET node at bus-bar Y,
    // then vertical down to Firewall. No continuous bus bar — eliminates dead ends.
    const connectedFwIds=new Set(Object.keys(tG).map(k=>k.split('|')[0]));
    const connectedFwList=fwGwList.filter(p=>connectedFwIds.has(p.gw.id));
    // Group by X to handle stacked gateways at same position
    const netXGroups=new Map();
    connectedFwList.forEach(pos=>{
      const gx=pos.x;
      if(!netXGroups.has(gx)) netXGroups.set(gx,[]);
      netXGroups.get(gx).push(pos);
    });
    // Collect X positions that reach bus-bar Y, sorted left to right
    const netXPositions=[];
    netXGroups.forEach((group,gx)=>{
      group.sort((a,b)=>(a.y-GR-4)-(b.y-GR-4));
      let reachesBus=false;
      for(let i=0;i<group.length;i++){
        const topY=i===0?iY:(group[i-1].y-GR-4);
        const botY=group[i].y-GR-4;
        const col='var(--fw-color)';
        if(Math.abs(botY-topY)>2){
          structG.append('path')
            .attr('class','route-trunk route-structural')
            .attr('d',`M${gx},${topY} L${gx},${botY}`)
            .attr('stroke',col).attr('stroke-width',3)
            .attr('data-gid',group[i].gw.id).attr('data-net-vert','1');
          if(topY===iY) reachesBus=true;
        }
      }
      if(reachesBus) netXPositions.push(gx);
    });
    netXPositions.sort((a,b)=>a-b);
    // Draw one horizontal bus from NET node to rightmost FW column
    if(netXPositions.length>0){
      const rightmostNetX=netXPositions[netXPositions.length-1];
      structG.append('path')
        .attr('class','route-trunk route-structural')
        .attr('d',`M${iX+38},${iY} L${rightmostNetX},${iY}`)
        .attr('stroke','var(--fw-color)').attr('stroke-width',3)
        .attr('data-net-line','1');
    }
  }

  // PE: at detail level 0 show summary badge; at level >= 1 PEs render inside subnets via buildResTree
  if(_detailLevel===0){
    vL.forEach(vl=>{
      const vnetPEs=peByVnet[vl.vnet.id]||[];
      if(!vnetPEs.length)return;
      const nw=70,nh=16;
      const gx=vl.x+nw/2+8;
      const ny=vl.y+vl.h-nh-8;
      const eG=ndL.append('g').attr('class','pe-summary').style('cursor','pointer');
      eG.append('rect').attr('x',gx-nw/2).attr('y',ny).attr('width',nw).attr('height',nh).attr('rx',3)
        .attr('fill','rgba(167,139,250,.2)').attr('stroke','var(--pe-color)').attr('stroke-width',1);
      eG.append('text').attr('x',gx).attr('y',ny+12).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600').attr('fill','var(--pe-color)').text(vnetPEs.length+' PE');
      eG.on('mouseenter',function(){
        const tip=document.createElement('div');
        const title=document.createElement('div');title.className='tt-title';title.textContent='Private Endpoints ('+vnetPEs.length+')';tip.appendChild(title);
        const sub=document.createElement('div');sub.className='tt-sub';sub.textContent=gn(vl.vnet);tip.appendChild(sub);
        const sec=document.createElement('div');sec.className='tt-sec';
        const sh=document.createElement('div');sh.className='tt-sh';sh.textContent='Endpoints';sec.appendChild(sh);
        vnetPEs.forEach(v=>{
          const pe=peById.get(v.id);
          const conn=pe?.properties?.privateLinkServiceConnections?.[0];
          const svc=(conn?.properties?.groupIds||[])[0]||'?';
          const state=conn?.properties?.privateLinkServiceConnectionState?.status||'?';
          const stCol=state==='Approved'?'#10b981':state==='Pending'?'#f59e0b':'#ef4444';
          const r=document.createElement('div');r.className='tt-r';
          const sp=document.createElement('span');sp.className='i';sp.textContent=gwNames[v.id]||sid(v.id);r.appendChild(sp);
          r.appendChild(document.createTextNode(' '+svc+' '));
          const stSp=document.createElement('span');stSp.style.color=stCol;stSp.textContent=state;r.appendChild(stSp);
          sec.appendChild(r);
        });
        tip.appendChild(sec);
        tt.textContent='';tt.appendChild(tip);tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('PE')});
    });
  }

  // PE→Service connection lines (detail level >= 1)
  if(_detailLevel>=1){
    // Build a map of rendered resource positions from the subnet tree nodes
    const peTargetPositions=new Map();
    // Map target resource IDs to their rendered position
    const renderedResPos=new Map();
    ndL.selectAll('.res-node[data-id]').each(function(){
      const el=d3.select(this);
      const rid=el.attr('data-id');
      if(!rid)return;
      const rect=el.select('rect');
      if(!rect.node())return;
      const rx=parseFloat(rect.attr('x')),ry=parseFloat(rect.attr('y'));
      const rw=parseFloat(rect.attr('width')),rh=parseFloat(rect.attr('height'));
      renderedResPos.set(rid,{x:rx+rw/2,y:ry+rh/2,w:rw,h:rh});
    });

    privateEndpoints.forEach(pe=>{
      const props=pe.properties||{};
      const conn=(props.privateLinkServiceConnections||[])[0];
      if(!conn)return;
      const connProps=conn.properties||{};
      const targetId=connProps.privateLinkServiceId||'';
      const state=connProps.privateLinkServiceConnectionState?.status||'Approved';
      const stCol=state==='Approved'?'#10b981':state==='Pending'?'#f59e0b':'#ef4444';
      const groupId=(connProps.groupIds||[])[0]||'';

      // Find this PE's rendered position (as a res-node inside a subnet)
      const pePos=renderedResPos.get(pe.id);
      if(!pePos)return;

      // Check if target is rendered in-topology
      const targetPos=renderedResPos.get(targetId);
      if(targetPos){
        // Draw dashed bezier from PE to target service node
        const dx=targetPos.x-pePos.x;
        const cpOff=Math.min(Math.abs(dx)*0.4,80);
        const path=`M${pePos.x},${pePos.y} C${pePos.x+cpOff},${pePos.y} ${targetPos.x-cpOff},${targetPos.y} ${targetPos.x},${targetPos.y}`;
        lnL.append('path').attr('class','pe-service-line')
          .attr('d',path).attr('fill','none')
          .attr('stroke',stCol).attr('stroke-width',1.5)
          .attr('stroke-dasharray','6,3').attr('opacity',.6)
          .attr('data-pe-id',pe.id).attr('data-target-id',targetId);
      } else if(targetId){
        // External target: render a small badge to the right of the PE node
        const badgeX=pePos.x+pePos.w/2+4;
        const badgeY=pePos.y-pePos.h/2;
        const targetName=targetId.split('/').pop();
        const shortName=targetName.length>12?targetName.slice(0,11)+'…':targetName;
        const bG=ndL.append('g').attr('class','pe-ext-target').style('cursor','default');
        bG.append('rect').attr('x',badgeX).attr('y',badgeY).attr('width',70).attr('height',12).attr('rx',2)
          .attr('fill',stCol+'18').attr('stroke',stCol).attr('stroke-width',.6);
        bG.append('text').attr('x',badgeX+35).attr('y',badgeY+9).attr('text-anchor','middle')
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))')
          .attr('fill',stCol).text(shortName);
        // Connector line from PE to badge
        lnL.append('line').attr('class','pe-service-line')
          .attr('x1',pePos.x+pePos.w/2).attr('y1',pePos.y)
          .attr('x2',badgeX).attr('y2',badgeY+6)
          .attr('stroke',stCol).attr('stroke-width',1).attr('stroke-dasharray','3,2').attr('opacity',.5);
      }
    });
  }

  // Build PE→DNS match map for resolution visualization
  const PE_GROUP_DNS_MAP={
    sqlServer:'privatelink.database.windows.net',blob:'privatelink.blob.core.windows.net',
    table:'privatelink.table.core.windows.net',queue:'privatelink.queue.core.windows.net',
    file:'privatelink.file.core.windows.net',vault:'privatelink.vaultcore.azure.net',
    redisCache:'privatelink.redis.cache.windows.net',namespace:'privatelink.servicebus.windows.net',
    cosmosdb:'privatelink.documents.azure.com',registry:'privatelink.azurecr.io',
    sites:'privatelink.azurewebsites.net',Sql:'privatelink.sql.azuresynapse.net',
    searchService:'privatelink.search.windows.net',account:'privatelink.cognitiveservices.azure.com',
    dfs:'privatelink.dfs.core.windows.net',web:'privatelink.web.core.windows.net',
  };
  const dnsZoneByName=new Map();
  dnsZones.forEach(z=>{
    const name=(z.name||z.Name||'').toLowerCase();
    if(name) dnsZoneByName.set(name,z);
  });
  const peDnsMatch=new Map();
  privateEndpoints.forEach(pe=>{
    const props=pe.properties||{};
    const conn=(props.privateLinkServiceConnections||[])[0];
    const connProps=conn?.properties||{};
    const groupId=(connProps.groupIds||[])[0]||'';
    const expectedZone=PE_GROUP_DNS_MAP[groupId]||'';
    const matchedZone=expectedZone?dnsZoneByName.get(expectedZone.toLowerCase()):null;
    const subId=props.subnet?.id||'';
    const vnetId=subId?subId.split('/subnets/')[0]:'';
    let vnetLinked=false;
    if(matchedZone){
      const mzProps=matchedZone.properties||matchedZone._azure?.properties||{};
      vnetLinked=(mzProps.virtualNetworkLinks||[]).some(l=>{
        const lv=l.properties?.virtualNetwork?.id||l.id||'';
        return lv.toLowerCase()===vnetId.toLowerCase();
      });
    }
    const fqdn=(props.customDnsConfigs||[])[0]?.fqdn||'';
    const ip=(props.customDnsConfigs||[])[0]?.ipAddresses?.[0]||'';
    const broken=!matchedZone||(matchedZone&&!vnetLinked);
    peDnsMatch.set(pe.id,{expectedZone,matchedZone,vnetLinked,broken,ip,fqdn,groupId});
  });

  // Private DNS zone badges - positioned at bottom-right of VNet
  const vnetById = new Map((vnets || []).map(v => [v.id, v]));
  let dnsBoxH=0;
  if(dnsZones.length>0){
    const privZonesByVnet={};
    dnsZones.forEach(z=>{
      const isPrivate=z.properties?.zoneType==='Private';
      if(isPrivate&&z.properties?.virtualNetworkLinks){
        z.properties.virtualNetworkLinks.forEach(v=>{
          const vid=v.properties?.virtualNetwork?.id||v.id;
          if(vid)(privZonesByVnet[vid]=privZonesByVnet[vid]||[]).push(z);
        });
      }
    });
    vL.forEach(vl=>{
      const pz=privZonesByVnet[vl.vnet.id];
      if(!pz||!pz.length)return;
      // Skip VNets without valid layout - must have reasonable size and position
      if(!vl.w||vl.w<50||!vl.h||vl.h<50) return;
      // Skip if position is clearly wrong (too far from diagram area)
      if(vl.x<0||vl.y<0||vl.x>10000||vl.y>10000) return;
      // Skip unknown/disconnected VNets
      if(unknownVL.includes(vl)) return;
      // Skip VNets with no subnets rendered
      if(!vl.subs||vl.subs.length===0) return;
      const nw=70,nh=16;
      // Position badge at bottom-right of VNet (inside the VNet box)
      const gx=vl.x+vl.w-nw/2-8;
      const ny=vl.y+vl.h-nh-8;
      const dG=ndL.append('g').attr('class','dns-summary').style('cursor','pointer');
      dG.append('rect').attr('x',gx-nw/2).attr('y',ny).attr('width',nw).attr('height',nh).attr('rx',3)
        .attr('fill','rgba(14,165,233,.15)').attr('stroke','#0ea5e9').attr('stroke-width',1);
      dG.append('text').attr('x',gx).attr('y',ny+12).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600').attr('fill','#0ea5e9').text(pz.length+' DNS');
      dG.on('mouseenter',function(){
        let h='<div class="tt-title">Private DNS Zones ('+pz.length+')</div>';
        h+='<div class="tt-sub">'+gn(vl.vnet)+'</div>';
        h+='<div class="tt-sec"><div class="tt-sh">Zones</div>';
        pz.forEach(z=>{
          h+='<div class="tt-r"><span class="i">'+esc(z.name||'')+'</span> '+(z.properties?.numberOfRecordSets||0)+' records</div>';
        });
        h+='</div>';
        tt.innerHTML=h;tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('DNS')});
    });

    // PE→DNS resolution lines + broken chain warnings (detail level >= 1)
    if(_detailLevel>=1){
      // Collect DNS badge positions from the rendered badges
      const dnsBadgePos=new Map();
      ndL.selectAll('.dns-summary').each(function(){
        const g=d3.select(this);
        const rect=g.select('rect');
        if(!rect.node())return;
        const bx=parseFloat(rect.attr('x')),by=parseFloat(rect.attr('y'));
        const bw=parseFloat(rect.attr('width')),bh=parseFloat(rect.attr('height'));
        const cx=bx+bw/2,cy=by+bh/2;
        // Find which VNet this badge belongs to by checking vL positions
        vL.forEach(vl=>{
          if(cx>=vl.x&&cx<=vl.x+vl.w&&cy>=vl.y&&cy<=vl.y+vl.h){
            // Map all DNS zones in this VNet to this badge position
            const pzArr=privZonesByVnet[vl.vnet.id]||[];
            pzArr.forEach(z=>{
              const zName=(z.name||z.Name||'').toLowerCase();
              if(zName&&!dnsBadgePos.has(zName)) dnsBadgePos.set(zName,{x:cx,y:cy,vnetId:vl.vnet.id});
            });
          }
        });
      });

      privateEndpoints.forEach(pe=>{
        const match=peDnsMatch.get(pe.id);
        if(!match)return;
        const pePos=renderedResPos.get(pe.id);
        if(!pePos)return;

        if(match.broken){
          // Broken chain: draw orange warning triangle near PE node
          const wx=pePos.x-pePos.w/2-8,wy=pePos.y-pePos.h/2-2;
          const wG=ndL.append('g').attr('class','pe-dns-warn').style('cursor','default');
          wG.append('text').attr('x',wx).attr('y',wy).attr('text-anchor','middle')
            .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(10px * var(--txt-scale,1))')
            .attr('fill','#f59e0b').text('\u26A0');
          wG.on('mouseenter',function(){
            const tip=document.createElement('div');
            const t=document.createElement('div');t.className='tt-title';t.style.color='#f59e0b';
            t.textContent='DNS Resolution Broken';tip.appendChild(t);
            const sec=document.createElement('div');sec.className='tt-sec';
            if(!match.matchedZone){
              const r=document.createElement('div');r.className='tt-r';r.textContent='No DNS zone "'+match.expectedZone+'" found';sec.appendChild(r);
            } else if(!match.vnetLinked){
              const r=document.createElement('div');r.className='tt-r';r.textContent='Zone "'+match.expectedZone+'" not linked to PE VNet';sec.appendChild(r);
            }
            if(match.fqdn){const f=document.createElement('div');f.className='tt-r';f.textContent='FQDN: '+match.fqdn;sec.appendChild(f)}
            tip.appendChild(sec);
            tt.textContent='';tt.appendChild(tip);tt.style.display='block';
          }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'});
        } else if(match.expectedZone){
          // Working chain: draw thin dotted line from PE to DNS badge
          const dnsPos=dnsBadgePos.get(match.expectedZone.toLowerCase());
          if(dnsPos){
            lnL.append('line').attr('class','pe-dns-line')
              .attr('x1',pePos.x).attr('y1',pePos.y+pePos.h/2)
              .attr('x2',dnsPos.x).attr('y2',dnsPos.y)
              .attr('stroke','#0ea5e9').attr('stroke-width',.8)
              .attr('stroke-dasharray','2,3').attr('opacity',.4)
              .attr('data-pe-id',pe.id);
          }
        }
      });
    }

    // DNS Zone section - positioned below all routing elements
    const dnsY=routingBottomY+40;
    const pubZones=dnsZones.filter(z=>z.properties?.zoneType!=='Private');
    const privZones=dnsZones.filter(z=>z.properties?.zoneType==='Private');
    const dnsBoxW=Math.max(320,allVnetRight-60);
    const dnsRecExp=_dnsRecordsExpanded;
    const recRowH=14;

    // Pre-calculate zone heights and positions
    const zoneLayouts=[];
    if(dnsRecExp){
      // Records expanded: single column, metadata + records nested inside
      const fullW=dnsBoxW-40;
      let cy=0;
      dnsZones.forEach(z=>{
        const zName=z.name||'';
        const isPub=z.properties?.zoneType!=='Private';
        const zRecs=recsByZoneMap[zName]||[];
        const assocVnets=(!isPub&&z.properties?.virtualNetworkLinks)?z.properties.virtualNetworkLinks.map(v=>{const vid=v.properties?.virtualNetwork?.id||'';const vnet=vnetById.get(vid);return gn(vnet||{})}).join(', '):'';
        let metaLines=2;
        if(assocVnets)metaLines++;
        const headerH=18+metaLines*14+4;
        const recsH=zRecs.length>0?(4+zRecs.length*recRowH):16;
        const zh=headerH+recsH+6;
        zoneLayouts.push({x:70,y:cy,w:fullW,h:zh,recs:zRecs,assocVnets});
        cy+=zh+6;
      });
    }else{
      // Default: 2-column compact zones with record count
      const colW2=Math.min(450,(dnsBoxW-40)/2);
      dnsZones.forEach((z,zi)=>{
        const col=zi%2;
        const row=Math.floor(zi/2);
        zoneLayouts.push({x:70+col*(colW2+10),y:row*32,w:colW2-10,h:26,recs:[]});
      });
    }
    const totalContentH=dnsRecExp?
      (zoneLayouts.length>0?zoneLayouts[zoneLayouts.length-1].y+zoneLayouts[zoneLayouts.length-1].h:0):
      (Math.ceil(dnsZones.length/2)*32);
    dnsBoxH=60+totalContentH+20;

    const dnsG=ndL.append('g').attr('class','dns-section');

    // Section container
    dnsG.append('rect').attr('x',60).attr('y',dnsY).attr('width',dnsBoxW).attr('height',dnsBoxH).attr('rx',8)
      .attr('fill','rgba(14,165,233,.06)').attr('stroke','#0ea5e9').attr('stroke-width',1.5).attr('stroke-dasharray','6 3');

    // Section title
    dnsG.append('text').attr('x',80).attr('y',dnsY+22).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(14px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','#0ea5e9').text('Azure DNS Zones');
    dnsG.append('text').attr('x',80).attr('y',dnsY+36).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(pubZones.length+' public, '+privZones.length+' private');

    // Records expand/collapse toggle button
    const togX=60+dnsBoxW-80;
    const togY=dnsY+8;
    const togG=dnsG.append('g').style('cursor','pointer');
    togG.append('rect').attr('x',togX).attr('y',togY).attr('width',70).attr('height',20).attr('rx',4)
      .attr('fill','rgba(14,165,233,.15)').attr('stroke','#0ea5e9').attr('stroke-width',0.8);
    togG.append('text').attr('x',togX+35).attr('y',togY+14).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600')
      .attr('fill','#0ea5e9').text(dnsRecExp?'\u25B2 Collapse':'\u25BC Expand');
    togG.on('click',function(event){
      event.stopPropagation();
      _dnsRecordsExpanded=!_dnsRecordsExpanded;
      renderMap();
    });

    const colW=Math.min(450,(dnsBoxW-40)/2);

    dnsZones.forEach((z,zi)=>{
      const isPub=z.properties?.zoneType!=='Private';
      const zid=z.name||sid(z.id);
      const lay=zoneLayouts[zi];
      const zx=lay.x;
      const zy=dnsY+52+lay.y;
      const zw=lay.w;
      const zh=lay.h;

      const zG=dnsG.append('g').style('cursor','pointer');
      zG.append('rect').attr('x',zx).attr('y',zy).attr('width',zw).attr('height',zh).attr('rx',4)
        .attr('fill',isPub?'rgba(16,185,129,.18)':'rgba(14,165,233,.18)')
        .attr('stroke',isPub?'#10b981':'#0ea5e9').attr('stroke-width',1.5);

      // Icon indicator
      zG.append('circle').attr('cx',zx+12).attr('cy',zy+13).attr('r',6)
        .attr('fill',isPub?'#10b981':'#0ea5e9');
      zG.append('text').attr('x',zx+12).attr('y',zy+16.5).attr('text-anchor','middle')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','700')
        .attr('fill','#fff').text(isPub?'P':'R');

      // Zone name (full in expanded, truncated in compact)
      const recLabel=(z.properties?.numberOfRecordSets||0)+' records';
      const zoneName=z.name||'';
      const maxNameLen=dnsRecExp?999:Math.max(12,Math.floor((zw-80)/6));
      const dispName=dnsRecExp?zoneName:(zoneName.length>maxNameLen?zoneName.substring(0,maxNameLen-2)+'..':zoneName);
      zG.append('text').attr('x',zx+24).attr('y',zy+15).attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(10px * var(--txt-scale,1))').attr('font-weight','600').attr('fill',isPub?'#10b981':'#0ea5e9')
        .text(dispName);

      // Compact: record count only
      if(!dnsRecExp){
        zG.append('text').attr('x',zx+zw-8).attr('y',zy+15).attr('text-anchor','end')
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(9px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
          .text(recLabel);
      }

      // Records expanded: metadata lines + record rows
      if(dnsRecExp){
        let my=zy+18;
        // Metadata: Zone ID
        zG.append('text').attr('x',zx+24).attr('y',my+14).attr('font-family','Segoe UI,system-ui,sans-serif')
          .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
          .text('Zone: '+zid+'  |  '+(z.properties?.numberOfRecordSets||0)+' records  |  '+(isPub?'Public':'Private'));
        my+=14;
        // Metadata: Associated VNets (if private)
        if(lay.assocVnets){
          zG.append('text').attr('x',zx+24).attr('y',my+14).attr('font-family','Segoe UI,system-ui,sans-serif')
            .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
            .text('VNets: '+lay.assocVnets);
          my+=14;
        }

        // Record sets (if available)
        if(lay.recs.length>0){
          my+=4;
          zG.append('line').attr('x1',zx+8).attr('y1',my).attr('x2',zx+zw-8).attr('y2',my)
            .attr('stroke',isPub?'#10b981':'#0ea5e9').attr('stroke-width',0.5).attr('stroke-opacity',0.4);
          my+=4;
          lay.recs.forEach(rec=>{
            const rName=(rec.name||'').replace(/\.$/,'');
            const rType=rec.properties?.type||rec.type||'';
            const rVal=rec.properties?.cnameRecord?'CNAME \u2192 '+(rec.properties.cnameRecord.cname||''):
              (rec.properties?.aRecords||rec.properties?.aaaaRecords||[]).map(rr=>rr.ipv4Address||rr.ipv6Address||'').join(', ');
            zG.append('text').attr('x',zx+10).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
              .style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','600').attr('fill',isPub?'#059669':'#0284c7')
              .text(rType);
            zG.append('text').attr('x',zx+50).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
              .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-primary)')
              .text(rName.length>50?rName.substring(0,48)+'..':rName);
            zG.append('text').attr('x',zx+350).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
              .style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
              .text(rVal.length>80?rVal.substring(0,78)+'..':rVal);
            my+=recRowH;
          });
        }else{
          my+=6;
          zG.append('text').attr('x',zx+24).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
            .style('font-size','calc(8px * var(--txt-scale,1))').attr('font-style','italic').attr('fill','var(--text-muted)')
            .text('Click zone for details \u2022 Load record sets via "Record Sets" input');
        }
      }

      // Tooltip (always)
      zG.on('mouseenter',function(){
        let h='<div class="tt-title">'+(isPub?'Public':'Private')+' DNS Zone</div>';
        h+='<div class="tt-sub">'+esc(z.name||'')+'</div>';
        h+='<div class="tt-sec">';
        h+='<div class="tt-r"><span class="i">Zone</span> '+esc(zid)+'</div>';
        h+='<div class="tt-r"><span class="i">Records</span> '+(z.properties?.numberOfRecordSets||0)+'</div>';
        h+='<div class="tt-r"><span class="i">Type</span> '+(isPub?'Public':'Private')+'</div>';
        if(!isPub&&z.properties?.virtualNetworkLinks&&z.properties.virtualNetworkLinks.length>0){
          h+='<div class="tt-sh" style="margin-top:6px">Associated VNets</div>';
          z.properties.virtualNetworkLinks.forEach(v=>{
            const vid=v.properties?.virtualNetwork?.id||'';
            const vnet=vnetById.get(vid);
            h+='<div class="tt-r"><span class="i">'+gn(vnet||{})+'</span> '+esc(sid(vid))+'</div>';
          });
        }
        h+='</div>';
        tt.innerHTML=h;tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('DNS')});
    });
  }

  // Storage Accounts section - positioned below DNS section (or below routing if no DNS)
  const dnsExists=dnsZones.length>0;
  const dnsBase=routingBottomY+40;
  const dnsSectionH=dnsExists?dnsBoxH:0;
  let sectionBottomY=dnsExists?(dnsBase+dnsSectionH):(routingBottomY);
  if(storageAccounts.length>0){
    const saY=sectionBottomY+40;
    const saBoxW=Math.max(320,allVnetRight-60);
    const saCols=3;
    const saColW=Math.min(320,(saBoxW-40)/saCols);
    const saRowH=24;
    const saRows=Math.ceil(storageAccounts.length/saCols);
    const saBoxH=50+saRows*(saRowH+4)+20;

    const saG=ndL.append('g').attr('class','storage-section');
    saG.append('rect').attr('x',60).attr('y',saY).attr('width',saBoxW).attr('height',saBoxH).attr('rx',8)
      .attr('fill','rgba(234,88,12,.04)').attr('stroke','#ea580c').attr('stroke-width',1.5).attr('stroke-dasharray','6 3');
    saG.append('text').attr('x',80).attr('y',saY+22).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(14px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','#ea580c').text('Storage Accounts');
    saG.append('text').attr('x',80).attr('y',saY+36).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(storageAccounts.length+' accounts');

    storageAccounts.forEach((sa,bi)=>{
      const col=bi%saCols;
      const row=Math.floor(bi/saCols);
      const bx=70+col*(saColW+5);
      const by=saY+48+row*(saRowH+4);

      const bG=saG.append('g').style('cursor','pointer');
      bG.append('rect').attr('x',bx).attr('y',by).attr('width',saColW-10).attr('height',saRowH).attr('rx',3)
        .attr('fill','rgba(234,88,12,.1)').attr('stroke','#ea580c').attr('stroke-width',0.8);

      const saName=sa.name||sid(sa.id)||'';
      const maxChars=Math.floor((saColW-20)/6);
      const dispName=saName.length>maxChars?saName.substring(0,maxChars-2)+'..':saName;
      bG.append('text').attr('x',bx+6).attr('y',by+16).attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(10px * var(--txt-scale,1))').attr('font-weight','500').attr('fill','#ea580c').text(dispName);

      bG.on('mouseenter',function(){
        let h='<div class="tt-title">Storage Account</div>';
        h+='<div class="tt-sub">'+esc(saName)+'</div>';
        h+='<div class="tt-sec">';
        h+='<div class="tt-r"><span class="i">Kind</span> '+(sa.kind||'N/A')+'</div>';
        h+='<div class="tt-r"><span class="i">SKU</span> '+(sa.sku?.name||'N/A')+'</div>';
        h+='</div>';
        tt.innerHTML=h;tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('Storage')});
    });
    sectionBottomY=saY+saBoxH;
  }

  // Front Door section
  if(frontDoors.length>0){
    const fdY=sectionBottomY+40;
    const fdBoxW=Math.max(320,allVnetRight-60);
    const fdCols=2;
    const fdColW=Math.min(480,(fdBoxW-40)/fdCols);
    const fdRowH=28;
    const fdRows=Math.ceil(frontDoors.length/fdCols);
    const fdBoxH=50+fdRows*(fdRowH+4)+20;

    const fdG=ndL.append('g').attr('class','frontdoor-section');
    fdG.append('rect').attr('x',60).attr('y',fdY).attr('width',fdBoxW).attr('height',fdBoxH).attr('rx',8)
      .attr('fill','rgba(139,92,246,.06)').attr('stroke','#8b5cf6').attr('stroke-width',1.5).attr('stroke-dasharray','6 3');
    fdG.append('text').attr('x',80).attr('y',fdY+22).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(14px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','#8b5cf6').text('Azure Front Door');
    fdG.append('text').attr('x',80).attr('y',fdY+36).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(frontDoors.length+' profiles');

    frontDoors.forEach((d,di)=>{
      const col=di%fdCols;
      const row=Math.floor(di/fdCols);
      const cx2=70+col*(fdColW+5);
      const cy2=fdY+48+row*(fdRowH+4);
      const hostNames=(d.properties?.frontendEndpoints||[]).map(fe=>fe.properties?.hostName).filter(Boolean);

      const cG=fdG.append('g').style('cursor','pointer');
      cG.append('rect').attr('x',cx2).attr('y',cy2).attr('width',fdColW-10).attr('height',fdRowH).attr('rx',3)
        .attr('fill','rgba(139,92,246,.12)').attr('stroke','#8b5cf6').attr('stroke-width',0.8);
      cG.append('text').attr('x',cx2+6).attr('y',cy2+12).attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(9px * var(--txt-scale,1))').attr('font-weight','600').attr('fill','#8b5cf6').text(d.name||sid(d.id));
      if(hostNames.length){
        cG.append('text').attr('x',cx2+6).attr('y',cy2+23).attr('font-family','Segoe UI,system-ui,sans-serif')
          .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(hostNames.join(', '));
      }

      cG.on('mouseenter',function(){
        let h='<div class="tt-title">Azure Front Door</div>';
        h+='<div class="tt-sub">'+esc(d.name||sid(d.id))+'</div>';
        h+='<div class="tt-sec">';
        h+='<div class="tt-r"><span class="i">State</span> '+esc(d.properties?.resourceState||d.properties?.provisioningState||'?')+'</div>';
        if(hostNames.length)h+='<div class="tt-r"><span class="i">Hosts</span> '+esc(hostNames.join(', '))+'</div>';
        const backends=(d.properties?.backendPools||[]);
        if(backends.length){
          h+='<div class="tt-sh" style="margin-top:4px">Backend Pools</div>';
          backends.forEach(bp=>{
            const bends=(bp.properties?.backends||[]);
            bends.forEach(b=>{h+='<div class="tt-r"><span class="i">'+esc(b.address||'')+'</span></div>'});
          });
        }
        h+='</div>';
        tt.innerHTML=h;tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('FrontDoor')});
    });
  }

  // Post-render label collision safety sweep
  // Catches any remaining overlaps within same-type label groups
  try{
    const labelGroups = {
      'vnet-label': [], 'vnet-cidr': [],
      'subnet-label': [], 'subnet-cidr': [],
      'gw-name': [], 'gw-id': []
    };
    Object.keys(labelGroups).forEach(cls=>{
      ndL.selectAll('.'+cls).each(function(){
        const el=d3.select(this);
        const node=el.node();
        try{
          const bb=node.getBBox();
          if(bb.width>0&&bb.height>0){
            labelGroups[cls].push({x:bb.x,y:bb.y,w:bb.width,h:bb.height,textNode:el});
          }
        }catch(e){}
      });
    });
    Object.values(labelGroups).forEach(group=>{
      if(group.length>1){
        group.sort((a,b)=>a.y-b.y||a.x-b.x);
        _resolveCollisions(group,{strategy:'shift-y',padding:2,maxIter:4});
        group.forEach(l=>l.textNode.attr('y',l.y+l.h));
      }
    });
  }catch(sweepErr){console.warn('Label collision sweep:',sweepErr)}

  // stats bar
  _rlCtx={vnets,subnets,pubSubs,udrs,nsgs,nics,firewalls,bastions,natGateways,privateEndpoints,vms,appGateways,loadBalancers,peerings,vpnConnections,managedDisks,diskSnapshots,storageAccounts,dnsZones,wafPolicies,wafByAgw,fdByAgw,sqlServers,containerInstances,functionApps,redisCaches,synapseWorkspaces,frontDoors,aksClusters,vmBySub,agwBySub,lbBySub,nicBySub,sqlBySub,containerBySub,fnBySub,aksBySub,subUDR,subNsg,nsgByVnet,diskByVm,snapByDisk,redisByVnet,synapseByVnet,vwans,recsByZone:recsByZoneMap,_multiSubscription,_subscriptions,_regions,_multiRegion,iamRoleResources};
  const sb2=document.getElementById('statsBar');sb2.innerHTML='';sb2.style.display='flex';
  [{l:'VNets',v:vnets.length},{l:'Subnets',v:subnets.length},{l:'Public',v:pubSubs.size},{l:'Private',v:subnets.length-pubSubs.size},{l:'Gateways',v:gwSet.size},{l:'UDRs',v:udrs.length},{l:'NSGs',v:nsgs.length},{l:'VMs',v:vms.length},{l:'NICs',v:nics.length},{l:'AppGW',v:appGateways.length},{l:'LBs',v:loadBalancers.length},{l:'SQL',v:sqlServers.length},{l:'Containers',v:containerInstances.length},{l:'Functions',v:functionApps.length},{l:'AKS',v:aksClusters.length},{l:'Redis',v:redisCaches.length},{l:'Synapse',v:synapseWorkspaces.length},{l:'Peering',v:peerings.length},{l:'VPN',v:vpnConnections.length},{l:'PE',v:privateEndpoints.length},{l:'Disks',v:managedDisks.length},{l:'Snapshots',v:diskSnapshots.length},{l:'Storage',v:storageAccounts.length},{l:'DNS',v:dnsZones.length},{l:'WAF',v:wafPolicies.length},{l:'FrontDoor',v:frontDoors.length},{l:'Firewall',v:firewalls.length},{l:'Bastion',v:bastions.length}].forEach(s=>{
    if(s.v>0){const c=document.createElement('div');c.className='stat-chip';c.dataset.type=s.l;c.innerHTML=`<b>${s.v}</b>${s.l}`;c.addEventListener('click',()=>openResourceList(s.l));sb2.appendChild(c)}
  });
  // Compliance chip (grid layout)
  try{const findings=runComplianceChecks(_rlCtx);if(findings.length)addComplianceChip(sb2,findings);_addBUDRChip(sb2)}catch(ce){console.warn('Compliance check error:',ce)}
  if(_iamData){const _ic=(_iamData.roles?.length||0)+(_iamData.users?.length||0);if(_ic>0){const ic=document.createElement('div');ic.className='stat-chip';ic.classList.add('accent-amber');ic.innerHTML='<b>'+_ic+'</b> RBAC';ic.addEventListener('click',()=>openResourceList('RBAC'));sb2.appendChild(ic)}}
  _depGraph=null;
  try{_renderNoteBadges()}catch(ne){}
  try{_renderComplianceBadges()}catch(cbe){console.warn('Compliance badge error:',cbe)}
  try{if(Date.now()-_lastAutoSnap>120000){takeSnapshot('Render',true);_lastAutoSnap=Date.now()}}catch(se){}
  // Design validation chip (when in design mode)
  if(_designMode&&_lastDesignValidation){
    const sv=_lastDesignValidation;
    const dvC=document.createElement('div');
    dvC.className='compliance-chip '+(sv.errors.length?'critical':sv.warnings.length?'warn':'clean');
    dvC.innerHTML='<b>'+(sv.errors.length+sv.warnings.length)+'</b> Design';
    dvC.title=sv.errors.concat(sv.warnings).join('\n');
    dvC.addEventListener('click',()=>{
      const cl=document.getElementById('changeLog');
      cl.style.display=cl.style.display==='block'?'none':'block';
    });
    sb2.appendChild(dvC);
  }
  // Multi-subscription chip
  if(_multiSubscription){
    const acC=document.createElement('div');
    acC.className='stat-chip';
    acC.classList.add('accent-purple');
    acC.innerHTML='<b>'+_subscriptions.size+'</b> Subscriptions';
    sb2.appendChild(acC);
  }
  if(_multiRegion){
    const rgC=document.createElement('div');
    rgC.className='stat-chip';
    rgC.classList.add('accent-blue');
    rgC.innerHTML='<b>'+_regions.size+'</b> Regions';
    sb2.appendChild(rgC);
  }
  // Diff overlay (grid layout)
  try{if(_diffMode)setTimeout(_applyDiffOverlay,150)}catch(de){}
  document.getElementById('legend').style.display='flex';
  if(_isMobile())document.getElementById('legend').classList.add('collapsed');
  document.getElementById('exportBar').style.display='flex';
  document.getElementById('bottomToolbar').style.display='flex';
  setTimeout(()=>d3.select('#zoomFit').dispatch('click'),100);
  }catch(e){console.error('renderMap error:',e);alert('Render error: '+e.message);document.getElementById('loadingOverlay').style.display='none'}
}

document.getElementById('renderBtn').addEventListener('click',function(){
  renderMap(()=>{_autoSaveSession()});
});

