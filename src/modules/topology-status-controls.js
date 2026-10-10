// #region TOPOLOGY STATUS CONTROLS
function renderTopologyStatusControls(ctx){
  const {
    mode,
    vpcs,subnets,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,
    wafAcls,rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions,
    pubSubs,subRT,gwSet,subNacl,nsgByVnet,iamRoleResources,
    instBySub,eniByInst,eniBySub,albBySub,volByInst,snapByVol,tgByAlb,wafByAlb,rdsBySub,ecsBySub,lambdaBySub,
    ecacheByVpc,redshiftByVpc,cfByAlb,storageBySub,storageTopology,recsByZoneMap,
    _multiTenant,_accounts,_regions,_multiRegion,
    showDesignValidation=false
  } = ctx;

  const runtimeContext={
    rbac:ctx.rbac||null,
    vnets:vpcs,subnets,pubSubs,udrs:rts,nsgs:sgs,subnetNsgs:nacls,nics:enis,eniByInst,
    firewalls:igws,natGateways:nats,privateEndpoints:vpces,vms:instances,appGateways:albs,tgs,
    peerings,vpns,volumes,snapshots,s3bk,zones,wafAcls,wafByAlb,tgByAlb,cfByAlb:cfByAlb||{},
    sqlServers:rdsInstances,containerInstances:ecsServices,functionApps:lambdaFns,redisCaches:ecacheClusters,
    synapseWorkspaces:redshiftClusters,cfDistributions,instBySub,albBySub,eniBySub,rdsBySub,ecsBySub,lambdaBySub,
    storageBySub,storageTopology,subRT,subNacl,nsgByVnet,volByInst,snapByVol,ecacheByVpc,redshiftByVpc,
    vhubs:tgwAttachments,recsByZone:recsByZoneMap,iamRoleResources,_multiTenant,_accounts
  };
  if(_regions) runtimeContext._regions=_regions;
  if(_multiRegion!==undefined) runtimeContext._multiRegion=_multiRegion;
  const topologyCtx=topologyPublishRuntimeContext(runtimeContext);

  const sb2=document.getElementById('statsBar');
  sb2.textContent='';
  sb2.style.display='flex';
  [
    {l:'VNets',v:vpcs.length},{l:'Subnets',v:subnets.length},{l:'Public',v:pubSubs.size},
    {l:'Private',v:subnets.length-pubSubs.size},{l:'Gateways',v:gwSet.size},{l:'UDRs',v:rts.length},
    {l:'SubNSGs',v:nacls.length},{l:'NSGs',v:sgs.length},{l:'VMs',v:instances.length},
    {l:'NICs',v:enis.length},{l:'AppGWs',v:albs.length},{l:'LBs',v:tgs.length},
    {l:'SQL',v:rdsInstances.length},{l:'Containers',v:ecsServices.length},{l:'FuncApps',v:lambdaFns.length},
    {l:'Redis',v:ecacheClusters.length},{l:'Synapse',v:redshiftClusters.length},{l:'Peering',v:peerings.length},
    {l:'VPNs',v:vpns.length},{l:'PvtEndpts',v:vpces.length},{l:'Disks',v:volumes.length},
    {l:'Snapshots',v:snapshots.length},{l:'Storage',v:s3bk.length},{l:'DNS',v:zones.length},
    {l:'WAF',v:wafAcls.length},{l:'FrontDoor',v:cfDistributions.length}
  ].forEach(stat=>{
    if(stat.v>0){
      const chip=document.createElement('div');
      chip.className='stat-chip';
      chip.dataset.type=stat.l;
      chip.innerHTML=`<b>${stat.v}</b>${stat.l}`;
      chip.addEventListener('click',()=>openResourceList(stat.l));
      sb2.appendChild(chip);
    }
  });

  try{
    const findings=topologyComplianceFindings(topologyCtx);
    if(findings.length)addComplianceChip(sb2,findings);
    _addBUDRChip(sb2);
  }catch(ce){console.warn('Compliance check error:',ce)}

  if(_iamData){
    const iamCount=(_iamData.roles?.length||0)+(_iamData.users?.length||0);
    if(iamCount>0){
      const iamChip=document.createElement('div');
      iamChip.className='stat-chip';
      iamChip.classList.add('accent-amber');
      iamChip.innerHTML='<b>'+iamCount+'</b> IAM';
      iamChip.addEventListener('click',()=>openResourceList('IAM'));
      sb2.appendChild(iamChip);
    }
  }

  _depGraph=null;
  try{_renderNoteBadges()}catch(ne){console.warn('Note badges failed:',ne)}
  try{_renderComplianceBadges()}catch(cbe){console.warn('Compliance badge error:',cbe)}
  try{if(Date.now()-_lastAutoSnap>120000){takeSnapshot('Render',true);_lastAutoSnap=Date.now()}}catch(se){console.warn('Auto-snapshot failed:',se)}

  if(showDesignValidation&&_designMode&&_lastDesignValidation){
    const sv=_lastDesignValidation;
    const designChip=document.createElement('div');
    designChip.className='compliance-chip '+(sv.errors.length?'critical':sv.warnings.length?'warn':'clean');
    designChip.innerHTML='<b>'+(sv.errors.length+sv.warnings.length)+'</b> Design';
    designChip.title=sv.errors.concat(sv.warnings).join('\n');
    designChip.addEventListener('click',()=>{
      const changeLog=document.getElementById('changeLog');
      changeLog.style.display=changeLog.style.display==='block'?'none':'block';
    });
    sb2.appendChild(designChip);
  }

  if(_multiTenant){
    const accountChip=document.createElement('div');
    accountChip.className='stat-chip';
    accountChip.classList.add('accent-purple');
    accountChip.innerHTML='<b>'+_accounts.size+'</b> Accounts';
    sb2.appendChild(accountChip);
  }
  if(_multiRegion){
    const regionChip=document.createElement('div');
    regionChip.className='stat-chip';
    regionChip.classList.add('accent-blue');
    regionChip.innerHTML='<b>'+_regions.size+'</b> Regions';
    sb2.appendChild(regionChip);
  }

  try{if(_diffMode)setTimeout(_applyDiffOverlay,150)}catch(de){console.warn('Diff overlay failed:',de)}
  document.getElementById('legend').style.display='flex';
  if(_isMobile())document.getElementById('legend').classList.add('collapsed');
  document.getElementById('exportBar').style.display='flex';
  document.getElementById('bottomToolbar').style.display='flex';
  setTimeout(()=>d3.select('#zoomFit').dispatch('click'),100);
}
// #endregion TOPOLOGY STATUS CONTROLS
