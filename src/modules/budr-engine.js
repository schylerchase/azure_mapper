// Backup, Uptime & Disaster Recovery (BUDR) assessment engine
// Evaluates backup coverage, HA configuration, and DR readiness for Azure resources
// Extracted from index.html for modularization

// --- Transitional window references ---
// _classificationData and runClassificationEngine live in the governance region
// of index.html and have not been extracted to a module yet. During this
// transition period we access them via window globals. Once the governance
// module is extracted, replace these with proper imports.
function _getClassificationData() { return window._classificationData || []; }
function _runClassificationEngine(ctx) { if (typeof window.runClassificationEngine === 'function') window.runClassificationEngine(ctx); }

// === BUDR: BACKUP, UPTIME, DISASTER RECOVERY ===
const _BUDR_STRATEGY={hot:'Hot',warm:'Warm',pilot:'Pilot Light',cold:'Cold'};
const _BUDR_STRATEGY_ORDER={hot:0,warm:1,pilot:2,cold:3};
const _BUDR_STRATEGY_LEGEND=[
  {k:'critical',label:'Critical (Hot)',color:'#ef4444',icon:'🔴',desc:'Active-active — full replica running at all times. Near-zero RTO & RPO.'},
  {k:'high',label:'High (Warm)',color:'#f59e0b',icon:'🟡',desc:'Scaled-down replica running. Scale up on failover. Minutes to recover.'},
  {k:'medium',label:'Medium (Pilot Light)',color:'#6366f1',icon:'🟣',desc:'Data replicated continuously, compute stopped. Spin up on failover. ~10-30 min.'},
  {k:'low',label:'Low (Cold)',color:'#64748b',icon:'⚪',desc:'Backups only, no standby. Rebuild from scratch. Hours to recover.'}
];
const _BUDR_RTO_RPO={
  sql_zone_redundant:{rto:'~5 min',rpo:'~1 min',tier:'protected',strategy:'warm'},
  sql_single_backup:{rto:'~30 min',rpo:'~24 hr',tier:'partial',strategy:'pilot'},
  sql_no_backup:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  vm_vmss:{rto:'~3 min',rpo:'0 (stateless)',tier:'protected',strategy:'warm'},
  vm_disk_snap:{rto:'~15 min',rpo:'~7 days',tier:'partial',strategy:'pilot'},
  vm_standalone:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  container_multi:{rto:'~1 min',rpo:'0 (stateless)',tier:'protected',strategy:'hot'},
  container_single:{rto:'~5 min',rpo:'0 (stateless)',tier:'partial',strategy:'warm'},
  function_app:{rto:'0 (managed)',rpo:'0 (stateless)',tier:'protected',strategy:'hot'},
  redis_zone_redundant:{rto:'~2 min',rpo:'~seconds',tier:'protected',strategy:'warm'},
  redis_single:{rto:'~15 min',rpo:'~7 days',tier:'partial',strategy:'pilot'},
  redis_no_snap:{rto:'~15 min',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  synapse_snap:{rto:'~30 min',rpo:'~8 hr',tier:'partial',strategy:'pilot'},
  synapse_multi:{rto:'~15 min',rpo:'~5 min',tier:'protected',strategy:'warm'},
  synapse_none:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  agw_zone_redundant:{rto:'0 (managed)',rpo:'N/A',tier:'protected',strategy:'hot'},
  agw_single_zone:{rto:'~5 min',rpo:'N/A',tier:'partial',strategy:'warm'},
  storage_grs:{rto:'0 (managed)',rpo:'0 (geo-replicated)',tier:'protected',strategy:'hot'},
  storage_ra_grs:{rto:'0 (managed)',rpo:'0 (read-access geo)',tier:'protected',strategy:'hot'},
  storage_lrs:{rto:'0 (managed)',rpo:'total loss on region failure',tier:'at_risk',strategy:'cold'},
  disk_snapshot:{rto:'~15 min',rpo:'~7 days',tier:'partial',strategy:'pilot'},
  disk_no_snap:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'}
};
// Estimated minutes for each BUDR profile (for tier compliance comparison)
// rtoWhy/rpoWhy: justification for estimated values
const _BUDR_EST_MINUTES={
  sql_zone_redundant:{rto:5,rpo:1,rtoWhy:'Zone-redundant failover completes in 1-2 min; DNS propagation adds ~3 min',rpoWhy:'Synchronous replication across zones — data loss limited to in-flight transactions (~seconds)'},
  sql_single_backup:{rto:30,rpo:1440,rtoWhy:'Restore from automated backup requires server provisioning + data load (~20-30 min)',rpoWhy:'Automated backups run daily — worst case RPO is 24 hours since last backup window'},
  sql_no_backup:{rto:480,rpo:Infinity,rtoWhy:'No backups — requires manual rebuild from application layer or external source',rpoWhy:'No backup mechanism configured — all data since creation is unrecoverable'},
  vm_vmss:{rto:3,rpo:0,rtoWhy:'VMSS health probe detects failure (1-2 min) and launches replacement from image (~1-2 min)',rpoWhy:'Stateless compute — no persistent data on instance; state lives in external stores'},
  vm_disk_snap:{rto:15,rpo:10080,rtoWhy:'New VM creation + managed disk restore from snapshot (~10-15 min depending on disk size)',rpoWhy:'Snapshot frequency is typically weekly — worst case RPO is 7 days since last snapshot'},
  vm_standalone:{rto:480,rpo:Infinity,rtoWhy:'No snapshot — requires full OS install, config, and application deployment from scratch',rpoWhy:'No backup mechanism — managed disk data is unrecoverable if VM or disk is lost'},
  container_multi:{rto:1,rpo:0,rtoWhy:'Container group scheduler replaces failed containers in ~30-60 sec from registry image',rpoWhy:'Stateless containers — no persistent data; state lives in external stores (SQL, Storage, etc.)'},
  container_single:{rto:5,rpo:0,rtoWhy:'Single container replacement takes ~2-5 min including image pull and health check',rpoWhy:'Stateless containers — no persistent data; state lives in external stores'},
  function_app:{rto:0,rpo:0,rtoWhy:'Fully managed — Azure handles all availability; cold start adds <1 sec latency',rpoWhy:'Stateless execution — no persistent data; code stored in Storage Account'},
  redis_zone_redundant:{rto:2,rpo:0.1,rtoWhy:'Zone-redundant replica promotion takes 1-2 min; DNS endpoint updates automatically',rpoWhy:'Async replication lag is typically <100ms — data loss limited to replication lag'},
  redis_single:{rto:15,rpo:10080,rtoWhy:'Restore from RDB snapshot requires new cache provisioning + data load (~10-15 min)',rpoWhy:'Snapshot frequency is typically daily/weekly — worst case RPO equals snapshot interval'},
  redis_no_snap:{rto:15,rpo:Infinity,rtoWhy:'New cache provisioning takes ~10-15 min but cache starts cold (empty)',rpoWhy:'No snapshots — entire cache contents are lost; must be rebuilt from source of truth'},
  synapse_snap:{rto:30,rpo:1440,rtoWhy:'Restore from snapshot creates new workspace (~20-30 min depending on data size)',rpoWhy:'Automated snapshots run periodically by default — worst case RPO is snapshot interval'},
  synapse_multi:{rto:15,rpo:5,rtoWhy:'Zone-redundant workspace redistributes work to surviving zones (~10-15 min recovery)',rpoWhy:'Synchronous replication across zones — RPO limited to in-flight queries (~minutes)'},
  synapse_none:{rto:480,rpo:Infinity,rtoWhy:'No snapshots — requires full data reload from Storage Account/source systems (hours to days)',rpoWhy:'No backup mechanism — all warehouse data is unrecoverable'},
  agw_zone_redundant:{rto:0,rpo:0,rtoWhy:'Fully managed zone-redundant — Azure handles node replacement transparently',rpoWhy:'Stateless gateway — no data to lose; config stored in Azure control plane'},
  agw_single_zone:{rto:5,rpo:0,rtoWhy:'Single-zone App Gateway may need DNS failover if zone goes down (~3-5 min)',rpoWhy:'Stateless gateway — no data to lose'},
  storage_grs:{rto:0,rpo:0,rtoWhy:'Geo-redundant storage replicates across paired regions — always available',rpoWhy:'Objects replicated synchronously within region and asynchronously to paired region'},
  storage_ra_grs:{rto:0,rpo:0,rtoWhy:'Read-access geo-redundant storage provides secondary read endpoint',rpoWhy:'Full GRS replication with additional read availability in secondary region'},
  storage_lrs:{rto:0,rpo:Infinity,rtoWhy:'Locally redundant storage is always available within a region but not across regions',rpoWhy:'No geo-replication — data loss possible if entire region is lost'},
  disk_snapshot:{rto:15,rpo:10080,rtoWhy:'Create new managed disk from snapshot + attach to VM (~10-15 min)',rpoWhy:'Snapshot frequency is typically weekly — worst case RPO is 7 days since last snapshot'},
  disk_no_snap:{rto:480,rpo:Infinity,rtoWhy:'No snapshots — disk data is unrecoverable if disk fails',rpoWhy:'No backup mechanism — all disk data is permanently lost on failure'}
};
// Classification tier targets in minutes (from compliance policy)
const _TIER_TARGETS={
  critical:{rto:240,rpo:60,rtoLabel:'2-4 hours',rpoLabel:'Hourly'},
  high:{rto:480,rpo:360,rtoLabel:'4-8 hours',rpoLabel:'6 hours'},
  medium:{rto:720,rpo:1440,rtoLabel:'12 hours',rpoLabel:'Daily'},
  low:{rto:1440,rpo:10080,rtoLabel:'24 hours',rpoLabel:'Weekly'}
};
// Compare estimated restore capability vs tier target — returns compliance status
function _budrTierCompliance(profileKey,classTier){
  if(!profileKey||!classTier)return{status:'unknown',issues:[]};
  var est=_BUDR_EST_MINUTES[profileKey];var target=_TIER_TARGETS[classTier];
  if(!est||!target)return{status:'unknown',issues:[]};
  var issues=[];
  if(est.rpo===Infinity)issues.push({field:'RPO',severity:'critical',msg:'No backup — RPO unrecoverable (target: '+target.rpoLabel+')'});
  else if(est.rpo>target.rpo)issues.push({field:'RPO',severity:'warning',msg:'Est. RPO ~'+_fmtMin(est.rpo)+' exceeds '+classTier+' target of '+target.rpoLabel});
  if(est.rto>target.rto)issues.push({field:'RTO',severity:'warning',msg:'Est. RTO ~'+_fmtMin(est.rto)+' exceeds '+classTier+' target of '+target.rtoLabel});
  var status=issues.some(function(i){return i.severity==='critical'})?'fail':issues.length?'warn':'pass';
  return{status:status,issues:issues,estRto:est.rto,estRpo:est.rpo,targetRto:target.rto,targetRpo:target.rpo,rtoWhy:est.rtoWhy||'',rpoWhy:est.rpoWhy||''};
}
function _fmtMin(m){if(m===0)return '0';if(m===Infinity)return '∞';if(m<60)return Math.round(m)+' min';if(m<1440)return Math.round(m/60*10)/10+' hr';return Math.round(m/1440*10)/10+' days'}

// --- Module state ---
// Exported as both underscore (backward compat with inline code) and clean names.
// Use setter functions to reassign from outside the module.
let budrFindings=[];
let budrAssessments=[];
let budrOverrides={};
function setBudrFindings(v) { budrFindings = v; }
function setBudrAssessments(v) { budrAssessments = v; }
function setBudrOverrides(v) { budrOverrides = v; }

function runBUDRChecks(ctx){
  const f=[];const assessments=[];
  // Azure resources use .name directly — no Tags[Name] lookup needed
  const gn=(o)=>o.name||o.id||'unknown';
  // SQL Servers (Azure SQL)
  (ctx.sqlServers||[]).forEach(sql=>{
    const id=sql.id;const name=gn(sql);
    const hasZoneRedundant=!!(sql.properties&&sql.properties.zoneRedundant);
    const backupDays=(sql.properties&&sql.properties.backupRetentionDays)||0;
    const hasBackup=backupDays>0;
    const geoRedundant=(sql.properties&&sql.properties.geoRedundantBackup)==='Enabled';
    const encrypted=!!(sql.properties&&sql.properties.storageEncrypted);
    let profile;
    if(hasZoneRedundant&&hasBackup){profile=_BUDR_RTO_RPO.sql_zone_redundant}
    else if(hasBackup){profile=_BUDR_RTO_RPO.sql_single_backup;
      f.push({severity:'MEDIUM',control:'BUDR-HA-1',framework:'BUDR',resource:id,resourceName:name,message:'SQL Server not zone-redundant — single point of failure',remediation:'Enable zone-redundant deployment for automatic failover'})}
    else{profile=_BUDR_RTO_RPO.sql_no_backup;
      f.push({severity:'CRITICAL',control:'BUDR-BAK-1',framework:'BUDR',resource:id,resourceName:name,message:'SQL Server has no automated backups (retention=0)',remediation:'Set backupRetentionDays to at least 7'})}
    if(!hasZoneRedundant&&hasBackup)
      f.push({severity:'HIGH',control:'BUDR-DR-1',framework:'BUDR',resource:id,resourceName:name,message:'SQL Server single-zone with backups only — extended RTO on zone failure',remediation:'Enable zone-redundant deployment or configure geo-replication'});
    assessments.push({type:'SQL Server',id,name,profile,signals:{ZoneRedundant:hasZoneRedundant,Backup:hasBackup,BackupDays:backupDays,Encrypted:encrypted,GeoRedundant:geoRedundant}});
  });
  // VMs (Azure Virtual Machines)
  const vmssInstIds=new Set();
  // Detect VMSS membership from tags
  (ctx.vms||[]).forEach(vm=>{
    const tags=vm.tags||{};
    const vmssTag=tags['vmss-name']||tags['scale-set-name']||tags['aks-managed-clustername'];
    if(vmssTag)vmssInstIds.add(vm.id);
  });
  (ctx.vms||[]).forEach(vm=>{
    const id=vm.id;const name=gn(vm);
    const inVMSS=vmssInstIds.has(id);
    // Check for managed disk snapshots
    const attachedDisks=((vm.properties&&vm.properties.storageProfile&&vm.properties.storageProfile.dataDisks)||[])
      .map(d=>d.managedDisk&&d.managedDisk.id).filter(Boolean);
    const osDiskId=vm.properties&&vm.properties.storageProfile&&vm.properties.storageProfile.osDisk&&vm.properties.storageProfile.osDisk.managedDisk&&vm.properties.storageProfile.osDisk.managedDisk.id;
    if(osDiskId)attachedDisks.push(osDiskId);
    const hasSnaps=attachedDisks.some(did=>{const s=(ctx.snapByDisk||{})[did];return s&&s.length>0});
    let newestSnap=null;
    attachedDisks.forEach(did=>{const ss=(ctx.snapByDisk||{})[did]||[];ss.forEach(s=>{
      const d=new Date(s.properties&&s.properties.timeCreated||0);if(!newestSnap||d>newestSnap)newestSnap=d;
    })});
    const snapAgeDays=newestSnap?Math.floor((Date.now()-newestSnap.getTime())/(864e5)):null;
    if(hasSnaps&&snapAgeDays!==null&&snapAgeDays>7){
      f.push({severity:'MEDIUM',control:'BUDR-AGE-1',framework:'BUDR',resource:id,resourceName:name,message:'Newest disk snapshot is '+snapAgeDays+' days old (>7 days)',remediation:'Configure Azure Backup to take disk snapshots at least weekly'});
    }
    const encrypted=attachedDisks.some(did=>{const vs=(ctx.disks||[]).filter(d=>d.id===did);return vs.length&&vs[0].properties&&vs[0].properties.encryption&&vs[0].properties.encryption.type});
    let profile;
    if(inVMSS){profile=_BUDR_RTO_RPO.vm_vmss}
    else if(hasSnaps){profile=_BUDR_RTO_RPO.vm_disk_snap;
      f.push({severity:'LOW',control:'BUDR-HA-2',framework:'BUDR',resource:id,resourceName:name,message:'VM not in a VM Scale Set — manual recovery required',remediation:'Deploy behind VMSS or configure Azure Backup for quick recovery'})}
    else{profile=_BUDR_RTO_RPO.vm_standalone;
      f.push({severity:'HIGH',control:'BUDR-BAK-2',framework:'BUDR',resource:id,resourceName:name,message:'VM standalone with no disk snapshots — unrecoverable on failure',remediation:'Create regular disk snapshots via Azure Backup; consider VMSS'});
      if(!inVMSS)f.push({severity:'MEDIUM',control:'BUDR-DR-2',framework:'BUDR',resource:id,resourceName:name,message:'VM has no disaster recovery strategy',remediation:'Configure Azure Backup, use VMSS with multiple zones, or take disk snapshots'})}
    assessments.push({type:'VM',id,name,profile,signals:{VMSS:inVMSS,Snapshots:hasSnaps,SnapAgeDays:snapAgeDays,Encrypted:encrypted}});
  });
  // Container Instances
  (ctx.containerInstances||[]).forEach(ci=>{
    const id=ci.id;const name=gn(ci);
    const replicas=(ci.properties&&ci.properties.containers||[]).length;
    const multi=replicas>1;
    let profile;
    if(multi){profile=_BUDR_RTO_RPO.container_multi}
    else{profile=_BUDR_RTO_RPO.container_single;
      f.push({severity:'LOW',control:'BUDR-HA-3',framework:'BUDR',resource:id,resourceName:name,message:'Container instance has only '+replicas+' container(s) — no redundancy',remediation:'Deploy multiple container instances across availability zones'})}
    assessments.push({type:'Container Instance',id,name,profile,signals:{Containers:replicas,MultiContainer:multi}});
  });
  // Function Apps (inherently resilient)
  (ctx.functionApps||[]).forEach(fn=>{
    assessments.push({type:'Function App',id:fn.id,name:gn(fn),profile:_BUDR_RTO_RPO.function_app,signals:{Managed:true}});
  });
  // Redis Caches
  (ctx.redisCaches||[]).forEach(rc=>{
    const id=rc.id;const name=gn(rc);
    const replicas=(rc.properties&&rc.properties.replicasPerMaster)||0;
    const hasSnap=!!(rc.properties&&(rc.properties.rdbBackupEnabled||rc.properties.aofBackupEnabled));
    const zoneRedundant=!!(rc.properties&&rc.properties.replicasPerPrimary>0);
    let profile;
    if(zoneRedundant||replicas>0){profile=_BUDR_RTO_RPO.redis_zone_redundant}
    else if(hasSnap){profile=_BUDR_RTO_RPO.redis_single;
      f.push({severity:'MEDIUM',control:'BUDR-HA-4',framework:'BUDR',resource:id,resourceName:name,message:'Redis Cache single node — failover requires manual intervention',remediation:'Add replicas or enable zone-redundant configuration for automatic failover'})}
    else{profile=_BUDR_RTO_RPO.redis_no_snap;
      f.push({severity:'HIGH',control:'BUDR-BAK-3',framework:'BUDR',resource:id,resourceName:name,message:'Redis Cache single node with no persistence — data loss risk',remediation:'Enable RDB/AOF persistence and add read replicas'})}
    assessments.push({type:'Redis Cache',id,name,profile,signals:{Replicas:replicas,Snapshots:hasSnap,ZoneRedundant:zoneRedundant}});
  });
  // Synapse Workspaces
  (ctx.synapseWorkspaces||[]).forEach(sw=>{
    const id=sw.id;const name=gn(sw);
    const hasSnap=!!(sw.properties&&sw.properties.managedResourceGroupName);
    const multiZone=!!(sw.properties&&sw.properties.encryption);
    let profile;
    if(multiZone&&hasSnap){profile=_BUDR_RTO_RPO.synapse_multi}
    else if(hasSnap){profile=_BUDR_RTO_RPO.synapse_snap;
      f.push({severity:'MEDIUM',control:'BUDR-HA-5',framework:'BUDR',resource:id,resourceName:name,message:'Synapse Workspace without zone-redundant compute — no compute redundancy',remediation:'Enable zone-redundant SQL pools for HA'})}
    else{profile=_BUDR_RTO_RPO.synapse_none;
      f.push({severity:'HIGH',control:'BUDR-BAK-4',framework:'BUDR',resource:id,resourceName:name,message:'Synapse Workspace with no backup configuration — data loss risk',remediation:'Configure automated backups with adequate retention'})}
    assessments.push({type:'Synapse Workspace',id,name,profile,signals:{Snapshots:hasSnap,MultiZone:multiZone}});
  });
  // App Gateways
  (ctx.appGateways||[]).forEach(agw=>{
    const id=agw.id;const name=gn(agw);
    const zones=(agw.zones||[]).length;
    let profile;
    if(zones>=2){profile=_BUDR_RTO_RPO.agw_zone_redundant}
    else{profile=_BUDR_RTO_RPO.agw_single_zone;
      f.push({severity:'MEDIUM',control:'BUDR-HA-6',framework:'BUDR',resource:id,resourceName:name,message:'App Gateway in single zone only — no failover',remediation:'Deploy across 2+ availability zones'})}
    assessments.push({type:'App Gateway',id,name,profile,signals:{ZoneCount:zones}});
  });
  // Managed Disks (standalone — not already counted via VM)
  (ctx.disks||[]).forEach(disk=>{
    if((disk.properties&&disk.properties.diskState)!=='Attached')return;
    const id=disk.id;const name=gn(disk);
    const snaps=(ctx.snapByDisk||{})[id]||[];
    if(snaps.length===0){
      f.push({severity:'MEDIUM',control:'BUDR-BAK-5',framework:'BUDR',resource:id,resourceName:name,message:'Attached managed disk has no snapshots',remediation:'Create snapshot schedule via Azure Backup or disk snapshot policy'});
    }
  });
  // Storage Accounts
  (ctx.storageAccounts||[]).forEach(sa=>{
    const id=sa.id;const name=gn(sa);
    const skuName=(sa.properties&&sa.properties.sku&&sa.properties.sku.name)||
                  (sa.sku&&sa.sku.name)||'LRS';
    const isGRS=skuName.includes('GRS')||skuName.includes('GZRS');
    const isRAGRS=skuName.includes('RA-GRS')||skuName.includes('RA-GZRS');
    let profile;
    if(isRAGRS){profile=_BUDR_RTO_RPO.storage_ra_grs}
    else if(isGRS){profile=_BUDR_RTO_RPO.storage_grs}
    else{profile=_BUDR_RTO_RPO.storage_lrs;
      f.push({severity:'HIGH',control:'BUDR-STG-1',framework:'BUDR',resource:id,resourceName:name,message:'Storage Account uses LRS — no geo-redundancy, data loss risk on region failure',remediation:'Upgrade to GRS or RA-GRS to protect against regional outages'})}
    assessments.push({type:'Storage Account',id,name,profile,signals:{SKU:skuName,GeoRedundant:isGRS,ReadAccess:isRAGRS}});
  });
  // Enrich assessments with account/vnet/region from raw resources
  var _budrLookup={};
  var _bSubVnet={};(ctx.subnets||[]).forEach(function(s){if(s.id)_bSubVnet[s.id]=(s.properties&&s.properties.vnetId)||''});
  (ctx.sqlServers||[]).forEach(function(r){_budrLookup['SQL Server:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:(r.properties&&r.properties.vnetId)||''}});
  (ctx.vms||[]).forEach(function(r){_budrLookup['VM:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:(r.properties&&r.properties.vnetId)||_bSubVnet[(r.properties&&r.properties.subnetId)]||''}});
  (ctx.containerInstances||[]).forEach(function(r){var subId=r.properties&&r.properties.subnetId;_budrLookup['Container Instance:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:subId?_bSubVnet[subId]||'':''}});
  (ctx.functionApps||[]).forEach(function(r){_budrLookup['Function App:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:(r.properties&&r.properties.vnetId)||''}});
  (ctx.redisCaches||[]).forEach(function(r){_budrLookup['Redis Cache:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:(r.properties&&r.properties.vnetId)||''}});
  (ctx.synapseWorkspaces||[]).forEach(function(r){_budrLookup['Synapse Workspace:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:''}});
  (ctx.appGateways||[]).forEach(function(r){_budrLookup['App Gateway:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:(r.properties&&r.properties.vnetId)||''}});
  (ctx.storageAccounts||[]).forEach(function(r){_budrLookup['Storage Account:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:''}});
  (ctx.disks||[]).forEach(function(r){_budrLookup['Managed Disk:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:''}});
  (ctx.snapshots||[]).forEach(function(r){_budrLookup['Snapshot:'+r.id]={a:r._accountId||'',r:r.location||r._region||'',v:''}});
  assessments.forEach(function(a){var info=_budrLookup[a.type+':'+a.id];if(info){a.account=info.a;a.region=info.r;a.vnetId=info.v}});
  // Fallback: unmatched assessments get primary account
  var _bAccts=new Set();(ctx.vnets||[]).forEach(function(v){if(v._accountId&&v._accountId!=='default')_bAccts.add(v._accountId)});
  if(_bAccts.size>=1){var _bPri=[..._bAccts][0];assessments.forEach(function(a){if(!a.account)a.account=_bPri})}
  // Enrich BUDR findings with account/region (for Action Plan sheet)
  var _bResLookup={};
  Object.keys(_budrLookup).forEach(function(k){var id=k.split(':').slice(1).join(':');_bResLookup[id]=_budrLookup[k]});
  f.forEach(function(finding){var info=_bResLookup[finding.resource];if(info){finding._accountId=info.a;finding._region=info.r;finding._vnetId=info.v}});
  if(_bAccts.size>=1){var _bPri2=[..._bAccts][0];f.forEach(function(finding){if(!finding._accountId)finding._accountId=_bPri2})};
  budrFindings=f;
  budrAssessments=assessments;
  // Cross-reference with classification engine for tier compliance
  _enrichBudrWithClassification(ctx,f);
  return f;
}
function _enrichBudrWithClassification(ctx,findings){
  // Run classification if not already done
  // NOTE: _classificationData and runClassificationEngine are from the governance
  // region (not yet extracted). Access via window globals during transition.
  var classData = _getClassificationData();
  if(!classData.length&&ctx) _runClassificationEngine(ctx);
  classData = _getClassificationData();
  // Build lookup by resource id/name (type-qualified keys take priority to avoid cross-type collisions)
  var classMap={};var classMapTyped={};
  classData.forEach(function(c){classMap[c.id]=c;classMap[c.name]=c;classMapTyped[c.type+'|'+c.id]=c;classMapTyped[c.type+'|'+c.name]=c});
  // Enrich each BUDR assessment
  budrAssessments.forEach(function(a){
    var cls=classMapTyped[a.type+'|'+a.id]||classMapTyped[a.type+'|'+a.name]||classMap[a.id]||classMap[a.name];
    a.classTier=cls?cls.tier:'low';
    a.classVnetName=cls?cls.vnetName:'';
    // Find which profile key this assessment uses
    var profileKey=null;
    for(var k in _BUDR_RTO_RPO){if(_BUDR_RTO_RPO[k]===a.profile){profileKey=k;break}}
    a.profileKey=profileKey;
    a.compliance=_budrTierCompliance(profileKey,a.classTier);
    // Generate findings for compliance gaps
    if(a.compliance.issues.length>0){
      a.compliance.issues.forEach(function(issue){
        var sev=issue.severity==='critical'?'CRITICAL':'HIGH';
        findings.push({severity:sev,control:'BUDR-TIER-'+issue.field,framework:'BUDR',resource:a.id,resourceName:a.name,
          message:issue.msg+' ['+a.classTier+' tier]',
          remediation:issue.field==='RPO'?'Configure automated backups to meet '+a.classTier+' RPO target':'Improve HA/DR strategy to meet '+a.classTier+' RTO target'});
      });
    }
    // Apply manual override if present
    var ov=budrOverrides[a.id];
    if(ov){
      a.overridden=true;
      a.autoProfile={strategy:a.profile.strategy,rto:a.profile.rto,rpo:a.profile.rpo,tier:a.profile.tier};
      if(ov.strategy){
        a.profile=Object.assign({},a.profile);
        var sm={critical:'hot',high:'warm',medium:'pilot',low:'cold'};
        var tm={critical:'protected',high:'protected',medium:'partial',low:'at_risk'};
        a.profile.strategy=sm[ov.strategy]||ov.strategy;
        a.profile.tier=tm[ov.strategy]||a.profile.tier;
      }
      if(ov.rto) a.profile.rto=ov.rto;
      if(ov.rpo) a.profile.rpo=ov.rpo;
    }
  });
}
function _reapplyBUDROverrides(){
  budrAssessments.forEach(function(a){
    // Restore auto values first
    if(a.autoProfile){
      a.profile=Object.assign({},a.profile);
      a.profile.strategy=a.autoProfile.strategy;
      a.profile.rto=a.autoProfile.rto;
      a.profile.rpo=a.autoProfile.rpo;
      a.profile.tier=a.autoProfile.tier;
      a.overridden=false;
    }
    var ov=budrOverrides[a.id];
    if(ov){
      a.overridden=true;
      if(!a.autoProfile)a.autoProfile={strategy:a.profile.strategy,rto:a.profile.rto,rpo:a.profile.rpo,tier:a.profile.tier};
      a.profile=Object.assign({},a.profile);
      if(ov.strategy){
        var sm={critical:'hot',high:'warm',medium:'pilot',low:'cold'};
        var tm={critical:'protected',high:'protected',medium:'partial',low:'at_risk'};
        a.profile.strategy=sm[ov.strategy]||ov.strategy;
        a.profile.tier=tm[ov.strategy]||a.profile.tier;
      }
      if(ov.rto)a.profile.rto=ov.rto;
      if(ov.rpo)a.profile.rpo=ov.rpo;
    }
  });
}
function _getBUDRTierCounts(){
  const counts={protected:0,partial:0,at_risk:0};
  budrAssessments.forEach(a=>{
    if(a.profile)counts[a.profile.tier]=(counts[a.profile.tier]||0)+1;
  });
  return counts;
}
function _getBudrComplianceCounts(){
  var counts={pass:0,warn:0,fail:0,unknown:0};
  budrAssessments.forEach(function(a){
    var s=a.compliance?a.compliance.status:'unknown';
    counts[s]=(counts[s]||0)+1;
  });
  return counts;
}

// === Exports ===
// Constants
export {
  _BUDR_STRATEGY,
  _BUDR_STRATEGY_ORDER,
  _BUDR_STRATEGY_LEGEND,
  _BUDR_RTO_RPO,
  _BUDR_EST_MINUTES,
  _TIER_TARGETS
};

// Functions
export {
  runBUDRChecks,
  _budrTierCompliance,
  _fmtMin,
  _enrichBudrWithClassification,
  _reapplyBUDROverrides,
  _getBUDRTierCounts,
  _getBudrComplianceCounts
};

// State — clean names + setters
export {
  budrFindings,
  budrAssessments,
  budrOverrides,
  setBudrFindings,
  setBudrAssessments,
  setBudrOverrides
};

// Backward-compat aliases for inline code that references underscore names.
// ES module `export let` bindings are live, so these getters stay current.
export {
  budrFindings as _budrFindings,
  budrAssessments as _budrAssessments,
  budrOverrides as _budrOverrides
};
