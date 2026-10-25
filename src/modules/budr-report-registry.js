// #region BUDR ENGINE
// === BUDR: BACKUP, UPTIME, DISASTER RECOVERY ===
const _BUDR_STRATEGY={hot:'Hot',warm:'Warm',pilot:'Pilot Light',cold:'Cold'};
const _BUDR_STRATEGY_ORDER={hot:0,warm:1,pilot:2,cold:3};
const _BUDR_STRATEGY_LEGEND=[
  {k:'critical',label:'Critical (Hot)',color:'#ef4444',icon:'',desc:'Active-active: full replica running at all times. Near-zero RTO & RPO.'},
  {k:'high',label:'High (Warm)',color:'#f59e0b',icon:'',desc:'Scaled-down replica running. Scale up on failover. Minutes to recover.'},
  {k:'medium',label:'Medium (Pilot Light)',color:'#6366f1',icon:'',desc:'Data replicated continuously, compute stopped. Spin up on failover. ~10-30 min.'},
  {k:'low',label:'Low (Cold)',color:'#64748b',icon:'',desc:'Backups only, no standby. Rebuild from scratch. Hours to recover.'}
];
const _BUDR_RTO_RPO={
  rds_multi_az:{rto:'~5 min',rpo:'~1 min',tier:'protected',strategy:'warm'},
  rds_single_backup:{rto:'~30 min',rpo:'~24 hr',tier:'partial',strategy:'pilot'},
  rds_no_backup:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  sql_unknown:{rto:'Unknown',rpo:'Unknown',tier:'unknown',strategy:'unknown'},
  rds_aurora:{rto:'<30 sec',rpo:'~5 min (PITR)',tier:'protected',strategy:'hot'},
  ec2_asg:{rto:'~3 min',rpo:'0 (stateless)',tier:'protected',strategy:'warm'},
  ec2_ami_snap:{rto:'~15 min',rpo:'~7 days',tier:'partial',strategy:'pilot'},
  ec2_standalone:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  ecs_multi:{rto:'~1 min',rpo:'0 (stateless)',tier:'protected',strategy:'hot'},
  ecs_single:{rto:'~5 min',rpo:'0 (stateless)',tier:'partial',strategy:'warm'},
  container_unknown:{rto:'Unknown',rpo:'Unknown',tier:'unknown',strategy:'unknown'},
  lambda:{rto:'0 (managed)',rpo:'0 (stateless)',tier:'protected',strategy:'hot'},
  ecache_multi:{rto:'~2 min',rpo:'~seconds',tier:'protected',strategy:'warm'},
  ecache_single:{rto:'~15 min',rpo:'~7 days',tier:'partial',strategy:'pilot'},
  ecache_no_snap:{rto:'~15 min',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  redis_unknown:{rto:'Unknown',rpo:'Unknown',tier:'unknown',strategy:'unknown'},
  redshift_snap:{rto:'~30 min',rpo:'~8 hr',tier:'partial',strategy:'pilot'},
  redshift_multi:{rto:'~15 min',rpo:'~5 min',tier:'protected',strategy:'warm'},
  redshift_none:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  synapse_unknown:{rto:'Unknown',rpo:'Unknown',tier:'unknown',strategy:'unknown'},
  alb_multi_az:{rto:'0 (managed)',rpo:'N/A',tier:'protected',strategy:'hot'},
  alb_single_az:{rto:'~5 min',rpo:'N/A',tier:'partial',strategy:'warm'},
  agw_unknown:{rto:'Unknown',rpo:'Unknown',tier:'unknown',strategy:'unknown'},
  s3:{rto:'0 (managed)',rpo:'0 (durable)',tier:'protected',strategy:'hot'},
  s3_versioned:{rto:'0 (managed)',rpo:'0 (versioned)',tier:'protected',strategy:'hot'},
  s3_unversioned:{rto:'0 (managed)',rpo:'total loss',tier:'at_risk',strategy:'cold'},
  storage_unknown:{rto:'Unknown',rpo:'Unknown',tier:'unknown',strategy:'unknown'},
  s3_mfa_delete:{rto:'0 (managed)',rpo:'0 (immutable)',tier:'protected',strategy:'hot'},
  ebs_snap:{rto:'~15 min',rpo:'~7 days',tier:'partial',strategy:'pilot'},
  ebs_no_snap:{rto:'~8 hr',rpo:'total loss',tier:'at_risk',strategy:'cold'}
};
// Estimated minutes for each BUDR profile (for tier compliance comparison)
// rtoWhy/rpoWhy: justification for estimated values
const _BUDR_EST_MINUTES={
  rds_multi_az:{rto:5,rpo:1,rtoWhy:'Multi-AZ automatic failover completes in 1-2 min; DNS propagation adds ~3 min',rpoWhy:'Synchronous replication to standby: data loss limited to in-flight transactions (~seconds)'},
  rds_single_backup:{rto:30,rpo:1440,rtoWhy:'Restore from automated snapshot requires instance provisioning + data load (~20-30 min)',rpoWhy:'Automated backups run daily: worst case RPO is 24 hours since last backup window'},
  rds_no_backup:{rto:480,rpo:Infinity,rtoWhy:'No backups: requires manual rebuild from application layer or external source',rpoWhy:'No backup mechanism configured: all data since creation is unrecoverable'},
  rds_aurora:{rto:0.5,rpo:5,rtoWhy:'Aurora automatic failover promotes read replica in <30 sec; DNS TTL is 5 sec',rpoWhy:'Aurora replicates 6 copies across 3 AZs: RPO limited to last committed transaction (~seconds)'},
  ec2_asg:{rto:3,rpo:0,rtoWhy:'ASG detects failure via health check (1-2 min) and launches replacement from AMI (~1-2 min)',rpoWhy:'Stateless compute: no persistent data on instance; state lives in external stores'},
  ec2_ami_snap:{rto:15,rpo:10080,rtoWhy:'Manual AMI launch + EBS restore from snapshot (~10-15 min depending on volume size)',rpoWhy:'Snapshot frequency is typically weekly: worst case RPO is 7 days since last snapshot'},
  ec2_standalone:{rto:480,rpo:Infinity,rtoWhy:'No AMI/snapshot: requires full OS install, config, and application deployment from scratch',rpoWhy:'No backup mechanism: local EBS data is unrecoverable if instance or volume is lost'},
  ecs_multi:{rto:1,rpo:0,rtoWhy:'ECS service scheduler replaces failed tasks in ~30-60 sec from container image',rpoWhy:'Stateless containers: no persistent data; state lives in external stores (RDS, S3, etc.)'},
  ecs_single:{rto:5,rpo:0,rtoWhy:'Single task replacement takes ~2-5 min including image pull and health check',rpoWhy:'Stateless containers: no persistent data; state lives in external stores'},
  lambda:{rto:0,rpo:0,rtoWhy:'Fully managed: Azure handles all availability; cold start adds <1 sec latency',rpoWhy:'Stateless execution: no persistent data; code stored in Azure Storage with versioning'},
  ecache_multi:{rto:2,rpo:0.1,rtoWhy:'Multi-AZ auto-failover promotes replica in 1-2 min; DNS endpoint updates automatically',rpoWhy:'Async replication lag is typically <100ms: data loss limited to replication lag'},
  ecache_single:{rto:15,rpo:10080,rtoWhy:'Restore from snapshot requires new cluster provisioning + data load (~10-15 min)',rpoWhy:'Snapshot frequency is typically daily/weekly: worst case RPO equals snapshot interval'},
  ecache_no_snap:{rto:15,rpo:Infinity,rtoWhy:'New cluster provisioning takes ~10-15 min but cache starts cold (empty)',rpoWhy:'No snapshots: entire cache contents are lost; must be rebuilt from source of truth'},
  redshift_snap:{rto:30,rpo:1440,rtoWhy:'Restore from snapshot creates new cluster (~20-30 min depending on data size)',rpoWhy:'Automated snapshots run every 8 hours by default: worst case RPO is snapshot interval'},
  redshift_multi:{rto:15,rpo:5,rtoWhy:'Multi-node cluster redistributes work to surviving nodes (~10-15 min recovery)',rpoWhy:'Synchronous replication across nodes: RPO limited to in-flight queries (~minutes)'},
  redshift_none:{rto:480,rpo:Infinity,rtoWhy:'No snapshots: requires full data reload from S3/source systems (hours to days)',rpoWhy:'No backup mechanism: all warehouse data is unrecoverable'},
  alb_multi_az:{rto:0,rpo:0,rtoWhy:'Fully managed multi-AZ: Azure handles node replacement transparently',rpoWhy:'Stateless load balancer: no data to lose; config stored in Azure control plane'},
  alb_single_az:{rto:5,rpo:0,rtoWhy:'Single-AZ ALB may need DNS failover if AZ goes down (~3-5 min)',rpoWhy:'Stateless load balancer: no data to lose'},
  s3:{rto:0,rpo:0,rtoWhy:'11 nines durability: service is always available across 3+ AZs',rpoWhy:'Objects replicated across multiple AZs automatically'},
  s3_versioned:{rto:0,rpo:0,rtoWhy:'Versioned objects can be restored to any previous version instantly',rpoWhy:'Every object change creates a new version: zero data loss possible'},
  s3_unversioned:{rto:0,rpo:Infinity,rtoWhy:'Bucket is always available, but deleted/overwritten objects cannot be recovered',rpoWhy:'No versioning: overwrites and deletes are permanent and unrecoverable'},
  s3_mfa_delete:{rto:0,rpo:0,rtoWhy:'MFA Delete prevents accidental deletion: objects recoverable from versions',rpoWhy:'Versioning + MFA Delete = immutable storage; data cannot be accidentally lost'},
  ebs_snap:{rto:15,rpo:10080,rtoWhy:'Create new volume from snapshot + attach to instance (~10-15 min)',rpoWhy:'Snapshot frequency is typically weekly: worst case RPO is 7 days since last snapshot'},
  ebs_no_snap:{rto:480,rpo:Infinity,rtoWhy:'No snapshots: volume data is unrecoverable if volume fails (rare but possible)',rpoWhy:'No backup mechanism: all volume data is permanently lost on failure'}
};
// Classification tier targets in minutes (from compliance policy)
const _TIER_TARGETS={
  critical:{rto:240,rpo:60,rtoLabel:'2-4 hours',rpoLabel:'Hourly'},
  high:{rto:480,rpo:360,rtoLabel:'4-8 hours',rpoLabel:'6 hours'},
  medium:{rto:720,rpo:1440,rtoLabel:'12 hours',rpoLabel:'Daily'},
  low:{rto:1440,rpo:10080,rtoLabel:'24 hours',rpoLabel:'Weekly'}
};
// Compare estimated restore capability vs tier target: returns compliance status
function _budrTierCompliance(profileKey,classTier){
  if(!profileKey||!classTier)return{status:'unknown',issues:[]};
  var est=_BUDR_EST_MINUTES[profileKey];var target=_TIER_TARGETS[classTier];
  if(!est||!target)return{status:'unknown',issues:[]};
  var issues=[];
  if(est.rpo===Infinity)issues.push({field:'RPO',severity:'critical',msg:'No backup: RPO unrecoverable (target: '+target.rpoLabel+')'});
  else if(est.rpo>target.rpo)issues.push({field:'RPO',severity:'warning',msg:'Est. RPO ~'+_fmtMin(est.rpo)+' exceeds '+classTier+' target of '+target.rpoLabel});
  if(est.rto>target.rto)issues.push({field:'RTO',severity:'warning',msg:'Est. RTO ~'+_fmtMin(est.rto)+' exceeds '+classTier+' target of '+target.rtoLabel});
  var status=issues.some(function(i){return i.severity==='critical'})?'fail':issues.length?'warn':'pass';
  return{status:status,issues:issues,estRto:est.rto,estRpo:est.rpo,targetRto:target.rto,targetRpo:target.rpo,rtoWhy:est.rtoWhy||'',rpoWhy:est.rpoWhy||''};
}
function _fmtMin(m){if(m===0)return '0';if(m===Infinity)return '∞';if(m<60)return Math.round(m)+' min';if(m<1440)return Math.round(m/60*10)/10+' hr';return Math.round(m/1440*10)/10+' days'}
let _budrFindings=[];
let _budrAssessments=[];
let _budrOverrides={};
function runBUDRChecks(ctx){
  const f=[];const assessments=[];
  const gn=(o,id)=>{const t=(o.Tags||o.tags||[]);const n=t.find(t=>t.Key==='Name');return n?n.Value:id};
  // SQL Servers
  (ctx.rdsInstances||ctx.sqlServers||[]).forEach(db=>{
    const id=db.id||db.DBInstanceIdentifier;const name=db.name||db.DBInstanceIdentifier||id;
    const hasGeoRepl=!!(db.properties?.failoverGroups?.length);
    const retention=db.properties?.backupRetentionDays??db.BackupRetentionPeriod;
    const backupKnown=retention!==undefined&&retention!==null&&retention!==''&&Number.isFinite(Number(retention));
    const hasBackup=backupKnown?Number(retention)>0:null;
    const encrypted=!!(db.properties?.transparentDataEncryption||db.StorageEncrypted);
    const isBasic=(db.properties?.sku?.tier||db.DBInstanceClass||'').toLowerCase().includes('basic');
    const hasPITR=!!(db.properties?.earliestRestoreDate||db.LatestRestorableTime);
    let profile,sev;
    if(!backupKnown){
      profile=_BUDR_RTO_RPO.sql_unknown;
      if(!ctx.assessmentGaps)ctx.assessmentGaps={};
      ctx.assessmentGaps.sqlBackupRetention='SQL database backup retention not collected';
    }
    else if(hasGeoRepl&&hasBackup){profile=_BUDR_RTO_RPO.rds_multi_az;sev=null}
    else if(hasBackup){profile=_BUDR_RTO_RPO.rds_single_backup;sev=isBasic?null:'MEDIUM';
      f.push({severity:'MEDIUM',control:'BUDR-HA-1',framework:'BUDR',resource:id,resourceName:name,message:'SQL Server without geo-replication: single point of failure',remediation:'Configure failover groups for automatic geo-failover'})}
    else{profile=_BUDR_RTO_RPO.rds_no_backup;sev='CRITICAL';
      f.push({severity:'CRITICAL',control:'BUDR-BAK-1',framework:'BUDR',resource:id,resourceName:name,message:'SQL Server has minimal backup retention',remediation:'Configure backup retention to at least 7 days'})}
    if(!hasGeoRepl&&!isBasic&&hasBackup)
      f.push({severity:'HIGH',control:'BUDR-DR-1',framework:'BUDR',resource:id,resourceName:name,message:'SQL Server single-region with backups only: extended RTO on region failure',remediation:'Configure failover groups or geo-replication'});
    assessments.push({type:'SQL',id,name,profile,signals:{GeoReplication:hasGeoRepl,Backup:backupKnown?hasBackup:'Unknown',Encrypted:encrypted,PITR:hasPITR}});
  });
  // VMs
  const vmssInstIds=new Set();
  // Detect VMSS membership from tags
  (ctx.instances||ctx.vms||[]).forEach(inst=>{
    const vmssTag=(inst.tags||{})['vmss']||(inst.Tags||[]).find(t=>t.Key==='vmss');
    if(vmssTag)vmssInstIds.add(inst.id||inst.InstanceId);
  });
  (ctx.instances||ctx.vms||[]).forEach(inst=>{
    const id=inst.id||inst.InstanceId;const name=gn(inst,id);
    const inVMSS=vmssInstIds.has(id);
    const diskIds=(inst.properties?.storageProfile?.dataDisks||[]).map(d=>d.managedDisk?.id).filter(Boolean);
    const osDiskId=inst.properties?.storageProfile?.osDisk?.managedDisk?.id;
    if(osDiskId)diskIds.push(osDiskId);
    const hasSnaps=diskIds.some(did=>{const s=(ctx.snapByVol||{})[did];return s&&s.length>0});
    let newestSnap=null;
    diskIds.forEach(did=>{const ss=(ctx.snapByVol||{})[did]||[];ss.forEach(s=>{
      const d=new Date(s.properties?.timeCreated||s.StartTime);if(!newestSnap||d>newestSnap)newestSnap=d;
    })});
    const snapAgeDays=newestSnap?Math.floor((Date.now()-newestSnap.getTime())/(864e5)):null;
    if(hasSnaps&&snapAgeDays!==null&&snapAgeDays>7){
      f.push({severity:'MEDIUM',control:'BUDR-AGE-1',framework:'BUDR',resource:id,resourceName:name,message:'Newest disk snapshot is '+snapAgeDays+' days old (>7 days)',remediation:'Configure Azure Backup to take snapshots at least weekly'});
    }
    const encrypted=diskIds.some(did=>{const vs=(ctx.volumes||[]).filter(v=>(v.id||v.VolumeId)===did);return vs.length&&(vs[0].properties?.encryption||vs[0].Encrypted)});
    let profile;
    if(inVMSS){profile=_BUDR_RTO_RPO.ec2_asg}
    else if(hasSnaps){profile=_BUDR_RTO_RPO.ec2_ami_snap;
      f.push({severity:'LOW',control:'BUDR-HA-2',framework:'BUDR',resource:id,resourceName:name,message:'VM not in a Scale Set: manual recovery required',remediation:'Place behind VMSS or configure Azure Backup for quick recovery'})}
    else{profile=_BUDR_RTO_RPO.ec2_standalone;
      f.push({severity:'HIGH',control:'BUDR-BAK-2',framework:'BUDR',resource:id,resourceName:name,message:'Standalone VM with no disk snapshots: unrecoverable on failure',remediation:'Configure Azure Backup or create disk snapshots regularly; consider VMSS'});
      if(!inVMSS)f.push({severity:'MEDIUM',control:'BUDR-DR-2',framework:'BUDR',resource:id,resourceName:name,message:'VM has no disaster recovery strategy',remediation:'Configure Azure Backup, use VMSS with availability zones, or create disk snapshots'})}
    assessments.push({type:'VM',id,name,profile,signals:{VMSS:inVMSS,Snapshots:hasSnaps,SnapAgeDays:snapAgeDays,Encrypted:encrypted}});
  });
  // Container Instances
  (ctx.ecsServices||ctx.containerInstances||[]).forEach(svc=>{
    const id=svc.id||svc.serviceName||svc.serviceArn;const name=svc.name||svc.serviceName||id;
    const props=svc.properties||svc;
    const nativeGroup=Array.isArray(props.containers)||/^Microsoft\.ContainerInstance\/containerGroups$/i.test(svc.type||'')||/\/providers\/Microsoft\.ContainerInstance\/containerGroups\//i.test(id||'');
    if(nativeGroup){
      if(!ctx.assessmentGaps)ctx.assessmentGaps={};
      ctx.assessmentGaps.containerGroupRecovery='Independent container groups, failover, and persistent-state protection not collected';
      assessments.push({type:'Container',id,name,profile:_BUDR_RTO_RPO.container_unknown,signals:{ContainerCount:Array.isArray(props.containers)?props.containers.length:'Unknown',IndependentGroups:'Unknown',DR:'Unknown'}});
      return;
    }
    const desired=svc.desiredCount||0;
    const multi=desired>1;
    let profile;
    if(multi){profile=_BUDR_RTO_RPO.ecs_multi}
    else{profile=_BUDR_RTO_RPO.ecs_single;
      f.push({severity:'LOW',control:'BUDR-HA-3',framework:'BUDR',resource:id,resourceName:name,message:'Container instance has '+desired+' container(s): limited redundancy',remediation:'Use multiple container groups or AKS for HA'})}
    assessments.push({type:'Container',id,name,profile,signals:{ContainerCount:desired,MultiContainer:multi}});
  });
  // Function Apps (inherently resilient)
  (ctx.lambdaFns||ctx.functionApps||[]).forEach(fn=>{
    const fnId=fn.id||fn.FunctionName;const fnName=fn.name||fn.FunctionName||fnId;
    assessments.push({type:'FunctionApp',id:fnId,name:fnName,profile:_BUDR_RTO_RPO.lambda,signals:{Managed:true}});
  });
  // Redis Cache
  (ctx.ecacheClusters||ctx.redisCaches||[]).forEach(ec=>{
    const id=ec.id||ec.CacheClusterId;const name=ec.name||ec.CacheClusterId||id;
    const shardCount=ec.properties?.shardCount||1;
    const multiNode=shardCount>1||(ec.properties?.replicasPerMaster||0)>0;
    const props=ec.properties||ec;
    const boolean=value=>typeof value==='boolean'?value:typeof value==='string'&&/^(true|false)$/i.test(value.trim())?value.trim().toLowerCase()==='true':null;
    const rdb=boolean(props.redisConfiguration?.['rdb-backup-enabled']??props.rdbBackupEnabled);
    const aof=boolean(props.redisConfiguration?.['aof-backup-enabled']??props.aofBackupEnabled);
    const retention=ec.SnapshotRetentionLimit;
    const legacyBackup=retention!==undefined&&retention!==null&&retention!==''&&Number.isFinite(Number(retention))?Number(retention)>0:null;
    const hasBackup=rdb===true||aof===true||legacyBackup===true?true:rdb===false&&aof===false||legacyBackup===false?false:null;
    if(hasBackup===null){
      if(!ctx.assessmentGaps)ctx.assessmentGaps={};
      ctx.assessmentGaps.redisPersistence='Redis RDB/AOF persistence settings not collected';
    }
    const geoRepl=!!(ec.properties?.linkedServers?.length);
    let profile;
    if(multiNode){profile=_BUDR_RTO_RPO.ecache_multi}
    else if(hasBackup){profile=_BUDR_RTO_RPO.ecache_single;
      f.push({severity:'MEDIUM',control:'BUDR-HA-4',framework:'BUDR',resource:id,resourceName:name,message:'Redis Cache single node: failover requires manual intervention',remediation:'Add replicas or enable clustering for automatic failover'})}
    else if(hasBackup===false){profile=_BUDR_RTO_RPO.ecache_no_snap;
      f.push({severity:'HIGH',control:'BUDR-BAK-3',framework:'BUDR',resource:id,resourceName:name,message:'Redis Cache single node with no persistence: data loss risk',remediation:'Enable RDB persistence and add replicas'})}
    else{profile=_BUDR_RTO_RPO.redis_unknown}
    assessments.push({type:'RedisCache',id,name,profile,signals:{MultiNode:multiNode,Persistence:hasBackup===null?'Unknown':hasBackup,GeoReplication:geoRepl}});
  });
  // Synapse
  (ctx.redshiftClusters||ctx.synapseWorkspaces||[]).forEach(rs=>{
    const id=rs.id||rs.ClusterIdentifier;const name=rs.name||rs.ClusterIdentifier||id;
    const props=rs.properties||rs;
    const nativeWorkspace=/^Microsoft\.Synapse\/workspaces$/i.test(rs.type||'')||/\/providers\/Microsoft\.Synapse\/workspaces\//i.test(id||'')||props.managedVirtualNetworkSettings!==undefined||props.workspaceRepositoryConfiguration!==undefined||props.managedResourceGroupName!==undefined;
    if(nativeWorkspace){
      if(!ctx.assessmentGaps)ctx.assessmentGaps={};
      ctx.assessmentGaps.synapseProtection='Synapse SQL pool backup, restore-point, and replication evidence not collected';
      assessments.push({type:'Synapse',id,name,profile:_BUDR_RTO_RPO.synapse_unknown,signals:{Backup:'Unknown',DR:'Unknown'}});
      return;
    }
    const hasBackup=!!rs.AutomatedSnapshotRetentionPeriod;
    const hasDR=false;
    let profile;
    if(hasDR&&hasBackup){profile=_BUDR_RTO_RPO.redshift_multi}
    else if(hasBackup){profile=_BUDR_RTO_RPO.redshift_snap;
      f.push({severity:'MEDIUM',control:'BUDR-HA-5',framework:'BUDR',resource:id,resourceName:name,message:'Synapse workspace without DR configuration',remediation:'Configure geo-redundant backups and disaster recovery'})}
    else{profile=_BUDR_RTO_RPO.redshift_none;
      f.push({severity:'HIGH',control:'BUDR-BAK-4',framework:'BUDR',resource:id,resourceName:name,message:'Synapse workspace with no backup configuration: data loss risk',remediation:'Configure restore points and geo-redundant backups'})}
    assessments.push({type:'Synapse',id,name,profile,signals:{Backup:hasBackup,DR:hasDR}});
  });
  // App Gateways
  (ctx.albs||ctx.appGateways||[]).forEach(alb=>{
    const id=alb.id||alb.LoadBalancerName||alb.LoadBalancerArn;const name=alb.name||alb.LoadBalancerName||id;
    const sku=alb.properties?.sku||alb.sku||{};
    const isV2=/^(Standard_v2|WAF_v2)$/i.test(sku.tier||sku.name||'');
    const zones=(alb.zones||(!isV2&&alb.AvailabilityZones)||[]).length;
    let profile;
    if(zones>=2){profile=_BUDR_RTO_RPO.alb_multi_az}
    else if(isV2&&zones===0){
      profile=_BUDR_RTO_RPO.agw_unknown;
      if(!ctx.assessmentGaps)ctx.assessmentGaps={};
      ctx.assessmentGaps.appGatewayZones='Application Gateway v2 regional zone support not collected; omitted zones can use the regional default';
    }
    else{profile=_BUDR_RTO_RPO.alb_single_az;
      f.push({severity:'MEDIUM',control:'BUDR-HA-6',framework:'BUDR',resource:id,resourceName:name,message:'App Gateway in single zone only: no failover',remediation:'Deploy across at least 2 availability zones'})}
    assessments.push({type:'AppGateway',id,name,profile,signals:{ZoneCount:isV2&&zones===0?'Unknown':zones}});
  });
  // Managed Disks (standalone: not already counted via VM)
  (ctx.volumes||[]).forEach(vol=>{
    const diskState=vol.properties?.diskState||vol.State||'';
    if(diskState!=='Attached'&&diskState!=='in-use')return;
    const id=vol.id||vol.VolumeId;const name=gn(vol,id);
    const snaps=(ctx.snapByVol||{})[id]||[];
    if(snaps.length===0){
      f.push({severity:'MEDIUM',control:'BUDR-BAK-5',framework:'BUDR',resource:id,resourceName:name,message:'Attached managed disk has no snapshots',remediation:'Create snapshot schedule via Azure Backup policy'});
    }
  });
  // Storage Accounts
  (ctx.s3bk||ctx.storageAccounts||[]).forEach(bk=>{
    const id=bk.id||bk.Name||'unknown';const name=bk.name||bk.Name||id;
    const props=bk.properties||bk;
    const versioning=props.isVersioningEnabled??props.isBlobVersioningEnabled??bk.isVersioningEnabled;
    const versioned=typeof versioning==='boolean'?versioning:(bk.Versioning?.Status?bk.Versioning.Status==='Enabled':null);
    const deletion=props.deleteRetentionPolicy?.enabled??bk.deleteRetentionPolicy?.enabled;
    const softDelete=typeof deletion==='boolean'?deletion:null;
    let profile;
    if(versioned===null||softDelete===null){
      if(!ctx.assessmentGaps)ctx.assessmentGaps={};
      ctx.assessmentGaps.storageBlobProtection='Blob Service versioning or soft-delete settings not collected';
    }
    if(softDelete===true){profile=_BUDR_RTO_RPO.s3_mfa_delete}
    else if(versioned===true){profile=_BUDR_RTO_RPO.s3_versioned}
    else if(versioned===null||softDelete===null){profile=_BUDR_RTO_RPO.storage_unknown}
    else{profile=_BUDR_RTO_RPO.s3_unversioned;
      f.push({severity:'HIGH',control:'BUDR-S3-1',framework:'BUDR',resource:id,resourceName:name,message:'Storage account has no blob versioning \u2014 data loss risk',remediation:'Enable blob versioning and soft delete to protect against accidental deletes'})}
    assessments.push({type:'StorageAccount',id,name,profile,signals:{Versioned:versioned===null?'Unknown':versioned,SoftDelete:softDelete===null?'Unknown':softDelete}});
  });
  // Enrich assessments with subscription/vnet/region from raw resources
  function _budrAccount(r){return r._subscriptionId||(String(r.id||"").match(/\/subscriptions\/([^/]+)/i)||[])[1]||""}
  var _budrLookup={};
  var _bSubVnet={};(ctx.subnets||[]).forEach(function(s){var sid=s.id||s.SubnetId;if(sid)_bSubVnet[sid]=s.VpcId||(s.id||'').split('/subnets/')[0]||''});
  (ctx.rdsInstances||ctx.sqlServers||[]).forEach(function(r){_budrLookup['SQL:'+(r.id||r.DBInstanceIdentifier)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.instances||ctx.vms||[]).forEach(function(r){var rid=r.id||r.InstanceId;_budrLookup['VM:'+rid]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.ecsServices||ctx.containerInstances||[]).forEach(function(r){_budrLookup['Container:'+(r.id||r.serviceName||r.serviceArn)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.lambdaFns||ctx.functionApps||[]).forEach(function(r){_budrLookup['FunctionApp:'+(r.id||r.FunctionName)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.ecacheClusters||ctx.redisCaches||[]).forEach(function(r){_budrLookup['RedisCache:'+(r.id||r.CacheClusterId)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.redshiftClusters||ctx.synapseWorkspaces||[]).forEach(function(r){_budrLookup['Synapse:'+(r.id||r.ClusterIdentifier)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.albs||ctx.appGateways||[]).forEach(function(r){_budrLookup['AppGateway:'+(r.id||r.LoadBalancerName||r.LoadBalancerArn)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.s3bk||ctx.storageAccounts||[]).forEach(function(r){_budrLookup['StorageAccount:'+(r.id||r.Name)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.volumes||[]).forEach(function(r){_budrLookup['Disk:'+(r.id||r.VolumeId)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  (ctx.snapshots||[]).forEach(function(r){_budrLookup['Snapshot:'+(r.id||r.SnapshotId)]={a:_budrAccount(r),r:r._region||r.location||'',v:''}});
  assessments.forEach(function(a){var info=_budrLookup[a.type+':'+a.id];if(info){a.account=info.a;a.region=info.r;a.vpcId=info.v}});
  // Fallback: unmatched assessments get primary account
  var _bAccts=new Set();(ctx.vpcs||[]).forEach(function(v){if(v._subscriptionId&&v._subscriptionId!=='default')_bAccts.add(v._subscriptionId)});
  if(_bAccts.size>=1){var _bPri=[..._bAccts][0];assessments.forEach(function(a){if(!a.account)a.account=_bPri})}
  // Enrich BUDR findings with account/region (for Action Plan sheet)
  var _bResLookup={};
  Object.keys(_budrLookup).forEach(function(k){var id=k.split(':').slice(1).join(':');_bResLookup[id]=_budrLookup[k]});
  f.forEach(function(finding){var info=_bResLookup[finding.resource];if(info){finding._subscriptionId=info.a;finding._region=info.r;finding._vpcId=info.v}});
  if(_bAccts.size>=1){var _bPri2=[..._bAccts][0];f.forEach(function(finding){if(!finding._subscriptionId)finding._subscriptionId=_bPri2})};
  _budrFindings=f;
  _budrAssessments=assessments;
  // Cross-reference with classification engine for tier compliance
  _enrichBudrWithClassification(ctx,f);
  return f;
}
function _enrichBudrWithClassification(ctx,findings){
  // Run classification if not already done
  var classData=GovernanceClassification.ensure(ctx);
  // Build lookup by resource id/name (type-qualified keys take priority to avoid cross-type collisions)
  var classMap={};var classMapTyped={};
  classData.forEach(function(c){classMap[c.id]=c;classMap[c.name]=c;classMapTyped[c.type+'|'+c.id]=c;classMapTyped[c.type+'|'+c.name]=c});
  // Enrich each BUDR assessment
  _budrAssessments.forEach(function(a){
    var cls=classMapTyped[a.type+'|'+a.id]||classMapTyped[a.type+'|'+a.name]||classMap[a.id]||classMap[a.name];
    a.classTier=cls?cls.tier:'low';
    a.classVpcName=cls?cls.vpcName:'';
    // Find which profile key this assessment uses
    var profileKey=null;
    for(let k in _BUDR_RTO_RPO){if(_BUDR_RTO_RPO[k]===a.profile){profileKey=k;break}}
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
    var ov=_budrOverrides[a.id];
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
  _budrAssessments.forEach(function(a){
    // Restore auto values first
    if(a.autoProfile){
      a.profile=Object.assign({},a.profile);
      a.profile.strategy=a.autoProfile.strategy;
      a.profile.rto=a.autoProfile.rto;
      a.profile.rpo=a.autoProfile.rpo;
      a.profile.tier=a.autoProfile.tier;
      a.overridden=false;
    }
    var ov=_budrOverrides[a.id];
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
  _budrAssessments.forEach(a=>{
    if(a.profile)counts[a.profile.tier]=(counts[a.profile.tier]||0)+1;
  });
  return counts;
}
function _getBudrComplianceCounts(){
  var counts={pass:0,warn:0,fail:0,unknown:0};
  _budrAssessments.forEach(function(a){
    var s=a.compliance?a.compliance.status:'unknown';
    counts[s]=(counts[s]||0)+1;
  });
  return counts;
}
// === REPORT BUILDER MODULE REGISTRY ===
function reportRegistryRuntimeContext(){
  return AppRenderContext.createRenderContext();
}
function reportRegistryContextData(){
  if(_importedReportData)return null;
  return reportRegistryRuntimeContext().rlCtx;
}
function reportRegistryComplianceRows(){
  return reportRegistryRuntimeContext().complianceFindings||[];
}
const _RPT_MODULES=[
  {id:'exec-summary',name:'Executive Summary',icon:'',category:'overview',enabled:true,
   available:function(){return !!reportRegistryContextData()||!!_importedReportData},
   desc:function(){var c=reportRegistryContextData();if(_importedReportData&&!c)return 'Imported report data';return c?(c.vnets||[]).length+' VNets, '+(c.vms||[]).length+' VMs':'No data'},
   render:function(ctx,opts){return _rptExecSummary(ctx,opts)}},
  {id:'architecture',name:'Architecture Diagram',icon:'',category:'overview',enabled:true,
   available:function(){return !!document.querySelector('#mapSvg .map-root')},
   desc:function(){return document.querySelector('#mapSvg .map-root')?'Map rendered':'No map'},
   render:function(ctx,opts){return _rptArchDiagram(ctx,opts)}},
  {id:'compliance',name:'Compliance Findings',icon:'',category:'security',enabled:true,
   available:function(){return reportRegistryComplianceRows().length>0},
   desc:function(){var a=typeof _rptGetAccountFilter==='function'?_rptGetAccountFilter():'all';var f=_rptFilterByAccount(reportRegistryComplianceRows(),a);return f.length+' findings'},
   render:function(ctx,opts){return _rptCompliance(ctx,opts)}},
  {id:'budr',name:'BUDR Assessment',icon:'',category:'security',enabled:true,
   available:function(){return _budrAssessments.length>0},
   desc:function(){var a=typeof _rptGetAccountFilter==='function'?_rptGetAccountFilter():'all';var f=_rptFilterByAccount(_budrAssessments||[],a);return f.length+' resources assessed'},
   render:function(ctx,opts){return _rptBUDR(ctx,opts)}},
  {id:'iam-review',name:'IAM Review',icon:'',category:'security',enabled:true,
   available:function(){if(_importedReportData)return _iamReviewData.length>0;return !!_iamData||!!safeParse(gv('in_rbac'))},
   desc:function(){if(!_importedReportData&&!_iamReviewData.length){var r=safeParse(gv('in_rbac'));if(r){var p=parseIAMData(r);if(p)prepareIAMReviewData(p)}}var a=typeof _rptGetAccountFilter==='function'?_rptGetAccountFilter():'all';var f=_rptFilterByAccount(_iamReviewData,a);return f.length?f.length+' principals/assignments':'No IAM data'},
   render:function(ctx,opts){return _rptIAMReview(ctx,opts)}},
  {id:'inventory',name:'Resource Inventory',icon:'',category:'data',enabled:true,
   available:function(){return !!reportRegistryContextData()||(_importedReportData&&_inventoryData.length>0)},
   desc:function(){var c=reportRegistryContextData();if(!c&&!_importedReportData)return 'No data';if(!_inventoryData.length&&c)_buildInventoryData();var a=typeof _rptGetAccountFilter==='function'?_rptGetAccountFilter():'all';var f=_rptFilterByAccount(_inventoryData,a);return f.length+' resources across all resource types'},
   render:function(ctx,opts){return _rptInventory(ctx,opts)}},
  {id:'action-plan',name:'Action Plan',icon:'',category:'remediation',enabled:true,
   available:function(){return reportRegistryComplianceRows().length>0},
   desc:function(){var a=typeof _rptGetAccountFilter==='function'?_rptGetAccountFilter():'all';var f=_rptFilterByAccount(reportRegistryComplianceRows(),a);return f.length+' items'},
   render:function(ctx,opts){return _rptActionPlan(ctx,opts)}},
  {id:'app-summary',name:'App Summary',icon:'',category:'overview',enabled:true,
   available:function(){if(_importedReportData)return _appRegistry.length>0;var c=reportRegistryContextData();if(!_appRegistry.length&&typeof _autoDiscoverApps==='function'){GovernanceClassification.ensure(c);_autoDiscoverApps()}return _appRegistry.length>0},
   desc:function(){return _appRegistry.length+' apps defined'},
   render:function(ctx,opts){return _rptAppSummary(ctx,opts)}},
  {id:'iac-recs',name:'IaC Recommendations',icon:'',category:'remediation',enabled:false,
   available:function(){return reportRegistryComplianceRows().length>0},
   desc:function(){return 'Terraform/CF snippets'},
   render:function(ctx,opts){return _rptIaCRecs(ctx,opts)}}
];
const _rptState={order:null,title:'Azure Infrastructure Assessment',author:'',date:new Date().toISOString().slice(0,10),logo:null};
var _importedReportData=null;

// #endregion BUDR ENGINE

