// Governance classification rules, scoring, and tier metadata.
// Dashboard, report, BUDR, and inventory owners use these legacy names until those callers move to explicit adapters.

let _classificationData=[];
let _classificationOverrides={};

const _DEFAULT_CLASS_RULES=[
  {pattern:'prod|production',scope:'vpc',tier:'critical',weight:100},
  {pattern:'pci|complian',scope:'vpc',tier:'critical',weight:95},
  {pattern:'dr-|disaster|recovery',scope:'vpc',tier:'critical',weight:90},
  {pattern:'shared.?serv|data.?platform|security',scope:'vpc',tier:'high',weight:80},
  {pattern:'edge|proxy|waf|cdn',scope:'vpc',tier:'high',weight:75},
  {pattern:'staging|stage|qa|uat',scope:'vpc',tier:'medium',weight:50},
  {pattern:'management|mgmt|monitor',scope:'vpc',tier:'medium',weight:45},
  {pattern:'dev|develop|sandbox|test|experiment',scope:'vpc',tier:'low',weight:20},
  {pattern:'rds|database|db|aurora|dynamo',scope:'type',tier:'critical',weight:90},
  {pattern:'redshift|warehouse',scope:'type',tier:'critical',weight:85},
  {pattern:'elasticache|redis|memcache|cache',scope:'type',tier:'high',weight:70},
  {pattern:'alb|elb|loadbalancer|nlb',scope:'type',tier:'high',weight:65},
  {pattern:'lambda|fargate|ecs',scope:'type',tier:'medium',weight:40},
  {pattern:'bastion|jump|ssh',scope:'name',tier:'medium',weight:35},
  // Tag-based rules: Environment tag is strongest classification signal
  {pattern:'prod|production|prd',scope:'tag:Environment',tier:'critical',weight:120},
  {pattern:'staging|stage|uat|qa',scope:'tag:Environment',tier:'medium',weight:110},
  {pattern:'dev|develop|sandbox|test',scope:'tag:Environment',tier:'low',weight:110}
];
var _classificationRules=structuredClone(_DEFAULT_CLASS_RULES);
var _discoveredTags={};

const _TIER_RPO_RTO={
  critical:{rpo:'Hourly',rto:'2-4 hours',priority:1,color:'#ef4444'},
  high:{rpo:'6 hours',rto:'4-8 hours',priority:2,color:'#f59e0b'},
  medium:{rpo:'Daily',rto:'12 hours',priority:3,color:'#22d3ee'},
  low:{rpo:'Weekly',rto:'24 hours',priority:4,color:'#64748b'}
};

function _getTagMap(obj){
  var tg=obj.Tags||obj.tags||obj.TagList;
  if(!tg)return{};
  // Azure flat object format: {Name: "value", Environment: "prod"}
  if(!Array.isArray(tg)&&typeof tg==='object')return tg;
  // AWS array format: [{Key: "Name", Value: "value"}]
  var m={};tg.forEach(function(t){if(t.Key)m[t.Key]=t.Value||''});return m;
}

function _safeRegex(pattern){
  try{var re=new RegExp(pattern,'i');
    if(/(\+|\*|\{)\s*\)(\+|\*|\{)/.test(pattern)) return null;
    return re;
  }catch(e){return null}
}
function _scoreClassification(name,type,vpcName,rules,tagMap){
  rules=rules||_classificationRules;
  tagMap=tagMap||{};
  var bestTier='low';var bestWeight=-1;
  rules.forEach(function(rule){
    if(rule.enabled===false) return;
    var p=rule.pattern;if(!p) return;
    p=p.replace(/^\|+|\|+$/g,'').replace(/\|{2,}/g,'|');if(!p) return;
    var re=_safeRegex(p);if(!re) return;
    var text='';
    if(rule.scope==='any') text=(name||'')+' '+(type||'')+' '+(vpcName||'')+' '+Object.values(tagMap).join(' ');
    else if(rule.scope==='vpc') text=vpcName||'';
    else if(rule.scope==='type') text=type||'';
    else if(rule.scope==='name') text=name||'';
    else if(rule.scope.indexOf('tag:')===0) text=tagMap[rule.scope.substring(4)]||'';
    else text=(name||'')+' '+(type||'')+' '+(vpcName||'');
    if(re.test(text)&&rule.weight>bestWeight){bestWeight=rule.weight;bestTier=rule.tier}
  });
  return {tier:bestTier,weight:bestWeight};
}

function _discoverTagKeys(ctx){
  if(!ctx) return {};
  var disc={};
  function scan(arr,typeName){
    (arr||[]).forEach(function(obj){
      Object.entries(_getTagMap(obj)).forEach(function(entry){
        var t={Key:entry[0],Value:entry[1]};
        if(!t.Key||t.Key.indexOf('aws:')===0||t.Key.indexOf('microsoft:')===0||t.Key.indexOf('hidden-')===0) return;
        if(!disc[t.Key]) disc[t.Key]={count:0,samples:[],types:{}};
        var d=disc[t.Key];d.count++;d.types[typeName]=true;
        if(d.samples.length<5&&t.Value&&d.samples.indexOf(t.Value)<0) d.samples.push(t.Value);
      });
    });
  }
  scan(ctx.instances,'VM');scan(ctx.rdsInstances,'SQL');scan(ctx.ecacheClusters,'Redis Cache');
  scan(ctx.albs,'App Gateway');scan(ctx.lambdaFns,'Function App');scan(ctx.ecsServices,'Container');
  scan(ctx.redshiftClusters,'Synapse');scan(ctx.vpcs,'VNet');scan(ctx.subnets,'Subnet');
  scan(ctx.sgs,'NSG');scan(ctx.s3bk,'Storage Account');
  Object.keys(disc).forEach(function(k){disc[k].types=Object.keys(disc[k].types)});
  return disc;
}

function runClassificationEngine(ctx){
  if(!ctx) return[];
  ctx={...ctx};
  [['vpcs','vnets'],['instances','vms'],['rdsInstances','sqlServers'],['ecacheClusters','redisCaches'],['albs','appGateways'],['lambdaFns','functionApps'],['ecsServices','containerInstances'],['redshiftClusters','synapseWorkspaces'],['sgs','nsgs'],['igws','firewalls'],['nats','natGateways'],['vpces','privateEndpoints'],['s3bk','storageAccounts']].forEach(function(pair){ctx[pair[0]]=ctx[pair[1]]||ctx[pair[0]]||[]});
  var results=[];
  var vpcNameMap={};
  (ctx.vpcs||[]).forEach(function(v){vpcNameMap[v.id||v.VpcId]=v.name||gn(v,v.VpcId)});
  // Build subnet→VPC lookup for resources that only have SubnetId
  var subnetVpcMap={};
  (ctx.subnets||[]).forEach(function(s){if(s.VpcId) subnetVpcMap[s.SubnetId]=s.VpcId});
  function resolveVpc(vpcId,subnetId){return vpcId||subnetVpcMap[subnetId]||''}
  // Classify instances
  (ctx.instances||[]).forEach(function(inst){
    var id=inst.id||inst.InstanceId;var name=inst.name||_getTagMap(inst).Name||id;
    var vpcId=resolveVpc(inst.VpcId,inst.SubnetId);
    var vpcName=vpcNameMap[vpcId]||'';
    var tm=_getTagMap(inst);
    var sc=_scoreClassification(name,'instance',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;
    var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'VM',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify RDS
  (ctx.rdsInstances||[]).forEach(function(db){
    var id=db.id||db.DBInstanceIdentifier;var name=db.name||db.DBInstanceIdentifier||id;
    var vpcId=db.DBSubnetGroup?db.DBSubnetGroup.VpcId:'';
    var vpcName=vpcNameMap[vpcId]||'';
    var tm=_getTagMap(db);
    var sc=_scoreClassification(name,'rds',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;
    var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'SQL',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify Redis Cache
  (ctx.ecacheClusters||[]).forEach(function(ec){
    var id=ec.id||ec.CacheClusterId;var name=ec.name||ec.CacheClusterId||id;
    var vpcId=ec.VpcId||'';
    var vpcName=vpcNameMap[vpcId]||'';
    var tm=_getTagMap(ec);
    var sc=_scoreClassification(name,'redis',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;
    var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Redis Cache',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify App Gateways
  (ctx.albs||[]).forEach(function(alb){
    var albId=alb.id||alb.LoadBalancerArn||'';
    var name=alb.name||alb.LoadBalancerName||albId;
    var vpcId=alb.VpcId||'';
    var vpcName=vpcNameMap[vpcId]||'';
    var tm=_getTagMap(alb);
    var sc=_scoreClassification(name,'appgateway',vpcName,null,tm);
    var tier=_classificationOverrides[albId]||sc.tier;
    var meta=_TIER_RPO_RTO[tier];
    results.push({id:albId||name,name:name,type:'App Gateway',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[albId],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify Function Apps
  (ctx.lambdaFns||[]).forEach(function(fn){
    var id=fn.id||fn.FunctionName;var name=fn.name||fn.FunctionName||id;
    var vpcId=fn.VpcConfig?fn.VpcConfig.VpcId:'';
    if(!vpcId&&fn.VpcConfig&&fn.VpcConfig.SubnetIds&&fn.VpcConfig.SubnetIds[0]) vpcId=subnetVpcMap[fn.VpcConfig.SubnetIds[0]]||'';
    var vpcName=vpcNameMap[vpcId]||'';
    var tm=_getTagMap(fn);
    var sc=_scoreClassification(name,'functionapp',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;
    var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Function App',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify Containers
  (ctx.ecsServices||[]).forEach(function(svc){
    var id=svc.id||svc.serviceName||svc.serviceArn||'';var name=svc.name||svc.serviceName||id;
    var nc=svc.networkConfiguration&&svc.networkConfiguration.awsvpcConfiguration;
    var vpcId=nc&&nc.subnets&&nc.subnets[0]?subnetVpcMap[nc.subnets[0]]||'':'';
    var vpcName=vpcNameMap[vpcId]||'';
    var tm=_getTagMap(svc);
    var sc=_scoreClassification(name,'container',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;
    var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Container',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify Synapse
  (ctx.redshiftClusters||[]).forEach(function(rs){
    var id=rs.id||rs.ClusterIdentifier;var name=rs.name||rs.ClusterIdentifier||id;
    var vpcId=rs.VpcId||'';
    var vpcName=vpcNameMap[vpcId]||'';
    var tm=_getTagMap(rs);
    var sc=_scoreClassification(name,'redshift',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;
    var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Synapse',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify NSGs
  (ctx.sgs||[]).forEach(function(sg){
    var id=sg.id||sg.GroupId;var name=sg.name||gn(sg,id);
    var vpcId=sg.VpcId||'';var vpcName=vpcNameMap[vpcId]||'';var tm=_getTagMap(sg);
    var sc=_scoreClassification(name,'security-group',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'NSG',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify VNets
  (ctx.vpcs||[]).forEach(function(v){
    var id=v.id||v.VpcId;var name=v.name||gn(v,id);var tm=_getTagMap(v);
    var sc=_scoreClassification(name,'vpc',name,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'VNet',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:id,vpcName:name,tags:tm});
  });
  // Classify Subnets
  (ctx.subnets||[]).forEach(function(s){
    var id=s.id||s.SubnetId;var name=s.name||gn(s,id);var vpcId=s.VpcId||'';var vpcName=vpcNameMap[vpcId]||'';var tm=_getTagMap(s);
    var sc=_scoreClassification(name,'subnet',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Subnet',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify Azure Firewalls
  (ctx.igws||[]).forEach(function(gw){
    var id=gw.id||gw.InternetGatewayId;var name=gw.name||gn(gw,id);var vpcId=(gw.Attachments&&gw.Attachments[0])?gw.Attachments[0].VpcId:'';var vpcName=vpcNameMap[vpcId]||'';var tm=_getTagMap(gw);
    var sc=_scoreClassification(name,'igw',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Azure Firewall',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify NAT GWs
  (ctx.nats||[]).forEach(function(ng){
    var id=ng.id||ng.NatGatewayId;var name=ng.name||gn(ng,id);var vpcId=ng.VpcId||'';var vpcName=vpcNameMap[vpcId]||'';var tm=_getTagMap(ng);
    var sc=_scoreClassification(name,'nat-gateway',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'NAT GW',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify Private Endpoints
  (ctx.vpces||[]).forEach(function(ve){
    var id=ve.id||ve.VpcEndpointId;var name=ve.name||ve.ServiceName||id;var vpcId=ve.VpcId||'';var vpcName=vpcNameMap[vpcId]||'';var tm=_getTagMap(ve);
    var sc=_scoreClassification(name,'vpc-endpoint',vpcName,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Private Endpoint',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:vpcId,vpcName:vpcName,tags:tm});
  });
  // Classify Storage Accounts
  (ctx.s3bk||[]).forEach(function(b){
    var id=b.id||b.Name||b.name||'';var name=b.name||b.Name||id;var tm=_getTagMap(b);
    var sc=_scoreClassification(name,'s3',''  ,null,tm);
    var tier=_classificationOverrides[id]||sc.tier;var meta=_TIER_RPO_RTO[tier];
    results.push({id:id,name:name,type:'Storage Account',tier:tier,rpo:meta.rpo,rto:meta.rto,auto:!_classificationOverrides[id],vpcId:'',vpcName:'',tags:tm});
  });
  // Enrich classification data with account IDs from source resources
  var _clResAcct={};
  (ctx.instances||[]).forEach(function(r){_clResAcct[r.InstanceId]=r._subscriptionId});
  (ctx.rdsInstances||[]).forEach(function(r){_clResAcct[r.DBInstanceIdentifier]=r._subscriptionId});
  (ctx.ecacheClusters||[]).forEach(function(r){_clResAcct[r.CacheClusterId]=r._subscriptionId});
  (ctx.albs||[]).forEach(function(r){_clResAcct[r.LoadBalancerName||r.LoadBalancerArn]=r._subscriptionId});
  (ctx.lambdaFns||[]).forEach(function(r){_clResAcct[r.FunctionName]=r._subscriptionId});
  (ctx.ecsServices||[]).forEach(function(r){_clResAcct[r.serviceName||r.serviceArn]=r._subscriptionId});
  (ctx.sgs||[]).forEach(function(r){_clResAcct[r.GroupId]=r._subscriptionId});
  (ctx.vpcs||[]).forEach(function(r){_clResAcct[r.VpcId]=r._subscriptionId});
  (ctx.subnets||[]).forEach(function(r){_clResAcct[r.SubnetId]=r._subscriptionId});
  (ctx.s3bk||[]).forEach(function(r){_clResAcct[r.Name]=r._subscriptionId});
  [ctx.instances,ctx.rdsInstances,ctx.ecacheClusters,ctx.albs,ctx.lambdaFns,ctx.ecsServices,ctx.redshiftClusters,ctx.sgs,ctx.vpcs,ctx.subnets,ctx.igws,ctx.nats,ctx.vpces,ctx.s3bk].forEach(function(arr){(arr||[]).forEach(function(r){if(r.id)_clResAcct[r.id]=r._subscriptionId||(String(r.id).match(/\/subscriptions\/([^/]+)/i)||[])[1]||''})});
  results.forEach(function(r){if(_clResAcct[r.id])r._subscriptionId=_clResAcct[r.id]});
  _classificationData=results;
  _discoveredTags=_discoverTagKeys(ctx);
  return results;
}

function ensureClassificationData(ctx){
  if(!_classificationData.length&&ctx) runClassificationEngine(ctx);
  return _classificationData;
}

function resetClassificationData(){
  _classificationData=[];
  _discoveredTags={};
  return _classificationData;
}

function classificationTierMeta(tier){
  return _TIER_RPO_RTO[tier]||_TIER_RPO_RTO.low;
}

function setClassificationOverride(id,tier){
  _classificationOverrides[id]=tier;
  var item=_classificationData.find(function(r){return r.id===id});
  if(item){
    var meta=classificationTierMeta(tier);
    item.tier=tier;
    item.rpo=meta.rpo;
    item.rto=meta.rto;
    item.auto=false;
  }
  return item;
}

function applyClassificationRules(rules,ctx){
  _classificationRules=(Array.isArray(rules)?rules:[]).filter(function(r){return r.pattern});
  _classificationOverrides={};
  if(ctx) runClassificationEngine(ctx);
  return _classificationData;
}

var GovernanceClassification={
  get data(){return _classificationData},
  set data(value){_classificationData=Array.isArray(value)?value:[]},
  get overrides(){return _classificationOverrides},
  set overrides(value){_classificationOverrides=value||{}},
  get rules(){return _classificationRules},
  set rules(value){_classificationRules=Array.isArray(value)?value:[]},
  get discoveredTags(){return _discoveredTags},
  get tiers(){return _TIER_RPO_RTO},
  classify:runClassificationEngine,
  ensure:ensureClassificationData,
  reset:resetClassificationData,
  tierMeta:classificationTierMeta,
  setOverride:setClassificationOverride,
  applyRules:applyClassificationRules,
  score:_scoreClassification,
  tagMap:_getTagMap,
  safeRegex:_safeRegex
};
