// Browser-runtime snapshot comparison for diff mode.
// The ES-module diff-engine.js stays pure for Node imports; this plain-script
// owner exists because app-core regions are still assembled as classic scripts.

function diffJson(value, spacing){
  var seen=new WeakSet();
  return JSON.stringify(value,function(key,item){
    if(item&&typeof item==='object'){
      if(seen.has(item)) return '[Circular]';
      seen.add(item);
    }
    return item;
  },spacing);
}

const _DIFF_KEYS={
  vnets:'id',subnets:'id',vms:'id',nsgs:'id',udrs:'id',
  natGateways:'id',privateEndpoints:'id',appGateways:'id',
  sqlServers:'id',functionApps:'id',containerInstances:'id',
  redisCaches:'id',synapseWorkspaces:'id',peerings:'id',
  storageAccounts:'id',aksCluster:'id',firewalls:'id',
  bastions:'id',loadBalancers:'id'
};

const _DIFF_KEY_FALLBACKS={
  vnets:['id','VpcId'],subnets:['id','SubnetId'],vms:['id','InstanceId'],
  nsgs:['id','GroupId'],udrs:['id','RouteTableId'],
  natGateways:['id','NatGatewayId'],privateEndpoints:['id','VpcEndpointId'],
  appGateways:['id','LoadBalancerArn','LoadBalancerName'],
  sqlServers:['id','DBInstanceIdentifier'],functionApps:['id','FunctionName'],
  containerInstances:['id','serviceArn','serviceName'],redisCaches:['id','CacheClusterId'],
  synapseWorkspaces:['id','ClusterIdentifier'],peerings:['id','VpcPeeringConnectionId'],
  storageAccounts:['id','Name'],aksCluster:['id','ClusterIdentifier'],
  firewalls:['id','InternetGatewayId'],bastions:['id'],loadBalancers:['id','TargetGroupArn','TargetGroupName']
};

const _DIFF_TEXTAREA_IDS={
  vnets:['in_vnets'],
  subnets:['in_subnets'],
  vms:['in_vms'],
  nsgs:['in_nsgs'],
  udrs:['in_udrs'],
  natGateways:['in_nats'],
  privateEndpoints:['in_pvteps','in_privateendpoints','in_private_endpoints'],
  appGateways:['in_albs','in_agws','in_app_gateways'],
  sqlServers:['in_sql'],
  functionApps:['in_funcapps','in_functions'],
  containerInstances:['in_containers'],
  redisCaches:['in_elasticache','in_redis'],
  synapseWorkspaces:['in_synapse'],
  peerings:['in_peer','in_peerings'],
  storageAccounts:['in_storage'],
  aksCluster:['in_aks'],
  firewalls:['in_azfws','in_firewalls'],
  bastions:['in_bastions'],
  loadBalancers:['in_tgs','in_lbs']
};

const _DIFF_VOLATILE=new Set([
  'createdTime','lastModifiedTime','provisioningTime','startTime',
  'endTime','lastSyncTime','changedTime','etag','managedBy',
  'LaunchTime','CreateTime','CreateDate','AttachTime','StartTime',
  'StatusMessage','TransitionReason','LastModifiedTime',
  'InstanceCreateTime','LatestRestorableTime','ReadyDateTime',
  'ClusterCreateTime',
  '_subscriptionId','_accountId','_accountLabel','_sourceFile','_vnetId','_vpcId'
]);

const _DIFF_STRUCTURAL=new Set([
  'addressPrefix','addressSpace','location','vmSize','version','sku',
  'vnetId','subnetId','destinationPortRange','sourceAddressPrefix',
  'destinationAddressPrefix','access','direction','priority','protocol',
  'zones','kubernetesVersion','replicasPerMaster','diskSizeGB','tier',
  'CidrBlock','AvailabilityZone','InstanceType','Engine','EngineVersion',
  'VpcId','SubnetId','FromPort','ToPort','IpProtocol','CidrIp',
  'Port','DBInstanceClass','NodeType','Runtime','MemorySize','Timeout',
  'CacheNodeType','ClusterType','NumberOfNodes','Scheme','Type'
]);

function normalizeResource(resource){
  const clone=structuredClone(resource);
  const active=new WeakSet();
  function walk(obj){
    if(!obj||typeof obj!=='object') return obj;
    if(Array.isArray(obj)){
      const mapped=obj.map(walk).filter(x=>x!==undefined);
      const ser=mapped.map(x=>JSON.stringify(x));
      const idx=ser.map((_,i)=>i);
      idx.sort((a,b)=>ser[a].localeCompare(ser[b]));
      return idx.map(i=>mapped[i]);
    }
    if(active.has(obj)) return undefined;
    active.add(obj);
    const out={};
    Object.keys(obj).sort().forEach(k=>{
      if(_DIFF_VOLATILE.has(k)) return;
      if(k==='properties'&&obj[k]===obj) return;
      var value=walk(obj[k]);
      if(value!==undefined) out[k]=value;
    });
    active.delete(obj);
    return out;
  }
  return walk(clone);
}

function normalizeNSG(nsg){
  const clone=structuredClone(nsg);
  function sortRules(rules){
    if(!Array.isArray(rules)) return rules;
    return rules.slice().sort(function(a,b){
      var ap=a.properties||a;
      var bp=b.properties||b;
      var left=(ap.direction||'')+'-'+(ap.priority||0)+'-'+(ap.name||a.name||'');
      var right=(bp.direction||'')+'-'+(bp.priority||0)+'-'+(bp.name||b.name||'');
      return left.localeCompare(right);
    });
  }
  function sortPerms(perms){
    if(!Array.isArray(perms)) return perms;
    return perms.map(function(p){
      const np={...p};
      if(np.IpRanges) np.IpRanges=[...np.IpRanges].sort((a,b)=>(a.CidrIp||'').localeCompare(b.CidrIp||''));
      if(np.Ipv6Ranges) np.Ipv6Ranges=[...np.Ipv6Ranges].sort((a,b)=>(a.CidrIpv6||'').localeCompare(b.CidrIpv6||''));
      if(np.UserIdGroupPairs) np.UserIdGroupPairs=[...np.UserIdGroupPairs].sort((a,b)=>(a.GroupId||'').localeCompare(b.GroupId||''));
      if(np.PrefixListIds) np.PrefixListIds=[...np.PrefixListIds].sort((a,b)=>(a.PrefixListId||'').localeCompare(b.PrefixListId||''));
      return np;
    }).sort((a,b)=>{
      const ak=(a.FromPort||0)+'-'+(a.ToPort||0)+'-'+(a.IpProtocol||'');
      const bk=(b.FromPort||0)+'-'+(b.ToPort||0)+'-'+(b.IpProtocol||'');
      return ak.localeCompare(bk);
    });
  }
  if(clone.properties&&clone.properties.securityRules) clone.properties.securityRules=sortRules(clone.properties.securityRules);
  if(clone.properties&&clone.properties.defaultSecurityRules) clone.properties.defaultSecurityRules=sortRules(clone.properties.defaultSecurityRules);
  if(clone.securityRules) clone.securityRules=sortRules(clone.securityRules);
  if(clone.defaultSecurityRules) clone.defaultSecurityRules=sortRules(clone.defaultSecurityRules);
  if(clone.IpPermissions) clone.IpPermissions=sortPerms(clone.IpPermissions);
  if(clone.IpPermissionsEgress) clone.IpPermissionsEgress=sortPerms(clone.IpPermissionsEgress);
  return normalizeResource(clone);
}

function classifyChange(field){
  if(_DIFF_STRUCTURAL.has(field)) return 'structural';
  if(field==='tags'||field==='name'||field==='description'||field==='Tags'||field==='TagSet'||field==='Name'||field==='Description') return 'metadata';
  return 'structural';
}

function _diffResourceKey(type,resource,primaryKey){
  if(!resource) return '';
  var keys=_DIFF_KEY_FALLBACKS[type]||[primaryKey];
  for(var i=0;i<keys.length;i++){
    var value=resource[keys[i]];
    if(value) return value;
  }
  return '';
}

const _diffStrCache=new WeakMap();

function _diffStr(obj){
  if(obj===null||typeof obj!=='object') return JSON.stringify(obj);
  if(_diffStrCache.has(obj)) return _diffStrCache.get(obj);
  var s=JSON.stringify(obj);
  _diffStrCache.set(obj,s);
  return s;
}

function _fieldDiff(normA,normB,path){
  const changes=[];
  if(normA===normB) return changes;
  if(typeof normA!==typeof normB||normA===null||normB===null||typeof normA!=='object'){
    changes.push({field:path,old:normA,new:normB,kind:classifyChange(path.split('.').pop())});
    return changes;
  }
  if(Array.isArray(normA)&&Array.isArray(normB)){
    if(_diffStr(normA)!==_diffStr(normB)) changes.push({field:path,old:normA,new:normB,kind:classifyChange(path.split('.').pop())});
    return changes;
  }
  const allKeys=new Set([...Object.keys(normA),...Object.keys(normB)]);
  allKeys.forEach(k=>{
    const sub=path?path+'.'+k:k;
    if(!(k in normA)){changes.push({field:sub,old:undefined,new:normB[k],kind:classifyChange(k)});return}
    if(!(k in normB)){changes.push({field:sub,old:normA[k],new:undefined,kind:classifyChange(k)});return}
    if(_diffStr(normA[k])!==_diffStr(normB[k])){
      if(typeof normA[k]==='object'&&typeof normB[k]==='object'&&normA[k]&&normB[k]){
        changes.push(..._fieldDiff(normA[k],normB[k],sub));
      } else {
        changes.push({field:sub,old:normA[k],new:normB[k],kind:classifyChange(k)});
      }
    }
  });
  return changes;
}

function computeDiff(baseline,current){
  const results={added:[],removed:[],modified:[],unchanged:[],total:{added:0,removed:0,modified:0,unchanged:0}};
  Object.entries(_DIFF_KEYS).forEach(([type,pk])=>{
    const bArr=baseline[type]||[];
    const cArr=current[type]||[];
    const bMap=new Map();
    const cMap=new Map();
    bArr.forEach(r=>{const key=_diffResourceKey(type,r,pk);if(key) bMap.set(key,r)});
    cArr.forEach(r=>{const key=_diffResourceKey(type,r,pk);if(key) cMap.set(key,r)});
    cMap.forEach((res,key)=>{
      if(!bMap.has(key)){
        results.added.push({type,key,name:_diffResName(res,key),resource:res});
        results.total.added++;
      }
    });
    bMap.forEach((res,key)=>{
      if(!cMap.has(key)){
        results.removed.push({type,key,name:_diffResName(res,key),resource:res});
        results.total.removed++;
      }
    });
    bMap.forEach((bRes,key)=>{
      if(!cMap.has(key)) return;
      const cRes=cMap.get(key);
      const normB=type==='nsgs'?normalizeNSG(bRes):normalizeResource(bRes);
      const normC=type==='nsgs'?normalizeNSG(cRes):normalizeResource(cRes);
      const sB=JSON.stringify(normB);
      const sC=JSON.stringify(normC);
      if(sB===sC){
        results.unchanged.push({type,key,name:_diffResName(cRes,key),resource:cRes});
        results.total.unchanged++;
        return;
      }
      const fields=_fieldDiff(normB,normC,'');
      if(fields.length===0){
        results.unchanged.push({type,key,name:_diffResName(cRes,key),resource:cRes});
        results.total.unchanged++;
        return;
      }
      results.modified.push({
        type,key,name:_diffResName(cRes,key),fields,
        hasStructural:fields.some(f=>f.kind==='structural'),
        resource:cRes,baseline:bRes
      });
      results.total.modified++;
    });
  });
  return results;
}

function _diffResName(res,fallback){
  if(!res) return fallback;
  if(res.name) return res.name;
  const tags=res.Tags||res.TagSet||[];
  const nt=tags.find(t=>t.Key==='Name');
  if(nt&&nt.Value) return nt.Value;
  return res.DBInstanceIdentifier||res.FunctionName||res.serviceName||res.CacheClusterId||res.ClusterIdentifier||res.id||fallback;
}

function diffRuntimeNormalizer(){
  var modules = typeof AppModules !== 'undefined' ? AppModules : null;
  if(modules&&typeof modules._normalizeAzureResources==='function') return modules._normalizeAzureResources;
  var normalizer = typeof _normalizeAzureResources !== 'undefined' ? _normalizeAzureResources : null;
  return typeof normalizer==='function' ? normalizer : null;
}

function diffComparableData(data){
  data=data||{};
  return {
    vnets:data.vnets||data.vpcs||[],
    subnets:data.subnets||[],
    vms:data.vms||data.instances||[],
    nsgs:data.nsgs||data.sgs||[],
    udrs:data.udrs||data.rts||[],
    natGateways:data.natGateways||data.nats||[],
    privateEndpoints:data.privateEndpoints||data.vpces||[],
    appGateways:data.appGateways||data.albs||[],
    sqlServers:data.sqlServers||data.rdsInstances||[],
    functionApps:data.functionApps||data.lambdaFns||[],
    containerInstances:data.containerInstances||data.ecsServices||[],
    redisCaches:data.redisCaches||data.ecacheClusters||[],
    synapseWorkspaces:data.synapseWorkspaces||[],
    peerings:data.peerings||[],
    storageAccounts:data.storageAccounts||data.s3bk||[],
    aksCluster:data.aksCluster||data.redshiftClusters||data.synapseWorkspaces||[],
    firewalls:data.firewalls||data.igws||[],
    bastions:data.bastions||[],
    loadBalancers:data.loadBalancers||data.tgs||[]
  };
}

function diffNormalizeSnapshot(data){
  var normalized=diffComparableData(data);
  var normalize=diffRuntimeNormalizer();
  if(normalize){
    normalize({
      vpcs:normalized.vnets,subnets:normalized.subnets,rts:normalized.udrs,sgs:normalized.nsgs,
      enis:[],nats:normalized.natGateways,vpces:normalized.privateEndpoints,instances:normalized.vms,
      albs:normalized.appGateways,tgs:normalized.loadBalancers,peerings:normalized.peerings,vpns:[],
      volumes:[],snapshots:[],s3bk:normalized.storageAccounts,zones:[],wafAcls:[],
      rdsInstances:normalized.sqlServers,ecsServices:normalized.containerInstances,
      lambdaFns:normalized.functionApps,ecacheClusters:normalized.redisCaches,
      redshiftClusters:normalized.aksCluster,tgwAttachments:[],cfDistributions:[]
    });
  }
  return normalized;
}

function _buildCtxFromTextareas(textareas){
  function parseTextarea(id){
    const raw=textareas[id];
    if(!raw) return [];
    const parsed=typeof raw==='string'?JSON.parse(raw):raw;
    if(Array.isArray(parsed)) return parsed;
    if(parsed&&Array.isArray(parsed.value)) return parsed.value;
    return [];
  }

  function parseFirstPresent(type){
    var ids=_DIFF_TEXTAREA_IDS[type]||[];
    for(var i=0;i<ids.length;i++){
      var id=ids[i];
      if(!Object.prototype.hasOwnProperty.call(textareas,id)) continue;
      if(!textareas[id]) continue;
      return parseTextarea(id);
    }
    return [];
  }

  var ctx={};
  Object.keys(_DIFF_TEXTAREA_IDS).forEach(function(type){
    ctx[type]=parseFirstPresent(type);
  });
  return ctx;
}
