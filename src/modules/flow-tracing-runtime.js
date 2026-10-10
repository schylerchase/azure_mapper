// #region FLOW TRACING
// === TRAFFIC FLOW VISUALIZATION ===
let _flowMode=false;
let _flowSource=null;
let _flowTarget=null;
let _flowConfig={protocol:'tcp',port:443};
let _flowPath=null;
let _flowBlocked=null;
let _flowStepIndex=-1;
let _flowSelecting=null;
// Multi-hop waypoint state
let _flowWaypoints=[];       // [{ref:{type,id}, config:{protocol,port}}]
let _flowLegs=[];            // [{source,target,config,result:{path,blocked}}]
let _flowActiveLeg=-1;       // which leg is expanded in detail, -1=all
let _flowSelectingWaypoint=-1; // insert position for new waypoint
let _flowSuggestions=[];     // [{via:{type,id,name}, leg1Result, leg2Result, leg1Config}]

function flowRuntimeContext(){
  var contextFactory = typeof AppRenderContext !== 'undefined' ? AppRenderContext : null;
  return contextFactory ? contextFactory.createRenderContext() : null;
}
function flowRuntimeData(){
  var ctx = flowRuntimeContext();
  return ctx ? flowResourceContext(ctx.rlCtx) : null;
}
function flowResourceContext(ctx){
  if(!ctx)return ctx;
  return {...ctx,vpcs:ctx.vnets||ctx.vpcs||[],instances:ctx.vms||ctx.instances||[],sgs:ctx.nsgs||ctx.sgs||[],nacls:ctx.subnetNsgs||ctx.nacls||[],igws:ctx.firewalls||ctx.igws||[],nats:ctx.natGateways||ctx.nats||[],rdsInstances:ctx.sqlServers||ctx.rdsInstances||[],lambdaFns:ctx.functionApps||ctx.lambdaFns||[],ecsServices:ctx.containerInstances||ctx.ecsServices||[],ecacheClusters:ctx.redisCaches||ctx.ecacheClusters||[],redshiftClusters:ctx.synapseWorkspaces||ctx.redshiftClusters||[]};
}

function flowNotify(message, type){
  var notifications = typeof AppNotifications !== 'undefined' ? AppNotifications : null;
  if(notifications && typeof notifications.show === 'function') notifications.show(message, type);
}
function flowSecurityGroup(ctx, groupId){
  if(!ctx||!groupId) return null;
  return (ctx.nsgs||ctx.sgs||[]).find(function(sg){return String(sg.GroupId||sg.id).toLowerCase()===String(groupId).toLowerCase()})||null;
}
function flowSubnetNsg(ctx,subnetId){
  var subnet=(ctx.subnets||[]).find(function(s){return String(s.SubnetId||s.id).toLowerCase()===String(subnetId).toLowerCase()});
  var properties=subnet&&(subnet.properties||subnet)||{};
  var id=(properties.networkSecurityGroup||{}).id;return id?(flowSecurityGroup(ctx,id)||{GroupId:id,_missing:true}):null;
}
function flowSecurityGroups(ctx, ids){
  return (ids||[]).map(function(groupId){return flowSecurityGroup(ctx, groupId)||{GroupId:groupId,_missing:true}});
}
function _suggestPort(targetType, targetResource){
  if(targetType==='rds') return (targetResource&&targetResource.Endpoint&&targetResource.Endpoint.Port)||3306;
  if(targetType==='ecache') return 6379;
  if(targetType==='alb') return 443;
  if(targetType==='instance') return 22;
  if(targetType==='lambda') return 443;
  if(targetType==='ecs') return 443;
  return 443;
}

function _cidrContains(cidr, ip){
  if(!cidr||!ip) return false;
  if(cidr==='0.0.0.0/0') return true;
  const parts=cidr.split('/');
  if(parts.length!==2) return false;
  const mask=parseInt(parts[1],10);
  const cidrNum=_ipToNum(parts[0]);
  const ipNum=_ipToNum(ip);
  if(cidrNum===null||ipNum===null) return false;
  const shift=32-mask;
  return (cidrNum>>>shift)===(ipNum>>>shift);
}

function _ipToNum(ip){
  if(!ip) return null;
  const p=ip.split('.');
  if(p.length!==4) return null;
  return ((parseInt(p[0],10)<<24)|(parseInt(p[1],10)<<16)|(parseInt(p[2],10)<<8)|parseInt(p[3],10))>>>0;
}

function _ipFromCidr(cidr){
  if(!cidr) return null;
  return cidr.split('/')[0];
}

function _protoMatch(ruleProto, queryProto){
  if(ruleProto==='-1'||ruleProto==='all'||ruleProto==='*') return true;
  const rp=String(ruleProto).toLowerCase();
  const qp=String(queryProto).toLowerCase();
  if(rp===qp) return true;
  if(rp==='6'&&qp==='tcp') return true;
  if(rp==='17'&&qp==='udp') return true;
  if(rp==='1'&&qp==='icmp') return true;
  if(qp==='6'&&rp==='tcp') return true;
  if(qp==='17'&&rp==='udp') return true;
  return false;
}
function _portInRange(port, from, to){
  if(from===undefined&&to===undefined) return true;
  if(from===0&&to===65535) return true;
  if(from===-1&&to===-1) return true;
  const p=parseInt(port,10);
  return p>=parseInt(from,10)&&p<=parseInt(to,10);
}
function evaluateRouteTable(rt, destCidr, systemPrefixes){
  if(!rt||!rt.Routes) return {target:'local',type:'local'};
  const dest=_ipFromCidr(destCidr)||destCidr;
  let bestMatch=null;
  let bestMask=-1;
  // A UDR table supplements Azure's VNet routes; equal-prefix UDRs take priority.
  var routes=rt.Routes.concat((systemPrefixes||[]).map(prefix=>({DestinationCidrBlock:prefix,GatewayId:'VnetLocal'})));
  routes.forEach(function(r){
    const rCidr=r.DestinationCidrBlock||r.DestinationIpv6CidrBlock;
    if(!rCidr) return;
    const mask=parseInt(rCidr.split('/')[1],10)||0;
    if(_cidrContains(rCidr, dest)&&mask>bestMask){
      bestMask=mask;
      bestMatch=r;
    }
  });
  if(!bestMatch) return {target:'blackhole',type:'blackhole',detail:'No matching route'};
  if(bestMatch.State==='blackhole') return {target:'blackhole',type:'blackhole',detail:'Route is blackholed'};
  if(bestMatch.GatewayId&&_isIgwRoute(bestMatch.GatewayId)) return {target:bestMatch.GatewayId,type:'igw'};
  if(bestMatch.NatGatewayId) return {target:bestMatch.NatGatewayId,type:'nat'};
  if(bestMatch.VpcPeeringConnectionId) return {target:bestMatch.VpcPeeringConnectionId,type:'pcx'};
  if(bestMatch.TransitGatewayId) return {target:bestMatch.TransitGatewayId,type:'tgw'};
  if(bestMatch.GatewayId==='local'||bestMatch.GatewayId==='VnetLocal') return {target:'local',type:'local'};
  if(bestMatch.GatewayId==='None') return {target:'blackhole',type:'blackhole',detail:'Route next hop is None'};
  if(bestMatch.VpcEndpointId) return {target:bestMatch.VpcEndpointId,type:'vpce'};
  if(bestMatch.GatewayId&&bestMatch.GatewayId.startsWith('vgw-')) return {target:bestMatch.GatewayId,type:'vgw'};
  return {target:'local',type:'local'};
}
function evaluateNACL(nacl, direction, protocol, port, sourceCidr, opts){
  if(!nacl||!nacl.Entries) return {action:'allow',rule:'Default allow (no NACL)',ruleNum:'-'};
  const entries=(nacl.Entries||[])
    .filter(function(e){return e.Egress===(direction==='outbound')})
    .sort(function(a,b){return a.RuleNumber-b.RuleNumber});
  // Discovery mode: if no entries for this direction, assume allow (missing data)
  if(entries.length===0&&opts&&opts.assumeAllow) return {action:'allow',rule:'No '+direction+' rules defined (assumed allow)',ruleNum:'-'};
  for(let i=0;i<entries.length;i++){
    var e=entries[i];
    if(e.RuleNumber===32767) continue;
    var protoOk=_protoMatch(e.Protocol, protocol);
    if(!protoOk) continue;
    var portOk=true;
    if(e.PortRange){
      portOk=_portInRange(port, e.PortRange.From, e.PortRange.To);
    }
    if(!portOk) continue;
    var cidrOk=false;
    if(e.CidrBlock) cidrOk=_cidrContains(e.CidrBlock, _ipFromCidr(sourceCidr));
    if(!cidrOk&&e.Ipv6CidrBlock){
      // IPv6 rules: match ::/0 as catch-all, skip others for IPv4 traffic
      if(e.Ipv6CidrBlock==='::/0') cidrOk=true;
      else continue;
    }
    if(!cidrOk) continue;
    var act=e.RuleAction==='allow'?'allow':'deny';
    var cidrLabel=e.CidrBlock||e.Ipv6CidrBlock||'';
    return {action:act,rule:'Rule #'+e.RuleNumber+' '+act.toUpperCase()+' '+_protoName(e.Protocol)+' port '+(e.PortRange?e.PortRange.From+'-'+e.PortRange.To:'all')+' from '+cidrLabel,ruleNum:e.RuleNumber};
  }
  return {action:'deny',rule:'Default deny (no matching rule)',ruleNum:'*'};
}

function _protoName(p){
  if(p==='-1'||p==='all') return 'ALL';
  if(p==='6') return 'TCP';
  if(p==='17') return 'UDP';
  if(p==='1') return 'ICMP';
  return String(p).toUpperCase();
}

function evaluateSG(sgs, direction, protocol, port, sourceCidr, opts){
  if(!sgs||sgs.length===0) return {action:'allow',rule:'No NSG attached (no NSG filtering)',matchedSg:null};
  var nativeResult=null;
  for(let si=0;si<sgs.length;si++){
    var sg=sgs[si];
    if(sg._missing)return {action:'deny',rule:'NSG data unavailable; unable to assess '+sg.GroupId,matchedSg:sg.GroupId};
    var properties=sg.properties||sg;
    var nativeRules=properties.securityRules;
    if(!nativeRules){
      var converted=[].concat(sg.IpPermissions||[],sg.IpPermissionsEgress||[]).filter(function(r){return r._azRule}).map(function(r){return r._azRule});
      if(converted.length)nativeRules=converted;
    }
    if(nativeRules){
      var peer=_ipFromCidr(sourceCidr)||sourceCidr||'*';
      var sourceAddress=opts&&opts.sourceAddress||(direction==='inbound'?peer:'*');
      var destinationAddress=opts&&opts.destinationAddress||(direction==='outbound'?peer:'*');
      var result=evaluateNsgRules({securityRules:nativeRules,defaultSecurityRules:properties.defaultSecurityRules},direction,protocol,sourceAddress,opts&&opts.sourcePort!==undefined?opts.sourcePort:'*',destinationAddress,port,opts);
      var action=String(result.action).toLowerCase();
      nativeResult={action:action,rule:(sg.GroupName||sg.name||sg.id)+': '+result.rule.name+' (priority '+result.priority+', '+action.toUpperCase()+')'+(result.sourcePortRequired?' — policy varies by source port; enter a source port to resolve':''),matchedSg:sg.GroupId||sg.id||sg.GroupName};
      // Azure NSGs attached at different levels must each permit the traffic.
      if(action==='deny')return nativeResult;
      continue;
    }
    var rules=direction==='inbound'?(sg.IpPermissions||[]):(sg.IpPermissionsEgress||[]);
    for(let ri=0;ri<rules.length;ri++){
      var r=rules[ri];
      var protoOk=_protoMatch(String(r.IpProtocol), protocol);
      if(!protoOk) continue;
      var portOk=true;
      if(r.FromPort!==undefined&&r.FromPort!==-1){
        portOk=_portInRange(port, r.FromPort, r.ToPort);
      }
      if(!portOk) continue;
      var cidrOk=false;
      (r.IpRanges||[]).forEach(function(ipr){
        if(_cidrContains(ipr.CidrIp, _ipFromCidr(sourceCidr))) cidrOk=true;
      });
      (r.Ipv6Ranges||[]).forEach(function(ipr){
        if(ipr.CidrIpv6==='::/0') cidrOk=true;
      });
      // SG-to-SG references: validate source SG IDs if provided, else assume allow
      if(!cidrOk&&(r.UserIdGroupPairs||[]).length>0){
        var srcSgIds=opts&&opts.sourceSgIds;
        if(srcSgIds){(r.UserIdGroupPairs||[]).forEach(function(gp){if(gp.GroupId&&srcSgIds.indexOf(gp.GroupId)!==-1)cidrOk=true})}
        else{(r.UserIdGroupPairs||[]).forEach(function(gp){if(gp.GroupId)cidrOk=true})}
      }
      if(cidrOk){
        var desc=sg.GroupName+': '+_protoName(String(r.IpProtocol))+' port '+(r.FromPort!==-1&&r.FromPort!==undefined?r.FromPort+'-'+r.ToPort:'all');
        return {action:'allow',rule:desc,matchedSg:sg.GroupId||sg.GroupName};
      }
    }
  }
  if(nativeResult)return nativeResult;
  return {action:'deny',rule:'No matching SG rule for '+protocol+'/'+port,matchedSg:null};
}
function _flowRuleOptions(ctx,source,target,opts){
  var prefixes=[];
  (ctx.vnets||ctx.vpcs||[]).forEach(function(v){if(v.VpcId===source.vpcId||v.VpcId===target.vpcId){var p=v.properties||v;prefixes=prefixes.concat((p.addressSpace||{}).addressPrefixes||[v.CidrBlock].filter(Boolean))}});
  return {assumeAllow:!!(opts&&opts.discovery),sourceAddress:source.ip||_ipFromCidr(source.cidr)||'*',destinationAddress:target.ip||_ipFromCidr(target.cidr)||'*',sourcePort:opts&&opts.sourcePort!==undefined?opts.sourcePort:'*',sourceAsgIds:source.asgIds||[],destinationAsgIds:target.asgIds||[],vnetPrefixes:prefixes};
}
function _resolveNetworkPosition(type, id, ctx){
  if(!ctx) return null;
  if(type==='internet') return {subnetId:null,vpcId:null,cidr:'0.0.0.0/0',sgs:[],name:'Internet',ip:'0.0.0.0'};
  if(type==='subnet'){
    var sub=(ctx.subnets||[]).find(function(s){return s.SubnetId===id});
    if(!sub) return null;
    var sgs2=[flowSubnetNsg(ctx,sub.SubnetId)].filter(Boolean);
    return {subnetId:sub.SubnetId,vpcId:sub.VpcId,cidr:sub.CidrBlock,sgs:sgs2,name:sub.Tags?((sub.Tags.find(function(t){return t.Key==='Name'})||{}).Value||sub.SubnetId):sub.SubnetId};
  }
  if(type==='instance'){
    var inst=null;
    Object.keys(ctx.instBySub||{}).forEach(function(sid){
      (ctx.instBySub[sid]||[]).forEach(function(i){
        if(i.InstanceId===id) inst=i;
      });
    });
    if(!inst) return null;
    var iSgs=(inst.SecurityGroups||[]).map(function(s){return s.GroupId});
    var fullSgs=flowSecurityGroups(ctx,iSgs);
    var subnetNsg=flowSubnetNsg(ctx,inst.SubnetId);
    if(subnetNsg&&!fullSgs.includes(subnetNsg))fullSgs.push(subnetNsg);
    return {subnetId:inst.SubnetId,vpcId:inst.VpcId||((ctx.subnets||[]).find(function(s){return s.SubnetId===inst.SubnetId})||{}).VpcId,cidr:inst.PrivateIpAddress?inst.PrivateIpAddress+'/32':null,sgs:fullSgs,name:inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId,ip:inst.PrivateIpAddress,nicId:inst._nicId,asgIds:inst._asgIds||[],hasPublicIp:inst.hasPublicIp||!!inst.PublicIpAddress||!!inst.publicIpAddress};
  }
  if(type==='rds'){
    var rds2=null;var rSid=null;
    Object.keys(ctx.rdsBySub||{}).forEach(function(sid){
      (ctx.rdsBySub[sid]||[]).forEach(function(d){
        if(d.DBInstanceIdentifier===id){rds2=d;rSid=sid}
      });
    });
    if(!rds2) return null;
    var rVpc=((ctx.subnets||[]).find(function(s){return s.SubnetId===rSid})||{}).VpcId;
    var rSgs2=flowSecurityGroups(ctx,(rds2.VpcSecurityGroups||[]).map(function(s){return s.VpcSecurityGroupId}));
    var rSubCidr=rSid?((ctx.subnets||[]).find(function(s){return s.SubnetId===rSid})||{}).CidrBlock:null;
    return {subnetId:rSid,vpcId:rVpc,cidr:rSubCidr,sgs:rSgs2,name:rds2.DBInstanceIdentifier};
  }
  if(type==='alb'){
    var alb2=null;var aSid=null;
    Object.keys(ctx.albBySub||{}).forEach(function(sid){
      (ctx.albBySub[sid]||[]).forEach(function(a){
        var aid=a.LoadBalancerArn?a.LoadBalancerArn.split('/').pop():'';
        if(aid===id||a.LoadBalancerName===id) {alb2=a;aSid=sid}
      });
    });
    if(!alb2) return null;
    var aVpc=((ctx.subnets||[]).find(function(s){return s.SubnetId===aSid})||{}).VpcId;
    var aSgs=flowSecurityGroups(ctx,alb2.SecurityGroups||[]);
    return {subnetId:aSid,vpcId:aVpc,cidr:null,sgs:aSgs,name:alb2.LoadBalancerName||id,hasPublicIp:alb2.Scheme==='internet-facing'||(alb2.frontendIPConfigurations||[]).some(f=>!!(f.properties||f).publicIPAddress?.id)};
  }
  if(type==='lambda'){
    var fn2=null;var fSid=null;
    Object.keys(ctx.lambdaBySub||{}).forEach(function(sid){
      (ctx.lambdaBySub[sid]||[]).forEach(function(f){
        if(f.FunctionName===id){fn2=f;fSid=sid}
      });
    });
    if(!fn2) return null;
    var fVpc=((ctx.subnets||[]).find(function(s){return s.SubnetId===fSid})||{}).VpcId;
    var fSgs2=flowSecurityGroups(ctx,(fn2.VpcConfig||{}).SecurityGroupIds||[]);
    return {subnetId:fSid,vpcId:fVpc,cidr:null,sgs:fSgs2,name:fn2.FunctionName};
  }
  if(type==='ecs'){
    var ecs2=null;var eSid=null;
    Object.keys(ctx.ecsBySub||{}).forEach(function(sid){
      (ctx.ecsBySub[sid]||[]).forEach(function(s){
        if(s.serviceName===id){ecs2=s;eSid=sid}
      });
    });
    if(!ecs2) return null;
    var eVpc=((ctx.subnets||[]).find(function(s){return s.SubnetId===eSid})||{}).VpcId;
    var eNc=(ecs2.networkConfiguration||{}).awsvpcConfiguration||{};
    var eSgs2=flowSecurityGroups(ctx,eNc.securityGroups||[]);
    return {subnetId:eSid,vpcId:eVpc,cidr:null,sgs:eSgs2,name:ecs2.serviceName||id};
  }
  if(type==='ecache'){
    var ec2=null;var ecVpc=null;
    (ctx.ecacheClusters||[]).forEach(function(c){if(c.CacheClusterId===id) ec2=c});
    if(!ec2) return null;
    // Find VPC from ecacheByVpc (can be Map or plain object)
    var ecMap=ctx.ecacheByVpc||{};
    var ecKeys=ecMap instanceof Map?Array.from(ecMap.keys()):Object.keys(ecMap);
    ecKeys.forEach(function(vid){var arr=ecMap instanceof Map?ecMap.get(vid):ecMap[vid];(arr||[]).forEach(function(c){if(c.CacheClusterId===id) ecVpc=vid})});
    // ElastiCache SGs stored as SecurityGroups array
    var ecSgs=flowSecurityGroups(ctx,(ec2.SecurityGroups||[]).map(function(s){return s.SecurityGroupId||s}));
    // Find subnet via VPC: pick first private subnet in that VPC
    var ecSid=null;
    if(ecVpc)(ctx.subnets||[]).forEach(function(s){if(!ecSid&&s.VpcId===ecVpc&&!(ctx.pubSubs&&ctx.pubSubs.has(s.SubnetId))) ecSid=s.SubnetId});
    if(!ecSid&&ecVpc)(ctx.subnets||[]).forEach(function(s){if(!ecSid&&s.VpcId===ecVpc) ecSid=s.SubnetId});
    var ecSubCidr=ecSid?((ctx.subnets||[]).find(function(s){return s.SubnetId===ecSid})||{}).CidrBlock:null;
    return {subnetId:ecSid,vpcId:ecVpc,cidr:ecSubCidr,sgs:ecSgs,name:ec2.CacheClusterId};
  }
  if(type==='redshift'){
    var rs2=null;var rsVpc=null;
    (ctx.redshiftClusters||[]).forEach(function(c){if(c.ClusterIdentifier===id) rs2=c});
    if(!rs2) return null;
    var rsMap=ctx.redshiftByVpc||{};
    var rsKeys=rsMap instanceof Map?Array.from(rsMap.keys()):Object.keys(rsMap);
    rsKeys.forEach(function(vid){var arr=rsMap instanceof Map?rsMap.get(vid):rsMap[vid];(arr||[]).forEach(function(c){if(c.ClusterIdentifier===id) rsVpc=vid})});
    var rsSgs=flowSecurityGroups(ctx,(rs2.VpcSecurityGroups||[]).map(function(s){return s.VpcSecurityGroupId||s}));
    var rsSid=null;
    if(rsVpc)(ctx.subnets||[]).forEach(function(s){if(!rsSid&&s.VpcId===rsVpc&&!(ctx.pubSubs&&ctx.pubSubs.has(s.SubnetId))) rsSid=s.SubnetId});
    if(!rsSid&&rsVpc)(ctx.subnets||[]).forEach(function(s){if(!rsSid&&s.VpcId===rsVpc) rsSid=s.SubnetId});
    var rsSubCidr=rsSid?((ctx.subnets||[]).find(function(s){return s.SubnetId===rsSid})||{}).CidrBlock:null;
    return {subnetId:rsSid,vpcId:rsVpc,cidr:rsSubCidr,sgs:rsSgs,name:rs2.ClusterIdentifier};
  }
  return null;
}

function _resolveClickTarget(el){
  var ctx=flowRuntimeData();
  if(!ctx) return null;
  // Internet globe node
  var inetNode=el.closest('.internet-node');
  if(inetNode) return {type:'internet',id:'internet'};
  var resNode=el.closest('.res-node');
  var subNode=el.closest('.subnet-node');
  var gwNode=el.closest('.gw-node')||el.closest('.lz-gw-node');
  if(resNode&&subNode){
    var subId=subNode.getAttribute('data-subnet-id');
    var resIdx=Array.from(subNode.querySelectorAll('.res-node')).indexOf(resNode);
    var tree=buildResTree(subId,ctx);
    if(tree&&tree[resIdx]){
      var res=tree[resIdx];
      if(res.type==='VM') return {type:'instance',id:res.rid||''};
      if(res.type==='ALB') return {type:'alb',id:res.rid||res.name};
      if(res.type==='RDS') return {type:'rds',id:res.rid||res.name};
      if(res.type==='FN') return {type:'lambda',id:res.rid||res.name};
      if(res.type==='ECS') return {type:'ecs',id:res.rid||res.name};
      if(res.type==='CACHE') return {type:'ecache',id:res.rid||res.name};
      if(res.type==='RS') return {type:'redshift',id:res.rid||res.name};
      if(res.type==='ENI') return {type:'subnet',id:subId};
    }
    return {type:'subnet',id:subId};
  }
  if(subNode){
    return {type:'subnet',id:subNode.getAttribute('data-subnet-id')};
  }
  return null;
}
// --- Internet to Resource trace (Azure model: Public IP + NSG, no IGW/NACL) ---
function _traceInternetToResource(target, config, ctx, opts){
  opts={...opts,sourcePort:opts&&opts.sourcePort!==undefined?opts.sourcePort:config.sourcePort??'*'};
  var path=[];var hopN=1;
  var tgtPos=_resolveNetworkPosition(target.type, target.id, ctx);
  if(!tgtPos) return {path:[{hop:1,type:'error',id:'-',action:'block',detail:'Cannot resolve target'}],blocked:{hop:1,reason:'Target not found'}};
  path.push({hop:hopN++,type:'source',id:'Internet',action:'allow',detail:'Source: Internet (0.0.0.0/0)'});
  // An Internet route supplies outbound routing, not an inbound public endpoint.
  var hasPublicIp=tgtPos.hasPublicIp||false;
  if(!hasPublicIp){
    path.push({hop:hopN++,type:'public-ip-check',id:'No Public IP',action:'block',detail:'Target has no modeled public endpoint'});
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Target in private subnet',subnetId:tgtPos.subnetId});
    return {path:path,blocked:{hop:hopN-2,reason:'Target is in a private subnet with no Public IP',suggestion:'Assign a Public IP or place behind an App Gateway/Load Balancer'}};
  }
  path.push({hop:hopN++,type:'public-ip-check',id:'Public IP',action:'allow',detail:'Resource has Public IP assigned'});
  if(target.type==='instance'&&!tgtPos.sgs.length)return {path:path,blocked:{hop:hopN-1,reason:'Public VM has no NSG permitting Internet ingress (secure by default)',suggestion:'Associate an NSG with an explicit inbound rule'}};
  // NSG inbound check (subnet-level NSG): replaces NACL in Azure
  var subNsg=flowSubnetNsg(ctx,tgtPos.subnetId);
  if(subNsg){
    var sgOpts1=_flowRuleOptions(ctx,_resolveNetworkPosition('internet','',ctx),tgtPos,opts);
    var nsgIn=evaluateSG([subNsg],'inbound',config.protocol,config.port,'0.0.0.0/0',sgOpts1);
    path.push({hop:hopN++,type:'sg-inbound',id:'Subnet NSG',action:nsgIn.action,detail:'Subnet NSG inbound from Internet',rule:nsgIn.rule});
    if(nsgIn.action==='deny'){
      path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by Subnet NSG',subnetId:tgtPos.subnetId});
      return {path:path,blocked:{hop:hopN-2,reason:'Subnet NSG denies inbound '+config.protocol+'/'+config.port,suggestion:'Add NSG inbound rule allowing '+config.protocol+'/'+config.port+' from 0.0.0.0/0'}};
    }
  }
  // NIC-level NSG check
  var sgOpts=_flowRuleOptions(ctx,_resolveNetworkPosition('internet','',ctx),tgtPos,opts);
  var sgIn=evaluateSG(tgtPos.sgs,'inbound',config.protocol,config.port,'0.0.0.0/0',sgOpts);
  path.push({hop:hopN++,type:'sg-inbound',id:'NIC NSG',action:sgIn.action,detail:'NIC NSG inbound from Internet',rule:sgIn.rule});
  if(sgIn.action==='deny'){
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by NIC NSG',subnetId:tgtPos.subnetId});
    return {path:path,blocked:{hop:hopN-2,reason:'NIC NSG denies inbound '+config.protocol+'/'+config.port+' from Internet',suggestion:'Add NSG inbound rule allowing '+config.protocol+'/'+config.port+' from 0.0.0.0/0'}};
  }
  path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'allow',detail:'Target: '+(tgtPos.name||target.id)+' ('+target.type+')',subnetId:tgtPos.subnetId});
  return {path:path,blocked:null};
}

// --- Resource to Internet trace (Azure model: NSG outbound + route table, no NACL) ---
function _traceResourceToInternet(source, config, ctx, opts){
  opts={...opts,sourcePort:opts&&opts.sourcePort!==undefined?opts.sourcePort:config.sourcePort??'*'};
  var path=[];var hopN=1;
  var srcPos=_resolveNetworkPosition(source.type, source.id, ctx);
  if(!srcPos) return {path:[{hop:1,type:'error',id:'-',action:'block',detail:'Cannot resolve source'}],blocked:{hop:1,reason:'Source not found'}};
  path.push({hop:hopN++,type:'source',id:srcPos.name||source.id,action:'allow',detail:'Source: '+(srcPos.name||source.id)+' ('+source.type+')',subnetId:srcPos.subnetId});
  // NIC NSG outbound check
  var sgOpts=_flowRuleOptions(ctx,srcPos,_resolveNetworkPosition('internet','',ctx),opts);
  var sgOut=evaluateSG(srcPos.sgs,'outbound',config.protocol,config.port,'0.0.0.0/0',sgOpts);
  path.push({hop:hopN++,type:'sg-outbound',id:'NIC NSG',action:sgOut.action,detail:'NIC NSG outbound to Internet',rule:sgOut.rule});
  if(sgOut.action==='deny'){
    path.push({hop:hopN++,type:'target',id:'Internet',action:'block',detail:'Blocked by NIC NSG'});
    return {path:path,blocked:{hop:2,reason:'NIC NSG denies outbound',suggestion:'Add NSG outbound rule allowing '+config.protocol+'/'+config.port+' to 0.0.0.0/0'}};
  }
  // Subnet NSG outbound check
  var subNsg=flowSubnetNsg(ctx,srcPos.subnetId);
  if(subNsg){
    var sgOpts2=sgOpts;
    var nsgOut=evaluateSG([subNsg],'outbound',config.protocol,config.port,'0.0.0.0/0',sgOpts2);
    path.push({hop:hopN++,type:'sg-outbound',id:'Subnet NSG',action:nsgOut.action,detail:'Subnet NSG outbound to Internet',rule:nsgOut.rule});
    if(nsgOut.action==='deny'){
      path.push({hop:hopN++,type:'target',id:'Internet',action:'block',detail:'Blocked by Subnet NSG'});
      return {path:path,blocked:{hop:hopN-2,reason:'Subnet NSG denies outbound',suggestion:'Add NSG outbound rule allowing '+config.protocol+'/'+config.port}};
    }
  }
  // Route table check: Internet or NAT route
  var srcRT=(ctx.subRT||{})[srcPos.subnetId];
  var hasInternetRoute=false;var hasNatRoute=false;var routeTarget='';
  if(srcRT&&srcRT.Routes){
    srcRT.Routes.forEach(function(r){
      if(r.DestinationCidrBlock!=='0.0.0.0/0')return;
      if(_isIgwRoute(r.GatewayId)){hasInternetRoute=true;routeTarget=_gwTypeLabel(r.GatewayId)}
      if(r.NatGatewayId||_isNatRoute(r.GatewayId)){hasNatRoute=true;routeTarget=r.NatGatewayId||_gwTypeLabel(r.GatewayId)}
    });
  }
  var sourceSubnet=(ctx.subnets||[]).find(s=>(s.SubnetId||s.id)===srcPos.subnetId);
  if((sourceSubnet&&(sourceSubnet.properties||sourceSubnet).defaultOutboundAccess===false)&&!hasNatRoute&&!hasExplicitOutbound(ctx,srcPos)){
    path.push({hop:hopN++,type:'route-table',id:'Private subnet',action:'block',detail:'Private subnet has no explicit outbound connectivity method'});
    return {path:path,blocked:{hop:hopN-1,reason:'Default outbound access is disabled; no public IP, NAT gateway or public load balancer outbound path',suggestion:'Configure an explicit outbound connectivity method'}};
  }
  // The system Internet route alone cannot supply SNAT for a private subnet.
  if(hasInternetRoute||hasNatRoute){
    path.push({hop:hopN++,type:'route-table',id:srcRT?(srcRT.RouteTableId||'UDR'):'Default route',action:'allow',detail:'Route to Internet via '+routeTarget,rule:'0.0.0.0/0 -> '+routeTarget});
  } else if(srcRT&&srcRT.Routes&&srcRT.Routes.some(function(r){return r.DestinationCidrBlock==='0.0.0.0/0'&&r.GatewayId==='None'})){
    path.push({hop:hopN++,type:'route-table',id:'Blackhole',action:'block',detail:'UDR has 0.0.0.0/0 -> None (blackhole route)'});
    path.push({hop:hopN++,type:'target',id:'Internet',action:'block',detail:'Internet route blackholed'});
    return {path:path,blocked:{hop:hopN-2,reason:'UDR blackholes internet traffic',suggestion:'Remove or modify the 0.0.0.0/0 -> None route'}};
  } else {
    // Azure default: implicit internet access via system route
    path.push({hop:hopN++,type:'route-table',id:'System route',action:'allow',detail:'Azure default system route to Internet (no UDR override)'});
  }
  path.push({hop:hopN++,type:'target',id:'Internet',action:'allow',detail:'Target: Internet (0.0.0.0/0)'});
  return {path:path,blocked:null};
}

function _traceFlowLeg(source, target, config, ctx, opts){
  if(source.type==='internet') return _traceInternetToResource(target, config, ctx, opts);
  if(target.type==='internet') return _traceResourceToInternet(source, config, ctx, opts);
  return traceFlow(source, target, config, ctx, opts);
}
function traceFlow(source, target, config, ctx, opts){
  opts={...opts,sourcePort:opts&&opts.sourcePort!==undefined?opts.sourcePort:config.sourcePort??'*'};
  var path=[];
  var srcPos=_resolveNetworkPosition(source.type, source.id, ctx);
  var tgtPos=_resolveNetworkPosition(target.type, target.id, ctx);
  var ruleOpts=srcPos&&tgtPos?_flowRuleOptions(ctx,srcPos,tgtPos,opts):{};
  if(!srcPos){return {path:[{hop:1,type:'error',id:'-',action:'block',detail:'Cannot resolve source position'}],blocked:{hop:1,reason:'Source not found'}}}
  if(!tgtPos){return {path:[{hop:1,type:'error',id:'-',action:'block',detail:'Cannot resolve target position'}],blocked:{hop:1,reason:'Target not found'}}}
  var hopN=1;
  var srcCidr=srcPos.ip||srcPos.cidr||((ctx.subnets||[]).find(function(s){return s.SubnetId===srcPos.subnetId})||{}).CidrBlock||'10.0.0.0/8';
  var tgtCidr=tgtPos.ip||tgtPos.cidr||((ctx.subnets||[]).find(function(s){return s.SubnetId===tgtPos.subnetId})||{}).CidrBlock||'10.0.0.0/8';
  path.push({hop:hopN++,type:'source',id:srcPos.name||source.id,action:'allow',detail:'Source: '+(srcPos.name||source.id)+' ('+source.type+') in subnet '+srcPos.subnetId,subnetId:srcPos.subnetId});
  var srcSgIds=srcPos.sgs.map(function(s){return s.GroupId}).filter(Boolean);
  var tgtSgIds=tgtPos.sgs.map(function(s){return s.GroupId}).filter(Boolean);
  if(srcPos.vpcId===tgtPos.vpcId){
    var srcRT=(ctx.subRT||{})[srcPos.subnetId];
    var rtResult=evaluateRouteTable(srcRT, tgtCidr, ruleOpts.vnetPrefixes);
    path.push({hop:hopN++,type:'route-table',id:srcRT?(srcRT.RouteTableId||'RT'):'Main RT',action:rtResult.type==='blackhole'?'block':'allow',detail:'Route table lookup for '+tgtCidr+' => '+rtResult.type+(rtResult.target!=='local'?' ('+rtResult.target+')':''),rule:'Route: '+rtResult.type+(rtResult.target!=='local'?' via '+rtResult.target:'')});
    if(rtResult.type==='blackhole'){
      path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Target unreachable',subnetId:tgtPos.subnetId});
      return {path:path,blocked:{hop:hopN-2,reason:'Route table has no route to destination',suggestion:'Add a route to '+tgtCidr+' in the source subnet route table'}};
    }
    var srcNacl=(ctx.subNacl||{})[srcPos.subnetId];
    var naclOut=evaluateNACL(srcNacl,'outbound',config.protocol,config.port,tgtCidr);
    path.push({hop:hopN++,type:'nacl-outbound',id:srcNacl?(srcNacl.NetworkAclId||'Subnet NSG'):'Default NACL',action:naclOut.action,detail:'Source subnet NACL outbound',rule:naclOut.rule});
    if(naclOut.action==='deny'){
      path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by NACL',subnetId:tgtPos.subnetId});
      return {path:path,blocked:{hop:hopN-2,reason:'Source NACL denies outbound traffic',suggestion:'Add NACL outbound rule allowing '+config.protocol+'/'+config.port}};
    }
    var sgOut2=evaluateSG(srcPos.sgs,'outbound',config.protocol,config.port,tgtCidr,{...ruleOpts,sourceSgIds:tgtSgIds});
    path.push({hop:hopN++,type:'sg-outbound',id:'Source SG',action:sgOut2.action,detail:'Source SG outbound',rule:sgOut2.rule});
    if(sgOut2.action==='deny'){
      path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by SG',subnetId:tgtPos.subnetId});
      return {path:path,blocked:{hop:hopN-2,reason:'Source security group denies outbound',suggestion:'Add SG outbound rule for '+config.protocol+'/'+config.port}};
    }
    var tgtNacl=(ctx.subNacl||{})[tgtPos.subnetId];
    var naclIn=evaluateNACL(tgtNacl,'inbound',config.protocol,config.port,srcCidr);
    path.push({hop:hopN++,type:'nacl-inbound',id:tgtNacl?(tgtNacl.NetworkAclId||'Subnet NSG'):'Default NACL',action:naclIn.action,detail:'Target subnet NACL inbound',rule:naclIn.rule});
    if(naclIn.action==='deny'){
      path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by NACL',subnetId:tgtPos.subnetId});
      return {path:path,blocked:{hop:hopN-2,reason:'Target NACL denies inbound traffic',suggestion:'Add NACL inbound rule allowing '+config.protocol+'/'+config.port+' from '+srcCidr}};
    }
    var sgIn2=evaluateSG(tgtPos.sgs,'inbound',config.protocol,config.port,srcCidr,{...ruleOpts,sourceSgIds:srcSgIds});
    path.push({hop:hopN++,type:'sg-inbound',id:'Target SG',action:sgIn2.action,detail:'Target SG inbound',rule:sgIn2.rule});
    if(sgIn2.action==='deny'){
      path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by SG',subnetId:tgtPos.subnetId});
      return {path:path,blocked:{hop:hopN-2,reason:'Target security group denies inbound',suggestion:'Add SG inbound rule for '+config.protocol+'/'+config.port+' from source'}};
    }
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'allow',detail:'Target: '+(tgtPos.name||target.id)+' ('+target.type+')',subnetId:tgtPos.subnetId});
    return {path:path,blocked:null};
  }
  // Cross-VPC: evaluate source-side controls first (NACL-out, SG-out, route table)
  var srcRTx=(ctx.subRT||{})[srcPos.subnetId];
  var rtResultX=evaluateRouteTable(srcRTx, tgtCidr, ruleOpts.vnetPrefixes);
  path.push({hop:hopN++,type:'route-table',id:srcRTx?(srcRTx.RouteTableId||'RT'):'Main RT',action:rtResultX.type==='blackhole'?'block':'allow',detail:'Route table lookup for '+tgtCidr+' => '+rtResultX.type+(rtResultX.target!=='local'?' ('+rtResultX.target+')':''),rule:'Route: '+rtResultX.type+(rtResultX.target!=='local'?' via '+rtResultX.target:'')});
  if(rtResultX.type==='blackhole'){
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Target unreachable',subnetId:tgtPos.subnetId});
    return {path:path,blocked:{hop:hopN-2,reason:'Route table has no route to destination',suggestion:'Add a route to '+tgtCidr+' via peering or TGW'}};
  }
  var srcNaclX=(ctx.subNacl||{})[srcPos.subnetId];
  var naclOutX=evaluateNACL(srcNaclX,'outbound',config.protocol,config.port,tgtCidr);
  path.push({hop:hopN++,type:'nacl-outbound',id:srcNaclX?(srcNaclX.NetworkAclId||'Subnet NSG'):'Default NACL',action:naclOutX.action,detail:'Source subnet NACL outbound',rule:naclOutX.rule});
  if(naclOutX.action==='deny'){
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by NACL',subnetId:tgtPos.subnetId});
    return {path:path,blocked:{hop:hopN-2,reason:'Source NACL denies outbound traffic',suggestion:'Add NACL outbound rule allowing '+config.protocol+'/'+config.port}};
  }
  var sgOutX=evaluateSG(srcPos.sgs,'outbound',config.protocol,config.port,tgtCidr,{...ruleOpts,sourceSgIds:tgtSgIds});
  path.push({hop:hopN++,type:'sg-outbound',id:'Source SG',action:sgOutX.action,detail:'Source SG outbound',rule:sgOutX.rule});
  if(sgOutX.action==='deny'){
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by SG',subnetId:tgtPos.subnetId});
    return {path:path,blocked:{hop:hopN-2,reason:'Source security group denies outbound',suggestion:'Add SG outbound rule for '+config.protocol+'/'+config.port}};
  }
  // Cross-VPC connectivity check (peering or TGW)
  var peeringRoute=null;
  (ctx.peerings||[]).forEach(function(p){
    var req=p.RequesterVpcInfo||{};
    var acc=p.AccepterVpcInfo||{};
    if((req.VpcId===srcPos.vpcId&&acc.VpcId===tgtPos.vpcId)||(acc.VpcId===srcPos.vpcId&&req.VpcId===tgtPos.vpcId)){
      if(!peeringRoute||req.VpcId===srcPos.vpcId)peeringRoute=p;
    }
  });
  if(peeringRoute){
    var peerState=String((peeringRoute.Status||{}).Code||peeringRoute.peeringState||'').toLowerCase();
    if(!['connected','active'].includes(peerState)||peeringRoute.allowVirtualNetworkAccess===false){
      var peerReason=peeringRoute.allowVirtualNetworkAccess===false?'VNet peering disables virtual network access':'VNet peering is not confirmed Connected';
      path.push({hop:hopN++,type:'peering',id:peeringRoute.VpcPeeringConnectionId||'PCX',action:'block',detail:peerReason});
      return {path:path,blocked:{hop:hopN-1,reason:peerReason,suggestion:'Confirm the peering is Connected with virtual network access enabled'}};
    }
    path.push({hop:hopN++,type:'peering',id:peeringRoute.VpcPeeringConnectionId||'PCX',action:'allow',detail:'VPC Peering connection between '+srcPos.vpcId+' and '+tgtPos.vpcId,rule:'Peering: '+peeringRoute.VpcPeeringConnectionId});
  } else {
    var tgwRoute=false;
    (ctx.tgwAttachments||[]).forEach(function(att){
      if(att.ResourceId===srcPos.vpcId||att.ResourceId===tgtPos.vpcId) tgwRoute=true;
    });
    if(tgwRoute){
      path.push({hop:hopN++,type:'tgw',id:'Transit Gateway',action:'allow',detail:'Transit Gateway route between VPCs'});
    } else {
      path.push({hop:hopN++,type:'cross-vpc',id:'No route',action:'block',detail:'No peering or TGW connection between VPCs'});
      path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Target unreachable',subnetId:tgtPos.subnetId});
      return {path:path,blocked:{hop:hopN-2,reason:'No connectivity between VPCs',suggestion:'Create a VPC peering connection or Transit Gateway attachment'}};
    }
  }
  // Target-side controls (NACL-in, SG-in)
  var tgtNaclX=(ctx.subNacl||{})[tgtPos.subnetId];
  var naclInX=evaluateNACL(tgtNaclX,'inbound',config.protocol,config.port,srcCidr);
  path.push({hop:hopN++,type:'nacl-inbound',id:tgtNaclX?(tgtNaclX.NetworkAclId||'Subnet NSG'):'Default NACL',action:naclInX.action,detail:'Target subnet NACL inbound',rule:naclInX.rule});
  if(naclInX.action==='deny'){
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by NACL',subnetId:tgtPos.subnetId});
    return {path:path,blocked:{hop:hopN-2,reason:'Target NACL denies inbound traffic',suggestion:'Add NACL inbound rule allowing '+config.protocol+'/'+config.port+' from '+srcCidr}};
  }
  var sgIn3=evaluateSG(tgtPos.sgs,'inbound',config.protocol,config.port,srcCidr,{...ruleOpts,sourceSgIds:srcSgIds});
  path.push({hop:hopN++,type:'sg-inbound',id:'Target SG',action:sgIn3.action,detail:'Target SG inbound (cross-VPC)',rule:sgIn3.rule});
  if(sgIn3.action==='deny'){
    path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'block',detail:'Blocked by SG',subnetId:tgtPos.subnetId});
    return {path:path,blocked:{hop:hopN-2,reason:'Target SG denies inbound from cross-VPC source',suggestion:'Add SG inbound rule for '+config.protocol+'/'+config.port}};
  }
  path.push({hop:hopN++,type:'target',id:tgtPos.name||target.id,action:'allow',detail:'Target: '+(tgtPos.name||target.id)+' ('+target.type+')',subnetId:tgtPos.subnetId});
  return {path:path,blocked:null};
}

function _flowBannerHTML(state,srcName,tgtName,info){return FlowTracingPanel.bannerHtml(state,srcName,tgtName,info)}
function enterFlowMode(presetSource){
  var ctx=flowRuntimeData();
  if(!ctx){flowNotify('Load a map first');return}
  if(document.getElementById('layoutMode').value==='executive') return;
  if(_flowMode) return;
  _flowMode=true;
  _flowSelecting=presetSource?'target':'source';
  _flowSource=presetSource||null;
  _flowTarget=null;
  _flowPath=null;
  _flowBlocked=null;
  _flowStepIndex=-1;
  _flowWaypoints=[];_flowLegs=[];_flowActiveLeg=-1;_flowSelectingWaypoint=-1;_flowSuggestions=[];
  var banner=document.getElementById('flowBanner');
  banner.style.display='flex';
  document.getElementById('flowStatus').textContent='';
  document.getElementById('flowStatus').className='flow-status';
  document.getElementById('flowStepBack').style.display='none';
  document.getElementById('flowStepFwd').style.display='none';
  var mainEl=_getMain();
  if(mainEl){mainEl.classList.add('flow-selecting');mainEl.classList.add('flow-active');}
  var _eb=document.querySelector('.export-bar');if(_eb) _eb.style.top='44px';
  var _mb=document.getElementById('mergeBanner');if(_mb&&_mb.style.display!=='none') _mb.style.display='none';
  var svg=document.getElementById('mapSvg');
  svg.addEventListener('click',_flowClickHandler,true);
  svg.addEventListener('contextmenu',_flowRightClickHandler,true);
  if(presetSource){
    var srcPos=_resolveNetworkPosition(presetSource.type, presetSource.id, ctx);
    var srcName=srcPos?srcPos.name:presetSource.id;
    document.getElementById('flowLabel').innerHTML=_flowBannerHTML(1,srcName);
    document.getElementById('flowSrcName')?.addEventListener('click',function(e){e.stopPropagation();_flowResetToSource();});
    _highlightFlowNode(presetSource,'source');
  } else {
    document.getElementById('flowLabel').innerHTML=_flowBannerHTML(0);
  }
}
function _flowResetToSource(){
  _flowSelecting='source';_flowSource=null;_clearFlowHighlights();_clearFlowOverlay();
  document.getElementById('flowLabel').innerHTML=_flowBannerHTML(0);
  var m=_getMain();if(m)m.classList.add('flow-selecting');
}
function _flowRightClickHandler(event){
  if(!_flowMode) return;
  if(_flowSelecting==='target'){event.preventDefault();_flowResetToSource();}
}

function exitFlowMode(){
  _flowMode=false;
  _flowSelecting=null;
  _flowSource=null;
  _flowTarget=null;
  _flowPath=null;
  _flowBlocked=null;
  _flowStepIndex=-1;
  _flowWaypoints=[];_flowLegs=[];_flowActiveLeg=-1;_flowSelectingWaypoint=-1;_flowSuggestions=[];
  if(typeof _cancelTracePick==='function') _cancelTracePick();
  var banner=document.getElementById('flowBanner');
  banner.style.display='none';
  var mainEl=_getMain();
  if(mainEl){mainEl.classList.remove('flow-selecting');mainEl.classList.remove('flow-active');}
  var _eb=document.querySelector('.export-bar');if(_eb) _eb.style.top='';
  if(_multiViewMode){var _mb=document.getElementById('mergeBanner');if(_mb) _mb.style.display='flex';}
  var svg=document.getElementById('mapSvg');
  svg.removeEventListener('click',_flowClickHandler,true);
  svg.removeEventListener('contextmenu',_flowRightClickHandler,true);
  _clearFlowOverlay();_clearFlowHighlights();
  var dp=document.getElementById('detailPanel');
  if(dp.classList.contains('open')){
    var dpBody=document.getElementById('dpBody');
    if(dpBody&&dpBody.querySelector('.flow-panel')) dp.classList.remove('open');
  }
}

function _flowClickHandler(event){
  if(!_flowMode||!_flowSelecting) return;
  var ctx=flowRuntimeData();
  if(!ctx) return;
  var target=_resolveClickTarget(event.target);
  if(!target) return;
  event.stopPropagation();
  event.preventDefault();
  if(_flowSelecting==='source'){
    _flowSource=target;
    _flowSelecting='target';
    _clearFlowHighlights();
    var srcPos=_resolveNetworkPosition(target.type, target.id, ctx);
    var srcName=srcPos?srcPos.name:target.id;
    document.getElementById('flowLabel').innerHTML=_flowBannerHTML(1,srcName);
    document.getElementById('flowSrcName')?.addEventListener('click',function(e){e.stopPropagation();_flowResetToSource();});
    _highlightFlowNode(target,'source');
    // If a preset target was set via right-click context menu, auto-fill it
    if(_flowCtxPresetTarget){
      var presetTgt=_flowCtxPresetTarget;
      _flowCtxPresetTarget=null;
      _flowTarget=presetTgt;
      _flowSelecting=null;
      var mainEl2=_getMain();
      if(mainEl2) mainEl2.classList.remove('flow-selecting');
      var tgtPos2=_resolveNetworkPosition(presetTgt.type, presetTgt.id, ctx);
      _flowConfig.port=_suggestPort(presetTgt.type, tgtPos2);
      _highlightFlowNode(presetTgt,'target');
      _executeTrace();
      return;
    }
  } else if(_flowSelecting==='target'){
    if(target.type===(_flowSource||{}).type&&target.id===(_flowSource||{}).id) return;
    _flowTarget=target;
    _flowSelecting=null;
    var mainEl=_getMain();
    if(mainEl) mainEl.classList.remove('flow-selecting');
    var tgtPos=_resolveNetworkPosition(target.type, target.id, ctx);
    var sugPort=_suggestPort(target.type, tgtPos);
    _flowConfig.port=sugPort;
    _highlightFlowNode(target,'target');
    _executeTrace();
  } else if(_flowSelecting==='waypoint'){
    // Prevent waypoint that equals source or target
    if((target.type===(_flowSource||{}).type&&target.id===(_flowSource||{}).id)||(target.type===(_flowTarget||{}).type&&target.id===(_flowTarget||{}).id)) return;
    // Prevent duplicate waypoints
    if(_flowWaypoints.some(function(wp){return wp.ref.type===target.type&&wp.ref.id===target.id})) return;
    // Insert waypoint into chain
    _flowSelecting=null;
    var mainEl2=_getMain();
    if(mainEl2) mainEl2.classList.remove('flow-selecting');
    var wpPos=_resolveNetworkPosition(target.type, target.id, ctx);
    var wpPort=_suggestPort(target.type, wpPos);
    var insertAt=_flowSelectingWaypoint>=0?_flowSelectingWaypoint:_flowWaypoints.length-1;
    _flowWaypoints.splice(insertAt,0,{ref:target,config:{protocol:'tcp',port:wpPort}});
    // Update the config of the prior waypoint to use the waypoint's suggested port
    _flowSelectingWaypoint=-1;
    _highlightFlowNode(target,'waypoint');
    _executeMultiTrace();
  }
}
function _clearFlowHighlights(){
  d3.select('#mapSvg').selectAll('.subnet-node rect, .res-node rect, .internet-node circle').each(function(){d3.select(this).style('filter',null)});
}

function _highlightFlowNode(ref, role){
  var svg=d3.select('#mapSvg');
  var color=role==='source'?'#22d3ee':role==='waypoint'?'#f59e0b':'#ef4444';
  if(ref.type==='internet'){
    svg.selectAll('.internet-node circle').each(function(){
      d3.select(this).style('filter','drop-shadow(0 0 10px '+color+')');
    });
    return;
  }
  if(ref.type==='subnet'){
    svg.selectAll('.subnet-node[data-subnet-id="'+ref.id+'"] rect').each(function(){
      d3.select(this).style('filter','drop-shadow(0 0 8px '+color+')');
    });
    return;
  }
  // Fallback: resolve resource to its containing subnet and highlight that
  var ctx=flowRuntimeData();
  var pos=ctx?_resolveNetworkPosition(ref.type, ref.id, ctx):null;
  if(pos&&pos.subnetId){
    svg.selectAll('.subnet-node[data-subnet-id="'+pos.subnetId+'"] rect').each(function(){
      d3.select(this).style('filter','drop-shadow(0 0 8px '+color+')');
    });
  }
}

function _executeTrace(){
  var ctx=flowRuntimeData();
  if(!_flowSource||!_flowTarget||!ctx) return;
  // Use _traceFlowLeg for internet support
  var result=_traceFlowLeg(_flowSource, _flowTarget, _flowConfig, ctx);
  _flowPath=result.path;
  _flowBlocked=result.blocked;
  _flowStepIndex=-1;
  _flowSuggestions=[];
  // If blocked, find alternate paths via intermediaries
  if(_flowBlocked) _flowSuggestions=_findAlternatePaths(_flowSource,_flowTarget,_flowConfig,ctx);
  var srcPos=_resolveNetworkPosition(_flowSource.type, _flowSource.id, ctx);
  var tgtPos=_resolveNetworkPosition(_flowTarget.type, _flowTarget.id, ctx);
  var srcName=srcPos?srcPos.name:_flowSource.id;
  var tgtName=tgtPos?tgtPos.name:_flowTarget.id;
  document.getElementById('flowLabel').innerHTML=_flowBannerHTML(3,srcName,tgtName,_flowConfig.protocol.toUpperCase()+'/'+_flowConfig.port+' · '+_flowPath.length+' hops');
  var statusEl=document.getElementById('flowStatus');
  if(_flowBlocked){
    statusEl.textContent='BLOCKED';
    statusEl.className='flow-status blocked';
  } else {
    statusEl.textContent='ALLOWED';
    statusEl.className='flow-status allowed';
  }
  document.getElementById('flowStepBack').style.display='';
  document.getElementById('flowStepFwd').style.display='';
  _renderFlowPath();
  _renderFlowDetail();
}

function _clearFlowOverlay(){
  var svg=d3.select('#mapSvg');
  svg.selectAll('.flow-overlay-g').remove();
  svg.selectAll('.subnet-node rect').style('filter',null);
}

function _renderFlowPath(){
  _clearFlowOverlay();
  if(!_flowPath||_flowPath.length<2) return;
  var g=d3.select('#mapSvg').select('g');
  if(g.empty()) g=d3.select('#mapSvg');
  var flowG=g.append('g').attr('class','flow-overlay-g');
  var coords=[];
  _flowPath.forEach(function(hop){
    var c=_getHopCoords(hop);
    if(c) coords.push({x:c.x,y:c.y,hop:hop});
  });
  if(coords.length<2) return;
  var line=d3.line().x(function(d){return d.x}).y(function(d){return d.y}).curve(d3.curveBasis);
  var isBlocked=!!_flowBlocked;
  flowG.append('path')
    .attr('class','flow-path'+(isBlocked?' blocked':''))
    .attr('d',line(coords));
  coords.forEach(function(c,i){
    if(_flowStepIndex!==-1&&i>_flowStepIndex) return;
    var isBlockedHop=c.hop.action==='block'||c.hop.action==='deny';
    var hopG=flowG.append('g').attr('class','flow-hop '+(isBlockedHop?'flow-hop-block':'flow-hop-allow'));
    hopG.append('circle').attr('cx',c.x).attr('cy',c.y).attr('r',10);
    hopG.append('text').attr('x',c.x).attr('y',c.y).text(i+1);
  });
}

function _getInternetCoords(){
  var inetEl=document.querySelector('.internet-node circle');
  if(!inetEl) return null;
  return {x:parseFloat(inetEl.getAttribute('cx'))||0,y:parseFloat(inetEl.getAttribute('cy'))||0};
}

function _getHopCoords(hop){
  var ctx=flowRuntimeData();
  // Internet node hops
  if(hop.type==='source'&&hop.id==='Internet') return _getInternetCoords();
  if(hop.type==='target'&&hop.id==='Internet') return _getInternetCoords();
  if(hop.type==='igw-check'){
    // Position between internet node and target subnet
    var ic=_getInternetCoords();
    var tPos=_flowTarget&&ctx?_resolveNetworkPosition(_flowTarget.type, _flowTarget.id, ctx):null;
    var tc=tPos?_getSubnetCenter(tPos.subnetId):null;
    if(ic&&tc) return {x:ic.x+(tc.x-ic.x)*0.35,y:ic.y+(tc.y-ic.y)*0.35};
    return ic;
  }
  var subId=hop.subnetId;
  if(!subId){
    if(hop.type==='route-table'||hop.type==='nacl-outbound'||hop.type==='sg-outbound'){
      var srcPos=_flowSource&&ctx?_resolveNetworkPosition(_flowSource.type, _flowSource.id, ctx):null;
      subId=srcPos?srcPos.subnetId:null;
    }
    if(hop.type==='nacl-inbound'||hop.type==='sg-inbound'){
      var tgtPos=_flowTarget&&ctx?_resolveNetworkPosition(_flowTarget.type, _flowTarget.id, ctx):null;
      subId=tgtPos?tgtPos.subnetId:null;
    }
  }
  if(subId){
    var subEl=document.querySelector('.subnet-node[data-subnet-id="'+subId+'"] rect');
    if(subEl){
      var x=parseFloat(subEl.getAttribute('x'))||0;
      var y=parseFloat(subEl.getAttribute('y'))||0;
      var w=parseFloat(subEl.getAttribute('width'))||100;
      var h=parseFloat(subEl.getAttribute('height'))||60;
      var offsetX=0;
      if(hop.type==='source') offsetX=-w*0.35;
      else if(hop.type==='target') offsetX=w*0.35;
      else if(hop.type==='route-table') offsetX=-w*0.2;
      else if(hop.type==='nacl-outbound') offsetX=-w*0.05;
      else if(hop.type==='sg-outbound') offsetX=w*0.08;
      else if(hop.type==='sg-inbound') offsetX=w*0.2;
      else if(hop.type==='nacl-inbound') offsetX=w*0.33;
      return {x:x+w/2+offsetX,y:y+h/2};
    }
  }
  if(hop.type==='peering'||hop.type==='tgw'||hop.type==='cross-vpc'){
    var srcPos2=ctx?_resolveNetworkPosition(_flowSource.type, _flowSource.id, ctx):null;
    var tgtPos2=ctx?_resolveNetworkPosition(_flowTarget.type, _flowTarget.id, ctx):null;
    var c1=_getSubnetCenter(srcPos2?srcPos2.subnetId:null);
    var c2=_getSubnetCenter(tgtPos2?tgtPos2.subnetId:null);
    if(c1&&c2) return {x:(c1.x+c2.x)/2,y:(c1.y+c2.y)/2-20};
  }
  return null;
}

function _getSubnetCenter(subId){
  if(!subId) return null;
  var subEl=document.querySelector('.subnet-node[data-subnet-id="'+subId+'"] rect');
  if(!subEl) return null;
  return {x:parseFloat(subEl.getAttribute('x'))+(parseFloat(subEl.getAttribute('width'))||100)/2,y:parseFloat(subEl.getAttribute('y'))+(parseFloat(subEl.getAttribute('height'))||60)/2};
}

function _renderFlowDetail(){
  if(!_flowPath) return;
  FlowTracingPanel.renderSingle({
    config: _flowConfig,
    path: _flowPath,
    blocked: _flowBlocked,
    suggestions: _flowSuggestions,
    stepIndex: _flowStepIndex
  }, {
    retrace: function(protocol, port, sourcePort){
      _flowConfig.protocol=protocol;
      _flowConfig.port=port;
      _flowConfig.sourcePort=sourcePort;
      _executeTrace();
    },
    quickPort: function(port){
      _flowConfig.protocol='tcp';
      _flowConfig.port=port;
      if(_flowWaypoints.length>0) _executeMultiTrace();
      else _executeTrace();
    },
    selectHop: function(index){
      _flowStepIndex=index;
      _renderFlowPath();
      _renderFlowDetail();
    },
    applySuggestion: _applySuggestion,
    addWaypoint: _addWaypoint
  });
}

function _stepForward(){
  if(!_flowPath||_flowPath.length===0) return;
  if(_flowStepIndex===-1) _flowStepIndex=0;
  else if(_flowStepIndex<_flowPath.length-1) _flowStepIndex++;
  _renderFlowPath();
  _renderFlowDetail();
}

function _stepBack(){
  if(!_flowPath||_flowPath.length===0) return;
  if(_flowStepIndex<=0) _flowStepIndex=-1;
  else _flowStepIndex--;
  _renderFlowPath();
  _renderFlowDetail();
}

// --- Auto-Suggestion: find alternate paths via intermediaries ---
function _findAlternatePaths(source, target, config, ctx){
  if(!ctx) return [];
  var tgtPos=_resolveNetworkPosition(target.type, target.id, ctx);
  if(!tgtPos) return [];
  var vpcId=tgtPos.vpcId;
  var results=[];
  // Collect candidates: instances + ALBs in the target VPC (or any VPC if source is internet)
  var candidates=[];
  var isInternet=source.type==='internet';
  // Public-subnet instances first (bastion pattern)
  (ctx.instances||[]).forEach(function(inst){
    var instVpc=inst.VpcId||((ctx.subnets||[]).find(function(s){return s.SubnetId===inst.SubnetId})||{}).VpcId;
    if(!isInternet&&instVpc!==vpcId) return;
    if(inst.InstanceId===(target.type==='instance'?target.id:'')) return;
    if(inst.InstanceId===(source.type==='instance'?source.id:'')) return;
    var isPub=ctx.pubSubs&&ctx.pubSubs.has(inst.SubnetId);
    var gn2=inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId;
    candidates.push({ref:{type:'instance',id:inst.InstanceId},name:gn2,isPub:isPub,defaultPort:22});
  });
  // ALBs
  Object.keys(ctx.albBySub||{}).forEach(function(sid){
    var sub=(ctx.subnets||[]).find(function(s){return s.SubnetId===sid});
    if(!sub||(!isInternet&&sub.VpcId!==vpcId)) return;
    (ctx.albBySub[sid]||[]).forEach(function(alb){
      var albId=alb.LoadBalancerArn?alb.LoadBalancerArn.split('/').pop():'';
      if(albId===(target.type==='alb'?target.id:'')) return;
      candidates.push({ref:{type:'alb',id:albId||alb.LoadBalancerName},name:alb.LoadBalancerName||albId,isPub:true,defaultPort:443});
    });
  });
  // Sort: public instances first, then ALBs, then private instances
  candidates.sort(function(a,b){return (b.isPub?1:0)-(a.isPub?1:0)});
  // Test each candidate (max 20)
  var tested=0;
  for(let i=0;i<candidates.length&&tested<20&&results.length<5;i++){
    var cand=candidates[i];
    tested++;
    var leg1Config={protocol:'tcp',port:cand.defaultPort};
    var leg1=_traceFlowLeg(source, cand.ref, leg1Config, ctx);
    if(leg1.blocked) continue;
    var leg2=_traceFlowLeg(cand.ref, target, config, ctx);
    if(leg2.blocked) continue;
    results.push({via:{type:cand.ref.type,id:cand.ref.id,name:cand.name},leg1Result:leg1,leg2Result:leg2,leg1Config:leg1Config});
  }
  return results;
}

function _applySuggestion(idx){
  if(!_flowSuggestions||!_flowSuggestions[idx]) return;
  var sug=_flowSuggestions[idx];
  // Build waypoint chain: source → via → target
  _flowWaypoints=[
    {ref:_flowSource,config:sug.leg1Config},
    {ref:sug.via,config:{protocol:_flowConfig.protocol,port:_flowConfig.port}},
    {ref:_flowTarget,config:null}
  ];
  _executeMultiTrace();
}

function _addWaypoint(){
  // Enter waypoint-selection mode: click a resource to insert as waypoint between source and target
  if(!_flowSource||!_flowTarget) return;
  // If no waypoints yet, initialize from current source/target
  if(_flowWaypoints.length===0){
    _flowWaypoints=[
      {ref:_flowSource,config:{protocol:_flowConfig.protocol,port:_flowConfig.port}},
      {ref:_flowTarget,config:null}
    ];
  }
  // Insert waypoint before the last node (target)
  _flowSelectingWaypoint=_flowWaypoints.length-1;
  _flowSelecting='waypoint';
  var mainEl=_getMain();
  if(mainEl) mainEl.classList.add('flow-selecting');
  document.getElementById('flowLabel').textContent='MULTI-HOP: Click a waypoint resource to insert';
}

function _removeWaypoint(idx){
  if(idx<=0||idx>=_flowWaypoints.length-1) return; // can't remove source or target
  _flowWaypoints.splice(idx,1);
  if(_flowWaypoints.length<=2){
    // Back to single-hop mode
    _flowWaypoints=[];
    _flowLegs=[];
    _flowActiveLeg=-1;
    _executeTrace();
  } else {
    _executeMultiTrace();
  }
}

function _executeMultiTrace(){
  var ctx=flowRuntimeData();
  if(_flowWaypoints.length<2||!ctx) return;
  _flowLegs=[];
  var allBlocked=false;
  for(let i=0;i<_flowWaypoints.length-1;i++){
    var src=_flowWaypoints[i];
    var tgt=_flowWaypoints[i+1];
    var cfg=src.config||{protocol:'tcp',port:443};
    if(allBlocked){
      _flowLegs.push({source:src.ref,target:tgt.ref,config:cfg,result:{path:[],blocked:{hop:0,reason:'Skipped (prior leg blocked)'}},status:'skipped'});
      continue;
    }
    var result=_traceFlowLeg(src.ref, tgt.ref, cfg, ctx);
    _flowLegs.push({source:src.ref,target:tgt.ref,config:cfg,result:result,status:result.blocked?'blocked':'allowed'});
    if(result.blocked) allBlocked=true;
  }
  // Update banner
  var anyBlocked=_flowLegs.some(function(l){return l.status==='blocked'});
  var statusEl=document.getElementById('flowStatus');
  if(anyBlocked){statusEl.textContent='BLOCKED';statusEl.className='flow-status blocked'}
  else{statusEl.textContent='ALLOWED';statusEl.className='flow-status allowed'}
  var names=_flowWaypoints.map(function(wp){
    var pos=_resolveNetworkPosition(wp.ref.type, wp.ref.id, ctx);
    return pos?pos.name:wp.ref.id;
  });
  document.getElementById('flowLabel').textContent='MULTI-HOP: '+names.join(' \u2192 ')+' | '+_flowLegs.length+' legs';
  document.getElementById('flowStepBack').style.display='none';
  document.getElementById('flowStepFwd').style.display='none';
  _renderMultiFlowPath();
  _renderMultiFlowDetail();
}

function _renderMultiFlowPath(){
  _clearFlowOverlay();
  if(!_flowLegs||_flowLegs.length===0) return;
  var ctx=flowRuntimeData();
  if(!ctx) return;
  var g=d3.select('#mapSvg').select('g');
  if(g.empty()) g=d3.select('#mapSvg');
  var flowG=g.append('g').attr('class','flow-overlay-g');
  _flowLegs.forEach(function(leg,legIdx){
    if(leg.status==='skipped'||!leg.result.path||leg.result.path.length<2) return;
    var coords=[];
    leg.result.path.forEach(function(hop){
      var c=_getHopCoordsForLeg(hop, leg, ctx);
      if(c) coords.push({x:c.x,y:c.y,hop:hop});
    });
    if(coords.length<2) return;
    var line=d3.line().x(function(d){return d.x}).y(function(d){return d.y}).curve(d3.curveBasis);
    var cls='flow-path-leg '+(leg.status==='blocked'?'blocked':leg.status==='skipped'?'skipped':'allowed');
    flowG.append('path').attr('class',cls).attr('d',line(coords));
    coords.forEach(function(c,i){
      var isBlk=c.hop.action==='block'||c.hop.action==='deny';
      var hopG=flowG.append('g').attr('class','flow-hop '+(isBlk?'flow-hop-block':'flow-hop-allow'));
      hopG.append('circle').attr('cx',c.x).attr('cy',c.y).attr('r',8);
      hopG.append('text').attr('x',c.x).attr('y',c.y).text((legIdx+1)+'.'+( i+1)).style('font-size','7px');
    });
  });
  // Waypoint markers
  _flowWaypoints.forEach(function(wp,i){
    if(i===0||i===_flowWaypoints.length-1) return; // skip source/target
    var pos=_resolveNetworkPosition(wp.ref.type, wp.ref.id, ctx);
    if(!pos) return;
    var c=wp.ref.type==='internet'?_getInternetCoords():_getSubnetCenter(pos.subnetId);
    if(!c) return;
    var wg=flowG.append('g').attr('class','flow-waypoint-marker');
    wg.append('circle').attr('cx',c.x).attr('cy',c.y).attr('r',14);
    wg.append('text').attr('x',c.x).attr('y',c.y+1).attr('text-anchor','middle').attr('dominant-baseline','central')
      .attr('fill','#000').attr('font-size','9px').attr('font-weight','700').attr('font-family','Segoe UI,system-ui,sans-serif').text('W'+(i));
  });
}

function _getHopCoordsForLeg(hop, leg, ctx){
  // Like _getHopCoords but uses leg.source/leg.target instead of globals
  ctx=ctx||flowRuntimeData();
  if(hop.type==='source'&&hop.id==='Internet') return _getInternetCoords();
  if(hop.type==='target'&&hop.id==='Internet') return _getInternetCoords();
  if(hop.type==='igw-check'){
    var ic=_getInternetCoords();
    var tPos2=ctx?_resolveNetworkPosition(leg.target.type, leg.target.id, ctx):null;
    var tc2=tPos2?_getSubnetCenter(tPos2.subnetId):null;
    if(ic&&tc2) return {x:ic.x+(tc2.x-ic.x)*0.35,y:ic.y+(tc2.y-ic.y)*0.35};
    return ic;
  }
  var subId=hop.subnetId;
  if(!subId){
    if(hop.type==='route-table'||hop.type==='nacl-outbound'||hop.type==='sg-outbound'){
      var srcP=ctx?_resolveNetworkPosition(leg.source.type, leg.source.id, ctx):null;
      subId=srcP?srcP.subnetId:null;
    }
    if(hop.type==='nacl-inbound'||hop.type==='sg-inbound'){
      var tgtP=ctx?_resolveNetworkPosition(leg.target.type, leg.target.id, ctx):null;
      subId=tgtP?tgtP.subnetId:null;
    }
  }
  if(subId){
    var subEl=document.querySelector('.subnet-node[data-subnet-id="'+subId+'"] rect');
    if(subEl){
      var x=parseFloat(subEl.getAttribute('x'))||0;
      var y=parseFloat(subEl.getAttribute('y'))||0;
      var w=parseFloat(subEl.getAttribute('width'))||100;
      var h=parseFloat(subEl.getAttribute('height'))||60;
      var ox=0;
      if(hop.type==='source') ox=-w*0.35;
      else if(hop.type==='target') ox=w*0.35;
      else if(hop.type==='route-table') ox=-w*0.2;
      else if(hop.type==='nacl-outbound') ox=-w*0.05;
      else if(hop.type==='sg-outbound') ox=w*0.08;
      else if(hop.type==='sg-inbound') ox=w*0.2;
      else if(hop.type==='nacl-inbound') ox=w*0.33;
      return {x:x+w/2+ox,y:y+h/2};
    }
  }
  if(hop.type==='peering'||hop.type==='tgw'||hop.type==='cross-vpc'){
    var sp3=ctx?_resolveNetworkPosition(leg.source.type, leg.source.id, ctx):null;
    var tp3=ctx?_resolveNetworkPosition(leg.target.type, leg.target.id, ctx):null;
    var c1=_getSubnetCenter(sp3?sp3.subnetId:null);
    var c2=_getSubnetCenter(tp3?tp3.subnetId:null);
    if(c1&&c2) return {x:(c1.x+c2.x)/2,y:(c1.y+c2.y)/2-20};
  }
  return null;
}

function _renderMultiFlowDetail(){
  if(!_flowLegs||_flowLegs.length===0) return;
  var ctx=flowRuntimeData();
  if(!ctx) return;
  FlowTracingPanel.renderMulti({
    legs: _flowLegs,
    waypoints: _flowWaypoints,
    activeLeg: _flowActiveLeg
  }, {
    resolvePosition: function(type, id){ return _resolveNetworkPosition(type, id, ctx); },
    toggleLeg: function(index){
      _flowActiveLeg=(_flowActiveLeg===index)?-1:index;
      _renderMultiFlowDetail();
    },
    removeWaypoint: _removeWaypoint,
    retraceLeg: function(index, protocol, port){
      if(_flowWaypoints[index]){
        _flowWaypoints[index].config={protocol:protocol,port:port};
        _executeMultiTrace();
      }
    },
    addWaypoint: _addWaypoint,
    clearWaypoints: function(){
      _flowWaypoints=[];
      _flowLegs=[];
      _flowActiveLeg=-1;
      _executeTrace();
    }
  });
}

document.getElementById('flowBtn').addEventListener('click',function(){
  if(_flowMode) exitFlowMode();
  else enterFlowMode();
});
document.getElementById('flowExitBtn').addEventListener('click',exitFlowMode);
document.getElementById('flowStepBack').addEventListener('click',_stepBack);
document.getElementById('flowStepFwd').addEventListener('click',_stepForward);
// #endregion FLOW TRACING

