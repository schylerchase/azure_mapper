// #region FIREWALL CHANGE SET
// === FIREWALL EDIT STATE AND COMMAND MODEL ===
let _fwEdits=[];
let _fwSnapshot=null;

function firewallRuntimeContext(){
  var contextFactory = typeof AppRenderContext !== 'undefined' ? AppRenderContext : null;
  return contextFactory ? contextFactory.createRenderContext() : {rlCtx:null,securityGroupsById:new Map()};
}

function firewallRuntimeData(){
  return firewallRuntimeContext().rlCtx;
}

function firewallSecurityGroup(sgId){
  var state=firewallRuntimeContext();
  var ctx=state.rlCtx||{};
  var current=(ctx.nsgs||[]).find(function(sg){return (sg.GroupId||sg.id)===sgId});
  if(current) return current;
  var lookup=state.securityGroupsById;
  if(lookup&&typeof lookup.get==='function'){
    var fromLookup=lookup.get(sgId);
    if(fromLookup) return fromLookup;
  }
  return null;
}

function firewallNotify(message, type){
  var notifications = typeof AppNotifications !== 'undefined' ? AppNotifications : null;
  if(notifications && typeof notifications.show === 'function') notifications.show(message, type);
}

function firewallEsc(value){
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function firewallZoomToResource(resourceId){
  if(typeof ResourceNavigation !== 'undefined' && ResourceNavigation.zoomToResource){
    return ResourceNavigation.zoomToResource(resourceId);
  }
}

function _fwTakeSnapshot(){
  if(_fwSnapshot) return;
  const ctx=firewallRuntimeData();
  if(!ctx) return;
  _fwSnapshot={
    nacls:structuredClone(ctx.subnetNsgs||[]),
    sgs:structuredClone(ctx.nsgs||[]),
    rts:structuredClone(ctx.udrs||[])
  };
}

function _fwResetAll(){
  const ctx=firewallRuntimeData();
  if(!_fwSnapshot||!ctx) return;
  // Restore nacls preserving array reference
  ctx.subnetNsgs.length=0;
  _fwSnapshot.nacls.forEach(n=>ctx.subnetNsgs.push(structuredClone(n)));
  // Restore sgs preserving array reference
  ctx.nsgs.length=0;
  _fwSnapshot.sgs.forEach(s=>ctx.nsgs.push(structuredClone(s)));
  // Restore rts preserving array reference
  ctx.udrs.length=0;
  _fwSnapshot.rts.forEach(r=>ctx.udrs.push(structuredClone(r)));
  _fwRebuildLookups();
  _fwEdits=[];
  _fwSnapshot=null;
}

function _fwRebuildLookups(){
  const state=firewallRuntimeContext();
  const ctx=state.rlCtx;
  if(!ctx) return;
  const sgLookup=state.securityGroupsById;
  if(sgLookup&&typeof sgLookup.clear==='function'&&typeof sgLookup.set==='function'){
    sgLookup.clear();
    (ctx.nsgs||[]).forEach(sg=>sgLookup.set(sg.GroupId||sg.id,sg));
  }
  // Rebuild subNacl
  const subNacl={};
  (ctx.subnetNsgs||[]).forEach(n=>{
    (n.Associations||[]).forEach(a=>{if(a.SubnetId) subNacl[a.SubnetId]=n});
  });
  ctx.subNacl=subNacl;
  // Rebuild subRT with main RT fallback
  const mainRT={};
  (ctx.udrs||[]).forEach(rt=>{
    if((rt.Associations||[]).some(a=>a.Main)) mainRT[rt.VpcId]=rt;
  });
  const subRT={};
  (ctx.udrs||[]).forEach(rt=>{
    (rt.Associations||[]).forEach(a=>{if(a.SubnetId) subRT[a.SubnetId]=rt});
  });
  (ctx.subnets||[]).forEach(s=>{
    if(!subRT[s.SubnetId]&&mainRT[s.VpcId]) subRT[s.SubnetId]=mainRT[s.VpcId];
  });
  ctx.subRT=subRT;
  // Rebuild nsgByVnet
  const nsgByVnet={};
  (ctx.nsgs||[]).forEach(sg=>{
    (nsgByVnet[sg.VpcId]=nsgByVnet[sg.VpcId]||[]).push(sg);
  });
  ctx.nsgByVnet=nsgByVnet;
}

// --- Edit operations ---
function _fwUndo(){
  if(!_fwEdits.length) return null;
  const edit=_fwEdits.pop();
  if(edit.action==='add') _fwRemoveRule(edit);
  else if(edit.action==='delete') _fwRestoreRule(edit);
  else if(edit.action==='modify'){
    _fwRemoveRule(edit);
    _fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule);
  }
  _fwRebuildLookups();
  return edit;
}

function _fwRemoveRule(edit){
  const ctx=firewallRuntimeData();
  if(!ctx) return;
  if(edit.type==='nacl'){
    const nacl=(ctx.subnetNsgs||[]).find(n=>n.NetworkAclId===edit.resourceId);
    if(!nacl) return;
    const isEgress=edit.direction==='egress';
    const idx=(nacl.Entries||[]).findIndex(e=>
      e.RuleNumber===edit.rule.RuleNumber && e.Egress===isEgress
    );
    if(idx>=0) nacl.Entries.splice(idx,1);
  } else if(edit.type==='sg'){
    const sg=firewallSecurityGroup(edit.resourceId);
    if(!sg) return;
    const arr=edit.direction==='ingress'?sg.IpPermissions:sg.IpPermissionsEgress;
    if(!arr) return;
    const idx=arr.findIndex(p=>_fwRuleMatch(p,edit.rule));
    if(idx>=0) arr.splice(idx,1);
    _fwSyncNativeSgRule(sg,edit.rule,true);
  } else if(edit.type==='route'){
    const rt=(ctx.udrs||[]).find(r=>r.RouteTableId===edit.resourceId);
    if(!rt||!rt.Routes) return;
    const idx=rt.Routes.findIndex(r=>r.DestinationCidrBlock===edit.rule.DestinationCidrBlock);
    if(idx>=0) rt.Routes.splice(idx,1);
    _fwSyncNativeRoute(rt,edit.rule,true);
  }
}

function _fwRestoreRule(edit){
  if(edit.originalRule){
    _fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule);
  }
}

function _fwApplyRule(type, resourceId, direction, ruleData){
  const ctx=firewallRuntimeData();
  if(!ctx) return;
  if(type==='nacl'){
    const nacl=(ctx.subnetNsgs||[]).find(n=>n.NetworkAclId===resourceId);
    if(!nacl) return;
    if(!nacl.Entries) nacl.Entries=[];
    const isEgress=direction==='egress';
    const idx=nacl.Entries.findIndex(e=>
      e.RuleNumber===ruleData.RuleNumber && e.Egress===isEgress
    );
    const entry=Object.assign({}, ruleData, {Egress:isEgress});
    if(idx>=0) nacl.Entries[idx]=entry;
    else nacl.Entries.push(entry);
  } else if(type==='sg'){
    const sg=firewallSecurityGroup(resourceId);
    if(!sg) return;
    const key=direction==='ingress'?'IpPermissions':'IpPermissionsEgress';
    if(!sg[key]) sg[key]=[];
    const arr=sg[key];
    const idx=arr.findIndex(p=>_fwRuleMatch(p,ruleData));
    if(idx>=0) arr[idx]=Object.assign({},ruleData);
    else arr.push(Object.assign({},ruleData));
    _fwSyncNativeSgRule(sg,ruleData,false);
  } else if(type==='route'){
    const rt=(ctx.udrs||[]).find(r=>r.RouteTableId===resourceId);
    if(!rt) return;
    if(!rt.Routes) rt.Routes=[];
    const idx=rt.Routes.findIndex(r=>r.DestinationCidrBlock===ruleData.DestinationCidrBlock);
    if(idx>=0) rt.Routes[idx]=Object.assign({},ruleData);
    else rt.Routes.push(Object.assign({},ruleData));
    _fwSyncNativeRoute(rt,ruleData,false);
  }
}

function _fwRuleMatch(a, b){
  if(!a||!b) return false;
  const aName=a._azRule&&a._azRule.name||a.RuleName;
  const bName=b._azRule&&b._azRule.name||b.RuleName;
  if(aName&&bName)return aName===bName;
  if(String(a.IpProtocol)!==String(b.IpProtocol)) return false;
  if((a.FromPort||0)!==(b.FromPort||0)) return false;
  if((a.ToPort||0)!==(b.ToPort||0)) return false;
  const aCidrs=(a.IpRanges||[]).map(r=>r.CidrIp).sort().join(',');
  const bCidrs=(b.IpRanges||[]).map(r=>r.CidrIp).sort().join(',');
  if(aCidrs!==bCidrs) return false;
  const aGrps=(a.UserIdGroupPairs||[]).map(g=>g.GroupId).sort().join(',');
  const bGrps=(b.UserIdGroupPairs||[]).map(g=>g.GroupId).sort().join(',');
  return aGrps===bGrps;
}

function _fwAzureRule(rule){
  const native=rule&&rule._azRule;
  if(!native)return null;
  const flattened=Object.assign({},native,native.properties||{});
  delete flattened.properties;
  return flattened;
}

function _fwSyncNativeSgRule(sg,rule,remove){
  const native=_fwAzureRule(rule);
  if(!native)return;
  const props=sg.properties||sg;
  if(!props.securityRules)props.securityRules=[];
  const index=props.securityRules.findIndex(candidate=>candidate.name===native.name);
  if(remove){if(index>=0)props.securityRules.splice(index,1)}
  else if(index>=0)props.securityRules[index]=native;
  else props.securityRules.push(native);
  if(sg.securityRules&&sg.securityRules!==props.securityRules)sg.securityRules=props.securityRules;
}

function _fwSgSourceText(rule,direction){
  const native=_fwAzureRule(rule);
  if(native){
    const side=direction==='ingress'?'source':'destination';
    const groups=native[side+'ApplicationSecurityGroups'];
    if(groups&&groups.length)return groups.map(group=>group.id).join(', ');
    const prefixes=native[side+'AddressPrefixes'];
    if(prefixes&&prefixes.length)return prefixes.join(', ');
    if(native[side+'AddressPrefix'])return native[side+'AddressPrefix'];
  }
  const cidrs=(rule.IpRanges||[]).map(range=>range.CidrIp).filter(Boolean);
  return cidrs.length?cidrs.join(', '):(rule.UserIdGroupPairs||[]).map(group=>group.GroupId).filter(Boolean).join(', ');
}

function _fwSyncNativeRoute(rt,route,remove){
  if(!route._azRoute)return;
  const native=Object.assign({},route._azRoute,route._azRoute.properties||{});
  delete native.properties;
  const props=rt.properties||rt;
  if(!props.routes)props.routes=[];
  const index=props.routes.findIndex(candidate=>native.name&&candidate.name===native.name||((candidate.properties||candidate).addressPrefix===native.addressPrefix));
  if(remove){if(index>=0)props.routes.splice(index,1)}
  else if(index>=0)props.routes[index]=native;
  else props.routes.push(native);
  if(rt.routes&&rt.routes!==props.routes)rt.routes=props.routes;
}

function _fwPrepareSgRule(sg,original,direction,protocol,from,to,source){
  const rule=original?structuredClone(original):{};
  rule.IpProtocol=protocol;
  if(protocol==='tcp'||protocol==='udp'){rule.FromPort=parseInt(from,10)||0;rule.ToPort=parseInt(to,10)||0}
  else {rule.FromPort=-1;rule.ToPort=-1}
  const native=_fwAzureRule(original)||{};
  const isUnchangedSource=original&&source===_fwSgSourceText(original,direction);
  const sides=source.split(/\s*,\s*/).filter(Boolean);
  const isAsg=sides.length&&sides.every(value=>value.startsWith('sg-')||/\/applicationSecurityGroups\//i.test(value));
  if(!isUnchangedSource){
    rule.IpRanges=isAsg?[]:sides.map(value=>({CidrIp:value}));
    rule.UserIdGroupPairs=isAsg?sides.map(value=>({GroupId:value})):[];
    const side=direction==='ingress'?'source':'destination';
    delete native[side+'AddressPrefix'];delete native[side+'AddressPrefixes'];delete native[side+'ApplicationSecurityGroups'];
    if(isAsg)native[side+'ApplicationSecurityGroups']=sides.map(value=>({id:value}));
    else if(sides.length>1)native[side+'AddressPrefixes']=sides;
    else native[side+'AddressPrefix']=sides[0]||'*';
  }
  const portsChanged=!original||rule.FromPort!==original.FromPort||rule.ToPort!==original.ToPort;
  if(portsChanged){
    delete native.destinationPortRanges;
    native.destinationPortRange=protocol==='tcp'||protocol==='udp'?(rule.FromPort===rule.ToPort?String(rule.FromPort):rule.FromPort+'-'+rule.ToPort):'*';
  }
  native.protocol=protocol==='-1'?'*':protocol==='tcp'?'Tcp':protocol==='udp'?'Udp':protocol==='icmp'?'Icmp':protocol==='ah'?'Ah':protocol==='esp'?'Esp':protocol;
  native.direction=direction==='ingress'?'Inbound':'Outbound';
  native.access=native.access||original&&original.Access||'Allow';
  native.priority=native.priority||original&&original.Priority;
  if(!native.priority){
    const props=sg.properties||sg;
    const used=new Set((props.securityRules||[]).map(candidate=>(candidate.properties||candidate).priority));
    let priority=100;
    while(used.has(priority)&&priority<=4096)priority++;
    native.priority=priority;
  }
  native.name=native.name||original&&original.RuleName||'mapper-rule-'+native.direction.toLowerCase()+'-'+native.priority;
  native.sourcePortRange=native.sourcePortRange||(native.sourcePortRanges&&native.sourcePortRanges.length?undefined:'*');
  if(!native.sourceAddressPrefix&&!native.sourceAddressPrefixes?.length&&!native.sourceApplicationSecurityGroups?.length)native.sourceAddressPrefix='*';
  if(!native.destinationAddressPrefix&&!native.destinationAddressPrefixes?.length&&!native.destinationApplicationSecurityGroups?.length)native.destinationAddressPrefix='*';
  rule._azRule=native;rule.RuleName=native.name;rule.Priority=native.priority;rule.Access=native.access;
  return rule;
}

function _fwEditCount(resourceId){
  return _fwEdits.filter(e=>e.resourceId===resourceId).length;
}

// --- Validation ---
function _fwValidateCidr(cidr){
  if(!cidr||typeof cidr!=='string') return false;
  if(!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) return false;
  const parts=cidr.split('/');
  const octets=parts[0].split('.');
  for(let i=0;i<4;i++){if(parseInt(octets[i],10)>255) return false}
  if(parseInt(parts[1],10)>32) return false;
  return true;
}

function _fwValidateNaclRule(rule, existingEntries, direction){
  const errs=[];
  const num=parseInt(rule.RuleNumber,10);
  if(isNaN(num)||num<1||num>32766) errs.push('Rule number must be 1-32766');
  const isEgress=direction==='egress';
  if(existingEntries&&!isNaN(num)){
    const dup=existingEntries.some(e=>
      e.RuleNumber===num && e.Egress===isEgress
    );
    if(dup) errs.push('Duplicate rule number '+num+' in '+direction+' direction');
  }
  if(!_fwValidateCidr(rule.CidrBlock)) errs.push('Invalid CIDR format');
  const proto=String(rule.Protocol);
  if(proto==='6'||proto==='17'){
    if(!rule.PortRange) errs.push('Port range required for TCP/UDP');
    else{
      const from=parseInt(rule.PortRange.From,10);
      const to=parseInt(rule.PortRange.To,10);
      if(isNaN(from)||isNaN(to)) errs.push('Invalid port range values');
      else{
        if(from<0||from>65535) errs.push('From port must be 0-65535');
        if(to<0||to>65535) errs.push('To port must be 0-65535');
        if(from>to) errs.push('From port must be <= To port');
      }
    }
  }
  return errs;
}

function _fwValidateSgRule(rule){
  const errs=[];
  const proto=String(rule.IpProtocol||'');
  const validProtos=['tcp','udp','icmp','-1','ah','esp'];
  if(!validProtos.includes(proto)) errs.push('Invalid protocol: '+proto);
  if(proto==='tcp'||proto==='udp'){
    const from=parseInt(rule.FromPort,10);
    const to=parseInt(rule.ToPort,10);
    if(isNaN(from)||isNaN(to)) errs.push('Port range required for TCP/UDP');
    else{
      if(from<0||from>65535) errs.push('FromPort must be 0-65535');
      if(to<0||to>65535) errs.push('ToPort must be 0-65535');
      if(from>to) errs.push('FromPort must be <= ToPort');
    }
  }
  const hasCidr=(rule.IpRanges||[]).some(r=>r.CidrIp);
  const hasSgRef=(rule.UserIdGroupPairs||[]).some(g=>g.GroupId);
  if(!hasCidr&&!hasSgRef) errs.push('At least one source (CIDR or SG reference) required');
  if(hasCidr){
    (rule.IpRanges||[]).forEach(r=>{
      if(r.CidrIp&&!_fwAddressPrefixValid(r.CidrIp)) errs.push('Invalid CIDR: '+r.CidrIp);
    });
  }
  const native=_fwAzureRule(rule);
  if(native&&(native.priority<100||native.priority>4096))errs.push('Custom NSG priority must be 100-4096');
  return errs;
}

function _fwAddressPrefixValid(value){
  if(value==='*'||_fwValidateCidr(value)||_fwValidateCidr(value+'/32')||/^[A-Za-z][A-Za-z0-9_.-]*$/.test(value))return true;
  const range=String(value).split('-');
  if(range.length===2&&range.every(ip=>_fwValidateCidr(ip+'/32')))return true;
  const ipv6=String(value).match(/^[:a-fA-F0-9]+(?:\/(\d{1,3}))?$/);
  return !!(ipv6&&value.includes(':')&&(!ipv6[1]||Number(ipv6[1])<=128));
}

function _fwValidateRoute(route, existingRoutes){
  const errs=[];
  if(!_fwValidateCidr(route.DestinationCidrBlock)) errs.push('Invalid destination CIDR');
  if(existingRoutes){
    const dup=existingRoutes.some(r=>
      r.DestinationCidrBlock===route.DestinationCidrBlock
    );
    if(dup) errs.push('Duplicate destination CIDR: '+route.DestinationCidrBlock);
  }
  const hasTarget=route.GatewayId||route.NatGatewayId||
    route.TransitGatewayId||route.VpcPeeringConnectionId||route.VpcEndpointId;
  if(!hasTarget) errs.push('Route target required');
  return errs;
}

// --- Conflict warnings ---
function _fwCheckNaclShadow(nacl, direction){
  if(!nacl||!nacl.Entries) return [];
  const isEgress=direction==='egress';
  const entries=(nacl.Entries||[])
    .filter(e=>e.Egress===isEgress && e.RuleNumber!==32767)
    .sort((a,b)=>a.RuleNumber-b.RuleNumber);
  const warnings=[];
  for(let i=1;i<entries.length;i++){
    for(let j=0;j<i;j++){
      const hi=entries[i], lo=entries[j];
      const sameCidr=(hi.CidrBlock||'')===(lo.CidrBlock||'');
      const sameProto=(hi.Protocol||'')===(lo.Protocol||'') || lo.Protocol==='-1';
      if(sameCidr&&sameProto&&hi.RuleAction!==lo.RuleAction){
        warnings.push(
          'Rule #'+hi.RuleNumber+' ('+hi.RuleAction+') is shadowed by #'+
          lo.RuleNumber+' ('+lo.RuleAction+'): same CIDR '+
          (hi.CidrBlock||'any')+', evaluated first'
        );
      }
    }
  }
  return warnings;
}

// --- CLI generation ---
function _fwGenerateCli(edits){
  const list=edits||_fwEdits;
  const cmds=[];
  list.forEach(edit=>{
    if(edit.type==='nacl') _fwGenNaclCli(edit, cmds);
    else if(edit.type==='sg') _fwGenSgCli(edit, cmds);
    else if(edit.type==='route') _fwGenRouteCli(edit, cmds);
  });
  return cmds;
}

function _fwGenNaclCli(edit, cmds){
  const nsgName=edit.resourceId;
  const rg=edit.resourceGroup||'<resource-group>';
  const dir=edit.direction==='egress'?'Outbound':'Inbound';
  if(edit.action==='add'||edit.action==='modify'){
    cmds.push(_fwNaclEntryCmd(nsgName, rg, edit.rule, dir));
  } else if(edit.action==='delete'){
    cmds.push(
      'az network nsg rule delete --nsg-name '+nsgName+
      ' --resource-group '+rg+
      ' --name '+edit.rule.RuleName
    );
  }
}

function _fwNaclEntryCmd(nsgName, rg, rule, direction){
  let cmd='az network nsg rule create --nsg-name '+nsgName+
    ' --resource-group '+rg+
    ' --name '+(rule.RuleName||'rule-'+rule.RuleNumber)+
    ' --priority '+rule.RuleNumber+
    ' --direction '+direction+
    ' --protocol '+rule.Protocol+
    ' --source-address-prefixes '+(rule.CidrBlock||'*');
  if(rule.PortRange){
    cmd+=' --destination-port-ranges '+rule.PortRange.From+(rule.PortRange.To!==rule.PortRange.From?'-'+rule.PortRange.To:'');
  }
  cmd+=' --access '+(rule.RuleAction==='allow'?'Allow':'Deny');
  return cmd;
}

function _fwGenSgCli(edit, cmds){
  const target=_fwCliTarget(edit.resourceId,edit.resourceGroup);
  const nsgName=target.name;
  const rg=target.resourceGroup;
  const dir=edit.direction==='ingress'?'Inbound':'Outbound';
  if(edit.action==='add'||edit.action==='modify'){
    if(edit.action==='modify'&&edit.originalRule){
      const oldName=_fwAzureRule(edit.originalRule)?.name||edit.originalRule.RuleName;
      const newName=_fwAzureRule(edit.rule)?.name||edit.rule.RuleName;
      if(oldName&&oldName!==newName)cmds.push('az network nsg rule delete --nsg-name '+_fwCliValue(nsgName)+' --resource-group '+_fwCliValue(rg)+_fwCliSubscription(target)+' --name '+_fwCliValue(oldName));
    }
    cmds.push(_fwSgRuleCmd(nsgName, rg, edit.rule, dir, target.subscription));
  } else if(edit.action==='delete'){
    cmds.push('az network nsg rule delete --nsg-name '+_fwCliValue(nsgName)+' --resource-group '+_fwCliValue(rg)+_fwCliSubscription(target)+' --name '+_fwCliValue(_fwAzureRule(edit.rule)?.name||edit.rule.RuleName||'rule'));
  }
}

function _fwSgRuleCmd(nsgName, rg, rule, direction, subscription){
  const ctx=firewallRuntimeData()||{};
  const sg=(ctx.nsgs||[]).find(group=>(group.name||String(group.GroupId||group.id||'').split('/').pop())===nsgName)||{securityRules:[]};
  const prepared=rule._azRule?rule:_fwPrepareSgRule(sg,null,direction==='Inbound'?'ingress':'egress',rule.IpProtocol,rule.FromPort,rule.ToPort,_fwSgSourceText(rule,direction==='Inbound'?'ingress':'egress'));
  const native=_fwAzureRule(prepared);
  if(!Number.isInteger(Number(native.priority))||native.priority<100||native.priority>4096)return '# NSG '+nsgName+': custom rule priority must be 100-4096';
  let cmd='az network nsg rule create --nsg-name '+_fwCliValue(nsgName)+
    ' --resource-group '+_fwCliValue(rg)+_fwCliSubscription({subscription})+
    ' --name '+_fwCliValue(native.name)+
    ' --priority '+native.priority+
    ' --direction '+_fwCliValue(native.direction||direction)+
    ' --protocol '+_fwCliValue(native.protocol||'*')+
    ' --access '+_fwCliValue(native.access||'Allow');
  for(const side of ['source','destination']){
    const ports=native[side+'PortRanges']?.length?native[side+'PortRanges']:[native[side+'PortRange']||'*'];
    cmd+=' --'+side+'-port-ranges '+ports.map(_fwCliValue).join(' ');
    const asgs=native[side+'ApplicationSecurityGroups'];
    if(asgs&&asgs.length)cmd+=' --'+side+'-asgs '+asgs.map(group=>_fwCliValue(group.id)).join(' ');
    else {
      const prefixes=native[side+'AddressPrefixes']?.length?native[side+'AddressPrefixes']:[native[side+'AddressPrefix']||'*'];
      cmd+=' --'+side+'-address-prefixes '+prefixes.map(_fwCliValue).join(' ');
    }
  }
  return cmd;
}

function _fwCliValue(value){return "'"+String(value).replace(/'/g,"'\\''")+"'"}
function _fwCliSubscription(target){return target.subscription?' --subscription '+_fwCliValue(target.subscription):''}
function _fwCliTarget(id,resourceGroup){
  return {name:String(id||'').split('/').pop(),resourceGroup:resourceGroup||(String(id||'').match(/\/resourceGroups\/([^/]+)/i)||[])[1]||'<resource-group>',subscription:(String(id||'').match(/\/subscriptions\/([^/]+)/i)||[])[1]};
}

function _fwGenRouteCli(edit, cmds){
  const target=_fwCliTarget(edit.resourceId,edit.resourceGroup);
  const rtName=target.name;
  const rg=target.resourceGroup;
  if(edit.action==='add'||edit.action==='modify'){
    cmds.push(_fwRouteCmd(rtName, rg, edit.rule, target.subscription));
  } else if(edit.action==='delete'){
    cmds.push(
      'az network route-table route delete --route-table-name '+_fwCliValue(rtName)+
      ' --resource-group '+_fwCliValue(rg)+_fwCliSubscription(target)+
      ' --name '+_fwCliValue(edit.rule._azRoute?.name||edit.rule.RouteName||'route')
    );
  }
}

function _fwRouteCmd(rtName, rg, route, subscription){
  const raw=route._azRoute||{};
  const native=raw.properties||raw;
  const type=native.nextHopType||route.nextHopType||(route.GatewayId==='local'?'VnetLocal':route.GatewayId);
  if(!['Internet','None','VnetLocal','VirtualNetworkGateway','VirtualAppliance'].includes(type))return '# Route '+(raw.name||route.RouteName||'route')+': select a supported Azure next-hop type before exporting';
  let cmd='az network route-table route create --route-table-name '+_fwCliValue(rtName)+
    ' --resource-group '+_fwCliValue(rg)+_fwCliSubscription({subscription})+
    ' --name '+_fwCliValue(raw.name||route.RouteName||'route')+
    ' --address-prefix '+_fwCliValue(native.addressPrefix||route.DestinationCidrBlock)+
    ' --next-hop-type '+type;
  if(type==='VirtualAppliance'){
    const ip=native.nextHopIpAddress||route.NextHopIpAddress;
    if(!ip||!_fwValidateCidr(ip+'/32'))return '# Route '+(raw.name||route.RouteName||'route')+': VirtualAppliance requires an IPv4 next-hop address';
    cmd+=' --next-hop-ip-address '+_fwCliValue(ip);
  }
  return cmd;
}
