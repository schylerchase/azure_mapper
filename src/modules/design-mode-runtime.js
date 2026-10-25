// #region DESIGN MODE
// === DESIGN MODE ===
let _designMode=false;
let _designChanges=[];
let _designBaseline=null;
let _designDebounce=null;
let _lastDesignValidation=null;
let _sidebarWasCollapsed=false;

function designRuntimeContext(){
  return AppRenderContext.createRenderContext();
}

function designRuntimeData(){
  return designRuntimeContext().rlCtx;
}

function designResourceType(type){
  return ({'Redis Cache':'Redis',ElastiCache:'Redis','Function App':'FunctionApp',Lambda:'FunctionApp',RDS:'SQL',ECS:'Container',Redshift:'Synapse'})[type]||type;
}

function designGatewayType(type){
  return ({IGW:'AZFW',Firewall:'AZFW','Azure Firewall':'AZFW',PVTEP:'VPCE','Private Endpoint':'VPCE'})[type]||type;
}

function designNotify(message,type){
  return AppNotifications.show(message,type);
}

function designDownload(blob,name){
  return AppDownloads.saveBlob(blob,name);
}

function designSubnetsForVNet(ctx,vnetId){
  if(!ctx||!vnetId)return [];
  return (ctx.subnets||[]).filter(s=>s.VpcId===vnetId||(s.properties&&s.properties.virtualNetwork&&s.properties.virtualNetwork.id===vnetId));
}

function designVNetAddressPrefixes(vnet){
  const prefixes=vnet.addressSpace?.addressPrefixes||vnet.properties?.addressSpace?.addressPrefixes;
  return prefixes?.length?prefixes:[vnet.CidrBlock].filter(Boolean);
}

function designSplitSubnetPlan(change,subnets){
  const errors=[];
  const targetId=change.target.SubnetId||change.target.id;
  const subnet=subnets.find(s=>(s.SubnetId||s.id)===targetId);
  if(!subnet)return{errors:['Subnet '+targetId+' not found'],prefixErrors:['Subnet '+targetId+' not found']};
  const props=subnet.properties||subnet;
  const prefixes=[...new Set([...(subnet.addressPrefixes||[]),...(props.addressPrefixes||[]),subnet.addressPrefix,props.addressPrefix,subnet.CidrBlock].filter(Boolean))];
  if(prefixes.length!==1||prefixes[0].includes(':'))errors.push('Split supports a single IPv4 subnet prefix. Dual-stack and multiple-prefix subnets cannot be split safely.');
  const cidr=prefixes[0]||'';
  const prefix=parseInt(cidr.split('/')[1],10);
  if(!parseCIDR(cidr))errors.push('Invalid subnet CIDR: '+cidr);
  else if(prefix>=_azureConstraints.subnet.cidrPrefixMax)errors.push('Cannot split /'+prefix+' subnet (minimum is /'+_azureConstraints.subnet.cidrPrefixMax+')');
  const prefixErrors=errors.slice();
  const names=(change.params.names||[gn(subnet,'')+'_a',gn(subnet,'')+'_b']).map(name=>String(name||'').trim());
  if(names.length!==2||names.some(name=>!name))errors.push('Enter a name for each subnet half.');
  else if(names[0].toLowerCase()===names[1].toLowerCase())errors.push('Subnet halves must have distinct names.');
  const vnetId=subnet.VpcId||(targetId.includes('/subnets/')?targetId.split('/subnets/')[0]:'');
  const newIds=change.params.newIds||(targetId.includes('/subnets/')?names.map(name=>vnetId+'/subnets/'+name):['subnet-split-a-'+Date.now(),'subnet-split-b-'+Date.now()]);
  if(newIds.length!==2||newIds.some(id=>!id)||newIds[0].toLowerCase()===newIds[1].toLowerCase())errors.push('Subnet halves must have distinct resource IDs.');
  const otherSubnets=subnets.filter(s=>(s.SubnetId||s.id)!==targetId);
  if(otherSubnets.some(s=>newIds.some(id=>id.toLowerCase()===(s.SubnetId||s.id||'').toLowerCase())))errors.push('A subnet with one of these resource IDs already exists.');
  if(otherSubnets.some(s=>(s.VpcId||(s.id||s.SubnetId||'').split('/subnets/')[0])===vnetId&&names.some(name=>name.toLowerCase()===gn(s,'').toLowerCase())))errors.push('A subnet with one of these names already exists in this VNet.');
  return{errors,prefixErrors,subnet,cidr,halves:splitCIDR(cidr),names,newIds,vnetId};
}

function designPublicSubnets(ctx,vnetId){
  if(!ctx)return [];
  const publicSet=ctx.pubSubs||new Set();
  return designSubnetsForVNet(ctx,vnetId).filter(s=>publicSet.has(s.SubnetId||s.id));
}

function designRouteTableForSubnet(ctx,subnetId){
  return ctx&&ctx.subRT?ctx.subRT[subnetId]:null;
}

function designGatewaysForVNet(ctx,vnetId){
  if(!ctx||!vnetId)return [];
  const gateways=[];
  (ctx.firewalls||[]).forEach(g=>{
    const props=g.properties||g;
    const config=(props.ipConfigurations||[]).map(ip=>ip.properties||ip).find(ip=>ip.privateIPAddress||ip.privateIpAddress);
    if(g.VpcId===vnetId||g._vnetId===vnetId||(g.Attachments||[]).some(a=>a.VpcId===vnetId))gateways.push({id:g.id||g.InternetGatewayId,label:'Firewall: '+gn(g,g.id||g.InternetGatewayId),nextHopType:'VirtualAppliance',nextHopIp:config&&(config.privateIPAddress||config.privateIpAddress)||''});
  });
  return gateways.filter(g=>g.id);
}

function designRouteNextHop(params){
  const type=params.nextHopType||params.TargetId;
  if(!['Internet','None','VnetLocal','VirtualNetworkGateway','VirtualAppliance'].includes(type))return null;
  const ip=params.NextHopIp||'';
  if(type==='VirtualAppliance'&&(!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)||!parseCIDR(ip+'/32')))return null;
  return {type,ip};
}

function designSubscriptionArg(){
  const ctx=designRuntimeData();
  const account=ctx&&ctx._accounts&&ctx._accounts[0];
  return account?'--subscription '+(account.subscriptionId||'${AZURE_SUBSCRIPTION_ID}'):'--subscription ${AZURE_SUBSCRIPTION_ID}';
}

function designToolbarButton(label,handler){
  const button=document.createElement('button');
  button.type='button';
  button.textContent=label;
  button.addEventListener('click',event=>{
    event.preventDefault();
    event.stopPropagation();
    handler(event);
  });
  return button;
}

function _snapshotTextareas(){const snap={};document.querySelectorAll('.ji').forEach(el=>{snap[el.id]=el.value});return snap}
function _restoreTextareas(snap){Object.entries(snap).forEach(([id,val])=>{const el=document.getElementById(id);if(el)el.value=val})}
function enterDesignMode(){
  _designMode=true;_designChanges=[];
  _designBaseline=_snapshotTextareas();
  document.getElementById('designToggle').classList.add('active');
  document.getElementById('designToggle').textContent='Exit Design';
  document.getElementById('designBanner').classList.add('visible');
  document.getElementById('designHelp').classList.remove('visible');
  document.getElementById('exportBar').style.display='none';
  const dp=document.getElementById('detailPanel');dp.style.top='32px';dp.style.height='calc(100% - 32px)';
  renderChangeLog();
  if(document.getElementById('designPalette'))document.getElementById('designPalette').classList.add('open');
  const sb=document.querySelector('.sidebar');
  _sidebarWasCollapsed=sb.classList.contains('collapsed');
  if(!_sidebarWasCollapsed){sb.classList.add('collapsed');document.getElementById('sidebarToggle').innerHTML='&#x25B6;'}
}
function exitDesignMode(options){
  _designMode=false;
  if(_designBaseline&&options?.restore!==false)_restoreTextareas(_designBaseline);
  _designBaseline=null;_designChanges=[];
  _lastDesignValidation=null;
  document.getElementById('designToggle').classList.remove('active');
  document.getElementById('designToggle').textContent='Design';
  document.getElementById('designBanner').classList.remove('visible');
  document.getElementById('exportBar').style.display='';
  const dp=document.getElementById('detailPanel');dp.style.top='';dp.style.height='';
  document.getElementById('changeLog').style.display='none';
  if(document.getElementById('designPalette'))document.getElementById('designPalette').classList.remove('open');
  if(!_sidebarWasCollapsed){document.querySelector('.sidebar').classList.remove('collapsed');document.getElementById('sidebarToggle').innerHTML='&#x25C0;'}
  if(_designDebounce)clearTimeout(_designDebounce);
  _designDebounce=null;
  if(options?.render!==false)renderMap();
}
function addDesignChange(change){
  change.id='chg_'+Date.now()+'_'+Math.random().toString(36).substr(2,4);
  change.timestamp=new Date().toISOString();
  // Validate against current state
  const vResult=validateDesignChange(change,designRuntimeData());
  change._validation=vResult;
  if(!vResult.valid){
    // Show errors but still allow user to see them in change log (marked as invalid)
    change._invalid=true;
  }
  _designChanges.push(change);
  renderChangeLog();
  // Debounced live mutation (300ms)
  if(_designDebounce)clearTimeout(_designDebounce);
  _designDebounce=setTimeout(()=>applyDesignChanges(),300);
}
function undoLastChange(){
  if(!_designChanges.length)return;
  _designChanges.pop();
  renderChangeLog();
  if(_designDebounce)clearTimeout(_designDebounce);
  _designDebounce=setTimeout(()=>applyDesignChanges(),300);
}
function applyDesignChanges(){
  if(!_designBaseline)return;
  _restoreTextareas(_designBaseline);
  // Apply each change sequentially (skip invalid ones)
  _designChanges.forEach(ch=>{
    if(ch._invalid)return;
    const apply=_designApplyFns[ch.action];
    if(apply)apply(ch);
  });
  // Re-render
  renderMap(()=>{if(typeof _autoSaveSession==='function')_autoSaveSession(true)});
  // Post-render: run full-state validation
  const designCtx=designRuntimeData();
  if(designCtx){
    const stateResult=validateDesignState(_designChanges,designCtx);
    _lastDesignValidation=stateResult;
  }
  // Post-render: add design overlay classes (delayed for RAF)
  setTimeout(()=>{
    _designChanges.forEach(ch=>{
      if(ch._addedIds){ch._addedIds.forEach(id=>{
        const el=document.querySelector(`[data-id="${id}"]`);
        if(el)(el.closest('.subnet-group')||el).classList.add('design-added');
      })}
      if(ch._modifiedIds){ch._modifiedIds.forEach(id=>{
        const el=document.querySelector(`[data-id="${id}"]`);
        if(el)(el.closest('.subnet-group')||el).classList.add('design-modified');
      })}
      if(ch._removedIds){ch._removedIds.forEach(id=>{
        const el=document.querySelector(`[data-id="${id}"]`);
        if(el)(el.closest('.subnet-group')||el).classList.add('design-removed');
      })}
    });
  },200);
}

// Design change apply functions: mutate textarea JSON
const _designApplyFns={
  add_vpc(ch){
    const raw=safeParse(gv('in_vnets'));const vpcs=raw?ext(raw,['value','VirtualNetworks']):[];
    const id=ch.params.VpcId||('vnet-design-'+Date.now());ch.params.VpcId=id;
    const location=ch.params.Location||_designRegion;
    const vpc={id:id,name:ch.params.Name||'New VNet',location,VpcId:id,CidrBlock:ch.params.CidrBlock,addressSpace:{addressPrefixes:[ch.params.CidrBlock]},tags:{Name:ch.params.Name||'New VNet'}};
    vpcs.push(vpc);
    document.getElementById('in_vnets').value=JSON.stringify({value:vpcs});
    ch._addedIds=[id];
    // Create default route table (UDR)
    const rtRaw=safeParse(gv('in_udrs'));const rts=rtRaw?ext(rtRaw,['value','RouteTables']):[];
    const rtId=ch.params._rtId||('rt-design-'+Date.now());ch.params._rtId=rtId;
    rts.push({id:rtId,name:(ch.params.Name||'vnet')+'-main-rt',location,RouteTableId:rtId,VpcId:id,routes:[{addressPrefix:ch.params.CidrBlock,nextHopType:'VnetLocal'}],tags:{Name:(ch.params.Name||'vnet')+'-main-rt'}});
    document.getElementById('in_udrs').value=JSON.stringify({value:rts});
    // Create default NSG (replaces SG+NACL)
    const sgRaw=safeParse(gv('in_nsgs'));const sgs=sgRaw?ext(sgRaw,['value','SecurityGroups']):[];
    const sgId=ch.params._sgId||('nsg-design-'+Date.now());ch.params._sgId=sgId;
    sgs.push({id:sgId,name:'default-nsg',location,GroupId:sgId,GroupName:'default-nsg',VpcId:id,securityRules:[],tags:{Name:'default-nsg'}});
    document.getElementById('in_nsgs').value=JSON.stringify({value:sgs});
  },
  add_subnet(ch){
    const raw=safeParse(gv('in_subnets'));
    const subs=raw?ext(raw,['value','Subnets']):[];
    const subId=ch.params.SubnetId||('subnet-design-'+Date.now());ch.params.SubnetId=subId;
    subs.push({id:subId,SubnetId:subId,VpcId:ch.params.VpcId,addressPrefix:ch.params.CidrBlock,CidrBlock:ch.params.CidrBlock,name:ch.params.Name||'New Subnet',tags:{Name:ch.params.Name||'New Subnet'}});
    document.getElementById('in_subnets').value=JSON.stringify({value:subs});
    ch._addedIds=[subId];
  },
  split_subnet(ch){
    const raw=safeParse(gv('in_subnets'));
    const subs=raw?ext(raw,['value','Subnets']):[];
    const targetId=ch.target.SubnetId||ch.target.id;
    const idx=subs.findIndex(s=>(s.SubnetId||s.id)===targetId);
    const plan=designSplitSubnetPlan(ch,subs);
    if(plan.errors.length){ch._invalid=true;ch._validation={valid:false,errors:plan.errors,warnings:[]};designNotify(plan.errors.join(' '),'error');return}
    const{halves,names,newIds,vnetId}=plan;
    const orig=plan.subnet;
    ch.target.CidrBlock=plan.cidr;
    ch.params.names=names;
    ch.params.newIds=newIds;
    const splitSubs=halves.map((cidr,i)=>{
      const sub={...JSON.parse(JSON.stringify(orig)),SubnetId:ch.params.newIds[i],id:ch.params.newIds[i],VpcId:vnetId,CidrBlock:cidr,addressPrefix:cidr,name:names[i],tags:{...orig.tags,Name:names[i]}};
      if(sub.addressPrefixes)sub.addressPrefixes=[cidr];
      if(sub.properties){sub.properties.addressPrefix=cidr;if(sub.properties.addressPrefixes)sub.properties.addressPrefixes=[cidr]}
      return sub;
    });
    const [sub1,sub2]=splitSubs;
    subs.splice(idx,1,sub1,sub2);
    document.getElementById('in_subnets').value=JSON.stringify({value:subs});
    ch._removedIds=[targetId];ch._addedIds=[sub1.SubnetId,sub2.SubnetId];
    // Update embedded VNet records and subnet associations alongside the standalone list.
    ['in_vnets','in_nsgs','in_udrs','in_nats'].forEach(input=>{
      const el=document.getElementById(input);const data=el&&safeParse(el.value);if(!data)return;
      let changed=false;
      ext(data,['value','VirtualNetworks','SecurityGroups','RouteTables','NatGateways']).forEach(resource=>{
        [resource,resource.properties].filter(Boolean).forEach(props=>{
          if(!Array.isArray(props.subnets))return;
          props.subnets=props.subnets.flatMap(sub=>{
            if((sub.SubnetId||sub.id)!==targetId)return [sub];
            changed=true;
            return input==='in_vnets'?splitSubs.map(s=>JSON.parse(JSON.stringify(s))):ch.params.newIds.map(id=>({...sub,id,...(sub.SubnetId?{SubnetId:id}:{})}));
          });
        });
      });
      if(changed)el.value=JSON.stringify(data);
    });
    const subnetForIp=ip=>ipInCIDR(ip,halves[0])?sub1.id:ipInCIDR(ip,halves[1])?sub2.id:null;
    const nicEl=document.getElementById('in_nics');const nicRaw=nicEl&&safeParse(nicEl.value);
    if(nicRaw){
      let changed=false;
      ext(nicRaw,['value']).forEach(nic=>(nic.ipConfigurations||nic.properties?.ipConfigurations||[]).forEach(config=>{
        const props=config.properties||config;
        if(props.subnet?.id!==targetId)return;
        const newSub=subnetForIp(props.privateIPAddress||props.privateIpAddress||'');
        if(newSub){props.subnet.id=newSub;changed=true}
      }));
      if(changed)nicEl.value=JSON.stringify(nicRaw);
    }
    // Migrate VMs by IP
    const instRaw=safeParse(gv('in_vms'));
    if(instRaw){
      const vms=ext(instRaw,['value']);
      vms.forEach(vm=>{
        const pip=vm.privateIpAddress||vm.PrivateIpAddress||'';
        if((vm.SubnetId===targetId||vm.subnetId===targetId)&&pip){
          const newSub=subnetForIp(pip);
          if(newSub){vm.SubnetId=newSub;vm.subnetId=newSub}
        }
      });
      document.getElementById('in_vms').value=JSON.stringify({value:vms});
    }
  },
  add_gateway(ch){
    const type=designGatewayType(ch.params.GatewayType);
    if(type==='NAT'){
      const raw=safeParse(gv('in_nats'));const nats=raw?ext(raw,['value','NatGateways']):[];
      const id=ch.params.GatewayId||('nat-design-'+Date.now());ch.params.GatewayId=id;
      nats.push({id:id,NatGatewayId:id,VpcId:ch.params.VpcId,SubnetId:ch.params.SubnetId,provisioningState:'Succeeded',tags:{Name:ch.params.Name||'New NAT Gateway'}});
      document.getElementById('in_nats').value=JSON.stringify({value:nats});
      ch._addedIds=[id];
    } else if(type==='PVTEP'||type==='VPCE'){
      const raw=safeParse(gv('in_pvteps'));const pvteps=raw?ext(raw,['value','PrivateEndpoints']):[];
      const id=ch.params.GatewayId||('pvtep-design-'+Date.now());ch.params.GatewayId=id;
      pvteps.push({id:id,VpcEndpointId:id,VpcId:ch.params.VpcId,SubnetId:ch.params.SubnetId,name:ch.params.Name||'New Private Endpoint',tags:{Name:ch.params.Name||'New Private Endpoint'}});
      document.getElementById('in_pvteps').value=JSON.stringify({value:pvteps});
      ch._addedIds=[id];
    } else if(type==='AZFW'){
      const raw=safeParse(gv('in_azfws'));const fws=raw?ext(raw,['value']):[];
      const id=ch.params.GatewayId||('azfw-design-'+Date.now());ch.params.GatewayId=id;
      fws.push({id:id,InternetGatewayId:id,type:'Microsoft.Network/azureFirewalls',name:ch.params.Name||'New Azure Firewall',VpcId:ch.params.VpcId,SubnetId:ch.params.SubnetId,_vnetId:ch.params.VpcId,Attachments:[{VpcId:ch.params.VpcId}],properties:{ipConfigurations:ch.params.SubnetId?[{subnet:{id:ch.params.SubnetId}}]:[]},tags:{Name:ch.params.Name||'New Azure Firewall'}});
      document.getElementById('in_azfws').value=JSON.stringify({value:fws});
      ch._addedIds=[id];
    }
  },
  add_route(ch){
    const raw=safeParse(gv('in_udrs'));const rts=raw?ext(raw,['value','RouteTables']):[];
    const rt=rts.find(r=>r.RouteTableId===ch.target.RouteTableId||r.id===ch.target.RouteTableId);
    if(!rt)return;
    const hop=designRouteNextHop(ch.params);
    if(!hop)return;
    const props=rt.properties||rt;
    props.routes=props.routes||[];
    props.routes.push({name:ch.params.Name||'mapper-route-'+ch.params.DestinationCidrBlock.replace(/[^a-zA-Z0-9]/g,'-'),addressPrefix:ch.params.DestinationCidrBlock,nextHopType:hop.type,...(hop.type==='VirtualAppliance'?{nextHopIpAddress:hop.ip}:{})});
    document.getElementById('in_udrs').value=JSON.stringify({value:rts});
    ch._modifiedIds=[ch.target.RouteTableId];
  },
  add_resource(ch){
    const type=designResourceType(ch.params.ResourceType);
    if(type==='VM'||type==='VM'){
      const raw=safeParse(gv('in_vms'));
      const vms=raw?ext(raw,['value']):[];
      const id=ch.params.ResourceId||('vm-design-'+Date.now());ch.params.ResourceId=id;
      vms.push({id:id,InstanceId:id,name:ch.params.Name||'New VM',SubnetId:ch.params.SubnetId,VpcId:ch.params.VpcId,_designCreated:true,properties:{provisioningState:'Succeeded',hardwareProfile:{vmSize:ch.params.InstanceType||'Standard_B2ms'}},tags:{Name:ch.params.Name||'New VM'}});
      document.getElementById('in_vms').value=JSON.stringify({value:vms});
      ch._addedIds=[id];
    } else if(type==='SQL'||type==='RDS'){
      const raw=safeParse(gv('in_sql'));const sql=raw?ext(raw,['value']):[];
      const id=ch.params.ResourceId||('sql-design-'+Date.now());ch.params.ResourceId=id;
      sql.push({id:id,DBInstanceIdentifier:id,name:ch.params.Name||'New SQL Server',VpcId:ch.params.VpcId,tags:{Name:ch.params.Name||'New SQL Server'}});
      document.getElementById('in_sql').value=JSON.stringify({value:sql});
      ch._addedIds=[id];
    } else if(type==='Redis'||type==='ElastiCache'){
      const raw=safeParse(gv('in_elasticache'));const caches=raw?ext(raw,['value']):[];
      const id=ch.params.ResourceId||('redis-design-'+Date.now());ch.params.ResourceId=id;
      caches.push({id:id,CacheClusterId:id,type:'Microsoft.Cache/Redis',name:ch.params.Name||'New Redis Cache',VpcId:ch.params.VpcId,SubnetId:ch.params.SubnetId,properties:{subnetId:ch.params.SubnetId},tags:{Name:ch.params.Name||'New Redis Cache'}});
      document.getElementById('in_elasticache').value=JSON.stringify({value:caches});
      ch._addedIds=[id];
    } else if(type==='FunctionApp'||type==='Lambda'){
      const raw=safeParse(gv('in_funcapps'));const fns=raw?ext(raw,['value']):[];
      const id=ch.params.ResourceId||('func-design-'+Date.now());ch.params.ResourceId=id;
      fns.push({id:id,type:'Microsoft.Web/sites',name:ch.params.Name||'new-function',kind:'functionapp',VpcId:ch.params.VpcId,SubnetId:ch.params.SubnetId,properties:{virtualNetworkSubnetId:ch.params.SubnetId},tags:{Name:ch.params.Name||'new-function'}});
      document.getElementById('in_funcapps').value=JSON.stringify({value:fns});
      ch._addedIds=[id];
    } else if(type==='Container'||type==='ECS'){
      const raw=safeParse(gv('in_containers'));const cs=raw?ext(raw,['value']):[];
      const id=ch.params.ResourceId||('aci-design-'+Date.now());ch.params.ResourceId=id;
      cs.push({id:id,name:ch.params.Name||'new-container',SubnetId:ch.params.SubnetId,VpcId:ch.params.VpcId,tags:{Name:ch.params.Name||'new-container'}});
      document.getElementById('in_containers').value=JSON.stringify({value:cs});
      ch._addedIds=[id];
    } else if(type==='Synapse'){
      const raw=safeParse(gv('in_synapse'));const workspaces=raw?ext(raw,['value']):[];
      const id=ch.params.ResourceId||('synapse-design-'+Date.now());ch.params.ResourceId=id;
      workspaces.push({id:id,type:'Microsoft.Synapse/workspaces',name:ch.params.Name||'new-synapse',VpcId:ch.params.VpcId,SubnetId:ch.params.SubnetId,tags:{Name:ch.params.Name||'new-synapse'}});
      document.getElementById('in_synapse').value=JSON.stringify({value:workspaces});
      ch._addedIds=[id];
    } else if(type==='AKS'){
      const raw=safeParse(gv('in_aks'));const clusters=raw?ext(raw,['value']):[];
      const id=ch.params.ResourceId||('aks-design-'+Date.now());ch.params.ResourceId=id;
      clusters.push({id:id,name:ch.params.Name||'new-aks-cluster',VpcId:ch.params.VpcId,tags:{Name:ch.params.Name||'new-aks-cluster'}});
      document.getElementById('in_aks').value=JSON.stringify({value:clusters});
      ch._addedIds=[id];
    }
  },
  add_security_group(ch){
    const raw=safeParse(gv('in_nsgs'));const sgs=raw?ext(raw,['value','SecurityGroups']):[];
    const id=ch.params.GroupId||('nsg-design-'+Date.now());ch.params.GroupId=id;
    const securityRules=(ch.params.IngressRules||[]).map((rule,i)=>({name:'rule-'+i,priority:100+i*10,direction:'Inbound',access:'Allow',protocol:rule.Protocol==='-1'||rule.Protocol==='*'?'*':rule.Protocol,sourcePortRange:'*',destinationPortRange:rule.FromPort===-1||rule.FromPort==null?'*':rule.ToPort!=null&&rule.ToPort!==rule.FromPort?rule.FromPort+'-'+rule.ToPort:String(rule.FromPort),sourceAddressPrefix:rule.CidrIp||'*',destinationAddressPrefix:'*'}));
    const sg={id:id,name:ch.params.Name||'new-nsg',GroupId:id,GroupName:ch.params.Name||'new-nsg',VpcId:ch.params.VpcId,securityRules,tags:{Name:ch.params.Name||'new-nsg'}};
    sgs.push(sg);
    document.getElementById('in_nsgs').value=JSON.stringify({value:sgs});
    ch._addedIds=[id];
  },
  remove_resource(ch){
    ch._removedIds=[ch.target.ResourceId];
    const type=designResourceType(designGatewayType(ch.target.ResourceType));
    if(type==='VM'||type==='VM'){
      const raw=safeParse(gv('in_vms'));if(!raw)return;
      const vms=ext(raw,['value']);
      document.getElementById('in_vms').value=JSON.stringify({value:vms.filter(v=>v.id!==ch.target.ResourceId&&v.InstanceId!==ch.target.ResourceId)});
    } else if(type==='SQL'||type==='RDS'){
      const raw=safeParse(gv('in_sql'));const sql=raw?ext(raw,['value']):[];
      document.getElementById('in_sql').value=JSON.stringify({value:sql.filter(d=>d.id!==ch.target.ResourceId)});
    } else if(type==='Redis'||type==='ElastiCache'){
      const raw=safeParse(gv('in_elasticache'));const c=raw?ext(raw,['value']):[];
      document.getElementById('in_elasticache').value=JSON.stringify({value:c.filter(d=>d.id!==ch.target.ResourceId)});
    } else if(type==='FunctionApp'||type==='Lambda'){
      const raw=safeParse(gv('in_funcapps'));const fns=raw?ext(raw,['value']):[];
      document.getElementById('in_funcapps').value=JSON.stringify({value:fns.filter(f=>f.id!==ch.target.ResourceId&&f.name!==ch.target.ResourceId)});
    } else if(type==='Subnet'){
      const raw=safeParse(gv('in_subnets'));const subs=raw?ext(raw,['value','Subnets']):[];
      const targetId=String(ch.target.ResourceId).toLowerCase();
      const keepSubnet=sub=>String(sub.SubnetId||sub.id||'').toLowerCase()!==targetId;
      document.getElementById('in_subnets').value=JSON.stringify({value:subs.filter(keepSubnet)});
      const vnetRaw=safeParse(gv('in_vnets'));
      if(vnetRaw){
        ext(vnetRaw,['value','VirtualNetworks']).forEach(vnet=>{
          [vnet,vnet.properties].filter(Boolean).forEach(props=>{
            if(Array.isArray(props.subnets))props.subnets=props.subnets.filter(keepSubnet);
          });
        });
        document.getElementById('in_vnets').value=JSON.stringify(vnetRaw);
      }
    } else if(type==='Synapse'){
      const raw=safeParse(gv('in_synapse'));const workspaces=raw?ext(raw,['value']):[];
      document.getElementById('in_synapse').value=JSON.stringify({value:workspaces.filter(d=>d.id!==ch.target.ResourceId)});
    } else if(type==='AKS'){
      const raw=safeParse(gv('in_aks'));const c=raw?ext(raw,['value']):[];
      document.getElementById('in_aks').value=JSON.stringify({value:c.filter(d=>d.id!==ch.target.ResourceId)});
    } else if(type==='Container'){
      const raw=safeParse(gv('in_containers'));const containers=raw?ext(raw,['value']):[];
      document.getElementById('in_containers').value=JSON.stringify({value:containers.filter(d=>d.id!==ch.target.ResourceId)});
    } else if(type==='AZFW'){
      const raw=safeParse(gv('in_azfws'));const firewalls=raw?ext(raw,['value']):[];
      document.getElementById('in_azfws').value=JSON.stringify({value:firewalls.filter(d=>d.id!==ch.target.ResourceId&&d.InternetGatewayId!==ch.target.ResourceId)});
    } else if(type==='NAT'){
      const raw=safeParse(gv('in_nats'));const nats=raw?ext(raw,['value','NatGateways']):[];
      document.getElementById('in_nats').value=JSON.stringify({value:nats.filter(g=>g.id!==ch.target.ResourceId&&g.NatGatewayId!==ch.target.ResourceId)});
    } else if(type==='PVTEP'||type==='VPCE'){
      const raw=safeParse(gv('in_pvteps'));const pvteps=raw?ext(raw,['value','PrivateEndpoints']):[];
      document.getElementById('in_pvteps').value=JSON.stringify({value:pvteps.filter(g=>g.id!==ch.target.ResourceId)});
    }
  }
};

// Azure location → availability-zone choices used by design forms.
const _azureLocationZones={
  eastus:['1','2','3'],
  eastus2:['1','2','3'],
  westus2:['1','2','3'],
  westus3:['1','2','3'],
  centralus:['1','2','3'],
  southcentralus:['1','2','3'],
  westeurope:['1','2','3'],
  northeurope:['1','2','3'],
  uksouth:['1','2','3'],
  francecentral:['1','2','3'],
  germanywestcentral:['1','2','3'],
  swedencentral:['1','2','3'],
  southeastasia:['1','2','3'],
  eastasia:['1','2','3'],
  japaneast:['1','2','3'],
  australiaeast:['1','2','3'],
  canadacentral:['1','2','3'],
  brazilsouth:['1','2','3'],
  koreacentral:['1','2','3']
};
let _designRegion='eastus';

// Azure Constraints Registry (sourced from official Azure docs)
const _azureConstraints={
  vnet:{
    cidrPrefixMin:8,cidrPrefixMax:29,maxAddressSpaces:500,maxPerSubscription:500,
    reservedCidrs:['168.63.129.16/32'],
    rfc1918:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']
  },
  subnet:{cidrPrefixMin:8,cidrPrefixMax:29,reservedIps:5,maxPerVnet:3000},
  nat:{maxPerSubnet:1,requiresPublicIp:true},
  routeTable:{maxPerSubscription:200,maxRoutesPerTable:400,reservedDestinations:['168.63.129.16/32'],systemRouteImmutable:true},
  nsg:{maxPerSubscription:5000,maxInboundRules:1000,maxOutboundRules:1000,maxPerNic:1,maxPerSubnet:1},
  peering:{maxPerVnet:500,noOverlappingCidrs:true,onePeerPerVnetPair:true}
};

// Validation Engine: validate a design change against Azure constraints
function validateDesignChange(change,ctx){
  const errors=[],warnings=[];
  const vpcs=ctx?ctx.vnets||ctx.vpcs||[]:ext(safeParse(gv('in_vnets')),['value','VirtualNetworks']);
  const subnets=ctx?ctx.subnets||[]:ext(safeParse(gv('in_subnets')),['value','Subnets']);
  const nats=ctx?ctx.nats||ctx.natGateways||[]:ext(safeParse(gv('in_nats')),['value','NatGateways']);
  const sgs=ctx?ctx.nsgs||ctx.sgs||[]:ext(safeParse(gv('in_nsgs')),['value','SecurityGroups']);
  const rts=ctx?ctx.udrs||ctx.rts||[]:ext(safeParse(gv('in_udrs')),['value','RouteTables']);
  const pubSubs=ctx?ctx.pubSubs||new Set():new Set();

  if(change.action==='add_vpc'){
    const p=change.params;
    const addrCidr=p.CidrBlock||p.addressPrefix;
    const cidr=parseCIDR(addrCidr);
    if(!cidr){errors.push('Invalid CIDR: '+addrCidr);return{valid:false,errors,warnings}}
    const prefix=parseInt(addrCidr.split('/')[1],10);
    if(prefix<_azureConstraints.vnet.cidrPrefixMin||prefix>_azureConstraints.vnet.cidrPrefixMax)
      errors.push('VNet address space must be /8 to /29, got /'+prefix);
    const isRfc1918=_azureConstraints.vnet.rfc1918.some(r=>cidrContains(r,addrCidr));
    if(!isRfc1918)warnings.push('CIDR '+addrCidr+' is not RFC 1918: private subnets may have issues');
    if(_azureConstraints.vnet.reservedCidrs.some(r=>cidrOverlap(addrCidr,r)))
      warnings.push('168.63.129.16/32 conflicts with Azure internal health probe');
    vpcs.forEach(v=>{const vCidr=v.CidrBlock||(v.properties?.addressSpace?.addressPrefixes?.[0])||'';if(vCidr&&cidrOverlap(addrCidr,vCidr))errors.push('Overlaps existing VNet '+gn(v,v.id||v.VpcId)+' ('+vCidr+')')});
    if(vpcs.length>=_azureConstraints.vnet.maxPerSubscription)warnings.push('Exceeds default quota of '+_azureConstraints.vnet.maxPerSubscription+' VNets per subscription (adjustable)');
  }

  if(change.action==='add_subnet'){
    const p=change.params;
    const subCidr=p.CidrBlock||p.addressPrefix;
    const cidr=parseCIDR(subCidr);
    if(!cidr){errors.push('Invalid CIDR: '+subCidr);return{valid:false,errors,warnings}}
    const prefix=parseInt(subCidr.split('/')[1],10);
    if(prefix<_azureConstraints.subnet.cidrPrefixMin||prefix>_azureConstraints.subnet.cidrPrefixMax)
      errors.push('Subnet CIDR must be /8 to /29, got /'+prefix);
    const vpc=vpcs.find(v=>(v.id||v.VpcId)===p.VpcId);
    if(!vpc){errors.push('VNet '+p.VpcId+' not found');return{valid:false,errors,warnings}}
    const vnetCidrs=designVNetAddressPrefixes(vpc);
    if(vnetCidrs.length&&!vnetCidrs.some(cidr=>cidrContains(cidr,subCidr)))errors.push('Subnet CIDR '+subCidr+' is not within VNet address space '+vnetCidrs.join(', '));
    const vpcSubs=subnets.filter(s=>s.VpcId===p.VpcId);
    vpcSubs.forEach(s=>{const sCidr=s.CidrBlock||(s.properties?.addressPrefix)||'';if(sCidr&&cidrOverlap(subCidr,sCidr))errors.push('Overlaps subnet '+gn(s,s.id||s.SubnetId)+' ('+sCidr+')')});
    if(vpcSubs.length>=_azureConstraints.subnet.maxPerVnet)warnings.push('Exceeds default quota of '+_azureConstraints.subnet.maxPerVnet+' subnets per VNet');
    const usable=Math.pow(2,32-prefix)-_azureConstraints.subnet.reservedIps;
    warnings.push(usable+' usable IPs ('+_azureConstraints.subnet.reservedIps+' reserved by Azure)');
  }

  if(change.action==='split_subnet'){
    const plan=designSplitSubnetPlan(change,subnets);
    errors.push(...plan.errors);
    if(!plan.errors.length){
      const prefix=parseInt(plan.cidr.split('/')[1],10);
      const newPrefix=prefix+1;
      const usable=Math.pow(2,32-newPrefix)-_azureConstraints.subnet.reservedIps;
      warnings.push('Each half: /'+newPrefix+' = '+usable+' usable IPs');
      if(usable<16)warnings.push('Very small subnets: limited IP capacity');
    }
    const targetSubId=change.target.id||change.target.SubnetId;
    const insts=ctx?(ctx.instBySub||{})[targetSubId]||[]:[];
    if(insts.length)warnings.push(insts.length+' VM(s) will require IP-based migration');
  }

  if(change.action==='add_gateway'){
    const p=change.params;
    if(designGatewayType(p.GatewayType)==='AZFW'){
      const subnet=subnets.find(s=>(s.SubnetId||s.id)===p.SubnetId);
      if(!subnet||gn(subnet,'')!=='AzureFirewallSubnet')warnings.push('Azure Firewall requires a subnet named AzureFirewallSubnet in the selected VNet.');
    }
    if(p.GatewayType==='NAT'){
      if(!p.publicIpId&&!p.publicIpPrefixId)
        warnings.push('NAT Gateway requires a Public IP or Public IP Prefix association');
      const subId=p.SubnetId||p.subnetId;
      const subNats=nats.filter(n=>n.properties?.subnets?.some(s=>(s.id||'')===subId));
      if(subNats.length>=_azureConstraints.nat.maxPerSubnet)errors.push('Subnet already has a NAT Gateway (limit: 1 per subnet)');
    }
  }

  if(change.action==='add_route'){
    const p=change.params;const t=change.target;
    const dest=p.DestinationCidrBlock||p.addressPrefix;
    if(!designRouteNextHop(p))errors.push('Select an Azure next-hop type; VirtualAppliance also requires an IPv4 next-hop address.');
    if(!parseCIDR(dest)&&dest!=='0.0.0.0/0')errors.push('Invalid destination CIDR: '+dest);
    if(_azureConstraints.routeTable.reservedDestinations.some(r=>cidrContains(r,dest)))
      errors.push('Cannot add routes to 168.63.129.16/32 (reserved for Azure health probes)');
    const rtId=t.RouteTableId||t.id;
    const rt=rts.find(r=>(r.id||r.RouteTableId)===rtId);
    if(rt){
      const rtRoutes=rt.Routes||rt.properties?.routes||[];
      if(rtRoutes.some(r=>(r.DestinationCidrBlock||r.properties?.addressPrefix)===dest))
        errors.push('Route table already has a route for '+dest);
      if(rtRoutes.length>=_azureConstraints.routeTable.maxRoutesPerTable)
        warnings.push('Exceeds default quota of '+_azureConstraints.routeTable.maxRoutesPerTable+' routes per table');
    }
    if(dest==='0.0.0.0/0'&&p.nextHopType==='Internet')
      warnings.push('This will allow direct internet access from associated subnets');
  }

  if(change.action==='add_security_group'){
    const p=change.params;
    if(sgs.length>=_azureConstraints.nsg.maxPerSubscription)
      warnings.push('Exceeds default quota of '+_azureConstraints.nsg.maxPerSubscription+' NSGs per subscription');
    const inboundRules=(p.IngressRules||p.properties?.securityRules||[]).filter(r=>r.properties?.direction==='Inbound'||!r.properties);
    if(inboundRules.length>_azureConstraints.nsg.maxInboundRules)
      errors.push('Exceeds limit of '+_azureConstraints.nsg.maxInboundRules+' inbound rules per NSG');
    inboundRules.forEach(r=>{
      const src=r.CidrIp||r.properties?.sourceAddressPrefix||'';
      const port=r.FromPort||r.properties?.destinationPortRange||'';
      if(src==='0.0.0.0/0'&&port!=='80'&&port!=='443'&&port!==80&&port!==443)
        warnings.push('Rule allows 0.0.0.0/0 on port '+port+': consider restricting source CIDR');
    });
  }

  if(change.action==='add_resource'){
    const p=change.params;
    if(p.SubnetId){
      const sub=subnets.find(s=>s.SubnetId===p.SubnetId);
      if(sub){
        const prefix=parseInt(sub.CidrBlock.split('/')[1],10);
        const usable=Math.pow(2,32-prefix)-_azureConstraints.subnet.reservedIps;
        const currentInst=(ctx?(ctx.instBySub||{})[p.SubnetId]||[]:ext(safeParse(gv('in_vms')),['value']).filter(i=>i.properties?.networkProfile?.networkInterfaces?.some(n=>n.id?.includes(p.SubnetId)))).length;
        const remaining=usable-currentInst;
        if(remaining<=0)warnings.push('Subnet '+gn(sub,sub.SubnetId)+' has no remaining IP capacity ('+usable+' usable, '+currentInst+' used)');
        else if(remaining<5)warnings.push('Subnet '+gn(sub,sub.SubnetId)+' has only '+remaining+' IPs remaining');
      }
    }
  }

  if(change.action==='remove_resource'){
    const t=change.target;
    if(t.ResourceType==='Firewall'){
      // Check if any UDRs route through this Azure Firewall
      const affectedRts=rts.filter(rt=>(rt.Routes||rt.properties?.routes||[]).some(r=>(r.properties?.nextHopIpAddress||'')&&(r.properties?.nextHopType||'')==='VirtualAppliance'));
      if(affectedRts.length)warnings.push(affectedRts.length+' route table(s) may reference this firewall: subnets will lose traffic inspection');
    }
    if(t.ResourceType==='NAT'){
      const affectedSubs=subnets.filter(s=>s.properties?.natGateway?.id===t.ResourceId);
      if(affectedSubs.length)warnings.push(affectedSubs.length+' subnet(s) use this NAT Gateway: they will lose outbound connectivity');
    }
    if(t.ResourceType==='Subnet'){
      const sub=subnets.find(s=>(s.id||s.SubnetId)===t.ResourceId);
      if(sub){
        const insts=(ctx?(ctx.instBySub||{})[t.ResourceId]||[]:ext(safeParse(gv('in_vms')),['value']).filter(i=>i.properties?.networkProfile?.networkInterfaces?.some(n=>n.id?.includes(t.ResourceId))));
        if(insts.length)warnings.push(insts.length+' VM(s) in this subnet will be deallocated');
        // Check NATs associated with this subnet
        const subNats=nats.filter(n=>n.properties?.subnets?.some(s=>(s.id||'')===(sub.id||t.ResourceId)));
        if(subNats.length)warnings.push(subNats.length+' NAT Gateway(s) associated with this subnet');
      }
    }
  }

  return{valid:errors.length===0,errors,warnings};
}

// Full-state cross-change validation
function validateDesignState(changes,ctx){
  const errors=[],warnings=[],stats={subnetsAdded:0,gatewaysAdded:0,resourcesAdded:0,removed:0,routes:0,sgs:0};
  changes.forEach(ch=>{
    if(ch.action==='add_subnet')stats.subnetsAdded++;
    if(ch.action==='add_gateway')stats.gatewaysAdded++;
    if(ch.action==='add_resource')stats.resourcesAdded++;
    if(ch.action==='remove_resource')stats.removed++;
    if(ch.action==='add_route')stats.routes++;
    if(ch.action==='add_security_group')stats.sgs++;
  });
  // Cross-check: subnet overlaps within each VNet
  if(ctx){
    const subsByVnet={};
    (ctx.subnets||[]).forEach(s=>{const vid=s.VpcId||(s.id||'').split('/subnets/')[0];(subsByVnet[vid]=subsByVnet[vid]||[]).push(s)});
    Object.entries(subsByVnet).forEach(([vid,subs])=>{
      for(let i=0;i<subs.length;i++){for(let j=i+1;j<subs.length;j++){
        const cidrI=subs[i].CidrBlock||(subs[i].properties?.addressPrefix)||'';
        const cidrJ=subs[j].CidrBlock||(subs[j].properties?.addressPrefix)||'';
        if(cidrI&&cidrJ&&cidrOverlap(cidrI,cidrJ))
          errors.push('Subnets '+gn(subs[i],subs[i].id||subs[i].SubnetId)+' and '+gn(subs[j],subs[j].id||subs[j].SubnetId)+' have overlapping CIDRs');
      }}
    });
    // NAT Gateway without public IP check
    (ctx.natGateways||ctx.nats||[]).forEach(n=>{
      if(!n.properties?.publicIpAddresses?.length)
        warnings.push('NAT Gateway '+gn(n,n.id||n.NatGatewayId)+' has no public IP: will not function');
    });
    // Peering CIDR overlap check
    const peerPairs=[];
    (ctx.peerings||[]).forEach(p=>{
      const local=p.properties?.remoteAddressSpace?.addressPrefixes?.[0]||p.RequesterVpcInfo?.CidrBlock||'';
      const remote=p.properties?.remoteAddressSpace?.addressPrefixes?.[0]||p.AccepterVpcInfo?.CidrBlock||'';
      const localVnet=p.properties?.virtualNetwork?.id||p.RequesterVpcInfo?.VpcId||'';
      const remoteVnet=p.properties?.remoteVirtualNetwork?.id||p.AccepterVpcInfo?.VpcId||'';
      if(local&&remote&&cidrOverlap(local,remote))
        errors.push('VNet Peering '+gn(p,p.id||p.VpcPeeringConnectionId)+': CIDRs overlap: '+local+' / '+remote);
      if(localVnet&&remoteVnet){
        const pair=[localVnet,remoteVnet].sort().join(':');
        if(peerPairs.includes(pair))warnings.push('Duplicate peering between '+localVnet+' and '+remoteVnet);
        peerPairs.push(pair);
      }
    });
  }
  return{valid:errors.length===0,errors,warnings,stats};
}

// Detect availability zones from loaded data, then design region, then fallback
function _detectAZs(){
  const raw=safeParse(gv('in_vms'));
  const vms=raw?ext(raw,['value']):[];
  const azSet=new Set();
  vms.forEach(v=>{if(v.zones)v.zones.forEach(z=>azSet.add(z));else if(v.location)azSet.add(v.location)});
  if(azSet.size>0)return Array.from(azSet).sort();
  // Use design region
  if(_azureLocationZones[_designRegion])return _azureLocationZones[_designRegion];
  return['1','2','3'];
}

// Design Mode UI: forms shown in detail panel
function showDesignForm(formType,context){
  const designCtx=designRuntimeData();
  const dpBody=document.getElementById('dpBody');
  const dpTitle=document.getElementById('dpTitle');
  const dpSub=document.getElementById('dpSub');
  const dp=document.getElementById('detailPanel');
  let h='';
  if(formType==='add_subnet'){
    dpTitle.textContent='Add Subnet';dpSub.textContent='VNet: '+gn(context.vpc,context.vpc.VpcId);
    const vpcCidrs=designVNetAddressPrefixes(context.vpc);
    const azs=_detectAZs();
    h='<div class="design-form"><label>CIDR Block</label><input id="df_cidr" placeholder="e.g. 10.0.4.0/24"><div class="form-hint" id="df_hint">Must be within '+esc(vpcCidrs.join(', '))+'</div><div class="form-error" id="df_err" style="display:none"></div>';
    h+='<label>Name</label><input id="df_name" placeholder="e.g. app-tier-1a">';
    h+='<label>Availability Zone</label><select id="df_az">'+azs.map(az=>'<option>'+az+'</option>').join('')+'</select>';
    h+='<label>Type</label><select id="df_type"><option value="false">Private</option><option value="true">Public</option></select>';
    h+='<div class="form-actions"><button class="btn-confirm" id="df_ok" disabled>Add Subnet</button><button class="btn-cancel" onclick="document.getElementById(\'detailPanel\').classList.remove(\'open\')">Cancel</button></div></div>';
    dpBody.innerHTML=h;dp.classList.add('open');
    const cidrInput=document.getElementById('df_cidr');const errEl=document.getElementById('df_err');const okBtn=document.getElementById('df_ok');
    cidrInput.addEventListener('input',()=>{
      const val=cidrInput.value.trim();const p=parseCIDR(val);
      if(!val){errEl.style.display='none';okBtn.disabled=true;cidrInput.classList.remove('invalid');return}
      if(!p){errEl.textContent='Invalid CIDR notation';errEl.style.display='block';okBtn.disabled=true;cidrInput.classList.add('invalid');return}
      if(!vpcCidrs.some(cidr=>cidrContains(cidr,val))){errEl.textContent='Not within VNet address space '+vpcCidrs.join(', ');errEl.style.display='block';okBtn.disabled=true;cidrInput.classList.add('invalid');return}
      // Check overlap with existing subnets
      const existSubs=designSubnetsForVNet(designCtx,context.vpc.VpcId);
      const overlap=existSubs.find(s=>cidrOverlap(val,s.CidrBlock));
      if(overlap){errEl.textContent='Overlaps with '+gn(overlap,overlap.SubnetId)+' ('+overlap.CidrBlock+')';errEl.style.display='block';okBtn.disabled=true;cidrInput.classList.add('invalid');return}
      errEl.style.display='none';okBtn.disabled=false;cidrInput.classList.remove('invalid');
    });
    okBtn.addEventListener('click',()=>{
      addDesignChange({action:'add_subnet',target:{VpcId:context.vpc.VpcId},params:{VpcId:context.vpc.VpcId,SubnetId:'subnet-design-'+Date.now(),CidrBlock:cidrInput.value.trim(),AZ:document.getElementById('df_az').value,isPublic:document.getElementById('df_type').value==='true',Name:document.getElementById('df_name').value||'New Subnet'}});
      dp.classList.remove('open');
    });
  } else if(formType==='split_subnet'){
    const subnetId=context.subnet.SubnetId||context.subnet.id;
    const change={action:'split_subnet',target:{SubnetId:subnetId},params:{}};
    const plan=designSplitSubnetPlan(change,designCtx.subnets||[]);
    dpTitle.textContent='Split Subnet';dpSub.textContent=gn(context.subnet,subnetId)+' ('+(plan.cidr||'')+')';
    if(plan.prefixErrors.length){dpBody.innerHTML='<div class="design-form"><div class="form-error">'+esc(plan.prefixErrors.join(' '))+'</div></div>';dp.classList.add('open');return}
    change.target.CidrBlock=plan.cidr;
    const halves=plan.halves;
    h='<div class="design-form"><label>This will create two subnets:</label>';
    h+='<div class="form-hint" style="margin:6px 0">'+halves[0]+' and '+halves[1]+'</div>';
    h+='<label>Name A</label><input id="df_name_a" value="'+esc(gn(context.subnet,''))+'_a">';
    h+='<label>Name B</label><input id="df_name_b" value="'+esc(gn(context.subnet,''))+'_b">';
    h+='<div class="form-error" id="df_err" style="display:none"></div>';
    h+='<div class="form-actions"><button class="btn-confirm" id="df_ok">Split</button><button class="btn-cancel" onclick="document.getElementById(\'detailPanel\').classList.remove(\'open\')">Cancel</button></div></div>';
    dpBody.innerHTML=h;dp.classList.add('open');
    const nameA=document.getElementById('df_name_a'),nameB=document.getElementById('df_name_b'),okBtn=document.getElementById('df_ok'),errEl=document.getElementById('df_err');
    const validateNames=()=>{
      change.params.names=[nameA.value,nameB.value];
      const plan=designSplitSubnetPlan(change,designCtx.subnets||[]),errors=plan.errors;
      if(!errors.length)change.params.names=plan.names;
      errEl.textContent=errors.join(' ');errEl.style.display=errors.length?'block':'none';okBtn.disabled=errors.length>0;
      return !errors.length;
    };
    nameA.addEventListener('input',validateNames);nameB.addEventListener('input',validateNames);
    validateNames();
    document.getElementById('df_ok').addEventListener('click',()=>{
      if(!validateNames())return;
      addDesignChange(change);
      dp.classList.remove('open');
    });
  } else if(formType==='add_gateway'){
    dpTitle.textContent='Add Gateway';dpSub.textContent='VNet: '+gn(context.vpc,context.vpc.VpcId||context.vpc.id);
    h='<div class="design-form"><label>Gateway Type</label><select id="df_gwtype"><option value="AZFW">Azure Firewall</option><option value="NAT">NAT Gateway</option><option value="VPCE">Private Endpoint</option></select>';
    h+='<label>Name</label><input id="df_gwname" placeholder="e.g. prod-nat-1a">';
    h+='<div id="df_gw_extra"></div>';
    h+='<div class="form-actions"><button class="btn-confirm" id="df_ok">Add Gateway</button><button class="btn-cancel" onclick="document.getElementById(\'detailPanel\').classList.remove(\'open\')">Cancel</button></div></div>';
    dpBody.innerHTML=h;dp.classList.add('open');
    const gwType=document.getElementById('df_gwtype');const extra=document.getElementById('df_gw_extra');
    const updateExtra=()=>{
      if(gwType.value==='NAT'){
        const pubSubs=designPublicSubnets(designCtx,context.vpc.VpcId);
        extra.innerHTML='<label>Subnet (public)</label><select id="df_gwsub">'+pubSubs.map(s=>'<option value="'+esc(s.SubnetId)+'">'+gn(s,s.SubnetId)+'</option>').join('')+'</select>';
      } else if(gwType.value==='AZFW'){
        const subnets=designSubnetsForVNet(designCtx,context.vpc.VpcId||context.vpc.id).slice().sort((a,b)=>(gn(b,'')==='AzureFirewallSubnet')-(gn(a,'')==='AzureFirewallSubnet'));
        extra.innerHTML='<label>Azure Firewall subnet</label><select id="df_gwsub">'+subnets.map(s=>'<option value="'+esc(s.SubnetId||s.id)+'">'+esc(gn(s,s.SubnetId||s.id))+'</option>').join('')+'</select>';
      } else if(gwType.value==='VPCE'){extra.innerHTML='<label>Service</label><input id="df_gwsvc" placeholder="Microsoft.Storage">'} else {extra.innerHTML=''}
    };
    gwType.addEventListener('change',updateExtra);updateExtra();
    document.getElementById('df_ok').addEventListener('click',()=>{
      const params={VpcId:context.vpc.VpcId||context.vpc.id,GatewayType:gwType.value,Name:document.getElementById('df_gwname').value};
      if(gwType.value==='NAT'||gwType.value==='AZFW'){const sel=document.getElementById('df_gwsub');if(sel)params.SubnetId=sel.value}
      if(gwType.value==='VPCE'){const svc=document.getElementById('df_gwsvc');if(svc)params.ServiceName=svc.value}
      addDesignChange({action:'add_gateway',target:{VpcId:context.vpc.VpcId||context.vpc.id},params});
      dp.classList.remove('open');
    });
  } else if(formType==='add_resource'){
    dpTitle.textContent='Add Resource';dpSub.textContent='Subnet: '+gn(context.subnet,context.subnet.SubnetId);
    h='<div class="design-form"><label>Resource Type</label><select id="df_restype"><option value="VM">Virtual Machine</option><option value="SQL">SQL Database</option><option value="Redis">Redis Cache</option><option value="FunctionApp">Function App</option><option value="Container">Container Instance</option><option value="Synapse">Synapse Workspace</option></select>';
    h+='<label>Name</label><input id="df_resname" placeholder="e.g. web-server-01">';
    h+='<div class="form-actions"><button class="btn-confirm" id="df_ok">Add Resource</button><button class="btn-cancel" onclick="document.getElementById(\'detailPanel\').classList.remove(\'open\')">Cancel</button></div></div>';
    dpBody.innerHTML=h;dp.classList.add('open');
    document.getElementById('df_ok').addEventListener('click',()=>{
      addDesignChange({action:'add_resource',target:{SubnetId:context.subnet.SubnetId},params:{SubnetId:context.subnet.SubnetId,VpcId:context.subnet.VpcId,ResourceType:document.getElementById('df_restype').value,Name:document.getElementById('df_resname').value}});
      dp.classList.remove('open');
    });
  } else if(formType==='add_route'){
    dpTitle.textContent='Add Route';dpSub.textContent='Route Table: '+(context.rtName||context.rtId);
    // Gather available gateways for this VNet
    const vpcId=context.vpcId;
    const gws=designGatewaysForVNet(designCtx,vpcId);
    h='<div class="design-form"><label>Destination CIDR</label><input id="df_dest" placeholder="e.g. 0.0.0.0/0"><div class="form-error" id="df_err" style="display:none"></div>';
    h+='<label>Target</label><select id="df_target">';
    h+=gws.map(g=>'<option value="'+g.id+'">'+g.label+'</option>').join('');
    h+=['Internet','None','VnetLocal','VirtualNetworkGateway','VirtualAppliance'].map(type=>'<option value="'+type+'">'+type+'</option>').join('');
    h+='</select>';
    h+='<label>Appliance IPv4 address</label><input id="df_next_hop_ip" placeholder="e.g. 10.0.0.4">';
    h+='<div class="form-actions"><button class="btn-confirm" id="df_ok">Add Route</button><button class="btn-cancel" onclick="document.getElementById(\'detailPanel\').classList.remove(\'open\')">Cancel</button></div></div>';
    dpBody.innerHTML=h;dp.classList.add('open');
    const destInput=document.getElementById('df_dest');const errEl=document.getElementById('df_err');const okBtn=document.getElementById('df_ok');
    destInput.addEventListener('input',()=>{
      const val=destInput.value.trim();
      if(!val){errEl.style.display='none';okBtn.disabled=true;return}
      if(!parseCIDR(val)&&val!=='0.0.0.0/0'){errEl.textContent='Invalid CIDR';errEl.style.display='block';okBtn.disabled=true;return}
      errEl.style.display='none';okBtn.disabled=false;
    });
    const targetInput=document.getElementById('df_target');
    const hopInput=document.getElementById('df_next_hop_ip');
    const updateHop=()=>{const gateway=gws.find(g=>g.id===targetInput.value);const type=gateway?gateway.nextHopType:targetInput.value;hopInput.disabled=type!=='VirtualAppliance';hopInput.value=gateway&&gateway.nextHopIp||''};
    targetInput.addEventListener('change',updateHop);updateHop();
    okBtn.addEventListener('click',()=>{
      const dest=destInput.value.trim();const tgt=document.getElementById('df_target').value;
      if(!dest||!tgt)return;
      const gateway=gws.find(g=>g.id===tgt);
      const params={DestinationCidrBlock:dest,TargetId:tgt,nextHopType:gateway?gateway.nextHopType:tgt,NextHopIp:hopInput.value.trim()};
      if(!designRouteNextHop(params)){errEl.textContent='VirtualAppliance requires a valid IPv4 next-hop address';errEl.style.display='block';return}
      addDesignChange({action:'add_route',target:{RouteTableId:context.rtId,VpcId:vpcId},params});
      dp.classList.remove('open');
    });
  } else if(formType==='add_security_group'){
    dpTitle.textContent='Add NSG';dpSub.textContent='VNet: '+gn(context.vpc,context.vpc.VpcId);
    h='<div class="design-form"><label>Name</label><input id="df_sgname" placeholder="e.g. web-tier-sg">';
    h+='<label>Description</label><input id="df_sgdesc" placeholder="e.g. Allow HTTP/HTTPS inbound">';
    h+='<div style="margin:8px 0 4px;font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1));color:var(--accent-orange);font-weight:600;text-transform:uppercase;letter-spacing:.5px">Inbound Rules</div>';
    h+='<div id="df_sg_rules"></div>';
    h+='<button type="button" id="df_sg_add_rule" style="background:transparent;border:1px dashed var(--border);border-radius:4px;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif;font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1));padding:3px 8px;cursor:pointer;width:100%;margin:4px 0">+ Add Rule</button>';
    h+='<div class="form-actions"><button class="btn-confirm" id="df_ok">Create SG</button><button class="btn-cancel" onclick="document.getElementById(\'detailPanel\').classList.remove(\'open\')">Cancel</button></div></div>';
    dpBody.innerHTML=h;dp.classList.add('open');
    let ruleCount=0;
    const rulesDiv=document.getElementById('df_sg_rules');
    function addRuleRow(){
      const idx=ruleCount++;
      const row=document.createElement('div');
      row.style.cssText='display:flex;gap:4px;margin-bottom:4px;align-items:center';
      row.innerHTML='<select id="df_sgr_proto_'+idx+'" style="width:60px;background:var(--bg-input);border:1px solid var(--border);border-radius:3px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:9px;padding:3px"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="-1">All</option></select>'
        +'<input id="df_sgr_port_'+idx+'" placeholder="Port" style="width:50px;background:var(--bg-input);border:1px solid var(--border);border-radius:3px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:9px;padding:3px">'
        +'<input id="df_sgr_cidr_'+idx+'" placeholder="0.0.0.0/0" value="0.0.0.0/0" style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:3px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:9px;padding:3px">';
      rulesDiv.appendChild(row);
    }
    addRuleRow();
    document.getElementById('df_sg_add_rule').addEventListener('click',addRuleRow);
    document.getElementById('df_ok').addEventListener('click',()=>{
      const rules=[];
      for(let i=0;i<ruleCount;i++){
        const proto=document.getElementById('df_sgr_proto_'+i)?.value||'tcp';
        const port=parseInt(document.getElementById('df_sgr_port_'+i)?.value,10);
        const cidr=document.getElementById('df_sgr_cidr_'+i)?.value||'0.0.0.0/0';
        if(proto==='-1')rules.push({Protocol:'-1',FromPort:-1,ToPort:-1,CidrIp:cidr});
        else if(!isNaN(port))rules.push({Protocol:proto,FromPort:port,ToPort:port,CidrIp:cidr});
      }
      addDesignChange({action:'add_security_group',target:{VpcId:context.vpc.VpcId},params:{VpcId:context.vpc.VpcId,Name:document.getElementById('df_sgname').value||'new-sg',Description:document.getElementById('df_sgdesc').value||'',IngressRules:rules}});
      dp.classList.remove('open');
    });
  } else if(formType==='add_vpc'){
    dpTitle.textContent='Create VNet';dpSub.textContent='Design a new Virtual Network';
    const locations=Object.keys(_azureLocationZones);
    h='<div class="design-form"><label>VNet Name</label><input id="df_vpcname" placeholder="e.g. production-vnet">';
    h+='<label>CIDR Block</label><input id="df_vpccidr" placeholder="e.g. 10.0.0.0/16">';
    h+='<div class="form-hint" id="df_hint">RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16</div>';
    h+='<div class="form-error" id="df_err" style="display:none"></div>';
    h+='<div id="df_vpc_warnings" style="display:none"></div>';
    h+='<div style="display:flex;gap:8px;margin:6px 0"><button type="button" class="btn-cancel" style="flex:none;padding:2px 8px;font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1))" onclick="document.getElementById(\'df_vpccidr\').value=\'10.0.0.0/16\';document.getElementById(\'df_vpccidr\').dispatchEvent(new Event(\'input\'))">10.0/16</button><button type="button" class="btn-cancel" style="flex:none;padding:2px 8px;font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1))" onclick="document.getElementById(\'df_vpccidr\').value=\'172.16.0.0/16\';document.getElementById(\'df_vpccidr\').dispatchEvent(new Event(\'input\'))">172.16/16</button><button type="button" class="btn-cancel" style="flex:none;padding:2px 8px;font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1))" onclick="document.getElementById(\'df_vpccidr\').value=\'192.168.0.0/16\';document.getElementById(\'df_vpccidr\').dispatchEvent(new Event(\'input\'))">192.168/16</button></div>';
    h+='<label>Location</label><select id="df_vpclocation">'+locations.map(r=>'<option value="'+r+'"'+(r===_designRegion?' selected':'')+'>'+r+' ('+(_azureLocationZones[r]||[]).length+' zones)</option>').join('')+'</select>';
    h+='<div id="df_vpc_ips" style="font-size:calc(8px * var(--txt-scale,1) * var(--dp-txt-scale,1));color:var(--text-muted);margin:4px 0;padding:4px 6px;background:rgba(255,255,255,.03);border-radius:3px;display:none"></div>';
    h+='<div class="form-actions"><button class="btn-confirm" id="df_ok" disabled>Create VNet</button><button class="btn-cancel" onclick="document.getElementById(\'detailPanel\').classList.remove(\'open\')">Cancel</button></div></div>';
    dpBody.innerHTML=h;dp.classList.add('open');
    const cidrInput=document.getElementById('df_vpccidr');const errEl=document.getElementById('df_err');const okBtn=document.getElementById('df_ok');
    const warnEl=document.getElementById('df_vpc_warnings');const ipsEl=document.getElementById('df_vpc_ips');
    cidrInput.addEventListener('input',()=>{
      const val=cidrInput.value.trim();
      if(!val){errEl.style.display='none';warnEl.style.display='none';ipsEl.style.display='none';okBtn.disabled=true;cidrInput.classList.remove('invalid');return}
      const result=validateDesignChange({action:'add_vpc',params:{CidrBlock:val}},designCtx);
      if(!result.valid){errEl.textContent=result.errors[0];errEl.style.display='block';okBtn.disabled=true;cidrInput.classList.add('invalid');warnEl.style.display='none'}
      else{errEl.style.display='none';okBtn.disabled=false;cidrInput.classList.remove('invalid')}
      if(result.warnings.length){warnEl.innerHTML=result.warnings.map(w=>'<div class="form-hint" style="color:var(--accent-orange)">'+esc(w)+'</div>').join('');warnEl.style.display='block'}
      else{warnEl.style.display='none'}
      // IP calculator
      const p=parseCIDR(val);
      if(p){const prefix=parseInt(val.split('/')[1],10);const total=Math.pow(2,32-prefix);ipsEl.innerHTML='<b>'+total.toLocaleString()+'</b> total IPs | <b>'+(total-5).toLocaleString()+'</b> usable per subnet (Azure reserves 5)';ipsEl.style.display='block'}
      else{ipsEl.style.display='none'}
    });
    document.getElementById('df_vpclocation').addEventListener('change',function(){_designRegion=this.value});
    okBtn.addEventListener('click',()=>{
      _designRegion=document.getElementById('df_vpclocation').value;
      addDesignChange({action:'add_vpc',target:{},params:{CidrBlock:cidrInput.value.trim(),Name:document.getElementById('df_vpcname').value||'New VNet',Location:_designRegion}});
      dp.classList.remove('open');
    });
  }
}

// Design toolbar injected into detail panel when in design mode
function injectDesignToolbar(container,context){
  if(!_designMode)return;
  const tb=document.createElement('div');tb.className='design-toolbar';
  if(context.type==='vpc'){
    tb.appendChild(designToolbarButton('+ Subnet',()=>showDesignForm('add_subnet',{vpc:context.data})));
    tb.appendChild(designToolbarButton('+ Gateway',()=>showDesignForm('add_gateway',{vpc:context.data})));
    tb.appendChild(designToolbarButton('+ NSG',()=>showDesignForm('add_security_group',{vpc:context.data})));
  } else if(context.type==='subnet'){
    const subnet=context.data;
    const rt=designRouteTableForSubnet(designRuntimeData(),subnet.SubnetId);
    tb.appendChild(designToolbarButton('Split',()=>showDesignForm('split_subnet',{subnet})));
    tb.appendChild(designToolbarButton('+ Resource',()=>showDesignForm('add_resource',{subnet})));
    if(rt)tb.appendChild(designToolbarButton('+ Route',()=>showDesignForm('add_route',{rtId:rt.RouteTableId,rtName:gn(rt,rt.RouteTableId),vpcId:subnet.VpcId})));
    tb.appendChild(designToolbarButton('Remove',()=>addDesignChange({action:'remove_resource',target:{ResourceId:subnet.SubnetId,ResourceType:'Subnet'}})));
  } else if(context.type==='gateway'){
    const gwType=designGatewayType(context.gwType);
    const gwId=context.data;
    if(gwType==='AZFW'||gwType==='NAT'||gwType==='VPCE'){
      tb.appendChild(designToolbarButton('Remove '+gwType,()=>addDesignChange({action:'remove_resource',target:{ResourceId:gwId,ResourceType:gwType}})));
    }
  }
  container.insertBefore(tb,container.firstChild);
}

// Change log panel
function renderChangeLog(){
  const cl=document.getElementById('changeLog');
  if(!_designChanges.length){cl.style.display='none';return}
  cl.style.display='block';
  const invalids=_designChanges.filter(c=>c._invalid).length;
  const warns=_designChanges.filter(c=>c._validation&&c._validation.warnings.length&&!c._invalid).length;
  let headerExtra='';
  if(invalids)headerExtra+=' <span style="color:#dc2626;font-size:8px">'+invalids+' blocked</span>';
  let h='<div class="change-log-header"><span>Changes ('+_designChanges.length+')'+headerExtra+'</span><div><button onclick="undoLastChange()">Undo</button> <button onclick="_designChanges=[];renderChangeLog();applyDesignChanges()">Clear All</button></div></div>';
  _designChanges.forEach((ch)=>{
    const desc=_changeDesc(ch);
    const chId=ch.id;
    let icon='<span style="color:var(--accent-green);margin-right:4px" title="Valid">&#10003;</span>';
    if(ch._invalid)icon='<span style="color:#dc2626;margin-right:4px" title="'+esc(((ch._validation||{}).errors||[]).join('; '))+'">&#10007;</span>';
    else if(ch._validation&&ch._validation.warnings.length)icon='<span style="color:var(--accent-orange);margin-right:4px" title="'+esc(ch._validation.warnings.join('; '))+'">&#9888;</span>';
    h+='<div class="change-log-item" style="'+(ch._invalid?'opacity:.5;text-decoration:line-through':'')+'"><span class="cl-desc">'+icon+desc+'</span><button class="cl-undo" onclick="_designChanges=_designChanges.filter(c=>c.id!==\''+chId+'\');renderChangeLog();applyDesignChanges()">x</button></div>';
  });
  // Full-state validation summary
  if(_lastDesignValidation){
    const sv=_lastDesignValidation;
    if(sv.errors.length||sv.warnings.length){
      h+='<div style="padding:4px 10px;border-top:1px solid var(--border);font-size:8px">';
      if(sv.errors.length)h+='<div style="color:#dc2626;margin-bottom:2px"><b>State Errors:</b> '+sv.errors.join('; ')+'</div>';
      sv.warnings.forEach(w=>{h+='<div style="color:var(--accent-orange)">'+w+'</div>'});
      h+='</div>';
    }
  }
  cl.innerHTML=h;
  // Update badge
  const btn=document.getElementById('designToggle');
  const existing=btn.querySelector('.change-badge');if(existing)existing.remove();
  if(_designChanges.length){const badge=document.createElement('span');badge.className='change-badge';badge.textContent=_designChanges.length;btn.appendChild(badge)}
}
function _changeDesc(ch){
  const action=ch.action;
  let badge='',label='';
  if(action==='add_vpc'){badge='<span class="cl-action-badge add">+vnet</span>';label=esc(ch.params.Name||'New VNet')+' ('+esc(ch.params.CidrBlock)+')'}
  else if(action==='add_subnet'){badge='<span class="cl-action-badge add">+subnet</span>';label=esc(ch.params.Name||ch.params.CidrBlock||'new')}
  else if(action==='split_subnet'){badge='<span class="cl-action-badge split">split</span>';label=esc(ch.target.SubnetId||'subnet')}
  else if(action==='add_gateway'){badge='<span class="cl-action-badge add">+'+(ch.params.GatewayType||'gw').toLowerCase()+'</span>';label=esc(ch.params.Name||'new')}
  else if(action==='add_route'){badge='<span class="cl-action-badge modify">+route</span>';label=esc(ch.params.DestinationCidrBlock||'?')+' → '+esc(sid(ch.params.TargetId||''))}
  else if(action==='add_resource'){badge='<span class="cl-action-badge add">+'+(ch.params.ResourceType||'res').toLowerCase()+'</span>';label=esc(ch.params.Name||'new')}
  else if(action==='add_security_group'){badge='<span class="cl-action-badge add">+sg</span>';label=esc(ch.params.Name||'new')}
  else if(action==='remove_resource'){badge='<span class="cl-action-badge remove">remove</span>';label=esc(ch.target.ResourceType||'')+' '+esc(sid(ch.target.ResourceId||''))}
  else{badge='';label=esc(action.replace(/_/g,' '))}
  return badge+label;
}

// Export design plan as JSON
function exportDesignPlan(planName){
  // Run full validation on export
  const designCtx=designRuntimeData();
  const stateValidation=designCtx?validateDesignState(_designChanges,designCtx):{valid:true,errors:[],warnings:[],stats:{}};
  const perChangeValidation=_designChanges.map(ch=>({id:ch.id,action:ch.action,validation:ch._validation||{valid:true,errors:[],warnings:[]}}));
  const cliCmds=[];
  _designChanges.filter(ch=>!ch._invalid).forEach(ch=>{
    const cmds=_generateCLI(ch);
    if(!cmds||!cmds.length)return;
    // Annotate with warnings
    if(ch._validation&&ch._validation.warnings.length)cliCmds.push('# WARNING: '+ch._validation.warnings.join('; '));
    cliCmds.push(...cmds);
  });
  const plan={version:'2.0',plan_name:planName||'Design Plan',created:new Date().toISOString(),location:_designRegion,
    validation:{status:stateValidation.valid?'valid':'errors',errors:stateValidation.errors,warnings:stateValidation.warnings,stats:stateValidation.stats,per_change:perChangeValidation},
    changes:_designChanges.filter(ch=>!ch._invalid).map(ch=>({id:ch.id,action:ch.action,target:ch.target,params:ch.params,timestamp:ch.timestamp})),
    blocked_changes:_designChanges.filter(ch=>ch._invalid).map(ch=>({id:ch.id,action:ch.action,target:ch.target,params:ch.params,errors:(ch._validation||{}).errors||[]})),
    az_cli:cliCmds,warnings:_generateWarnings()};
  const blob=new Blob([JSON.stringify(plan,null,2)],{type:'application/json'});
  designDownload(blob,(planName||'design-plan')+'.json');
}
function _generateCLI(ch){
  const cmds=[];
  const params=ch.params||{};
  const rg=params.resourceGroup||'$RESOURCE_GROUP';
  const quote=value=>"'"+String(value).replace(/'/g,"'\\''")+"'";
  if(ch.action==='add_vpc'){cmds.push(`az network vnet create --name ${ch.params.Name||'new-vnet'} --resource-group ${rg} --address-prefixes ${ch.params.CidrBlock}`)}
  if(ch.action==='add_subnet')cmds.push(`az network vnet subnet create --name ${ch.params.Name||'new-subnet'} --resource-group ${rg} --vnet-name $VNET_NAME --address-prefixes ${ch.params.CidrBlock}`);
  if(ch.action==='split_subnet'){
    cmds.push('# Split subnet: delete original, create two new');
    cmds.push(`az network vnet subnet delete --name $SUBNET_NAME --resource-group ${rg} --vnet-name $VNET_NAME`);
    const halves=splitCIDR(ch.target.CidrBlock||ch.target.addressPrefix||ch.target.properties?.addressPrefix||ch.target.properties?.addressPrefixes?.[0]);
    if(halves){
      cmds.push(`az network vnet subnet create --name ${ch.params.names?.[0]||'subnet-a'} --resource-group ${rg} --vnet-name $VNET_NAME --address-prefixes ${halves[0]}`);
      cmds.push(`az network vnet subnet create --name ${ch.params.names?.[1]||'subnet-b'} --resource-group ${rg} --vnet-name $VNET_NAME --address-prefixes ${halves[1]}`);
    }
  }
  if(ch.action==='add_gateway'){
    const type=designGatewayType(params.GatewayType);
    if(type==='AZFW'){
      const name=params.Name||'new-firewall';
      const rgArg=params.resourceGroup?quote(params.resourceGroup):'$RESOURCE_GROUP';
      cmds.push(`az network public-ip create --name ${quote(name+'-pip')} --resource-group ${rgArg} --sku Standard`);
      cmds.push(`az network firewall create --name ${quote(name)} --resource-group ${rgArg} --location $LOCATION --sku AZFW_VNet --tier Standard`);
      cmds.push(`az network firewall ip-config create --name ${quote(name+'-ipconfig')} --firewall-name ${quote(name)} --resource-group ${rgArg} --public-ip-address ${quote(name+'-pip')} --vnet-name $VNET_NAME`);
    }
    if(type==='NAT'){
      const subnet=String(params.SubnetId||'').match(/^\/subscriptions\/([^/]+)\/resourceGroups\/([^/]+)\/providers\/Microsoft.Network\/virtualNetworks\/([^/]+)\/subnets\/([^/]+)$/i);
      const targetRg=params.resourceGroup||subnet?.[2]||'$RESOURCE_GROUP';
      const rgArg=targetRg==='$RESOURCE_GROUP'?targetRg:quote(targetRg);
      const subscription=subnet?' --subscription '+quote(subnet[1]):'';
      const name=quote(params.Name||'new-nat'),pip=quote((params.Name||'nat')+'-pip');
      cmds.push(`az network public-ip create --name ${pip} --resource-group ${rgArg} --sku Standard${subscription}`);
      cmds.push(`az network nat gateway create --name ${name} --resource-group ${rgArg} --public-ip-addresses ${pip}${subscription}`);
      cmds.push(`az network vnet subnet update --name ${subnet?quote(subnet[4]):'$SUBNET_NAME'} --resource-group ${rgArg} --vnet-name ${subnet?quote(subnet[3]):'$VNET_NAME'} --nat-gateway ${name}${subscription}`);
    }
    if(type==='VPCE')cmds.push(`az network private-endpoint create --name ${params.Name||'new-pe'} --resource-group ${rg} --vnet-name $VNET_NAME --subnet $SUBNET_NAME --private-connection-resource-id $TARGET_RESOURCE_ID --group-ids $GROUP_ID --connection-name $CONNECTION_NAME`);
  }
  if(ch.action==='add_route'){
    const hop=designRouteNextHop(ch.params);
    if(!hop)cmds.push('# Route needs a supported Azure next-hop type and, for VirtualAppliance, an IPv4 address before export.');
    else cmds.push(`az network route-table route create --route-table-name $ROUTE_TABLE_NAME --resource-group ${rg} --name ${ch.params.Name||'mapper-route-'+ch.params.DestinationCidrBlock.replace(/[^a-zA-Z0-9]/g,'-')} --address-prefix ${ch.params.DestinationCidrBlock} --next-hop-type ${hop.type}`+(hop.type==='VirtualAppliance'?' --next-hop-ip-address '+hop.ip:''));
  }
  if(ch.action==='add_resource'){
    const type=designResourceType(params.ResourceType);
    if(type==='VM')cmds.push(`az vm create --name ${params.Name||'new-vm'} --resource-group ${rg} --image UbuntuLTS --size ${params.InstanceType||'Standard_B2ms'} --vnet-name $VNET_NAME --subnet $SUBNET_NAME --admin-username azureuser --generate-ssh-keys`);
    if(type==='SQL')cmds.push(`az sql server create --name ${params.Name||'new-sql'} --resource-group ${rg} --admin-user sqladmin --admin-password $SQL_PASSWORD\naz sql db create --server ${params.Name||'new-sql'} --resource-group ${rg} --name ${params.Name||'new-db'} --service-objective ${params.InstanceClass||'S0'}`);
    if(type==='FunctionApp')cmds.push(`az functionapp create --name ${params.Name||'new-function'} --resource-group ${rg} --runtime ${params.Runtime||'node'} --runtime-version ${params.RuntimeVersion||'18'} --storage-account $STORAGE_ACCOUNT --consumption-plan-location $LOCATION`);
    if(type==='Redis')cmds.push(`az redis create --name ${params.Name||'new-redis'} --resource-group ${rg} --location $LOCATION --sku ${params.Sku||'Basic'} --vm-size ${params.NodeType||'c0'}`);
    if(type==='Container')cmds.push(`az container create --name ${params.Name||'new-container'} --resource-group ${rg} --image $CONTAINER_IMAGE --cpu 1 --memory 1 --vnet $VNET_NAME --subnet $SUBNET_NAME`);
    if(type==='Synapse')cmds.push(`az synapse workspace create --name ${params.Name||'new-synapse'} --resource-group ${rg} --location $LOCATION --storage-account $STORAGE_ACCOUNT --file-system $FS_NAME --sql-admin-login-user sqladmin --sql-admin-login-password $SYNAPSE_PASSWORD`);
  }
  if(ch.action==='add_security_group'){
    cmds.push(`az network nsg create --name ${ch.params.Name||'new-nsg'} --resource-group ${rg}`);
    if(ch.params.IngressRules){ch.params.IngressRules.forEach((r,idx)=>{
      const protocol=r.Protocol==='*'||r.Protocol==='-1'||r.Protocol===-1?'*':r.Protocol;
      const port=r.FromPort===-1||r.FromPort==null?'*':r.ToPort!=null&&r.ToPort!==r.FromPort?r.FromPort+'-'+r.ToPort:String(r.FromPort);
      cmds.push(`az network nsg rule create --nsg-name ${ch.params.Name||'new-nsg'} --resource-group ${rg} --name rule-${idx} --priority ${100+idx*10} --direction Inbound --access Allow --protocol ${quote(protocol)} --destination-port-ranges ${quote(port)} --source-address-prefixes ${quote(r.CidrIp||'*')}`);
    })}
  }
  if(ch.action==='remove_resource'){
    const t=designResourceType(designGatewayType(ch.target.ResourceType));
    if(t==='VM')cmds.push(`az vm delete --name $VM_NAME --resource-group ${rg} --yes`);
    if(t==='SQL')cmds.push(`az sql server delete --name $SQL_SERVER --resource-group ${rg} --yes`);
    if(t==='FunctionApp')cmds.push(`az functionapp delete --name $FUNC_NAME --resource-group ${rg}`);
    if(t==='Redis')cmds.push(`az redis delete --name $REDIS_NAME --resource-group ${params.resourceGroup?quote(params.resourceGroup):'$RESOURCE_GROUP'} --yes`);
    if(t==='Synapse')cmds.push(`az synapse workspace delete --name $SYNAPSE_NAME --resource-group ${rg} --yes`);
    if(t==='Container')cmds.push(`az container delete --name $CONTAINER_NAME --resource-group ${rg} --yes`);
    if(t==='Subnet')cmds.push(`az network vnet subnet delete --name $SUBNET_NAME --resource-group ${rg} --vnet-name $VNET_NAME`);
    if(t==='AZFW')cmds.push(`az network firewall delete --name $FW_NAME --resource-group ${rg}`);
    if(t==='NAT')cmds.push(`az network nat gateway delete --name $NAT_NAME --resource-group ${rg}`);
    if(t==='VPCE')cmds.push(`az network private-endpoint delete --name $PE_NAME --resource-group ${rg}`);
  }
  return cmds;
}
function _generateWarnings(){
  const w=[];
  const splits=_designChanges.filter(c=>c.action==='split_subnet');
  if(splits.length)w.push(splits.length+' subnet split(s) require instance migration');
  const removes=_designChanges.filter(c=>c.action==='remove_resource');
  if(removes.length)w.push(removes.length+' resource removal(s): verify dependencies first');
  return w;
}
function importDesignPlan(json){
  try{
    const plan=typeof json==='string'?JSON.parse(json):json;
    if(!plan.changes||!Array.isArray(plan.changes)){designNotify('Invalid plan format');return}
    if(!_designMode)enterDesignMode();
    if(plan.location||plan.region)_designRegion=plan.location||plan.region;
    let imported=0,blocked=0;
    plan.changes.forEach(ch=>{
      addDesignChange(ch);
      if(ch._invalid)blocked++;else imported++;
    });
    if(blocked>0)designNotify('Imported '+imported+' changes, '+blocked+' blocked by validation errors');
  }catch(e){designNotify('Failed to import plan: '+e.message)}
}

// === IAC POLICY EXPORT ===
function generateAzurePolicyRules(findings){
  // Generates Azure Policy rule definitions from compliance findings
  return findings.map(f=>{
    const rule={
      name:('custom-'+f.control+'-'+f.resource).toLowerCase().replace(/[^a-z0-9-]/g,'-').substring(0,64),
      description:f.message,
      policyType:'Custom',
      mode:'All',
      metadata:{category:'Network Security',control:f.control,severity:f.severity},
      parameters:{resource:{type:'String',defaultValue:f.resource}},
      policyRule:{if:{field:'type',in:[]},then:{effect:'Audit'}}
    };
    if(f.control.startsWith('CIS 5.')||f.control.startsWith('NET-'))rule.policyRule.if.in=['Microsoft.Network/networkSecurityGroups'];
    else if(f.control.startsWith('WAF'))rule.policyRule.if.in=['Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'];
    else if(f.control.startsWith('IAM')||f.control.startsWith('RBAC'))rule.policyRule.if.in=['Microsoft.Authorization/roleAssignments'];
    return rule;
  });
}
function generateOPARego(findings){
  const rules=new Map();
  findings.forEach(f=>{
    const key=f.control;if(rules.has(key))return;
    let rego='';
    if(f.control==='CIS 5.2')rego='deny[msg] {\n  nsg := input.resource.azurerm_network_security_group[name]\n  rule := nsg.security_rule[_]\n  rule.direction == "Inbound"\n  rule.destination_port_range == "22"\n  rule.source_address_prefix == "*"\n  msg := sprintf("NSG %s allows SSH from * (CIS 5.2)", [name])\n}';
    else if(f.control==='CIS 5.3')rego='deny[msg] {\n  nsg := input.resource.azurerm_network_security_group[name]\n  rule := nsg.security_rule[_]\n  rule.direction == "Inbound"\n  rule.destination_port_range == "3389"\n  rule.source_address_prefix == "*"\n  msg := sprintf("NSG %s allows RDP from * (CIS 5.3)", [name])\n}';
    else if(f.control==='NET-2')rego='deny[msg] {\n  nsg := input.resource.azurerm_network_security_group[name]\n  rule := nsg.security_rule[_]\n  rule.direction == "Inbound"\n  rule.protocol == "*"\n  rule.source_address_prefix == "*"\n  msg := sprintf("NSG %s allows ALL traffic from * (NET-2)", [name])\n}';
    else rego='# '+f.control+': '+f.message+'\ndeny[msg] {\n  # TODO: Implement check for '+f.control+'\n  msg := "'+f.control+': '+f.message.replace(/\\/g,'\\\\').replace(/"/g,'\\"')+'"\n}';
    rules.set(key,rego);
  });
  return'package azure_compliance\n\nimport input\n\n'+Array.from(rules.values()).join('\n\n')+'\n';
}
function generateCheckovCheck(findings){
  const checks=new Map();
  findings.forEach(f=>{
    const key=f.control;if(checks.has(key))return;
    checks.set(key,`# ${f.control}: ${f.message}\n# Severity: ${f.severity}\n# Remediation: ${f.remediation}\nfrom checkov.common.models.enums import CheckResult, CheckCategories\nfrom checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck\n\nclass ${f.control.replace(/[^a-zA-Z0-9]/g,'')}Check(BaseResourceCheck):\n    def __init__(self):\n        name = "${f.message}"\n        id = "CUSTOM_${f.control.replace(/[^a-zA-Z0-9]/g,'_')}"\n        supported_resources = ["azurerm_network_security_group"]\n        categories = [CheckCategories.NETWORKING]\n        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)\n\n    def scan_resource_conf(self, conf):\n        # TODO: Implement check logic\n        return CheckResult.PASSED\n`);
  });
  return Array.from(checks.values()).join('\n\n');
}
function generateRemediationCLI(findings){
  const sub=designSubscriptionArg();
  const lines=['#!/bin/bash','# Azure Compliance Remediation Script','# Generated: '+new Date().toISOString().slice(0,19).replace('T',' '),'# REVIEW EACH COMMAND BEFORE RUNNING: some are destructive','','set -euo pipefail',''];
  const seen=new Set();
  const cliMap={
    'CIS 5.2':f=>'# '+f.message+'\n# Remove SSH inbound rule from NSG:\naz network nsg rule delete '+sub+' --nsg-name '+f.resource+' --name "AllowSSH" 2>/dev/null || az network nsg rule update '+sub+' --nsg-name '+f.resource+' --name allow-ssh --access Deny',
    'CIS 5.3':f=>'# '+f.message+'\n# Remove RDP inbound rule from NSG:\naz network nsg rule delete '+sub+' --nsg-name '+f.resource+' --name "AllowRDP" 2>/dev/null || az network nsg rule update '+sub+' --nsg-name '+f.resource+' --name allow-rdp --access Deny',
    'CIS 5.4':f=>'# '+f.message+': Remove open inbound rules from NSG\naz network nsg rule list '+sub+' --nsg-name '+f.resource+' -o table',
    'NET-2':f=>'# '+f.message+'\n# Remove all-traffic inbound rule from NSG:\naz network nsg rule list '+sub+' --nsg-name '+f.resource+' --query "[?direction==\'Inbound\' && sourceAddressPrefix==\'*\' && access==\'Allow\']" -o table',
    'ARCH-D1':f=>'# '+f.message+'\n# Disable public access on Azure SQL server:\naz sql server update '+sub+' --name '+f.resource+' --restrict-outbound-network-access true',
    'ARCH-D2':f=>'# '+f.message+'\n# Enable zone redundancy for Azure SQL:\naz sql db update '+sub+' --server '+f.resource+' --zone-redundant true',
    'ARCH-D3':f=>'# '+f.message+': Enable transparent data encryption\naz sql db tde set '+sub+' --server '+f.resource+' --status Enabled',
    'ARCH-C2':f=>'# '+f.message+'\n# Enable disk encryption on VM:\naz vm encryption enable '+sub+' --name '+f.resource+' --disk-encryption-keyvault ${KEYVAULT_ID}',
    'ARCH-S1':f=>'# '+f.message+'\n# Enable storage account encryption:\naz storage account update '+sub+' --name '+f.resource+' --encryption-services blob --encryption-services file',
    'ARCH-D5':f=>'# '+f.message+': Enable Redis SSL\naz redis update '+sub+' --name '+f.resource+' --enable-non-ssl-port false',
    'ARCH-D7':f=>'# '+f.message+'\n# Disable public access on AKS:\naz aks update '+sub+' --name '+f.resource+' --api-server-authorized-ip-ranges ""',
    'ARCH-E2':f=>'# '+f.message+'\n# Update Front Door to enforce HTTPS:\naz afd endpoint update '+sub+' --profile-name '+f.resource+' --https-redirect Enabled',
    'WAF-3':f=>'# '+f.message+'\n# Associate App Gateway with WAF policy:\naz network application-gateway waf-policy create '+sub+' --name waf-policy-'+f.resource+' --resource-group ${RESOURCE_GROUP}',
    'WAF-4':f=>'# '+f.message+'\n# Set WAF to prevention mode:\naz network application-gateway waf-policy update '+sub+' --name '+f.resourceName+' --resource-group ${RESOURCE_GROUP} --mode Prevention',
    'SOC2-CC7.2':f=>'# '+f.message+'\n# Enable VNet flow logs:\naz network watcher flow-log create '+sub+' --name flowlog-'+f.resource+' --vnet '+f.resource+' --storage-account ${STORAGE_ACCOUNT_ID} --enabled true',
    'PCI-10.2.1':f=>'# '+f.message+'\n# Enable VNet flow logs for PCI:\naz network watcher flow-log create '+sub+' --name flowlog-'+f.resource+' --vnet '+f.resource+' --storage-account ${STORAGE_ACCOUNT_ID} --enabled true',
    'PCI-3.4.1':f=>{
      if(f.message.includes('disk')||f.message.includes('Disk'))return '# '+f.message+'\naz vm encryption enable '+sub+' --name '+f.resource+' --disk-encryption-keyvault ${KEYVAULT_ID}';
      if(f.message.includes('SQL')||f.message.includes('sql'))return '# '+f.message+'\naz sql db tde set '+sub+' --server '+f.resource+' --status Enabled';
      return '# '+f.message+'\naz storage account update '+sub+' --name '+f.resource+' --encryption-services blob';
    },
    'PCI-11.3.1':f=>{
      if(f.message.includes('AKS'))return '# '+f.message+'\naz aks update '+sub+' --name '+f.resource+' --api-server-authorized-ip-ranges ""';
      return '# '+f.message+'\naz sql server update '+sub+' --name '+f.resource+' --restrict-outbound-network-access true';
    },
    'PCI-4.2.1':f=>'# '+f.message+'\n# Enforce HTTPS on App Gateway listener:\naz network application-gateway http-listener update '+sub+' --gateway-name '+f.resource+' --name https-listener --ssl-cert ${CERT_NAME}',
    'IAM-9':f=>'# '+f.message+'\n# Rotate service principal credential:\naz ad sp credential reset --id '+f.resource,
    'IAM-11':f=>'# '+f.message+'\n# Enable MFA for Azure AD user (requires Azure AD P2 license):\n# Configure via Azure AD portal or Microsoft Graph API',
    'ARCH-G2':f=>'# '+f.message+'\n# Create Private Endpoint for storage:\naz network private-endpoint create '+sub+' --name pe-storage-'+f.resource+' --vnet-name ${VNET_NAME} --subnet ${SUBNET_NAME} --private-connection-resource-id ${STORAGE_ACCOUNT_ID} --group-id blob --connection-name conn-storage',
  };
  findings.filter(f=>!_isMuted(f)).forEach(f=>{
    const key=f.control+'|'+f.resource;
    if(seen.has(key))return;seen.add(key);
    const gen=cliMap[f.control];
    if(gen){
      const cmd=typeof gen==='function'?gen(f):gen;
      lines.push(cmd,'');
    } else {
      lines.push('# ['+f.severity+'] '+f.control+(f.ckv?' ('+f.ckv+')':'')+': '+f.message+' ('+f.resource+')','# Remediation: '+f.remediation,'');
    }
  });
  lines.push('echo "Remediation script complete. Review output for errors."');
  return lines.join('\n');
}
function exportPolicies(findings,format){
  let content,filename,mime;
  if(format==='config'){content=JSON.stringify(generateAzurePolicyRules(findings),null,2);filename='azure-policy-rules.json';mime='application/json'}
  else if(format==='rego'){content=generateOPARego(findings);filename='compliance.rego';mime='text/plain'}
  else if(format==='checkov'){content=generateCheckovCheck(findings);filename='custom_checks.py';mime='text/x-python'}
  else if(format==='cli'){content=generateRemediationCLI(findings);filename='remediation.sh';mime='text/x-shellscript'}
  else return;
  designDownload(new Blob([content],{type:mime}),filename);
}
function exportCheckovCfn(){
  const designCtx=designRuntimeData();
  if(!designCtx){designNotify('Render a map first');return;}
  var json=generateCheckovCfn(designCtx,_iamData);
  if(!json){designNotify('No data available');return;}
  var count=Object.keys(JSON.parse(json).Resources||{}).length;
  designDownload(new Blob([json],{type:'application/json'}),'checkov-template.json');
  designNotify(count+' resources exported. Run: checkov -f checkov-template.json --framework arm');
}

// #endregion DESIGN MODE

