// Resource list panel owns the clickable inventory drawer launched from topology counters.
// It intentionally keeps the legacy openResourceList(type) entry point used by map regions.

function resourceListContext(){
  const adapter=typeof AppRenderContext!=='undefined'?AppRenderContext.createRenderContext():null;
  const ctx=adapter?adapter.rlCtx:null;
  return ctx?{...ctx,vpcs:ctx.vnets||ctx.vpcs||[],instances:ctx.vms||ctx.instances||[],sgs:ctx.nsgs||ctx.sgs||[],rts:ctx.udrs||ctx.rts||[],nacls:ctx.subnetNsgs||ctx.nacls||[],enis:ctx.nics||ctx.enis||[],igws:ctx.firewalls||ctx.igws||[],nats:ctx.natGateways||ctx.nats||[],vpces:ctx.privateEndpoints||ctx.vpces||[],albs:ctx.appGateways||ctx.albs||[],rdsInstances:ctx.sqlServers||ctx.rdsInstances||[],ecsServices:ctx.containerInstances||ctx.ecsServices||[],lambdaFns:ctx.functionApps||ctx.lambdaFns||[],ecacheClusters:ctx.redisCaches||ctx.ecacheClusters||[],redshiftClusters:ctx.synapseWorkspaces||ctx.redshiftClusters||[]}:null;
}

function resourceListDesignButton(label,handler){
  if(typeof designToolbarButton==='function')return designToolbarButton(label,handler);
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

function addResourceListDesignToolbar(container,ctx,type){
  if(!_designMode||!['VPCs','VNets'].includes(type)||typeof showDesignForm!=='function')return;
  const tb=document.createElement('div');
  tb.className='design-toolbar';
  tb.appendChild(resourceListDesignButton('+ VNet',()=>showDesignForm('add_vpc',{})));
  (ctx.vpcs||ctx.vnets||[]).forEach(vnet=>{
    const label=gn(vnet,vnet.VpcId);
    tb.appendChild(resourceListDesignButton('+ Sub ('+label+')',()=>showDesignForm('add_subnet',{vpc:vnet})));
    tb.appendChild(resourceListDesignButton('+ GW ('+label+')',()=>showDesignForm('add_gateway',{vpc:vnet})));
    tb.appendChild(resourceListDesignButton('+ SG ('+label+')',()=>showDesignForm('add_security_group',{vpc:vnet})));
  });
  container.insertBefore(tb,container.firstChild);
}

function openResourceList(type, pushNav){
  const ctx=resourceListContext();if(!ctx)return;
  if(pushNav===undefined) pushNav=true;
  if(pushNav) _navStack=[];
  _lastRlType=type;
  const dp=document.getElementById('detailPanel');
  const dpTitle=document.getElementById('dpTitle');
  const dpSub=document.getElementById('dpSub');
  const dpBody=document.getElementById('dpBody');

  function vpcName(id){const v=(ctx.vpcs||[]).find(v=>v.VpcId===id);return v?gn(v,id):esc(id)||'--'}
  function subName(id){const s=(ctx.subnets||[]).find(s=>s.SubnetId===id);return s?gn(s,id):id||'--'}

  // row builder: action = {t:'vpc'|'sub', id:'...'} or null
  function row(main,details,color,action){
    const act=action?` data-act="${esc(action.t)}" data-id="${esc(action.id)}"`:'';
    const style=` style="border-left:3px solid ${color||'var(--border)'};padding-left:8px;margin:4px 0${action?';cursor:pointer':''}"`;
    const navBtn=action?'<span class="dp-nav-btn" data-nav="1" data-nav-t="'+esc(action.t)+'" data-nav-id="'+esc(action.id)+'" title="Navigate to resource on map">Go to</span>':'';
    const tog=details?'<span class="dp-tog">&#9660;</span>':'';
    const hasHtml=details&&/<[a-z][\s\S]*>/i.test(details);
    const det=details?'<span class="dp-det"><br><span class="k">'+(hasHtml?details:esc(details))+'</span></span>':'';
    return '<div class="dp-row"'+act+style+'>'
      +tog+'<span class="i" style="color:'+(color||'var(--text-primary)')+'">'+esc(main)+'</span>'+navBtn
      +det+'</div>';
  }

  // Find first subnet containing a resource
  function findSubForInst(iid){return (ctx.subnets||[]).find(s=>((ctx.instBySub||{})[s.SubnetId]||[]).some(i=>i.InstanceId===iid))?.SubnetId}
  function findSubForAlb(arn){return (ctx.subnets||[]).find(s=>((ctx.albBySub||{})[s.SubnetId]||[]).some(a=>a.LoadBalancerArn===arn))?.SubnetId}
  function findSubForEni(eid){return (ctx.subnets||[]).find(s=>((ctx.eniBySub||{})[s.SubnetId]||[]).some(e=>e.NetworkInterfaceId===eid))?.SubnetId}
  function findSubForRds(dbid){for(const[sid,dbs]of Object.entries(ctx.rdsBySub||{})){if(dbs.some(d=>d.DBInstanceIdentifier===dbid))return sid}return null}
  function findSubForEcs(name){for(const[sid,svcs]of Object.entries(ctx.ecsBySub||{})){if(svcs.some(s=>s.serviceName===name))return sid}return null}
  function findSubForLambda(fn){for(const[sid,fns]of Object.entries(ctx.lambdaBySub||{})){if(fns.some(f=>f.FunctionName===fn))return sid}return null}

  let title='',sub='',items=[];

  switch(type){
    case 'VPCs':case 'VNets':{
      const d=ctx.vpcs||[];
      const accounts=new Set(d.map(v=>v._subscriptionId).filter(a=>a&&a!=='default'));
      title='VNets';sub=d.length+' total'+(accounts.size>1?' | '+accounts.size+' accounts':'');
      // Group by account if multi-account
      if(accounts.size>1||_loadedContexts.length>1){
        const grouped={};d.forEach(v=>{const a=v._accountLabel||v._subscriptionId||'default';(grouped[a]=grouped[a]||[]).push(v)});
        Object.entries(grouped).forEach(([acct,vpcList])=>{
          const acCol=vpcList[0]._ctxColor||getAccountColor(acct);
          items.push('<div style="font-size:calc(9px * var(--txt-scale) * var(--dp-txt-scale));font-weight:600;color:'+(acCol||'var(--text-secondary)')+';padding:6px 0 2px;border-bottom:1px solid var(--border);margin-top:6px;text-transform:uppercase;letter-spacing:.5px">'+esc(acct)+'</div>');
          vpcList.forEach(v=>{
            const sc=(ctx.subnets||[]).filter(s=>s.VpcId===v.VpcId).length;
            items.push(row(gn(v,v.VpcId),'ID: '+v.VpcId+' | CIDR: '+(v.CidrBlock||'?')+' | '+sc+' subnets','#7C3AED',{t:'vpc',id:v.VpcId}));
          });
        });
      } else {
        d.forEach(v=>{
          const sc=(ctx.subnets||[]).filter(s=>s.VpcId===v.VpcId).length;
          items.push(row(gn(v,v.VpcId),'ID: '+v.VpcId+' | CIDR: '+(v.CidrBlock||'?')+' | '+sc+' subnets','#7C3AED',{t:'vpc',id:v.VpcId}));
        });
      }
      break;
    }
    case 'Subnets':case 'Public':case 'Private':{
      let d=ctx.subnets||[];
      if(type==='Public')d=d.filter(s=>ctx.pubSubs.has(s.SubnetId));
      if(type==='Private')d=d.filter(s=>!ctx.pubSubs.has(s.SubnetId));
      title=type+' Subnets';sub=d.length+' total';
      d.forEach(s=>{
        const isPub=ctx.pubSubs.has(s.SubnetId);
        items.push(row(gn(s,s.SubnetId),'CIDR: '+s.CidrBlock+' | AZ: '+(s.AvailabilityZone||'?')+' | VPC: '+vpcName(s.VpcId)+' | '+(isPub?'Public':'Private'),isPub?'#10b981':'#3b82f6',{t:'sub',id:s.SubnetId}));
      });break;
    }
    case 'Gateways':{
      const d=[...(ctx.igws||[]).map(g=>({...g,_type:'IGW',_id:g.InternetGatewayId,_vpc:(g.Attachments||[])[0]?.VpcId})),
        ...(ctx.nats||[]).map(g=>({...g,_type:'NAT',_id:g.NatGatewayId,_vpc:g.VpcId})),
        ...(ctx.vpces||[]).map(g=>({...g,_type:'VPCE',_id:g.VpcEndpointId,_vpc:g.VpcId}))];
      title='Gateways';sub=d.length+' total';
      d.forEach(g=>{
        items.push(row(gn(g,g._id),'Type: '+g._type+' | ID: '+g._id,gch(g._type),g._vpc?{t:'vpc',id:g._vpc}:null));
      });break;
    }
    case 'RTs':case 'UDRs':{
      const d=ctx.rts||[];title='Route Tables';sub=d.length+' total';
      d.forEach(rt=>{
        const rc=(rt.Routes||[]).length;const ac=(rt.Associations||[]).length;
        items.push(row(gn(rt,rt.RouteTableId),'ID: '+rt.RouteTableId+' | VPC: '+vpcName(rt.VpcId)+' | '+rc+' routes | '+ac+' assoc','#6366f1',{t:'vpc',id:rt.VpcId}));
      });break;
    }
    case 'NACLs':case 'SubNSGs':{
      const d=ctx.nacls||[];title='Network ACLs';sub=d.length+' total';
      d.forEach(n=>{
        const rc=(n.Entries||[]).length;
        items.push(row(gn(n,n.NetworkAclId),'ID: '+n.NetworkAclId+' | VPC: '+vpcName(n.VpcId)+' | '+rc+' rules','#8b5cf6',{t:'vpc',id:n.VpcId}));
      });break;
    }
    case 'SGs':case 'NSGs':{
      const d=ctx.sgs||[];title='Security Groups';sub=d.length+' total';
      d.forEach(sg=>{
        const inR=(sg.IpPermissions||[]).length;const outR=(sg.IpPermissionsEgress||[]).length;
        items.push(row(esc(sg.GroupName||sg.GroupId),'ID: '+sg.GroupId+' | VPC: '+vpcName(sg.VpcId)+' | In: '+inR+' Out: '+outR,'#f59e0b',{t:'vpc',id:sg.VpcId}));
      });break;
    }
    case 'VM':case 'VMs':{
      const d=ctx.instances||[];title='Virtual Machines';sub=d.length+' total';
      d.forEach(i=>{
        const pip=(i.NetworkInterfaces||[]).flatMap(n=>[n.PrivateIpAddress]).filter(Boolean).join(', ');
        const sid=i.SubnetId||findSubForInst(i.InstanceId);
        items.push(row(gn(i,i.InstanceId),'Type: '+i.InstanceType+' | State: '+(i.State?.Name||'?')+' | IP: '+pip+' | Subnet: '+subName(i.SubnetId),'#10b981',sid?{t:'sub',id:sid}:null));
      });break;
    }
    case 'ENIs':case 'NICs':{
      const d=ctx.enis||[];title='NICs';sub=d.length+' total';
      d.forEach(e=>{
        items.push(row(gn(e,e.NetworkInterfaceId),'Type: '+(e.InterfaceType||'?')+' | Status: '+(e.Status||'?')+' | IP: '+(e.PrivateIpAddress||'?')+' | Subnet: '+subName(e.SubnetId),'#3b82f6',e.SubnetId?{t:'sub',id:e.SubnetId}:null));
      });break;
    }
    case 'ALBs':case 'AppGWs':{
      const d=ctx.albs||[];title='Load Balancers';sub=d.length+' total';
      d.forEach(a=>{
        const tgc=((ctx.tgByAlb||{})[a.LoadBalancerArn]||[]).length;
        const wc=((ctx.wafByAlb||{})[a.LoadBalancerArn]||[]).length;
        const cfc=((ctx.cfByAlb||{})[a.LoadBalancerArn]||[]).length;
        let det='Type: '+(a.Type||'?')+' | Scheme: '+(a.Scheme||'?')+' | TGs: '+tgc;
        if(wc)det+=' | WAF: '+wc;
        if(cfc)det+=' | CF: '+cfc;
        det+='<br>DNS: '+esc(a.DNSName||'?');
        const sid=findSubForAlb(a.LoadBalancerArn);
        items.push(row(esc(a.LoadBalancerName)+'<span class="k" style="margin-left:6px">'+(a.Scheme||'')+'</span>',det,'#38bdf8',sid?{t:'sub',id:sid}:null));
      });break;
    }
    case 'TGs':case 'LBs':{
      const d=ctx.tgs||[];title='Backend Pools';sub=d.length+' total';
      d.forEach(tg=>{
        const tc=(tg.Targets||[]).length;
        const vid=tg.VpcId;
        items.push(row(esc(tg.TargetGroupName),'Protocol: '+(tg.Protocol||'?')+':'+(tg.Port||'?')+' | Type: '+(tg.TargetType||'?')+' | Targets: '+tc+(tg.HealthCheckPath?' | HC: '+esc(tg.HealthCheckPath):''),'#06b6d4',vid?{t:'vpc',id:vid}:null));
      });break;
    }
    case 'RDS':case 'SQL':{
      const d=ctx.rdsInstances||[];title='SQL Databases';sub=d.length+' total';
      d.forEach(db=>{
        let det='Engine: '+db.Engine+' | Class: '+db.DBInstanceClass+' | Status: '+db.DBInstanceStatus;
        if(db.MultiAZ)det+=' | Multi-AZ';
        det+=' | Storage: '+db.AllocatedStorage+'GB';
        if(db.Endpoint)det+='<br>Endpoint: '+esc(db.Endpoint.Address)+':'+esc(db.Endpoint.Port);
        const sid=findSubForRds(db.DBInstanceIdentifier);
        items.push(row(esc(db.DBInstanceIdentifier),det,'#3b82f6',sid?{t:'sub',id:sid}:null));
      });break;
    }
    case 'ECS':case 'Containers':{
      const d=ctx.ecsServices||[];title='Container Instances';sub=d.length+' total';
      d.forEach(svc=>{
        const cluster=(svc.clusterArn||'').split('/').pop();
        const sid=findSubForEcs(svc.serviceName);
        items.push(row(esc(svc.serviceName),'Cluster: '+cluster+' | Launch: '+(svc.launchType||'?')+' | Tasks: '+svc.runningCount+'/'+svc.desiredCount+(svc.cpu?' | CPU: '+svc.cpu:'')+(svc.memory?' | Mem: '+svc.memory+'MB':''),'#f97316',sid?{t:'sub',id:sid}:null));
      });break;
    }
    case 'Lambda':case 'FuncApps':{
      const d=ctx.lambdaFns||[];title='Function Apps';sub=d.length+' total';
      d.forEach(fn=>{
        const sid=findSubForLambda(fn.FunctionName);
        items.push(row(esc(fn.FunctionName),'Runtime: '+fn.Runtime+' | Mem: '+fn.MemorySize+'MB | Timeout: '+fn.Timeout+'s | VPC: '+vpcName(fn.VpcConfig?.VpcId),'#a855f7',sid?{t:'sub',id:sid}:{t:'vpc',id:fn.VpcConfig?.VpcId}));
      });break;
    }
    case 'Cache':case 'Redis':{
      const d=ctx.ecacheClusters||[];title='Redis Caches';sub=d.length+' total';
      d.forEach(c=>{
        const ep=(c.CacheNodes||[]).length>0?c.CacheNodes[0].Endpoint?.Address:'--';
        items.push(row(esc(c.CacheClusterId),'Engine: '+c.Engine+' | Type: '+c.CacheNodeType+' | Nodes: '+c.NumCacheNodes+' | VPC: '+vpcName(c.VpcId)+(ep?'<br>Endpoint: '+esc(ep):''),'#ef4444',c.VpcId?{t:'vpc',id:c.VpcId}:null));
      });break;
    }
    case 'Redshift':case 'Synapse':{
      const d=ctx.redshiftClusters||[];title='Synapse Workspaces';sub=d.length+' total';
      d.forEach(c=>{
        items.push(row(esc(c.ClusterIdentifier),'Type: '+c.NodeType+' | Nodes: '+c.NumberOfNodes+' | Status: '+c.ClusterStatus+' | VPC: '+vpcName(c.VpcId)+(c.Endpoint?'<br>Endpoint: '+esc(c.Endpoint.Address)+':'+esc(c.Endpoint.Port):''),'#dc2626',c.VpcId?{t:'vpc',id:c.VpcId}:null));
      });break;
    }
    case 'Peering':{
      const d=ctx.peerings||[];title='VNet Peering';sub=d.length+' total';
      d.forEach(p=>{
        const req=p.RequesterVpcInfo||{};const acc=p.AccepterVpcInfo||{};
        items.push(row(esc(gn(p,p.VpcPeeringConnectionId)),'Status: '+(p.Status?.Code||'?')+' | Requester: '+vpcName(req.VpcId)+' ('+((req.CidrBlock)||'?')+') | Accepter: '+vpcName(acc.VpcId)+' ('+(acc.CidrBlock||'?')+')','#fb923c',req.VpcId?{t:'vpc',id:req.VpcId}:null));
      });break;
    }
    case 'VPNs':{
      const d=ctx.vpns||[];title='VPN Connections';sub=d.length+' total';
      d.forEach(v=>{
        items.push(row(gn(v,v.VpnConnectionId),'Type: '+(v.Type||'?')+' | State: '+(v.State||'?')+' | VGW: '+(v.VpnGatewayId||'?')+' | CGW: '+(v.CustomerGatewayId||'?'),'#ef4444'));
      });break;
    }
    case 'Endpoints':case 'PvtEndpts':{
      const d=ctx.vpces||[];title='Private Endpoints';sub=d.length+' total';
      d.forEach(e=>{
        items.push(row(gn(e,e.VpcEndpointId),'Service: '+(e.ServiceName||'?').split('.').pop()+' | Type: '+(e.VpcEndpointType||'?')+' | VPC: '+vpcName(e.VpcId),'#a78bfa',e.VpcId?{t:'vpc',id:e.VpcId}:null));
      });break;
    }
    case 'PE':{
      const d=ctx.privateEndpoints||ctx.vpces||[];title='Private Endpoints';sub=d.length+' total';
      d.forEach(pe=>{
        const props=pe.properties||pe._azure?.properties||{};
        const conn=props.privateLinkServiceConnections?.[0];
        const connProps=conn?.properties||{};
        const targetId=connProps.privateLinkServiceId||'';
        const targetName=targetId?targetId.split('/').pop():'?';
        const groupId=(connProps.groupIds||[])[0]||'?';
        const state=connProps.privateLinkServiceConnectionState?.status||'?';
        const stCol=state==='Approved'?'#10b981':state==='Pending'?'#f59e0b':'#ef4444';
        const ip=(props.customDnsConfigs||[])[0]?.ipAddresses?.[0]||'';
        const subId=props.subnet?.id||'';
        const detail='Service: '+esc(groupId)+' | Target: '+esc(targetName)+' | State: <span style="color:'+stCol+'">'+esc(state)+'</span>'+(ip?' | IP: '+esc(ip):'');
        items.push(row(gn(pe,pe.id),detail,'#a78bfa',subId?{t:'sub',id:subId}:null));
      });break;
    }
    case 'Volumes':case 'Disks':{
      const d=ctx.volumes||[];title='Managed Disks';sub=d.length+' total';
      d.forEach(v=>{
        const att=(v.Attachments||[]).map(a=>a.InstanceId).filter(Boolean).join(', ')||'detached';
        items.push(row(gn(v,v.VolumeId),'Size: '+v.Size+'GB | Type: '+(v.VolumeType||'?')+' | State: '+(v.State||'?')+' | AZ: '+(v.AvailabilityZone||'?')+' | Attached: '+att,'#64748b'));
      });break;
    }
    case 'Snapshots':{
      const d=ctx.snapshots||[];title='Disk Snapshots';sub=d.length+' total';
      d.forEach(s=>{
        items.push(row(gn(s,s.SnapshotId),'Volume: '+(s.VolumeId||'?')+' | Size: '+(s.VolumeSize||'?')+'GB | State: '+(s.State||'?')+' | Started: '+((s.StartTime||'').split('T')[0]||'?'),'#94a3b8'));
      });break;
    }
    case 'S3':case 'Storage':{
      const d=ctx.s3bk||[];title='Storage Accounts';sub=d.length+' total';
      d.forEach(b=>{
        items.push(row(esc(b.Name),'Created: '+((b.CreationDate||'').split('T')[0]||'?'),'#ea580c'));
      });break;
    }
    case 'R53':case 'DNS':{
      const d=ctx.zones||[];const rbz=ctx.recsByZone||{};
      title='Azure DNS Private Zones';sub=d.length+' total';
      d.forEach(z=>{
        const priv=z.Config?.PrivateZone;
        const zid=(z.Id||'').replace('/hostedzone/','');
        const vpcsStr=(z.VPCs||[]).map(v=>vpcName(v.VPCId||v.VpcId)).join(', ');
        const firstVpc=(z.VPCs||[])[0];const fvid=firstVpc?.VPCId||firstVpc?.VpcId;
        const zColor=priv?'#0ea5e9':'#10b981';
        const zRecs=rbz[zid]||[];
        let det='ID: '+zid+' | '+(priv?'Private':'Public')+' | Records: '+(z.ResourceRecordSetCount||'?');
        if(vpcsStr)det+=' | VPCs: '+vpcsStr;
        if(zRecs.length>0){
          det+='<div style="margin-top:6px;border-top:1px solid rgba(255,255,255,.08);padding-top:6px">';
          zRecs.forEach(rec=>{
            const rName=esc((rec.Name||'').replace(/\.$/,''));
            const rType=rec.Type||'';
            const rVal=rec.AliasTarget?'ALIAS → '+esc((rec.AliasTarget.DNSName||'').replace(/\.$/,'')):
              esc((rec.ResourceRecords||[]).map(rr=>rr.Value).join(', '));
            const ttl=rec.TTL?'TTL: '+rec.TTL:'';
            const tColor=rType==='A'||rType==='AAAA'?'#34d399':rType==='CNAME'?'#60a5fa':rType==='MX'?'#f59e0b':rType==='TXT'?'#a78bfa':rType==='NS'?'#94a3b8':rType==='SOA'?'#64748b':'#e2e8f0';
            det+='<div style="margin:3px 0;padding:3px 0;display:flex;gap:6px;align-items:baseline">';
            det+='<span style="background:'+tColor+';color:#0f172a;font-size:calc(7px * var(--txt-scale) * var(--dp-txt-scale));font-weight:700;padding:1px 4px;border-radius:2px;min-width:36px;text-align:center;flex-shrink:0">'+rType+'</span>';
            det+='<span style="color:var(--text-primary);font-size:calc(9px * var(--txt-scale) * var(--dp-txt-scale));min-width:120px">'+rName+'</span>';
            det+='<span style="color:var(--text-muted);font-size:calc(8px * var(--txt-scale) * var(--dp-txt-scale));word-break:break-all">'+rVal+(ttl?' <span style="color:#475569;font-size:calc(7px * var(--txt-scale) * var(--dp-txt-scale))">['+ttl+']</span>':'')+'</span>';
            det+='</div>';
          });
          det+='</div>';
        }else{
          det+='<div style="margin-top:4px;color:#64748b;font-size:calc(8px * var(--txt-scale) * var(--dp-txt-scale));font-style:italic">No record sets loaded. Paste output of:<br><code style="color:#0ea5e9;font-size:calc(8px * var(--txt-scale) * var(--dp-txt-scale))">az network dns record-set list --zone-name &lt;zone&gt; --resource-group &lt;rg&gt;</code><br>into the "Record Sets" input field.</div>';
        }
        items.push(row(esc(z.Name),det,zColor,fvid?{t:'vpc',id:fvid}:null));
      });break;
    }
    case 'WAF':{
      const d=ctx.wafAcls||[];title='WAF WebACLs';sub=d.length+' total';
      d.forEach(w=>{
        const rc=(w.Rules||[]).length;const res=(w.ResourceArns||[]).length;
        let det='Rules: '+rc+' | Resources: '+res;
        if(w.Description)det+='<br>'+esc(w.Description);
        if(rc)det+='<br>Rules: '+(w.Rules||[]).map(r=>r.Name).join(', ');
        items.push(row(esc(w.Name),det,'#f59e0b'));
      });break;
    }
    case 'CF':{
      const d=ctx.cfDistributions||[];title='Front Door / CDN Profiles';sub=d.length+' total';
      d.forEach(cf=>{
        const aliases=(cf.Aliases?.Items||[]).join(', ');
        const origins=(cf.Origins?.Items||[]).map(o=>o.DomainName).join(', ');
        let det='ID: '+cf.Id+' | Status: '+(cf.Status||'?');
        if(aliases)det+=' | Aliases: '+aliases;
        det+='<br>Origins: '+origins;
        items.push(row(esc(cf.DomainName||cf.Id),det,'#8b5cf6'));
      });break;
    }
    case 'IAM':{
      const iamData=_iamData||(()=>{const r=safeParse(gv('in_rbac'));if(r){_iamData=parseIAMData(r)}return _iamData})();
      if(!iamData){items.push('<div class="dp-row" style="color:var(--text-muted);padding:12px">No IAM data loaded</div>');title='IAM Principals';sub='No data';break}
      const roles=iamData.roles||[];const users=iamData.users||[];
      title='IAM Principals';sub=roles.length+' roles, '+users.length+' users';
      // Risk summary cards
      let adminCount=0,wildcardCount=0,noMfaCount=0,boundaryCount=0;
      roles.forEach(r=>{if(r._isAdmin)adminCount++;if(r._hasWildcard&&!r._isAdmin)wildcardCount++;if(r.PermissionsBoundary)boundaryCount++});
      users.forEach(u=>{
        let uAdmin=false;const ups=[...(u.UserPolicyList||[]),...(u.AttachedManagedPolicies||[])];
        ups.forEach(p=>{const doc=_safePolicyParse(p.PolicyDocument);_stmtArr(doc.Statement).forEach(s=>{if(s.Effect==='Allow'){const a=Array.isArray(s.Action)?s.Action:[s.Action||''];if(a.some(x=>x==='*'))uAdmin=true}})});
        (u.AttachedManagedPolicies||[]).forEach(mp=>{const pol=(iamData.policies||[]).find(p=>p.Arn===mp.PolicyArn);if(pol){const ver=(pol.PolicyVersionList||[]).find(v=>v.IsDefaultVersion);if(ver){let dd=_safePolicyParse(ver.Document);_stmtArr(dd.Statement).forEach(s=>{if(s.Effect==='Allow'&&(Array.isArray(s.Action)?s.Action:[s.Action||'']).some(x=>x==='*'))uAdmin=true})}}});
        if(uAdmin)adminCount++;
        if(!(u.MFADevices||[]).length)noMfaCount++;
      });
      const riskHtml='<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;padding:8px 0;border-bottom:1px solid var(--border)">'
        +'<div class="iam-risk-card critical"><span class="count">'+adminCount+'</span><span class="label">Admin</span></div>'
        +'<div class="iam-risk-card warning"><span class="count">'+wildcardCount+'</span><span class="label">Wildcard</span></div>'
        +'<div class="iam-risk-card warning"><span class="count">'+noMfaCount+'</span><span class="label">No MFA</span></div>'
        +'<div class="iam-risk-card clean"><span class="count">'+boundaryCount+'</span><span class="label">Boundary</span></div>'
        +'</div>';
      items.push(riskHtml);
      items.push('<div class="iam-dashboard-link" data-action="open-gov-dash">Open Full Governance Dashboard <span style="opacity:.6">\u2192</span></div>');
      // Roles section
      if(roles.length){
        items.push('<div style="font-weight:700;color:var(--accent-cyan);margin:8px 0 4px;font-size:calc(10px * var(--txt-scale,1) * var(--dp-txt-scale,1));text-transform:uppercase;letter-spacing:.5px">ROLES ('+roles.length+')</div>');
        roles.forEach((r,ri)=>{
          const badges=[];
          if(r._isAdmin)badges.push('<span class="sev-badge sev-CRITICAL">ADMIN</span>');
          if(r._hasWildcard&&!r._isAdmin)badges.push('<span class="sev-badge sev-HIGH">WILDCARD</span>');
          if(r.PermissionsBoundary)badges.push('<span class="sev-badge sev-LOW" style="background:rgba(16,185,129,.15);color:#10b981;border-color:rgba(16,185,129,.3)">BOUNDARY</span>');
          const resCount=ctx.iamRoleResources?ctx.iamRoleResources[r.RoleName]:null;
          const rcText=resCount?(' | '+(resCount.vms?.length||0)+' VMs, '+(resCount.functionApps?.length||0)+' Func Apps, '+(resCount.aks?.length||0)+' Containers'):'';
          const trustSvc=r.AssumeRolePolicyDocument?(function(){try{const td=_safePolicyParse(r.AssumeRolePolicyDocument);return _stmtArr(td.Statement).map(s=>{const p=s.Principal||{};return p.Service||p.AWS||''}).flat().join(', ')}catch(e){return ''}})():'';
          items.push('<div class="dp-row" data-iam-role="'+ri+'" style="border-left:3px solid #f59e0b;padding-left:8px;margin:3px 0;cursor:pointer">'+badges.join(' ')+' <span style="color:var(--accent-cyan);text-decoration:underline;text-decoration-style:dashed;text-underline-offset:3px;text-decoration-color:rgba(103,232,249,.3)">'+esc(r.RoleName)+'</span><br><span class="k">Trust: '+esc((trustSvc||'?').substring(0,60))+esc(rcText)+'</span></div>');
        });
      }
      // Users section
      if(users.length){
        items.push('<div style="font-weight:700;color:var(--accent-cyan);margin:12px 0 4px;font-size:calc(10px * var(--txt-scale,1) * var(--dp-txt-scale,1));text-transform:uppercase;letter-spacing:.5px">USERS ('+users.length+')</div>');
        users.forEach((u,ui)=>{
          const badges=[];
          let uAdm=false;const ups2=[...(u.UserPolicyList||[]),...(u.AttachedManagedPolicies||[])];
          ups2.forEach(p=>{const doc=_safePolicyParse(p.PolicyDocument);_stmtArr(doc.Statement).forEach(s=>{if(s.Effect==='Allow'){const a=Array.isArray(s.Action)?s.Action:[s.Action||''];if(a.some(x=>x==='*'))uAdm=true}})});
          (u.AttachedManagedPolicies||[]).forEach(mp=>{const pol=(iamData.policies||[]).find(p=>p.Arn===mp.PolicyArn);if(pol){const ver=(pol.PolicyVersionList||[]).find(v=>v.IsDefaultVersion);if(ver){let dd=_safePolicyParse(ver.Document);_stmtArr(dd.Statement).forEach(s=>{if(s.Effect==='Allow'&&(Array.isArray(s.Action)?s.Action:[s.Action||'']).some(x=>x==='*'))uAdm=true})}}});
          if(uAdm)badges.push('<span class="sev-badge sev-CRITICAL">ADMIN</span>');
          if(!(u.MFADevices||[]).length)badges.push('<span class="sev-badge sev-HIGH">NO MFA</span>');
          else badges.push('<span class="sev-badge sev-LOW" style="background:rgba(16,185,129,.15);color:#10b981;border-color:rgba(16,185,129,.3)">MFA</span>');
          const polCount=(u.UserPolicyList||[]).length+(u.AttachedManagedPolicies||[]).length;
          items.push('<div class="dp-row" data-iam-user="'+ui+'" style="border-left:3px solid #3b82f6;padding-left:8px;margin:3px 0;cursor:pointer">'+badges.join(' ')+' <span style="color:var(--accent-cyan);text-decoration:underline;text-decoration-style:dashed;text-underline-offset:3px;text-decoration-color:rgba(103,232,249,.3)">'+esc(u.UserName)+'</span><br><span class="k">'+polCount+' policies</span></div>');
        });
      }
      // Store iamData for click handlers
      setTimeout(()=>{
        document.querySelectorAll('[data-iam-role]').forEach(el=>{
          el.addEventListener('click',(e)=>{e.stopPropagation();const ri=parseInt(el.dataset.iamRole);const role=(iamData.roles||[])[ri];if(role)openIAMPrincipalPanel(role,iamData,ctx)});
        });
        document.querySelectorAll('.iam-dashboard-link').forEach(function(el){el.addEventListener('click',function(){document.getElementById('detailPanel').classList.remove('open');openGovernanceDashboard('iam')})});
        document.querySelectorAll('[data-iam-user]').forEach(el=>{
          el.addEventListener('click',(e)=>{e.stopPropagation();
            const ui=parseInt(el.dataset.iamUser);const user=(iamData.users||[])[ui];
            if(user){
              // Enrich user with _isAdmin/_hasWildcard for display
              user._isAdmin=false;user._hasWildcard=false;
              const ups3=[...(user.UserPolicyList||[]),...(user.AttachedManagedPolicies||[])];
              ups3.forEach(p=>{const doc=_safePolicyParse(p.PolicyDocument);_stmtArr(doc.Statement).forEach(s=>{if(s.Effect==='Allow'){const a=Array.isArray(s.Action)?s.Action:[s.Action||''];const r=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];if(a.some(x=>x==='*'))user._isAdmin=true;if(r.some(x=>x==='*'))user._hasWildcard=true}})});
              (user.AttachedManagedPolicies||[]).forEach(mp=>{const pol=(iamData.policies||[]).find(p=>p.Arn===mp.PolicyArn);if(pol){const ver=(pol.PolicyVersionList||[]).find(v=>v.IsDefaultVersion);if(ver){let dd=_safePolicyParse(ver.Document);_stmtArr(dd.Statement).forEach(s=>{if(s.Effect==='Allow'){const a=Array.isArray(s.Action)?s.Action:[s.Action||''];const r=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];if(a.some(x=>x==='*'))user._isAdmin=true;if(r.some(x=>x==='*'))user._hasWildcard=true}})}}});
              openIAMPrincipalPanel(user,iamData,ctx);
            }
          });
        });
      },50);
      break;
    }
    default: return;
  }

  const backHtml='<span id="dpBack" style="cursor:pointer;color:var(--accent-blue);font-size:calc(10px * var(--txt-scale) * var(--dp-txt-scale));font-family:Segoe UI,system-ui,sans-serif;margin-right:8px" title="Back">&lt; Back</span>';
  dpTitle.innerHTML=backHtml+title;
  dpSub.textContent=sub;

  // Build with search filter and expand/collapse toggle
  let h='<div style="margin-bottom:8px;display:flex;gap:6px;align-items:center"><input type="text" id="rlFilter" placeholder="Filter..." style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:calc(10px * var(--txt-scale) * var(--dp-txt-scale));padding:5px 8px;box-sizing:border-box">';
  h+='<span id="rlToggleAll" style="font-family:Segoe UI,system-ui,sans-serif;font-size:calc(8px * var(--txt-scale) * var(--dp-txt-scale));color:var(--accent-blue);cursor:pointer;white-space:nowrap;padding:4px 8px;border:1px solid rgba(59,130,246,.3);border-radius:4px;background:rgba(59,130,246,.08)">Collapse All</span></div>';
  h+='<div id="rlItems">'+items.join('')+'</div>';
  dpBody.innerHTML=h;
  dp.classList.add('open');
  addResourceListDesignToolbar(dpBody,ctx,type);
  applyDpScale();

  // back nav from resource list
  const backEl=document.getElementById('dpBack');
  if(backEl){
    backEl.addEventListener('click',(e)=>{
      e.stopPropagation();
      const prev=_navStack.pop();
      if(prev&&prev.fn) prev.fn();
      else { dp.classList.remove('open'); }
    });
  }

  // filter logic
  const filterEl=document.getElementById('rlFilter');
  const itemsEl=document.getElementById('rlItems');
  if(filterEl){
    filterEl.focus();
    filterEl.addEventListener('input',function(){
      const q=this.value.toLowerCase();
      const rows=itemsEl.querySelectorAll('.dp-row');
      rows.forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'});
    });
  }
  // expand/collapse all toggle
  const toggleAllBtn=document.getElementById('rlToggleAll');
  if(toggleAllBtn&&itemsEl){
    let allCollapsed=false;
    toggleAllBtn.addEventListener('click',function(){
      allCollapsed=!allCollapsed;
      itemsEl.querySelectorAll('.dp-row').forEach(r=>{
        if(allCollapsed)r.classList.add('collapsed');
        else r.classList.remove('collapsed');
      });
      this.textContent=allCollapsed?'Expand All':'Collapse All';
    });
  }
  // click-to-navigate
  if(itemsEl){
    itemsEl.addEventListener('click',function(e){
      // toggle detail expand/collapse
      const tog=e.target.closest('.dp-tog');
      if(tog){
        e.stopPropagation();
        tog.closest('.dp-row').classList.toggle('collapsed');
        return;
      }
      // "Go to" nav button - switch layout and zoom
      const navBtn=e.target.closest('.dp-nav-btn[data-nav]');
      if(navBtn){
        e.stopPropagation();
        const t=navBtn.dataset.navT,nid=navBtn.dataset.navId;
        if(!t||!nid)return;
        const layoutSel=document.getElementById('layoutMode');
        const curLayout=layoutSel?.value||'grid';
        // switch to grid if on executive
        if(curLayout==='executive'){
          layoutSel.value='grid';
          layoutSel.dispatchEvent(new Event('change'));
          // wait for re-render then zoom
          setTimeout(()=>{
            MapViewport.zoomToResource(nid);
            setTimeout(()=>MapViewport.flashResource(nid),200);
          },400);
        } else {
          MapViewport.zoomToResource(nid);
          setTimeout(()=>MapViewport.flashResource(nid),200);
        }
        return;
      }
      // regular row click
      const r=e.target.closest('.dp-row[data-act]');if(!r)return;
      const act=r.dataset.act,id=r.dataset.id;if(!act||!id)return;
      MapViewport.zoomToResource(id);
      setTimeout(()=>{
        MapViewport.flashResource(id);
        if(act==='sub'){
          const sub=(ctx.subnets||[]).find(s=>s.SubnetId===id);
          if(sub){
            const vpcId=sub.VpcId;
            openSubnetPanel(sub,vpcId,{pubSubs:ctx.pubSubs,subRT:ctx.subRT,subNacl:ctx.subNacl,instBySub:ctx.instBySub,eniBySub:ctx.eniBySub,albBySub:ctx.albBySub,nsgByVnet:ctx.nsgByVnet,volByInst:ctx.volByInst,enis:ctx.enis,snapByVol:ctx.snapByVol,tgByAlb:ctx.tgByAlb,wafByAlb:ctx.wafByAlb,rdsBySub:ctx.rdsBySub,ecsBySub:ctx.ecsBySub,lambdaBySub:ctx.lambdaBySub,ecacheByVpc:ctx.ecacheByVpc,redshiftByVpc:ctx.redshiftByVpc,cfByAlb:ctx.cfByAlb});
          }
        }
      },300);
    });
  }
}
