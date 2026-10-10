// #region UI UTILITIES & DETAIL PANELS
function positionTooltip(event,tt){
  const r=_getMain().getBoundingClientRect();
  let tx=event.clientX-r.left+16,ty=event.clientY-r.top-10;
  const ttW=tt.offsetWidth||420,ttH=tt.offsetHeight||200;
  if(tx+ttW>r.width) tx=event.clientX-r.left-ttW-10;
  if(ty+ttH>r.height) ty=r.height-ttH-8;
  if(tx<4) tx=4;
  if(ty<4) ty=4;
  tt.style.left=tx+'px';tt.style.top=ty+'px';
}

function copyText(text){
  navigator.clipboard.writeText(text).then(()=>{
    const toast=document.getElementById('copyToast');
    toast.classList.add('show');
    setTimeout(()=>toast.classList.remove('show'),1200);
  }).catch(()=>{});
}


let _lastRlType=null;
let _navStack=[]; // navigation stack for detail panel back button
let _fwDpBodyHandler=null;

var DetailTraceSelection=(function(){
  var current=null;
  return {
    set:function(value){ current=value||null; },
    clear:function(){ current=null; },
    get:function(){ return current; }
  };
})();

function resetDetailNavigation(){
  _lastRlType=null;
  _navStack=[];
}

function detailRuntimeContext(){
  return AppRenderContext.createRenderContext().rlCtx;
}

function detailSubnetLookup(ctx){
  return {
    pubSubs:ctx.pubSubs,
    subRT:ctx.subRT,
    subNacl:ctx.subNacl,
    instBySub:ctx.instBySub,
    eniBySub:ctx.eniBySub,
    albBySub:ctx.albBySub,
    nsgByVnet:ctx.nsgByVnet,
    volByInst:ctx.volByInst,
    enis:ctx.nics,
    snapByVol:ctx.snapByVol,
    tgByAlb:ctx.tgByAlb,
    wafByAlb:ctx.wafByAlb,
    rdsBySub:ctx.rdsBySub,
    ecsBySub:ctx.ecsBySub,
    lambdaBySub:ctx.lambdaBySub,
    ecacheByVpc:ctx.ecacheByVpc,
    redshiftByVpc:ctx.redshiftByVpc,
    cfByAlb:ctx.cfByAlb,
    storageBySub:ctx.storageBySub
  };
}

function detailGatewayLookup(ctx){
  return {
    gwNames,
    igws:ctx.firewalls,
    nats:ctx.natGateways,
    vpns:ctx.vpns,
    vpces:ctx.privateEndpoints,
    peerings:ctx.peerings,
    rts:ctx.udrs,
    subnets:ctx.subnets,
    subRT:ctx.subRT,
    pubSubs:ctx.pubSubs,
    vpcs:ctx.vnets,
    tgwAttachments:ctx.vhubs||[]
  };
}

// Shared detail panel builder for both layouts
function routeTgtHtml(tgtId){
  if(!tgtId||tgtId==='local')return '<span class="p">local</span>';
  const nm=gwNames[tgtId];
  const label=nm?(nm+' ('+tgtId+')'):(tgtId);
  const gwType=clsGw(tgtId);
  if(tgtId.startsWith('nat-'))return '<span class="p dp-link" data-gwid="'+tgtId+'" data-gwtype="NAT" style="cursor:pointer;color:var(--nat-color)">'+label+'</span>';
  if(tgtId.startsWith('tgw-'))return '<span class="p dp-link" data-gwid="'+tgtId+'" data-gwtype="TGW" style="cursor:pointer;color:var(--tgw-color)">'+label+'</span>';
  if(tgtId.startsWith('igw-'))return '<span class="p dp-link" data-gwid="'+tgtId+'" data-gwtype="IGW" style="cursor:pointer;color:var(--igw-color)">'+label+'</span>';
  if(tgtId.startsWith('vgw-'))return '<span class="p dp-link" data-gwid="'+tgtId+'" data-gwtype="VGW" style="cursor:pointer;color:var(--vgw-color)">'+label+'</span>';
  if(tgtId.startsWith('vpce-'))return '<span class="p dp-link" data-gwid="'+tgtId+'" data-gwtype="VPCE" style="cursor:pointer;color:var(--vpce-color)">'+label+'</span>';
  if(tgtId.startsWith('pcx-'))return '<span class="p dp-link" data-gwid="'+tgtId+'" data-gwtype="PCX" style="cursor:pointer;color:var(--pcx-color)">'+label+'</span>';
  return '<span class="p">'+tgtId+'</span>';
}
function openSubnetPanel(sub,vpcId,lk){
  const dp=document.getElementById('detailPanel');
  const dpTitle=document.getElementById('dpTitle');
  const dpSub=document.getElementById('dpSub');
  const dpBody=document.getElementById('dpBody');
  const isPub=lk.pubSubs.has(sub.SubnetId);
  // push current resource list state if coming from one
  if(_lastRlType){
    const savedType=_lastRlType;
    _navStack.push({fn:()=>openResourceList(savedType,false)});
  }
  const backBtn=_navStack.length>0?'<span id="dpBack" style="cursor:pointer;color:var(--accent-blue);font-size:calc(10px * var(--txt-scale) * var(--dp-txt-scale));font-family:Segoe UI,system-ui,sans-serif;margin-right:8px" title="Back">&lt; Back</span>':'';
  dpTitle.innerHTML=backBtn+esc(gn(sub,sub.SubnetId))+' <span class="dp-badge '+(isPub?'pub':'prv')+'">'+(isPub?'PUBLIC':'PRIVATE')+'</span>';
  // IP capacity calculation
  const subPrefix=parseInt((sub.CidrBlock||'').split('/')[1],10);
  const totalIps=isNaN(subPrefix)?0:Math.pow(2,32-subPrefix);
  const usableIps=Math.max(0,totalIps-5);
  const eniCount=(lk.eniBySub[sub.SubnetId]||[]).length;
  const usedIps=eniCount;
  const ipCapHtml=usableIps>0?(' | <span style="color:'+(usedIps>=usableIps?'#dc2626':usedIps>usableIps*0.8?'var(--accent-orange)':'var(--accent-green)')+'">'+usedIps+'/'+usableIps+' IPs used</span>'):'';
  dpSub.innerHTML='<span class="copyable" data-copy="'+esc(sub.SubnetId)+'">'+esc(sub.SubnetId)+'</span> | '+esc(sub.CidrBlock)+' | '+esc(sub.AvailabilityZone||'N/A')+ipCapHtml;
  let h='';
  function sec(title,count,bodyHtml,startOpen){
    return '<div class="dp-section"><div class="dp-sec-hdr'+(startOpen?'':' collapsed')+'" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">'+title+'</span><span><span class="dp-sec-count">'+count+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body'+(startOpen?'':' hidden')+'">'+bodyHtml+'</div></div>';
  }
  // IP capacity visual bar
  if(usableIps>0){
    const pct=Math.min(100,Math.round(usedIps/usableIps*100));
    const barCol=pct>=90?'#dc2626':pct>=70?'var(--accent-orange)':'var(--accent-green)';
    h+='<div style="margin-bottom:8px;padding:6px;background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:4px;column-span:all">';
    h+='<div style="display:flex;justify-content:space-between;font-size:calc(8px * var(--txt-scale) * var(--dp-txt-scale));margin-bottom:3px"><span style="color:var(--text-muted)">IP Capacity</span><span style="color:'+barCol+'">'+pct+'% ('+usedIps+' of '+usableIps+' usable)</span></div>';
    h+='<div style="height:4px;background:var(--bg-tertiary);border-radius:2px;overflow:hidden"><div style="height:100%;width:'+pct+'%;background:'+barCol+';border-radius:2px;transition:width .3s"></div></div>';
    h+='<div style="font-size:calc(7px * var(--txt-scale) * var(--dp-txt-scale));color:var(--text-muted);margin-top:2px">'+totalIps+' total - 5 Azure reserved = '+usableIps+' usable</div>';
    h+='</div>';
  }
  const si=lk.instBySub[sub.SubnetId]||[];
  const se=lk.eniBySub[sub.SubnetId]||[];
  const sa=lk.albBySub[sub.SubnetId]||[];
  const storageLinks=(lk.storageBySub||{})[sub.SubnetId]||[];
  // Route Table (interactive)
  const rt=lk.subRT[sub.SubnetId];
  if(rt){
    h+=sec('Route Table',(rt.Routes||[]).length+' routes',_fwRenderRtInline(rt, vpcId, lk),true);
  }
  // NACLs (interactive)
  const nc=lk.subNacl[sub.SubnetId];
  if(nc){
    h+=sec('NACLs',(nc.Entries||[]).filter(e=>!e.Egress).length+' in / '+(nc.Entries||[]).filter(e=>e.Egress).length+' out',_fwRenderNaclInline(nc, sub),false);
  }
  // Virtual Machines
  if(si.length){
    let eb='';
    si.forEach(inst=>{
      const vols=(lk.volByInst||{})[inst.InstanceId]||[];
      const totalGB=vols.reduce((a,v)=>a+v.Size,0);
      const state=inst.State?.Name||'?';
      const stCls=state==='running'?'running':'stopped';
      eb+='<div class="dp-row">';
      eb+='<span class="i">'+gn(inst,inst.InstanceId)+'</span> <span class="dp-badge '+stCls+'">'+state+'</span>';
      eb+='<div class="dp-props">';
      eb+='<span class="k">ID</span><span class="v">'+inst.InstanceId+'</span>';
      eb+='<span class="k">Type</span><span class="v">'+inst.InstanceType+'</span>';
      if(inst.PrivateIpAddress)eb+='<span class="k">IP</span><span class="v">'+inst.PrivateIpAddress+'</span>';
      eb+='</div>';
      if(vols.length){
        eb+='<div class="dp-sub">';
        eb+='<div class="dp-sub-title">Storage <span class="dp-sub-count">'+totalGB+'GB &middot; '+vols.length+' vol'+(vols.length>1?'s':'')+'</span></div>';
        vols.forEach(v=>{
          const vSnaps=(lk.snapByVol||{})[v.VolumeId]||[];
          eb+='<div class="dp-sub-item"><span class="s">'+v.VolumeId+'</span> '+v.Size+'GB '+(v.VolumeType||'')+' '+(v.State||'');
          if(vSnaps.length){
            eb+=' <span class="k">['+vSnaps.length+' snap'+(vSnaps.length>1?'s':'')+']</span>';
            const latest=vSnaps.sort((a,b)=>(b.StartTime||'').localeCompare(a.StartTime||''))[0];
            if(latest)eb+='<br><span class="k" style="margin-left:8px">Latest:</span> '+latest.SnapshotId+' '+(latest.StartTime||'').split('T')[0]+' '+(latest.State||'');
          }
          eb+='</div>';
        });
        eb+='</div>';
      }
      const instEnis=(lk.enis||[]).filter(e=>e.Attachment&&e.Attachment.InstanceId===inst.InstanceId);
      if(instEnis.length){
        eb+='<div class="dp-sub">';
        eb+='<div class="dp-sub-title">NICs <span class="dp-sub-count">'+instEnis.length+'</span></div>';
        instEnis.forEach(e=>{
          eb+='<div class="dp-sub-item">'+e.NetworkInterfaceId+' <span style="color:var(--text-muted)">'+(e.PrivateIpAddress||'')+'</span> <span style="color:var(--accent-orange)">'+(e.InterfaceType||'')+'</span></div>';
        });
        eb+='</div>';
      }
      eb+='</div>';
    });
    h+=sec('Virtual Machines',si.length,eb,true);
  }
  // ENIs
  if(se.length){
    let enb='';
    se.forEach(e=>{
      enb+='<div class="dp-row">';
      enb+='<span class="i">'+e.NetworkInterfaceId+'</span>';
      enb+='<div class="dp-props">';
      enb+='<span class="k">Type</span><span class="v">'+(e.InterfaceType||'N/A')+'</span>';
      enb+='<span class="k">Status</span><span class="v">'+(e.Status||'?')+'</span>';
      if(e.PrivateIpAddress)enb+='<span class="k">Private IP</span><span class="v">'+e.PrivateIpAddress+'</span>';
      if(e.Description)enb+='<span class="k">Desc</span><span class="v">'+e.Description+'</span>';
      if(e.Attachment&&e.Attachment.InstanceId)enb+='<span class="k">Attached to</span><span class="v"><span class="i">'+e.Attachment.InstanceId+'</span></span>';
      const eSgs=(e.Groups||[]);
      if(eSgs.length)enb+='<span class="k">SGs</span><span class="v">'+eSgs.map(g=>g.GroupName||g.GroupId).join(', ')+'</span>';
      enb+='</div>';
      enb+='</div>';
    });
    h+=sec('NICs',se.length,enb,true);
  }
  // Load Balancers
  if(sa.length){
    let lb='';
    sa.forEach(a=>{
      lb+='<div class="dp-row">';
      lb+='<span class="i">'+a.LoadBalancerName+'</span>';
      lb+='<div class="dp-props">';
      lb+='<span class="k">Type</span><span class="v">'+a.Type+'</span>';
      lb+='<span class="k">Scheme</span><span class="v">'+a.Scheme+'</span>';
      if(a.DNSName)lb+='<span class="k">DNS</span><span class="v">'+a.DNSName+'</span>';
      if(a.LoadBalancerArn)lb+='<span class="k">ARN</span><span class="v" style="font-size:calc(8px * var(--txt-scale) * var(--dp-txt-scale))">'+a.LoadBalancerArn+'</span>';
      lb+='</div>';
      if(a.LoadBalancerArn){
        const albTgs=(lk.tgByAlb||{})[a.LoadBalancerArn]||[];
        if(albTgs.length){
          lb+='<div class="dp-sub">';
          lb+='<div class="dp-sub-title">Backend Pools <span class="dp-sub-count">'+albTgs.length+'</span></div>';
          albTgs.forEach(tg=>{
            lb+='<div class="dp-sub-item"><span class="i">'+(tg.TargetGroupName||tg.TargetGroupArn.split('/')[1]||'')+'</span>';
            lb+=' <span class="k">'+tg.Protocol+':'+tg.Port+'</span> ['+tg.TargetType+']';
            lb+=' HC:'+tg.HealthCheckPath;
            const tCount=(tg.Targets||[]).length;
            if(tCount)lb+=' <span class="p">'+tCount+' target'+(tCount>1?'s':'')+'</span>';
            lb+='</div>';
          });
          lb+='</div>';
        }
        const albWafs=(lk.wafByAlb||{})[a.LoadBalancerArn]||[];
        if(albWafs.length){
          lb+='<div class="dp-sub">';
          lb+='<div class="dp-sub-title" style="color:#f59e0b">WAF WebACLs <span class="dp-sub-count">'+albWafs.length+'</span></div>';
          albWafs.forEach(w=>{
            lb+='<div class="dp-sub-item"><span class="i" style="color:#f59e0b">'+w.Name+'</span>';
            if(w.Description)lb+=' <span class="k">'+w.Description+'</span>';
            const rCount=(w.Rules||[]).length;
            if(rCount)lb+='<br><span class="k" style="margin-left:8px">Rules:</span> '+(w.Rules||[]).map(r=>r.Name).join(', ');
            lb+='</div>';
          });
          lb+='</div>';
        }
        const albCfs=(lk.cfByAlb||{})[a.LoadBalancerArn]||[];
        if(albCfs.length){
          lb+='<div class="dp-sub">';
          lb+='<div class="dp-sub-title" style="color:#8b5cf6">Front Door <span class="dp-sub-count">'+albCfs.length+'</span></div>';
          albCfs.forEach(d=>{
            lb+='<div class="dp-sub-item"><span class="i" style="color:#8b5cf6">'+d.DomainName+'</span>';
            const aliases=(d.Aliases?.Items||[]);
            if(aliases.length)lb+=' ['+aliases.join(', ')+']';
            lb+='</div>';
          });
          lb+='</div>';
        }
      }
      lb+='</div>';
    });
    h+=sec('Load Balancers',sa.length,lb,false);
  }
  // RDS Instances
  const sr=(lk.rdsBySub||{})[sub.SubnetId]||[];
  if(sr.length){
    let rb='';
    sr.forEach(db=>{
      rb+='<div class="dp-row">';
      rb+='<span class="i" style="color:#3b82f6">'+db.DBInstanceIdentifier+'</span>';
      if(db.MultiAZ)rb+=' <span class="dp-badge" style="background:rgba(249,115,22,.15);color:var(--accent-orange)">Multi-AZ</span>';
      rb+='<div class="dp-props">';
      rb+='<span class="k">Engine</span><span class="v">'+db.Engine+'</span>';
      rb+='<span class="k">Class</span><span class="v">'+db.DBInstanceClass+'</span>';
      rb+='<span class="k">Status</span><span class="v">'+db.DBInstanceStatus+'</span>';
      if(db.Endpoint)rb+='<span class="k">Endpoint</span><span class="v">'+db.Endpoint.Address+':'+db.Endpoint.Port+'</span>';
      rb+='<span class="k">Storage</span><span class="v">'+db.AllocatedStorage+'GB'+(db.StorageEncrypted?' (encrypted)':'')+'</span>';
      rb+='</div>';
      rb+='</div>';
    });
    h+=sec('SQL Databases',sr.length,rb,false);
  }
  // ECS Services
  const secs=(lk.ecsBySub||{})[sub.SubnetId]||[];
  if(secs.length){
    let eb='';
    secs.forEach(svc=>{
      eb+='<div class="dp-row">';
      eb+='<span class="i" style="color:#f97316">'+svc.serviceName+'</span>';
      const cluster=(svc.clusterArn||'').split('/').pop();
      eb+='<div class="dp-props">';
      eb+='<span class="k">Cluster</span><span class="v">'+cluster+'</span>';
      eb+='<span class="k">Launch</span><span class="v">'+(svc.launchType||'?')+'</span>';
      eb+='<span class="k">Tasks</span><span class="v">'+svc.runningCount+'/'+svc.desiredCount+' running</span>';
      if(svc.cpu)eb+='<span class="k">CPU</span><span class="v">'+svc.cpu+'</span>';
      if(svc.memory)eb+='<span class="k">Mem</span><span class="v">'+svc.memory+'MB</span>';
      eb+='</div>';
      eb+='</div>';
    });
    h+=sec('Container Instances',secs.length,eb,false);
  }
  // Lambda Functions
  const slm=(lk.lambdaBySub||{})[sub.SubnetId]||[];
  if(slm.length){
    let lmb='';
    slm.forEach(fn=>{
      lmb+='<div class="dp-row">';
      lmb+='<span class="i" style="color:#a855f7">'+fn.FunctionName+'</span>';
      lmb+='<div class="dp-props">';
      lmb+='<span class="k">Runtime</span><span class="v">'+fn.Runtime+'</span>';
      lmb+='<span class="k">Mem</span><span class="v">'+fn.MemorySize+'MB</span>';
      lmb+='<span class="k">Timeout</span><span class="v">'+fn.Timeout+'s</span>';
      lmb+='</div>';
      lmb+='</div>';
    });
    h+=sec('Function Apps',slm.length,lmb,false);
  }
  // Storage Accounts reachable from this subnet
  if(storageLinks.length){
    let stb='';
    storageLinks.forEach(link=>{
      const st=link.account||link;
      const info=_storageInfo(st,{linksByStorageId:{[(_saId(st).toLowerCase()||_saName(st).toLowerCase())]:[link]}});
      stb+='<div class="dp-row">';
      stb+='<span class="i" style="color:'+info.color+'">'+esc(_saName(st))+'</span> <span class="dp-badge" style="background:'+info.bg+';color:'+info.color+'">'+esc(link.via)+'</span>';
      stb+='<div class="dp-props">';
      if(info.sku)stb+='<span class="k">SKU</span><span class="v">'+esc(info.sku)+'</span>';
      stb+='<span class="k">Access</span><span class="v">'+esc(info.access)+'</span>';
      if(info.tls)stb+='<span class="k">TLS</span><span class="v">'+esc(info.tls)+'</span>';
      stb+='<span class="k">Services</span><span class="v">'+esc(info.services.join(', '))+'</span>';
      if(link.detail)stb+='<span class="k">Link</span><span class="v">'+esc(link.detail)+'</span>';
      stb+='</div></div>';
    });
    h+=sec('Storage Accounts',storageLinks.length,stb,false);
  }
  // Security Groups (interactive)
  const vSgs=lk.nsgByVnet[vpcId]||[];
  const subSgIds=new Set();
  se.forEach(e=>(e.Groups||[]).forEach(g=>subSgIds.add(g.GroupId)));
  const subSgs=vSgs.filter(sg=>subSgIds.has(sg.GroupId));
  const displaySgs=subSgs.length?subSgs:vSgs;
  if(displaySgs.length){
    let sgb='';
    displaySgs.forEach(sg=>{sgb+=_fwRenderSgInline(sg)});
    if(subSgs.length&&vSgs.length>subSgs.length){
      sgb+='<div class="dp-row"><span class="k">+ '+(vSgs.length-subSgs.length)+' more SGs in VNet (not attached to this subnet)</span></div>';
    }
    h+=sec('Security Groups',displaySgs.length,sgb,false);
  }
  // --- Split point: everything above goes to left column, compliance goes to right ---
  var hLeft=h; h='';
  // Compliance Findings for this subnet and its resources
  const complianceFindings=AppRenderContext.createRenderContext().complianceFindings || [];
  if(complianceFindings.length){
    const subResIds=new Set([sub.SubnetId,vpcId]);
    si.forEach(inst=>subResIds.add(inst.InstanceId));
    (lk.rdsBySub[sub.SubnetId]||[]).forEach(db=>subResIds.add(db.DBInstanceIdentifier));
    displaySgs.forEach(sg=>subResIds.add(sg.GroupId));
    if(nc)subResIds.add(nc.NetworkAclId);
    if(rt)subResIds.add(rt.RouteTableId);
    sa.forEach(a=>subResIds.add(a.LoadBalancerName));
    const subFindings=complianceFindings.filter(f=>!_isMuted(f)&&subResIds.has(f.resource));
    if(subFindings.length){
      let cfb='';
      subFindings.sort((a,b)=>(_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9));
      subFindings.forEach(f=>{
        cfb+='<div class="dp-row" style="border-left:3px solid '+(f.severity==='CRITICAL'?'#ef4444':f.severity==='HIGH'?'#f97316':f.severity==='MEDIUM'?'#eab308':'#3b82f6')+';padding-left:8px">';
        cfb+='<span class="sev-badge sev-'+f.severity+'" style="font-size:8px;padding:1px 4px">'+f.severity+'</span> ';
        cfb+='<span style="color:var(--accent-cyan);font-size:10px">'+f.control+(f.ckv?' <span style="opacity:.5">('+f.ckv+')</span>':'')+'</span> ';
        cfb+='<span style="color:var(--text-muted);font-size:9px">['+f.framework+']</span><br>';
        cfb+='<span style="color:var(--text-secondary);font-size:10px">'+esc(f.message)+'</span><br>';
        cfb+='<span style="color:var(--text-muted);font-size:9px;font-style:italic">'+esc(f.remediation)+'</span>';
        cfb+='</div>';
      });
      h+=sec('Compliance Findings',subFindings.length,cfb,subFindings.some(f=>f.severity==='CRITICAL'||f.severity==='HIGH'));
    }
  }
  var hRight=h; h='';
  // === Related Resources section ===
  const detailCtx=detailRuntimeContext();
  if(detailCtx){
    let relBody='';
    // --- Network Flow Paths ---
    const naclIn=nc?(nc.Entries||[]).filter(e=>!e.Egress).length:0;
    const naclOut=nc?(nc.Entries||[]).filter(e=>e.Egress).length:0;
    const sgCount=displaySgs?displaySgs.length:0;
    const sgInRules=displaySgs?displaySgs.reduce((a,sg)=>a+(sg.IpPermissions||[]).length,0):0;
    const sgOutRules=displaySgs?displaySgs.reduce((a,sg)=>a+(sg.IpPermissionsEgress||[]).length,0):0;
    const rdsCount=(lk.rdsBySub[sub.SubnetId]||[]).length;
    const ecsCount=(lk.ecsBySub[sub.SubnetId]||[]).length;
    const lamCount=(lk.lambdaBySub[sub.SubnetId]||[]).length;
    let resParts=[];
    if(si.length) resParts.push(si.length+' EC2');
    if(rdsCount) resParts.push(rdsCount+' RDS');
    if(ecsCount) resParts.push(ecsCount+' ECS');
    if(lamCount) resParts.push(lamCount+' Lambda');
    if(sa.length) resParts.push(sa.length+' ALB');
    const resLabel=resParts.length?resParts.join(' &middot; '):'no resources';

    // Build ingress flow per gateway source
    const gwTargets=[];
    if(rt){
      (rt.Routes||[]).forEach(r=>{
        const gw=r.GatewayId||r.NatGatewayId||r.TransitGatewayId||r.VpcPeeringConnectionId||r.VpcEndpointId||'';
        if(gw&&gw!=='local'){
          const type=_isIgwRoute(gw)?'Internet':_isNatRoute(gw)?'NAT':_isVpnRoute(gw)?'VPN':gw.startsWith('tgw-')?'vWAN':gw.startsWith('pcx-')?'Peering':gw.startsWith('vpce-')?'Private Endpoint':gw==='VnetLocal'?'VNet Local':'GW';
          if(!gwTargets.some(g=>g.id===gw)) gwTargets.push({id:gw,type:type,dest:r.DestinationCidrBlock||'',name:gn({Tags:((detailCtx.firewalls||[]).concat(detailCtx.natGateways||[]).find(x=>(x.InternetGatewayId||x.NatGatewayId||x.TransitGatewayId||'')===gw)||{}).Tags},gw)});
        }
      });
    }

    // Source labels and role descriptions for gateway types
    const gwSource=(g)=>g.type==='IGW'?'Internet':g.type==='NAT'?'Internet (outbound)':g.type==='TGW'?'Other VNets / On-prem':g.type==='Peering'?'Peered VNet':g.type==='VGW'?'On-premises (VPN)':g.type==='VPCE'?'Azure Service':'External';
    const gwRole=(t)=>t==='IGW'?'Edge gateway':t==='NAT'?'Network translation':t==='TGW'?'Transit hub':t==='Peering'?'Cross-VNet link':t==='VGW'?'VPN tunnel':t==='VPCE'?'Private link':'Gateway';
    // Build hop pill with role descriptor
    function _hop(n,lbl,det,role,attrs){
      return '<span class="dp-flow-hop"'+(attrs||'')+'><span class="dp-flow-hopnum">'+n+'</span><div class="dp-flow-hopbody"><span class="dp-flow-hoplbl">'+lbl+'</span><span class="dp-flow-hopdet">'+det+'</span><span class="dp-flow-hoprole">'+role+'</span></div></span>';
    }
    // Compute NACL allow/deny breakdown
    const naclAllowIn=nc?(nc.Entries||[]).filter(e=>!e.Egress&&e.RuleAction==='allow').length:0;
    const naclDenyIn=naclIn-naclAllowIn;
    const naclAllowOut=nc?(nc.Entries||[]).filter(e=>e.Egress&&e.RuleAction==='allow').length:0;
    const naclDenyOut=naclOut-naclAllowOut;
    // Compute common open ports from SG inbound rules
    const openPorts=new Set();
    if(displaySgs) displaySgs.forEach(sg=>(sg.IpPermissions||[]).forEach(p=>{
      if(p.FromPort===p.ToPort&&p.FromPort>0) openPorts.add(p.FromPort);
      else if(p.FromPort===-1) openPorts.add('all');
    }));
    const portStr=openPorts.size?[...openPorts].slice(0,5).join(', '):'none';
    const rtRouteCount=rt?(rt.Routes||[]).length:0;

    relBody+='<div class="dp-flow-paths">';
    relBody+='<div class="dp-flow-label">INGRESS</div>';
    if(gwTargets.length){
      gwTargets.forEach((g,gi)=>{
        relBody+='<div class="dp-flow-row">';
        relBody+=_hop(1,gwSource(g),esc(g.dest),'Traffic origin');
        relBody+='<span class="dp-dep-arrow">&rarr;</span>';
        relBody+='<span class="dp-flow-hop" data-rel-gw="'+esc(g.id)+'" data-rel-gwtype="'+esc(g.type)+'" style="border-color:'+gcv(g.type)+'"><span class="dp-flow-hopnum">2</span><div class="dp-flow-hopbody"><span class="dp-flow-hoplbl">'+g.type+'</span><span class="dp-flow-hopdet">'+esc(g.name)+'</span><span class="dp-flow-hoprole">'+gwRole(g.type)+'</span></div></span>';
        relBody+='<span class="dp-dep-arrow">&rarr;</span>';
        relBody+=_hop(3,'Route Table',(rt?esc(gn(rt,rt.RouteTableId)):'none')+' &middot; '+rtRouteCount+' routes','Path selection','data-rel-scroll="Route Table"');
        relBody+='<span class="dp-dep-arrow">&rarr;</span>';
        relBody+=_hop(4,'Subnet NSG',naclAllowIn+' allow &middot; '+naclDenyIn+' deny','Stateless filter','data-rel-scroll="NACLs"');
        relBody+='<span class="dp-dep-arrow">&rarr;</span>';
        relBody+=_hop(5,'SGs',sgCount+' groups &middot; ports: '+portStr,'Stateful filter','data-rel-scroll="Security Groups"');
        relBody+='<span class="dp-dep-arrow">&rarr;</span>';
        relBody+=_hop(6,'Resources',resLabel,'Destination','data-rel-scroll="Virtual Machines"');
        relBody+='</div>';
      });
    } else {
      relBody+='<div class="dp-flow-row">';
      relBody+=_hop(1,'VPC Local',esc(sub.CidrBlock||''),'Traffic origin');
      relBody+='<span class="dp-dep-arrow">&rarr;</span>';
      relBody+=_hop(2,'Route Table',(rt?esc(gn(rt,rt.RouteTableId)):'none')+' &middot; '+rtRouteCount+' routes','Path selection','data-rel-scroll="Route Table"');
      relBody+='<span class="dp-dep-arrow">&rarr;</span>';
      relBody+=_hop(3,'Subnet NSG',naclAllowIn+' allow &middot; '+naclDenyIn+' deny','Stateless filter','data-rel-scroll="NACLs"');
      relBody+='<span class="dp-dep-arrow">&rarr;</span>';
      relBody+=_hop(4,'SGs',sgCount+' groups &middot; ports: '+portStr,'Stateful filter','data-rel-scroll="Security Groups"');
      relBody+='<span class="dp-dep-arrow">&rarr;</span>';
      relBody+=_hop(5,'Resources',resLabel,'Destination','data-rel-scroll="Virtual Machines"');
      relBody+='</div>';
    }

    // Egress flow
    relBody+='<div class="dp-flow-label" style="margin-top:8px">EGRESS</div>';
    relBody+='<div class="dp-flow-row">';
    relBody+=_hop(1,'Resources',resLabel,'Traffic origin','data-rel-scroll="Virtual Machines"');
    relBody+='<span class="dp-dep-arrow">&rarr;</span>';
    relBody+=_hop(2,'SGs',sgOutRules+' outbound rules','Stateful filter','data-rel-scroll="Security Groups"');
    relBody+='<span class="dp-dep-arrow">&rarr;</span>';
    relBody+=_hop(3,'Subnet NSG',naclAllowOut+' allow &middot; '+naclDenyOut+' deny','Stateless filter','data-rel-scroll="NACLs"');
    relBody+='<span class="dp-dep-arrow">&rarr;</span>';
    relBody+=_hop(4,'Route Table',(rt?esc(gn(rt,rt.RouteTableId)):'none')+' &middot; '+rtRouteCount+' routes','Path selection','data-rel-scroll="Route Table"');
    relBody+='<span class="dp-dep-arrow">&rarr;</span>';
    if(gwTargets.length){
      const gwLabels=gwTargets.map(g=>g.type).filter((v,i,a)=>a.indexOf(v)===i).join(' / ');
      relBody+=_hop(5,gwLabels,gwTargets.map(g=>esc(g.dest)).join(', '),'Egress target');
    } else {
      relBody+=_hop(5,'VPC Local','local routing only','Egress target');
    }
    relBody+='</div>';
    relBody+='</div>';

    // --- VPC Sibling Subnets ---
    const allSubs=(detailCtx.subnets||[]).filter(s=>s.VpcId===vpcId&&s.SubnetId!==sub.SubnetId);
    if(allSubs.length){
      // Group by AZ
      const byAz={};
      allSubs.forEach(s=>{const az=s.AvailabilityZone||'unknown';if(!byAz[az])byAz[az]=[];byAz[az].push(s)});
      relBody+='<div class="dp-related-group"><div class="dp-related-title">VNet Subnets ('+allSubs.length+')</div>';
      Object.keys(byAz).sort().forEach(az=>{
        byAz[az].forEach(s=>{
          const sIsPub=lk.pubSubs&&lk.pubSubs.has(s.SubnetId);
          const sInst=(lk.instBySub[s.SubnetId]||[]).length;
          const sEni=(lk.eniBySub[s.SubnetId]||[]).length;
          const sAlb=(lk.albBySub[s.SubnetId]||[]).length;
          const resCnt=sInst+sEni+sAlb;
          relBody+='<div class="dp-related-item" data-rel-sub="'+esc(s.SubnetId)+'">';
          relBody+='<span class="rel-name">'+esc(gn(s,s.SubnetId))+'</span>';
          relBody+='<span class="rel-cidr">'+esc(s.CidrBlock||'')+'</span>';
          relBody+='<span class="rel-badge '+(sIsPub?'pub':'prv')+'">'+(sIsPub?'PUB':'PRV')+'</span>';
          if(resCnt) relBody+='<span class="rel-count">'+resCnt+' res</span>';
          relBody+='<span class="rel-az">'+esc(az)+'</span>';
          relBody+='</div>';
        });
      });
      relBody+='</div>';
    }

    // --- Cross-Subnet Connections ---
    const crossLinks=[];
    // ALB targeting: find ALBs in other subnets targeting instances in this subnet
    const myInstIds=new Set(si.map(i=>i.InstanceId));
    const myAlbArns=new Set(sa.map(a=>a.LoadBalancerArn));
    if(detailCtx.appGateways&&detailCtx.tgByAlb){
      (detailCtx.appGateways||[]).filter(a=>a.VpcId===vpcId||((a.AvailabilityZones||[]).some(az=>az.SubnetId&&(detailCtx.subnets||[]).find(s=>s.SubnetId===az.SubnetId&&s.VpcId===vpcId)))).forEach(alb=>{
        const tgs=detailCtx.tgByAlb[alb.LoadBalancerArn]||[];
        const isMyAlb=myAlbArns.has(alb.LoadBalancerArn);
        tgs.forEach(tg=>{
          const targets=tg.Targets||[];
          const hitsHere=targets.filter(t=>myInstIds.has(t.Id));
          if(!isMyAlb&&hitsHere.length){
            // External ALB targets our instances
            const albSub=(alb.AvailabilityZones||[]).map(az=>az.SubnetId).filter(Boolean)[0]||'?';
            crossLinks.push({type:'alb-in',label:alb.LoadBalancerName||'ALB',detail:'targets '+hitsHere.length+' instance'+(hitsHere.length>1?'s':'')+' here',subId:albSub,icon:'&#8592;'});
          }
          if(isMyAlb){
            // Our ALB targets instances in other subnets
            const extTargets=targets.filter(t=>!myInstIds.has(t.Id));
            if(extTargets.length){
              // Find which subnets the targets are in
              const targetSubs=new Set();
              extTargets.forEach(t=>{
                for(const sid in lk.instBySub){
                  if(sid!==sub.SubnetId&&(lk.instBySub[sid]||[]).some(i=>i.InstanceId===t.Id)) targetSubs.add(sid);
                }
              });
              if(targetSubs.size) crossLinks.push({type:'alb-out',label:alb.LoadBalancerName||'ALB',detail:'targets '+extTargets.length+' instance'+(extTargets.length>1?'s':'')+' in '+targetSubs.size+' other subnet'+(targetSubs.size>1?'s':''),subId:null,icon:'&#8594;'});
            }
          }
        });
      });
    }
    // Shared SGs: find other subnets with ENIs sharing our SGs
    const mySgIds=new Set();
    se.forEach(e=>(e.Groups||[]).forEach(g=>mySgIds.add(g.GroupId)));
    si.forEach(inst=>(inst.SecurityGroups||[]).forEach(g=>mySgIds.add(g.GroupId)));
    if(mySgIds.size&&detailCtx.nics){
      const sharedSubs={};
      detailCtx.nics.forEach(e=>{
        if(e.VpcId!==vpcId) return;
        const eSub=e.SubnetId;
        if(!eSub||eSub===sub.SubnetId) return;
        const shared=(e.Groups||[]).filter(g=>mySgIds.has(g.GroupId));
        if(shared.length){
          if(!sharedSubs[eSub]) sharedSubs[eSub]={sgs:new Set(),count:0};
          shared.forEach(g=>sharedSubs[eSub].sgs.add(g.GroupName||g.GroupId));
          sharedSubs[eSub].count++;
        }
      });
      Object.entries(sharedSubs).forEach(([sid,info])=>{
        crossLinks.push({type:'sg',label:info.sgs.size+' shared SG'+(info.sgs.size>1?'s':''),detail:info.count+' NIC'+(info.count>1?'s':'')+' in '+sid.slice(0,16),subId:sid,icon:'&#8596;'});
      });
    }
    // Peering / TGW routes
    if(rt){
      (rt.Routes||[]).forEach(r=>{
        const pcx=r.VpcPeeringConnectionId;
        const tgw=r.TransitGatewayId;
        if(pcx){
          const peer=(detailCtx.peerings||[]).find(p=>p.VpcPeeringConnectionId===pcx);
          const peerVpc=peer?(peer.AccepterVpcInfo&&peer.AccepterVpcInfo.VpcId!==vpcId?peer.AccepterVpcInfo.VpcId:peer.RequesterVpcInfo&&peer.RequesterVpcInfo.VpcId!==vpcId?peer.RequesterVpcInfo.VpcId:'?'):'?';
          crossLinks.push({type:'peering',label:'Peering '+pcx.slice(0,12),detail:'to VNet '+peerVpc.slice(0,16)+' via '+(r.DestinationCidrBlock||'?'),subId:null,icon:'&#8644;'});
        }
        if(tgw){
          crossLinks.push({type:'tgw',label:'TGW '+tgw.slice(0,14),detail:'route to '+(r.DestinationCidrBlock||'?'),subId:null,icon:'&#8644;'});
        }
      });
    }
    if(crossLinks.length){
      relBody+='<div class="dp-related-group"><div class="dp-related-title">Cross-Subnet Links ('+crossLinks.length+')</div>';
      crossLinks.forEach(cl=>{
        relBody+='<div class="dp-related-item'+(cl.subId?' data-rel-sub="'+esc(cl.subId)+'"':'')+'">';
        relBody+='<span style="color:var(--text-muted);min-width:16px;text-align:center">'+cl.icon+'</span>';
        relBody+='<span class="rel-name" style="color:'+(cl.type==='sg'?'var(--accent-orange)':cl.type.startsWith('alb')?'var(--accent-cyan)':'var(--accent-purple)')+'">'+esc(cl.label)+'</span>';
        relBody+='<span style="color:var(--text-muted);font-size:calc(9px * var(--txt-scale) * var(--dp-txt-scale))">'+esc(cl.detail)+'</span>';
        relBody+='</div>';
      });
      relBody+='</div>';
    }

    const totalRelated=allSubs.length+crossLinks.length;
    if(totalRelated) h+=sec('Related Resources',totalRelated,relBody,true);
  }

  // Wrap sections in grid container (2-col grid in fullscreen)
  var hFull=h;
  h='<div class="dp-grid"><div class="dp-col-left">'+hLeft+'</div><div class="dp-col-right">'+hRight+'</div><div class="dp-col-full">'+hFull+'</div></div>';
  document.getElementById('dpExpandAll').style.display='';
  document.getElementById('dpCollapseAll').style.display='';
  document.getElementById('dpTraceFrom').style.display='';
  dpBody.innerHTML=h;
  dp.classList.add('open');
  if(_fwDpBodyHandler) dpBody.removeEventListener('click', _fwDpBodyHandler);
  _fwDpBodyHandler = function(ev){ _fwHandleAction(ev, sub, vpcId, lk); };
  dpBody.addEventListener('click', _fwDpBodyHandler);
  injectDesignToolbar(dpBody,{type:'subnet',data:sub});
  applyDpScale();
  DetailTraceSelection.set({type:'subnet',id:sub.SubnetId});
  dpBody.querySelectorAll('.dp-link').forEach(el=>{
    el.addEventListener('click',(e)=>{
      e.stopPropagation();
      const gwId=el.dataset.gwid, gwType=el.dataset.gwtype;
      const detailCtx=detailRuntimeContext();
      if(!gwId||!detailCtx) return;
      _navStack.push({fn:()=>{ openSubnetPanel(sub,vpcId,lk); MapViewport.zoomToResource(sub.SubnetId); }});
      openGatewayPanel(gwId,gwType,detailGatewayLookup(detailCtx));
      MapViewport.zoomToResource(gwId);
      MapViewport.highlightGateway(gwId);
    });
  });
  // Related Resources: click sibling subnet → navigate
  dpBody.querySelectorAll('[data-rel-sub]').forEach(el=>{
    el.addEventListener('click',(e)=>{
      e.stopPropagation();
      const targetSubId=el.dataset.relSub;
      const detailCtx=detailRuntimeContext();
      if(!targetSubId||!detailCtx) return;
      const targetSub=(detailCtx.subnets||[]).find(s=>s.SubnetId===targetSubId);
      if(!targetSub) return;
      _navStack.push({fn:()=>{ openSubnetPanel(sub,vpcId,lk); MapViewport.zoomToResource(sub.SubnetId); }});
      openSubnetPanel(targetSub,targetSub.VpcId,detailSubnetLookup(detailCtx));
      MapViewport.zoomToResource(targetSubId);
    });
  });
  // Related Resources: click gateway node → open gateway panel
  dpBody.querySelectorAll('[data-rel-gw]').forEach(el=>{
    el.addEventListener('click',(e)=>{
      e.stopPropagation();
      const gwId2=el.dataset.relGw, gwType2=el.dataset.relGwtype;
      const detailCtx=detailRuntimeContext();
      if(!gwId2||!detailCtx) return;
      _navStack.push({fn:()=>{ openSubnetPanel(sub,vpcId,lk); MapViewport.zoomToResource(sub.SubnetId); }});
      openGatewayPanel(gwId2,gwType2,detailGatewayLookup(detailCtx));
      MapViewport.zoomToResource(gwId2);
    });
  });
  // Related Resources: click dependency chain node → scroll to that section
  dpBody.querySelectorAll('[data-rel-scroll]').forEach(el=>{
    el.addEventListener('click',(e)=>{
      e.stopPropagation();
      const target=el.dataset.relScroll;
      const secHdrs=dpBody.querySelectorAll('.dp-sec-title');
      for(const hdr of secHdrs){
        if(hdr.textContent.trim()===target){
          const secEl=hdr.closest('.dp-section');
          if(secEl){
            const hdrEl=secEl.querySelector('.dp-sec-hdr');
            if(hdrEl&&hdrEl.classList.contains('collapsed')) hdrEl.click();
            secEl.scrollIntoView({behavior:'smooth',block:'start'});
          }
          break;
        }
      }
    });
  });
  const backEl=document.getElementById('dpBack');
  if(backEl){backEl.addEventListener('click',()=>{
    const prev=_navStack.pop();
    if(prev&&prev.fn) prev.fn();
    else { dp.classList.remove('open'); }
  })}
}

// Gateway detail panel - shows info for IGW, TGW, NAT, VGW, PCX, VPCE
function openGatewayPanel(gwId,gwType,lk){
  const dp=document.getElementById('detailPanel');
  const dpTitle=document.getElementById('dpTitle');
  const dpSub=document.getElementById('dpSub');
  const dpBody=document.getElementById('dpBody');
  const nm=esc(lk.gwNames[gwId]||gwId);
  const col=gcv(gwType);
  function sec(title,count,bodyHtml,startOpen){
    return '<div class="dp-section"><div class="dp-sec-hdr'+(startOpen?'':' collapsed')+'" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">'+title+'</span><span><span class="dp-sec-count">'+count+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body'+(startOpen?'':' hidden')+'">'+bodyHtml+'</div></div>';
  }
  dpTitle.innerHTML='<span id="dpBack" style="cursor:pointer;color:var(--accent-blue);font-size:calc(10px * var(--txt-scale) * var(--dp-txt-scale));font-family:Segoe UI,system-ui,sans-serif;margin-right:8px" title="Back">&lt; Back</span><span style="color:'+col+'">'+gwType+'</span>: '+esc(nm);
  dpSub.innerHTML='<span class="copyable" data-copy="'+esc(gwId)+'">'+esc(gwId)+'</span>';
  let h='';

  // General info
  let gi='<div class="dp-kv"><span class="k">Type</span><span class="v">'+esc(gwType)+'</span></div>';
  gi+='<div class="dp-kv"><span class="k">ID</span><span class="v">'+esc(gwId)+'</span></div>';
  if(nm&&nm!==gwId) gi+='<div class="dp-kv"><span class="k">Name</span><span class="v">'+esc(nm)+'</span></div>';

  // Type-specific info
  if(gwType==='IGW'){
    const igw=(lk.igws||[]).find(g=>g.InternetGatewayId===gwId);
    if(igw){
      const att=igw.Attachments||[];
      att.forEach(a=>{
        const vn=lk.vpcs?lk.vpcs.find(v=>v.VpcId===a.VpcId):null;
        gi+='<div class="dp-kv"><span class="k">VPC</span><span class="v">'+(vn?gn(vn,a.VpcId):a.VpcId)+'</span></div>';
        gi+='<div class="dp-kv"><span class="k">State</span><span class="v"><span class="dp-badge pub">'+(a.State||'attached')+'</span></span></div>';
      });
      // Tags
      const tags=(igw.Tags||[]).filter(t=>t.Key!=='Name');
      if(tags.length){
        gi+='<div style="margin-top:6px;border-top:1px solid var(--border);padding-top:6px">';
        tags.forEach(t=>{gi+='<div class="dp-kv"><span class="k">'+esc(t.Key)+'</span><span class="v">'+esc(t.Value)+'</span></div>'});
        gi+='</div>';
      }
    }
  } else if(gwType==='NAT'){
    const nat=(lk.nats||[]).find(n=>n.NatGatewayId===gwId);
    if(nat){
      gi+='<div class="dp-kv"><span class="k">State</span><span class="v"><span class="dp-badge '+(nat.State==='available'?'pub':'prv')+'">'+(nat.State||'N/A')+'</span></span></div>';
      if(nat.SubnetId) gi+='<div class="dp-kv"><span class="k">Subnet</span><span class="v">'+nat.SubnetId+'</span></div>';
      if(nat.VpcId){
        const vn=lk.vpcs?lk.vpcs.find(v=>v.VpcId===nat.VpcId):null;
        gi+='<div class="dp-kv"><span class="k">VPC</span><span class="v">'+(vn?gn(vn,nat.VpcId):nat.VpcId)+'</span></div>';
      }
      if(nat.ConnectivityType) gi+='<div class="dp-kv"><span class="k">Connectivity</span><span class="v">'+nat.ConnectivityType+'</span></div>';
      const eips=(nat.NatGatewayAddresses||[]);
      eips.forEach((a,i)=>{
        if(a.PublicIp) gi+='<div class="dp-kv"><span class="k">Public IP'+(eips.length>1?' '+(i+1):'')+'</span><span class="v">'+a.PublicIp+'</span></div>';
        if(a.PrivateIp) gi+='<div class="dp-kv"><span class="k">Private IP'+(eips.length>1?' '+(i+1):'')+'</span><span class="v">'+a.PrivateIp+'</span></div>';
        if(a.AllocationId) gi+='<div class="dp-kv"><span class="k">EIP Alloc</span><span class="v">'+a.AllocationId+'</span></div>';
      });
      const tags=(nat.Tags||[]).filter(t=>t.Key!=='Name');
      if(tags.length){
        gi+='<div style="margin-top:6px;border-top:1px solid var(--border);padding-top:6px">';
        tags.forEach(t=>{gi+='<div class="dp-kv"><span class="k">'+esc(t.Key)+'</span><span class="v">'+esc(t.Value)+'</span></div>'});
        gi+='</div>';
      }
    }
  } else if(gwType==='VGW'){
    // Show VPN connections for this VGW
    const gwVpns=(lk.vpns||[]).filter(v=>v.VpnGatewayId===gwId);
    if(gwVpns.length){
      gi+='<div class="dp-kv"><span class="k">VPN Connections</span><span class="v">'+gwVpns.length+'</span></div>';
    }
  } else if(gwType==='VPCE'){
    const vpce=(lk.vpces||[]).find(v=>v.VpcEndpointId===gwId);
    if(vpce){
      if(vpce.VpcEndpointType) gi+='<div class="dp-kv"><span class="k">Endpoint Type</span><span class="v">'+vpce.VpcEndpointType+'</span></div>';
      if(vpce.ServiceName) gi+='<div class="dp-kv"><span class="k">Service</span><span class="v">'+esc(vpce.ServiceName)+'</span></div>';
      if(vpce.State) gi+='<div class="dp-kv"><span class="k">State</span><span class="v"><span class="dp-badge pub">'+vpce.State+'</span></span></div>';
      if(vpce.VpcId){
        const vn=lk.vpcs?lk.vpcs.find(v=>v.VpcId===vpce.VpcId):null;
        gi+='<div class="dp-kv"><span class="k">VPC</span><span class="v">'+(vn?gn(vn,vpce.VpcId):vpce.VpcId)+'</span></div>';
      }
    }
  } else if(gwType==='PCX'){
    const pcx=(lk.peerings||[]).find(p=>p.VpcPeeringConnectionId===gwId);
    if(pcx){
      if(pcx.Status) gi+='<div class="dp-kv"><span class="k">Status</span><span class="v"><span class="dp-badge pub">'+(pcx.Status.Code||pcx.Status)+'</span></span></div>';
      const req=pcx.RequesterVpcInfo;
      if(req){
        const vn=lk.vpcs?lk.vpcs.find(v=>v.VpcId===req.VpcId):null;
        gi+='<div class="dp-kv"><span class="k">Requester VPC</span><span class="v">'+(vn?gn(vn,req.VpcId):req.VpcId||'N/A')+'</span></div>';
        if(req.CidrBlock) gi+='<div class="dp-kv"><span class="k">Requester CIDR</span><span class="v">'+req.CidrBlock+'</span></div>';
      }
      const acc=pcx.AccepterVpcInfo;
      if(acc){
        const vn=lk.vpcs?lk.vpcs.find(v=>v.VpcId===acc.VpcId):null;
        gi+='<div class="dp-kv"><span class="k">Accepter VPC</span><span class="v">'+(vn?gn(vn,acc.VpcId):acc.VpcId||'N/A')+'</span></div>';
        if(acc.CidrBlock) gi+='<div class="dp-kv"><span class="k">Accepter CIDR</span><span class="v">'+acc.CidrBlock+'</span></div>';
      }
    }
  } else if(gwType==='PE'){
    const peList=lk.vpces||lk.privateEndpoints||[];
    const pe=peList.find(p=>p.id===gwId);
    if(pe){
      const props=pe.properties||pe._azure?.properties||{};
      const conn=props.privateLinkServiceConnections?.[0];
      const connProps=conn?.properties||{};
      const targetId=connProps.privateLinkServiceId||'';
      const groupIds=(connProps.groupIds||[]).join(', ');
      const state=connProps.privateLinkServiceConnectionState?.status||'Unknown';
      const stateDesc=connProps.privateLinkServiceConnectionState?.description||'';
      const stCol=state==='Approved'?'#10b981':state==='Pending'?'#f59e0b':'#ef4444';
      const stBg=state==='Approved'?'pub':state==='Pending'?'warn':'prv';
      const subnetId=props.subnet?.id||'';
      const vnetId=subnetId?subnetId.split('/subnets/')[0]:'';
      const dnsConfigs=props.customDnsConfigs||[];
      const fqdns=dnsConfigs.map(d=>d.fqdn).filter(Boolean);
      const ips=dnsConfigs.flatMap(d=>d.ipAddresses||[]);
      const nicIds=(props.networkInterfaces||[]).map(n=>n.id);
      const networkPolicies=props.subnet?.properties?.privateEndpointNetworkPolicies||'';

      gi+='<div class="dp-kv"><span class="k">Connection State</span><span class="v"><span class="dp-badge '+stBg+'" style="background:'+stCol+'22;color:'+stCol+';border:1px solid '+stCol+'44">'+esc(state)+'</span></span></div>';
      if(stateDesc) gi+='<div class="dp-kv"><span class="k">State Description</span><span class="v">'+esc(stateDesc)+'</span></div>';
      if(targetId){
        const targetName=targetId.split('/').pop();
        gi+='<div class="dp-kv"><span class="k">Target Service</span><span class="v copyable" data-copy="'+esc(targetId)+'">'+esc(targetName)+'</span></div>';
        gi+='<div class="dp-kv"><span class="k">Target Resource ID</span><span class="v copyable" data-copy="'+esc(targetId)+'" style="font-size:0.85em;word-break:break-all">'+esc(targetId)+'</span></div>';
      }
      if(groupIds) gi+='<div class="dp-kv"><span class="k">Group IDs</span><span class="v">'+esc(groupIds)+'</span></div>';
      ips.forEach((ip,i)=>{gi+='<div class="dp-kv"><span class="k">Private IP'+(ips.length>1?' '+(i+1):'')+'</span><span class="v">'+esc(ip)+'</span></div>'});
      fqdns.forEach(f=>{gi+='<div class="dp-kv"><span class="k">FQDN</span><span class="v copyable" data-copy="'+esc(f)+'">'+esc(f)+'</span></div>'});
      if(subnetId){
        const subName=subnetId.split('/').pop();
        gi+='<div class="dp-kv"><span class="k">Subnet</span><span class="v">'+esc(subName)+'</span></div>';
      }
      if(vnetId){
        const vnetName=vnetId.split('/').pop();
        gi+='<div class="dp-kv"><span class="k">VNet</span><span class="v">'+esc(vnetName)+'</span></div>';
      }
      nicIds.forEach(n=>{gi+='<div class="dp-kv"><span class="k">NIC</span><span class="v copyable" data-copy="'+esc(n)+'">'+esc(n.split('/').pop())+'</span></div>'});
      if(networkPolicies) gi+='<div class="dp-kv"><span class="k">Network Policies</span><span class="v">'+esc(networkPolicies)+'</span></div>';
      if(pe.location) gi+='<div class="dp-kv"><span class="k">Location</span><span class="v">'+esc(pe.location)+'</span></div>';
      // Tags
      const tags=pe.tags||{};
      const tagEntries=Object.entries(tags).filter(([k])=>k!=='Name'&&k!=='name');
      if(tagEntries.length){
        gi+='<div style="margin-top:6px;border-top:1px solid var(--border);padding-top:6px">';
        tagEntries.forEach(([k,v])=>{gi+='<div class="dp-kv"><span class="k">'+esc(k)+'</span><span class="v">'+esc(v)+'</span></div>'});
        gi+='</div>';
      }
    }
  }
  h+=sec('Details','',gi,true);

  // TGW Attachments section (for TGW type)
  if(gwType==='TGW'){
    const atts=(lk.tgwAttachments||[]).filter(a=>a.TransitGatewayId===gwId);
    if(atts.length){
      let ab='';
      atts.forEach(a=>{
        const rid=a.ResourceId||'N/A';
        const vn=(a.ResourceType==='vpc'&&lk.vpcs)?lk.vpcs.find(v=>v.VpcId===rid):null;
        const rName=vn?gn(vn,rid):rid;
        const isVpc=a.ResourceType==='vpc'&&rid.startsWith('vpc-');
        ab+='<div class="dp-row'+(isVpc?' tgw-att-link':'')+'"'+(isVpc?' data-act="vpc" data-id="'+rid+'" style="cursor:pointer"':'')+'><span class="p" style="color:var(--accent-cyan)">'+esc(rName)+'</span>';
        ab+=' <span style="color:var(--text-muted);font-size:0.85em">'+a.ResourceType+'</span>';
        ab+=' <span class="dp-badge pub">'+(a.State||'available')+'</span>';
        if(a.Association?.TransitGatewayRouteTableId) ab+='<br><span style="color:var(--text-muted);font-size:0.85em">RT: '+a.Association.TransitGatewayRouteTableId+'</span>';
        ab+='</div>';
      });
      h+=sec('TGW Attachments',atts.length,ab,true);
    }
  }

  // Route tables referencing this gateway
  const refRts=(lk.rts||[]).filter(rt=>(rt.Routes||[]).some(r=>
    r.GatewayId===gwId||r.NatGatewayId===gwId||r.TransitGatewayId===gwId||r.VpcPeeringConnectionId===gwId
  ));
  if(refRts.length){
    let rb='';
    refRts.forEach(rt=>{
      const rtName=gn(rt,rt.RouteTableId);
      rb+='<div style="margin-bottom:8px;padding:6px;background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:4px">';
      rb+='<div style="font-weight:bold;color:var(--accent-cyan);margin-bottom:4px">'+esc(rtName)+'</div>';
      rb+='<div style="color:var(--text-muted);font-size:0.85em;margin-bottom:4px">'+rt.RouteTableId+'</div>';
      (rt.Routes||[]).forEach(r=>{
        const dest=r.DestinationCidrBlock||r.DestinationPrefixListId||'?';
        const tgt=r.GatewayId||r.NatGatewayId||r.TransitGatewayId||r.VpcPeeringConnectionId||'local';
        const isThis=(tgt===gwId);
        if(isThis)rb+='<div class="dp-row">'+dest+' <span class="p">-></span> <span class="p" style="color:var(--accent-cyan);font-weight:bold">'+gwType+' (this)</span></div>';
        else rb+='<div class="dp-row">'+dest+' <span class="p">-></span> '+routeTgtHtml(tgt)+'</div>';
      });
      rb+='</div>';
    });
    h+=sec('Route Tables',refRts.length+' tables',rb,false);
  }

  // VPN connections (for VGW)
  if(gwType==='VGW'){
    const gwVpns=(lk.vpns||[]).filter(v=>v.VpnGatewayId===gwId);
    if(gwVpns.length){
      let vb='';
      gwVpns.forEach(v=>{
        vb+='<div style="margin-bottom:8px;padding:6px;background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:4px">';
        vb+='<div style="font-weight:bold;color:var(--accent-red)">'+gn(v,v.VpnConnectionId)+'</div>';
        vb+='<div class="dp-kv"><span class="k">ID</span><span class="v">'+v.VpnConnectionId+'</span></div>';
        vb+='<div class="dp-kv"><span class="k">State</span><span class="v"><span class="dp-badge '+(v.State==='available'?'pub':'prv')+'">'+v.State+'</span></span></div>';
        if(v.CustomerGatewayId) vb+='<div class="dp-kv"><span class="k">Customer GW</span><span class="v">'+v.CustomerGatewayId+'</span></div>';
        if(v.Type) vb+='<div class="dp-kv"><span class="k">Type</span><span class="v">'+v.Type+'</span></div>';
        vb+='</div>';
      });
      h+=sec('VPN Connections',gwVpns.length,vb,true);
    }
  }

  // Connected subnets (subnets whose route tables point to this gateway)
  const connSubs=[];
  (lk.subnets||[]).forEach(s=>{
    const rt=lk.subRT[s.SubnetId];
    if(!rt)return;
    const hasRoute=(rt.Routes||[]).some(r=>r.GatewayId===gwId||r.NatGatewayId===gwId||r.TransitGatewayId===gwId||r.VpcPeeringConnectionId===gwId);
    if(hasRoute) connSubs.push(s);
  });
  if(connSubs.length){
    let sb='';
    connSubs.forEach(s=>{
      const isPub=lk.pubSubs.has(s.SubnetId);
      const vn=lk.vpcs?lk.vpcs.find(v=>v.VpcId===s.VpcId):null;
      sb+='<div class="dp-row" data-act="sub" data-id="'+s.SubnetId+'" style="cursor:pointer">'+gn(s,s.SubnetId)+' <span class="dp-badge '+(isPub?'pub':'prv')+'">'+(isPub?'PUB':'PRV')+'</span>';
      sb+=' <span style="color:var(--text-muted);font-size:0.85em">'+s.CidrBlock+'</span>';
      if(vn) sb+=' <span style="color:var(--text-muted);font-size:0.85em">| '+(gn(vn,vn.VpcId))+'</span>';
      sb+='</div>';
    });
    h+=sec('Connected Subnets',connSubs.length,sb,false);
  }

  document.getElementById('dpExpandAll').style.display='';
  document.getElementById('dpCollapseAll').style.display='';
  document.getElementById('dpTraceFrom').style.display='none';
  DetailTraceSelection.clear();
  dpBody.innerHTML=h;
  dp.classList.add('open');
  injectDesignToolbar(dpBody,{type:'gateway',gwType:gwType,data:gwId});
  applyDpScale();
  dpBody.querySelectorAll('.dp-row[data-act]').forEach(el=>{
    el.addEventListener('click',(e)=>{
      e.stopPropagation();
      const act=el.dataset.act,id=el.dataset.id;if(!act||!id)return;
      MapViewport.zoomToResource(id);
      setTimeout(()=>{
        MapViewport.flashResource(id);
        const detailCtx=detailRuntimeContext();
        if(act==='sub'&&detailCtx){
          const sub=(detailCtx.subnets||[]).find(s=>s.SubnetId===id);
          if(sub){
            _navStack.push({fn:()=>{ openGatewayPanel(gwId,gwType,lk); MapViewport.zoomToResource(gwId); MapViewport.highlightGateway(gwId); }});
            openSubnetPanel(sub,sub.VpcId,detailSubnetLookup(detailCtx));
          }
        }
      },300);
    });
  });
  dpBody.querySelectorAll('.dp-link').forEach(el=>{
    el.addEventListener('click',(e)=>{
      e.stopPropagation();
      const nGwId=el.dataset.gwid, nGwType=el.dataset.gwtype;
      const detailCtx=detailRuntimeContext();
      if(!nGwId||!detailCtx) return;
      _navStack.push({fn:()=>{ openGatewayPanel(gwId,gwType,lk); MapViewport.zoomToResource(gwId); MapViewport.highlightGateway(gwId); }});
      openGatewayPanel(nGwId,nGwType,detailGatewayLookup(detailCtx));
      MapViewport.zoomToResource(nGwId);
      MapViewport.highlightGateway(nGwId);
    });
  });
  document.getElementById('dpBack')?.addEventListener('click',(e)=>{
    e.stopPropagation();
    const prev=_navStack.pop();
    if(prev&&prev.fn) prev.fn();
    else dp.classList.remove('open');
  });
}

// Shared resource tree builder - creates hierarchical resource list with children
function resTooltipHtml(res,subId,subRT){
  const titleType=res.fullType||res.type;
  let h='<div class="tt-title" style="color:'+res.col+'">'+esc(titleType)+': '+esc(res.name)+'</div>';
  if(res.rid) h+='<div class="tt-sub">'+esc(res.rid)+'</div>';
  h+='<div class="tt-sec">';
  if(res.ip) h+='<div class="tt-r">IP: <span class="i">'+esc(res.ip)+'</span></div>';
  if(res.state&&res.type==='PE'){
    const stCol=res.stateDot||'#10b981';
    h+='<div class="tt-r">State: <span style="color:'+stCol+'">'+esc(res.state)+'</span></div>';
  } else if(res.state) h+='<div class="tt-r">State: <span class="'+(res.state==='running'?'a':'d')+'">'+esc(res.state)+'</span></div>';
  if(res.itype) h+='<div class="tt-r">Type: <span class="i">'+esc(res.itype)+'</span></div>';
  if(res.lbType) h+='<div class="tt-r">LB Type: <span class="i">'+esc(res.lbType)+'</span></div>';
  if(res.sgIds) h+='<div class="tt-r">SGs: <span class="s">'+esc(res.sgIds)+'</span></div>';
  if(res.extra) h+='<div class="tt-r"><span class="i">'+esc(res.extra)+'</span></div>';
  h+='</div>';
  if((res.children||[]).length){
    h+='<div class="tt-sec"><div class="tt-sh">Nested ('+res.children.length+')</div>';
    res.children.forEach(ch=>{
      h+='<div class="tt-r"><span style="color:'+ch.col+'">'+esc(ch.type)+'</span> '+esc(ch.name)+(ch.detail?' <span class="i">'+esc(ch.detail)+'</span>':'')+'</div>';
    });
    h+='</div>';
  }
  const rt=subRT?subRT[subId]:null;
  if(rt){
    h+='<div class="tt-sec"><div class="tt-sh">Route Table</div>';
    (rt.Routes||[]).slice(0,6).forEach(r=>{
      const dest=esc(r.DestinationCidrBlock||r.DestinationPrefixListId||'?');
      const tgt=esc(r.GatewayId||r.NatGatewayId||r.TransitGatewayId||r.VpcPeeringConnectionId||'local');
      h+='<div class="tt-r">'+dest+' <span class="p">-></span> <span class="p">'+tgt+'</span></div>';
    });
    if((rt.Routes||[]).length>6) h+='<div class="tt-r">+'+(rt.Routes.length-6)+' more</div>';
    h+='</div>';
  }
  return h;
}
// #endregion UI UTILITIES & DETAIL PANELS

