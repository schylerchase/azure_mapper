// #region TOPOLOGY EXECUTIVE OVERVIEW
// EXECUTIVE OVERVIEW
function renderExecutiveOverview(ctx){
  const {vpcs,subnets,instances,albs,peerings,vpns,s3bk,zones,rdsInstances,ecsServices,
    lambdaFns,ecacheClusters,redshiftClusters,cfDistributions,subByVnet,instBySub,albBySub,
    rdsBySub,ecsBySub,lambdaBySub,pvGws,shGws,vpceByVpc,tgwAttachments,
    rts,sgs,nacls,enis,igws,nats,vpces,tgs,volumes,snapshots,wafAcls,
    pubSubs,subRT,subNacl,nsgByVnet,eniBySub,volByInst,snapByVol,tgByAlb,wafByAlb,
    ecacheByVpc,redshiftByVpc,cfByAlb}=ctx;
  
  // Store context for stat chip clicks
  ctx=topologyPublishRuntimeContext(ctx);
  topologyPublishSecurityGroups(ctx.sgs);
  
  const svg=d3.select('#mapSvg');
  const W=_getMain().clientWidth,H=_getMain().clientHeight;
  svg.attr('width',W).attr('height',H);
  const g=svg.append('g').attr('class','map-root');
  const zB=d3.zoom().scaleExtent([.08,5]).on('zoom',e=>{g.attr('transform',e.transform);MapViewport.updateZoomLabel(e.transform.k)});svg.call(zB);
  MapViewport.setMapRefs(svg,zB,g);
  MapViewport.bindZoomButtons();
  
  const tt=document.getElementById('tooltip');
  
  // Per-VPC resource stats
  const vpcStats=vpcs.map(v=>{
    const ss=subByVnet[v.VpcId]||[];
    let ec2=0,alb=0,rds=0,ecs=0,fn=0,eniC=0,volC=0;
    ss.forEach(s=>{
      ec2+=(instBySub[s.SubnetId]||[]).length;
      alb+=(albBySub[s.SubnetId]||[]).length;
      rds+=(rdsBySub[s.SubnetId]||[]).length;
      ecs+=(ecsBySub[s.SubnetId]||[]).length;
      fn+=(lambdaBySub[s.SubnetId]||[]).length;
      eniC+=(eniBySub[s.SubnetId]||[]).length;
      (instBySub[s.SubnetId]||[]).forEach(i=>{volC+=(volByInst[i.InstanceId]||[]).length});
    });
    const sgC=(nsgByVnet[v.VpcId]||[]).length;
    const gws=(pvGws[v.VpcId]||[]);
    const vpceCount=(vpceByVpc[v.VpcId]||[]).length;
    const region=ss.find(s=>s.AvailabilityZone)?.AvailabilityZone?.replace(/[a-z]$/,'')||'';
    return {vpc:v,subCount:ss.length,ec2,alb,rds,ecs,fn,eniC,volC,sgC,total:ec2+alb+rds+ecs+fn,gwCount:gws.length,vpceCount,region};
  });
  
  // Layout VPC cards in grid
  const CARD_W=300,CARD_H=220,CARD_GAP=40,COLS=Math.max(2,Math.min(4,Math.ceil(Math.sqrt(vpcs.length))));
  const startX=60;
  const _hdrStats=[
    {l:'VNets',v:vpcs.length,t:'VNets',c:'#7C3AED'},
    {l:'Subnets',v:subnets.length,t:'Subnets',c:'#06b6d4'},
    {l:'VMs',v:instances.length,t:'VMs',c:'#10b981'},
    {l:'AppGW',v:albs.length,t:'AppGWs',c:'#38bdf8'},
    {l:'SQL',v:rdsInstances.length,t:'SQL',c:'#3b82f6'},
    {l:'Containers',v:ecsServices.length,t:'Containers',c:'#f97316'},
    {l:'FuncApps',v:lambdaFns.length,t:'FuncApps',c:'#a855f7'},
    {l:'NICs',v:enis.length,t:'NICs',c:'#64748b'},
    {l:'NSGs',v:sgs.length,t:'NSGs',c:'#eab308'},
    {l:'Disks',v:volumes.length,t:'Disks',c:'#f59e0b'},
    {l:'Storage',v:s3bk.length,t:'Storage',c:'#ea580c'},
    {l:'DNS',v:zones.length,t:'DNS',c:'#06b6d4'},
    {l:'FrontDoor',v:cfDistributions.length,t:'FrontDoor',c:'#8b5cf6'},
    {l:'vWAN',v:shGws.filter(g2=>g2.type==='TGW').length,t:'Gateways',c:'#ec4899'},
    {l:'VPN',v:vpns?.length||0,t:'VPNs',c:'#ef4444'},
    {l:'Peering',v:peerings.length,t:'Peering',c:'#fb923c'},
    {l:'Snapshots',v:snapshots.length,t:'Snapshots',c:'#94a3b8'},
    {l:'WAF',v:wafAcls.length,t:'WAF',c:'#eab308'},
    {l:'Redis',v:ecacheClusters.length,t:'Redis',c:'#ef4444'},
    {l:'Synapse',v:redshiftClusters.length,t:'Synapse',c:'#dc2626'}
  ].filter(s=>s.v>0);
  const _hdrCols=8,_hdrCardW=58,_hdrCardH=38,_hdrGapX=6,_hdrGapY=6;
  const _hdrRows=Math.ceil(_hdrStats.length/_hdrCols);
  const _hdrGridH=_hdrRows*(_hdrCardH+_hdrGapY);
  const _hdrH=32+_hdrGridH+30+16;
  const _hdrTotalW=Math.min(_hdrStats.length,_hdrCols)*(_hdrCardW+_hdrGapX)-_hdrGapX+24;
  const startY=_hdrH+20;
  
  const vpcPositions=new Map();
  vpcStats.forEach((vs,i)=>{
    const col=i%COLS,row=Math.floor(i/COLS);
    const cx=startX+col*(CARD_W+CARD_GAP);
    const cy=startY+row*(CARD_H+CARD_GAP);
    vpcPositions.set(vs.vpc.VpcId,{x:cx,y:cy,cx:cx+CARD_W/2,cy:cy+CARD_H/2,vs});
  });
  
  // Draw connections first (behind cards)
  const connG=g.append('g').attr('class','exec-connections');
  
  // Peering connections
  peerings.forEach(p=>{
    const aVpc=p.AccepterVpcInfo?.VpcId,rVpc=p.RequesterVpcInfo?.VpcId;
    const pa=vpcPositions.get(aVpc),pr=vpcPositions.get(rVpc);
    if(!pa||!pr)return;
    const mx=(pa.cx+pr.cx)/2,my=(pa.cy+pr.cy)/2;
    connG.append('path').attr('d',`M${pa.cx},${pa.cy} Q${mx},${my-30} ${pr.cx},${pr.cy}`)
      .attr('fill','none').attr('stroke','var(--pcx-color)').attr('stroke-width',2)
      .attr('stroke-dasharray','8 4').attr('opacity',.6);
    connG.append('circle').attr('cx',mx).attr('cy',my-15).attr('r',10)
      .attr('fill','var(--bg-card)').attr('stroke','var(--pcx-color)').attr('stroke-width',1);
    connG.append('text').attr('x',mx).attr('y',my-11).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))').attr('fill','var(--pcx-color)').text('PCX');
  });
  
  // TGW connections (shared gateways connect to all VPCs that route through them)
  const tgwVpcs=new Map();
  shGws.filter(g2=>g2.type==='TGW').forEach(tgw=>{
    const connected=[];
    vpcs.forEach(v=>{
      const ss=subByVnet[v.VpcId]||[];
      const rts2=ctx.rts.filter(rt=>rt.VpcId===v.VpcId||(rt.Associations||[]).some(a=>ss.some(s=>s.SubnetId===a.SubnetId)));
      const hasTgw=rts2.some(rt=>(rt.Routes||[]).some(r=>r.TransitGatewayId===tgw.id));
      if(hasTgw)connected.push(v.VpcId);
    });
    if(connected.length>1) tgwVpcs.set(tgw.id,connected);
  });
  
  // Draw TGW hub if present
  tgwVpcs.forEach((vids,tgwId)=>{
    let hubX=0,hubY=0,cnt=0;
    vids.forEach(vid=>{const p=vpcPositions.get(vid);if(p){hubX+=p.cx;hubY+=p.cy;cnt++}});
    if(!cnt)return;
    hubX/=cnt;hubY/=cnt;
    
    // TGW node
    connG.append('circle').attr('cx',hubX).attr('cy',hubY).attr('r',22)
      .attr('fill','var(--bg-card)').attr('stroke','var(--tgw-color)').attr('stroke-width',2);
    connG.append('text').attr('x',hubX).attr('y',hubY+3).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','700')
      .attr('fill','var(--tgw-color)').text('TGW');
    
    // Spokes to VPCs
    vids.forEach(vid=>{
      const p=vpcPositions.get(vid);if(!p)return;
      connG.append('line').attr('x1',hubX).attr('y1',hubY).attr('x2',p.cx).attr('y2',p.cy)
        .attr('stroke','var(--tgw-color)').attr('stroke-width',1.5).attr('stroke-dasharray','6 3').attr('opacity',.4);
    });
  });
  
  // Draw VPC cards
  const cardG=g.append('g').attr('class','exec-cards');
  
  vpcStats.forEach((vs,i)=>{
    const pos=vpcPositions.get(vs.vpc.VpcId);
    const cx=pos.x,cy=pos.y;
    const cG=cardG.append('g').attr('class','exec-card').style('cursor','pointer');
    
    // Card background
    cG.append('rect').attr('x',cx).attr('y',cy).attr('width',CARD_W).attr('height',CARD_H)
      .attr('rx',6).attr('fill','rgba(30,41,59,.85)').attr('stroke','var(--vpc-stroke)').attr('stroke-width',1.5);
    
    // Header bar
    cG.append('rect').attr('x',cx).attr('y',cy).attr('width',CARD_W).attr('height',32)
      .attr('rx',6).attr('fill','rgba(59,130,246,.12)');
    cG.append('rect').attr('x',cx).attr('y',cy+26).attr('width',CARD_W).attr('height',6)
      .attr('fill','rgba(59,130,246,.12)');
    
    // VPC name
    cG.append('text').attr('x',cx+12).attr('y',cy+20)
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(11px * var(--txt-scale,1))').attr('font-weight','700')
      .attr('fill','var(--text-primary)').text(gn(vs.vpc,vs.vpc.VpcId));
    
    // Region tag
    if(vs.region){
      cG.append('text').attr('x',cx+CARD_W-10).attr('y',cy+20).attr('text-anchor','end')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(vs.region);
    }
    
    // CIDR
    cG.append('text').attr('x',cx+12).attr('y',cy+48)
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
      .text(vs.vpc.CidrBlock||'N/A');
    
    // Subnet count
    cG.append('text').attr('x',cx+CARD_W-10).attr('y',cy+48).attr('text-anchor','end')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-secondary)')
      .text(vs.subCount+' subnet'+(vs.subCount!==1?'s':''));
    
    // Resource bars
    const barY=cy+62;
    const resTypes=[
      {label:'VMs',count:vs.ec2,col:'#10b981',rlType:'VMs'},
      {label:'AppGW',count:vs.alb,col:'#38bdf8',rlType:'AppGWs'},
      {label:'SQL',count:vs.rds,col:'#3b82f6',rlType:'SQL'},
      {label:'Containers',count:vs.ecs,col:'#f97316',rlType:'Containers'},
      {label:'FuncApps',count:vs.fn,col:'#a855f7',rlType:'FuncApps'},
      {label:'NICs',count:vs.eniC,col:'#64748b',rlType:'NICs'},
      {label:'Disks',count:vs.volC,col:'#f59e0b',rlType:'Disks'},
      {label:'NSGs',count:vs.sgC,col:'#eab308',rlType:'NSGs'}
    ].filter(r=>r.count>0);
    
    const maxCount=Math.max(1,...resTypes.map(r=>r.count));
    const barMaxW=CARD_W-80;
    
    resTypes.forEach((rt,ri)=>{
      const by=barY+ri*16;
      const barG=cG.append('g').style('cursor','pointer');
      barG.append('rect').attr('x',cx).attr('y',by-1).attr('width',CARD_W).attr('height',15)
        .attr('fill','transparent');
      barG.append('text').attr('x',cx+12).attr('y',by+9)
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6.5px * var(--txt-scale,1))').attr('fill',rt.col).text(rt.label);
      barG.append('rect').attr('x',cx+52).attr('y',by+1).attr('width',barMaxW).attr('height',9)
        .attr('rx',2).attr('fill','rgba(255,255,255,.03)');
      const bw=Math.max(4,(rt.count/maxCount)*barMaxW);
      barG.append('rect').attr('x',cx+52).attr('y',by+1).attr('width',bw).attr('height',9)
        .attr('rx',2).attr('fill',rt.col).attr('fill-opacity',.3);
      barG.append('text').attr('x',cx+54+bw).attr('y',by+9)
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6.5px * var(--txt-scale,1))').attr('font-weight','600')
        .attr('fill',rt.col).text(rt.count);
      barG.on('click',function(event){event.stopPropagation();openResourceList(rt.rlType)});
      barG.on('mouseenter',function(){d3.select(this).selectAll('rect').filter(function(d,i){return i===2}).attr('fill-opacity',.6)})
        .on('mouseleave',function(){d3.select(this).selectAll('rect').filter(function(d,i){return i===2}).attr('fill-opacity',.3)});
    });
    
    // Gateway summary at bottom
    const gwY=cy+CARD_H-18;
    let gwX=cx+12;
    if(vs.gwCount){
      const gwG2=cG.append('g').style('cursor','pointer');
      gwG2.append('text').attr('x',gwX).attr('y',gwY)
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6.5px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
        .text(vs.gwCount+' gateway'+(vs.gwCount!==1?'s':''));
      gwG2.on('click',function(event){event.stopPropagation();openResourceList('Gateways')});
      gwX+=vs.gwCount.toString().length*6+50;
    }
    if(vs.vpceCount){
      const vpceG2=cG.append('g').style('cursor','pointer');
      vpceG2.append('text').attr('x',gwX).attr('y',gwY)
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6.5px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
        .text(vs.vpceCount+' endpoint'+(vs.vpceCount!==1?'s':''));
      vpceG2.on('click',function(event){event.stopPropagation();openResourceList('Endpoints')});
    }
    
    // Total resources badge
    if(vs.total>0){
      const tw=vs.total.toString().length*6+30;
      cG.append('rect').attr('x',cx+CARD_W-tw-8).attr('y',gwY-10).attr('width',tw).attr('height',14)
        .attr('rx',3).attr('fill','rgba(99,102,241,.15)').attr('stroke','rgba(99,102,241,.4)').attr('stroke-width',.5);
      cG.append('text').attr('x',cx+CARD_W-tw/2-8).attr('y',gwY+1).attr('text-anchor','middle')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','700')
        .attr('fill','#818cf8').text(vs.total+' total');
    }
    
    // Tooltip on hover
    cG.on('mouseenter',function(){
      let h='<div class="tt-title">'+gn(vs.vpc,vs.vpc.VpcId)+'</div>';
      h+='<div class="tt-sub">'+esc(vs.vpc.VpcId)+'</div>';
      h+='<div class="tt-sec"><div class="tt-sh">Overview</div>';
      h+='<div class="tt-r">CIDR: <span class="i">'+esc(vs.vpc.CidrBlock)+'</span></div>';
      h+='<div class="tt-r">Region: <span class="i">'+esc(vs.region||'Unknown')+'</span></div>';
      h+='<div class="tt-r">Subnets: <span class="i">'+vs.subCount+'</span></div>';
      h+='<div class="tt-r">Total Resources: <span class="i">'+vs.total+'</span></div>';
      h+='</div>';
      tt.innerHTML=h;tt.style.display='block';
    }).on('mousemove',function(event){
      positionTooltip(event,tt);
    }).on('mouseleave',()=>{tt.style.display='none'})
    .on('click',function(){openResourceList('VPCs')});
  });
  
  const hdrG=g.append('g');
  const _hdrX=startX-12,_hdrY=8;
  hdrG.append('rect').attr('x',_hdrX).attr('y',_hdrY).attr('width',_hdrTotalW).attr('height',_hdrH)
    .attr('rx',8).attr('fill','rgba(17,24,39,.85)').attr('stroke','var(--border)');
  hdrG.append('text').attr('x',startX).attr('y',_hdrY+22)
    .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(14px * var(--txt-scale,1))').attr('font-weight','700')
    .attr('fill','var(--text-primary)').text('Executive Overview');
  const _regions=new Set(vpcStats.map(vs=>vs.region).filter(Boolean));
  const _regionLabel=_regions.size===1?[..._regions][0]:(_regions.size>1?'Multi-Region':'');
  if(_regionLabel){
    hdrG.append('text').attr('x',_hdrX+_hdrTotalW-12).attr('y',_hdrY+22).attr('text-anchor','end')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(10px * var(--txt-scale,1))')
      .attr('fill','var(--text-muted)').text(_regionLabel);
  }
  const _gridY=_hdrY+32;
  _hdrStats.forEach((s,i)=>{
    const col=i%_hdrCols,row=Math.floor(i/_hdrCols);
    const cx=startX+col*(_hdrCardW+_hdrGapX);
    const cy=_gridY+row*(_hdrCardH+_hdrGapY);
    const mcG=hdrG.append('g').style('cursor','pointer');
    mcG.append('rect').attr('x',cx).attr('y',cy).attr('width',_hdrCardW).attr('height',_hdrCardH)
      .attr('rx',4).attr('fill','rgba(255,255,255,.03)').attr('class','hdr-stat-bg');
    mcG.append('rect').attr('x',cx).attr('y',cy+4).attr('width',3).attr('height',_hdrCardH-8)
      .attr('fill',s.c).attr('rx',1);
    mcG.append('text').attr('x',cx+10).attr('y',cy+16)
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(12px * var(--txt-scale,1))').attr('font-weight','700')
      .attr('fill',s.c).text(s.v);
    mcG.append('text').attr('x',cx+10).attr('y',cy+28)
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))')
      .attr('fill','var(--text-muted)').text(s.l);
    mcG.on('click',function(){openResourceList(s.t)});
    mcG.on('mouseenter',function(){d3.select(this).select('.hdr-stat-bg').attr('fill','rgba(255,255,255,.08)')})
      .on('mouseleave',function(){d3.select(this).select('.hdr-stat-bg').attr('fill','rgba(255,255,255,.03)')});
  });
  const _compY=_gridY+_hdrGridH+4;
  let _compFindings=[];
  try{_compFindings=topologyComplianceFindings(ctx)}catch(e){console.warn('Compliance checks failed:',e)}
  const _compN=_compFindings.length;
  const _compColor=_compN===0?'#22c55e':_compN<=20?'#eab308':_compN<=50?'#f97316':'#ef4444';
  const _compG=hdrG.append('g').style('cursor','pointer');
  _compG.append('rect').attr('x',startX).attr('y',_compY).attr('width',_hdrTotalW-24).attr('height',22)
    .attr('rx',4).attr('fill','rgba(255,255,255,.03)').attr('class','comp-bar-bg');
  _compG.append('circle').attr('cx',startX+12).attr('cy',_compY+11).attr('r',4).attr('fill',_compColor);
  _compG.append('text').attr('x',startX+22).attr('y',_compY+15)
    .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(9px * var(--txt-scale,1))')
    .attr('fill',_compColor).text(_compN===0?'No findings':_compN+' finding'+(_compN===1?'':'s'));
  _compG.on('click',function(){renderCompliancePanel(_compFindings)});
  _compG.on('mouseenter',function(){d3.select(this).select('.comp-bar-bg').attr('fill','rgba(255,255,255,.08)')})
    .on('mouseleave',function(){d3.select(this).select('.comp-bar-bg').attr('fill','rgba(255,255,255,.03)')});
  
  // Hide stats bar in executive overview (stats are shown in the header)
  const sb2=document.getElementById('statsBar');sb2.textContent='';sb2.style.display='none';
  
  // Show legend but auto-collapse it
  const leg=document.getElementById('legend');
  leg.style.display='flex';
  leg.classList.add('collapsed');
  document.getElementById('exportBar').style.display='flex';
  document.getElementById('bottomToolbar').style.display='flex';
  setTimeout(()=>d3.select('#zoomFit').dispatch('click'),100);
}

// #endregion TOPOLOGY EXECUTIVE OVERVIEW
