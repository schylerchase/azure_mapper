// #region TOPOLOGY GRID LAYOUT
function renderGridTopologyMap(ctx){
  const {
    svg,
    vpcs,subnets,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,
    wafAcls,rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions,
    recsByZoneMap,subByVnet,pubSubs,subRT,gwSet,subNacl,nsgByVnet,iamRoleResources,
    instBySub,eniByInst,eniBySub,albBySub,volByInst,volBySub,snapByVol,tgByAlb,wafByAlb,rdsBySub,ecsBySub,lambdaBySub,
    ecacheByVpc,redshiftByVpc,cfByAlb,pvGws,shGws,vpceByVpc,vpceIds,gwNames,storageTopology,storageBySub,
    _regions,_multiRegion,_multiTenant,_accounts
  } = ctx;

  // GRID LAYOUT

  const gridGeometry=buildTopologyGridGeometry({
    vpcs,
    subnets,
    subByVnet,
    pubSubs,
    subRT,
    pvGws,
    shGws,
    vpceIds,
    gwNames,
    instBySub,
    albBySub,
    rdsBySub,
    ecsBySub,
    lambdaBySub,
    volByInst,
    volBySub,
    enis,
    eniByInst,
    tgByAlb,
    wafByAlb,
    cfByAlb,
    snapByVol,
    eniBySub,
    storageBySub,
    _multiTenant,
    _multiRegion
  });
  const {
    GR,
    RES_ICON,
    RES_CHILD_H,
    RES_GAP,
    RES_COLS,
    RES_TOP,
    AZ_HDR,
    subTrees,
    vL,
    getVpcRegion,
    knownVL,
    unknownVL,
    iGwList,
    allVpcRight,
    iX,
    iY,
    allS,
    tG,
    gwP
  } = gridGeometry;
  let { routingBottomY } = gridGeometry;
  // SVG
  const g=svg.append('g').attr('class','map-root');
  const zB=d3.zoom().scaleExtent([.08,5]).on('zoom',e=>{g.attr('transform',e.transform);MapViewport.updateZoomLabel(e.transform.k)});svg.call(zB);
  MapViewport.setMapRefs(svg,zB,g);
  MapViewport.bindZoomButtons();

  const lnL=g.append('g').attr('class','lines-layer'); // Routes first (bottom)
  const ndL=g.append('g').attr('class','nodes-layer'); // Nodes on top of routes
  const routeG=lnL.append('g').attr('class','route-group');
  const structG=lnL.append('g').attr('class','struct-group'); // structural route lines at full opacity
  const allLb=[];
  const olL=g.append('g').attr('class','highlight-overlay');
  const labelL=g.append('g').attr('class','label-layer'); // Labels on top of everything

  // Highlight lock state for click-to-toggle
  let _hlLocked=false, _hlKey=null, _hlType=null;
  const lockInd=document.getElementById('hlLockInd');
  function showLockInd(v){lockInd.style.display=v?'block':'none'}
  function setGwHl(gid){
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    if(gid) ndL.selectAll('.gw-node').each(function(){
      const el=d3.select(this);
      if(el.datum&&el.datum()===gid) el.classed('gw-hl',true);
    });
  }
  
  function clonePathToOl(srcEl){
    const s=d3.select(srcEl);
    const op=olL.append('path')
      .attr('d',s.attr('d'))
      .style('stroke',s.attr('stroke'))
      .style('fill',s.attr('fill')||'none')
      .style('stroke-width','4px')
      .style('opacity','1')
      .style('stroke-dasharray','8 5')
      .style('pointer-events','none');
    // Preserve solid style for L-bends, connectors, junctions
    const srcDash=s.style('stroke-dasharray');
    if(srcDash==='none'||s.classed('route-junction')){
      op.style('stroke-dasharray','none').style('stroke-width','3px');
    }
    return op;
  }

  function hlGw(gid){
    olL.selectAll('*').remove();
    routeG.style('opacity','0.03');structG.style('opacity','0.03');
    g.classed('hl-active',true);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.vpc-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
    ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);

    // Find all VPCs connected to this gateway and highlight them
    const gwVids=new Set();
    structG.node().querySelectorAll('[data-gid="'+gid+'"][data-vid]').forEach(el=>{
      gwVids.add(el.getAttribute('data-vid'));
    });
    gwVids.forEach(vid=>ndL.selectAll('.vpc-group[data-vnet-id="'+vid+'"]').each(function(){d3.select(this).select('rect').style('stroke-width','3px').style('filter','drop-shadow(0 0 8px rgba(99,180,255,.7))');}));

    // Clone ALL structural paths for this gateway into overlay
    let hasNet=false;
    const sNode=structG.node();
    sNode.querySelectorAll('[data-gid="'+gid+'"]').forEach(el=>{
      if(el.hasAttribute('data-net-vert')) hasNet=true;
      clonePathToOl(el);
    });
    // Also clone paths with just data-gid (no data-vid): e.g. bus-bar-to-gateway verticals
    // (already included above since querySelectorAll matches all with data-gid)

    if(hasNet){
      // Clone NET-vert segments: same X column (above this gateway) + intermediate X columns
      const gp=gwP.get(gid);
      if(gp){
        const gwX=gp.x;
        const gwBotY=gp.y-GR-4;
        sNode.querySelectorAll('[data-net-vert]').forEach(el=>{
          if(el.getAttribute('data-gid')===gid) return; // already cloned above
          const dm=el.getAttribute('d').match(/^M([\d.]+),([-\d.]+)\s*L\1,([-\d.]+)$/);
          if(dm){
            const segX=parseFloat(dm[1]);
            const segBot=Math.max(parseFloat(dm[2]),parseFloat(dm[3]));
            if(Math.abs(segX-gwX)<2){
              // Same X column: only segments above this gateway
              if(segBot<=gwBotY+2) clonePathToOl(el);
            }
          }
        });
      }
      const netLine=sNode.querySelector('[data-net-line]');
      if(netLine&&gp){
        // Trim NET horizontal line from Internet node to this gateway's X only
        const nlD=netLine.getAttribute('d');
        const nlM=nlD.match(/^M([-\d.]+),([-\d.]+)\s*L([-\d.]+),([-\d.]+)$/);
        if(nlM){
          const nlX1=parseFloat(nlM[1]),nlY=parseFloat(nlM[2]),nlX2=parseFloat(nlM[3]);
          const trimX=Math.min(Math.max(nlX1,nlX2),gp.x);
          const trimD=`M${Math.min(nlX1,nlX2)},${nlY} L${trimX},${nlY}`;
          const s=d3.select(netLine);
          olL.append('path').attr('d',trimD)
            .style('stroke',s.attr('stroke')).style('fill','none')
            .style('stroke-width','4px').style('opacity','1')
            .style('stroke-dasharray','8 5').style('pointer-events','none');
        }else{
          clonePathToOl(netLine);
        }
      }else if(netLine){
        clonePathToOl(netLine);
      }
      ndL.selectAll('.internet-node').style('opacity','1');
      // Highlight IGW gateways in the same X column (shared trunk) as this gateway
      if(gp){
        const gwX=gp.x;
        ndL.selectAll('.gw-node').each(function(){
          const c=d3.select(this).select('circle');
          const t=d3.select(this).select('text');
          if(!c.node()||!t.node()) return;
          const cx=parseFloat(c.attr('cx'));
          if(t.text()==='IGW'&&Math.abs(cx-gwX)<2) d3.select(this).classed('gw-hl',true);
        });
      }
    }
    allLb.forEach(l=>l.g.classed('visible',l.gid===gid));
  }
  
  function hlSub(sid){
    const subVpc=vL.find(v=>v.subs.some(s=>s.sub&&s.sub.SubnetId===sid));
    const subVid=subVpc?.vpc.VpcId;
    const subLayout=subVpc?.subs.find(s=>s.sub&&s.sub.SubnetId===sid);
    const subMidY=subLayout?(subLayout.y+subLayout.h/2):null;

    const mg=new Set();
    Object.entries(tG).forEach(([key,cs])=>{
      if(cs.some(c=>c.sid===sid)) mg.add(cs[0].gid);
    });

    olL.selectAll('*').remove();
    routeG.style('opacity','0.03');structG.style('opacity','0.03');
    g.classed('hl-active',true);
    ndL.selectAll('.vpc-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
    if(subVid) ndL.selectAll('.vpc-group[data-vnet-id="'+subVid+'"]').each(function(){d3.select(this).select('rect').style('stroke-width','3px').style('filter','drop-shadow(0 0 8px rgba(99,180,255,.7))');});

    if(mg.size===0){
      allLb.forEach(l=>l.g.classed('visible',false));
      return;
    }

    ndL.selectAll('.gw-node').classed('gw-hl',false);
    const sNode=structG.node();

    mg.forEach(gid=>{
      ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);

      // Find the subnet's route-line Y for this gateway
      const subRouteEl=sNode.querySelector('[data-gid="'+gid+'"][data-sid="'+sid+'"].route-line');
      let subY=subMidY;
      if(subRouteEl){
        const rm=subRouteEl.getAttribute('d').match(/M[\d.]+,([\d.]+)/);
        if(rm) subY=parseFloat(rm[1]);
      }

      // Find the gateway Y (L-bend endpoint or connector point)
      const gp=gwP.get(gid);
      const gwY=gp?gp.y:subY;

      // 1. Clone this subnet's route-lines + junctions for this gateway
      sNode.querySelectorAll('[data-gid="'+gid+'"][data-sid="'+sid+'"]').forEach(el=>clonePathToOl(el));

      // 2. Clone trunk/L-bend/junction paths: but TRIM vertical trunks to subnet↔gateway range
      // First, find the L-bend/connector Y to use as trim target
      let bendY=gwY;
      sNode.querySelectorAll('[data-gid="'+gid+'"][data-vid="'+subVid+'"]:not([data-sid]):not([data-net-vert])').forEach(el=>{
        if(el.style.strokeDasharray==='none'&&!el.classList.contains('route-junction')){
          // This is the L-bend or L-connector: extract its Y
          const bm=el.getAttribute('d').match(/^M[\d.]+,([\d.]+)/);
          if(bm) bendY=parseFloat(bm[1]);
        }
      });
      sNode.querySelectorAll('[data-gid="'+gid+'"][data-vid="'+subVid+'"]:not([data-sid]):not([data-net-vert])').forEach(el=>{
        const s=d3.select(el);
        const d=el.getAttribute('d');
        const isDashed=el.style.strokeDasharray!=='none'&&!el.classList.contains('route-junction');
        // Detect vertical trunk: M{x},{y1} L{x},{y2} (same X)
        const vm=isDashed&&d.match(/^M([\d.]+),([\d.]+)\s*L\1,([\d.]+)$/);
        if(vm){
          // Trim vertical trunk to span only from subY to the L-bend/connector Y
          const tx=parseFloat(vm[1]);
          const trimTop=Math.min(subY,bendY);
          const trimBot=Math.max(subY,bendY);
          const trimD=`M${tx},${trimTop} L${tx},${trimBot}`;
          olL.append('path').attr('d',trimD)
            .style('stroke',s.attr('stroke')).style('fill','none')
            .style('stroke-width','4px').style('opacity','1')
            .style('stroke-dasharray','8 5').style('pointer-events','none');
        }else{
          clonePathToOl(el);
        }
      });

      // 3. Clone shared gateway paths with no vid (bus-bar-to-gateway verticals)
      sNode.querySelectorAll('[data-gid="'+gid+'"]:not([data-vid]):not([data-net-vert]):not([data-net-line])').forEach(el=>clonePathToOl(el));

      // 4. For IGW: show full path from gateway up to internet node
      // NET verticals are segmented per-gateway, so collect ALL segments
      // at this gateway's X from iY down to the gateway's Y,
      // PLUS intermediate NET-vert segments at other X columns between NET node and this gateway
      if(gp&&gp.gw.type==='IGW'){
        const gwX=gp.x;
        const gwBotY=gp.y-GR-4; // top of gateway circle
        sNode.querySelectorAll('[data-net-vert]').forEach(el=>{
          const dm=el.getAttribute('d').match(/^M([\d.]+),([-\d.]+)\s*L\1,([-\d.]+)$/);
          if(dm){
            const segX=parseFloat(dm[1]);
            const segTop=Math.min(parseFloat(dm[2]),parseFloat(dm[3]));
            const segBot=Math.max(parseFloat(dm[2]),parseFloat(dm[3]));
            if(Math.abs(segX-gwX)<2){
              // Same X column: only segments above or touching the gateway
              if(segTop<=gwBotY+2 && segBot<=gwBotY+2) clonePathToOl(el);
            }
          }
        });
        const netLine=sNode.querySelector('[data-net-line]');
        if(netLine){
          // Trim NET horizontal line to only extend from Internet node to this gateway's X
          const nlD=netLine.getAttribute('d');
          const nlM=nlD.match(/^M([-\d.]+),([-\d.]+)\s*L([-\d.]+),([-\d.]+)$/);
          if(nlM){
            const nlX1=parseFloat(nlM[1]),nlY=parseFloat(nlM[2]),nlX2=parseFloat(nlM[3]);
            const trimX=Math.min(Math.max(nlX1,nlX2),gwX);
            const trimD=`M${Math.min(nlX1,nlX2)},${nlY} L${trimX},${nlY}`;
            const s=d3.select(netLine);
            olL.append('path').attr('d',trimD)
              .style('stroke',s.attr('stroke')).style('fill','none')
              .style('stroke-width','4px').style('opacity','1')
              .style('stroke-dasharray','8 5').style('pointer-events','none');
          }else{
            clonePathToOl(netLine);
          }
        }
        ndL.selectAll('.internet-node').style('opacity','1');
        // Highlight IGW gateways in the same X column (shared trunk) as this gateway
        ndL.selectAll('.gw-node').each(function(){
          const c=d3.select(this).select('circle');
          const t=d3.select(this).select('text');
          if(!c.node()||!t.node()) return;
          const cx=parseFloat(c.attr('cx'));
          if(t.text()==='IGW'&&Math.abs(cx-gwX)<2) d3.select(this).classed('gw-hl',true);
        });
      }
    });
    
    // Position labels based on gateway type
    let labelOffset=0;
    const visibleLabels=[];
    if(subVpc){
      allLb.forEach(l=>{
        const show=mg.has(l.gid)&&(l.shared||l.vid===subVid);
        l.g.classed('visible',show);
        if(show&&subMidY!=null){
          const ly=subMidY+labelOffset;
          let labelX;
          if(l.shared){
            if(subVpc.gwSide==='left'){
              labelX=subVpc.x-(subVpc.chanW||100)/2-40;
            }else{
              labelX=subVpc.x+subVpc.w+(subVpc.chanW||100)/2+40;
            }
          }else{
            const gp=gwP.get(l.gid);
            if(subVpc.gwSide==='left'){
              labelX=gp?gp.x-GR-50:subVpc.x-100;
            }else{
              labelX=gp?gp.x+GR+50:subVpc.x+subVpc.w+100;
            }
          }
          l.g.select('rect').attr('x',labelX-l.lw/2).attr('y',ly-8);
          l.g.select('text').attr('x',labelX).attr('y',ly+3);
          visibleLabels.push({g:l.g,lw:l.lw,x:labelX-l.lw/2,y:ly-8,h:16});
          labelOffset+=22;
        }
      });
      
      // Dynamic collision avoidance: shift labels right if any route lines pass through
      visibleLabels.forEach(vl=>{
        let lx=vl.x,ly=vl.y,lw=vl.lw,lh=vl.h;
        let shifted=false;
        for(let iter=0;iter<5;iter++){
          let maxCrossX=0;
          // Check all route paths (trunks and lines)
          structG.selectAll('.route-trunk,.route-line').each(function(){
            const d=d3.select(this).attr('d')||'';
            // Check vertical lines: M{x},{y1} L{x},{y2}
            const vm=d.match(/M([\d.]+),([\d.]+)\s*L\1,([\d.]+)/);
            if(vm){
              const tx=parseFloat(vm[1]);
              const ty1=Math.min(parseFloat(vm[2]),parseFloat(vm[3]));
              const ty2=Math.max(parseFloat(vm[2]),parseFloat(vm[3]));
              if(tx>=lx&&tx<=lx+lw&&ty1<=ly+lh&&ty2>=ly){
                if(tx>maxCrossX)maxCrossX=tx;
              }
            }
            // Check horizontal lines: M{x1},{y} L{x2},{y}
            const hm=d.match(/M([\d.]+),([\d.]+)\s*L([\d.]+),\2/);
            if(hm){
              const hx1=Math.min(parseFloat(hm[1]),parseFloat(hm[3]));
              const hx2=Math.max(parseFloat(hm[1]),parseFloat(hm[3]));
              const hy=parseFloat(hm[2]);
              if(hy>=ly&&hy<=ly+lh&&hx2>=lx&&hx1<=lx+lw){
                if(hx2>maxCrossX)maxCrossX=hx2;
              }
            }
          });
          if(maxCrossX>0){
            lx=maxCrossX+12;
            shifted=true;
          }else break;
        }
        if(shifted){
          vl.g.select('rect').attr('x',lx);
          vl.g.select('text').attr('x',lx+lw/2);
        }
      });
    }
  }
  function clr(){
    if(_hlLocked) return;
    olL.selectAll('*').remove();routeG.style('opacity',null);structG.style('opacity',null);allLb.forEach(l=>l.g.classed('visible',false));g.classed('hl-active',false);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.internet-node').style('opacity',null);
    ndL.selectAll('.vpc-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
  }
  function forceClr(){
    _hlLocked=false;_hlKey=null;_hlType=null;showLockInd(false);
    olL.selectAll('*').remove();routeG.style('opacity',null);structG.style('opacity',null);allLb.forEach(l=>l.g.classed('visible',false));g.classed('hl-active',false);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.internet-node').style('opacity',null);
    ndL.selectAll('.vpc-group').each(function(){d3.select(this).select('rect').style('stroke-width',null).style('filter',null);});
  }
  topologySetGatewayHighlighter(function(gid){
    forceClr();hlGw(gid);
    ndL.selectAll('.gw-node').classed('gw-hl',false);
    ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);
    _hlLocked=true;_hlKey=gid;_hlType='gw';showLockInd(true);
  });
  topologySetUnlockHandler('grid',forceClr);
  svg.on('click',function(event){
    if(!event.target.closest('.gw-node')&&!event.target.closest('.subnet-node')&&!event.target.closest('.res-node')&&!event.target.closest('.route-hitarea')&&!event.target.closest('.internet-node')){
      forceClr();
      if(topologyIsResourceSpotlightOpen()) topologyCloseResourceSpotlight();
    }
  });

  // Attach route-highlighting to subnet bodies and their resource nodes
  ndL.selectAll('.subnet-node').each(function(){
    const el=d3.select(this);
    const sid=el.attr('data-subnet-id');
    if(!sid)return;
    el.on('mouseenter.hl',function(){if(!_hlLocked)hlSub(sid)})
      .on('mouseleave.hl',function(){if(!_hlLocked)clr()})
      .on('click.hl',function(event){
        if(event.target.closest('.res-node'))return;
        event.stopPropagation();
        if(_hlLocked&&_hlKey===sid&&_hlType==='sub'){forceClr();return}
        forceClr();hlSub(sid);_hlLocked=true;_hlKey=sid;_hlType='sub';showLockInd(true);
      });
    el.selectAll('.res-node')
      .on('mouseenter.hl',function(){if(!_hlLocked)hlSub(sid)})
      .on('mouseleave.hl',function(){if(!_hlLocked)clr()})
      .on('click.hl',function(event){
        event.stopPropagation();
        var resEl=d3.select(this);
        var resId=resEl.attr('data-id');
        if(resId){
          forceClr();hlSub(sid);_hlLocked=true;_hlKey=sid;_hlType='sub';showLockInd(true);
          topologyOpenResourceSpotlight(resId);
          return;
        }
        if(_hlLocked&&_hlKey===sid&&_hlType==='sub'){forceClr();return}
        forceClr();hlSub(sid);_hlLocked=true;_hlKey=sid;_hlType='sub';showLockInd(true);
      });
  });

  // peering lines - horizontal connections between VPC edges, stacked by span
  const peeringG=lnL.append('g').attr('class','peering-group');
  
  // Deduplicate peerings by VPC pair (same peering may appear from each account)
  const peeringMap = new Map();
  peerings
    .filter(pcx => !pcx.Status || pcx.Status.Code === 'active')
    .forEach(pcx => {
      const rv = pcx.RequesterVpcInfo?.VpcId, av = pcx.AccepterVpcInfo?.VpcId;
      const v1 = vL.find(v => v.vpc.VpcId === rv), v2 = vL.find(v => v.vpc.VpcId === av);
      if (!v1 || !v2) return;
      const leftVpc = v1.x < v2.x ? v1 : v2;
      const rightVpc = v1.x < v2.x ? v2 : v1;
      const key = leftVpc.vpc.VpcId + '_' + rightVpc.vpc.VpcId;
      if (!peeringMap.has(key)) {
        const span = rightVpc.x - (leftVpc.x + leftVpc.w);
        peeringMap.set(key, { pcx, leftVpc, rightVpc, span });
      }
    });
  const uniquePeerings = [...peeringMap.values()].sort((a, b) => a.span - b.span);

  const globalMinY = Math.min(...vL.map(v => v.y));
  const globalMaxBottom = Math.max(...vL.map(v => v.y + v.h));
  const laneSpacing = 28;
  const stubLen = 15;
  const peerStagger = 20;
  const peeringOccupied = [];
  const addPeeringOccupied = (r) => peeringOccupied.push({ x: r.x - 4, y: r.y - 4, w: r.w + 8, h: r.h + 8 });
  const peeringRectsOverlap = (a, b) => !(a.x + a.w < b.x || b.x + b.w < a.x || a.y + a.h < b.y || b.y + b.h < a.y);
  const placePeeringLane = (midX, baseY, labelW, direction) => {
    const step = direction === 'down' ? laneSpacing : -laneSpacing;
    let y = baseY;
    for (let attempt = 0; attempt < 10; attempt++) {
      const candidate = { x: midX - labelW / 2, y: y - 9, w: labelW, h: 18 };
      if (!peeringOccupied.some(o => peeringRectsOverlap(candidate, o))) return y;
      y += step;
    }
    return y;
  };
  gwP.forEach((pos, id) => {
    if (vpceIds.has(id)) return;
    addPeeringOccupied({ x: pos.x - GR, y: pos.y - GR, w: GR * 2, h: GR * 2 });
    const gw = pos.gw;
    const nm = gwNames[gw.id];
    const lblTxt = nm && nm !== gw.id ? nm : sid(gw.id);
    const tw = lblTxt.length * 6.2 + 16;
    addPeeringOccupied({ x: pos.x - tw / 2, y: pos.y + GR + 14 - 9, w: tw, h: 15 });
  });
  if (zones.length > 0) {
    addPeeringOccupied({ x: 60, y: routingBottomY + 40, w: Math.max(320, allVpcRight - 60), h: 120 });
  }

  // Per-VPC exit counters for above (inner) and below (outer) stubs
  const vpcAboveExit = {}, vpcBelowExit = {};

  // Each unique peering draws TWO arcs: forward (above) + inverse (below)
  uniquePeerings.forEach((p, i) => {
    const { pcx, leftVpc, rightVpc } = p;
    const pn = gn(pcx, pcx.VpcPeeringConnectionId);

    // --- Forward arc: ABOVE VPCs, inner edge stubs (facing each other) ---
    const aL = vpcAboveExit[leftVpc.vpc.VpcId] = (vpcAboveExit[leftVpc.vpc.VpcId] || 0) + 1;
    const aR = vpcAboveExit[rightVpc.vpc.VpcId] = (vpcAboveExit[rightVpc.vpc.VpcId] || 0) + 1;
    const fwdLeftX = leftVpc.x + leftVpc.w - stubLen - (aL - 1) * peerStagger;
    const fwdRightX = rightVpc.x + stubLen + (aR - 1) * peerStagger;
    const fwdMidX = (fwdLeftX + fwdRightX) / 2;
    const pw = pn.length * 5.5 + 20;
    const fwdY = placePeeringLane(fwdMidX, globalMinY - 40 - i * laneSpacing, pw, 'up');
    const fwdD = `M${fwdLeftX},${leftVpc.y} L${fwdLeftX},${fwdY} L${fwdRightX},${fwdY} L${fwdRightX},${rightVpc.y}`;

    peeringG.append('path')
      .attr('class', 'peering-line animated')
      .attr('d', fwdD)
      .attr('stroke', 'var(--pcx-color)');

    // Forward label
    const fwdLg = lnL.append('g').attr('class', 'peering-label-g');
    fwdLg.append('rect')
      .attr('x', fwdMidX - pw / 2).attr('y', fwdY - 9)
      .attr('width', pw).attr('height', 18).attr('rx', 3)
      .attr('class','note-label-bg').attr('fill', 'var(--panel-bg)').attr('stroke', '#fb923c').attr('stroke-width', .5);
    fwdLg.append('text')
      .attr('x', fwdMidX).attr('y', fwdY + 4)
      .attr('text-anchor', 'middle').attr('font-family', 'Segoe UI,system-ui,sans-serif')
      .style('font-size', 'calc(9px * var(--txt-scale,1))').attr('fill', '#fb923c').text(pn);
    addPeeringOccupied({ x: fwdMidX - pw / 2, y: fwdY - 9, w: pw, h: 18 });

    // --- Inverse arc: BELOW VPCs, outer edge stubs (facing away) ---
    const bL = vpcBelowExit[leftVpc.vpc.VpcId] = (vpcBelowExit[leftVpc.vpc.VpcId] || 0) + 1;
    const bR = vpcBelowExit[rightVpc.vpc.VpcId] = (vpcBelowExit[rightVpc.vpc.VpcId] || 0) + 1;
    const invLeftX = leftVpc.x + stubLen + (bL - 1) * peerStagger;
    const invRightX = rightVpc.x + rightVpc.w - stubLen - (bR - 1) * peerStagger;
    const invMidX = (invLeftX + invRightX) / 2;
    const invY = placePeeringLane(invMidX, globalMaxBottom + 40 + i * laneSpacing, pw, 'up');
    const invD = `M${invLeftX},${leftVpc.y + leftVpc.h} L${invLeftX},${invY} L${invRightX},${invY} L${invRightX},${rightVpc.y + rightVpc.h}`;

    peeringG.append('path')
      .attr('class', 'peering-line animated')
      .attr('d', invD)
      .attr('stroke', 'var(--pcx-color)');

    // Inverse label
    const invLg = lnL.append('g').attr('class', 'peering-label-g');
    invLg.append('rect')
      .attr('x', invMidX - pw / 2).attr('y', invY - 9)
      .attr('width', pw).attr('height', 18).attr('rx', 3)
      .attr('class','note-label-bg').attr('fill', 'var(--panel-bg)').attr('stroke', '#fb923c').attr('stroke-width', .5);
    invLg.append('text')
      .attr('x', invMidX).attr('y', invY + 4)
      .attr('text-anchor', 'middle').attr('font-family', 'Segoe UI,system-ui,sans-serif')
      .style('font-size', 'calc(9px * var(--txt-scale,1))').attr('fill', '#fb923c').text(pn);
    addPeeringOccupied({ x: invMidX - pw / 2, y: invY - 9, w: pw, h: 18 });
  });

  // VPN marker
  vpns.forEach(vpn=>{
    if(vpn.State!=='available')return;
    const vgwId=vpn.VpnGatewayId;if(!vgwId||!gwP.has(vgwId))return;
    const pos=gwP.get(vgwId);
    const vpnLbl='VPN: '+gn(vpn,'VPN');const vpnLblY=pos.y-GR-12;const vpnTw=vpnLbl.length*5.2+14;
    ndL.append('rect').attr('x',pos.x-vpnTw/2).attr('y',vpnLblY-9).attr('width',vpnTw).attr('height',14).attr('rx',4).attr('class','gw-label-bg').attr('fill','var(--overlay-bg)').attr('stroke','rgba(249,115,22,.3)').attr('stroke-width',.5);
    ndL.append('text').attr('x',pos.x).attr('y',vpnLblY).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','#f97316').text(vpnLbl);
  });

  // route trunks
  const tpv={};
  // Count per-VPC and shared gateways separately for trunk spacing
  const tpvPerVpc={};
  const tpvShared={};
  Object.entries(tG).forEach(([k])=>{
    const parts=k.split('|');
    const gid=parts[0],vid=parts[1];
    const gp=gwP.get(gid);
    if(gp&&isShared(gp.gw.type)){
      tpvShared[vid]=(tpvShared[vid]||0)+1;
    }else{
      tpvPerVpc[vid]=(tpvPerVpc[vid]||0)+1;
    }
    tpv[vid]=(tpv[vid]||0)+1;
  });
  const vtcPerVpc={};
  const vtcPerVpcUp={}; // Counter for UP-going per-VPC gateways
  const vtcPerVpcDown={}; // Counter for DOWN-going per-VPC gateways
  const vtcShared={};
  const lsg=new Set();
  
  // Track bus Y levels per shared gateway for vertical connector
  const sharedGwBusY={};

  // Sort gateway entries by DIRECTION relative to subnets to prevent line crossings
  // Lines going UP (gateway above subnets) get trunk X further LEFT
  // Lines going DOWN (gateway below subnets) get trunk X further RIGHT
  const sortedTgEntries=Object.entries(tG).sort((a,b)=>{
    const connsA=a[1],connsB=b[1];
    const gpA=gwP.get(connsA[0].gid);
    const gpB=gwP.get(connsB[0].gid);
    const vidA=connsA[0].vid,vidB=connsB[0].vid;
    // Group by VPC first
    if(vidA!==vidB)return 0;
    if(!gpA||!gpB)return 0;
    // Calculate average subnet Y for each gateway's connections
    const avgSubYA=connsA.reduce((s,c)=>s+c.sl.y+c.sl.h/2,0)/connsA.length;
    const avgSubYB=connsB.reduce((s,c)=>s+c.sl.y+c.sl.h/2,0)/connsB.length;
    // Direction: negative = going UP, positive = going DOWN
    const dirA=gpA.y-avgSubYA;
    const dirB=gpB.y-avgSubYB;
    // Lines going UP (negative dir) should be LEFT (sorted first)
    // Lines going DOWN (positive dir) should be RIGHT (sorted later)
    return dirA-dirB;
  });

  sortedTgEntries.forEach(([key,conns])=>{
    const gid=conns[0].gid,vid=conns[0].vid;
    const gp=gwP.get(gid);if(!gp)return;
    const gi=gp.gw,col=gcv(gi.type),colH=gch(gi.type);
    const ov=vL.find(v=>v.vpc.VpcId===vid);if(!ov)return;
    conns.sort((a,b)=>a.sl.y-b.sl.y);

    // Separate trunk X for per-VPC vs shared gateways - large gap to avoid visual collision
    const sh=isShared(gi.type);
    const gwLeft=ov.gwSide==='left'; // last VPC: gateways to the left
    const cl=gwLeft?(ov.x-8):(ov.x+ov.w+8);

    // Direction based on gateway type: per-VPC (IGW/NAT) go UP to NET, shared (TGW) go DOWN to bus
    conns.sort((a,b)=>a.sl.y-b.sl.y);
    const goingUp=!sh; // per-VPC gateways route UP, shared gateways route DOWN

    let tx;
    if(sh){
      // Shared gateways (TGW) use trunks close to VPC edge
      const tn=vtcShared[vid]=(vtcShared[vid]||0)+1;
      const nt=tpvShared[vid]||1;
      const sp=Math.max(12,Math.min(18,(ov.chanW*0.2)/Math.max(nt,1)));
      tx=gwLeft?(cl-4-(tn-1)*sp):(cl+4+(tn-1)*sp);
    }else{
      // Per-VPC gateways: UP lines get inner trunks, DOWN lines get outer trunks
      const baseOffset=50;
      const perVpcCount=tpvPerVpc[vid]||1;
      const sp=Math.max(12,Math.min(18,(ov.chanW*0.3)/Math.max(perVpcCount,1)));

      // Separate counters for up vs down
      if(!vtcPerVpcUp[vid])vtcPerVpcUp[vid]=0;
      if(!vtcPerVpcDown[vid])vtcPerVpcDown[vid]=0;

      if(goingUp){
        const tn=++vtcPerVpcUp[vid];
        tx=gwLeft?(cl-baseOffset-(tn-1)*sp):(cl+baseOffset+(tn-1)*sp);
      }else{
        const tn=++vtcPerVpcDown[vid];
        // Calculate avgSubY for THIS gateway's connections (was undefined before)
        const thisAvgSubY=conns.reduce((s,c)=>s+c.sl.y+c.sl.h/2,0)/conns.length;
        const upCount=Object.keys(tG).filter(k=>{
          const c=tG[k][0];
          if(c.vid!==vid)return false;
          const g=gwP.get(c.gid);
          return g&&!isShared(g.gw.type)&&g.y<thisAvgSubY;
        }).length;
        tx=gwLeft?(cl-baseOffset-(upCount)*sp-(tn-1)*sp):(cl+baseOffset+(upCount)*sp+(tn-1)*sp);
      }
      // Clamp trunk outside gateway circle so the L-bend always points toward the gateway
      if(gwLeft) tx=Math.max(tx,gp.x+GR+10);
      else tx=Math.min(tx,gp.x-GR-10);
    }

    // Deduplicate connections by subnet ID
    const seenSubs=new Set();
    const uniqueConns=conns.filter(c=>{
      if(seenSubs.has(c.sid))return false;
      seenSubs.add(c.sid);return true;
    });

    // Collect all per-VPC gateway positions for this VPC to avoid crossing them
    const vpcGwPositions=[];
    gwP.forEach((pos,id)=>{
      if(!isShared(pos.gw.type)){
        const ovGw=vL.find(v=>v.subs.some(s=>true)&&pvGws[v.vpc.VpcId]?.some(g=>g.id===id));
        if(ovGw&&ovGw.vpc.VpcId===vid) vpcGwPositions.push(pos);
      }
    });

    uniqueConns.forEach(c=>{
      // Exit from top of subnet if going UP, bottom if going DOWN
      const sy=goingUp?(c.sl.y+6):(c.sl.y+c.sl.h-6);

      // Check if horizontal line would cross any gateway circle (not our own)
      let d;
      if(gwLeft){
        const subLeft=c.sl.x;
        const crossingGw=vpcGwPositions.find(g=>g!==gp&&Math.abs(g.y-sy)<GR+8&&g.x<subLeft&&g.x>tx);
        if(crossingGw){
          const jogY=sy<crossingGw.y?(crossingGw.y-GR-10):(crossingGw.y+GR+10);
          d=`M${subLeft},${sy} L${crossingGw.x+GR+6},${sy} L${crossingGw.x+GR+6},${jogY} L${tx},${jogY} L${tx},${sy}`;
        }else{
          d=`M${subLeft},${sy} L${tx},${sy}`;
        }
      }else{
        const subRight=c.sl.x+c.sl.w;
        const crossingGw=vpcGwPositions.find(g=>g!==gp&&Math.abs(g.y-sy)<GR+8&&g.x>subRight&&g.x<tx);
        if(crossingGw){
          const jogY=sy<crossingGw.y?(crossingGw.y-GR-10):(crossingGw.y+GR+10);
          d=`M${subRight},${sy} L${crossingGw.x-GR-6},${sy} L${crossingGw.x-GR-6},${jogY} L${tx},${jogY} L${tx},${sy}`;
        }else{
          d=`M${subRight},${sy} L${tx},${sy}`;
        }
      }
      const rl=structG.append('path').attr('class','route-line route-structural').attr('d',d).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vid).attr('data-sid',c.sid);
      if(gwLeft) rl.style('animation-direction','reverse');
      // Solid filled square at trunk junction to cover dash-pattern gaps
      const jd=`M${tx-3},${sy-3} L${tx+3},${sy-3} L${tx+3},${sy+3} L${tx-3},${sy+3} Z`;
      structG.append('path').attr('class','route-junction route-structural').attr('d',jd).attr('stroke',col).attr('fill',col).attr('stroke-width',1).style('stroke-dasharray','none').attr('data-gid',gid).attr('data-vid',vid).attr('data-sid',c.sid);
      lnL.append('path').attr('class','route-hitarea').attr('d',d)
        .on('mouseenter',()=>{if(!_hlLocked)hlSub(c.sid)}).on('mouseleave',clr)
        .on('click',function(event){event.stopPropagation();
          if(_hlLocked&&_hlKey===c.sid&&_hlType==='sub'){forceClr();return}
          forceClr();hlSub(c.sid);_hlLocked=true;_hlKey=c.sid;_hlType='sub';showLockInd(true);
        });
    });

    // Trunk Y matches horizontal line positions
    const topY=goingUp?(uniqueConns[0].sl.y+6):(uniqueConns[0].sl.y+uniqueConns[0].sl.h-6);
    const botY=goingUp?(uniqueConns[uniqueConns.length-1].sl.y+6):(uniqueConns[uniqueConns.length-1].sl.y+uniqueConns[uniqueConns.length-1].sl.h-6);
    let lx,ly;

    if(!sh){
      // Per-VPC gateway: trunk spans ALL connected subnets AND gateway, then L-connector
      const gwEdgeX=gwLeft?(gp.x+GR+4):(gp.x-GR-4);

      // Compute actual min/max Y across ALL connected subnets (not just first/last)
      const allSubYs=uniqueConns.map(c=>goingUp?(c.sl.y+6):(c.sl.y+c.sl.h-6));
      // Trunk must cover ALL subnet Ys AND the gateway Y
      const vertTop=Math.min(...allSubYs,gp.y);
      const vertBot=Math.max(...allSubYs,gp.y);

      // Vertical trunk covering full range + L-bend to gateway
      const fullPath=`M${tx},${vertTop} L${tx},${vertBot}`;
      const lbendPath=`M${tx},${gp.y} L${gwEdgeX},${gp.y}`;
      const combinedPath=`M${tx},${vertTop} L${tx},${vertBot} M${tx},${gp.y} L${gwEdgeX},${gp.y}`;
      // Dashed vertical trunk spanning all subnets
      structG.append('path').attr('class','route-trunk route-structural').attr('d',fullPath).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vid).attr('data-vert','1');
      // Solid L-bend connector from trunk to gateway
      const lb=structG.append('path').attr('class','route-trunk route-structural').attr('d',lbendPath).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vid);
      if(gwLeft) lb.style('animation-direction','reverse');
      // Solid patch at L-bend corner
      const bendPatch=`M${tx-3},${gp.y-3} L${tx+3},${gp.y-3} L${tx+3},${gp.y+3} L${tx-3},${gp.y+3} Z`;
      structG.append('path').attr('class','route-junction route-structural').attr('d',bendPatch).attr('stroke',col).attr('fill',col).style('stroke-dasharray','none').attr('data-gid',gid).attr('data-vid',vid);
      lnL.append('path').attr('class','route-hitarea').attr('d',combinedPath)
        .on('mouseenter',()=>{if(!_hlLocked){hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true)}}).on('mouseleave',()=>{clr()})
        .on('click',function(event){event.stopPropagation();
          if(_hlLocked&&_hlKey===gid&&_hlType==='gw'){forceClr();return}
          forceClr();hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);
          _hlLocked=true;_hlKey=gid;_hlType='gw';showLockInd(true);
        });

      // Route label between gateway and VPC (on the trunk-line side)
      ly=gp.y;
      lx=gwLeft?(gp.x+GR+8):(gp.x-GR-8);
    }else{
      // Shared gateway: collect for bus bar routing (drawn later)
      if(!sharedGwBusY[gid]){
        sharedGwBusY[gid]={vpcs:[],col,gp};
      }
      sharedGwBusY[gid].vpcs.push({tx,ov,conns:uniqueConns});

      // For shared gateways, label near the trunk line at the last connected subnet
      lx=gwLeft?(tx-4):(tx+4);ly=uniqueConns[uniqueConns.length-1].sl.y+uniqueConns[uniqueConns.length-1].sl.h+10;
    }

    let skip=false;
    if(sh){if(lsg.has(gid))skip=true;else lsg.add(gid)}
    if(!skip){
      const lt=uniqueConns[0].dst+' > '+gi.type,lw=lt.length*5.4+16;
      const lg=labelL.append('g').attr('class','route-label-g');
      const anchor=(!sh&&gwLeft)?'start':'end';
      const rx=anchor==='end'?(lx-lw):lx;
      const textX=rx+lw/2;
      lg.append('rect').attr('x',rx).attr('y',ly-9).attr('width',lw).attr('height',18).attr('rx',3).attr('class','route-label-bg').attr('fill','var(--panel-bg)').attr('stroke',colH).attr('stroke-width',1);
      lg.append('text').attr('x',textX).attr('y',ly+4).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(9px * var(--txt-scale,1))').attr('font-weight','700').attr('fill',colH).text(lt);
      allLb.push({gid,vid,shared:sh,lx:textX,lw,g:lg});
    }
  });

  // Draw shared gateway bus routing AFTER all VPCs processed
  var _sharedBusIdx=0;
  Object.entries(sharedGwBusY).forEach(([gid,info])=>{
    const {vpcs:vpcConns,col,gp}=info;
    if(!vpcConns.length)return;

    // Bus bar Y: offset each shared gateway's bus bar to avoid overlap
    const allVpcBotForBus=Math.max(...vpcConns.map(v=>v.ov.y+v.ov.h));
    const busY=allVpcBotForBus+30+(_sharedBusIdx*20);
    _sharedBusIdx++;

    // Each VPC trunk: dashed trunk spanning subnets + solid connector to bus bar
    vpcConns.forEach(vc=>{
      const uniqueC=vc.conns.sort((a,b)=>a.sl.y-b.sl.y);
      const vpcId=vc.ov.vpc.VpcId;
      const allSubYs=uniqueC.map(c=>c.sl.y+c.sl.h-6);
      const trunkTop=Math.min(...allSubYs);
      const trunkBot=Math.max(...allSubYs);

      // Dashed trunk spanning only connected subnet range
      if(trunkTop!==trunkBot){
        const trunkPath=`M${vc.tx},${trunkTop} L${vc.tx},${trunkBot}`;
        structG.append('path').attr('class','route-trunk route-structural').attr('d',trunkPath).attr('stroke',col).attr('data-gid',gid).attr('data-vid',vpcId).attr('data-vert','1');
      }

      // Vertical drop from trunk bottom to bus Y (horizontal drawn once after loop)
      const connPath=`M${vc.tx},${trunkBot} L${vc.tx},${busY}`;
      structG.append('path').attr('class','route-trunk route-structural').attr('d',connPath).attr('stroke',col).style('stroke-dasharray','none').style('opacity',0.45).attr('data-gid',gid).attr('data-vid',vpcId);
      // Solid patch at trunk-to-connector junction
      const tgwJunc=`M${vc.tx-3},${trunkBot-3} L${vc.tx+3},${trunkBot-3} L${vc.tx+3},${trunkBot+3} L${vc.tx-3},${trunkBot+3} Z`;
      structG.append('path').attr('class','route-junction route-structural').attr('d',tgwJunc).attr('stroke',col).attr('fill',col).style('stroke-dasharray','none').attr('data-gid',gid).attr('data-vid',vpcId);

      // Hitarea covers trunk path
      const fullPath=`M${vc.tx},${trunkTop} L${vc.tx},${busY}`;
      lnL.append('path').attr('class','route-hitarea').attr('d',fullPath)
        .on('mouseenter',()=>{if(!_hlLocked){hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true)}}).on('mouseleave',()=>{clr()})
        .on('click',function(event){event.stopPropagation();
          if(_hlLocked&&_hlKey===gid&&_hlType==='gw'){forceClr();return}
          forceClr();hlGw(gid);ndL.selectAll('.gw-node[data-gwid="'+gid+'"]').classed('gw-hl',true);
          _hlLocked=true;_hlKey=gid;_hlType='gw';showLockInd(true);
        });
    });

    // Direct spoke lines from each VPC trunk to gateway (no bus bar, no long horizontals)
    var gwX=gp.x,gwTopY=gp.y-GR-4;
    vpcConns.forEach(vc=>{
      var d=`M${vc.tx},${busY} L${gwX},${gwTopY}`;
      structG.append('path').attr('class','route-trunk route-structural')
        .attr('d',d).attr('stroke',col).style('opacity',0.35)
        .attr('data-gid',gid).attr('data-vid',vc.ov.vpc.VpcId);
      // Junction dot at trunk origin
      structG.append('circle').attr('cx',vc.tx).attr('cy',busY).attr('r',3)
        .attr('fill',col).attr('stroke','none').style('opacity',0.6)
        .attr('class','route-junction route-structural').attr('data-gid',gid);
    });
  });

  // (Per-VPC verticals to gateway drawn inline above)

  // Find edges for routing
  const allVpcBottomEdge=Math.max(...vL.map(v=>v.y+v.h));

  // IGW/NAT to Internet lines are now drawn with the NET node for proper animation

  // Reposition disconnected VPCs below all routing (gateways, bus lanes, peering)
  if(unknownVL.length>0){
    const newUnkY=routingBottomY+60;
    const oldUnkY=unknownVL[0].y;
    const dy=newUnkY-oldUnkY;
    if(dy!==0){
      unknownVL.forEach(v=>{v.y+=dy;v.subs.forEach(s=>{s.y+=dy})});
    }
    routingBottomY=Math.max(...unknownVL.map(v=>v.y+v.h))+20;
  }

  const {vpcRegionMap}=drawTopologyGridRegionBands({
    ndL,
    vL,
    knownVL,
    unknownVL,
    subByVnet,
    _multiRegion
  });

  // VPC boxes
  const tt=document.getElementById('tooltip');
  vL.forEach(vl=>{
    const vG=ndL.append('g').attr('class','vpc-group').attr('data-vnet-id',vl.vpc.VpcId);
    vG.append('rect').attr('x',vl.x).attr('y',vl.y).attr('width',vl.w).attr('height',vl.h).attr('fill','rgba(59,130,246,.03)').attr('stroke','var(--vpc-stroke)').attr('stroke-width',1.5);
    const _vpcName=gn(vl.vpc,vl.vpc.VpcId);
    const regionTag=vpcRegionMap[vl.vpc.VpcId]||'';
    const _acLbl2=vl.vpc._accountLabel||vl.vpc._subscriptionId;
    const acctTag=_multiTenant&&vl.vpc._subscriptionId&&vl.vpc._subscriptionId!=='default'?(' ['+_acLbl2+']'):'';
    // Name on first line, CIDR+subscription on second line
    vG.append('text').attr('class','vnet-label').attr('x',vl.x+14).attr('y',vl.y+16)
      .attr('textLength',Math.max(40,vl.w-28)).attr('lengthAdjust','spacingAndGlyphs').text(_vpcName);
    vG.append('text').attr('class','vnet-cidr').attr('x',vl.x+14).attr('y',vl.y+28)
      .text(vl.vpc.CidrBlock+(regionTag?' | '+regionTag:'')+(acctTag||''));
    // Account color stripe for multi-account
    if(_multiTenant&&vl.vpc._subscriptionId!=='default'){
      const acCol=vl.vpc._ctxColor||getAccountColor(vl.vpc._subscriptionId);
      if(acCol){
        const acLbl=vl.vpc._accountLabel||vl.vpc._subscriptionId;
        vG.append('rect').attr('x',vl.x).attr('y',vl.y).attr('width',8).attr('height',vl.h).attr('fill',acCol).attr('rx',2).attr('opacity',.7);
        var maxTH=vl.h-12;var idealF=7;var needH=acLbl.length*idealF*0.65;var fPx=needH>maxTH?Math.max(4,idealF*(maxTH/needH)):idealF;
        vG.append('text').attr('x',vl.x+5).attr('y',vl.y+vl.h-6).attr('transform','rotate(-90,'+((vl.x+5))+','+((vl.y+vl.h-6))+')')
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc('+fPx.toFixed(1)+'px * var(--txt-scale,1))').attr('fill','#fff').attr('font-weight','600').attr('letter-spacing','.3px')
          .text(acLbl);
      }
    }
    // show indicator for VPCs with no subnets
    if(vl.subs.length===0){
      vG.append('text').attr('x',vl.x+vl.w/2).attr('y',vl.y+vl.h/2+10).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text('No subnets');
    }
  });

  // subnets
  vL.forEach(vl=>{
    // Draw AZ separator labels
    vl.subs.filter(sl=>sl.azLabel).forEach(sl=>{
      ndL.append('text').attr('x',sl.x).attr('y',sl.y+AZ_HDR-2).attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','var(--text-muted)').attr('opacity',.6).attr('letter-spacing','1px').text('AZ: '+sl.azLabel.slice(-2).toUpperCase());
      ndL.append('line').attr('x1',sl.x+38).attr('y1',sl.y+AZ_HDR-5).attr('x2',sl.x+sl.w).attr('y2',sl.y+AZ_HDR-5).attr('stroke','var(--border)').attr('stroke-width',.5).attr('opacity',.4);
    });
    vl.subs.filter(sl=>sl.sub).forEach(sl=>{
    const sG=ndL.append('g').attr('class','subnet-node').attr('data-subnet-id',sl.sub.SubnetId);
    const col=sl.pub?'var(--subnet-public)':'var(--subnet-private)';
    sG.append('rect').attr('x',sl.x).attr('y',sl.y).attr('width',sl.w).attr('height',sl.h).attr('fill',sl.pub?'rgba(6,182,212,.15)':'rgba(139,92,246,.15)').attr('stroke',col).attr('stroke-width',1.2);
    const cid='c-'+sl.sub.SubnetId.replace(/[^a-zA-Z0-9]/g,'');
    sG.append('clipPath').attr('id',cid).append('rect').attr('x',sl.x+6).attr('y',sl.y).attr('width',sl.w-12).attr('height',sl.h);
    const tG2=sG.append('g').attr('clip-path',`url(#${cid})`);
    tG2.append('text').attr('class','subnet-label').attr('x',sl.x+8).attr('y',sl.y+18).text(gn(sl.sub,sl.sub.SubnetId));
    tG2.append('text').attr('class','subnet-cidr').attr('x',sl.x+8).attr('y',sl.y+30).text(sl.sub.CidrBlock+(sl.sub.AvailabilityZone?'  '+sl.sub.AvailabilityZone.slice(-2):''));
    sG.append('text').attr('x',sl.x+sl.w-8).attr('y',sl.y+14).attr('text-anchor','end').attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','600').attr('fill',col).text(sl.pub?'PUBLIC':'PRIVATE');

    // resource icons inside subnet (tree-based with nesting)
    const tree=subTrees[sl.sub.SubnetId]||[];
    
    if(_detailLevel===0&&tree.length>0){
      // collapsed: show resource count summary
      const counts={};
      tree.forEach(r=>{counts[r.type]=(counts[r.type]||0)+1});
      const summary=Object.entries(counts).map(([t,c])=>c+' '+t).join(', ');
      sG.append('text').attr('x',sl.x+8).attr('y',sl.y+sl.h-6)
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))').attr('fill','var(--text-muted)').attr('opacity',.5).text(summary);
    } else if(tree.length>0){
      const iconW=Math.max(70,Math.floor((sl.w-16)/RES_COLS)-RES_GAP);
      const maxCh=Math.max(0,...tree.map(r=>(r.children||[]).length));
      const rowH=RES_ICON+maxCh*RES_CHILD_H+6;
      let rx=sl.x+6, ry=sl.y+RES_TOP, rci=0;
      tree.forEach((res,ri)=>{
        if(rci>=RES_COLS){rci=0;rx=sl.x+6;ry+=rowH;}
        const nCh=(res.children||[]).length;
        const iconH=RES_ICON+nCh*RES_CHILD_H;
        // wrap in interactive group
        const rG=sG.append('g').attr('class','res-node').style('cursor','pointer');
        if(res.rid) rG.attr('data-id',res.rid);
        const _rx=rx,_ry=ry;
        rG.on('mouseenter',function(event){
          event.stopPropagation();
          if(!_hlLocked) hlSub(sl.sub.SubnetId);
          tt.innerHTML=resTooltipHtml(res,sl.sub.SubnetId,subRT);
          tt.style.display='block';
        }).on('mousemove',function(event){
          positionTooltip(event,tt);
        }).on('mouseleave',function(){
          tt.style.display='none';
        });
        // outer box
        rG.append('rect').attr('x',rx).attr('y',ry).attr('width',iconW).attr('height',iconH)
          .attr('rx',3).attr('fill',res.bg).attr('stroke',res.col).attr('stroke-width',.7);
        // type badge
        rG.append('rect').attr('x',rx).attr('y',ry).attr('width',24).attr('height',iconH)
          .attr('rx',3).attr('fill',res.col).attr('fill-opacity',.3);
        rG.append('text').attr('x',rx+12).attr('y',ry+13).attr('text-anchor','middle')
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7.5px * var(--txt-scale,1))').attr('font-weight','700')
          .attr('fill',res.col).text(res.type);
        // clip for text overflow
        const nameClip='rc-'+sl.sub.SubnetId.replace(/[^a-zA-Z0-9]/g,'')+'-'+ri;
        rG.append('clipPath').attr('id',nameClip).append('rect')
          .attr('x',rx+26).attr('y',ry).attr('width',iconW-28).attr('height',iconH);
        // name
        rG.append('text').attr('x',rx+28).attr('y',ry+10).attr('clip-path',`url(#${nameClip})`)
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600')
          .attr('fill','var(--text-primary)').text(res.name);
        // IP
        if(res.ip){
          rG.append('text').attr('x',rx+28).attr('y',ry+20).attr('clip-path',`url(#${nameClip})`)
            .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))')
            .attr('fill','var(--text-muted)').text(res.ip);
        }
        // state dot
        if(res.state){
          const sc=res.state==='running'?'#10b981':'#ef4444';
          rG.append('circle').attr('cx',rx+iconW-6).attr('cy',ry+6).attr('r',2.5).attr('fill',sc);
        }
        // nested children
        if(nCh>0){
          (res.children||[]).forEach((ch,ci)=>{
            const cy2=ry+RES_ICON-2+ci*RES_CHILD_H;
            const cx2=rx+26,cw=iconW-30,ch2=RES_CHILD_H-2;
            rG.append('rect').attr('x',cx2).attr('y',cy2).attr('width',cw).attr('height',ch2)
              .attr('rx',2).attr('fill',ch.bg).attr('stroke',ch.col).attr('stroke-width',.4);
            rG.append('text').attr('x',cx2+2).attr('y',cy2+ch2/2+2)
              .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))').attr('font-weight','600')
              .attr('fill',ch.col).text(ch.type);
            rG.append('text').attr('x',cx2+19).attr('y',cy2+ch2/2+2).attr('clip-path',`url(#${nameClip})`)
              .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6px * var(--txt-scale,1))')
              .attr('fill','var(--text-secondary)').text(ch.name+(ch.detail?' '+ch.detail:''));
          });
        }
        rx+=iconW+RES_GAP;
        rci++;
      });
    } else {
      // empty subnet indicator
      sG.append('text').attr('x',sl.x+sl.w/2).attr('y',sl.y+sl.h/2+4).attr('text-anchor','middle')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','var(--text-muted)').attr('opacity',.4).text('No resources');
    }

    // click to open detail panel, hover for highlight only
    sG.on('mouseenter',function(){if(!_hlLocked)hlSub(sl.sub.SubnetId)})
    .on('mouseleave',()=>{clr()})
    .on('click',function(event){
      event.stopPropagation();
      const sid2=sl.sub.SubnetId;
      if(_hlLocked&&_hlKey===sid2&&_hlType==='sub'){
        // already locked on this subnet, just open panel
      } else {
        forceClr();hlSub(sid2);
        _hlLocked=true;_hlKey=sid2;_hlType='sub';showLockInd(true);
      }
      _lastRlType=null;_navStack=[];
      openSubnetPanel(sl.sub,vl.vpc.VpcId,{pubSubs,subRT,subNacl,instBySub,eniBySub,albBySub,nsgByVnet,volByInst,enis,snapByVol,tgByAlb,wafByAlb,rdsBySub,ecsBySub,lambdaBySub,ecacheByVpc,redshiftByVpc,cfByAlb,storageBySub});
    });
  })});

  // gateway circles -- skip VPCEs (they get summary boxes instead)
  gwP.forEach((pos,id)=>{
    if(vpceIds.has(id))return;
    const gw=pos.gw,gG=ndL.append('g').attr('class','gw-node').attr('data-gwid',id),col=gcv(gw.type);
    gG.append('circle').attr('cx',pos.x).attr('cy',pos.y).attr('r',GR).attr('fill','var(--bg-primary)').attr('stroke',col).attr('stroke-width',2);
    gG.append('text').attr('class','gw-label').attr('x',pos.x).attr('y',pos.y+1).attr('text-anchor','middle').attr('dominant-baseline','middle').attr('fill',col).text(gw.type);
    const nm=gwNames[gw.id];
    const lblY=pos.y+GR+14;
    const lblTxt=nm&&nm!==gw.id?nm:sid(gw.id);
    const lblClass=nm&&nm!==gw.id?'gw-name':'gw-id';
    const tw=lblTxt.length*6.2+16;
    gG.append('rect').attr('x',pos.x-tw/2).attr('y',lblY-9).attr('width',tw).attr('height',15).attr('rx',4).attr('class','gw-label-bg').attr('fill','var(--overlay-bg)').attr('stroke','var(--hover-bg)').attr('stroke-width',.5);
    gG.append('text').attr('class',lblClass).attr('x',pos.x).attr('y',lblY).attr('text-anchor','middle').text(lblTxt);
    gG.on('mouseenter',function(){
      if(_hlLocked) return;
      hlGw(id);
      ndL.selectAll('.gw-node').classed('gw-hl',false);
      gG.classed('gw-hl',true);
      let h=`<div class="tt-title">${nm||gw.id}</div><div class="tt-sub">${gw.type} | ${gw.id}</div>`;
      const natInfo=nats.find(n=>n.NatGatewayId===gw.id);
      if(natInfo){h+=`<div class="tt-sec"><div class="tt-sh">NAT Gateway</div><div class="tt-r">Subnet: <span class="i">${natInfo.SubnetId||'N/A'}</span></div><div class="tt-r">State: ${natInfo.State||'N/A'}</div></div>`}
      tt.innerHTML=h;tt.style.display='block';
    }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none';clr()})
    .on('click',function(event){
      event.stopPropagation();
      if(_hlLocked&&_hlKey===id&&_hlType==='gw'){forceClr();return}
      forceClr();hlGw(id);
      ndL.selectAll('.gw-node').classed('gw-hl',false);gG.classed('gw-hl',true);
      _hlLocked=true;_hlKey=id;_hlType='gw';showLockInd(true);
      _lastRlType=null;_navStack=[];
      openGatewayPanel(gw.id,gw.type,{gwNames,igws,nats,vpns,vpces,peerings,rts,subnets,subRT,pubSubs,vpcs,tgwAttachments});
    });
  });

  // Gateway name badges can pack tightly under adjacent shared gateways.
  // Resolve them as one label family after all gateway nodes have been rendered.
  {
    const labels = [];
    ndL.selectAll('.gw-node').each(function(){
      const g = d3.select(this);
      const bg = g.select('.gw-label-bg');
      const txt = g.select('.gw-name, .gw-id');
      if(!bg.node()||!txt.node())return;
      labels.push({
        rectNode: bg,
        textNode: txt,
        x: parseFloat(bg.attr('x')),
        y: parseFloat(bg.attr('y')),
        w: parseFloat(bg.attr('width')),
        h: parseFloat(bg.attr('height')),
      });
    });
    labels.sort((a,b)=>a.y-b.y||a.x-b.x);
    for(let iter=0;iter<12;iter++){
      let moved=false;
      for(let i=0;i<labels.length;i++){
        for(let j=i+1;j<labels.length;j++){
          const a=labels[i],b=labels[j];
          if(!peeringRectsOverlap({x:a.x-2,y:a.y-2,w:a.w+4,h:a.h+4},{x:b.x,y:b.y,w:b.w,h:b.h}))continue;
          b.y=a.y+a.h+4;
          moved=true;
        }
      }
      if(!moved)break;
    }
    labels.forEach(l=>{
      l.rectNode.attr('y',l.y);
      l.textNode.attr('y',l.y+9);
    });
  }

  // internet node - positioned at top-left
  if(iGwList.length){
    const iG=ndL.append('g').attr('class','internet-node');
    // Outer glow
    iG.append('circle').attr('cx',iX).attr('cy',iY).attr('r',42)
      .attr('fill','none').attr('stroke','var(--igw-color)').attr('stroke-width',1).attr('opacity',.15);
    // Main circle
    iG.append('circle').attr('cx',iX).attr('cy',iY).attr('r',36)
      .attr('fill','rgba(16,185,129,.06)').attr('stroke','var(--igw-color)').attr('stroke-width',2);
    // Globe effect
    iG.append('ellipse').attr('cx',iX).attr('cy',iY).attr('rx',22).attr('ry',36)
      .attr('fill','none').attr('stroke','var(--igw-color)').attr('stroke-width',1).attr('opacity',.25);
    iG.append('line').attr('x1',iX-36).attr('y1',iY).attr('x2',iX+36).attr('y2',iY)
      .attr('stroke','var(--igw-color)').attr('stroke-width',1).attr('opacity',.25);
    // Text inside circle
    iG.append('text').attr('x',iX).attr('y',iY+4).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(13px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','var(--igw-color)').text('NET');
    // Text below circle
    iG.append('text').attr('x',iX).attr('y',iY+50).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text('Internet');
    iG.append('text').attr('x',iX).attr('y',iY+62).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','var(--igw-color)').text(iGwList.length+' Gateway'+(iGwList.length>1?'s':''));
    
    // Draw NET connections: L-shaped paths from bus-bar to each IGW.
    // Each IGW gets its own L-bend: horizontal from NET node at bus-bar Y,
    // then vertical down to IGW. No continuous bus bar: eliminates dead ends.
    const connectedIgwIds=new Set(Object.keys(tG).map(k=>k.split('|')[0]));
    const connectedIgwList=iGwList.filter(p=>connectedIgwIds.has(p.gw.id));
    // Group by X to handle stacked gateways at same position
    const netXGroups=new Map();
    connectedIgwList.forEach(pos=>{
      const gx=pos.x;
      if(!netXGroups.has(gx)) netXGroups.set(gx,[]);
      netXGroups.get(gx).push(pos);
    });
    // Collect X positions that reach bus-bar Y, sorted left to right
    const netXPositions=[];
    netXGroups.forEach((group,gx)=>{
      group.sort((a,b)=>(a.y-GR-4)-(b.y-GR-4));
      let reachesBus=false;
      for(let i=0;i<group.length;i++){
        const topY=i===0?iY:(group[i-1].y-GR-4);
        const botY=group[i].y-GR-4;
        const col='var(--igw-color)';
        if(Math.abs(botY-topY)>2){
          structG.append('path')
            .attr('class','route-trunk route-structural')
            .attr('d',`M${gx},${topY} L${gx},${botY}`)
            .attr('stroke',col).attr('stroke-width',3)
            .attr('data-gid',group[i].gw.id).attr('data-net-vert','1');
          if(topY===iY) reachesBus=true;
        }
      }
      if(reachesBus) netXPositions.push(gx);
    });
    netXPositions.sort((a,b)=>a-b);
    // Draw one horizontal bus from NET node to rightmost IGW column
    if(netXPositions.length>0){
      const rightmostNetX=netXPositions[netXPositions.length-1];
      structG.append('path')
        .attr('class','route-trunk route-structural')
        .attr('d',`M${iX+38},${iY} L${rightmostNetX},${iY}`)
        .attr('stroke','var(--igw-color)').attr('stroke-width',3)
        .attr('data-net-line','1');
    }
  }

  drawTopologyGridResourceSections({
    ndL,
    vL,
    unknownVL,
    vpceByVpc,
    vpces,
    gwNames,
    tt,
    zones,
    routingBottomY,
    allVpcRight,
    recsByZoneMap,
    vpcs,
    s3bk,
    storageTopology,
    cfDistributions
  });
  renderTopologyStatusControls({
    rbac:ctx.rbac,
    mode:'grid',
    vpcs,subnets,rts,sgs,nacls,enis,igws,nats,vpces,instances,albs,tgs,peerings,vpns,volumes,snapshots,s3bk,zones,
    wafAcls,rdsInstances,ecsServices,lambdaFns,ecacheClusters,redshiftClusters,tgwAttachments,cfDistributions,
    pubSubs,subRT,gwSet,subNacl,nsgByVnet,iamRoleResources,
    instBySub,eniByInst,eniBySub,albBySub,volByInst,snapByVol,tgByAlb,wafByAlb,rdsBySub,ecsBySub,lambdaBySub,
    ecacheByVpc,redshiftByVpc,cfByAlb,storageBySub,storageTopology,recsByZoneMap,
    _multiTenant,_accounts,_regions,_multiRegion,
    showDesignValidation:true
  });
}
// #endregion TOPOLOGY GRID LAYOUT
