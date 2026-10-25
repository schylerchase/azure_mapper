// #region TOPOLOGY GRID GEOMETRY
function buildTopologyGridGeometry(ctx){
  const {
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
  } = ctx;

  // layout constants
  const SH_BASE=52,SG=12,VP=30,VH=40,GR=20,MSW=240,CW=6.5;
  const RES_ICON=26,RES_CHILD_H=11,RES_GAP=4,RES_COLS=2,RES_TOP=36,RES_BOT=12;
  
  // Tree context for buildResTree
  const treeCtx={instBySub,albBySub,rdsBySub,ecsBySub,lambdaBySub,volByInst,volBySub,enis,eniByInst,tgByAlb,wafByAlb,cfByAlb,snapByVol,eniBySub,storageBySub};
  
  // Pre-calc resource tree per subnet for sizing
  const subTrees={};
  subnets.forEach(s=>{
    subTrees[s.SubnetId]=buildResTree(s.SubnetId,treeCtx);
  });
  function subHeight(sid2){
    if(_detailLevel===0) return SH_BASE;
    const tree=subTrees[sid2]||[];
    if(!tree.length) return SH_BASE;
    const maxCh=Math.max(0,...tree.map(r=>(r.children||[]).length));
    const tallest=RES_ICON+maxCh*RES_CHILD_H;
    const rowH=tallest+6;
    const rows=Math.ceil(tree.length/RES_COLS);
    return Math.max(SH_BASE, RES_TOP+rows*rowH+RES_BOT+4);
  }
  
  const vSW={};
  vpcs.forEach(v=>{
    const ss=subByVnet[v.VpcId]||[];
    const vpcNameLen=(gn(v,v.VpcId).length+2)*CW+30;
    const regionStr=v.location||v._region||'';
    const acctLbl=v._accountLabel||'';
    const subtitleStr=(v.CidrBlock||'')+(regionStr?' | '+regionStr:'')+(acctLbl&&_multiTenant?' ['+acctLbl+']':'');
    const subtitleLen=(subtitleStr.length+4)*CW+20;
    const cidrLen=Math.max(((v.CidrBlock||'').length+15)*CW+20,subtitleLen);
    let mx=Math.max(MSW,vpcNameLen+cidrLen);
    ss.forEach(s=>{
      const nameW=gn(s,s.SubnetId).length*CW+100;
      if(_detailLevel>0){
        const resCols=Math.min((subTrees[s.SubnetId]||[]).length, RES_COLS);
        const resW=resCols*(RES_ICON+RES_GAP+80)+50;
        mx=Math.max(mx,nameW,resW);
      } else {
        mx=Math.max(mx,nameW);
      }
    });
    vSW[v.VpcId]=Math.min(mx,600);
  });

  const getVpcRegion=(v)=>{
    const ss=subByVnet[v.VpcId]||[];
    const az=ss.find(s=>s.AvailabilityZone)?.AvailabilityZone||'';
    return az.replace(/[a-z]$/,'')||'unknown';
  };
  const knownVpcs=vpcs.filter(v=>getVpcRegion(v)!=='unknown');
  const unknownVpcs=vpcs.filter(v=>getVpcRegion(v)==='unknown');
  
  knownVpcs.sort((a,b)=>{
    const rc=getVpcRegion(a).localeCompare(getVpcRegion(b));
    if(rc!==0)return rc;
    const ac=(a._subscriptionId||'').localeCompare(b._subscriptionId||'');
    if(ac!==0)return ac;
    return (a.VpcId||'').localeCompare(b.VpcId||'');
  });

  const GC_BASE=140;
  const vL=[];let cx=60;
  
  // Calculate VPC height with dynamic subnet sizes
  const AZ_HDR=16; // height for AZ separator label
  function sortByAZ(ss){return ss.slice().sort((a,b)=>(a.AvailabilityZone||'').localeCompare(b.AvailabilityZone||''))}
  function countAZHeaders(ss){const azs=new Set();ss.forEach(s=>{if(s.AvailabilityZone)azs.add(s.AvailabilityZone)});return Math.max(0,azs.size-1)}
  function calcVpcHeight(ss){
    let ih=0;
    const sorted=sortByAZ(ss);
    sorted.forEach((s,i)=>{ih+=subHeight(s.SubnetId)+(i<sorted.length-1?SG:0)});
    ih+=countAZHeaders(sorted)*(AZ_HDR+SG);
    return Math.max(ih+VP*2+VH+30,150);
  }

  // Build subnet layout with cumulative Y positions, grouped by AZ
  function buildSubLayouts(ss,baseX,baseY,sw){
    const layouts=[];
    const sorted=sortByAZ(ss);
    let cy=baseY+VH+VP;
    let lastAZ=null;
    sorted.forEach(s=>{
      const az=s.AvailabilityZone||'';
      if(az&&lastAZ!==null&&az!==lastAZ){cy+=AZ_HDR+SG;layouts.push({azLabel:az,x:baseX+VP,y:cy-AZ_HDR-SG/2,w:sw})}
      else if(az&&lastAZ===null&&sorted.filter(x=>x.AvailabilityZone).length>1){layouts.push({azLabel:az,x:baseX+VP,y:cy-2,w:sw});cy+=AZ_HDR}
      lastAZ=az;
      const sh=subHeight(s.SubnetId);
      layouts.push({sub:s,x:baseX+VP,y:cy,w:sw,h:sh,pub:pubSubs.has(s.SubnetId)});
      cy+=sh+SG;
    });
    return layouts;
  }
  
  const REGION_GAP=120;
  let _prevLayoutRegion=null;
  knownVpcs.forEach((vpc,idx)=>{
    const _vpcRegion=getVpcRegion(vpc);
    if(_prevLayoutRegion&&_vpcRegion!==_prevLayoutRegion&&_multiRegion)cx+=REGION_GAP;
    _prevLayoutRegion=_vpcRegion;
    const ss=subByVnet[vpc.VpcId]||[];
    const sw=vSW[vpc.VpcId]||MSW;
    const vw=sw+VP*2,vh=calcVpcHeight(ss);
    const routingGws=(pvGws[vpc.VpcId]||[]);
    let maxGwNameW=0;
    routingGws.forEach(gw=>{
      const nm=gwNames[gw.id]||sid(gw.id);
      maxGwNameW=Math.max(maxGwNameW,nm.length*6+40);
    });
    const chanW=Math.max(GC_BASE,routingGws.length*55+50,maxGwNameW+60);
    const isLast=idx===knownVpcs.length-1&&knownVpcs.length>1;
    const gwSide=isLast?'left':'right';

    if(isLast){
      // Last VPC: put channel to the LEFT (gateways between this and previous VPC)
      vL.push({vpc,x:cx+chanW,y:80,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,cx+chanW,80,sw)
      });
      cx+=chanW+vw;
    }else{
      vL.push({vpc,x:cx,y:80,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,cx,80,sw)
      });
      cx+=vw+chanW;
    }
  });
  
  // Calculate row 2 Y position for unknown VPCs (below all known VPCs + shared gateways area)
  const maxKnownH=vL.length>0?Math.max(...vL.map(v=>v.h)):0;
  const unknownRowY=80+maxKnownH+320;
  let ux=60;
  
  unknownVpcs.forEach((vpc,idx)=>{
    const ss=subByVnet[vpc.VpcId]||[];
    const sw=vSW[vpc.VpcId]||MSW;
    const vw=sw+VP*2,vh=calcVpcHeight(ss);
    const routingGws=(pvGws[vpc.VpcId]||[]);
    let maxGwNameW=0;
    routingGws.forEach(gw=>{
      const nm=gwNames[gw.id]||sid(gw.id);
      maxGwNameW=Math.max(maxGwNameW,nm.length*6+40);
    });
    const chanW=Math.max(GC_BASE,routingGws.length*55+50,maxGwNameW+60);
    const isLast=idx===unknownVpcs.length-1&&unknownVpcs.length>1;
    const gwSide=isLast?'left':'right';

    if(isLast){
      vL.push({vpc,x:ux+chanW,y:unknownRowY,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,ux+chanW,unknownRowY,sw)
      });
      ux+=chanW+vw;
    }else{
      vL.push({vpc,x:ux,y:unknownRowY,w:vw,h:vh,sw,chanW,gwSide,
        subs:buildSubLayouts(ss,ux,unknownRowY,sw)
      });
      ux+=vw+chanW;
    }
  });

  const W=_getMain().clientWidth,H=_getMain().clientHeight;

  // Center known VPCs (row 1)
  const knownVL=vL.filter(v=>getVpcRegion(v.vpc)!=='unknown');
  const unknownVL=vL.filter(v=>getVpcRegion(v.vpc)==='unknown');
  
  if(knownVL.length>0){
    const knownWidth=cx-60-GC_BASE;
    const offX=Math.max(0,(W-knownWidth)/2-60);
    knownVL.forEach(v=>{v.x+=offX;v.subs.forEach(s=>s.x+=offX)});
  }
  
  // Center unknown VPCs (row 2) independently
  if(unknownVL.length>0){
    const unknownWidth=ux-60-GC_BASE;
    const offX2=Math.max(0,(W-unknownWidth)/2-60);
    unknownVL.forEach(v=>{v.x+=offX2;v.subs.forEach(s=>s.x+=offX2)});
  }

  // Pre-pass: determine which subnets connect to each per-VPC gateway
  // This lets us position gateways near their connected subnets instead of at VPC bottom
  // Uses subRT (which includes Main route table fallback) for complete coverage
  const gwSubnetYs=new Map(); // gwId -> [subnet Y midpoints]
  const preAllS=vL.flatMap(v=>v.subs).filter(sl=>sl.sub);
  preAllS.forEach(sl=>{
    const rt=subRT[sl.sub.SubnetId];if(!rt)return;
    (rt.Routes||[]).forEach(r=>{
      if(r.GatewayId==='local')return;
      const tid=r.GatewayId||r.NatGatewayId||r.TransitGatewayId||r.VpcPeeringConnectionId;
      if(!tid||vpceIds.has(tid))return;
      if(!gwSubnetYs.has(tid))gwSubnetYs.set(tid,[]);
      gwSubnetYs.get(tid).push(sl.y+sl.h/2);
    });
  });

  // per-VPC gateways positioned near connected subnet centroid
  const gwP=new Map();
  const gwOrder={IGW:0,NAT:1,VGW:2,EIGW:3,LGW:4};
  vL.forEach(vl=>{
    const gs=[...(pvGws[vl.vpc.VpcId]||[])].sort((a,b)=>{const oa=gwOrder[a.type]??9,ob=gwOrder[b.type]??9;return oa-ob;});
    const gwOff=Math.max(60,Math.min(vl.chanW*0.7,120));
    const gx=vl.gwSide==='left'?(vl.x-gwOff):(vl.x+vl.w+gwOff);
    const minGap=GR*2+40; // minimum vertical gap between gateway circles (room for label + line clearance)

    // Compute ideal Y for each gateway at centroid of its connected subnets
    const gwYs=gs.map(gw=>{
      const subYs=gwSubnetYs.get(gw.id);
      if(subYs&&subYs.length>0){
        const avgY=subYs.reduce((a,b)=>a+b,0)/subYs.length;
        let gy=avgY;
        gy=Math.min(gy, vl.y+vl.h-GR-10);
        gy=Math.max(gy, vl.y+GR+20);
        return {gw,gy};
      }
      return {gw,gy:vl.y+vl.h-GR-10}; // fallback: near bottom
    });

    // Resolve overlaps: push later gateways down if too close
    for(let i=1;i<gwYs.length;i++){
      if(gwYs[i].gy-gwYs[i-1].gy<minGap){
        gwYs[i].gy=gwYs[i-1].gy+minGap;
      }
    }
    // Final clamp: distribute evenly within VPC bounds if gateways overflow
    const totalNeeded=(gwYs.length-1)*minGap;
    const vpcAvailable=vl.h-GR-10-(GR+20);
    if(totalNeeded>vpcAvailable&&gwYs.length>1){
      // Not enough room: distribute evenly within available space
      const evenGap=vpcAvailable/(gwYs.length-1);
      gwYs.forEach((g,i)=>{g.gy=vl.y+GR+20+i*evenGap});
    }else{
      gwYs.forEach(g=>{
        g.gy=Math.min(g.gy, vl.y+vl.h-GR-10);
        g.gy=Math.max(g.gy, vl.y+GR+20);
      });
    }

    gwYs.forEach(({gw,gy})=>gwP.set(gw.id,{x:gx,y:gy,gw}));
  });

  // shared gateways below KNOWN VPCs only (not disconnected)
  const knownVpcBot=knownVL.length>0?Math.max(...knownVL.map(v=>v.y+v.h)):80;
  const lE=knownVL[0]?.x||0,rE=knownVL.length?knownVL[knownVL.length-1].x+knownVL[knownVL.length-1].w:W;
  const sCX=(lE+rE)/2,sY=knownVpcBot+80;
  const ssX=sCX-((shGws.length-1)*80)/2;
  shGws.forEach((gw,i)=>{gwP.set(gw.id,{x:ssX+i*80,y:sY,gw})});
  
  // Track the lowest Y used by routing elements (gateways, bus lanes, peering)
  let routingBottomY=shGws.length>0?(sY+GR+20):(knownVpcBot+20);

  // Disconnected VPCs will be repositioned after all routing is computed

  // internet node positioned far left, anchoring the NET bus bar
  // Only IGWs connect to NET bus bar; NATs have their own subnet route lines
  const iGwList=[...gwP.values()].filter(p=>p.gw.type==='IGW');
  const allVpcRight=Math.max(...vL.map(v=>v.gwSide==='left'?(v.x+v.w):(v.x+v.w+v.chanW)));
  const allVpcLeft=Math.min(...vL.map(v=>v.x));
  const allVpcTop=Math.min(...vL.map(v=>v.y));
  const allVpcBottom=Math.max(...vL.map(v=>v.y+v.h));
  // Position NET node left of all VPCs
  const iX=allVpcLeft-80;
  const iY=allVpcTop-100;

  const allS=vL.flatMap(v=>v.subs).filter(sl=>sl.sub);

  // trunk groups -- iterate subnets using subRT (includes Main route table fallback)
  const tG={};
  allS.forEach(sl=>{
    const rt=subRT[sl.sub.SubnetId];if(!rt)return;
    const ov=vL.find(v=>v.subs.includes(sl));if(!ov)return;
    (rt.Routes||[]).forEach(r=>{
      if(r.GatewayId==='local')return;
      const tid=r.GatewayId||r.NatGatewayId||r.TransitGatewayId||r.VpcPeeringConnectionId;
      if(!tid||!gwP.has(tid)||vpceIds.has(tid))return;
      const k=tid+'|'+ov.vpc.VpcId;
      (tG[k]=tG[k]||[]).push({sl,sid:sl.sub.SubnetId,dst:r.DestinationCidrBlock||r.DestinationPrefixListId||'?',gid:tid,vid:ov.vpc.VpcId});
    });
  });


  return {
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
    routingBottomY,
    iGwList,
    allVpcRight,
    iX,
    iY,
    allS,
    tG,
    gwP
  };
}
// #endregion TOPOLOGY GRID GEOMETRY
