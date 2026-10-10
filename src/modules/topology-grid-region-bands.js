// #region TOPOLOGY GRID REGION BANDS
function drawTopologyGridRegionBands(ctx){
  const {
    ndL,
    vL,
    knownVL,
    unknownVL,
    subByVnet,
    _multiRegion
  } = ctx;

  const vpcRegionMap={};
  vL.forEach(vl=>{
    const ss=subByVnet[vl.vpc.VpcId]||[];
    const region=vl.vpc._region||ss.find(s=>s._region)?._region||'unknown';
    vpcRegionMap[vl.vpc.VpcId]=region;
  });

  const regionGroups=[];
  let prevRegion='',regionVpcs=[];
  knownVL.forEach((vl,i)=>{
    const region=vpcRegionMap[vl.vpc.VpcId];
    if(region!==prevRegion&&prevRegion&&regionVpcs.length){
      regionGroups.push({region:prevRegion,vpcs:[...regionVpcs]});
      regionVpcs=[];
    }
    regionVpcs.push(vl);
    prevRegion=region;
    if(i===knownVL.length-1&&regionVpcs.length){
      regionGroups.push({region,vpcs:[...regionVpcs]});
    }
  });

  if(unknownVL.length>0){
    regionGroups.push({region:'DISCONNECTED',vpcs:unknownVL});
  }

  regionGroups.forEach(regionGroup=>{
    const first=regionGroup.vpcs[0];
    const last=regionGroup.vpcs[regionGroup.vpcs.length-1];
    const ry=first.y-30;
    const lastRight=last.gwSide==='left'?(last.x+last.w):(last.x+last.w+last.chanW);
    const rx=first.x-10;
    const rw=lastRight-first.x+20;
    const rh=Math.max(...regionGroup.vpcs.map(v=>v.h))+50;
    const isDisconnected=regionGroup.region==='DISCONNECTED';
    const isMultiRegion=_multiRegion&&!isDisconnected;

    ndL.append('rect').attr('class','region-boundary').attr('x',rx).attr('y',ry).attr('width',rw).attr('height',rh)
      .attr('fill',isDisconnected?'rgba(239,68,68,.06)':isMultiRegion?'rgba(59,130,246,.08)':'rgba(59,130,246,.06)')
      .attr('stroke',isDisconnected?'rgba(239,68,68,.3)':isMultiRegion?'rgba(59,130,246,.25)':'rgba(59,130,246,.15)')
      .attr('stroke-width',isMultiRegion?1.5:1)
      .attr('stroke-dasharray',isDisconnected?'4 2':'none')
      .attr('rx',12);

    if(isMultiRegion){
      const labelText=regionGroup.region+' ('+regionGroup.vpcs.length+' VPC'+(regionGroup.vpcs.length>1?'s':'')+')';
      const pillW=labelText.length*6.5+16;
      const pillX=rx+rw/2-pillW/2;
      const pillY=ry-16;
      ndL.append('rect').attr('x',pillX).attr('y',pillY).attr('width',pillW).attr('height',18)
        .attr('rx',9).attr('fill','rgba(59,130,246,.12)').attr('stroke','rgba(59,130,246,.3)').attr('stroke-width',1);
      ndL.append('text').attr('x',pillX+pillW/2).attr('y',pillY+12.5)
        .attr('text-anchor','middle').attr('fill','#60a5fa')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(9px * var(--txt-scale,1))')
        .attr('font-weight','600').text(labelText);
    }else{
      ndL.append('text').attr('class','region-label')
        .attr('x',rx+10).attr('y',ry-6)
        .attr('fill',isDisconnected?'var(--accent-red)':'var(--text-muted)')
        .text(regionGroup.region);
    }
  });

  return {vpcRegionMap};
}
// #endregion TOPOLOGY GRID REGION BANDS
