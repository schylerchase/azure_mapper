// #region TOPOLOGY LANDING ZONE RESOURCE SECTIONS
function drawLandingZoneResourceSections(ctx){
  const {
    ndL,
    vL,
    vpceByVpc,
    vpces,
    gwNames,
    tt,
    zones,
    lzRecsByZone,
    vpcs,
    maxY,
    s3bk,
    storageTopology,
    cfDistributions
  } = ctx;

  vL.forEach(vl=>{
    const vpcVpces=vpceByVpc[vl.vpc.VpcId]||[];
    if(!vpcVpces.length)return;
    const nw=70,nh=16;
    const gx=vl.x+nw/2+8;
    const ny=vl.y+vl.h-nh-8;
    const eG=ndL.append('g').attr('class','vpce-summary').style('cursor','pointer');
    eG.append('rect').attr('x',gx-nw/2).attr('y',ny).attr('width',nw).attr('height',nh).attr('rx',3)
      .attr('fill','rgba(167,139,250,.2)').attr('stroke','var(--vpce-color)').attr('stroke-width',1);
    eG.append('text').attr('x',gx).attr('y',ny+12).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600').attr('fill','var(--vpce-color)').text(vpcVpces.length+' VPCE');
    eG.on('mouseenter',function(){
      let h='<div class="tt-title">VPC Endpoints ('+vpcVpces.length+')</div>';
      h+='<div class="tt-sub">'+gn(vl.vpc,vl.vpc.VpcId)+'</div>';
      h+='<div class="tt-sec"><div class="tt-sh">Endpoints</div>';
      vpcVpces.forEach(v=>{
        const vi=vpces.find(x=>x.VpcEndpointId===v.id);
        const svc=vi?.ServiceName||'?';
        const nm=gwNames[v.id];
        h+='<div class="tt-r"><span class="i">'+esc(nm||v.id.slice(-8))+'</span> '+esc(svc.split('.').pop())+' ['+esc(vi?.VpcEndpointType)+']</div>';
      });
      h+='</div>';
      tt.innerHTML=h;tt.style.display='block';
    }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
    .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('Endpoints')});
  });

  if(zones.length>0){
    const privZonesByVpc={};
    zones.forEach(z=>{
      if(z.Config?.PrivateZone&&z.VPCs){
        z.VPCs.forEach(v=>{
          const vid=v.VPCId||v.VpcId;
          if(vid)(privZonesByVpc[vid]=privZonesByVpc[vid]||[]).push(z);
        });
      }
    });
    vL.forEach(vl=>{
      const pz=privZonesByVpc[vl.vpc.VpcId];
      if(!pz||!pz.length)return;
      if(!vl.w||vl.w<50||!vl.h||vl.h<50)return;
      const nw=70,nh=16;
      const gx=vl.x+vl.w-nw/2-8;
      const ny=vl.y+vl.h-nh-8;
      const dG=ndL.append('g').attr('class','dns-summary').style('cursor','pointer');
      dG.append('rect').attr('x',gx-nw/2).attr('y',ny).attr('width',nw).attr('height',nh).attr('rx',3)
        .attr('fill','rgba(14,165,233,.15)').attr('stroke','#0ea5e9').attr('stroke-width',1);
      dG.append('text').attr('x',gx).attr('y',ny+12).attr('text-anchor','middle').attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600').attr('fill','#0ea5e9').text(pz.length+' DNS');
      dG.on('mouseenter',function(){
        let h='<div class="tt-title">Private Hosted Zones ('+pz.length+')</div>';
        h+='<div class="tt-sub">'+gn(vl.vpc,vl.vpc.VpcId)+'</div>';
        h+='<div class="tt-sec"><div class="tt-sh">Zones</div>';
        pz.forEach(z=>{
          const zid=z.Id.replace('/hostedzone/','');
          h+='<div class="tt-r"><span class="i">'+z.Name+'</span> '+z.ResourceRecordSetCount+' records ['+zid+']</div>';
        });
        h+='</div>';
        tt.innerHTML=h;tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('R53')});
    });
  }

  let lzSectionY=maxY+40;
  const lzAllVpcRight=Math.max(...vL.map(v=>v.x+v.w));
  if(zones.length>0){
    const dnsY=lzSectionY;
    const pubZones=zones.filter(z=>!z.Config?.PrivateZone);
    const privZones=zones.filter(z=>z.Config?.PrivateZone);
    const dnsBoxW=Math.max(320,lzAllVpcRight-40);
    const lzDnsRecExp=_dnsRecordsExpanded;
    const recRowH=14;
    const lzZoneLayouts=[];

    if(lzDnsRecExp){
      const fullW=dnsBoxW-40;
      let cy=0;
      zones.forEach(z=>{
        const zid=z.Id.replace('/hostedzone/','');
        const isPub=!z.Config?.PrivateZone;
        const zRecs=lzRecsByZone[zid]||[];
        const assocVpcs=(!isPub&&z.VPCs)?z.VPCs.map(v=>{
          const vid=v.VPCId||v.VpcId;
          const vpc=vpcs.find(vp=>vp.VpcId===vid);
          return gn(vpc||{},vid);
        }).join(', '):'';
        let metaLines=2;
        if(assocVpcs)metaLines++;
        const headerH=18+metaLines*14+4;
        const recsH=zRecs.length>0?(4+zRecs.length*recRowH):16;
        const zh=headerH+recsH+6;
        lzZoneLayouts.push({x:50,y:cy,w:fullW,h:zh,recs:zRecs,assocVpcs});
        cy+=zh+6;
      });
    }else{
      const dnsColW=(dnsBoxW-60)/2;
      zones.forEach((z,zi)=>{
        const col=zi%2;
        const row=Math.floor(zi/2);
        lzZoneLayouts.push({x:50+col*(dnsColW+10),y:row*32,w:dnsColW-10,h:26,recs:[]});
      });
    }

    const totalContentH=lzDnsRecExp?
      (lzZoneLayouts.length>0?lzZoneLayouts[lzZoneLayouts.length-1].y+lzZoneLayouts[lzZoneLayouts.length-1].h:0):
      (Math.ceil(zones.length/2)*32);
    const dnsBoxH=60+totalContentH+20;
    const dnsG=ndL.append('g').attr('class','dns-section');
    dnsG.append('rect').attr('x',40).attr('y',dnsY).attr('width',dnsBoxW).attr('height',dnsBoxH).attr('rx',8)
      .attr('fill','rgba(14,165,233,.06)').attr('stroke','#0ea5e9').attr('stroke-width',1.5).attr('stroke-dasharray','6 3');
    dnsG.append('text').attr('x',60).attr('y',dnsY+22).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(14px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','#0ea5e9').text('Azure DNS Private Zones');
    dnsG.append('text').attr('x',60).attr('y',dnsY+36).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(pubZones.length+' public, '+privZones.length+' private');

    const lzTogX=40+dnsBoxW-80;
    const lzTogY=dnsY+8;
    const lzTogG=dnsG.append('g').style('cursor','pointer');
    lzTogG.append('rect').attr('x',lzTogX).attr('y',lzTogY).attr('width',70).attr('height',20).attr('rx',4)
      .attr('fill','rgba(14,165,233,.15)').attr('stroke','#0ea5e9').attr('stroke-width',0.8);
    lzTogG.append('text').attr('x',lzTogX+35).attr('y',lzTogY+14).attr('text-anchor','middle')
      .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(8px * var(--txt-scale,1))').attr('font-weight','600')
      .attr('fill','#0ea5e9').text(lzDnsRecExp?'\u25B2 Collapse':'\u25BC Expand');
    lzTogG.on('click',function(event){
      event.stopPropagation();
      _dnsRecordsExpanded=!_dnsRecordsExpanded;
      renderMap();
    });

    zones.forEach((z,zi)=>{
      const isPub=!z.Config?.PrivateZone;
      const zid=z.Id.replace('/hostedzone/','');
      const lay=lzZoneLayouts[zi];
      const zx=lay.x;
      const zy=dnsY+52+lay.y;
      const zw=lay.w;
      const zh=lay.h;
      const zG=dnsG.append('g').style('cursor','pointer');
      zG.append('rect').attr('x',zx).attr('y',zy).attr('width',zw).attr('height',zh).attr('rx',4)
        .attr('fill',isPub?'rgba(16,185,129,.18)':'rgba(14,165,233,.18)')
        .attr('stroke',isPub?'#10b981':'#0ea5e9').attr('stroke-width',1.5);
      zG.append('circle').attr('cx',zx+12).attr('cy',zy+13).attr('r',6).attr('fill',isPub?'#10b981':'#0ea5e9');
      zG.append('text').attr('x',zx+12).attr('y',zy+16.5).attr('text-anchor','middle')
        .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','700')
        .attr('fill','#fff').text(isPub?'P':'R');

      const recLabel=z.ResourceRecordSetCount+' records';
      const maxNameLen=lzDnsRecExp?999:Math.max(12,Math.floor((zw-80)/6));
      const dispName=lzDnsRecExp?z.Name:(z.Name.length>maxNameLen?z.Name.substring(0,maxNameLen-2)+'..':z.Name);
      zG.append('text').attr('x',zx+24).attr('y',zy+15).attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(10px * var(--txt-scale,1))').attr('font-weight','600').attr('fill',isPub?'#10b981':'#0ea5e9')
        .text(dispName);

      if(!lzDnsRecExp){
        zG.append('text').attr('x',zx+zw-8).attr('y',zy+15).attr('text-anchor','end')
          .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(9px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
          .text(recLabel);
      }

      if(lzDnsRecExp){
        let my=zy+18;
        zG.append('text').attr('x',zx+24).attr('y',my+14).attr('font-family','Segoe UI,system-ui,sans-serif')
          .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
          .text('Zone ID: '+zid+'  |  '+z.ResourceRecordSetCount+' records  |  '+(isPub?'Public':'Private'));
        my+=14;
        if(lay.assocVpcs){
          zG.append('text').attr('x',zx+24).attr('y',my+14).attr('font-family','Segoe UI,system-ui,sans-serif')
            .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
            .text('VPCs: '+lay.assocVpcs);
          my+=14;
        }
        if(lay.recs.length>0){
          my+=4;
          zG.append('line').attr('x1',zx+8).attr('y1',my).attr('x2',zx+zw-8).attr('y2',my)
            .attr('stroke',isPub?'#10b981':'#0ea5e9').attr('stroke-width',0.5).attr('stroke-opacity',0.4);
          my+=4;
          lay.recs.forEach(rec=>{
            const rName=(rec.Name||'').replace(/\.$/,'');
            const rType=rec.Type||'';
            const rVal=rec.AliasTarget?'ALIAS \u2192 '+(rec.AliasTarget.DNSName||'').replace(/\.$/,''):
              (rec.ResourceRecords||[]).map(rr=>rr.Value).join(', ');
            zG.append('text').attr('x',zx+10).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
              .style('font-size','calc(7px * var(--txt-scale,1))').attr('font-weight','600').attr('fill',isPub?'#059669':'#0284c7')
              .text(rType);
            zG.append('text').attr('x',zx+50).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
              .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-primary)')
              .text(rName.length>50?rName.substring(0,48)+'..':rName);
            zG.append('text').attr('x',zx+350).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
              .style('font-size','calc(7px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
              .text(rVal.length>80?rVal.substring(0,78)+'..':rVal);
            my+=recRowH;
          });
        }else{
          my+=6;
          zG.append('text').attr('x',zx+24).attr('y',my+10).attr('font-family','Segoe UI,system-ui,sans-serif')
            .style('font-size','calc(8px * var(--txt-scale,1))').attr('font-style','italic').attr('fill','var(--text-muted)')
            .text('Click zone for details \u2022 Load record sets via "Record Sets" input');
        }
      }

      zG.on('mouseenter',function(){
        let h='<div class="tt-title">'+(isPub?'Public':'Private')+' Hosted Zone</div>';
        h+='<div class="tt-sub">'+esc(z.Name)+'</div>';
        h+='<div class="tt-sec">';
        h+='<div class="tt-r"><span class="i">Zone ID</span> '+esc(zid)+'</div>';
        h+='<div class="tt-r"><span class="i">Records</span> '+z.ResourceRecordSetCount+'</div>';
        if(!isPub&&z.VPCs){
          h+='<div class="tt-sh" style="margin-top:4px">Associated VPCs</div>';
          z.VPCs.forEach(v=>{
            const vid=v.VPCId||v.VpcId;
            const vpcObj=vpcs.find(x=>x.VpcId===vid);
            h+='<div class="tt-r"><span class="i">'+(vpcObj?gn(vpcObj,vid):esc(vid))+'</span></div>';
          });
        }
        h+='</div>';
        tt.innerHTML=h;tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('R53')});
    });
    lzSectionY=dnsY+dnsBoxH+30;
  }

  if(s3bk.length>0){
    const s3Y=lzSectionY;
    const s3BoxW=Math.max(320,lzAllVpcRight-40);
    const s3Cols=3;
    const s3ColW=Math.min(320,(s3BoxW-40)/s3Cols);
    const s3RowH=58;
    const s3Rows=Math.ceil(s3bk.length/s3Cols);
    const s3BoxH=50+s3Rows*(s3RowH+4)+20;
    const storageInfos=s3bk.map(bk=>({bk,info:_storageInfo(bk,storageTopology)}));
    const privateCount=storageInfos.filter(x=>x.info.hasPe||x.info.hasRules).length;
    const publicCount=storageInfos.filter(x=>x.info.severity==='risk'||x.info.severity==='open').length;
    const s3G=ndL.append('g').attr('class','s3-section');
    s3G.append('rect').attr('x',40).attr('y',s3Y).attr('width',s3BoxW).attr('height',s3BoxH).attr('rx',8)
      .attr('fill','rgba(234,88,12,.06)').attr('stroke','#ea580c').attr('stroke-width',1.5).attr('stroke-dasharray','6 3');
    s3G.append('text').attr('x',60).attr('y',s3Y+22).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(14px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','#ea580c').text('Storage Accounts');
    s3G.append('text').attr('x',60).attr('y',s3Y+36).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)')
      .text(s3bk.length+' accounts \u00b7 '+privateCount+' private/VNet \u00b7 '+publicCount+' public/risk');
    storageInfos.forEach(({bk,info},bi)=>{
      const col=bi%s3Cols;
      const row=Math.floor(bi/s3Cols);
      const bx=50+col*(s3ColW+5);
      const by=s3Y+48+row*(s3RowH+4);
      _drawStorageAccountCard(s3G,bk,info,storageTopology,bx,by,s3ColW-10,s3RowH);
    });
    lzSectionY=s3Y+s3BoxH+30;
  }

  if(cfDistributions.length>0){
    const cfY=lzSectionY;
    const cfBoxW=Math.max(320,lzAllVpcRight-40);
    const cfCols=2;
    const cfColW=Math.min(480,(cfBoxW-40)/cfCols);
    const cfRowH=28;
    const cfRows=Math.ceil(cfDistributions.length/cfCols);
    const cfBoxH=50+cfRows*(cfRowH+4)+20;
    const cfG=ndL.append('g').attr('class','cf-section');
    cfG.append('rect').attr('x',40).attr('y',cfY).attr('width',cfBoxW).attr('height',cfBoxH).attr('rx',8)
      .attr('fill','rgba(139,92,246,.06)').attr('stroke','#8b5cf6').attr('stroke-width',1.5).attr('stroke-dasharray','6 3');
    cfG.append('text').attr('x',60).attr('y',cfY+22).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(14px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','#8b5cf6').text('Front Door / CDN Profiles');
    cfG.append('text').attr('x',60).attr('y',cfY+36).attr('font-family','Segoe UI,system-ui,sans-serif')
      .style('font-size','calc(10px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(cfDistributions.length+' profiles');
    cfDistributions.forEach((d,di)=>{
      const col=di%cfCols;
      const row=Math.floor(di/cfCols);
      const cx=50+col*(cfColW+5);
      const cy=cfY+48+row*(cfRowH+4);
      const aliases=(d.Aliases?.Items||[]);
      const cG=cfG.append('g').style('cursor','pointer');
      cG.append('rect').attr('x',cx).attr('y',cy).attr('width',cfColW-10).attr('height',cfRowH).attr('rx',3)
        .attr('fill','rgba(139,92,246,.12)').attr('stroke','#8b5cf6').attr('stroke-width',0.8);
      cG.append('text').attr('x',cx+6).attr('y',cy+12).attr('font-family','Segoe UI,system-ui,sans-serif')
        .style('font-size','calc(9px * var(--txt-scale,1))').attr('font-weight','600').attr('fill','#8b5cf6').text(d.DomainName||d.Id);
      if(aliases.length){
        cG.append('text').attr('x',cx+6).attr('y',cy+23).attr('font-family','Segoe UI,system-ui,sans-serif')
          .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-muted)').text(aliases.join(', '));
      }
      cG.on('mouseenter',function(){
        let h='<div class="tt-title">Front Door Profile</div>';
        h+='<div class="tt-sub">'+esc(d.DomainName||d.Id)+'</div>';
        h+='<div class="tt-sec">';
        h+='<div class="tt-r"><span class="i">ID</span> '+esc(d.Id)+'</div>';
        h+='<div class="tt-r"><span class="i">Status</span> '+esc(d.Status||'?')+'</div>';
        if(aliases.length)h+='<div class="tt-r"><span class="i">Aliases</span> '+esc(aliases.join(', '))+'</div>';
        const origins=(d.Origins?.Items||[]);
        if(origins.length){
          h+='<div class="tt-sh" style="margin-top:4px">Origins</div>';
          origins.forEach(o=>{h+='<div class="tt-r"><span class="i">'+esc(o.Id||'')+'</span> '+esc(o.DomainName)+'</div>'});
        }
        if(d.WebACLId)h+='<div class="tt-r"><span class="i">WAF</span> '+esc(d.WebACLId.split('/').pop())+'</div>';
        h+='</div>';
        tt.innerHTML=h;tt.style.display='block';
      }).on('mousemove',function(event){positionTooltip(event,tt)}).on('mouseleave',()=>{tt.style.display='none'})
      .on('click',function(event){event.stopPropagation();tt.style.display='none';_lastRlType=null;_navStack=[];openResourceList('CF')});
    });
    lzSectionY=cfY+cfBoxH+30;
  }

  return {lzSectionY};
}
// #endregion TOPOLOGY LANDING ZONE RESOURCE SECTIONS
