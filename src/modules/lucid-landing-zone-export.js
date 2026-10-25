// #region LUCID LANDING ZONE EXPORT
// Landing Zone Hub-Spoke Layout
function buildLandingZoneLayout(ctx){
  // buildLandingZoneLayout
  try{
  const {vpcs,subByVnet,nsgByVnet,pubSubs,rts,instances,albs,enis,nacls,subRT,
    igws,nats,vpceList,peerings,sharedGws,gwByVpc,vpceByVpc,gwSet2L,
    gn,sid,tw,userHubName,COL,gwColors2,gwFills,ICON_MAP,volumes,zones,
    s3bk,snapshots,snapByVol,tgByAlb,tgs,wafAcls,wafByAlb,
    instBySub,albBySub,eniBySub,volByInst,volBySub,rdsBySub,ecsBySub,lambdaBySub,cfByAlb,recsByZone:lzRecsByZone}=ctx;
  const recsByZoneLZ=lzRecsByZone||{};

  const shapes=[],lines=[],iconSet=new Set();
  let lid=0;
  const NOTEXT='<p style="font-size:1pt;color:transparent">&nbsp;</p>';
  const IC=36,VP=50,VH=80,SG=32,SP=24;
  const EC2W=260,EC2H=34,EC2G=16;
  
  function addIcon(type,x,y){
    iconSet.add(type);
    shapes.push({
      id:'icon_'+(lid++),type:'rectangle',
      boundingBox:{x,y,w:IC,h:IC},
      text:NOTEXT,
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'image',ref:(ICON_MAP[type]||type.toLowerCase())+'.png'}}
    });
  }
  
  // Identify hub VPC
  const hubKeywords=['shared','connectivity','hub','transit','network','core'];
  let hubVpc=null;
  if(userHubName){
    hubVpc=vpcs.find(v=>{
      const vn=gn(v,v.VpcId).toLowerCase();
      return vn.includes(userHubName);
    });
  }
  if(!hubVpc){
    hubVpc=vpcs.find(v=>{
      const vn=gn(v,v.VpcId).toLowerCase();
      return hubKeywords.some(k=>vn.includes(k));
    });
  }
  // Fallback: VPC with most TGW/peering connections
  if(!hubVpc){
    let maxConn=0;
    vpcs.forEach(v=>{
      let conn=0;
      rts.filter(rt=>rt.VpcId===v.VpcId).forEach(rt=>{
        (rt.Routes||[]).forEach(r=>{
          if(r.TransitGatewayId||r.VpcPeeringConnectionId)conn++;
        });
      });
      peerings.forEach(p=>{
        if(p.RequesterVpcInfo?.VpcId===v.VpcId||p.AccepterVpcInfo?.VpcId===v.VpcId)conn++;
      });
      if(conn>maxConn){maxConn=conn;hubVpc=v;}
    });
  }
  if(!hubVpc)hubVpc=vpcs[0];
  
  const spokeVpcs=vpcs.filter(v=>v.VpcId!==hubVpc.VpcId);
  const shapeIds={};
  
  // Layout constants
  const HUB_X=100,HUB_Y=120;
  const SPOKE_START_X=900;
  const SPOKE_START_Y=80;
  const SPOKE_COL_W=700;
  const SPOKE_ROW_GAP=40;
  const SPOKES_PER_COL=4;
  const numSpokeCols=Math.max(1,Math.ceil(spokeVpcs.length/SPOKES_PER_COL));
  const EXT_X=SPOKE_START_X+numSpokeCols*SPOKE_COL_W+100;
  
  // Shared resource builder for LZ subnets (mirrors grid logic)
  const LZ_NAME_H=36,LZ_DETAIL_H=28,LZ_CHILD_LINE_H=22,LZ_CHILD_GAP=8,LZ_RES_PAD=10;
  const LZ_CHILD_INNER_W=EC2W-24;
  function lzChildLines(label){return Math.max(1,Math.ceil(tw(label,8)/LZ_CHILD_INNER_W));}
  function lzChildH(label){return lzChildLines(label)*LZ_CHILD_LINE_H+8;}
  function lzResHeight(r){
    const chs=r.children||[];
    let h=LZ_RES_PAD+LZ_NAME_H;
    if(r.detail)h+=LZ_DETAIL_H;
    if(chs.length>0){h+=LZ_CHILD_GAP;chs.forEach(ch=>{const lbl=ch.type+': '+ch.name+(ch.detail?' \u00b7 '+ch.detail:'');h+=lzChildH(lbl)+LZ_CHILD_GAP;});}
    h+=LZ_RES_PAD;
    return Math.max(EC2H,h);
  }
  function lzBuildResources(subId){
    const sInsts=instBySub[subId]||[];
    const sAlbs=albBySub[subId]||[];
    const sRds=(rdsBySub||{})[subId]||[];
    const sEcs=(ecsBySub||{})[subId]||[];
    const sLam=(lambdaBySub||{})[subId]||[];
    const sEni=(eniBySub||{})[subId]||[];
    const attached=new Set();
    const res=[];
    sInsts.forEach(i=>{
      const ch=[];const ie=(enis||[]).filter(e=>e.Attachment&&e.Attachment.InstanceId===i.InstanceId);
      ie.forEach(e=>attached.add(e.NetworkInterfaceId));
      if(_showNested){
        ie.forEach(e=>ch.push({type:'NIC',name:e.NetworkInterfaceId.slice(-8),detail:e.PrivateIpAddress||'',col:'#3b82f6'}));
        ((volByInst||{})[i.InstanceId]||[]).forEach(v=>{const sc=((snapByVol||{})[v.VolumeId]||[]).length;ch.push({type:'VOL',name:v.Size+'GB '+(v.VolumeType||''),detail:sc?sc+' snap':'',col:'#f59e0b'});});
      }
      res.push({type:'VM',name:gn(i,i.InstanceId),id:i.InstanceId,detail:i.InstanceType,children:ch,resCol:'#10b981'});
    });
    sAlbs.forEach(lb=>{
      const ch=[];
      if(_showNested){
        ((tgByAlb||{})[lb.LoadBalancerArn]||[]).forEach(tg=>ch.push({type:'TG',name:tg.TargetGroupName||'TG',detail:(tg.Targets||[]).length+' tgt',col:'#06b6d4'}));
        ((wafByAlb||{})[lb.LoadBalancerArn]||[]).forEach(w=>ch.push({type:'WAF',name:w.Name||'WAF',detail:(w.Rules||[]).length+' rules',col:'#eab308'}));
      }
      res.push({type:'App Gateway',name:lb.LoadBalancerName||'ALB',id:lb.LoadBalancerArn,detail:lb.Scheme||'',children:ch,resCol:'#38bdf8'});
    });
    sRds.forEach(db=>res.push({type:'SQL',name:db.DBInstanceIdentifier||'SQL',id:db.DBInstanceIdentifier,detail:db.Engine||'',children:[],resCol:'#3b82f6'}));
    sEcs.forEach(svc=>res.push({type:'Container',name:svc.serviceName||'Container',id:svc.serviceName,detail:svc.launchType||'',children:[],resCol:'#f97316'}));
    sLam.forEach(fn=>res.push({type:'FN',name:fn.FunctionName||'FuncApp',id:fn.FunctionName,detail:fn.Runtime||'',children:[],resCol:'#a855f7'}));
    sEni.forEach(e=>{if(!attached.has(e.NetworkInterfaceId))res.push({type:'NIC',name:e.NetworkInterfaceId.slice(-8),id:e.NetworkInterfaceId,detail:e.PrivateIpAddress||'',children:[],resCol:'#3b82f6'});});
    // Standalone EBS volumes (instance not in EC2 data, placed via ENI subnet)
    ((volBySub||{})[subId]||[]).forEach(v=>{const sc=((snapByVol||{})[v.VolumeId]||[]).length;const att=(v.Attachments||[])[0];
      res.push({type:'VOL',name:v.Size+'GB '+(v.VolumeType||''),id:v.VolumeId,detail:att?att.InstanceId?.slice(-8)||'':'detached',children:[],resCol:'#f59e0b'});});
    return res;
  }
  function lzSubResHeight(subId,subW){
    const resources=lzBuildResources(subId);
    const cols=Math.max(1,Math.floor((subW-SP*2)/(EC2W+EC2G)));
    const rowCount=Math.ceil(resources.length/cols);
    let totalResH=0;
    for(let row=0;row<rowCount;row++){
      let maxH=EC2H;
      for(let c=0;c<cols;c++){const ri=row*cols+c;if(ri<resources.length){const h=lzResHeight(resources[ri]);if(h>maxH)maxH=h;}}
      totalResH+=maxH+EC2G;
    }
    return resources.length>0?VH+totalResH+SP*2:60;
  }
  function lzRenderResources(resources,sx,sy,subW){
    const cols=Math.max(1,Math.floor((subW-SP*2)/(EC2W+EC2G)));
    const rowCount=Math.ceil(resources.length/cols);
    const rowHeights=[];
    for(let row=0;row<rowCount;row++){
      let maxH=EC2H;
      for(let c=0;c<cols;c++){const ri=row*cols+c;if(ri<resources.length){const h=lzResHeight(resources[ri]);if(h>maxH)maxH=h;}}
      rowHeights.push(maxH);
    }
    const rowYOff=[0];
    for(let i=0;i<rowHeights.length;i++)rowYOff.push(rowYOff[i]+rowHeights[i]+EC2G);
    resources.forEach((r,ri)=>{
      const col=ri%cols,row=Math.floor(ri/cols);
      const rx=sx+SP+col*(EC2W+EC2G);
      const ry=sy+VH+rowYOff[row];
      const rH=lzResHeight(r);
      const rc=r.resCol||'#232F3E';
      const maxResChars=Math.floor((EC2W-20)/8);
      const dispResName=r.name.length>maxResChars?r.name.substring(0,maxResChars-2)+'..':r.name;
      let resHtml='<p style="font-size:9pt;color:'+rc+';font-weight:bold;text-align:left;padding:4px 6px">'+r.type+': '+dispResName+'</p>';
      if(r.detail)resHtml+='<p style="font-size:7pt;color:#6B7280;text-align:left;padding:0 6px">'+r.detail+'</p>';
      (r.children||[]).forEach(ch=>{
        const chLabel=ch.type+': '+ch.name+(ch.detail?' \u00b7 '+ch.detail:'');
        resHtml+='<p style="font-size:8pt;color:'+ch.col+';font-weight:bold;text-align:left;padding:2px 6px;margin:4px 0">\u00a0\u00a0'+chLabel+'</p>';
      });
      shapes.push({id:'res_'+(lid++),type:'rectangle',boundingBox:{x:rx,y:ry,w:EC2W,h:rH},text:resHtml,
        style:{stroke:{color:rc,width:1},fill:{type:'color',color:'#FFFFFF'}},
        customData:[{key:'Type',value:r.type},{key:'Name',value:r.name||''},{key:'ID',value:r.id||''}]
      });
    });
  }

  // Helper to compute VPC height
  function vpcHeight(vpc){
    const ss=subByVnet[vpc.VpcId]||[];
    let h=VH+VP;
    ss.forEach(s=>{
      const subW=500;
      h+=Math.max(60,lzSubResHeight(s.SubnetId,subW))+SG;
    });
    return h;
  }
  
  // Place Hub VNet (larger, center-left)
  const hubSubs=subByVnet[hubVpc.VpcId]||[];
  const hubW=650;
  const hubH=vpcHeight(hubVpc)+100;
  const hubLabel=gn(hubVpc,hubVpc.VpcId)+' (HUB)\n'+hubVpc.CidrBlock;
  const hubId='vpc_hub';
  shapeIds[hubVpc.VpcId]=hubId;
  
  shapes.push({
    id:hubId,type:'roundedRectangleContainer',
    boundingBox:{x:HUB_X,y:HUB_Y,w:hubW,h:hubH},
    text:NOTEXT,
    style:{stroke:{color:'#7C3AED',width:4,style:'dashed'},fill:{type:'color',color:'#F5F3FF'}},
    magnetize:true,
    customData:[{key:'VNet ID',value:hubVpc.VpcId||hubVpc.id},{key:'Name',value:gn(hubVpc,hubVpc.VpcId||hubVpc.id)},{key:'Role',value:'Hub / Connectivity'},{key:'Address Space',value:hubVpc.CidrBlock||((hubVpc.properties&&hubVpc.properties.addressSpace&&hubVpc.properties.addressSpace.addressPrefixes&&hubVpc.properties.addressSpace.addressPrefixes[0])||'')}]
  });
  addIcon('VPC',HUB_X+6,HUB_Y+4);
  
  const hubLabelDisp='HUB: '+gn(hubVpc,hubVpc.VpcId)+' ('+hubVpc.CidrBlock+')';
  shapes.push({
    id:'hublbl',type:'rectangle',
    boundingBox:{x:HUB_X+IC+12,y:HUB_Y+4,w:hubW-IC-24,h:VH-10},
    text:'<p style="font-size:14pt;font-weight:bold;color:#7C3AED;text-align:left;padding:4px 8px">'+hubLabelDisp+'</p>',
    style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
  });
  
  // Hub gateways inside hub VPC
  const hubGws=gwByVpc[hubVpc.VpcId]||[];
  const hubGwBadgeW=hubW-VP*2;
  let gwY=HUB_Y+VH+20;
  hubGws.forEach((gw,i)=>{
    const nm=gwNames[gw.gwMapId]||gwNames[gw.id]||sid(gw.gwMapId||gw.id);
    const gc=gwColors2[gw.type]||'#546E7A';
    const gf=gwFills[gw.type]||'#F5F0FF';
    const gwCD=[{key:'Gateway ID',value:gw.id},{key:'Type',value:gw.type},{key:'Name',value:nm}];
    if(gw.type==='NAT'){
      const natGw=nats.find(n=>n.NatGatewayId===gw.id);
      if(natGw){
        gwCD.push({key:'State',value:natGw.State||''});
        gwCD.push({key:'Connectivity',value:natGw.ConnectivityType||'public'});
        const pubIp=(natGw.NatGatewayAddresses||[])[0]?.PublicIp;
        const privIp=(natGw.NatGatewayAddresses||[])[0]?.PrivateIp;
        if(pubIp)gwCD.push({key:'Public IP',value:pubIp});
        if(privIp)gwCD.push({key:'Private IP',value:privIp});
      }
    }
    if(gw.type==='IGW'){
      const igw=igws.find(g=>g.InternetGatewayId===gw.id);
      if(igw){
        const att=(igw.Attachments||[]).map(a=>a.VpcId).join(', ');
        gwCD.push({key:'Attached VPCs',value:att||'None'});
      }
    }
    shapes.push({
      id:'hubgw_'+i,type:'rectangle',
      boundingBox:{x:HUB_X+VP,y:gwY,w:hubGwBadgeW,h:50},
      text:NOTEXT,
      style:{stroke:{color:gc,width:2},fill:{type:'color',color:gf}},
      customData:gwCD
    });
    addIcon(gw.type,HUB_X+VP+8,gwY+7);
    shapes.push({
      id:'hubgw_lbl_'+i,type:'rectangle',
      boundingBox:{x:HUB_X+VP+50,y:gwY+8,w:hubGwBadgeW-60,h:34},
      text:'<p style="font-size:10pt;font-weight:bold;color:#232F3E;text-align:left">'+gw.type+': '+nm+'</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
    });
    gwY+=60;
  });
  
  // Hub subnets with resources
  let hubSubY=gwY+20;
  const hubSubW=hubW-VP*2;
  hubSubs.forEach(s=>{
    const sName=gn(s,s.SubnetId);
    const isPub=pubSubs.has(s.SubnetId);
    const fc=isPub?COL.pubFont:COL.prvFont;
    const fill=isPub?COL.pubFill:COL.prvFill;
    const stroke=isPub?COL.pubStroke:COL.prvStroke;
    const resources=lzBuildResources(s.SubnetId);
    const subH=Math.max(60,lzSubResHeight(s.SubnetId,hubSubW));
    const rt=subRT[s.SubnetId];
    const nacl=nacls?nacls[s.SubnetId]:null;
    const rtName=rt?gn(rt,rt.RouteTableId):'Main';
    const naclName=nacl?gn(nacl,nacl.NetworkAclId):'Default';
    const sx=HUB_X+VP;
    shapes.push({
      id:'hubsub_'+(lid++),type:'rectangle',
      boundingBox:{x:sx,y:hubSubY,w:hubSubW,h:subH},
      text:NOTEXT,
      style:{stroke:{color:stroke,width:2},fill:{type:'color',color:fill}},
      customData:[
        {key:'Subnet ID',value:s.SubnetId},{key:'Name',value:sName},
        {key:'CIDR',value:s.CidrBlock||''},{key:'AZ',value:s.AvailabilityZone||''},
        {key:'Type',value:isPub?'Public':'Private'},
        {key:'Route Table',value:rtName+(rt?' ('+rt.RouteTableId+')':'')},
        {key:'Subnet NSG',value:naclName+(nacl?' ('+nacl.NetworkAclId+')':'')}
      ]
    });
    addIcon(isPub?'SUB_PUB':'SUB_PRV',sx+6,hubSubY+6);
    const subLabel=sName+' ['+s.CidrBlock+']';
    const maxSubChars=Math.floor((hubSubW-IC-40)/9);
    const dispSubLabel=subLabel.length>maxSubChars?subLabel.substring(0,maxSubChars-2)+'..':subLabel;
    shapes.push({id:'sublbl_'+(lid++),type:'rectangle',
      boundingBox:{x:sx+IC+12,y:hubSubY+6,w:hubSubW-IC-24,h:32},
      text:'<p style="font-size:9pt;font-weight:bold;color:'+fc+';text-align:left;padding:4px 6px">'+dispSubLabel+'</p>',
      style:{stroke:{color:fill,width:0},fill:{type:'color',color:fill}}
    });
    if(resources.length>0) lzRenderResources(resources,sx,hubSubY,hubSubW);
    hubSubY+=subH+SG;
  });
  
  // Place Spoke VNets
  const spokePositions={};
  let spokeY=SPOKE_START_Y;
  let spokeCol=0;
  
  spokeVpcs.forEach((vpc,idx)=>{
    if(idx>0&&idx%SPOKES_PER_COL===0){
      spokeCol++;
      spokeY=SPOKE_START_Y;
    }
    const spokeX=SPOKE_START_X+spokeCol*SPOKE_COL_W;
    const ss=subByVnet[vpc.VpcId]||[];
    const spokeW=550;
    const spokeSubWCalc=spokeW-40;
    let spokeSubsH=0;
    ss.forEach(s2=>{spokeSubsH+=Math.max(45,lzSubResHeight(s2.SubnetId,spokeSubWCalc))+SG;});
    const spokeH=Math.max(200, VH+20+spokeSubsH+40);
    const vpcId='vpc_spoke_'+idx;
    shapeIds[vpc.VpcId]=vpcId;
    spokePositions[vpc.VpcId]={x:spokeX,y:spokeY,w:spokeW,h:spokeH};
    
    shapes.push({
      id:vpcId,type:'roundedRectangleContainer',
      boundingBox:{x:spokeX,y:spokeY,w:spokeW,h:spokeH},
      text:NOTEXT,
      style:{stroke:{color:COL.vpcStroke,width:2,style:'dashed'},fill:{type:'color',color:COL.vpcFill}},
      magnetize:true,
      customData:[{key:'VNet ID',value:vpc.VpcId||vpc.id},{key:'Name',value:gn(vpc,vpc.VpcId||vpc.id)},{key:'Role',value:'Spoke / Workload'},{key:'Address Space',value:vpc.CidrBlock||((vpc.properties&&vpc.properties.addressSpace&&vpc.properties.addressSpace.addressPrefixes&&vpc.properties.addressSpace.addressPrefixes[0])||'')}]
    });
    addIcon('VPC',spokeX+6,spokeY+4);
    
    const spokeLbl=gn(vpc,vpc.VpcId)+' ('+vpc.CidrBlock+')';
    const maxChars=Math.floor((spokeW-IC-40)/9);
    const dispLbl=spokeLbl.length>maxChars?spokeLbl.substring(0,maxChars-2)+'..':spokeLbl;
    shapes.push({
      id:'spokelbl_'+idx,type:'rectangle',
      boundingBox:{x:spokeX+IC+12,y:spokeY+4,w:spokeW-IC-24,h:VH-10},
      text:'<p style="font-size:12pt;font-weight:bold;color:'+COL.vpcFont+';text-align:left;padding:4px 8px">'+dispLbl+'</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
    });
    
    // Spoke subnets - all of them
    let subY=spokeY+VH+10;
    const spokeSubW=spokeW-40;
    ss.forEach(s=>{
      const sName=gn(s,s.SubnetId);
      const isPub=pubSubs.has(s.SubnetId);
      const fc=isPub?COL.pubFont:COL.prvFont;
      const fill=isPub?COL.pubFill:COL.prvFill;
      const stroke=isPub?COL.pubStroke:COL.prvStroke;
      const rt=subRT[s.SubnetId];
      const nacl=nacls?nacls[s.SubnetId]:null;
      const rtName=rt?gn(rt,rt.RouteTableId):'Main';
      const naclName=nacl?gn(nacl,nacl.NetworkAclId):'Default';
      const resources=lzBuildResources(s.SubnetId);
      const subH=Math.max(45,lzSubResHeight(s.SubnetId,spokeSubW));
      const sx=spokeX+20;
      shapes.push({
        id:'spokesub_'+(lid++),type:'rectangle',
        boundingBox:{x:sx,y:subY,w:spokeSubW,h:subH},
        text:NOTEXT,
        style:{stroke:{color:stroke,width:1.5},fill:{type:'color',color:fill}},
        customData:[
          {key:'Subnet ID',value:s.SubnetId},{key:'Name',value:sName},
          {key:'CIDR',value:s.CidrBlock||''},{key:'AZ',value:s.AvailabilityZone||''},
          {key:'Type',value:isPub?'Public':'Private'},
          {key:'Route Table',value:rtName+(rt?' ('+rt.RouteTableId+')':'')},
          {key:'Subnet NSG',value:naclName+(nacl?' ('+nacl.NetworkAclId+')':'')}
        ]
      });
      addIcon(isPub?'SUB_PUB':'SUB_PRV',sx+6,subY+6);
      const spokeSubLabel=sName+' ['+s.CidrBlock+']';
      const maxSpokeChars=Math.floor((spokeSubW-IC-40)/8);
      const dispSpokeLabel=spokeSubLabel.length>maxSpokeChars?spokeSubLabel.substring(0,maxSpokeChars-2)+'..':spokeSubLabel;
      shapes.push({id:'sublbl_'+(lid++),type:'rectangle',
        boundingBox:{x:sx+IC+12,y:subY+6,w:spokeSubW-IC-24,h:32},
        text:'<p style="font-size:8pt;font-weight:bold;color:'+fc+';text-align:left;padding:4px 6px">'+dispSpokeLabel+'</p>',
        style:{stroke:{color:fill,width:0},fill:{type:'color',color:fill}}
      });
      if(resources.length>0) lzRenderResources(resources,sx,subY,spokeSubW);
      subY+=subH+SG;
    });
    
    spokeY+=spokeH+SPOKE_ROW_GAP;
  });
  
  // External Connectivity Zone - wider with more room
  const extY=HUB_Y;
  const extW=340;
  shapes.push({
    id:'ext_zone',type:'rectangle',
    boundingBox:{x:EXT_X,y:extY,w:extW,h:400},
    text:NOTEXT,
    style:{stroke:{color:'#64748B',width:2,style:'dashed'},fill:{type:'color',color:'#F8FAFC'}}
  });
  shapes.push({
    id:'ext_title',type:'rectangle',
    boundingBox:{x:EXT_X+10,y:extY+10,w:extW-20,h:30},
    text:'<p style="font-size:11pt;font-weight:bold;color:#334155;text-align:center">External Connectivity</p>',
    style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
  });
  
  // Internet node
  shapes.push({
    id:'inet',type:'rectangle',
    boundingBox:{x:EXT_X+30,y:extY+60,w:extW-60,h:60},
    text:NOTEXT,
    style:{stroke:{color:'#232F3E',width:2},fill:{type:'color',color:'#E2E8F0'}},
    customData:[{key:'Type',value:'Internet Gateway / Public Access'},{key:'Description',value:'External internet connectivity'}]
  });
  addIcon('INET',EXT_X+38,extY+72);
  shapes.push({
    id:'inet_lbl',type:'rectangle',
    boundingBox:{x:EXT_X+80,y:extY+72,w:extW-120,h:36},
    text:'<p style="font-size:11pt;font-weight:bold;color:#232F3E;text-align:left">Internet</p>',
    style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
  });
  
  // On-premises / VPN
  if(sharedGws.some(g=>g.type==='VGW')||gwSet2L.has('vgw')){
    shapes.push({
      id:'onprem',type:'rectangle',
      boundingBox:{x:EXT_X+30,y:extY+140,w:extW-60,h:60},
      text:NOTEXT,
      style:{stroke:{color:'#7C3AED',width:2},fill:{type:'color',color:'#F5F3FF'}},
      customData:[{key:'Type',value:'Virtual Private Gateway / VPN'},{key:'Description',value:'On-premises connectivity'}]
    });
    addIcon('VGW',EXT_X+38,extY+152);
    shapes.push({
      id:'onprem_lbl',type:'rectangle',
      boundingBox:{x:EXT_X+80,y:extY+152,w:extW-120,h:36},
      text:'<p style="font-size:11pt;font-weight:bold;color:#7C3AED;text-align:left">On-Premises / VPN</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
    });
  }
  
  // Transit Gateway (shared)
  const tgwGws=sharedGws.filter(g=>g.type==='TGW');
  if(tgwGws.length>0){
    shapes.push({
      id:'tgw_shared',type:'rectangle',
      boundingBox:{x:EXT_X+30,y:extY+220,w:extW-60,h:60},
      text:NOTEXT,
      style:{stroke:{color:'#EC4899',width:2},fill:{type:'color',color:'#FDF2F8'}},
      customData:[{key:'Type',value:'Transit Gateway'},{key:'TGW IDs',value:tgwGws.map(g=>g.id).join(', ')}]
    });
    addIcon('TGW',EXT_X+38,extY+232);
    shapes.push({
      id:'tgw_shared_lbl',type:'rectangle',
      boundingBox:{x:EXT_X+80,y:extY+232,w:extW-120,h:36},
      text:'<p style="font-size:11pt;font-weight:bold;color:#EC4899;text-align:left">Transit Gateway</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
    });
  }
  
  // Hub to External lines - route above all spokes using straight segments
  const routeAboveY=Math.min(HUB_Y,SPOKE_START_Y)-60;
  const extMidX=EXT_X+extW/2;
  
  // Hub -> Internet: up from hub top, across above spokes, down to ext zone top border
  const hubHasInternet=(subByVnet[hubVpc.VpcId]||[]).some(subnet=>pubSubs.has(subnet.SubnetId));
  if(hubHasInternet){
  lines.push({
    id:'hub_inet_1',lineType:'straight',
    stroke:{color:'#10B981',width:3},
    endpoint1:{type:'shapeEndpoint',style:'none',shapeId:hubId,position:{x:0.8,y:0}},
    endpoint2:{type:'positionEndpoint',style:'none',position:{x:HUB_X+hubW*0.8,y:routeAboveY}}
  });
  lines.push({
    id:'hub_inet_2',lineType:'straight',
    stroke:{color:'#10B981',width:3},
    endpoint1:{type:'positionEndpoint',style:'none',position:{x:HUB_X+hubW*0.8,y:routeAboveY}},
    endpoint2:{type:'positionEndpoint',style:'none',position:{x:extMidX,y:routeAboveY}}
  });
  lines.push({
    id:'hub_inet_3',lineType:'straight',
    stroke:{color:'#10B981',width:3},
    endpoint1:{type:'positionEndpoint',style:'none',position:{x:extMidX,y:routeAboveY}},
    endpoint2:{type:'shapeEndpoint',style:'arrow',shapeId:'inet',position:{x:0.5,y:0}}
  });
  }
  
  // Hub -> TGW connection (if TGW exists) - route above spokes
  const hubTgwIds=new Set(rts.filter(rt=>rt.VpcId===hubVpc.VpcId).flatMap(rt=>(rt.Routes||[]).map(route=>route.TransitGatewayId).filter(Boolean)));
  if(tgwGws.some(gateway=>hubTgwIds.has(gateway.id))){
    const tgwRouteY=routeAboveY-30;
    lines.push({
      id:'hub_tgw_1',lineType:'straight',
      stroke:{color:'#EC4899',width:2},
      endpoint1:{type:'shapeEndpoint',style:'none',shapeId:hubId,position:{x:0.6,y:0}},
      endpoint2:{type:'positionEndpoint',style:'none',position:{x:HUB_X+hubW*0.6,y:tgwRouteY}}
    });
    lines.push({
      id:'hub_tgw_2',lineType:'straight',
      stroke:{color:'#EC4899',width:2},
      endpoint1:{type:'positionEndpoint',style:'none',position:{x:HUB_X+hubW*0.6,y:tgwRouteY}},
      endpoint2:{type:'positionEndpoint',style:'none',position:{x:EXT_X+extW/2,y:tgwRouteY}}
    });
    lines.push({
      id:'hub_tgw_3',lineType:'straight',
      stroke:{color:'#EC4899',width:2},
      endpoint1:{type:'positionEndpoint',style:'none',position:{x:EXT_X+extW/2,y:tgwRouteY}},
      endpoint2:{type:'shapeEndpoint',style:'arrow',shapeId:'tgw_shared',position:{x:0.5,y:0}}
    });
  }
  
  // Hub -> Spokes (peering) and TGW -> Spokes (TGW routes)
  spokeVpcs.forEach((vpc,idx)=>{
    const sp=spokePositions[vpc.VpcId];
    if(!sp)return;
    
    // Check connection type
    let connType=null;
    let connColor='#FB923C';
    const idEquals=(a,b)=>String(a||'').toLowerCase()===String(b||'').toLowerCase();
    const hasHubPeering=peerings.some(peering=>{
      const props=peering.properties||peering;
      const state=props.peeringState||peering.Status?.Code;
      if(state&& !['connected','active'].includes(String(state).toLowerCase()))return false;
      const local=peering.RequesterVpcInfo?.VpcId||peering.localVirtualNetwork?.id||(peering.id||'').split('/virtualNetworkPeerings/')[0];
      const remote=peering.AccepterVpcInfo?.VpcId||props.remoteVirtualNetwork?.id;
      return (idEquals(local,hubVpc.VpcId)&&idEquals(remote,vpc.VpcId))||(idEquals(remote,hubVpc.VpcId)&&idEquals(local,vpc.VpcId));
    });
    if(hasHubPeering)connType='peering';
    rts.filter(rt=>rt.VpcId===vpc.VpcId).forEach(rt=>{
      (rt.Routes||[]).forEach(r=>{
        if(r.TransitGatewayId){connType='tgw';connColor='#EC4899';}
      });
    });
    
    if(connType==='tgw'&&tgwGws.length>0){
      // TGW -> Spoke: straight horizontal from TGW left to spoke right
      const tgwCount=spokeVpcs.filter((v,i)=>{
        let ct='peering';
        rts.filter(rt=>rt.VpcId===v.VpcId).forEach(rt=>{
          (rt.Routes||[]).forEach(r=>{if(r.TransitGatewayId)ct='tgw';});
        });
        return ct==='tgw'&&i<=idx;
      }).length;
      const tgwYPos=tgwCount>1?0.2+(tgwCount-1)*(0.6/(Math.max(1,spokeVpcs.length-1))):0.5;
      lines.push({
        id:'tgw_spoke_'+idx,lineType:'straight',
        stroke:{color:'#EC4899',width:2},
        endpoint1:{type:'shapeEndpoint',style:'none',shapeId:'tgw_shared',position:{x:0,y:Math.min(0.9,tgwYPos)}},
        endpoint2:{type:'shapeEndpoint',style:'arrow',shapeId:shapeIds[vpc.VpcId],position:{x:1,y:0.5}}
      });
    } else if(connType==='peering'){
      // Direct hub -> spoke (peering)
      lines.push({
        id:'hub_spoke_'+idx,lineType:'elbow',
        stroke:{color:connColor,width:2,style:'dashed'},
        endpoint1:{type:'shapeEndpoint',style:'none',shapeId:hubId,position:{x:1,y:spokeVpcs.length>1?0.1+idx*(0.8/(spokeVpcs.length-1)):0.5}},
        endpoint2:{type:'shapeEndpoint',style:'arrow',shapeId:shapeIds[vpc.VpcId],position:{x:0,y:0.5}}
      });
    }
  });
  
  // Legend
  const legendX=HUB_X;
  const legendY=HUB_Y+hubH+40;
  shapes.push({
    id:'legend_box',type:'rectangle',
    boundingBox:{x:legendX,y:legendY,w:300,h:140},
    text:NOTEXT,
    style:{stroke:{color:'#CBD5E1',width:1},fill:{type:'color',color:'#FFFFFF'}}
  });
  shapes.push({
    id:'legend_title',type:'rectangle',
    boundingBox:{x:legendX+10,y:legendY+8,w:280,h:24},
    text:'<p style="font-size:11pt;font-weight:bold;color:#334155;text-align:left">Legend</p>',
    style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
  });
  
  // Legend items
  const legendItems=[
    {color:'#7C3AED',label:'Hub VNet',y:40},
    {color:'#3B82F6',label:'Spoke VNet',y:65},
    {color:'#10B981',label:'Internet Gateway',y:90},
    {color:'#EC4899',label:'Virtual WAN',y:115}
  ];
  legendItems.forEach(item=>{
    shapes.push({
      id:'leg_'+item.y,type:'rectangle',
      boundingBox:{x:legendX+15,y:legendY+item.y,w:20,h:16},
      text:NOTEXT,
      style:{stroke:{color:item.color,width:2},fill:{type:'color',color:item.color+'20'}}
    });
    shapes.push({
      id:'leglbl_'+item.y,type:'rectangle',
      boundingBox:{x:legendX+45,y:legendY+item.y,w:240,h:18},
      text:'<p style="font-size:9pt;color:#334155;text-align:left">'+item.label+'</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
    });
  });
  
  // Route 53 DNS Zone section
  if(zones&&zones.length>0){
    const dnsX=HUB_X;
    const dnsY=Math.max(HUB_Y+hubH,spokeY)+60;
    const pubZ=zones.filter(z=>!z.Config?.PrivateZone);
    const privZ=zones.filter(z=>z.Config?.PrivateZone);
    const dnsExp=(_detailLevel>=1);
    const cols=dnsExp?1:2;
    const colW=dnsExp?700:460;
    const recRowH=16;
    const recHeaderH=18;

    // Pre-calculate per-zone height
    const zoneHeights=[];
    zones.forEach(z=>{
      if(!dnsExp){zoneHeights.push(54);return}
      const isPub=!z.Config?.PrivateZone;
      const zid=z.Id.replace('/hostedzone/','');
      const assocVpcs=(!isPub&&z.VPCs)?z.VPCs.length:0;
      const zRecs=recsByZoneLZ[zid]||[];
      let h=28; // header area (name line + zone info line)
      if(assocVpcs)h+=recRowH;
      if(zRecs.length>0) h+=recHeaderH+zRecs.length*recRowH;
      zoneHeights.push(Math.max(54,h+12));
    });
    const zoneGap=8;

    let totalZoneH=0;
    if(dnsExp){zoneHeights.forEach(h=>{totalZoneH+=h+zoneGap})}
    else{totalZoneH=Math.ceil(zones.length/cols)*62}
    const dnsW=cols*colW+60;
    const dnsH=60+totalZoneH+20;

    shapes.push({
      id:'dns_zone',type:'rectangle',
      boundingBox:{x:dnsX,y:dnsY,w:dnsW,h:dnsH},
      text:NOTEXT,
      style:{stroke:{color:'#0ea5e9',width:2,style:'dashed'},fill:{type:'color',color:'#F0F9FF'}}
    });
    shapes.push({
      id:'dns_title',type:'rectangle',
      boundingBox:{x:dnsX+10,y:dnsY+8,w:dnsW-20,h:30},
      text:'<p style="font-size:12pt;font-weight:bold;color:#0ea5e9;text-align:left">Azure DNS Private Zones ('+pubZ.length+' public, '+privZ.length+' private)</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
    });

    let curY=dnsY+48;
    zones.forEach((z,zi)=>{
      const isPub=!z.Config?.PrivateZone;
      const zid=z.Id.replace('/hostedzone/','');
      const assocVpcs=(!isPub&&z.VPCs)?z.VPCs.map(v=>{
        const vid=v.VPCId||v.VpcId;
        const vpc=vpcs.find(vp=>vp.VpcId===vid);
        return gn(vpc||{},vid);
      }).join(', '):'';
      const zh=zoneHeights[zi];
      const zRecs=recsByZoneLZ[zid]||[];

      if(dnsExp){
        const zx=dnsX+20;
        const zCol=isPub?'#10b981':'#0ea5e9';
        shapes.push({
          id:'dns_'+zi,type:'rectangle',
          boundingBox:{x:zx,y:curY,w:colW-20,h:zh},
          text:NOTEXT,
          style:{stroke:{color:zCol,width:1.5},fill:{type:'color',color:isPub?'#F0FDF4':'#F0F9FF'}},
          customData:[
            {key:'Zone ID',value:zid},{key:'Name',value:z.Name},
            {key:'Type',value:isPub?'Public':'Private'},
            {key:'Records',value:String(z.ResourceRecordSetCount)},
            {key:'Associated VPCs',value:assocVpcs||'N/A'}
          ]
        });
        // Line 1: type + name
        shapes.push({
          id:'dnslbl_'+zi+'a',type:'rectangle',
          boundingBox:{x:zx+6,y:curY+4,w:colW-32,h:18},
          text:'<p style="font-size:10pt;font-weight:bold;color:'+zCol+';text-align:left">'+(isPub?'[Public]':'[Private]')+' '+z.Name+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
        // Line 2: record count + zone ID
        let ly=curY+22;
        shapes.push({
          id:'dnslbl_'+zi+'b',type:'rectangle',
          boundingBox:{x:zx+6,y:ly,w:colW-32,h:recRowH},
          text:'<p style="font-size:8pt;color:#64748B;text-align:left">'+z.ResourceRecordSetCount+' records | Zone ID: '+zid+' | Type: '+(isPub?'Public':'Private')+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
        ly+=recRowH;
        if(assocVpcs){
          shapes.push({
            id:'dnslbl_'+zi+'d',type:'rectangle',
            boundingBox:{x:zx+6,y:ly,w:colW-32,h:recRowH},
            text:'<p style="font-size:8pt;color:#64748B;text-align:left">VPCs: '+assocVpcs+'</p>',
            style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
          });
          ly+=recRowH;
        }
        // Record sets
        if(zRecs.length>0){
          shapes.push({
            id:'dnshdr_'+zi,type:'rectangle',
            boundingBox:{x:zx+6,y:ly,w:colW-32,h:recHeaderH},
            text:'<p style="font-size:7pt;font-weight:bold;color:#475569;text-align:left">NAME                                                  TYPE      VALUE</p>',
            style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
          });
          ly+=recHeaderH;
          zRecs.forEach((rec,ri)=>{
            const rName=rec.Name||'';
            const rType=rec.Type||'';
            const rVal=rec.AliasTarget?'ALIAS → '+rec.AliasTarget.DNSName:
              (rec.ResourceRecords||[]).map(rr=>rr.Value).join(', ');
            const ttl=rec.TTL!=null?'  TTL:'+rec.TTL:'';
            shapes.push({
              id:'dnsrec_'+zi+'_'+ri,type:'rectangle',
              boundingBox:{x:zx+6,y:ly,w:colW-32,h:recRowH},
              text:'<p style="font-size:7pt;color:#334155;text-align:left;font-family:monospace">'+rName+' &nbsp; '+rType+' &nbsp; '+rVal+ttl+'</p>',
              style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
            });
            ly+=recRowH;
          });
        }
        curY+=zh+zoneGap;
      }else{
        // Collapsed: 2-column compact layout
        const col=zi%cols;
        const row=Math.floor(zi/cols);
        const zx=dnsX+20+col*colW;
        const zy=dnsY+48+row*62;
        shapes.push({
          id:'dns_'+zi,type:'rectangle',
          boundingBox:{x:zx,y:zy,w:colW-20,h:54},
          text:NOTEXT,
          style:{stroke:{color:isPub?'#10b981':'#0ea5e9',width:1.5},fill:{type:'color',color:isPub?'#F0FDF4':'#F0F9FF'}},
          customData:[
            {key:'Zone ID',value:zid},{key:'Name',value:z.Name},
            {key:'Type',value:isPub?'Public':'Private'},
            {key:'Records',value:String(z.ResourceRecordSetCount)},
            {key:'Associated VPCs',value:assocVpcs||'N/A'}
          ]
        });
        shapes.push({
          id:'dnslbl_'+zi+'a',type:'rectangle',
          boundingBox:{x:zx+6,y:zy+4,w:colW-32,h:22},
          text:'<p style="font-size:9pt;font-weight:bold;color:'+(isPub?'#10b981':'#0ea5e9')+';text-align:left">'+(isPub?'[Public]':'[Private]')+' '+z.Name+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
        shapes.push({
          id:'dnslbl_'+zi+'b',type:'rectangle',
          boundingBox:{x:zx+6,y:zy+28,w:colW-32,h:20},
          text:'<p style="font-size:8pt;color:#64748B;text-align:left">'+z.ResourceRecordSetCount+' records | '+zid+(assocVpcs?' | VPCs: '+assocVpcs:'')+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
      }
    });
  }
  
  // Storage Accounts section
  if(s3bk&&s3bk.length>0){
    const s3Cols=3;
    const s3ColW=360;
    const s3W=s3Cols*s3ColW+60;
    const s3RowH=36;
    const s3Rows=Math.ceil(s3bk.length/s3Cols);
    const s3H=50+s3Rows*s3RowH+20;
    const dnsExists=zones&&zones.length>0;
    const _lucidDnsH=(function(){
      if(!dnsExists)return 0;
      const dExp=(_detailLevel>=1);const c=dExp?1:2;
      if(dExp){let th=0;(zones||[]).forEach(z=>{const ip=!z.Config?.PrivateZone;const av=(!ip&&z.VPCs)?z.VPCs.length:0;const zid=z.Id.replace('/hostedzone/','');const zR=recsByZoneLZ[zid]||[];let h=28;if(av)h+=16;if(zR.length>0)h+=18+zR.length*16;th+=Math.max(54,h+12)+8});return 60+th+20}
      return 60+Math.ceil((zones||[]).length/c)*62+20;
    })();
    const s3Y=dnsExists?(Math.max(HUB_Y+hubH,spokeY)+60+_lucidDnsH+40):(Math.max(HUB_Y+hubH,spokeY)+60);

    shapes.push({
      id:'s3_lz_section',type:'rectangle',
      boundingBox:{x:HUB_X,y:s3Y,w:s3W,h:s3H},
      text:NOTEXT,
      style:{stroke:{color:'#EA580C',width:2,style:'dashed'},fill:{type:'color',color:'#FFF7ED'}}
    });
    shapes.push({
      id:'s3_lz_title',type:'rectangle',
      boundingBox:{x:HUB_X+10,y:s3Y+8,w:s3W-20,h:30},
      text:'<p style="font-size:12pt;font-weight:bold;color:#EA580C;text-align:left">Storage Accounts ('+s3bk.length+')</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
    });
    
    s3bk.forEach((bk,bi)=>{
      const col=bi%s3Cols;
      const row=Math.floor(bi/s3Cols);
      const bx=HUB_X+20+col*s3ColW;
      const by=s3Y+48+row*s3RowH;
      
      shapes.push({
        id:'ls3_'+bi,type:'rectangle',
        boundingBox:{x:bx,y:by,w:s3ColW-20,h:28},
        text:NOTEXT,
        style:{stroke:{color:'#EA580C',width:1},fill:{type:'color',color:'#FFFFFF'}},
        customData:[
          {key:'Bucket Name',value:bk.Name},
          {key:'Created',value:(bk.CreationDate||'N/A').split('T')[0]}
        ]
      });
      shapes.push({
        id:'ls3lbl_'+bi,type:'rectangle',
        boundingBox:{x:bx+4,y:by+2,w:s3ColW-28,h:24},
        text:'<p style="font-size:8pt;color:#232F3E;text-align:left">'+bk.Name+'</p>',
        style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
      });
    });
  }

  // Compute page dimensions
  let pgW=EXT_X+extW+100;
  let pgH=Math.max(HUB_Y+hubH+200,spokeY+200);
  if(zones&&zones.length>0){
    const pgDnsH=(function(){
      const dExp=(_detailLevel>=1);const c=dExp?1:2;
      if(dExp){let th=0;zones.forEach(z=>{const ip=!z.Config?.PrivateZone;const av=(!ip&&z.VPCs)?z.VPCs.length:0;const zid=z.Id.replace('/hostedzone/','');const zR=recsByZoneLZ[zid]||[];let h=28;if(av)h+=16;if(zR.length>0)h+=18+zR.length*16;th+=Math.max(54,h+12)+8});return 60+th+20}
      return 60+Math.ceil(zones.length/c)*62+20;
    })();
    const dnsBottom=Math.max(HUB_Y+hubH,spokeY)+60+pgDnsH+40;
    pgH=Math.max(pgH,dnsBottom);
  }
  if(s3bk&&s3bk.length>0){
    const pgDnsH2=(function(){
      if(!(zones&&zones.length>0))return 0;
      const dExp=(_detailLevel>=1);const c=dExp?1:2;
      if(dExp){let th=0;zones.forEach(z=>{const ip=!z.Config?.PrivateZone;const av=(!ip&&z.VPCs)?z.VPCs.length:0;const zid=z.Id.replace('/hostedzone/','');const zR=recsByZoneLZ[zid]||[];let h=28;if(av)h+=16;if(zR.length>0)h+=18+zR.length*16;th+=Math.max(54,h+12)+8});return 60+th+20}
      return 60+Math.ceil(zones.length/c)*62+20;
    })();
    const dnsExists=zones&&zones.length>0;
    const s3Y=dnsExists?(Math.max(HUB_Y+hubH,spokeY)+60+pgDnsH2+40):(Math.max(HUB_Y+hubH,spokeY)+60);
    const s3Rows=Math.ceil(s3bk.length/3);
    const s3Bottom=s3Y+50+s3Rows*36+40;
    pgH=Math.max(pgH,s3Bottom);
  }
  
  // Build final export - format must match buildLucidExport
  const doc={version:1,pages:[{id:'page1',title:'Azure-Landing-Zone',shapes,lines}]};
  
  // Landing Zone layout complete
  return {doc,iconSet};
  }catch(e){
    console.error('Landing Zone layout error:', e);
    exportUtilitiesNotify('Landing Zone layout error: '+e.message);
    return null;
  }
}

// #endregion LUCID LANDING ZONE EXPORT
