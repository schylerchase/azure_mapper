// #region LUCID NETWORK EXPORT
function buildLucidExport(){
  const exportData=LucidNetworkExportData.collect();
  const {
    vpcs,subnets,rts,nacls,igws,nats,vpceList,peerings,volumes,snapshots,s3bk,
    zones,instances,albs,tgs,enis,wafAcls,subByVnet,nsgByVnet,subNacl,subRT,
    instBySub,eniBySub,albBySub,volByInst,volBySub,snapByVol,tgByAlb,wafByAlb,
    rdsBySub,ecsBySub,lambdaBySub,cfByAlb,recsByZone,pubSubs,gwSet2L,gwByVpc,
    sharedGws,vpceByVpc,activeVpcs,layoutMode,userHubName
  }=exportData;
  if(!vpcs.length){exportUtilitiesNotify('Render map first');return null}

  function tw(str,pt){return(str||'').length*pt*0.62+20}

  const shapes=[],lines=[],iconSet=new Set();
  const shapeIds={};
  let lid=0;
  const IC=36;
  const VP=50;
  const VH=80;
  const SG=32;
  const SP=24;
  const EC2W=260,EC2H=34,EC2G=16;

  // Official Azure Architecture Group Icon colors
  const COL={
    vpcFill:'#FFFFFF',vpcStroke:'#8C4FFF',vpcFont:'#8C4FFF',
    pubFill:'#FFFFFF',pubStroke:'#7AA116',pubFont:'#7AA116',
    prvFill:'#FFFFFF',prvStroke:'#147EBA',prvFont:'#147EBA',
    ec2Fill:'#FFFFFF',ec2Stroke:'#ED7100',ec2Font:'#232F3E',
    igw:'#8C4FFF',nat:'#8C4FFF',tgw:'#8C4FFF',vgw:'#8C4FFF',
    vpce:'#8C4FFF',pcx:'#8C4FFF',inet:'#232F3E',
    albFill:'#FFFFFF',albStroke:'#8C4FFF',albFont:'#232F3E'
  };
  const gwFills={IGW:'#F5F0FF',NAT:'#F5F0FF',TGW:'#F5F0FF',VGW:'#F5F0FF',PCX:'#F5F0FF',VPCE:'#F5F0FF'};


  // icons as rectangles with image fill
  function addIcon(type,x,y){
    iconSet.add(type);
    shapes.push({
      id:'icon_'+(lid++),type:'rectangle',
      boundingBox:{x,y,w:IC,h:IC},
      text:'<p style="font-size:1pt;color:transparent">&nbsp;</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'image',ref:(ICON_MAP[type]||type.toLowerCase())+'.png'}}
    });
  }

  const gwColors2={IGW:COL.igw,NAT:COL.nat,TGW:COL.tgw,VGW:COL.vgw,PCX:COL.pcx,VPCE:COL.vpce};
  const GW_W=350,GW_H=52,GW_GAP=10;
  // buildLucidExport

  // Landing Zone layout mode
  if(layoutMode==='landingzone'){
    // Landing Zone layout mode
    const result=buildLandingZoneLayout({
      vpcs:activeVpcs,subByVnet,nsgByVnet,pubSubs,rts,instances,albs,enis,nacls:subNacl,
      subRT,igws,nats,vpceList,peerings,sharedGws,gwByVpc,vpceByVpc,gwSet2L,
      gn,sid,tw,userHubName,COL,gwColors2,gwFills,ICON_MAP,volumes,zones,
      s3bk,snapshots,snapByVol,tgByAlb,tgs,wafAcls,wafByAlb,
      instBySub,albBySub,eniBySub,volByInst,volBySub,rdsBySub,ecsBySub,lambdaBySub,cfByAlb,recsByZone
    });
    // buildLandingZoneLayout returned
    return result;
  }

  // transparent text to suppress Lucid "Text" placeholder
  const NOTEXT='<p style="font-size:1pt;color:transparent">&nbsp;</p>';

  // gateway badge sizing (wider and taller to fit text)
  const GW_BADGE_W=350,GW_BADGE_H=56,GW_BADGE_GAP=12;
  const GW_BADGES_PER_ROW=2;

  // PASS 1: compute VPC column sizes
  const vpcInfos=[];
  activeVpcs.forEach(vpc=>{
    const ss=subByVnet[vpc.VpcId]||[];
    const vpcName=gn(vpc,vpc.VpcId);
    const vpcLabel=vpcName+' ('+vpc.CidrBlock+')';
    let maxSubW=580;
    ss.forEach(s=>{
      const sName=gn(s,s.SubnetId);
      const isPub=pubSubs.has(s.SubnetId);
      const tag=isPub?'PUBLIC':'PRIVATE';
      const az=s.AvailabilityZone||'';
      const subLabel=sName+' ['+tag+'] '+s.CidrBlock+' '+az;
      const needed=tw(subLabel,10)+IC+24;
      if(needed>maxSubW)maxSubW=needed;
      const insts=instances.filter(i=>i.SubnetId===s.SubnetId);
      const albsInSub=albs.filter(lb=>(lb.AvailabilityZones||[]).some(az2=>az2.SubnetId===s.SubnetId));
      const uaEnis=(eniBySub[s.SubnetId]||[]).filter(e=>!insts.some(i=>enis.some(en=>en.Attachment&&en.Attachment.InstanceId===i.InstanceId&&en.NetworkInterfaceId===e.NetworkInterfaceId)));
      const resCount=insts.length+albsInSub.length+(rdsBySub[s.SubnetId]||[]).length+(ecsBySub[s.SubnetId]||[]).length+(lambdaBySub[s.SubnetId]||[]).length+uaEnis.length;
      const cols=Math.max(1,Math.floor((maxSubW-SP*2)/(EC2W+EC2G)));
      const neededForInst=resCount>0?cols*(EC2W+EC2G)+SP*2:0;
      if(neededForInst>maxSubW)maxSubW=neededForInst;
    });
    maxSubW=Math.min(900,Math.max(520,maxSubW));

    const myGws=gwByVpc[vpc.VpcId]||[];
    const myVpce=vpceByVpc[vpc.VpcId]||[];
    const allGwItems=[...myGws];
    if(myVpce.length>0)allGwItems.push({type:'VPCE',id:'vpce_bundle',isVpce:true,count:myVpce.length});

    // Use fixed badge width
    const maxBadgeW=GW_BADGE_W;
    
    // ensure VPC wide enough for gateway badges
    const gwRowW=Math.min(allGwItems.length,GW_BADGES_PER_ROW)*(maxBadgeW+GW_BADGE_GAP)+VP*2;
    if(gwRowW>maxSubW)maxSubW=Math.max(maxSubW,gwRowW);

    const vpcW=maxSubW+VP*2;
    const vpcLabelW=tw(vpcLabel,14)+IC+24;
    const finalVpcW=Math.max(vpcW,vpcLabelW+VP*2);

    // gateway badge section height
    const gwRows=Math.ceil(allGwItems.length/GW_BADGES_PER_ROW);
    const gwSectionH=gwRows>0?(gwRows*(GW_BADGE_H+GW_BADGE_GAP)+GW_BADGE_GAP+10):0;

    const P1_NAME_H=36,P1_DETAIL_H=28,P1_CHILD_LINE_H=22,P1_CHILD_GAP=8,P1_RES_PAD=10;
    const P1_CHILD_INNER_W=EC2W-24;
    function p1ChildH(label){return Math.max(1,Math.ceil(tw(label,8)/P1_CHILD_INNER_W))*P1_CHILD_LINE_H+8;}
    function p1ResH(r){
      const chs=r.children||[];
      let h=P1_RES_PAD+P1_NAME_H;
      if(r.detail)h+=P1_DETAIL_H;
      if(chs.length>0){
        h+=P1_CHILD_GAP;
        chs.forEach(ch=>{h+=p1ChildH(ch.label||'')+P1_CHILD_GAP;});
      }
      h+=P1_RES_PAD;
      return Math.max(EC2H,h);
    }
    let subStackH=0;
    const subHeights={};
    ss.forEach(s=>{
      const sInsts=instances.filter(i=>i.SubnetId===s.SubnetId);
      const sAlbs=albs.filter(lb=>(lb.AvailabilityZones||[]).some(az=>az.SubnetId===s.SubnetId));
      const sRds=(rdsBySub[s.SubnetId]||[]);
      const sEcs=(ecsBySub[s.SubnetId]||[]);
      const sLam=(lambdaBySub[s.SubnetId]||[]);
      const sEni=(eniBySub[s.SubnetId]||[]);
      const p1Attached=new Set();
      // Build resources with children for height calc
      const p1Res=[];
      sInsts.forEach(i=>{
        const ie=enis.filter(e=>e.Attachment&&e.Attachment.InstanceId===i.InstanceId);
        ie.forEach(e=>p1Attached.add(e.NetworkInterfaceId));
        const ch=[];
        if(_showNested){
          ie.forEach(e=>ch.push({label:'ENI: '+e.NetworkInterfaceId.slice(-8)+(e.PrivateIpAddress?' \u00b7 '+e.PrivateIpAddress:'')}));
          (volByInst[i.InstanceId]||[]).forEach(v=>{const sc=(snapByVol[v.VolumeId]||[]).length;ch.push({label:'VOL: '+v.Size+'GB '+(v.VolumeType||'')+(sc?' \u00b7 '+sc+' snap':'')})});
        }
        p1Res.push({detail:i.InstanceType,children:ch});
      });
      sAlbs.forEach(lb=>{
        const ch=[];
        if(_showNested){
          (tgByAlb[lb.LoadBalancerArn]||[]).forEach(t=>ch.push({label:'TG: '+(t.TargetGroupName||'TG')+' \u00b7 '+((t.Targets||[]).length)+' tgt'}));
          (wafByAlb[lb.LoadBalancerArn]||[]).forEach(w=>ch.push({label:'WAF: '+(w.Name||'WAF')+' \u00b7 '+((w.Rules||[]).length)+' rules'}));
          (cfByAlb[lb.LoadBalancerArn]||[]).forEach(cf=>ch.push({label:'CF: '+(cf.DomainName||'CF')}));
        }
        p1Res.push({detail:lb.Scheme||'',children:ch});
      });
      sRds.forEach(db=>p1Res.push({detail:db.Engine||'',children:[]}));
      sEcs.forEach(svc=>p1Res.push({detail:svc.launchType||'',children:[]}));
      sLam.forEach(fn=>p1Res.push({detail:fn.Runtime||'',children:[]}));
      sEni.forEach(e=>{if(!p1Attached.has(e.NetworkInterfaceId))p1Res.push({detail:e.PrivateIpAddress||'',children:[]})});
      // Standalone EBS volumes
      ((volBySub||{})[s.SubnetId]||[]).forEach(v=>p1Res.push({detail:v.Size+'GB '+(v.VolumeType||''),children:[]}));
      const cols=Math.max(1,Math.floor((maxSubW-SP*2)/(EC2W+EC2G)));
      const rowCount=Math.ceil(p1Res.length/cols);
      let totalResH=0;
      for(let row=0;row<rowCount;row++){
        let maxH=EC2H;
        for(let c=0;c<cols;c++){const ri=row*cols+c;if(ri<p1Res.length){const h=p1ResH(p1Res[ri]);if(h>maxH)maxH=h;}}
        totalResH+=maxH+EC2G;
      }
      const subH=VH+totalResH+SP*2;
      const finalSubH=Math.max(60,subH);
      subHeights[s.SubnetId]=finalSubH;
      subStackH+=finalSubH+SG;
    });
    const vpcH=VH+gwSectionH+subStackH+VP;
    vpcInfos.push({vpc,ss,vpcLabel,maxSubW,finalVpcW,vpcH,allGwItems,gwSectionH,subHeights,maxBadgeW});
  });

  const VPC_TOP=80;
  const COL_SPACE=500; // extra space for per-VPC gateways on the right

  // track VPC positions for line routing
  const vpcPositions={};

  // PASS 2: place shapes
  let vpcX=120;

  vpcInfos.forEach(info=>{
    const {vpc,ss,vpcLabel,maxSubW,finalVpcW,vpcH,allGwItems,gwSectionH,subHeights,maxBadgeW}=info;
    info.vpcX=vpcX; // store for later use in line drawing
    const vpcId='vpc_'+(lid++);
    shapeIds[vpc.VpcId]=vpcId;
    
    // Get VPC stats
    const vpcSgs=nsgByVnet[vpc.VpcId]||[];
    const vpcRts=rts.filter(rt=>rt.VpcId===vpc.VpcId);
    const vpcVpces=vpceList.filter(v=>v.VpcId===vpc.VpcId);
    const vpcInsts=instances.filter(i=>ss.some(s=>s.SubnetId===i.SubnetId));
    const vpcEnis=enis.filter(e=>e.VpcId===vpc.VpcId);
    const region=vpc._region||ss[0]?._region||'';

    // VPC container
    shapes.push({
      id:vpcId,type:'roundedRectangleContainer',
      boundingBox:{x:vpcX,y:VPC_TOP,w:finalVpcW,h:vpcH},
      text:NOTEXT,
      style:{stroke:{color:COL.vpcStroke,width:3,style:'dashed'},fill:{type:'color',color:COL.vpcFill}},
      magnetize:true,
      customData:[
        {key:'VNet ID',value:vpc.VpcId||vpc.id},
        {key:'Name',value:gn(vpc,vpc.VpcId||vpc.id)},
        {key:'Address Space',value:vpc.CidrBlock||((vpc.properties&&vpc.properties.addressSpace&&vpc.properties.addressSpace.addressPrefixes&&vpc.properties.addressSpace.addressPrefixes[0])||'')},
        {key:'Location',value:region||vpc.location||''},
        {key:'Subnets',value:String(ss.length)},
        {key:'NSGs',value:String(vpcSgs.length)},
        {key:'Route Tables (UDR)',value:String(vpcRts.length)},
        {key:'Virtual Machines',value:String(vpcInsts.length)},
        {key:'NICs',value:String(vpcEnis.length)},
        {key:'Private Endpoints',value:String(vpcVpces.length)}
      ]
    });
    // store VPC position for line routing
    vpcPositions[vpc.VpcId]={x:vpcX,w:finalVpcW,h:vpcH,bottomY:VPC_TOP+vpcH};
    addIcon('VPC',vpcX+6,VPC_TOP+4);
    // Truncate VPC label to fit - conservative estimate
    const maxVpcChars=Math.floor((finalVpcW-IC-50)/11);
    const dispVpcLabel=vpcLabel.length>maxVpcChars?vpcLabel.substring(0,maxVpcChars-2)+'..':vpcLabel;
    shapes.push({
      id:'vpclbl_'+(lid++),type:'rectangle',
      boundingBox:{x:vpcX+IC+12,y:VPC_TOP+4,w:finalVpcW-IC-24,h:VH-10},
      text:'<p style="font-size:14pt;font-weight:bold;color:'+COL.vpcFont+';text-align:left;padding:4px 8px">'+dispVpcLabel+'</p>',
      style:{stroke:{color:COL.vpcFill,width:0},fill:{type:'color',color:COL.vpcFill}}
    });

    // gateway badges inside VPC, below header
    const thisBadgeW=maxBadgeW||GW_BADGE_W;
    let gwBadgeY=VPC_TOP+VH+6;
    for(let row=0;row<Math.ceil(allGwItems.length/GW_BADGES_PER_ROW);row++){
      const rowItems=allGwItems.slice(row*GW_BADGES_PER_ROW,(row+1)*GW_BADGES_PER_ROW);
      let gwBX=vpcX+VP;
      rowItems.forEach(gw=>{
        const gc=gwColors2[gw.type]||'#546E7A';
        const gf=gwFills[gw.type]||'#F5F0FF';
        if(gw.isVpce){
          // Truncate VPCE text
          const vpceText='VPCE ('+gw.count+')';
          // VPCE badge with text
          shapes.push({
            id:'vpce_'+(lid++),type:'rectangle',
            boundingBox:{x:gwBX,y:gwBadgeY,w:thisBadgeW,h:GW_BADGE_H},
            text:NOTEXT,
            style:{stroke:{color:COL.vpce,width:2,style:'dashed'},fill:{type:'color',color:'#F5F0FF'}}
          });
          addIcon('VPCE',gwBX+10,gwBadgeY+10);
          shapes.push({
            id:'vpce_lbl_'+(lid++),type:'rectangle',
            boundingBox:{x:gwBX+52,y:gwBadgeY+10,w:thisBadgeW-62,h:36},
            text:'<p style="font-size:10pt;color:#232F3E;font-weight:bold;text-align:left">'+vpceText+'</p>',
            style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
          });
        } else {
          const nm=gwNames[gw.id]||sid(gw.id);
          
          // Build gateway-specific customData
          let gwCustomData=[
            {key:'Gateway ID',value:gw.id},
            {key:'Type',value:gw.type==='IGW'?'Internet Gateway':gw.type==='NAT'?'NAT Gateway':gw.type==='VGW'?'Virtual Private Gateway':gw.type},
            {key:'Name',value:nm}
          ];
          
          // Add NAT-specific info
          if(gw.type==='NAT'){
            const natGw=nats.find(n=>n.NatGatewayId===gw.id);
            if(natGw){
              gwCustomData.push({key:'State',value:natGw.State||''});
              gwCustomData.push({key:'Connectivity',value:natGw.ConnectivityType||'public'});
              const pubIp=(natGw.NatGatewayAddresses||[])[0]?.PublicIp;
              const privIp=(natGw.NatGatewayAddresses||[])[0]?.PrivateIp;
              if(pubIp)gwCustomData.push({key:'Public IP',value:pubIp});
              if(privIp)gwCustomData.push({key:'Private IP',value:privIp});
            }
          }
          
          // Add IGW-specific info
          if(gw.type==='IGW'){
            const igw=igws.find(g=>g.InternetGatewayId===gw.id);
            if(igw){
              const attachedVpcs=(igw.Attachments||[]).map(a=>a.VpcId).join(', ');
              gwCustomData.push({key:'Attached VPCs',value:attachedVpcs||'None'});
              gwCustomData.push({key:'State',value:(igw.Attachments||[])[0]?.State||''});
            }
          }
          
          // Truncate text to fit
          const maxBChars=Math.floor((thisBadgeW-60)/7);
          const fullBText=gw.type+': '+nm;
          const dispBText=fullBText.length>maxBChars?fullBText.substring(0,maxBChars-2)+'..':fullBText;
          
          // Gateway badge with text
          shapes.push({
            id:'gwb_'+(lid++),type:'rectangle',
            boundingBox:{x:gwBX,y:gwBadgeY,w:thisBadgeW,h:GW_BADGE_H},
            text:NOTEXT,
            style:{stroke:{color:gc,width:2},fill:{type:'color',color:gf}},
            customData:gwCustomData
          });
          addIcon(gw.type,gwBX+10,gwBadgeY+10);
          shapes.push({
            id:'gwb_lbl_'+(lid++),type:'rectangle',
            boundingBox:{x:gwBX+52,y:gwBadgeY+10,w:thisBadgeW-62,h:36},
            text:'<p style="font-size:10pt;font-weight:bold;color:#232F3E;text-align:left">'+dispBText+'</p>',
            style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
          });
        }
        gwBX+=thisBadgeW+GW_BADGE_GAP;
      });
      gwBadgeY+=GW_BADGE_H+GW_BADGE_GAP;
    }

    // subnets below gateway badges
    let subY=VPC_TOP+VH+gwSectionH;
    ss.forEach(s=>{
      const sName=gn(s,s.SubnetId);
      const isPub=pubSubs.has(s.SubnetId);
      const tag=isPub?'PUBLIC':'PRIVATE';
      const az=s.AvailabilityZone||'';
      const subLabel=sName+' ['+tag+'] '+s.CidrBlock+' '+az;
      const subId='sub_'+(lid++);
      shapeIds[s.SubnetId]=subId;
      const insts=instBySub[s.SubnetId]||[];
      const subEnis=eniBySub[s.SubnetId]||[];
      const subAlbs=albBySub[s.SubnetId]||[];
      const subRds=rdsBySub[s.SubnetId]||[];
      const subEcs=ecsBySub[s.SubnetId]||[];
      const subLambda=lambdaBySub[s.SubnetId]||[];
      const NAME_H=36,DETAIL_H=28,CHILD_LINE_H=22,CHILD_GAP=8,RES_PAD=10;
      const CHILD_INNER_W=EC2W-24;
      function childLines(label){return Math.max(1,Math.ceil(tw(label,8)/CHILD_INNER_W));}
      function childH(label){return childLines(label)*CHILD_LINE_H+8;}
      const attachedEnis=new Set();
      const resources=[];
      // EC2 with ENI + VOL children
      insts.forEach(i=>{
        const ch=[];
        const ie=enis.filter(e=>e.Attachment&&e.Attachment.InstanceId===i.InstanceId);
        ie.forEach(e=>attachedEnis.add(e.NetworkInterfaceId));
        if(_showNested){
          ie.forEach(e=>ch.push({type:'NIC',name:e.NetworkInterfaceId.slice(-8),detail:e.PrivateIpAddress||'',col:'#3b82f6'}));
          (volByInst[i.InstanceId]||[]).forEach(v=>{
            const sc=(snapByVol[v.VolumeId]||[]).length;
            ch.push({type:'VOL',name:v.Size+'GB '+(v.VolumeType||''),detail:sc?sc+' snap':'',col:'#f59e0b'});
          });
        }
        resources.push({type:'VM',name:gn(i,i.InstanceId),id:i.InstanceId,detail:i.InstanceType,children:ch,resCol:'#10b981'});
      });
      // ALB with TG + WAF + CF children
      subAlbs.forEach(lb=>{
        const ch=[];
        if(_showNested){
          (tgByAlb[lb.LoadBalancerArn]||[]).forEach(tg=>ch.push({type:'TG',name:tg.TargetGroupName||'TG',detail:(tg.Targets||[]).length+' tgt',col:'#06b6d4'}));
          (wafByAlb[lb.LoadBalancerArn]||[]).forEach(w=>ch.push({type:'WAF',name:w.Name||'WAF',detail:(w.Rules||[]).length+' rules',col:'#eab308'}));
          (cfByAlb[lb.LoadBalancerArn]||[]).forEach(cf=>ch.push({type:'CF',name:cf.DomainName||'CF',detail:'',col:'#8b5cf6'}));
        }
        resources.push({type:'App Gateway',name:lb.LoadBalancerName||'ALB',id:lb.LoadBalancerArn,detail:lb.Scheme||'',children:ch,resCol:'#38bdf8'});
      });
      // RDS
      subRds.forEach(db=>resources.push({type:'SQL',name:db.DBInstanceIdentifier||'SQL',id:db.DBInstanceIdentifier,detail:db.Engine||'',children:[],resCol:'#3b82f6'}));
      // ECS
      subEcs.forEach(svc=>resources.push({type:'Container',name:svc.serviceName||'Container',id:svc.serviceName,detail:svc.launchType||'',children:[],resCol:'#f97316'}));
      // Lambda
      subLambda.forEach(fn=>resources.push({type:'FN',name:fn.FunctionName||'FuncApp',id:fn.FunctionName,detail:fn.Runtime||'',children:[],resCol:'#a855f7'}));
      // Unattached ENIs
      subEnis.forEach(e=>{
        if(attachedEnis.has(e.NetworkInterfaceId))return;
        resources.push({type:'NIC',name:e.NetworkInterfaceId.slice(-8),id:e.NetworkInterfaceId,detail:e.PrivateIpAddress||'',children:[],resCol:'#3b82f6'});
      });
      // Standalone EBS volumes
      ((volBySub||{})[s.SubnetId]||[]).forEach(v=>{const att=(v.Attachments||[])[0];
        resources.push({type:'VOL',name:v.Size+'GB '+(v.VolumeType||''),id:v.VolumeId,detail:att?att.InstanceId?.slice(-8)||'':'detached',children:[],resCol:'#f59e0b'});
      });
      // Calculate per-resource height (name + detail + children + padding)
      function resHeight(r){
        const chs=r.children||[];
        let h=RES_PAD+NAME_H;
        if(r.detail)h+=DETAIL_H;
        if(chs.length>0){
          h+=CHILD_GAP;
          chs.forEach(ch=>{
            const lbl=ch.type+': '+ch.name+(ch.detail?' \u00b7 '+ch.detail:'');
            h+=childH(lbl)+CHILD_GAP;
          });
        }
        h+=RES_PAD;
        return Math.max(EC2H,h);
      }
      const cols=Math.max(1,Math.floor((maxSubW-SP*2)/(EC2W+EC2G)));
      // For row height, use max height of resources in that row
      const rowCount=Math.ceil(resources.length/cols);
      let totalResH=0;
      for(let row=0;row<rowCount;row++){
        let maxH=EC2H;
        for(let c=0;c<cols;c++){const ri=row*cols+c;if(ri<resources.length){const h=resHeight(resources[ri]);if(h>maxH)maxH=h;}}
        totalResH+=maxH+EC2G;
      }
      const subH=VH+totalResH+SP*2;
      const finalSubH=Math.max(60,subH);
      const sx=vpcX+VP,sy=subY;
      const fc=isPub?COL.pubFont:COL.prvFont;
      const fill=isPub?COL.pubFill:COL.prvFill;
      const stroke=isPub?COL.pubStroke:COL.prvStroke;
      
      // Get NACL and route table info
      const nacl=subNacl[s.SubnetId];
      const rt=subRT[s.SubnetId];
      const naclName=nacl?gn(nacl,nacl.NetworkAclId):'Default';
      const rtName=rt?gn(rt,rt.RouteTableId):'Main';
      const routes=(rt?.Routes||[]).filter(r=>r.GatewayId!=='local').map(r=>(r.DestinationCidrBlock||r.DestinationPrefixListId||'?')+' > '+(r.GatewayId||r.NatGatewayId||r.TransitGatewayId||'?')).join('; ');
      
      shapes.push({
        id:subId,type:'rectangle',
        boundingBox:{x:sx,y:sy,w:maxSubW,h:finalSubH},
        text:NOTEXT,
        style:{stroke:{color:stroke,width:2},fill:{type:'color',color:fill}},
        customData:[
          {key:'Subnet ID',value:s.SubnetId||s.id},
          {key:'Name',value:gn(s,s.SubnetId||s.id)},
          {key:'Address Prefix',value:s.CidrBlock||((s.properties&&s.properties.addressPrefix)||'')},
          {key:'Location',value:s.AvailabilityZone||s.location||''},
          {key:'Type',value:isPub?'Public':'Private'},
          {key:'NSG',value:naclName+(nacl?' ('+nacl.NetworkAclId+')':'')},
          {key:'Route Table',value:rtName+(rt?' ('+rt.RouteTableId+')':'')},
          {key:'Routes',value:routes||'local only'},
          {key:'Virtual Machines',value:String(insts.length)},
          {key:'NICs',value:String(subEnis.length)},
          {key:'Load Balancers',value:String(subAlbs.length)}
        ]
      });
      addIcon(isPub?'SUB_PUB':'SUB_PRV',sx+6,sy+6);
      // Truncate subnet label to fit - conservative estimate
      const maxSubChars=Math.floor((maxSubW-IC-40)/9);
      const dispSubLabel=subLabel.length>maxSubChars?subLabel.substring(0,maxSubChars-2)+'..':subLabel;
      shapes.push({
        id:'sublbl_'+(lid++),type:'rectangle',
        boundingBox:{x:sx+IC+12,y:sy+6,w:maxSubW-IC-24,h:32},
        text:'<p style="font-size:10pt;font-weight:bold;color:'+fc+';text-align:left;padding:4px 6px">'+dispSubLabel+'</p>',
        style:{stroke:{color:fill,width:0},fill:{type:'color',color:fill}}
      });
      // Compute row Y offsets using variable row heights
      const rowHeights=[];
      for(let row=0;row<rowCount;row++){
        let maxH=EC2H;
        for(let c=0;c<cols;c++){const ri=row*cols+c;if(ri<resources.length){const h=resHeight(resources[ri]);if(h>maxH)maxH=h;}}
        rowHeights.push(maxH);
      }
      const rowYOff=[0];
      for(let i=0;i<rowHeights.length;i++)rowYOff.push(rowYOff[i]+rowHeights[i]+EC2G);

      resources.forEach((r,ri)=>{
        const col=ri%cols,row=Math.floor(ri/cols);
        const rx=sx+SP+col*(EC2W+EC2G);
        const ry=sy+VH+rowYOff[row];
        const isAlb=r.type==='ALB';
        const rH=resHeight(r);

        // Build customData based on resource type
        const resCustomData=[{key:'Type',value:r.type},{key:'Name',value:r.name||''},{key:'ID',value:r.id||''}];
        if(r.detail)resCustomData.push({key:'Detail',value:r.detail});

        // Truncate name to fit box
        const maxResChars=Math.floor((EC2W-20)/8);
        const dispResName=r.name.length>maxResChars?r.name.substring(0,maxResChars-2)+'..':r.name;

        // Build rich text: type badge + name + detail + children
        const rc=r.resCol||COL.ec2Font;
        let resHtml='<p style="font-size:9pt;color:'+rc+';font-weight:bold;text-align:left;padding:4px 6px">'+r.type+': '+dispResName+'</p>';
        if(r.detail){
          resHtml+='<p style="font-size:7pt;color:#6B7280;text-align:left;padding:0 6px">'+r.detail+'</p>';
        }
        (r.children||[]).forEach(ch=>{
          const chLabel=ch.type+': '+ch.name+(ch.detail?' \u00b7 '+ch.detail:'');
          resHtml+='<p style="font-size:8pt;color:'+ch.col+';font-weight:bold;text-align:left;padding:2px 6px;margin:4px 0">\u00a0\u00a0'+chLabel+'</p>';
        });

        // Resource container box
        shapes.push({
          id:'res_'+(lid++),type:'rectangle',
          boundingBox:{x:rx,y:ry,w:EC2W,h:rH},
          text:resHtml,
          style:{
            stroke:{color:rc,width:1},
            fill:{type:'color',color:'#FFFFFF'}
          },
          customData:resCustomData
        });
      });
      subY+=finalSubH+SG;
    });

    vpcX+=finalVpcW+COL_SPACE;
  });

  // Build subnet positions lookup (needed for gateway line routing)
  const subnetPositions={};
  vpcInfos.forEach(vi=>{
    const vpcX=vi.vpcX;
    let sy=VPC_TOP+VH+vi.gwSectionH;
    vi.ss.forEach((s,si)=>{
      const finalSubH=vi.subHeights[s.SubnetId]||60;
      subnetPositions[s.SubnetId]={
        x:vpcX+VP,
        y:sy,
        w:vi.maxSubW,
        h:finalSubH,
        vpcId:vi.vpc.VpcId,
        vpcX:vpcX,
        vpcW:vi.finalVpcW,
        vpcH:vi.vpcH,
        subIndex:si,
        centerX:vpcX+VP+vi.maxSubW/2,
        centerY:sy+finalSubH/2
      };
      sy+=finalSubH+SG;
    });
  });

  // --- Per-VPC Gateways (IGW, NAT, VGW) to the RIGHT of each VPC ---
  const PER_VPC_GW_X_OFFSET=60; // distance from VPC right edge
  const PER_VPC_GW_MAX_W=COL_SPACE-PER_VPC_GW_X_OFFSET-40; // max width to fit in column gap
  const PER_VPC_GW_H=56;
  const PER_VPC_GW_GAP=50;
  const perVpcGwPos={}; // gwId -> {x,y,centerX,centerY}
  
  vpcInfos.forEach(vi=>{
    const vpcRightX=vi.vpcX+vi.finalVpcW;
    const gwX=vpcRightX+PER_VPC_GW_X_OFFSET;
    
    // Get per-VPC gateways (IGW, NAT, VGW) for this VPC
    const vpcGws=vi.allGwItems.filter(g=>!g.isVpce && (g.type==='IGW'||g.type==='NAT'||g.type==='VGW'));
    
    // Use fixed width that fits within column space
    const maxGwW=PER_VPC_GW_MAX_W;
    
    let gwY=VPC_TOP+50;
    vpcGws.forEach((gw,gi)=>{
      const nm=gwNames[gw.id]||sid(gw.id);
      const gc=gwColors2[gw.type]||'#546E7A';
      const gf=gwFills[gw.type]||'#F5F0FF';
      const gwShapeId='pvgw_'+(lid++);
      shapeIds[gw.id]=gwShapeId;
      
      // Truncate text aggressively to fit within box (accounting for icon)
      const maxChars=Math.floor((maxGwW-70)/9);
      const fullText=gw.type+': '+nm;
      const dispText=fullText.length>maxChars?fullText.substring(0,maxChars-2)+'..':fullText;
      
      // Rectangle with text - icon overlaps but text stays in bounds
      shapes.push({
        id:gwShapeId,type:'rectangle',
        boundingBox:{x:gwX,y:gwY,w:maxGwW,h:PER_VPC_GW_H},
        text:'<p style="font-size:9pt;font-weight:bold;color:'+gc+';text-align:center">'+dispText+'</p>',
        style:{stroke:{color:gc,width:2},fill:{type:'color',color:gf}},
        customData:[
          {key:'Gateway ID',value:gw.id},
          {key:'Type',value:gw.type==='IGW'?'Internet Gateway':gw.type==='NAT'?'NAT Gateway':'Virtual Private Gateway'},
          {key:'Name',value:nm},
          {key:'VPC',value:vi.vpc.VpcId}
        ]
      });
      // Icon
      addIcon(gw.type,gwX+10,gwY+10);
      
      perVpcGwPos[gw.id]={
        x:gwX,
        y:gwY,
        centerX:gwX+maxGwW/2,
        centerY:gwY+PER_VPC_GW_H/2,
        leftEdge:gwX,
        vpcId:vi.vpc.VpcId
      };
      
      gwY+=PER_VPC_GW_H+PER_VPC_GW_GAP;
    });
  });

  // Build reverse map: rtId -> all subnets using it (for both per-VPC and shared gw lines)
  const rtToSubs={};
  subnets.forEach(s=>{
    const rt=subRT[s.SubnetId];
    if(rt){(rtToSubs[rt.RouteTableId]=rtToSubs[rt.RouteTableId]||[]).push(s.SubnetId)}
  });

  // --- Lines from subnets to per-VPC gateways (IGW, NAT, VGW) ---
  const perVpcGwLines={};
  rts.forEach(rt=>{
    const vId=rt.VpcId;
    const rtSubnets=rtToSubs[rt.RouteTableId]||[];
    if(rtSubnets.length===0)return;
    
    (rt.Routes||[]).forEach(r=>{
      // Check for IGW, NAT, VGW routes
      let gwId=null,gwType=null;
      if(_isIgwRoute(r.GatewayId)){gwId=r.GatewayId;gwType='IGW';}
      else if(r.NatGatewayId){gwId=r.NatGatewayId;gwType='NAT';}
      else if(r.GatewayId?.startsWith('vgw-')){gwId=r.GatewayId;gwType='VGW';}
      
      if(!gwId||!perVpcGwPos[gwId])return;
      
      rtSubnets.forEach(subId=>{
        const key=subId+'|'+gwId;
        if(perVpcGwLines[key])return;
        perVpcGwLines[key]=true;
        
        const subPos=subnetPositions[subId];
        if(!subPos||!shapeIds[subId]||!shapeIds[gwId])return;
        
        const gwPos=perVpcGwPos[gwId];
        const gc=gwColors2[gwType]||'#546E7A';
        
        // Get names for metadata
        const subObj=subnets.find(s=>s.SubnetId===subId);
        const subName=subObj?gn(subObj,subId):subId;
        const gwName=gwNames[gwId]||sid(gwId);
        
        // Line from right edge of subnet to left edge of gateway
        // Route: right of subnet -> trunk outside VPC -> gateway
        const trunkX=subPos.vpcX+subPos.vpcW+30;
        
        lines.push({
          id:'pvln_'+(lid++),lineType:'straight',
          stroke:{color:gc,width:1.5},
          endpoint1:{type:'shapeEndpoint',style:'none',shapeId:shapeIds[subId],position:{x:1,y:0.5}},
          endpoint2:{type:'shapeEndpoint',style:'arrow',shapeId:shapeIds[gwId],position:{x:0,y:0.5}},
          joints:[
            {x:trunkX,y:subPos.centerY},
            {x:trunkX,y:gwPos.centerY}
          ],
          customData:[
            {key:'From Subnet',value:subName},
            {key:'Subnet ID',value:subId},
            {key:'To Gateway',value:gwName},
            {key:'Gateway ID',value:gwId},
            {key:'Gateway Type',value:gwType},
            {key:'Route',value:r.DestinationCidrBlock||''}
          ]
        });
      });
    });
  });

  // --- shared gateways (TGW, PCX) centered BELOW all VPCs ---
  const maxVpcH=vpcInfos.length>0?Math.max(...vpcInfos.map(v=>v.vpcH)):200;
  const BUS_Y=VPC_TOP+maxVpcH+80; // horizontal routing channel
  const SHARED_ROW_Y=VPC_TOP+maxVpcH+200;
  
  // Use fixed width for shared gateways
  const sharedTotalW=sharedGws.length*(GW_W+60);
  let sharedStartX=Math.max(40,(vpcX-sharedTotalW)/2);
  const sharedGwPos={};
  let sharedCurX=sharedStartX;
  sharedGws.forEach((gw,i)=>{
    const nm=gwNames[gw.id]||sid(gw.id);
    const gwLabel=gw.type+': '+nm;
    const gc=gwColors2[gw.type]||'#546E7A';
    const gf=gwFills[gw.type]||'#F5F0FF';
    const gwShapeId='sgw_'+(lid++);
    shapeIds[gw.gwMapId]=gwShapeId;
    const gwX=sharedCurX;
    const thisGwW=GW_W;
    
    // Find connected VPCs
    const connectedVpcs=new Set();
    rts.forEach(rt=>{
      (rt.Routes||[]).forEach(r=>{
        if((r.TransitGatewayId===gw.id)||(r.VpcPeeringConnectionId===gw.id)){
          connectedVpcs.add(rt.VpcId);
        }
      });
    });
    
    let gwCustomData=[
      {key:'Gateway ID',value:gw.id},
      {key:'Type',value:gw.type==='TGW'?'Virtual WAN':gw.type==='PCX'?'VNet Peering':'Gateway'},
      {key:'Name',value:nm},
      {key:'Connected VNets',value:String(connectedVpcs.size)}
    ];
    
    // Add peering-specific info
    if(gw.type==='PCX'){
      const pcx=peerings.find(p=>p.VpcPeeringConnectionId===gw.id);
      if(pcx){
        gwCustomData.push({key:'Requester VPC',value:pcx.RequesterVpcInfo?.VpcId||''});
        gwCustomData.push({key:'Accepter VPC',value:pcx.AccepterVpcInfo?.VpcId||''});
        gwCustomData.push({key:'Status',value:pcx.Status?.Code||''});
      }
    }
    
    // Truncate text to fit
    const maxSChars=Math.floor((thisGwW-20)/9);
    const dispSText=gwLabel.length>maxSChars?gwLabel.substring(0,maxSChars-2)+'..':gwLabel;
    
    // Rectangle with text
    shapes.push({
      id:gwShapeId,type:'rectangle',
      boundingBox:{x:gwX,y:SHARED_ROW_Y,w:thisGwW,h:GW_H},
      text:'<p style="font-size:10pt;font-weight:bold;color:'+gc+';text-align:center">'+dispSText+'</p>',
      style:{stroke:{color:gc,width:2},fill:{type:'color',color:gf}},
      customData:gwCustomData
    });
    addIcon(gw.type,gwX+10,SHARED_ROW_Y+8);
    sharedGwPos[gw.gwMapId]={x:gwX,centerX:gwX+thisGwW/2,topY:SHARED_ROW_Y};
    sharedCurX+=thisGwW+60;
  });

  // --- LINES: Subnet -> shared TGW/PCX (per-subnet, routed around VPCs) ---
  // Track which subnet-gateway pairs we've drawn
  const subGwSeen=new Set();
  
  // Count lines per gateway for spreading connection points
  const gwLineCount={};
  rts.forEach(rt=>{
    const rtSubnets=rtToSubs[rt.RouteTableId]||[];
    (rt.Routes||[]).forEach(r=>{
      const tid=r.TransitGatewayId||r.VpcPeeringConnectionId;
      if(!tid)return;
      rtSubnets.forEach(subId=>{
        const ek=subId+'|'+tid;
        if(!subGwSeen.has(ek)){
          subGwSeen.add(ek);
          gwLineCount[tid]=(gwLineCount[tid]||0)+1;
        }
      });
    });
  });
  subGwSeen.clear();
  
  // Track current line index per gateway for spreading
  const gwLineIdx={};
  let globalLineIdx=0;
  
  rts.forEach(rt=>{
    const vId=rt.VpcId;
    if(!vpcPositions[vId])return;

    const rtSubnets=rtToSubs[rt.RouteTableId]||[];
    if(rtSubnets.length===0)return;

    (rt.Routes||[]).forEach(r=>{
      const tid=r.TransitGatewayId||r.VpcPeeringConnectionId;
      if(!tid||!shapeIds[tid]||!sharedGwPos[tid])return;
      const gc=gwColors2[gwSet2L.get(tid)?.type]||'#546E7A';
      const gwPos=sharedGwPos[tid];
      const totalLines=gwLineCount[tid]||1;

      rtSubnets.forEach(subId=>{
        const ek=subId+'|'+tid;
        if(subGwSeen.has(ek))return;
        subGwSeen.add(ek);
        
        const subPos=subnetPositions[subId];
        if(!subPos||!shapeIds[subId])return;
        
        // Get this line's index for this gateway
        if(gwLineIdx[tid]===undefined)gwLineIdx[tid]=0;
        const lineNum=gwLineIdx[tid]++;
        
        // Spread trunk lines across left margin of VPC
        const trunkX=subPos.vpcX-15-(subPos.subIndex%5)*4;
        
        // Spread bus Y levels
        const busYOff=globalLineIdx*2;
        
        // Spread connection points across gateway top (0.1 to 0.9)
        const spreadRatio=totalLines>1?lineNum/(totalLines-1):0.5;
        const gwConnectXRel=0.1+spreadRatio*0.8;
        
        // Get subnet and gateway names for line metadata
        const subObj=subnets.find(s=>s.SubnetId===subId);
        const subName=subObj?gn(subObj,subId):subId;
        const gwName=gwNames[tid]||sid(tid);
        
        lines.push({
          id:'ln_'+(lid++),lineType:'straight',
          stroke:{color:gc,width:1},
          endpoint1:{type:'shapeEndpoint',style:'none',shapeId:shapeIds[subId],position:{x:0,y:0.5}},
          endpoint2:{type:'shapeEndpoint',style:'arrow',shapeId:shapeIds[tid],position:{x:gwConnectXRel,y:0}},
          joints:[
            {x:trunkX,y:subPos.centerY},
            {x:trunkX,y:BUS_Y+busYOff},
            {x:gwPos.x+GW_W*gwConnectXRel,y:BUS_Y+busYOff}
          ],
          customData:[
            {key:'From Subnet',value:subName},
            {key:'Subnet ID',value:subId},
            {key:'To Gateway',value:gwName},
            {key:'Gateway ID',value:tid},
            {key:'Route Table',value:rt.RouteTableId||''}
          ]
        });
        globalLineIdx++;
      });
    });
  });

  // --- peering lines routed ABOVE VPCs ---
  const PEER_Y=VPC_TOP-30; // above all VPCs
  peerings.forEach((pcx,pi)=>{
    const state=String(pcx.Status?.Code||(pcx.properties||pcx).peeringState||'').toLowerCase();
    if(state&&!['active','connected'].includes(state))return;
    const rv=pcx.RequesterVpcInfo?.VpcId,av=pcx.AccepterVpcInfo?.VpcId;
    if(!shapeIds[rv]||!shapeIds[av])return;
    if(!vpcPositions[rv]||!vpcPositions[av])return;
    const vpcPosR=vpcPositions[rv];
    const vpcPosA=vpcPositions[av];
    
    // Get VPC names
    const vpcR=vpcs.find(v=>v.VpcId===rv);
    const vpcA=vpcs.find(v=>v.VpcId===av);
    const nameR=vpcR?gn(vpcR,rv):rv;
    const nameA=vpcA?gn(vpcA,av):av;
    
    // Get peering name
    const peerName=gn(pcx,pcx.VpcPeeringConnectionId)||pcx.VpcPeeringConnectionId;
    
    // Route via top edge of VPCs
    const exitXR=vpcPosR.x+vpcPosR.w*0.3+(pi%4)*20;
    const exitXA=vpcPosA.x+vpcPosA.w*0.7-(pi%4)*20;
    const peerYOff=pi*6;
    const midX=(exitXR+exitXA)/2;
    
    // Compute label dimensions first
    const maxPeerChars=35;
    const dispPeerName=peerName.length>maxPeerChars?peerName.substring(0,maxPeerChars-2)+'..':peerName;
    const labelW=Math.min(dispPeerName.length*9+32,320);
    const labelH=26;
    const labelX=midX-labelW/2;
    const labelY=PEER_Y-peerYOff-labelH/2;
    const labelPad=8;
    
    // Line segment 1: VPC R to label left edge
    lines.push({
      id:'pcx_L_'+(lid++),lineType:'straight',
      stroke:{color:COL.pcx,width:2,style:'dashed'},
      endpoint1:{type:'shapeEndpoint',style:'none',shapeId:shapeIds[rv],position:{x:0.3+(pi%4)*0.05,y:0}},
      endpoint2:{type:'positionEndpoint',style:'none',position:{x:labelX-labelPad,y:PEER_Y-peerYOff}},
      joints:[{x:exitXR,y:PEER_Y-peerYOff}],
      customData:[
        {key:'Peering ID',value:pcx.VpcPeeringConnectionId||''},
        {key:'Name',value:peerName},
        {key:'Requester VPC',value:nameR+' ('+rv+')'},
        {key:'Accepter VPC',value:nameA+' ('+av+')'},
        {key:'Status',value:pcx.Status?.Code||''}
      ]
    });
    
    // Line segment 2: label right edge to VPC A
    lines.push({
      id:'pcx_R_'+(lid++),lineType:'straight',
      stroke:{color:COL.pcx,width:2,style:'dashed'},
      endpoint1:{type:'positionEndpoint',style:'none',position:{x:labelX+labelW+labelPad,y:PEER_Y-peerYOff}},
      endpoint2:{type:'shapeEndpoint',style:'none',shapeId:shapeIds[av],position:{x:0.7-(pi%4)*0.05,y:0}},
      joints:[{x:exitXA,y:PEER_Y-peerYOff}]
    });
    
    // Label in the gap between line segments
    shapes.push({
      id:'pcxlbl_'+(lid++),type:'rectangle',
      boundingBox:{x:labelX,y:labelY,w:labelW,h:labelH},
      text:'<p style="font-size:10pt;color:'+COL.pcx+';text-align:center;font-weight:bold">'+dispPeerName+'</p>',
      style:{stroke:{color:COL.pcx,width:1.5},fill:{type:'color',color:'#FFFFFF'}}
    });
  });

  // --- Route 53 DNS Zones section ---
  if(zones.length>0){
    const pubZ=zones.filter(z=>!z.Config?.PrivateZone);
    const privZ=zones.filter(z=>z.Config?.PrivateZone);
    const dnsExp=(_detailLevel>=1);
    const dnsCols=dnsExp?1:2;
    const dnsColW=dnsExp?700:460;
    const dnsX=120;
    const dnsY=SHARED_ROW_Y+GW_H+80;
    const lzRecRowH=16,lzRecHdrH=18;

    const lzZoneHeights=[];
    zones.forEach(z=>{
      if(!dnsExp){lzZoneHeights.push(54);return}
      const isPub=!z.Config?.PrivateZone;
      const av=(!isPub&&z.VPCs)?z.VPCs.length:0;
      const zid=z.Id.replace('/hostedzone/','');
      const zR=recsByZone[zid]||[];
      let h=28;if(av)h+=lzRecRowH;
      if(zR.length>0)h+=lzRecHdrH+zR.length*lzRecRowH;
      lzZoneHeights.push(Math.max(54,h+12));
    });
    const lzZoneGap=8;
    let lzTotalZoneH=0;
    if(dnsExp){lzZoneHeights.forEach(h=>{lzTotalZoneH+=h+lzZoneGap})}
    else{lzTotalZoneH=Math.ceil(zones.length/dnsCols)*62}

    const dnsW=dnsCols*dnsColW+60;
    const dnsH=60+lzTotalZoneH+20;

    shapes.push({
      id:'dns_section',type:'rectangle',
      boundingBox:{x:dnsX,y:dnsY,w:dnsW,h:dnsH},
      text:NOTEXT,
      style:{stroke:{color:'#0ea5e9',width:2,style:'dashed'},fill:{type:'color',color:'#F0F9FF'}}
    });
    shapes.push({
      id:'dns_sec_title',type:'rectangle',
      boundingBox:{x:dnsX+10,y:dnsY+8,w:dnsW-20,h:30},
      text:'<p style="font-size:12pt;font-weight:bold;color:#0ea5e9;text-align:left">Azure DNS Private Zones ('+pubZ.length+' public, '+privZ.length+' private)</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
    });

    let lzCurY=dnsY+48;
    zones.forEach((z,zi)=>{
      const isPub=!z.Config?.PrivateZone;
      const zid=z.Id.replace('/hostedzone/','');
      const assocVpcs=(!isPub&&z.VPCs)?z.VPCs.map(v=>{
        const vid=v.VPCId||v.VpcId;
        const vpc=vpcs.find(vp=>vp.VpcId===vid);
        return gn(vpc||{},vid);
      }).join(', '):'';
      const zh=lzZoneHeights[zi];
      const zRecs=recsByZone[zid]||[];

      if(dnsExp){
        const zx=dnsX+20;
        const zCol=isPub?'#10b981':'#0ea5e9';
        shapes.push({
          id:'gdns_'+zi,type:'rectangle',
          boundingBox:{x:zx,y:lzCurY,w:dnsColW-20,h:zh},
          text:NOTEXT,
          style:{stroke:{color:zCol,width:1.5},fill:{type:'color',color:isPub?'#F0FDF4':'#F0F9FF'}},
          customData:[
            {key:'Zone ID',value:zid},{key:'Name',value:z.Name},
            {key:'Type',value:isPub?'Public':'Private'},
            {key:'Records',value:String(z.ResourceRecordSetCount)},
            {key:'Associated VPCs',value:assocVpcs||'N/A'}
          ]
        });
        shapes.push({
          id:'gdnslbl_'+zi+'a',type:'rectangle',
          boundingBox:{x:zx+6,y:lzCurY+4,w:dnsColW-32,h:18},
          text:'<p style="font-size:10pt;font-weight:bold;color:'+zCol+';text-align:left">'+(isPub?'[Public]':'[Private]')+' '+z.Name+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
        let ly=lzCurY+22;
        shapes.push({
          id:'gdnslbl_'+zi+'b',type:'rectangle',
          boundingBox:{x:zx+6,y:ly,w:dnsColW-32,h:lzRecRowH},
          text:'<p style="font-size:8pt;color:#64748B;text-align:left">'+z.ResourceRecordSetCount+' records | Zone ID: '+zid+' | Type: '+(isPub?'Public':'Private')+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
        ly+=lzRecRowH;
        if(assocVpcs){
          shapes.push({
            id:'gdnslbl_'+zi+'d',type:'rectangle',
            boundingBox:{x:zx+6,y:ly,w:dnsColW-32,h:lzRecRowH},
            text:'<p style="font-size:8pt;color:#64748B;text-align:left">VPCs: '+assocVpcs+'</p>',
            style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
          });
          ly+=lzRecRowH;
        }
        if(zRecs.length>0){
          shapes.push({
            id:'gdnshdr_'+zi,type:'rectangle',
            boundingBox:{x:zx+6,y:ly,w:dnsColW-32,h:lzRecHdrH},
            text:'<p style="font-size:7pt;font-weight:bold;color:#475569;text-align:left">NAME                                                  TYPE      VALUE</p>',
            style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
          });
          ly+=lzRecHdrH;
          zRecs.forEach((rec,ri)=>{
            const rName=rec.Name||'';
            const rType=rec.Type||'';
            const rVal=rec.AliasTarget?'ALIAS → '+rec.AliasTarget.DNSName:
              (rec.ResourceRecords||[]).map(rr=>rr.Value).join(', ');
            const ttl=rec.TTL!=null?'  TTL:'+rec.TTL:'';
            shapes.push({
              id:'gdnsrec_'+zi+'_'+ri,type:'rectangle',
              boundingBox:{x:zx+6,y:ly,w:dnsColW-32,h:lzRecRowH},
              text:'<p style="font-size:7pt;color:#334155;text-align:left;font-family:monospace">'+rName+' &nbsp; '+rType+' &nbsp; '+rVal+ttl+'</p>',
              style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
            });
            ly+=lzRecRowH;
          });
        }
        lzCurY+=zh+lzZoneGap;
      }else{
        const col=zi%dnsCols;
        const row=Math.floor(zi/dnsCols);
        const zx=dnsX+20+col*dnsColW;
        const zy=dnsY+48+row*62;
        shapes.push({
          id:'gdns_'+zi,type:'rectangle',
          boundingBox:{x:zx,y:zy,w:dnsColW-20,h:54},
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
          id:'gdnslbl_'+zi+'a',type:'rectangle',
          boundingBox:{x:zx+6,y:zy+4,w:dnsColW-32,h:22},
          text:'<p style="font-size:9pt;font-weight:bold;color:'+(isPub?'#10b981':'#0ea5e9')+';text-align:left">'+(isPub?'[Public]':'[Private]')+' '+z.Name+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
        shapes.push({
          id:'gdnslbl_'+zi+'b',type:'rectangle',
          boundingBox:{x:zx+6,y:zy+28,w:dnsColW-32,h:20},
          text:'<p style="font-size:8pt;color:#64748B;text-align:left">'+z.ResourceRecordSetCount+' records | '+zid+(assocVpcs?' | VPCs: '+assocVpcs:'')+'</p>',
          style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
        });
      }
    });
  }

  // --- Storage Accounts section ---
  if(s3bk.length>0){
    const s3Cols=3;
    const s3ColW=360;
    const s3W=s3Cols*s3ColW+60;
    const s3RowH=36;
    const s3Rows=Math.ceil(s3bk.length/s3Cols);
    const s3H=50+s3Rows*s3RowH+20;
    const s3X=120;
    const dnsExists=zones.length>0;
    const _lzDnsH=(function(){
      if(!dnsExists)return 0;
      const dExp=(_detailLevel>=1);const c=dExp?1:2;
      if(dExp){let th=0;zones.forEach(z=>{const ip=!z.Config?.PrivateZone;const av=(!ip&&z.VPCs)?z.VPCs.length:0;const zid=z.Id.replace('/hostedzone/','');const zR=recsByZone[zid]||[];let h=28;if(av)h+=16;if(zR.length>0)h+=18+zR.length*16;th+=Math.max(54,h+12)+8});return 60+th+20}
      return 60+Math.ceil(zones.length/c)*62+20;
    })();
    const s3Y=dnsExists?(SHARED_ROW_Y+GW_H+80+_lzDnsH+40):(SHARED_ROW_Y+GW_H+80);

    shapes.push({
      id:'s3_section',type:'rectangle',
      boundingBox:{x:s3X,y:s3Y,w:s3W,h:s3H},
      text:NOTEXT,
      style:{stroke:{color:'#EA580C',width:2,style:'dashed'},fill:{type:'color',color:'#FFF7ED'}}
    });
    shapes.push({
      id:'s3_sec_title',type:'rectangle',
      boundingBox:{x:s3X+10,y:s3Y+8,w:s3W-20,h:30},
      text:'<p style="font-size:12pt;font-weight:bold;color:#EA580C;text-align:left">Storage Accounts ('+s3bk.length+')</p>',
      style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
    });
    
    s3bk.forEach((bk,bi)=>{
      const col=bi%s3Cols;
      const row=Math.floor(bi/s3Cols);
      const bx=s3X+20+col*s3ColW;
      const by=s3Y+48+row*s3RowH;
      
      shapes.push({
        id:'gs3_'+bi,type:'rectangle',
        boundingBox:{x:bx,y:by,w:s3ColW-20,h:28},
        text:NOTEXT,
        style:{stroke:{color:'#EA580C',width:1},fill:{type:'color',color:'#FFFFFF'}},
        customData:[
          {key:'Bucket Name',value:bk.Name},
          {key:'Created',value:(bk.CreationDate||'N/A').split('T')[0]}
        ]
      });
      shapes.push({
        id:'gs3lbl_'+bi,type:'rectangle',
        boundingBox:{x:bx+4,y:by+2,w:s3ColW-28,h:24},
        text:'<p style="font-size:8pt;color:#232F3E;text-align:left">'+bk.Name+'</p>',
        style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF00'}}
      });
    });
  }

  // --- LEGEND ---
  const legendX=vpcX+40;
  const legendY=VPC_TOP+20;
  const LEGEND_W=220,LEGEND_H=100;
  shapes.push({
    id:'legend_box',type:'rectangle',
    boundingBox:{x:legendX,y:legendY,w:LEGEND_W,h:LEGEND_H},
    text:NOTEXT,
    style:{stroke:{color:'#546E7A',width:1},fill:{type:'color',color:'#FFFFFF'}}
  });
  shapes.push({
    id:'legend_title',type:'rectangle',
    boundingBox:{x:legendX+8,y:legendY+8,w:LEGEND_W-16,h:20},
    text:'<p style="font-size:11pt;font-weight:bold;color:#232F3E;text-align:left">Legend</p>',
    style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
  });
  // TGW line sample (solid)
  lines.push({
    id:'legend_tgw_line',lineType:'straight',
    stroke:{color:COL.tgw,width:2},
    endpoint1:{type:'positionEndpoint',style:'none',position:{x:legendX+12,y:legendY+45}},
    endpoint2:{type:'positionEndpoint',style:'arrow',position:{x:legendX+55,y:legendY+45}}
  });
  shapes.push({
    id:'legend_tgw_label',type:'rectangle',
    boundingBox:{x:legendX+62,y:legendY+36,w:150,h:20},
    text:'<p style="font-size:9pt;color:#232F3E;text-align:left">Transit Gateway</p>',
    style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
  });
  // PCX line sample (dashed)
  lines.push({
    id:'legend_pcx_line',lineType:'straight',
    stroke:{color:COL.pcx,width:2,style:'dashed'},
    endpoint1:{type:'positionEndpoint',style:'none',position:{x:legendX+12,y:legendY+75}},
    endpoint2:{type:'positionEndpoint',style:'none',position:{x:legendX+55,y:legendY+75}}
  });
  shapes.push({
    id:'legend_pcx_label',type:'rectangle',
    boundingBox:{x:legendX+62,y:legendY+66,w:150,h:20},
    text:'<p style="font-size:9pt;color:#232F3E;text-align:left">VPC Peering</p>',
    style:{stroke:{color:'#FFFFFF',width:0},fill:{type:'color',color:'#FFFFFF'}}
  });

  const doc={version:1,pages:[{id:'page1',title:'Azure-Network-Map',shapes,lines}]};
  return{doc,iconSet};
}

// #endregion LUCID NETWORK EXPORT
