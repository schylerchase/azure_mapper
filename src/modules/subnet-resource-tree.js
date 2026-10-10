// Subnet resource tree owns the per-subnet service inventory shown in topology and flow tracing.
var SubnetResourceTree=(function(){
  function nestedEnabled(ctx){
    if(ctx&&typeof ctx.showNested==='boolean')return ctx.showNested;
    return typeof _showNested==='undefined'?true:_showNested;
  }

  function storageInfo(sa,link){
    if(typeof _storageInfo==='function'&&typeof _saId==='function'&&typeof _saName==='function'){
      return _storageInfo(sa,{linksByStorageId:{[(_saId(sa).toLowerCase()||_saName(sa).toLowerCase())]:[link]}});
    }
    return{
      services:['blob'],
      access:link&&link.via||'Storage',
      color:'#0078d4',
      bg:'rgba(0,120,212,.12)',
      sku:'',
      tls:'',
      httpsOnly:true
    };
  }

  function storageId(sa){
    if(typeof _saId==='function')return _saId(sa);
    return(sa&&sa.id)||sa?.ResourceId||sa?.Arn||'';
  }

  function storageName(sa){
    if(typeof _saName==='function')return _saName(sa);
    return(sa&&sa.Name)||sa?.name||storageId(sa).split('/').filter(Boolean).pop()||'storage';
  }

  function buildResTree(subId,ctx){
    ctx=ctx||{};
    const res=[];
    const {instBySub={},albBySub={},rdsBySub={},ecsBySub={},lambdaBySub={},volByInst={},volBySub={},enis=[],eniByInst={},tgByAlb={},wafByAlb={},cfByAlb={},snapByVol={},eniBySub={},storageBySub={}}=ctx;
    const showNested=nestedEnabled(ctx);
    const attachedEnis=new Set();

    (instBySub[subId]||[]).forEach(inst=>{
      const ch=[];
      if(showNested){
        const ie=(eniByInst||{})[inst.InstanceId]||[];
        ie.forEach(e=>{attachedEnis.add(e.NetworkInterfaceId);ch.push({type:'NIC',name:e.NetworkInterfaceId.slice(-8),detail:e.PrivateIpAddress||'',col:'#3b82f6',bg:'rgba(59,130,246,.08)'})});
        (volByInst[inst.InstanceId]||[]).forEach(v=>{
          const sc=(snapByVol[v.VolumeId]||[]).length;
          ch.push({type:'VOL',name:v.Size+'GB '+(v.VolumeType||''),detail:sc?sc+' snap':'',col:'#f59e0b',bg:'rgba(245,158,11,.08)'});
        });
      }else{
        const ie=(eniByInst||{})[inst.InstanceId]||[];
        ie.forEach(e=>attachedEnis.add(e.NetworkInterfaceId));
      }
      res.push({type:'VM',name:inst.Tags?.find(t=>t.Key==='Name')?.Value||inst.InstanceId?.slice(-8),state:inst.State?.Name,ip:inst.PrivateIpAddress||'',col:'#10b981',bg:'rgba(16,185,129,.12)',children:ch,
        rid:inst.InstanceId,itype:inst.InstanceType||'',sgIds:(inst.SecurityGroups||[]).map(s=>s.GroupName||s.GroupId).join(', ')});
    });

    (albBySub[subId]||[]).forEach(lb=>{
      const ch=[];
      if(showNested){
        ((tgByAlb||{})[lb.LoadBalancerArn]||[]).forEach(tg=>ch.push({type:'TG',name:tg.TargetGroupName||'TG',detail:(tg.Targets||[]).length+' tgt',col:'#06b6d4',bg:'rgba(6,182,212,.08)'}));
        ((wafByAlb||{})[lb.LoadBalancerArn]||[]).forEach(w=>ch.push({type:'WAF',name:w.Name||'WAF',detail:(w.Rules||[]).length+' rules',col:'#eab308',bg:'rgba(234,179,8,.08)'}));
        (((cfByAlb||{})[lb.LoadBalancerArn])||[]).forEach(cf=>ch.push({type:'CF',name:cf.DomainName||'CF',detail:'',col:'#8b5cf6',bg:'rgba(139,92,246,.08)'}));
      }
      res.push({type:'App Gateway',name:lb.LoadBalancerName||'ALB',ip:lb.Scheme||'',col:'#38bdf8',bg:'rgba(56,189,248,.12)',children:ch,
        rid:lb.LoadBalancerArn?.split('/').pop()||'',lbType:lb.Type||'application',sgIds:(lb.SecurityGroups||[]).join(', ')});
    });

    (rdsBySub[subId]||[]).forEach(db=>res.push({type:'SQL',name:db.DBInstanceIdentifier||'SQL',ip:db.Engine||'',col:'#3b82f6',bg:'rgba(59,130,246,.12)',children:[],
      rid:db.DBInstanceIdentifier,itype:db.DBInstanceClass||'',extra:db.EngineVersion||''}));
    (ecsBySub[subId]||[]).forEach(svc=>res.push({type:'Container',name:svc.serviceName||'Container',ip:svc.launchType||'',col:'#f97316',bg:'rgba(249,115,22,.12)',children:[],
      rid:svc.serviceName,extra:'Tasks: '+(svc.runningCount||0)+'/'+(svc.desiredCount||0)}));
    (lambdaBySub[subId]||[]).forEach(fn=>res.push({type:'FN',name:fn.FunctionName||'FuncApp',ip:fn.Runtime||'',col:'#a855f7',bg:'rgba(168,85,247,.12)',children:[],
      rid:fn.FunctionName,extra:fn.MemorySize?fn.MemorySize+'MB':''}));

    (eniBySub[subId]||[]).forEach(e=>{
      if(attachedEnis.has(e.NetworkInterfaceId))return;
      res.push({type:'NIC',name:e.NetworkInterfaceId.slice(-8),ip:e.PrivateIpAddress||'',col:'#3b82f6',bg:'rgba(59,130,246,.12)',children:[],
        rid:e.NetworkInterfaceId,extra:e.Description||'',sgIds:(e.Groups||[]).map(g=>g.GroupName||g.GroupId).join(', ')});
    });

    ((volBySub||{})[subId]||[]).forEach(v=>{
      const sc=((snapByVol||{})[v.VolumeId]||[]).length;
      const att=(v.Attachments||[])[0];
      res.push({type:'VOL',name:v.Size+'GB '+(v.VolumeType||''),ip:att?att.InstanceId?.slice(-8)||'':'detached',
        col:'#f59e0b',bg:'rgba(245,158,11,.12)',children:[],
        rid:v.VolumeId,extra:(v.State||'')+(sc?' - '+sc+' snap':'')});
    });

    ((ctx.peBySub||{})[subId]||[]).forEach(pe=>{
      const nm=pe.name||pe.id;
      const conn=pe.properties?.privateLinkServiceConnections?.[0];
      const groupId=(conn?.properties?.groupIds||[])[0]||'';
      const state=conn?.properties?.privateLinkServiceConnectionState?.status||'Approved';
      const ip=(pe.properties?.customDnsConfigs||[])[0]?.ipAddresses?.[0]||'';
      const stateCol=state==='Approved'?'#10b981':state==='Pending'?'#f59e0b':'#ef4444';
      res.push({type:'PE',name:nm,ip:ip,col:'#a78bfa',bg:'rgba(167,139,250,.12)',children:[],
        rid:pe.id,extra:groupId,state:state,stateDot:stateCol});
    });

    ((storageBySub||{})[subId]||[]).forEach(link=>{
      const sa=link.account||link;
      const info=storageInfo(sa,link);
      const ch=[];
      if(showNested){
        info.services.slice(0,4).forEach(svc=>ch.push({type:svc.slice(0,4).toUpperCase(),name:link.detail||info.access,detail:'',col:info.color,bg:info.bg}));
      }
      res.push({type:'STG',fullType:'Storage Account',name:storageName(sa),ip:link.via,col:info.color,bg:info.bg,children:ch,
        rid:storageId(sa),itype:info.sku,extra:[info.access,info.tls,info.httpsOnly?'HTTPS':'HTTP allowed'].filter(Boolean).join(' - ')});
    });

    return res;
  }

  function subMaxChildren(subId,ctx){
    const tree=buildResTree(subId,ctx);
    return tree.length?Math.max(0,...tree.map(r=>(r.children||[]).length)):0;
  }

  return{buildResTree,subMaxChildren};
})();

function buildResTree(subId,ctx){return SubnetResourceTree.buildResTree(subId,ctx)}
function subMaxChildren(subId,ctx){return SubnetResourceTree.subMaxChildren(subId,ctx)}

if(typeof module!=='undefined'&&module.exports){
  module.exports=SubnetResourceTree;
}
