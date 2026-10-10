// LucidNetworkExportData owns Azure Mapper input collection and relationship
// indexes for Lucid standard and landing-zone exports.
var LucidNetworkExportData = (function(){
  function readInput(id, paths){
    return ext(safeParse(gv(id)), paths);
  }

  function pushByKey(index, key, value){
    if(!key) return;
    (index[key]=index[key]||[]).push(value);
  }

  function collect(){
    var vpcs=readInput('in_vnets',['value','VirtualNetworks']);
    var subnets=readInput('in_subnets',['value','Subnets']);
    var rts=readInput('in_udrs',['value','RouteTables']);
    var sgs=readInput('in_nsgs',['value','SecurityGroups']);
    var nacls=[];
    var igws=[];
    var nats=readInput('in_nats',['value','NatGateways']);
    var vpceList=readInput('in_pvteps',['value','PrivateEndpoints']);
    var peerings=readInput('in_peer',['value','VirtualNetworkPeerings']);
    var volumes=readInput('in_disks',['value','Volumes']);
    var snapshots=readInput('in_snaps',['value','Snapshots']);
    var storageRaw=safeParse(gv('in_storage'));
    var s3bk=storageRaw?ext(storageRaw,['value','StorageAccounts']):[];
    var zones=readInput('in_dnsz',['value','PrivateZones']);
    var allRecordSets=readInput('in_r53records',['value','RecordSets']);
    var instances=readInput('in_vms',['value']);
    var albs=readInput('in_albs',['value','LoadBalancers']);
    var tgs=readInput('in_tgs',['value','BackendPools']);
    var enis=readInput('in_nics',['value','NetworkInterfaces']);
    var wafAcls=readInput('in_waf',['value','WebACLs']);
    var rdsInstances=readInput('in_sql',['value','DBInstances']);
    var ecsServices=readInput('in_containers',['value']);
    var lambdaFns=readInput('in_funcapps',['value']).filter(function(fn){return (fn.properties||fn).siteConfig});
    var cfDistributions=readInput('in_cf',['value','FrontDoors']);

    _normalizeAzureResources({vpcs:vpcs,subnets:subnets,rts:rts,sgs:sgs,enis:enis,nats:nats,vpces:vpceList,
      instances:instances,albs:albs,tgs:tgs,peerings:peerings,volumes:volumes,snapshots:snapshots,
      s3bk:s3bk,zones:zones,wafAcls:wafAcls,rdsInstances:rdsInstances,ecsServices:ecsServices,
      lambdaFns:lambdaFns,cfDistributions:cfDistributions});
    peerings.forEach(function(peer){
      var native=peer.properties||peer;
      var localId=(native.localVirtualNetwork||{}).id||((peer.id||'').match(/^(.*)\/virtualNetworkPeerings\//i)||[])[1];
      if(!peer.RequesterVpcInfo&&localId)peer.RequesterVpcInfo={VpcId:localId};
    });

    var indexes=buildRelationshipIndexes({
      vpcs:vpcs,subnets:subnets,rts:rts,sgs:sgs,nacls:nacls,volumes:volumes,
      snapshots:snapshots,allRecordSets:allRecordSets,instances:instances,
      albs:albs,tgs:tgs,enis:enis,wafAcls:wafAcls,rdsInstances:rdsInstances,
      ecsServices:ecsServices,lambdaFns:lambdaFns,cfDistributions:cfDistributions
    });
    var gateways=buildGatewayGroups({rts:rts,igws:igws,nats:nats,vpceList:vpceList});
    var activeVpcs=vpcs.filter(function(vpc){return (indexes.subByVnet[vpc.VpcId]||[]).length>0});

    return Object.assign({
      vpcs:vpcs,subnets:subnets,rts:rts,sgs:sgs,nacls:nacls,igws:igws,nats:nats,
      vpceList:vpceList,peerings:peerings,volumes:volumes,snapshots:snapshots,
      s3bk:s3bk,zones:zones,instances:instances,albs:albs,tgs:tgs,enis:enis,
      wafAcls:wafAcls,rdsInstances:rdsInstances,ecsServices:ecsServices,
      lambdaFns:lambdaFns,cfDistributions:cfDistributions,activeVpcs:activeVpcs,
      layoutMode:(document.getElementById('layoutMode')&&document.getElementById('layoutMode').value)||'grid',
      userHubName:((document.getElementById('hubVpcName')&&document.getElementById('hubVpcName').value)||'').toLowerCase().trim()
    }, indexes, gateways);
  }

  function buildRelationshipIndexes(data){
    var subByVnet={};
    data.subnets.forEach(function(subnet){pushByKey(subByVnet,subnet.VpcId,subnet)});

    var nsgByVnet={};
    data.sgs.forEach(function(nsg){pushByKey(nsgByVnet,nsg.VpcId,nsg)});

    var subNacl={};
    data.nacls.forEach(function(nacl){
      (nacl.Associations||[]).forEach(function(assoc){if(assoc.SubnetId)subNacl[assoc.SubnetId]=nacl});
    });

    var exMainRT={};
    data.rts.forEach(function(rt){if((rt.Associations||[]).some(function(assoc){return assoc.Main}))exMainRT[rt.VpcId]=rt});

    var subRT={};
    data.rts.forEach(function(rt){
      (rt.Associations||[]).forEach(function(assoc){if(assoc.SubnetId)subRT[assoc.SubnetId]=rt});
    });
    data.subnets.forEach(function(subnet){if(!subRT[subnet.SubnetId]&&exMainRT[subnet.VpcId])subRT[subnet.SubnetId]=exMainRT[subnet.VpcId]});

    var instBySub={};
    data.instances.forEach(function(instance){pushByKey(instBySub,instance.SubnetId,instance)});

    var eniBySub={};
    var instSubFromEni={};
    data.enis.forEach(function(eni){
      pushByKey(eniBySub,eni.SubnetId,eni);
      if(eni.SubnetId&&eni.Attachment&&eni.Attachment.InstanceId)instSubFromEni[eni.Attachment.InstanceId]=eni.SubnetId;
    });

    var albBySub={};
    data.albs.forEach(function(lb){
      (lb.AvailabilityZones||[]).forEach(function(az){pushByKey(albBySub,az.SubnetId,lb)});
    });

    var volByInst={};
    data.volumes.forEach(function(volume){
      (volume.Attachments||[]).forEach(function(attachment){pushByKey(volByInst,attachment.InstanceId,volume)});
    });

    var knownInstIds=new Set(data.instances.map(function(instance){return instance.InstanceId}));
    var volBySub={};
    data.volumes.forEach(function(volume){
      var attachment=(volume.Attachments||[])[0];
      if(!attachment||!attachment.InstanceId||knownInstIds.has(attachment.InstanceId))return;
      pushByKey(volBySub,instSubFromEni[attachment.InstanceId],volume);
    });

    var snapByVol={};
    data.snapshots.forEach(function(snapshot){pushByKey(snapByVol,snapshot.VolumeId,snapshot)});

    var tgByAlb={};
    data.tgs.forEach(function(tg){
      (tg.LoadBalancerArns||[]).forEach(function(arn){pushByKey(tgByAlb,arn,tg)});
    });

    var wafByAlb={};
    data.wafAcls.forEach(function(acl){
      (acl.ResourceArns||[]).forEach(function(arn){pushByKey(wafByAlb,arn,acl)});
    });

    var rdsBySub={};
    data.rdsInstances.forEach(function(db){
      var subnetGroup=db.DBSubnetGroup;
      if(!subnetGroup)return;
      (subnetGroup.Subnets||[]).forEach(function(subnet){pushByKey(rdsBySub,subnet.SubnetIdentifier,db)});
    });

    var ecsBySub={};
    data.ecsServices.forEach(function(service){
      var network=(service.networkConfiguration||{}).awsvpcConfiguration;
      if(!network)return;
      (network.subnets||[]).forEach(function(subnetId){pushByKey(ecsBySub,subnetId,service)});
    });

    var lambdaBySub={};
    data.lambdaFns.forEach(function(fn){
      ((fn.VpcConfig||{}).SubnetIds||[]).forEach(function(subnetId){pushByKey(lambdaBySub,subnetId,fn)});
    });

    var cfByAlb={};
    data.cfDistributions.forEach(function(cf){
      ((cf.Origins||{}).Items||[]).forEach(function(origin){
        var domain=origin.DomainName||'';
        data.albs.forEach(function(lb){
          if(lb.DNSName&&domain.includes(lb.DNSName))pushByKey(cfByAlb,lb.LoadBalancerArn,cf);
        });
      });
    });

    var recsByZone={};
    data.allRecordSets.forEach(function(record){pushByKey(recsByZone,record.id,record)});

    var pubSubs=buildPublicSubnetSet(data.rts,data.subnets,exMainRT);
    return {
      subByVnet:subByVnet,nsgByVnet:nsgByVnet,subNacl:subNacl,subRT:subRT,
      instBySub:instBySub,eniBySub:eniBySub,albBySub:albBySub,volByInst:volByInst,
      volBySub:volBySub,snapByVol:snapByVol,tgByAlb:tgByAlb,wafByAlb:wafByAlb,
      rdsBySub:rdsBySub,ecsBySub:ecsBySub,lambdaBySub:lambdaBySub,cfByAlb:cfByAlb,
      recsByZone:recsByZone,pubSubs:pubSubs
    };
  }

  function buildPublicSubnetSet(rts,subnets,exMainRT){
    var pubSubs=new Set();
    rts.forEach(function(rt){
      var hasIgw=(rt.Routes||[]).some(function(route){return _isIgwRoute(route.GatewayId)&&route.State!=='blackhole'});
      (rt.Associations||[]).forEach(function(assoc){if(assoc.SubnetId&&hasIgw)pubSubs.add(assoc.SubnetId)});
    });
    subnets.forEach(function(subnet){
      if(pubSubs.has(subnet.SubnetId)||!exMainRT[subnet.VpcId])return;
      var hasIgw=(exMainRT[subnet.VpcId].Routes||[]).some(function(route){return _isIgwRoute(route.GatewayId)&&route.State!=='blackhole'});
      if(hasIgw)pubSubs.add(subnet.SubnetId);
    });
    return pubSubs;
  }

  function buildGatewayGroups(data){
    var gwSet2L=new Map();
    data.rts.forEach(function(rt){
      (rt.Routes||[]).forEach(function(route){
        if(route.GatewayId&&route.GatewayId!=='local')gwSet2L.set(route.GatewayId,{type:clsGw(route.GatewayId),id:route.GatewayId,vpcId:rt.VpcId});
        if(route.NatGatewayId)gwSet2L.set(route.NatGatewayId,{type:'NAT',id:route.NatGatewayId,vpcId:rt.VpcId});
        if(route.TransitGatewayId)gwSet2L.set(route.TransitGatewayId,{type:'TGW',id:route.TransitGatewayId,vpcId:'shared'});
        if(route.VpcPeeringConnectionId)gwSet2L.set(route.VpcPeeringConnectionId,{type:'PCX',id:route.VpcPeeringConnectionId,vpcId:'shared'});
      });
    });
    data.igws.forEach(function(gateway){
      if(gwSet2L.has(gateway.InternetGatewayId))return;
      var attachment=(gateway.Attachments||[])[0];
      gwSet2L.set(gateway.InternetGatewayId,{type:'IGW',id:gateway.InternetGatewayId,vpcId:attachment?attachment.VpcId:'unk'});
    });
    data.nats.forEach(function(gateway){
      if(!gwSet2L.has(gateway.NatGatewayId))gwSet2L.set(gateway.NatGatewayId,{type:'NAT',id:gateway.NatGatewayId,vpcId:gateway.VpcId||'unk'});
    });

    var gwByVpc={};
    var sharedGws=[];
    gwSet2L.forEach(function(gw,gwId){
      if(gw.type==='VPCE')return;
      if(gw.vpcId==='shared'){
        sharedGws.push(Object.assign({},gw,{gwMapId:gwId}));
        return;
      }
      pushByKey(gwByVpc,gw.vpcId,Object.assign({},gw,{gwMapId:gwId}));
    });

    var vpceByVpc={};
    gwSet2L.forEach(function(gw){if(gw.type==='VPCE')pushByKey(vpceByVpc,gw.vpcId,gw)});
    data.vpceList.forEach(function(endpoint){
      if(!vpceByVpc[endpoint.VpcId])vpceByVpc[endpoint.VpcId]=[{type:'VPCE',id:endpoint.VpcEndpointId,vpcId:endpoint.VpcId}];
    });

    return {gwSet2L:gwSet2L,gwByVpc:gwByVpc,sharedGws:sharedGws,vpceByVpc:vpceByVpc};
  }

  return {collect: collect};
})();
