// Normalization utilities extracted from app-core.js
// Purpose: Enable unit testing of Azure property mapping functions.
// These are pure functions with no DOM dependencies.

// Tag normalization: Azure {Name:"val"} → [{Key:"Name",Value:"val"}] array
function _normTags(r){
  if(!r)return;var tg=r.tags;
  if(tg&&!Array.isArray(tg)&&typeof tg==='object')r.Tags=Object.keys(tg).map(function(k){return{Key:k,Value:tg[k]||''}});
  if(!r.Tags&&!r.tags&&r.name)r.Tags=[{Key:'Name',Value:r.name}];
}

// Shared Azure normalization: maps Azure-native properties to internal format.
// Called from both _renderMapInner (textarea parse) and _buildRlCtxFromData (multi-view).
function _normalizeAzureResources(d){
  var allArrays=[d.vpcs,d.subnets,d.rts,d.sgs,d.enis,d.nats,d.vpces,d.instances,d.albs,d.tgs,d.peerings,d.vpns,d.volumes,d.snapshots,d.s3bk,d.zones,d.wafAcls,d.rdsInstances,d.ecsServices,d.lambdaFns,d.ecacheClusters,d.redshiftClusters,d.tgwAttachments,d.cfDistributions];
  allArrays.forEach(function(arr){if(arr)arr.forEach(function(r){
    _normTags(r);
    // Azure CLI flattens properties to top level; renderer expects properties.* wrapper.
    // Create self-reference so r.properties.routes === r.routes, etc.
    if(r&&!r.properties)r.properties=r;
    // Also add self-ref to nested arrays (ipConfigurations, securityRules, routes, etc.)
    // so nic.properties.ipConfigurations[0].properties.subnet.id resolves correctly
    ['ipConfigurations','securityRules','defaultSecurityRules','routes','frontendIPConfigurations',
     'gatewayIPConfigurations','backendPools','originGroups','backends','origins',
     'privateLinkServiceConnections','privateEndpointConnections','agentPoolProfiles',
     'virtualNetworkLinks','loadBalancingRules'].forEach(function(k){
      if(r[k]&&Array.isArray(r[k]))r[k].forEach(function(item){if(item&&typeof item==='object'&&!item.properties)item.properties=item});
    });
  })});
  // Property mappings
  if(d.vpcs)d.vpcs.forEach(function(v){if(!v.VpcId)v.VpcId=v.id||'';if(!v.CidrBlock)v.CidrBlock=(v.addressSpace&&v.addressSpace.addressPrefixes&&v.addressSpace.addressPrefixes[0])||''});
  if(d.subnets)d.subnets.forEach(function(s){if(!s.SubnetId)s.SubnetId=s.id||'';if(!s.VpcId)s.VpcId=(s.id||'').split('/subnets/')[0]||'';if(!s.CidrBlock)s.CidrBlock=s.addressPrefix||''});
  if(d.rts)d.rts.forEach(function(r){if(!r.RouteTableId)r.RouteTableId=r.id||'';if(!r.VpcId){var subs=r.subnets||[];if(subs[0]&&subs[0].id)r.VpcId=subs[0].id.split('/subnets/')[0]||''}if(!r.Routes&&r.routes)r.Routes=r.routes.map(function(rt){return{DestinationCidrBlock:rt.addressPrefix||'',GatewayId:rt.nextHopType||'',State:'active',_azRoute:rt}})});
  if(d.sgs)d.sgs.forEach(function(s){if(!s.GroupId)s.GroupId=s.id||'';if(!s.GroupName)s.GroupName=s.name||'';if(!s.VpcId&&s.subnets&&s.subnets[0]&&s.subnets[0].id)s.VpcId=s.subnets[0].id.split('/subnets/')[0]||'';if(!s.IpPermissions&&(s.securityRules||s.defaultSecurityRules)){var allRules=[].concat(s.securityRules||[]).concat(s.defaultSecurityRules||[]);s.IpPermissions=allRules.filter(function(r){return(r.direction||'').toLowerCase()==='inbound'}).map(function(r){return{IpProtocol:(r.protocol||'*').toLowerCase(),FromPort:r.destinationPortRange==='*'?0:parseInt(r.destinationPortRange)||0,ToPort:r.destinationPortRange==='*'?65535:parseInt((r.destinationPortRange||'').split('-').pop())||0,IpRanges:[{CidrIp:r.sourceAddressPrefix||'*'}],_azRule:r}});s.IpPermissionsEgress=allRules.filter(function(r){return(r.direction||'').toLowerCase()==='outbound'}).map(function(r){return{IpProtocol:(r.protocol||'*').toLowerCase(),FromPort:r.destinationPortRange==='*'?0:parseInt(r.destinationPortRange)||0,ToPort:r.destinationPortRange==='*'?65535:parseInt((r.destinationPortRange||'').split('-').pop())||0,IpRanges:[{CidrIp:r.destinationAddressPrefix||'*'}],_azRule:r}})}});
  if(d.enis)d.enis.forEach(function(e){if(!e.NetworkInterfaceId)e.NetworkInterfaceId=e.id||'';if(!e.SubnetId&&e.ipConfigurations&&e.ipConfigurations[0]&&e.ipConfigurations[0].subnet)e.SubnetId=e.ipConfigurations[0].subnet.id||'';if(!e.VpcId&&e.SubnetId)e.VpcId=(e.SubnetId||'').split('/subnets/')[0]||''});
  if(d.nats)d.nats.forEach(function(n){if(!n.NatGatewayId)n.NatGatewayId=n.id||'';if(!n.SubnetId&&n.subnets&&n.subnets[0])n.SubnetId=n.subnets[0].id||'';if(!n.VpcId&&n.SubnetId)n.VpcId=(n.SubnetId||'').split('/subnets/')[0]||''});
  if(d.vpces)d.vpces.forEach(function(v){if(!v.VpcEndpointId)v.VpcEndpointId=v.id||'';if(!v.ServiceName&&v.privateLinkServiceConnections&&v.privateLinkServiceConnections[0]){var plc=v.privateLinkServiceConnections[0];v.ServiceName=(plc.groupIds&&plc.groupIds[0])||plc.privateLinkServiceId||''}if(!v.SubnetId&&v.subnet)v.SubnetId=v.subnet.id||'';if(!v.VpcId&&v.SubnetId)v.VpcId=(v.SubnetId||'').split('/subnets/')[0]||''});
  if(d.instances)d.instances.forEach(function(i){if(!i.InstanceId)i.InstanceId=i.id||'';if(!i.InstanceType&&i.hardwareProfile)i.InstanceType=i.hardwareProfile.vmSize||'';if(!i.SubnetId&&i.networkProfile&&i.networkProfile.networkInterfaces&&i.networkProfile.networkInterfaces[0])i._nicId=i.networkProfile.networkInterfaces[0].id||''});
  if(d.albs)d.albs.forEach(function(a){if(!a.LoadBalancerArn)a.LoadBalancerArn=a.id||'';if(!a.LoadBalancerName)a.LoadBalancerName=a.name||'';if(!a.AvailabilityZones&&a.frontendIPConfigurations)a.AvailabilityZones=a.frontendIPConfigurations.filter(function(f){return f.subnet}).map(function(f){return{SubnetId:f.subnet.id||''}})});
  if(d.tgs)d.tgs.forEach(function(t){if(!t.TargetGroupArn)t.TargetGroupArn=t.id||'';if(!t.TargetGroupName)t.TargetGroupName=t.name||'';if(!t.LoadBalancerArns&&t.loadBalancingRules)t.LoadBalancerArns=t.loadBalancingRules.map(function(r){return(r.id||'').split('/loadBalancingRules/')[0]}).filter(Boolean)});
  if(d.peerings)d.peerings.forEach(function(p){if(!p.VpcPeeringConnectionId)p.VpcPeeringConnectionId=p.id||'';if(!p.RequesterVpcInfo&&p.localVirtualNetwork)p.RequesterVpcInfo={VpcId:p.localVirtualNetwork.id||'',CidrBlock:p.localAddressSpace&&p.localAddressSpace.addressPrefixes&&p.localAddressSpace.addressPrefixes[0]||''};if(!p.AccepterVpcInfo&&p.remoteVirtualNetwork)p.AccepterVpcInfo={VpcId:p.remoteVirtualNetwork.id||'',CidrBlock:p.remoteAddressSpace&&p.remoteAddressSpace.addressPrefixes&&p.remoteAddressSpace.addressPrefixes[0]||''};if(!p.Status&&p.peeringState)p.Status={Code:p.peeringState}});
  if(d.vpns)d.vpns.forEach(function(v){if(!v.VpnGatewayId)v.VpnGatewayId=v.virtualNetworkGateway1&&v.virtualNetworkGateway1.id||v.id||'';if(!v.State)v.State=v.connectionStatus||v.provisioningState||''});
  if(d.volumes)d.volumes.forEach(function(v){if(!v.VolumeId)v.VolumeId=v.id||'';if(!v.Size&&v.diskSizeGb)v.Size=v.diskSizeGb;if(!v.VolumeType&&v.sku)v.VolumeType=v.sku.name||'';if(!v.State)v.State=v.diskState||v.provisioningState||'';if(!v.Attachments&&v.managedBy)v.Attachments=[{InstanceId:v.managedBy}]});
  if(d.snapshots)d.snapshots.forEach(function(s){if(!s.SnapshotId)s.SnapshotId=s.id||'';if(!s.VolumeId&&s.creationData)s.VolumeId=s.creationData.sourceResourceId||'';if(!s.VolumeSize&&s.diskSizeGb)s.VolumeSize=s.diskSizeGb;if(!s.State)s.State=s.provisioningState||''});
  if(d.s3bk)d.s3bk.forEach(function(s){if(!s.Name)s.Name=s.name||''});
  if(d.zones)d.zones.forEach(function(z){if(!z.Id)z.Id=z.id||'';if(!z.Config)z.Config={PrivateZone:z.zoneType==='Private'}});
  if(d.wafAcls)d.wafAcls.forEach(function(w){if(!w.ResourceArns&&w.applicationGateways)w.ResourceArns=w.applicationGateways.map(function(a){return a.id||''})});
  if(d.rdsInstances)d.rdsInstances.forEach(function(r){if(!r.DBInstanceIdentifier)r.DBInstanceIdentifier=r.name||'';if(!r.DBInstanceClass&&r.sku)r.DBInstanceClass=r.sku.tier||r.sku.name||'';if(!r.Engine)r.Engine=r.version||r.kind||'SQL'});
  if(d.ecsServices)d.ecsServices.forEach(function(c){if(!c.serviceName)c.serviceName=c.name||'';if(!c.serviceArn)c.serviceArn=c.id||''});
  if(d.lambdaFns)d.lambdaFns.forEach(function(f){if(!f.FunctionName)f.FunctionName=f.name||'';if(!f.FunctionArn)f.FunctionArn=f.id||'';if(!f.Runtime){var lv=f.siteConfig&&f.siteConfig.linuxFxVersion;f.Runtime=lv||f.kind||''}if(!f.VpcConfig&&f.virtualNetworkSubnetId)f.VpcConfig={SubnetIds:[f.virtualNetworkSubnetId]}});
  if(d.ecacheClusters)d.ecacheClusters.forEach(function(c){if(!c.CacheClusterId)c.CacheClusterId=c.name||'';if(!c.Engine&&c.sku)c.Engine=c.sku.family||'Redis';if(!c.CacheNodeType&&c.sku)c.CacheNodeType=c.sku.capacity||'';if(!c.CacheClusterStatus)c.CacheClusterStatus=c.provisioningState||''});
  if(d.redshiftClusters)d.redshiftClusters.forEach(function(c){if(!c.ClusterIdentifier)c.ClusterIdentifier=c.name||'';if(!c.NumberOfNodes&&c.agentPoolProfiles&&c.agentPoolProfiles[0])c.NumberOfNodes=c.agentPoolProfiles[0].count||1;if(!c.NodeType&&c.agentPoolProfiles&&c.agentPoolProfiles[0])c.NodeType=c.agentPoolProfiles[0].vmSize||'';if(!c.ClusterStatus)c.ClusterStatus=c.provisioningState||''});
  if(d.tgwAttachments)d.tgwAttachments.forEach(function(t){if(!t.TransitGatewayId)t.TransitGatewayId=t.id||'';if(!t.State)t.State=t.provisioningState||''});
  if(d.cfDistributions)d.cfDistributions.forEach(function(c){if(!c.Id)c.Id=c.id||'';if(!c.DomainName&&c.frontendEndpoints&&c.frontendEndpoints[0])c.DomainName=c.frontendEndpoints[0].hostName||c.frontendEndpoints[0].name||''});
}

// filename-to-input mapping
const fileMap=[
  {id:'in_vnets',patterns:['vnet','vnets','virtual-network','virtualnetwork']},
  {id:'in_subnets',patterns:['subnet','subnets']},
  {id:'in_udrs',patterns:['route-table','route_table','routetable','udr','udrs']},
  {id:'in_nsgs',patterns:['nsg','nsgs','network-security-group','networksecuritygroup']},
  {id:'in_nics',patterns:['nic','nics','network-interface','networkinterface']},
  {id:'in_pubips',patterns:['public-ip','publicip','pip','pubip']},
  {id:'in_nats',patterns:['nat-gw','nat_gw','natgw','nat-gateway','nat_gateway','natgateway']},
  {id:'in_pvteps',patterns:['private-endpoint','privateendpoint','pvtep','private_endpoint']},
  {id:'in_azfws',patterns:['azfw','azure-firewall','azurefirewall','firewall']},
  {id:'in_bastions',patterns:['bastion','bastions','azure-bastion']},
  {id:'in_vms',patterns:['vm','vms','virtual-machine','virtualmachine']},
  {id:'in_albs',patterns:['appgw','app-gateway','applicationgateway','agw']},
  {id:'in_tgs',patterns:['lb','lbs','load-balancer','load_balancer','loadbalancer']},
  {id:'in_peer',patterns:['peering','vnet-peering','vnetpeering','peer']},
  {id:'in_vpn',patterns:['vpn','vpn-connection','vpn_connection']},
  {id:'in_disks',patterns:['disk','disks','managed-disk','manageddisk']},
  {id:'in_snaps',patterns:['snapshot','snapshots','snap']},
  {id:'in_storage',patterns:['storage-account','storageaccount','storage']},
  {id:'in_dnsz',patterns:['dns-zone','dnszone','dns']},
  {id:'in_r53records',patterns:['record-set','recordset','dns-record','dnsrecord']},
  {id:'in_waf',patterns:['waf','waf-policy','wafpolicy']},
  {id:'in_sql',patterns:['sql','sql-server','sqlserver']},
  {id:'in_containers',patterns:['container','containers','aci','containerinstance']},
  {id:'in_funcapps',patterns:['functionapp','func','function-app','funcapp']},
  {id:'in_elasticache',patterns:['redis','redis-cache','rediscache']},
  {id:'in_aks',patterns:['aks','kubernetes','k8s']},
  {id:'in_tgwatt',patterns:['vwan','virtual-wan','virtualwan']},
  {id:'in_cf',patterns:['frontdoor','front-door','afd','front_door']},
  {id:'in_rbac',patterns:['rbac','role-assignment','roleassignment']},
  {id:'in_rgs',patterns:['resource-group','resourcegroup','rg']},
  {id:'in_vnetgw',patterns:['vnet-gateway','vnetgateway','vnet_gateway','vpn-gateway','vpngateway']},
  {id:'in_expressrt',patterns:['express-route','expressroute','express_route','expressrt']},
  {id:'in_pdnslinks',patterns:['private-dns-link','privatednslink','pdns-link','private_dns_link']},
  {id:'in_aspans',patterns:['app-service-plan','appserviceplan','asp','app_service_plan']},
  {id:'in_webapps',patterns:['webapp','web-app','web_app','webapps','app-service','appservice']},
  {id:'in_cosmosdb',patterns:['cosmos','cosmosdb','cosmos-db','cosmos_db','documentdb']},
  {id:'in_keyvaults',patterns:['keyvault','key-vault','key_vault','kv']},
  {id:'in_svcbus',patterns:['service-bus','servicebus','service_bus','svcbus']},
  {id:'in_evhubs',patterns:['event-hub','eventhub','event_hub','eventhubs']},
  {id:'in_appinsights',patterns:['app-insight','appinsight','application-insight','app_insight']},
  {id:'in_acr',patterns:['acr','container-registry','containerregistry','container_registry']},
  {id:'in_batch',patterns:['batch','batch-account','batchaccount','batch_account']},
  {id:'in_avd',patterns:['virtual-desktop','virtualdesktop','hostpool','host-pool','avd']},
  {id:'in_cdn',patterns:['cdn','cdn-profile','cdnprofile']},
  {id:'in_trafficmgr',patterns:['traffic-manager','trafficmanager','traffic_manager','tm-profile']},
  {id:'in_privlink',patterns:['private-link-service','privatelinkservice','private_link_service','privlink']},
  {id:'in_ddos',patterns:['ddos','ddos-protection','ddosprotection','ddos_protection']},
  {id:'in_netapp',patterns:['netapp','netappfiles','netapp-files','netapp_files']},
  {id:'in_mysql',patterns:['mysql','mysql-server','mysqlserver','mysql_server']},
  {id:'in_postgres',patterns:['postgres','postgresql','postgres-server','postgresserver']},
  {id:'in_apim',patterns:['apim','api-management','apimanagement','api_management']},
  {id:'in_logicapps',patterns:['logic-app','logicapp','logic_app','logic-workflow']},
  {id:'in_signalr',patterns:['signalr','signal-r','signal_r']},
  {id:'in_relay',patterns:['relay','relay-namespace','relaynamespace']},
  {id:'in_adf',patterns:['data-factory','datafactory','data_factory','adf']},
  {id:'in_iothub',patterns:['iot-hub','iothub','iot_hub','iot']},
  {id:'in_loganalytics',patterns:['log-analytics','loganalytics','log_analytics','la-workspace']},
  {id:'in_actiongroups',patterns:['action-group','actiongroup','action_group']},
  {id:'in_metricalerts',patterns:['metric-alert','metricalert','metric_alert','metrics-alert']},
  {id:'in_automation',patterns:['automation','automation-account','automationaccount']},
  {id:'in_cognitive',patterns:['cognitive','cognitiveservices','cognitive-services','cognitive_services']},
  {id:'in_mlworkspace',patterns:['ml-workspace','mlworkspace','ml_workspace','machine-learning']},
  {id:'in_purview',patterns:['purview','purview-account','purviewaccount']},
  {id:'in_managedid',patterns:['managed-identity','managedidentity','managed_identity','identity']},
  {id:'in_policyassign',patterns:['policy-assignment','policyassignment','policy_assignment','policy']},
  {id:'in_arcmachines',patterns:['arc-machine','arcmachine','arc_machine','connectedmachine','arc']},
  {id:'in_recoveryvaults',patterns:['recovery-vault','recoveryvault','recovery_vault','backup-vault']},
  {id:'in_managedapps',patterns:['managed-app','managedapp','managed_app','managedapplication']},
  {id:'in_mapsaccts',patterns:['maps','maps-account','mapsaccount','azure-maps']},
];

function matchFile(fname, content){
  const base=fname.replace(/\.json$/i,'').toLowerCase().replace(/[^a-z0-9-_]/g,'');
  // Helper: check if content has a key (works for both objects and strings)
  function _hasKey(k){
    if(!content)return false;
    if(typeof content==='object')return k in content;
    return content.slice(0,500).includes('"'+k+'"');
  }
  // exact match first
  for(const fm of fileMap){
    for(const p of fm.patterns){if(base===p||base===p+'s')return fm.id}
  }
  // contains match: sort candidates by longest pattern first to avoid partial matches
  const candidates=[];
  for(const fm of fileMap){
    for(const p of fm.patterns){if(base.includes(p))candidates.push({id:fm.id,p,len:p.length})}
  }
  if(candidates.length){
    candidates.sort((a,b)=>b.len-a.len);
    const best=candidates[0].id;
    // content-override: verify filename match doesn't contradict content
    if(content){
      if(best==='in_vms'){
        if(_hasKey('servers')&&!_hasKey('virtualMachines'))return 'in_sql';
        if(_hasKey('CacheClusters')||_hasKey('redisConfiguration'))return 'in_elasticache';
      }
      // Verify critical inputs have expected Azure key: reject mismatched content
      // Accept flat arrays (az CLI -o json) OR wrapped {value:[...]} format
      const expectedKey={in_udrs:'value',in_vnets:'value',in_subnets:'value',in_nsgs:'value',in_nics:'value'};
      if(expectedKey[best]&&!_hasKey(expectedKey[best])){
        // Allow flat arrays: check if content starts with '[' (az CLI direct output)
        const trimmed=typeof content==='string'?content.trimStart():'';
        if(!trimmed.startsWith('['))return null;
      }
    }
    return best;
  }
  // content-based fallback: detect by JSON keys
  if(content){
    if(_hasKey('virtualMachines')||(_hasKey('value')&&_hasKey('osProfile')))return 'in_vms';
    if(_hasKey('servers')&&_hasKey('administratorLogin'))return 'in_sql';
    if(_hasKey('addressSpace')||(_hasKey('value')&&_hasKey('addressSpace')))return 'in_vnets';
    if(_hasKey('addressPrefix')&&_hasKey('networkSecurityGroup'))return 'in_subnets';
    if(_hasKey('securityRules'))return 'in_nsgs';
    if(_hasKey('routes')&&_hasKey('disableBgpRoutePropagation'))return 'in_udrs';
    if(_hasKey('privateIPAddress')&&_hasKey('macAddress'))return 'in_nics';
    if(_hasKey('natRuleCollections'))return 'in_azfws';
    if(_hasKey('dnsSettings')&&_hasKey('publicIPAllocationMethod'))return 'in_pubips';
    if(_hasKey('natGatewayTimeout'))return 'in_nats';
    if(_hasKey('privateLinkServiceConnections'))return 'in_pvteps';
    if(_hasKey('bastionHostPropertiesFormat'))return 'in_bastions';
    if(_hasKey('applicationGatewayIPConfigurations'))return 'in_albs';
    if(_hasKey('frontendIPConfigurations')&&_hasKey('loadBalancingRules'))return 'in_tgs';
    if(_hasKey('peeringState')&&_hasKey('remoteVirtualNetwork'))return 'in_peer';
    if(_hasKey('vpnConnectionType'))return 'in_vpn';
    if(_hasKey('diskSizeGB')&&_hasKey('diskState'))return 'in_disks';
    if(_hasKey('snapshotType'))return 'in_snaps';
    if(_hasKey('primaryEndpoints')&&_hasKey('accountType'))return 'in_storage';
    if(_hasKey('zoneType')&&_hasKey('nameServers'))return 'in_dnsz';
    if(_hasKey('TTL')&&_hasKey('fqdn'))return 'in_r53records';
    if(_hasKey('policySettings')&&_hasKey('managedRules'))return 'in_waf';
    if(_hasKey('vnetType')&&_hasKey('type')&&_hasKey('allowVnetToVnetTraffic'))return 'in_tgwatt';
    if(_hasKey('frontendEndpoints')&&_hasKey('backendPools'))return 'in_cf';
    if(_hasKey('hostNames')&&_hasKey('functionAppConfig'))return 'in_funcapps';
    if(_hasKey('redisConfiguration'))return 'in_elasticache';
    if(_hasKey('agentPoolProfiles')&&_hasKey('kubernetesVersion'))return 'in_aks';
    if(_hasKey('containers')&&_hasKey('osType')&&!_hasKey('agentPoolProfiles'))return 'in_containers';
    if(_hasKey('roleDefinitionId')&&_hasKey('principalId'))return 'in_rbac';
    if(_hasKey('managedBy')&&_hasKey('properties')&&_hasKey('provisioningState'))return 'in_rgs';
  }
  return null;
}

function _friendlyFolderLabel(folderName){
  if(!folderName)return null;
  // "azure-export-lmat-PROD-20260330-075242" → "lmat-PROD"
  // "azure-export-bddb1488-285c-419e-adfa-b336450de7a3-20260330-080034" → truncated sub ID
  var m=folderName.match(/^azure-export-(.+?)-\d{8}-\d{6}$/);
  if(m){
    var sub=m[1];
    // If it's a GUID (subscription ID), truncate it
    if(/^[0-9a-f]{8}-[0-9a-f]{4}-/.test(sub))return sub.substring(0,13)+'...';
    return sub;
  }
  // Truncate any long folder name
  return folderName.length>30?folderName.substring(0,27)+'...':folderName;
}

// Exports for unit testing (pure functions + constants)
export { _normalizeAzureResources, _normTags, matchFile, fileMap, _friendlyFolderLabel };
