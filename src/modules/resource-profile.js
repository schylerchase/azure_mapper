// ResourceProfile owns pure Azure resource type resolution and detail summaries.
var ResourceProfile = (function(){
  function findById(items, id){
    return (items || []).find(function(item){
      return item && (item.id === id || item.name === id || item.SubnetId === id ||
        item.VpcId === id || item.InstanceId === id || item.GroupId === id ||
        item.NatGatewayId === id || item.InternetGatewayId === id);
    });
  }

  function propsOf(resource){
    return resource && (resource.properties || resource._azure && resource._azure.properties) || {};
  }

  function resolveResourceType(ctx, id){
    if(!id || !ctx) return null;
    var low = String(id).toLowerCase();
    if(low.includes('/virtualnetworks/') && !low.includes('/subnets/')) return 'VNet';
    if(low.includes('/subnets/')) return 'Subnet';
    if(low.includes('/virtualmachines/')) return 'VM';
    if(low.includes('/networksecuritygroups/')) return 'NSG';
    if(low.includes('/natgateways/')) return 'NAT Gateway';
    if(low.includes('/privateendpoints/')) return 'Private Endpoint';
    if(low.includes('/virtualnetworkgateways/')) return 'VPN Gateway';
    if(low.includes('/applicationgateways/')) return 'App Gateway';
    if(low.includes('/loadbalancers/')) return 'Load Balancer';
    if(low.includes('/virtualnetworkpeerings/')) return 'VNet Peering';
    if(low.includes('/routetables/')) return 'UDR';
    if(low.includes('/networkinterfaces/')) return 'NIC';
    if(low.includes('/disks/')) return 'Managed Disk';
    if(low.includes('/storageaccounts/')) return 'Storage Account';
    if(low.includes('/dnszones/')) return 'DNS Zone';
    if(low.includes('/managedclusters/')) return 'AKS';
    if(low.includes('/azurefirewalls/')) return 'Firewall';
    if(low.includes('/bastionhosts/')) return 'Bastion';
    if(findById(ctx.vnets, id) || findById(ctx.vpcs, id)) return 'VNet';
    if(findById(ctx.subnets, id)) return 'Subnet';
    if(findById(ctx.vms, id) || findById(ctx.instances, id)) return 'VM';
    if(findById(ctx.sqlServers, id)) return 'SQL Server';
    if(findById(ctx.functionApps, id)) return 'Function App';
    if(findById(ctx.containerInstances, id)) return 'Container Instance';
    if(findById(ctx.redisCaches, id)) return 'Redis Cache';
    if(findById(ctx.synapseWorkspaces, id)) return 'Synapse Workspace';
    if(findById(ctx.nsgs, id)) return 'NSG';
    return null;
  }

  function findResourceByType(ctx, type, id){
    var map = {
      'VM': ctx.vms || ctx.instances,
      'NSG': ctx.nsgs,
      'NAT Gateway': ctx.natGateways,
      'Private Endpoint': ctx.privateEndpoints,
      'VPN Gateway': ctx.vpns,
      'App Gateway': ctx.appGateways,
      'Load Balancer': ctx.loadBalancers,
      'UDR': ctx.udrs || ctx.rts,
      'NIC': ctx.nics,
      'Managed Disk': ctx.disks,
      'Storage Account': ctx.storageAccounts,
      'DNS Zone': ctx.dnsZones,
      'AKS': ctx.aksCluster,
      'Firewall': ctx.firewalls,
      'Bastion': ctx.bastions,
      'SQL Server': ctx.sqlServers,
      'Function App': ctx.functionApps,
      'Container Instance': ctx.containerInstances,
      'Redis Cache': ctx.redisCaches,
      'Synapse Workspace': ctx.synapseWorkspaces
    };
    return findById(map[type], id);
  }

  function findArmResource(ctx, id){
    var buckets = ['vnets','subnets','vms','nsgs','natGateways','privateEndpoints','vpns','appGateways','loadBalancers','udrs','nics','disks','storageAccounts','dnsZones','aksCluster','firewalls','bastions','sqlServers','functionApps','containerInstances','redisCaches','synapseWorkspaces'];
    for(var i = 0; i < buckets.length; i++){
      var found = findById(ctx[buckets[i]], id);
      if(found) return found;
    }
    return null;
  }

  function buildGenericDetails(resource, type){
    var p = propsOf(resource);
    var details = [['Type', type], ['Location', resource.location || '--']];
    if(p.provisioningState || resource.State) details.push(['State', p.provisioningState || resource.State]);
    if(p.hardwareProfile && p.hardwareProfile.vmSize) details.push(['VM Size', p.hardwareProfile.vmSize]);
    if(p.version || resource.EngineVersion) details.push(['Version', p.version || resource.EngineVersion]);
    if(p.sku && p.sku.name || resource.sku && resource.sku.name) details.push(['SKU', p.sku && p.sku.name || resource.sku.name]);
    if(p.addressPrefix || resource.CidrBlock) details.push(['Address', p.addressPrefix || resource.CidrBlock]);
    return details;
  }

  function addNetworkRelations(resource, info){
    var p = propsOf(resource);
    var subnetId = p.subnetId || p.subnet && p.subnet.id || resource.SubnetId;
    var vnetId = p.vnetId || resource.VpcId;
    if(subnetId) info.related.push({ id:subnetId, name:subnetId.split('/').pop(), type:'Subnet' });
    if(vnetId) info.related.push({ id:vnetId, name:vnetId.split('/').pop(), type:'VNet' });
  }

  function buildResourceProfile(ctx, id, complianceFindings, includeFinding){
    if(!ctx || !id) return null;
    var info = { id:id, name:id, type:resolveResourceType(ctx, id) || 'Unknown', details:[], findings:[], related:[], nearby:[] };
    var low = String(id).toLowerCase();
    var resource = null;
    if(info.type === 'VNet'){
      resource = findById(ctx.vnets, id) || findById(ctx.vpcs, id);
      if(!resource) return null;
      var vnetProps = propsOf(resource);
      var vnetSubs = (ctx.subnets || []).filter(function(subnet){ return propsOf(subnet).vnetId === id || subnet.VpcId === id; });
      var prefixes = (vnetProps.addressSpace && vnetProps.addressSpace.addressPrefixes || []).join(', ') || resource.CidrBlock || '';
      info.name = resource.name || resource.VpcId || id;
      info.details = [['Address Space', prefixes || '--'], ['Location', resource.location || '--'], ['Subnets', '' + vnetSubs.length]];
      vnetSubs.slice(0,8).forEach(function(subnet){ info.nearby.push({ id:subnet.id || subnet.SubnetId, name:subnet.name || subnet.SubnetId || subnet.id, type:'Subnet' }); });
    } else if(info.type === 'Subnet'){
      resource = findById(ctx.subnets, id);
      if(!resource) return null;
      var subnetProps = propsOf(resource);
      info.name = resource.name || resource.SubnetId || id;
      info.details = [['Address Prefix', subnetProps.addressPrefix || resource.CidrBlock || '--'], ['Location', resource.location || resource.AvailabilityZone || '--'], ['VNet', subnetProps.vnetId || resource.VpcId || '--']];
      (ctx.vms || ctx.instances || []).filter(function(vm){ return propsOf(vm).subnetId === id || vm.SubnetId === id; }).slice(0,8)
        .forEach(function(vm){ info.nearby.push({ id:vm.id || vm.InstanceId, name:vm.name || vm.InstanceId || vm.id, type:'VM' }); });
      if(subnetProps.vnetId || resource.VpcId) info.related.push({ id:subnetProps.vnetId || resource.VpcId, name:subnetProps.vnetId || resource.VpcId, type:'VNet' });
    } else {
      resource = findResourceByType(ctx, info.type, id);
      if(!resource && low.includes('/')) resource = findArmResource(ctx, id);
      if(!resource) return null;
      info.name = resource.name || resource.FunctionName || resource.DBInstanceIdentifier || resource.InstanceId || id;
      info.details = buildGenericDetails(resource, info.type);
      addNetworkRelations(resource, info);
    }
    (complianceFindings || []).forEach(function(finding){
      if(finding.resource === id && (!includeFinding || includeFinding(finding))) info.findings.push(finding);
    });
    return info;
  }

  return {
    resolveResourceType: resolveResourceType,
    buildResourceProfile: buildResourceProfile
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ResourceProfile;
}
