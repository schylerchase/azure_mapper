// SearchIndex owns pure resource search indexing and matching.
var SearchIndex = (function(){
  function resourceName(resource, fallback) {
    var tags = Array.isArray(resource && resource.Tags) ? resource.Tags : [];
    var tag = tags.find(function(item) { return item.Key === 'Name'; });
    return tag ? tag.Value : fallback;
  }

  function addResource(index, type, name, id, extra, account, searchParts) {
    if (!id && !name) return;
    index.push({
      type: type,
      name: name || id,
      id: id || name,
      extra: extra || '',
      acct: account || '',
      searchStr: searchParts.filter(Boolean).join(' ').toLowerCase()
    });
  }

  function buildSearchIndex(ctx) {
    ctx = ctx || {};
    var index = [];
    (ctx.vnets || ctx.vpcs || []).forEach(function(vnet) {
      var name = resourceName(vnet, vnet.VpcId) || vnet.name || vnet.VpcId;
      var id = vnet.id || vnet.VpcId;
      var cidr = vnet.CidrBlock || (vnet.properties && vnet.properties.addressSpace && vnet.properties.addressSpace.addressPrefixes && vnet.properties.addressSpace.addressPrefixes[0]) || '';
      addResource(index, 'VNet', name, id, cidr, vnet._accountLabel || vnet._subscriptionId, ['vnet', name, id, cidr]);
    });
    (ctx.subnets || []).forEach(function(subnet) {
      var name = resourceName(subnet, subnet.SubnetId) || subnet.name || subnet.SubnetId;
      var id = subnet.id || subnet.SubnetId;
      var cidr = subnet.CidrBlock || (subnet.properties && subnet.properties.addressPrefix) || '';
      addResource(index, 'Subnet', name, id, cidr, subnet._accountLabel || subnet._subscriptionId, ['subnet', name, id, cidr]);
    });
    (ctx.vms || ctx.instances || []).forEach(function(vm) {
      var name = resourceName(vm, vm.InstanceId) || vm.name || vm.InstanceId;
      var id = vm.id || vm.InstanceId;
      var size = vm.InstanceType || (vm.properties && vm.properties.hardwareProfile && vm.properties.hardwareProfile.vmSize) || '';
      addResource(index, 'VM', name, id, size, vm._accountLabel || vm._subscriptionId, ['vm', name, id, size]);
    });
    (ctx.firewalls || ctx.igws || []).forEach(function(firewall) {
      var name = resourceName(firewall, firewall.InternetGatewayId) || firewall.name || firewall.InternetGatewayId;
      var id = firewall.id || firewall.InternetGatewayId;
      addResource(index, 'Firewall', name, id, '', firewall._accountLabel || firewall._subscriptionId, ['firewall', name, id]);
    });
    (ctx.natGateways || ctx.nats || []).forEach(function(nat) {
      var name = resourceName(nat, nat.NatGatewayId) || nat.name || nat.NatGatewayId;
      var id = nat.id || nat.NatGatewayId;
      addResource(index, 'NAT', name, id, '', nat._accountLabel || nat._subscriptionId, ['nat', name, id]);
    });
    (ctx.sqlServers || ctx.rdsInstances || []).forEach(function(db) {
      var name = db.name || db.DBInstanceIdentifier;
      var id = db.id || db.DBInstanceIdentifier;
      addResource(index, 'SQL', name, id, db.Engine || '', db._accountLabel || db._subscriptionId, ['sql', name, id]);
    });
    (ctx.functionApps || ctx.lambdaFns || []).forEach(function(fn) {
      var name = fn.name || fn.FunctionName;
      var id = fn.id || fn.FunctionName;
      var runtime = fn.Runtime || (fn.properties && fn.properties.runtime) || '';
      addResource(index, 'Function App', name, id, runtime, fn._accountLabel || fn._subscriptionId, ['function app', name, id, runtime]);
    });
    (ctx.nsgs || ctx.sgs || []).forEach(function(nsg) {
      var name = nsg.name || nsg.GroupName || nsg.GroupId;
      var id = nsg.id || nsg.GroupId;
      addResource(index, 'NSG', name, id, nsg.VpcId || '', nsg._accountLabel || nsg._subscriptionId, ['nsg', 'security group', name, id]);
    });
    return index;
  }

  function findSearchMatches(index, query, limit) {
    var q = String(query || '').toLowerCase().trim();
    var max = limit || 30;
    var matches = [];
    if (!q) return matches;
    for (var i = 0; i < (index || []).length && matches.length < max; i++) {
      if (index[i].searchStr.includes(q)) matches.push(index[i]);
    }
    return matches;
  }

  return {
    buildSearchIndex: buildSearchIndex,
    findSearchMatches: findSearchMatches
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SearchIndex;
}
