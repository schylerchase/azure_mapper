var GovernanceInventoryModel = (function(){
  function list(ctx, primary, fallback){
    if(!ctx) return [];
    var primaryItems = ctx[primary];
    var fallbackItems = fallback ? ctx[fallback] : null;
    if(Array.isArray(primaryItems) && primaryItems.length === 0 && fallbackItems) return fallbackItems;
    return primaryItems || fallbackItems || [];
  }

  function resourceName(resource, fallback, nameForResource){
    if(typeof nameForResource === 'function') return nameForResource(resource, fallback);
    if(!resource) return fallback || '';
    var tagValue = tag(resource);
    return tagValue || resource.name || resource.Name || fallback || '';
  }

  function tag(obj){
    var tg = obj && (obj.Tags || obj.tags);
    if(!tg) return '';
    if(Array.isArray(tg)){
      var found = tg.find(function(x){ return x && x.Key === 'Name'; });
      return found ? found.Value : '';
    }
    return tg.Name || tg.name || '';
  }

  function tags(obj){
    var tg = obj && (obj.Tags || obj.tags);
    if(!tg) return {};
    if(Array.isArray(tg)){
      var map = {};
      tg.forEach(function(t){ if(t && t.Key) map[t.Key] = t.Value; });
      return map;
    }
    return tg;
  }

  function createRow(vnetNameMap, id, type, name, obj, extra){
    var data = extra || {};
    return {
      id: id,
      type: type,
      name: name,
      account: obj._accountLabel || obj._subscriptionId || '',
      _subscriptionId: obj._subscriptionId || (String(obj.id || id || '').match(/\/subscriptions\/([^/]+)/i) || [])[1] || '',
      region: obj._region || obj.location || obj.Location || '',
      vpcId: data.vpcId || '',
      vpcName: data.vpcId ? vnetNameMap[data.vpcId] || '' : '',
      subnetId: data.subnetId || '',
      az: data.az || '',
      state: data.state || '',
      config: data.config || '',
      tags: tags(obj),
      encrypted: data.encrypted != null ? data.encrypted : null,
      sgCount: data.sgCount || 0,
      classificationTier: null,
      budrTier: null,
      budrStrategy: null,
      rto: null,
      rpo: null,
      compliancePass: 0,
      complianceFail: 0,
      _raw: obj,
      _related: data.related || []
    };
  }

  function buildInventoryData(ctx, options){
    if(!ctx) return [];
    var opts = options || {};
    var nameForResource = opts.nameForResource;
    var rows = [];
    var vnets = list(ctx, 'vpcs', 'vnets');
    var subnets = ctx.subnets || [];
    var vnetNameMap = {};

    vnets.forEach(function(vnet){
      vnetNameMap[vnet.VpcId] = resourceName(vnet, vnet.VpcId, nameForResource);
    });

    function row(id, type, name, obj, extra){
      rows.push(createRow(vnetNameMap, id, type, name, obj || {}, extra));
    }

    var subVpcMap = {};
    subnets.forEach(function(subnet){ if(subnet.SubnetId) subVpcMap[subnet.SubnetId] = subnet.VpcId || ''; });

    var instances = list(ctx, 'instances', 'vms');
    var instVpcMap = {};
    instances.forEach(function(instance){
      if(instance.InstanceId) instVpcMap[instance.InstanceId] = instance.VpcId || subVpcMap[instance.SubnetId] || '';
    });

    vnets.forEach(function(vnet){
      row(vnet.VpcId, 'VNet', tag(vnet) || vnet.VpcId, vnet, {
        vpcId: vnet.VpcId,
        config: vnet.CidrBlock || '',
        state: vnet.State || ''
      });
    });

    subnets.forEach(function(subnet){
      var isPublic = ctx.pubSubs && ctx.pubSubs.has && ctx.pubSubs.has(subnet.SubnetId);
      row(subnet.SubnetId, 'Subnet', tag(subnet) || subnet.SubnetId, subnet, {
        vpcId: subnet.VpcId,
        az: subnet.AvailabilityZone || '',
        config: (subnet.CidrBlock || '') + ' ' + (isPublic ? 'public' : 'private'),
        state: subnet.State || ''
      });
    });

    instances.forEach(function(instance){
      var securityGroups = (instance.SecurityGroups || []).map(function(group){ return group.GroupId; });
      row(instance.InstanceId, 'VM', tag(instance) || instance.InstanceId, instance, {
        vpcId: instance.VpcId || subVpcMap[instance.SubnetId] || '',
        subnetId: instance.SubnetId || '',
        az: instance.Placement ? instance.Placement.AvailabilityZone : '',
        config: instance.InstanceType || '',
        state: instance.State ? instance.State.Name || '' : '',
        sgCount: securityGroups.length,
        related: securityGroups
      });
    });

    list(ctx, 'rdsInstances', 'sqlServers').forEach(function(db){
      var vpcId = (db.DBSubnetGroup && db.DBSubnetGroup.VpcId) || db.VpcId || '';
      row(db.id || db.DBInstanceIdentifier || db.name, 'SQL', db.name || db.DBInstanceIdentifier || db.id, db, {
        vpcId: vpcId,
        az: db.AvailabilityZone || '',
        config: (db.Engine || '') + ' ' + (db.DBInstanceClass || ''),
        state: db.DBInstanceStatus || db.properties?.state || '',
        encrypted: !!db.StorageEncrypted
      });
    });

    list(ctx, 'lambdaFns', 'functionApps').forEach(function(fn){
      var vpcConfig = fn.VpcConfig || {};
      var subnetId = (vpcConfig.SubnetIds && vpcConfig.SubnetIds[0]) || '';
      row(fn.id || fn.FunctionName || fn.name, 'Function App', fn.FunctionName || fn.name || fn.id, fn, {
        vpcId: vpcConfig.VpcId || '',
        subnetId: subnetId,
        config: (fn.Runtime || '') + (fn.MemorySize ? ' ' + fn.MemorySize + 'MB' : ''),
        state: fn.State || 'Active'
      });
    });

    list(ctx, 'ecsServices', 'containerInstances').forEach(function(service){
      var networkConfig = service.networkConfiguration && service.networkConfiguration.awsvpcConfiguration;
      var subnetId = networkConfig && networkConfig.subnets && networkConfig.subnets[0] ? networkConfig.subnets[0] : '';
      var vpcId = '';
      if(subnetId){
        var subnetObj = subnets.find(function(subnet){ return subnet.SubnetId === subnetId; });
        if(subnetObj) vpcId = subnetObj.VpcId || '';
      }
      row(service.id || service.serviceName || service.name, 'Container', service.serviceName || service.name || service.id, service, {
        vpcId: vpcId,
        subnetId: subnetId,
        config: (service.launchType || '') + ' ' + (service.cpu ? service.cpu + '/' : '') + (service.memory || ''),
        state: service.status || ''
      });
    });

    list(ctx, 'albs', 'appGateways').forEach(function(loadBalancer){
      row(loadBalancer.id || loadBalancer.LoadBalancerName || loadBalancer.name, 'App Gateway', loadBalancer.LoadBalancerName || loadBalancer.name || loadBalancer.id, loadBalancer, {
        vpcId: loadBalancer.VpcId || '',
        config: (loadBalancer.Type || 'application') + ' ' + (loadBalancer.Scheme || ''),
        state: loadBalancer.State ? loadBalancer.State.Code || '' : ''
      });
    });

    list(ctx, 'ecacheClusters', 'redisCaches').forEach(function(cache){
      var vpcId = cache.VpcId || (cache.CacheSubnetGroupName ? '' : '');
      if(!vpcId && cache.CacheNodes && cache.CacheNodes[0] && cache.CacheNodes[0].SubnetId) {
        vpcId = subVpcMap[cache.CacheNodes[0].SubnetId] || '';
      }
      row(cache.id || cache.CacheClusterId || cache.name, 'Redis Cache', cache.CacheClusterId || cache.name || cache.id, cache, {
        vpcId: vpcId,
        config: (cache.Engine || '') + ' ' + (cache.CacheNodeType || ''),
        state: cache.CacheClusterStatus || ''
      });
    });

    list(ctx, 'redshiftClusters', 'synapseWorkspaces').forEach(function(cluster){
      row(cluster.id || cluster.ClusterIdentifier || cluster.name, 'Synapse', cluster.ClusterIdentifier || cluster.name || cluster.id, cluster, {
        vpcId: cluster.VpcId || '',
        config: (cluster.NodeType || '') + ' x' + (cluster.NumberOfNodes || 1),
        state: cluster.ClusterStatus || '',
        encrypted: !!cluster.Encrypted
      });
    });

    list(ctx, 'sgs', 'nsgs').forEach(function(group){
      var inCount = (group.IpPermissions || []).length;
      var outCount = (group.IpPermissionsEgress || []).length;
      row(group.GroupId, 'NSG', group.GroupName || group.GroupId, group, {
        vpcId: group.VpcId || '',
        config: inCount + ' inbound / ' + outCount + ' outbound'
      });
    });

    list(ctx, 'nacls', 'subnetNsgs').forEach(function(nacl){
      row(nacl.NetworkAclId, 'Subnet NSG', tag(nacl) || nacl.NetworkAclId, nacl, {
        vpcId: nacl.VpcId || '',
        config: (nacl.Entries || []).length + ' entries'
      });
    });

    list(ctx, 'rts', 'udrs').forEach(function(routeTable){
      row(routeTable.RouteTableId, 'UDR', tag(routeTable) || routeTable.RouteTableId, routeTable, {
        vpcId: routeTable.VpcId || '',
        config: (routeTable.Routes || []).length + ' routes'
      });
    });

    list(ctx, 'igws', 'firewalls').forEach(function(gateway){
      var attachments = gateway.Attachments || [];
      var attachedVpc = attachments.length ? attachments[0].VpcId : gateway.VpcId || '';
      row(gateway.InternetGatewayId || gateway.id || gateway.name, 'Azure Firewall', tag(gateway) || gateway.InternetGatewayId || gateway.name || gateway.id, gateway, {
        vpcId: attachedVpc,
        config: attachedVpc ? 'attached: ' + attachedVpc : 'detached'
      });
    });

    list(ctx, 'nats', 'natGateways').forEach(function(nat){
      row(nat.NatGatewayId || nat.id || nat.name, 'NAT GW', tag(nat) || nat.NatGatewayId || nat.name || nat.id, nat, {
        vpcId: nat.VpcId || '',
        subnetId: nat.SubnetId || '',
        config: (nat.SubnetId || '') + ' ' + (nat.State || ''),
        state: nat.State || ''
      });
    });

    list(ctx, 'vpces', 'privateEndpoints').forEach(function(endpoint){
      row(endpoint.VpcEndpointId || endpoint.id || endpoint.name, 'Private Endpoint', tag(endpoint) || endpoint.VpcEndpointId || endpoint.name || endpoint.id, endpoint, {
        vpcId: endpoint.VpcId || '',
        config: endpoint.ServiceName || '',
        state: endpoint.State || ''
      });
    });

    list(ctx, 'enis', 'nics').forEach(function(nic){
      row(nic.NetworkInterfaceId || nic.id || nic.name, 'NIC', nic.Description || nic.NetworkInterfaceId || nic.name || nic.id, nic, {
        vpcId: nic.VpcId || '',
        subnetId: nic.SubnetId || '',
        az: nic.AvailabilityZone || '',
        config: nic.PrivateIpAddress || '',
        state: nic.Status || ''
      });
    });

    (ctx.volumes || []).forEach(function(volume){
      var attachedInstances = (volume.Attachments || []).map(function(attachment){ return attachment.InstanceId; }).filter(Boolean);
      row(volume.VolumeId, 'Managed Disk', tag(volume) || volume.VolumeId, volume, {
        vpcId: attachedInstances.length ? instVpcMap[attachedInstances[0]] || '' : '',
        az: volume.AvailabilityZone || '',
        config: volume.Size + 'GB ' + (volume.VolumeType || ''),
        state: volume.State || '',
        encrypted: !!volume.Encrypted,
        related: attachedInstances
      });
    });

    (ctx.snapshots || []).forEach(function(snapshot){
      row(snapshot.SnapshotId, 'Snapshot', snapshot.Description || snapshot.SnapshotId, snapshot, {
        config: (snapshot.VolumeSize || '') + 'GB',
        state: snapshot.State || '',
        encrypted: !!snapshot.Encrypted
      });
    });

    list(ctx, 's3bk', 'storageAccounts').forEach(function(storage){
      row(storage.id || storage.Name || storage.name, 'Storage Account', storage.Name || storage.name || storage.id, storage, {
        config: storage.CreationDate || ''
      });
    });

    (ctx.zones || []).forEach(function(zone){
      var records = ctx.recsByZone && ctx.recsByZone[zone.Id] ? ctx.recsByZone[zone.Id].length : zone.ResourceRecordSetCount || 0;
      var visibility = zone.Config && zone.Config.PrivateZone ? 'private' : 'public';
      row(zone.Id, 'DNS Zone', zone.Name || zone.Id, zone, { config: records + ' records ' + visibility });
    });

    (ctx.wafAcls || []).forEach(function(waf){
      row(waf.Id || waf.Name, 'WAF', waf.Name || waf.Id || '', waf, { config: (waf.Rules || []).length + ' rules' });
    });

    (ctx.cfDistributions || []).forEach(function(frontDoor){
      row(frontDoor.Id, 'Front Door', frontDoor.DomainName || frontDoor.Id, frontDoor, {
        config: frontDoor.Status || '',
        state: frontDoor.Status || ''
      });
    });

    (ctx.peerings || []).forEach(function(peering){
      var requester = peering.RequesterVpcInfo ? peering.RequesterVpcInfo.VpcId : '';
      var accepter = peering.AccepterVpcInfo ? peering.AccepterVpcInfo.VpcId : '';
      row(peering.VpcPeeringConnectionId, 'VNet Peering', tag(peering) || peering.VpcPeeringConnectionId, peering, {
        config: requester + '<->' + accepter,
        state: peering.Status ? peering.Status.Code || '' : ''
      });
    });

    (ctx.vpns || []).forEach(function(vpn){
      row(vpn.VpnConnectionId, 'VPN', tag(vpn) || vpn.VpnConnectionId, vpn, {
        config: (vpn.State || '') + ' ' + (vpn.Type || ''),
        state: vpn.State || ''
      });
    });

    (ctx.tgwAttachments || ctx.vhubs || []).forEach(function(attachment){
      var id = attachment.TransitGatewayAttachmentId || (attachment.TransitGatewayId + '-' + (attachment.VpcId || ''));
      row(id, 'vWAN', tag(attachment) || id, attachment, {
        vpcId: attachment.VpcId || '',
        config: (attachment.ResourceType || '') + ' ' + (attachment.TransitGatewayId || ''),
        state: attachment.State || ''
      });
    });

    (ctx.tgs || []).forEach(function(pool){
      row(pool.TargetGroupName, 'Backend Pool', pool.TargetGroupName, pool, {
        vpcId: pool.VpcId || '',
        config: (pool.Protocol || '') + ':' + (pool.Port || ''),
        state: pool.TargetType || ''
      });
    });

    enrichRows(rows, opts);
    return rows;
  }

  function enrichRows(rows, options){
    var opts = options || {};
    var classMap = {};
    (opts.classificationData || []).forEach(function(item){ classMap[item.id] = item; });

    var budrMap = {};
    (opts.budrAssessments || []).forEach(function(item){
      budrMap[item.id] = {
        tier: item.profile ? item.profile.tier : null,
        strategy: item.profile ? item.profile.strategy : null,
        rto: item.profile ? item.profile.rto : null,
        rpo: item.profile ? item.profile.rpo : null
      };
    });

    var complianceMap = {};
    (opts.complianceFindings || []).forEach(function(finding){
      var identity = finding.resourceId || finding.resource;
      if(!identity || finding.status === 'UNKNOWN') return;
      var key = String(identity).toLowerCase();
      if(!complianceMap[key]) complianceMap[key] = { pass: 0, fail: 0 };
      if(finding.status === 'PASS') complianceMap[key].pass++;
      else complianceMap[key].fail++;
    });

    rows.forEach(function(row){
      var classification = classMap[row.id];
      if(classification) row.classificationTier = classification.tier;
      var budr = budrMap[row.id];
      if(budr) {
        row.budrTier = budr.tier;
        row.budrStrategy = budr.strategy;
        row.rto = budr.rto;
        row.rpo = budr.rpo;
      }
      var compliance = complianceMap[String(row.id).toLowerCase()];
      if(compliance) {
        row.compliancePass = compliance.pass;
        row.complianceFail = compliance.fail;
      }
    });
  }

  function filterInventory(rows, state, accountFilter){
    var st = state || {};
    var items = typeof accountFilter === 'function' ? accountFilter(rows || []) : (rows || []);
    items = items.slice();

    if(st.typeFilter && st.typeFilter !== 'all') items = items.filter(function(row){ return row.type === st.typeFilter; });
    if(st.regionFilter && st.regionFilter !== 'all') items = items.filter(function(row){ return row.region === st.regionFilter; });
    if(st.accountFilter && st.accountFilter !== 'all') items = items.filter(function(row){ return row.account === st.accountFilter; });
    if(st.vpcFilter && st.vpcFilter !== 'all') items = items.filter(function(row){ return row.vpcId === st.vpcFilter; });

    if(st.search){
      var query = st.search.toLowerCase();
      items = items.filter(function(row){
        return (row.name || '').toLowerCase().indexOf(query) !== -1 ||
          (row.id || '').toLowerCase().indexOf(query) !== -1 ||
          (row.type || '').toLowerCase().indexOf(query) !== -1 ||
          (row.config || '').toLowerCase().indexOf(query) !== -1 ||
          (row.vpcName || '').toLowerCase().indexOf(query) !== -1 ||
          (row.region || '').toLowerCase().indexOf(query) !== -1 ||
          JSON.stringify(row.tags || {}).toLowerCase().indexOf(query) !== -1;
      });
    }

    var sortKey = st.sort || 'type';
    var dir = st.sortDir === 'asc' ? 1 : -1;
    items.sort(function(a, b){
      if(sortKey === 'complianceFail') return ((a.complianceFail || 0) - (b.complianceFail || 0)) * dir;
      if(sortKey === 'tags') return (Object.keys(a.tags || {}).length - Object.keys(b.tags || {}).length) * dir;
      var av = (a[sortKey] || '').toString().toLowerCase();
      var bv = (b[sortKey] || '').toString().toLowerCase();
      return av < bv ? -dir : av > bv ? dir : 0;
    });

    return items;
  }

  return {
    buildInventoryData: buildInventoryData,
    filterInventory: filterInventory
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = GovernanceInventoryModel;
}
