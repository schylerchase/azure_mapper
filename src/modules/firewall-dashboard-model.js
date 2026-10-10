var FirewallDashboardModel = (function(){
  var SEVERITY_ORDER = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
  var TYPE_LABELS = { sg: 'Security Groups', nacl: 'Network ACLs', route: 'Route Tables' };
  var TYPE_ORDER = { 'Security Groups': 1, 'Network ACLs': 2, 'Route Tables': 3 };

  function resourceName(resource, fallback, nameForResource){
    if(typeof nameForResource === 'function') return nameForResource(resource, fallback);
    if(!resource) return fallback || '';
    if(resource.GroupName) return resource.GroupName;
    if(resource.name) return resource.name;
    if(Array.isArray(resource.Tags)){
      var tag = resource.Tags.find(function(t){ return t && t.Key === 'Name'; });
      if(tag && tag.Value) return tag.Value;
    }
    return fallback || '';
  }

  function hasOpenIngress(securityGroup){
    return (securityGroup.IpPermissions || []).some(function(permission){
      return (permission.IpRanges || []).some(function(range){ return range.CidrIp === '0.0.0.0/0'; }) ||
        (permission.Ipv6Ranges || []).some(function(range){ return range.CidrIpv6 === '::/0'; });
    });
  }

  function vnetLabelMap(ctx, nameForResource){
    var labels = {};
    (ctx.vnets || []).forEach(function(vnet){
      labels[vnet.VpcId] = resourceName(vnet, vnet.VpcId, nameForResource);
    });
    return labels;
  }

  function buildVnetOptions(ctx, options){
    var opts = options || {};
    return (ctx.vnets || []).map(function(vnet){
      return {
        id: vnet.VpcId,
        label: resourceName(vnet, vnet.VpcId, opts.nameForResource)
      };
    });
  }

  function buildRows(ctx, options){
    var opts = options || {};
    var complianceLookup = opts.complianceLookup || {};
    var editCount = typeof opts.editCount === 'function' ? opts.editCount : function(){ return 0; };
    var nameForResource = opts.nameForResource;
    var rows = [];

    (ctx.nsgs || []).forEach(function(sg){
      var inCount = (sg.IpPermissions || []).length;
      var outCount = (sg.IpPermissionsEgress || []).length;
      rows.push({
        type: 'sg',
        id: sg.GroupId,
        name: sg.GroupName || resourceName(sg, sg.GroupId, nameForResource),
        vpc: sg.VpcId,
        rules: inCount + outCount,
        rulesLabel: inCount + ' in / ' + outCount + ' out',
        edits: editCount(sg.GroupId),
        desc: sg.Description || '',
        obj: sg,
        comp: complianceLookup[sg.GroupId] || null,
        openIngress: hasOpenIngress(sg),
        _subscriptionId: sg._subscriptionId || ''
      });
    });

    (ctx.subnetNsgs || []).forEach(function(nacl){
      var entries = nacl.Entries || [];
      var inCount = entries.filter(function(entry){ return !entry.Egress && entry.RuleNumber !== 32767; }).length;
      var outCount = entries.filter(function(entry){ return entry.Egress && entry.RuleNumber !== 32767; }).length;
      rows.push({
        type: 'nacl',
        id: nacl.NetworkAclId,
        name: resourceName(nacl, nacl.NetworkAclId, nameForResource),
        vpc: nacl.VpcId,
        rules: inCount + outCount,
        rulesLabel: inCount + ' in / ' + outCount + ' out',
        edits: editCount(nacl.NetworkAclId),
        desc: '',
        obj: nacl,
        comp: complianceLookup[nacl.NetworkAclId] || null,
        openIngress: false,
        _subscriptionId: nacl._subscriptionId || ''
      });
    });

    (ctx.udrs || []).forEach(function(routeTable){
      var routeCount = (routeTable.Routes || []).length;
      rows.push({
        type: 'route',
        id: routeTable.RouteTableId,
        name: resourceName(routeTable, routeTable.RouteTableId, nameForResource),
        vpc: routeTable.VpcId,
        rules: routeCount,
        rulesLabel: routeCount + ' routes',
        edits: editCount(routeTable.RouteTableId),
        desc: '',
        obj: routeTable,
        comp: complianceLookup[routeTable.RouteTableId] || null,
        openIngress: false,
        _subscriptionId: routeTable._subscriptionId || ''
      });
    });

    if(typeof opts.accountFilter === 'function') rows = opts.accountFilter(rows);
    return rows;
  }

  function summarizeRows(rows, totalEdits){
    var summary = {
      resources: rows.length,
      securityGroups: 0,
      subnetNsgs: 0,
      routeTables: 0,
      totalFindings: 0,
      worstSeverity: 'LOW',
      openIngress: 0,
      totalEdits: totalEdits || 0
    };

    rows.forEach(function(row){
      if(row.type === 'sg') summary.securityGroups++;
      if(row.type === 'nacl') summary.subnetNsgs++;
      if(row.type === 'route') summary.routeTables++;
      if(row.openIngress) summary.openIngress++;
      if(row.comp){
        summary.totalFindings += row.comp.count;
        if((SEVERITY_ORDER[row.comp.worst] || 9) < (SEVERITY_ORDER[summary.worstSeverity] || 9)){
          summary.worstSeverity = row.comp.worst;
        }
      }
    });

    return summary;
  }

  function filterRows(rows, state, activeType){
    var dashState = state || {};
    var filtered = rows.slice();
    var cardFilter = dashState.cardFilter;

    if(cardFilter === 'findings') filtered = filtered.filter(function(row){ return row.comp; });
    if(cardFilter === 'open') filtered = filtered.filter(function(row){ return row.openIngress; });
    if(cardFilter === 'edits') filtered = filtered.filter(function(row){ return row.edits > 0; });
    if(activeType && activeType !== 'all') filtered = filtered.filter(function(row){ return row.type === activeType; });
    if(dashState.vpcFilter && dashState.vpcFilter !== 'all') {
      filtered = filtered.filter(function(row){ return row.vpc === dashState.vpcFilter; });
    }
    if(dashState.search) {
      filtered = filtered.filter(function(row){
        return (row.name + ' ' + row.id + ' ' + row.vpc + ' ' + row.desc).toLowerCase().indexOf(dashState.search) !== -1;
      });
    }

    return filtered;
  }

  function sortRows(rows, state){
    var dashState = state || {};
    var sortBy = dashState.sort || 'type';
    var dir = dashState.sortDir === 'asc' ? 1 : -1;
    return rows.slice().sort(function(a, b){
      if(sortBy === 'type') return (a.type.localeCompare(b.type) || a.name.localeCompare(b.name)) * dir;
      if(sortBy === 'name') return a.name.localeCompare(b.name) * dir;
      if(sortBy === 'rules') return (b.rules - a.rules) * dir;
      if(sortBy === 'severity') {
        var aSeverity = a.comp ? (SEVERITY_ORDER[a.comp.worst] || 9) : 99;
        var bSeverity = b.comp ? (SEVERITY_ORDER[b.comp.worst] || 9) : 99;
        return (aSeverity - bSeverity) * dir;
      }
      return 0;
    });
  }

  function groupRows(filteredRows, state, labelsByVnet){
    var dashState = state || {};
    var groupBy = dashState.groupBy || 'vpc';
    if(groupBy !== 'vpc' && groupBy !== 'type') {
      return [{
        key: 'all',
        label: null,
        rows: filteredRows.map(function(row, idx){ return { r: row, idx: idx }; }),
        stats: null
      }];
    }

    var groupMap = {};
    filteredRows.forEach(function(row, idx){
      var key = groupBy === 'vpc' ? row.vpc : TYPE_LABELS[row.type];
      if(!groupMap[key]) groupMap[key] = { key: key, rows: [] };
      groupMap[key].rows.push({ r: row, idx: idx });
    });

    var groups = Object.values(groupMap);
    if(groupBy === 'vpc') {
      groups.forEach(function(group){
        var groupFindings = 0;
        var groupWorst = 'LOW';
        var groupOpen = 0;
        group.rows.forEach(function(item){
          if(item.r.comp) {
            groupFindings += item.r.comp.count;
            if((SEVERITY_ORDER[item.r.comp.worst] || 9) < (SEVERITY_ORDER[groupWorst] || 9)){
              groupWorst = item.r.comp.worst;
            }
          }
          if(item.r.openIngress) groupOpen++;
        });
        group.label = labelsByVnet[group.key] || group.key || 'Unknown';
        group.vpcId = group.key;
        group.stats = { count: group.rows.length, findings: groupFindings, worst: groupWorst, open: groupOpen };
      });
      groups.sort(function(a, b){ return a.label.localeCompare(b.label); });
    } else {
      groups.sort(function(a, b){ return (TYPE_ORDER[a.key] || 9) - (TYPE_ORDER[b.key] || 9); });
      groups.forEach(function(group){
        group.label = group.key;
        group.stats = { count: group.rows.length };
      });
    }

    return groups;
  }

  function emptyMessage(state){
    var dashState = state || {};
    if(dashState.cardFilter === 'edits') return 'No resources with pending edits';
    if(dashState.cardFilter === 'findings') return 'No resources with compliance findings';
    if(dashState.cardFilter === 'open') return 'No SGs with open 0.0.0.0/0 ingress';
    if(dashState.search) return 'No resources match "' + dashState.search + '"';
    return 'No firewall resources found';
  }

  function buildColumns(rows){
    var hasMultiAccount = new Set(rows.map(function(row){ return row._subscriptionId; }).filter(Boolean)).size > 1;
    var columns = [{ k: 'type', l: 'Type' }, { k: 'name', l: 'Name' }];
    if(hasMultiAccount) columns.push({ k: '_subscriptionId', l: 'Account' });
    columns.push(
      { k: 'vpc', l: 'VNet' },
      { k: 'rules', l: 'Rules' },
      { k: 'severity', l: 'Compliance' },
      { k: 'edits', l: 'Edits', nosort: true }
    );
    return { columns: columns, hasMultiAccount: hasMultiAccount };
  }

  function buildViewModel(ctx, state, activeType, options){
    var opts = options || {};
    var rows = buildRows(ctx || {}, opts);
    var summary = summarizeRows(rows, opts.totalEdits || 0);
    var filteredRows = sortRows(filterRows(rows, state, activeType), state);
    var labelsByVnet = vnetLabelMap(ctx || {}, opts.nameForResource);
    var columnModel = buildColumns(rows);

    return {
      rows: rows,
      filteredRows: filteredRows,
      summary: summary,
      groups: groupRows(filteredRows, state, labelsByVnet),
      columns: columnModel.columns,
      hasMultiAccount: columnModel.hasMultiAccount,
      labelsByVnet: labelsByVnet,
      emptyMessage: emptyMessage(state)
    };
  }

  return {
    buildVnetOptions: buildVnetOptions,
    buildRows: buildRows,
    summarizeRows: summarizeRows,
    filterRows: filterRows,
    sortRows: sortRows,
    groupRows: groupRows,
    buildViewModel: buildViewModel
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = FirewallDashboardModel;
}
