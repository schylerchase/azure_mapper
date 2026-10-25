// IaC resource formatting, naming, and Azure ID helpers.

// === Name Helpers ===

/**
 * Sanitize a name for Terraform resource identifiers.
 * Strips non-alphanumeric/underscore chars, lowercases, prefixes if starts with digit.
 */
export function safeName(name) {
  if (!name) return 'unnamed';
  return name
    .replace(/[^a-zA-Z0-9_]/g, '_')
    .replace(/^[0-9]/, 'r$&')
    .replace(/__+/g, '_')
    .replace(/_$/, '')
    .toLowerCase();
}

/**
 * Extract a display name from an Azure resource.
 * Falls back through name, id segment, or prefix.
 */
export function _resName(resource, prefix) {
  const raw = resource.name
    || (resource.id ? resource.id.split('/').pop() : null)
    || prefix
    || 'res';
  return safeName(raw);
}

/**
 * Extract tags from an Azure resource object.
 * Azure tags are a flat object: { "Environment": "prod", "Team": "net" }
 */
export function _extractTags(resource) {
  return resource.tags || {};
}

/**
 * Write HCL tags block from Azure tag object.
 */
export function _writeTags(lines, resource) {
  const tags = _extractTags(resource);
  const keys = Object.keys(tags);
  if (!keys.length) return;
  lines.push('');
  lines.push('  tags = {');
  keys.forEach(k => {
    const safeKey = k.match(/^[a-zA-Z_][a-zA-Z0-9_]*$/) ? k : ('"' + _hclEsc(k) + '"');
    lines.push('    ' + safeKey + ' = "' + _hclEsc(tags[k]) + '"');
  });
  lines.push('  }');
}

/**
 * Escape a string for use in HCL double-quoted strings.
 */
export function _hclEsc(s) {
  return String(s ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/[\u0000-\u001f]/g, char => ({ '\n': '\\n', '\r': '\\r', '\t': '\\t' })[char] || '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'))
    .replace(/\$\{/g, () => '$${').replace(/%\{/g, '%%{');
}

/** Escape literal data in a Bicep single-quoted string, including interpolation. */
export function _bicepEsc(s) {
  return String(s ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'")
    .replace(/[\u0000-\u001f]/g, char => ({ '\n': '\\n', '\r': '\\r', '\t': '\\t' })[char] || '\\u{' + char.charCodeAt(0).toString(16) + '}')
    .replace(/\$\{/g, '\\${');
}

/**
 * Get the location from a resource, with fallback.
 */
export function _loc(resource) {
  return resource.location || 'eastus';
}

/**
 * Map Azure protocol string to Terraform/ARM-safe value.
 */
export function _proto(p) {
  if (!p || p === '*') return '*';
  const low = p.toLowerCase();
  if (low === 'tcp') return 'Tcp';
  if (low === 'udp') return 'Udp';
  if (low === 'icmp') return 'Icmp';
  return p;
}

// Azure NSG selectors are alternatives. A populated array or ASG selector must
// not be replaced by the wildcard used when no selector was supplied.
export function _nsgSelectors(rule) {
  const selectors = {};
  for (const side of ['source', 'destination']) {
    const ports = rule[side + 'PortRanges'];
    if (Array.isArray(ports) && ports.length) selectors[side + 'PortRanges'] = ports.slice();
    else selectors[side + 'PortRange'] = rule[side + 'PortRange'] || '*';
    const asgs = rule[side + 'ApplicationSecurityGroups'];
    const prefixes = rule[side + 'AddressPrefixes'];
    if (Array.isArray(asgs) && asgs.length) {
      selectors[side + 'ApplicationSecurityGroups'] = asgs.map(group => ({ id: group.id }));
    } else if (Array.isArray(prefixes) && prefixes.length) {
      selectors[side + 'AddressPrefixes'] = prefixes.slice();
    } else selectors[side + 'AddressPrefix'] = rule[side + 'AddressPrefix'] || '*';
  }
  return selectors;
}

// NAT CLI exports can carry references without a separate public-IP export.
export function _natPublicIps(data) {
  const available = new Map((data.publicIps || []).map(ip => [(ip.id || '').toLowerCase(), ip]));
  const referenced = new Map();
  (data.natGateways || []).forEach(nat => {
    ((nat.properties || nat).publicIpAddresses || []).forEach(ref => {
      if (!ref.id) return;
      const key = ref.id.toLowerCase();
      referenced.set(key, available.get(key) || { id: ref.id, name: ref.id.split('/').pop(), location: nat.location });
    });
  });
  return Array.from(referenced.values());
}

export function _subnetNatId(subnet, natGateways) {
  const direct = (subnet.properties || subnet).natGateway?.id;
  if (direct) return direct;
  const id = (subnet.id || subnet.SubnetId || '').toLowerCase();
  const nat = natGateways.find(gateway => ((gateway.properties || gateway).subnets || []).some(ref => (ref.id || '').toLowerCase() === id));
  return nat?.id;
}

// These generators cannot create an unconfigured design VM or deploy definitions
// across resource-group scopes. Return a visible error instead of invalid IaC.
export function _iacExportBlock(data, format) {
  const warnings = [];
  (data.vms || []).forEach(vm => {
    const props = vm.properties || vm;
    const attachedOs = String(props.storageProfile?.osDisk?.createOption || '').toLowerCase() === 'attach';
    if (attachedOs && format === 'terraform') {
      warnings.push('VM "' + (vm.name || vm.id) + '" attaches an existing OS disk, which the Terraform VM resource used by this exporter does not support. Export ARM/Bicep or exclude this VM from the Terraform export.');
    }
    if (attachedOs && !props.storageProfile?.osDisk?.managedDisk?.id) {
      warnings.push('VM "' + (vm.name || vm.id) + '" needs the managed OS disk ID before exporting an attached OS disk. Configure its VM data and generate again.');
    }
    if (!vm._designCreated && !String(vm.id || '').startsWith('vm-design-')) return;
    const missing = [];
    if (!props.networkProfile?.networkInterfaces?.length) missing.push('a network interface');
    const image = props.storageProfile?.imageReference;
    if (!attachedOs && !image?.id && !image?.publisher) missing.push('an OS image');
    if (missing.length) warnings.push('VM "' + (vm.name || vm.id) + '" needs ' + missing.join(' and ') + ' before IaC export. Configure its VM data and generate again.');
  });
  if (format === 'terraform') {
    (data.nics || []).forEach(nic => {
      ((nic.properties || nic).ipConfigurations || []).forEach(ip => {
        const version = (ip.properties || ip).privateIPAddressVersion;
        if (version != null && version !== '' && !['IPv4', 'IPv6'].includes(version)) {
          warnings.push('NIC "' + (nic.name || nic.id) + '" IP address version must be IPv4 or IPv6 before Terraform export.');
        }
      });
    });
  }
  const keys = ['vnets', 'nsgs', 'subnetNsgs', 'udrs', 'natGateways', 'vms', 'nics', 'disks', 'peerings', 'firewalls', 'bastions'];
  const resources = keys.flatMap(key => data[key] || []).concat(_natPublicIps(data));
  if (format === 'terraform') {
    const subscriptions = new Set(resources.map(resource => String(resource.id || '').match(/^\/subscriptions\/([^/]+)/i)?.[1]?.toLowerCase()).filter(Boolean));
    if (subscriptions.size > 1) warnings.push('Terraform export supports one subscription at a time. Select a VNet and export each subscription separately.');
  } else {
    const scopes = new Set();
    resources.forEach(resource => {
      const scope = String(resource.id || '').match(/^(\/subscriptions\/[^/]+\/resourceGroups\/[^/]+)/i)?.[1];
      if (scope) scopes.add(scope.toLowerCase());
    });
    if (scopes.size > 1) warnings.push(format.toUpperCase() + ' export supports one subscription/resource group at a time. Select a VNet whose resources share one scope and export each scope separately.');
  }
  return warnings.length ? { code: '', warnings, stats: {}, blocked: true } : null;
}

// Apply export options before format-specific generators enumerate resources.
export function _selectIacData(data, options = {}) {
  data = { ...data, disks: data.disks ?? data.managedDisks ?? data.volumes ?? [] };
  const scope = (options.scopeVpcId || '').toLowerCase();
  const designOnly = options.designOnly || options.mode === 'create';
  const idOf = resource => String(resource.id || resource.VpcId || resource.SubnetId || resource.InstanceId || resource.GroupId || resource.RouteTableId || '').toLowerCase();
  const designIds = new Set((options.designResourceIds || []).map(id => String(id).toLowerCase()));
  const allVnets = data.vnets || [];
  const seenSubnets = new Set();
  const subnets = (data.subnets || []).concat(allVnets.flatMap(vnet => ((vnet.properties || vnet).subnets || []).map(subnet => ({ ...subnet, _vnetId: vnet.id })))).filter(subnet => {
    const id = idOf(subnet);
    if (id && seenSubnets.has(id)) return false;
    if (id) seenSubnets.add(id);
    return true;
  });
  const belongs = resource => {
    const id = idOf(resource);
    const props = resource.properties || resource;
    const related = [resource.VpcId, resource.vnetId, resource._vnetId, resource.SubnetId, resource.subnetId, props.subnet?.id,
      ...(props.ipConfigurations || []).map(ip => (ip.properties || ip).subnet?.id)];
    return !scope || id === scope || id.startsWith(scope + '/') || related.some(value => String(value || '').toLowerCase() === scope || String(value || '').toLowerCase().startsWith(scope + '/'));
  };
  const wanted = resource => belongs(resource) && (!designOnly || designIds.has(idOf(resource)));
  const selectedSubnets = subnets.filter(wanted);
  const subnetIds = new Set(selectedSubnets.map(idOf));
  const nics = (data.nics || []).filter(nic => wanted(nic) || (!designOnly && ((nic.properties || nic).ipConfigurations || []).some(ip => subnetIds.has(String((ip.properties || ip).subnet?.id || '').toLowerCase()))));
  const nicIds = new Set(nics.map(idOf));
  const selected = { ...data };
  for (const [key, resources] of Object.entries(data)) {
    if (Array.isArray(resources)) selected[key] = resources.filter(wanted);
  }
  selected.subnets = selectedSubnets;
  selected.nics = nics;
  selected.vms = (data.vms || []).filter(vm => wanted(vm) || (!designOnly && ((vm.properties || vm).networkProfile?.networkInterfaces || []).some(nic => nicIds.has(String(nic.id || '').toLowerCase()))));
  selected.vnets = allVnets.filter(vnet => wanted(vnet) || selectedSubnets.some(subnet => String(subnet.VpcId || subnet._vnetId || idOf(subnet).split('/subnets/')[0]).toLowerCase() === idOf(vnet))).map(vnet => ({
    ...vnet,
    _iacExistingParent: designOnly && !designIds.has(idOf(vnet)),
    properties: { ...(vnet.properties || vnet), subnets: selectedSubnets.filter(subnet => String(subnet.VpcId || subnet._vnetId || idOf(subnet).split('/subnets/')[0]).toLowerCase() === idOf(vnet)) }
  }));
  if (!designOnly) {
    const dependencyIds = new Set();
    selectedSubnets.forEach(subnet => {
      const props = subnet.properties || subnet;
      [props.networkSecurityGroup?.id, props.routeTable?.id, _subnetNatId(subnet, data.natGateways || [])].filter(Boolean).forEach(id => dependencyIds.add(id.toLowerCase()));
    });
    nics.forEach(nic => {
      const nsgId = (nic.properties || nic).networkSecurityGroup?.id;
      if (nsgId) dependencyIds.add(nsgId.toLowerCase());
    });
    for (const key of ['nsgs', 'subnetNsgs', 'udrs', 'natGateways']) {
      selected[key] = (data[key] || []).filter(resource => wanted(resource) || dependencyIds.has(idOf(resource)));
    }
    selected.publicIps = _natPublicIps({ natGateways: selected.natGateways, publicIps: data.publicIps });
    const vmIds = new Set(selected.vms.map(idOf));
    const attachedDiskIds = new Set(selected.vms.flatMap(vm => ((vm.properties || vm).storageProfile?.dataDisks || []).map(disk => String(disk.managedDisk?.id || '').toLowerCase())).filter(Boolean));
    selected.disks = (data.disks || []).filter(disk => wanted(disk) || attachedDiskIds.has(idOf(disk)) || vmIds.has(String(disk.managedBy || '').toLowerCase()));
    const rgIds = new Set(Object.values(selected).filter(Array.isArray).flat().map(resource => idOf(resource).match(/^.*\/resourcegroups\/[^/]+/i)?.[0]).filter(Boolean));
    selected.resourceGroups = (data.resourceGroups || []).filter(resource => rgIds.has(idOf(resource)));
  }
  return selected;
}

/**
 * Extract resource group name from an Azure resource ID.
 */
export function _rgFromId(id) {
  if (!id) return '';
  const m = id.match(/\/resourceGroups\/([^/]+)/i);
  return m ? m[1] : '';
}

/**
 * Extract the VNet name from a subnet ID.
 */
export function _vnetFromSubnetId(subnetId) {
  if (!subnetId) return '';
  const m = subnetId.match(/\/virtualNetworks\/([^/]+)/i);
  return m ? m[1] : '';
}

/**
 * Convert Azure tags object to ARM template tags format.
 */
export function _armTags(resource) {
  return resource.tags || {};
}

/**
 * Generate a unique logical ID for ARM template resources.
 */
export function _armId(name, prefix, seen) {
  let base = (name || prefix || 'Res').replace(/[^a-zA-Z0-9]/g, '');
  if (!base || /^\d/.test(base)) base = (prefix || 'R') + base;
  let id = base, i = 2;
  while (seen.has(id)) { id = base + i; i++; }
  seen.add(id);
  return id;
}
