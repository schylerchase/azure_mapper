// Design Mode — pure logic, state, constants, and validation engine
// Azure Network Mapper — rewritten from AWS design mode for Azure VNet/subnet constraints
// DOM-dependent functions (showDesignForm, renderChangeLog, injectDesignToolbar,
// exportDesignPlan) remain inline in index.html.

import { safeParse, ext, esc, gn } from './utils.js';
import { parseCIDR, cidrContains, cidrOverlap, splitCIDR, ipInCIDR } from './cidr-engine.js';

// ---------------------------------------------------------------------------
// State variables
// ---------------------------------------------------------------------------
let _designMode = false;
let _designChanges = [];
let _designBaseline = null;
let _designDebounce = null;
let _lastDesignValidation = null;
let _sidebarWasCollapsed = false;
let _designLocation = 'eastus';

// ---------------------------------------------------------------------------
// Getters / setters for state consumed by inline code
// ---------------------------------------------------------------------------
export function getDesignMode() { return _designMode; }
export function setDesignMode(v) { _designMode = v; }

export function getDesignChanges() { return _designChanges; }
export function setDesignChanges(v) { _designChanges = v; }

export function getDesignBaseline() { return _designBaseline; }
export function setDesignBaseline(v) { _designBaseline = v; }

export function getDesignDebounce() { return _designDebounce; }
export function setDesignDebounce(v) { _designDebounce = v; }

export function getLastDesignValidation() { return _lastDesignValidation; }
export function setLastDesignValidation(v) { _lastDesignValidation = v; }

export function getSidebarWasCollapsed() { return _sidebarWasCollapsed; }
export function setSidebarWasCollapsed(v) { _sidebarWasCollapsed = v; }

export function getDesignLocation() { return _designLocation; }
export function setDesignLocation(v) { _designLocation = v; }

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Azure locations (regions) with availability zone counts
export const _locationZones = {
  'eastus': 3,
  'eastus2': 3,
  'westus2': 3,
  'westus3': 3,
  'centralus': 3,
  'northcentralus': 0,
  'southcentralus': 3,
  'westeurope': 3,
  'northeurope': 3,
  'uksouth': 3,
  'ukwest': 0,
  'francecentral': 3,
  'germanywestcentral': 3,
  'swedencentral': 3,
  'norwayeast': 3,
  'switzerlandnorth': 3,
  'southeastasia': 3,
  'eastasia': 3,
  'japaneast': 3,
  'australiaeast': 3,
  'canadacentral': 3,
  'brazilsouth': 3,
  'koreacentral': 3,
  'southafricanorth': 3,
  'qatarcentral': 3,
  'uaenorth': 3,
  'israelcentral': 3,
  'italynorth': 3,
  'polandcentral': 3,
};

// Azure Constraints Registry (sourced from official Azure docs)
export const _azureConstraints = {
  vnet: {
    cidrPrefixMin: 8,
    cidrPrefixMax: 29,
    maxAddressPrefixes: 500,
    maxPerSubscription: 1000,
    rfc1918: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    cgnat: '100.64.0.0/10',
    reservedPrefixes: ['224.0.0.0/4', '255.255.255.255/32', '127.0.0.0/8', '169.254.0.0/16', '168.63.129.16/32']
  },
  subnet: {
    cidrPrefixMin: 8,
    cidrPrefixMax: 29,
    reservedIps: 5, // first 4 (network, gateway, 2x Azure DNS) + last (broadcast)
    maxPerVnet: 3000,
    specialSubnets: {
      AzureFirewallSubnet: { minPrefix: 26, exactName: true },
      AzureFirewallManagementSubnet: { minPrefix: 26, exactName: true },
      AzureBastionSubnet: { minPrefix: 26, exactName: true },
      GatewaySubnet: { minPrefix: 27, exactName: true },
      RouteServerSubnet: { minPrefix: 27, exactName: true },
    }
  },
  nsg: {
    maxPerSubscription: 5000,
    maxRulesPerNsg: 1000,
    defaultPriority: { min: 100, max: 4096 },
    reservedPriority: 65000 // Azure default rules start at 65000
  },
  routeTable: {
    maxPerSubscription: 200,
    maxRoutesPerTable: 400,
    reservedNextHops: ['VirtualNetworkGateway', 'VnetLocal', 'Internet', 'VirtualAppliance', 'None']
  },
  peering: {
    maxPerVnet: 500,
    noOverlappingCidrs: true,
    onePeerPerVnetPair: true
  },
  natGateway: {
    maxPerSubnet: 1,
    maxPublicIps: 16,
    maxPublicPrefixes: 16
  },
  publicIp: {
    maxPerSubscription: 1000
  }
};

// ---------------------------------------------------------------------------
// Validation Engine
// ---------------------------------------------------------------------------

/**
 * Validate a single design change against Azure constraints.
 * @param {Object} change - The design change to validate
 * @param {Object} ctx - Render-context (_rlCtx) or null
 * @returns {{valid:boolean, errors:string[], warnings:string[]}}
 */
export function validateDesignChange(change, ctx) {
  const errors = [], warnings = [];
  const vnets = ctx ? ctx.vnets || [] : [];
  const subnets = ctx ? ctx.subnets || [] : [];
  const nsgs = ctx ? ctx.nsgs || [] : [];
  const routeTables = ctx ? ctx.routeTables || [] : [];
  const natGateways = ctx ? ctx.natGateways || [] : [];
  const peerings = ctx ? ctx.peerings || [] : [];

  if (change.action === 'add_vnet') {
    const p = change.params;
    const cidr = parseCIDR(p.addressPrefix);
    if (!cidr) { errors.push('Invalid CIDR: ' + p.addressPrefix); return { valid: false, errors, warnings }; }
    const prefix = parseInt(p.addressPrefix.split('/')[1], 10);
    if (prefix < _azureConstraints.vnet.cidrPrefixMin || prefix > _azureConstraints.vnet.cidrPrefixMax)
      errors.push('VNet address prefix must be /8 to /29, got /' + prefix);
    const isRfc1918 = _azureConstraints.vnet.rfc1918.some(r => cidrContains(r, p.addressPrefix));
    const isCgnat = cidrContains(_azureConstraints.vnet.cgnat, p.addressPrefix);
    if (!isRfc1918 && !isCgnat) warnings.push('CIDR ' + p.addressPrefix + ' is not RFC 1918 or CGNAT range — verify this is intentional for public IP usage');
    const isReserved = _azureConstraints.vnet.reservedPrefixes.some(r => cidrOverlap(p.addressPrefix, r));
    if (isReserved) errors.push('Address prefix ' + p.addressPrefix + ' overlaps with a reserved range');
    vnets.forEach(v => {
      const vnetPrefixes = v.addressSpace?.addressPrefixes || [v.addressPrefix];
      vnetPrefixes.forEach(vp => {
        if (cidrOverlap(p.addressPrefix, vp))
          errors.push('Overlaps existing VNet ' + gn(v) + ' (' + vp + ')');
      });
    });
    if (vnets.length >= _azureConstraints.vnet.maxPerSubscription)
      warnings.push('Exceeds default limit of ' + _azureConstraints.vnet.maxPerSubscription + ' VNets per subscription');
  }

  if (change.action === 'add_subnet') {
    const p = change.params;
    const cidr = parseCIDR(p.addressPrefix);
    if (!cidr) { errors.push('Invalid CIDR: ' + p.addressPrefix); return { valid: false, errors, warnings }; }
    const prefix = parseInt(p.addressPrefix.split('/')[1], 10);
    if (prefix < _azureConstraints.subnet.cidrPrefixMin || prefix > _azureConstraints.subnet.cidrPrefixMax)
      errors.push('Subnet address prefix must be /8 to /29, got /' + prefix);
    const vnet = vnets.find(v => v.id === p.vnetId || v.name === p.vnetName);
    if (!vnet) { errors.push('VNet ' + (p.vnetId || p.vnetName) + ' not found'); return { valid: false, errors, warnings }; }
    const vnetPrefixes = vnet.addressSpace?.addressPrefixes || [vnet.addressPrefix];
    const withinVnet = vnetPrefixes.some(vp => cidrContains(vp, p.addressPrefix));
    if (!withinVnet) errors.push('Subnet CIDR ' + p.addressPrefix + ' is not within VNet address space');
    const vnetId = vnet.id || vnet.name;
    const vnetSubs = subnets.filter(s => s._vnetId === vnetId || s.vnetName === vnet.name);
    vnetSubs.forEach(s => {
      const subPrefix = s.addressPrefix || (s.properties?.addressPrefix);
      if (subPrefix && cidrOverlap(p.addressPrefix, subPrefix))
        errors.push('Overlaps subnet ' + gn(s) + ' (' + subPrefix + ')');
    });
    if (vnetSubs.length >= _azureConstraints.subnet.maxPerVnet)
      warnings.push('Exceeds limit of ' + _azureConstraints.subnet.maxPerVnet + ' subnets per VNet');
    // Check special subnet naming constraints
    const specialSubnet = _azureConstraints.subnet.specialSubnets[p.name];
    if (specialSubnet) {
      if (prefix > specialSubnet.minPrefix)
        errors.push(p.name + ' requires minimum /' + specialSubnet.minPrefix + ', got /' + prefix);
    }
    const usable = Math.pow(2, 32 - prefix) - _azureConstraints.subnet.reservedIps;
    warnings.push(usable + ' usable IPs (' + _azureConstraints.subnet.reservedIps + ' reserved by Azure: first 4 + last 1)');
  }

  if (change.action === 'split_subnet') {
    const subPrefix = change.target.addressPrefix || '';
    const prefix = parseInt(subPrefix.split('/')[1], 10);
    if (prefix >= _azureConstraints.subnet.cidrPrefixMax)
      errors.push('Cannot split /' + prefix + ' subnet (minimum Azure subnet is /' + _azureConstraints.subnet.cidrPrefixMax + ')');
    else {
      const newPrefix = prefix + 1;
      const usable = Math.pow(2, 32 - newPrefix) - _azureConstraints.subnet.reservedIps;
      warnings.push('Each half: /' + newPrefix + ' = ' + usable + ' usable IPs');
      if (usable < 8) warnings.push('Very small subnets — limited IP capacity');
    }
    const resources = ctx ? (ctx.resourcesBySub || {})[change.target.subnetId] || [] : [];
    if (resources.length) warnings.push(resources.length + ' resource(s) will require IP-based migration');
  }

  if (change.action === 'add_nat_gateway') {
    const p = change.params;
    if (p.subnetId) {
      const subNats = natGateways.filter(n => n.subnetId === p.subnetId);
      if (subNats.length >= _azureConstraints.natGateway.maxPerSubnet)
        errors.push('Subnet already has a NAT Gateway (limit: 1 per subnet)');
    }
  }

  if (change.action === 'add_route') {
    const p = change.params; const t = change.target;
    const dest = p.addressPrefix;
    if (dest !== '0.0.0.0/0' && !parseCIDR(dest)) errors.push('Invalid destination prefix: ' + dest);
    const rt = routeTables.find(r => r.id === t.routeTableId || r.name === t.routeTableName);
    if (rt) {
      const routes = rt.properties?.routes || rt.routes || [];
      if (routes.some(r => (r.properties?.addressPrefix || r.addressPrefix) === dest))
        errors.push('Route table already has a route for ' + dest);
      if (routes.length >= _azureConstraints.routeTable.maxRoutesPerTable)
        warnings.push('Exceeds limit of ' + _azureConstraints.routeTable.maxRoutesPerTable + ' routes per table');
    }
    if (dest === '0.0.0.0/0' && p.nextHopType === 'Internet')
      warnings.push('This will route all internet traffic directly — ensure NSG rules are appropriate');
  }

  if (change.action === 'add_nsg') {
    const p = change.params;
    if (nsgs.length >= _azureConstraints.nsg.maxPerSubscription)
      warnings.push('Exceeds limit of ' + _azureConstraints.nsg.maxPerSubscription + ' NSGs per subscription');
    const rules = [...(p.securityRules || [])];
    if (rules.length > _azureConstraints.nsg.maxRulesPerNsg)
      errors.push('Exceeds limit of ' + _azureConstraints.nsg.maxRulesPerNsg + ' rules per NSG');
    rules.forEach(r => {
      if (r.properties?.sourceAddressPrefix === '*' && r.properties?.access === 'Allow') {
        const port = r.properties?.destinationPortRange;
        if (port !== '80' && port !== '443')
          warnings.push('Rule "' + (r.name || 'unnamed') + '" allows all sources (*) on port ' + port + ' — consider restricting');
      }
    });
  }

  if (change.action === 'add_resource') {
    const p = change.params;
    if (p.subnetId) {
      const sub = subnets.find(s => s.id === p.subnetId || s.name === p.subnetName);
      if (sub) {
        const subAddrPrefix = sub.addressPrefix || sub.properties?.addressPrefix || '';
        const prefix = parseInt(subAddrPrefix.split('/')[1], 10);
        const usable = Math.pow(2, 32 - prefix) - _azureConstraints.subnet.reservedIps;
        const currentResources = (ctx ? (ctx.resourcesBySub || {})[p.subnetId] || [] : []).length;
        const remaining = usable - currentResources;
        if (remaining <= 0) warnings.push('Subnet ' + gn(sub) + ' has no remaining IP capacity (' + usable + ' usable, ' + currentResources + ' used)');
        else if (remaining < 5) warnings.push('Subnet ' + gn(sub) + ' has only ' + remaining + ' IPs remaining');
      }
    }
  }

  if (change.action === 'remove_resource') {
    const t = change.target;
    if (t.resourceType === 'Microsoft.Network/natGateways') {
      const affectedSubs = subnets.filter(s =>
        (s.properties?.natGateway?.id || s.natGatewayId) === t.resourceId
      );
      if (affectedSubs.length) warnings.push(affectedSubs.length + ' subnet(s) reference this NAT Gateway — they will lose outbound connectivity');
    }
    if (t.resourceType === 'subnet') {
      const resources = ctx ? (ctx.resourcesBySub || {})[t.resourceId] || [] : [];
      if (resources.length) warnings.push(resources.length + ' resource(s) in this subnet will lose connectivity');
    }
    if (t.resourceType === 'Microsoft.Network/networkSecurityGroups') {
      const affectedSubs = subnets.filter(s =>
        (s.properties?.networkSecurityGroup?.id || s.nsgId) === t.resourceId
      );
      if (affectedSubs.length) warnings.push(affectedSubs.length + ' subnet(s) reference this NSG — they will lose security rules');
    }
  }

  if (change.action === 'add_peering') {
    const p = change.params;
    const localVnet = vnets.find(v => v.id === p.localVnetId || v.name === p.localVnetName);
    const remoteVnet = vnets.find(v => v.id === p.remoteVnetId || v.name === p.remoteVnetName);
    if (localVnet && remoteVnet) {
      const localPrefixes = localVnet.addressSpace?.addressPrefixes || [localVnet.addressPrefix];
      const remotePrefixes = remoteVnet.addressSpace?.addressPrefixes || [remoteVnet.addressPrefix];
      localPrefixes.forEach(lp => {
        remotePrefixes.forEach(rp => {
          if (cidrOverlap(lp, rp))
            errors.push('Peering CIDRs overlap: ' + lp + ' / ' + rp);
        });
      });
    }
    const vnetPeerings = peerings.filter(peer =>
      peer.localVnetId === p.localVnetId || peer.remoteVnetId === p.localVnetId
    );
    if (vnetPeerings.length >= _azureConstraints.peering.maxPerVnet)
      warnings.push('Exceeds limit of ' + _azureConstraints.peering.maxPerVnet + ' peerings per VNet');
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Full-state cross-change validation.
 * @param {Object[]} changes - Array of design changes
 * @param {Object} ctx - Render context (_rlCtx)
 * @returns {{valid:boolean, errors:string[], warnings:string[], stats:Object}}
 */
export function validateDesignState(changes, ctx) {
  const errors = [], warnings = [], stats = {
    subnetsAdded: 0, natGatewaysAdded: 0, resourcesAdded: 0, removed: 0, routes: 0, nsgs: 0, peerings: 0
  };
  changes.forEach(ch => {
    if (ch.action === 'add_subnet') stats.subnetsAdded++;
    if (ch.action === 'add_nat_gateway') stats.natGatewaysAdded++;
    if (ch.action === 'add_resource') stats.resourcesAdded++;
    if (ch.action === 'remove_resource') stats.removed++;
    if (ch.action === 'add_route') stats.routes++;
    if (ch.action === 'add_nsg') stats.nsgs++;
    if (ch.action === 'add_peering') stats.peerings++;
  });
  if (ctx) {
    // Cross-check: subnet overlaps within each VNet
    const subsByVnet = {};
    (ctx.subnets || []).forEach(s => {
      const vnetId = s._vnetId || s.vnetId || '';
      (subsByVnet[vnetId] = subsByVnet[vnetId] || []).push(s);
    });
    Object.entries(subsByVnet).forEach(([vid, subs]) => {
      for (let i = 0; i < subs.length; i++) {
        for (let j = i + 1; j < subs.length; j++) {
          const cidrA = subs[i].addressPrefix || subs[i].properties?.addressPrefix || '';
          const cidrB = subs[j].addressPrefix || subs[j].properties?.addressPrefix || '';
          if (cidrA && cidrB && cidrOverlap(cidrA, cidrB))
            errors.push('Subnets ' + gn(subs[i]) + ' and ' + gn(subs[j]) + ' have overlapping address prefixes');
        }
      }
    });
    // Peering CIDR overlap check
    const peerPairs = [];
    (ctx.peerings || []).forEach(p => {
      const localPrefixes = p.localAddressPrefixes || [];
      const remotePrefixes = p.remoteAddressPrefixes || [];
      localPrefixes.forEach(lp => {
        remotePrefixes.forEach(rp => {
          if (cidrOverlap(lp, rp))
            errors.push('VNet Peering ' + gn(p) + ' — address spaces overlap: ' + lp + ' / ' + rp);
        });
      });
      const pair = [p.localVnetId, p.remoteVnetId].filter(Boolean).sort().join(':');
      if (pair && peerPairs.includes(pair)) warnings.push('Duplicate peering between VNets');
      if (pair) peerPairs.push(pair);
    });
    // Check for subnets without NSGs
    (ctx.subnets || []).forEach(s => {
      const hasNsg = s.properties?.networkSecurityGroup || s.nsgId;
      if (!hasNsg && s.name !== 'GatewaySubnet')
        warnings.push('Subnet ' + gn(s) + ' has no NSG attached — traffic is unrestricted');
    });
  }
  return { valid: errors.length === 0, errors, warnings, stats };
}

// ---------------------------------------------------------------------------
// Design Apply Functions — mutate textarea JSON via getter/setter callbacks
//
// Each function receives:
//   ch        - the design change object
//   getTa(id) - returns the current value string for a textarea ID
//   setTa(id, value) - sets the value string for a textarea ID
// ---------------------------------------------------------------------------

function _applyAddVnet(ch, getTa, setTa) {
  const raw = safeParse(getTa('in_vnets'));
  const vnets = raw ? ext(raw, ['value']) : [];
  const id = ch.params.vnetId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Network/virtualNetworks/vnet-design-' + Date.now());
  ch.params.vnetId = id;
  const name = ch.params.name || 'New-VNet';
  const vnet = {
    id: id,
    name: name,
    type: 'Microsoft.Network/virtualNetworks',
    location: ch.params.location || _designLocation,
    properties: {
      addressSpace: { addressPrefixes: [ch.params.addressPrefix] },
      subnets: [],
      provisioningState: 'Succeeded'
    },
    tags: ch.params.tags || {}
  };
  // Flatten for easier access
  vnet.addressPrefix = ch.params.addressPrefix;
  vnet.addressSpace = vnet.properties.addressSpace;
  vnets.push(vnet);
  setTa('in_vnets', JSON.stringify({ value: vnets }));
  ch._addedIds = [id];
  // Create default NSG
  const nsgRaw = safeParse(getTa('in_nsgs'));
  const nsgs = nsgRaw ? ext(nsgRaw, ['value']) : [];
  const nsgId = ch.params._nsgId || (id.replace('/virtualNetworks/', '/networkSecurityGroups/').replace(name, name + '-default-nsg'));
  ch.params._nsgId = nsgId;
  nsgs.push({
    id: nsgId,
    name: name + '-default-nsg',
    type: 'Microsoft.Network/networkSecurityGroups',
    location: ch.params.location || _designLocation,
    properties: {
      securityRules: [],
      defaultSecurityRules: [
        { name: 'AllowVnetInBound', properties: { priority: 65000, direction: 'Inbound', access: 'Allow', protocol: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: 'VirtualNetwork', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'AllowAzureLoadBalancerInBound', properties: { priority: 65001, direction: 'Inbound', access: 'Allow', protocol: '*', sourceAddressPrefix: 'AzureLoadBalancer', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'DenyAllInBound', properties: { priority: 65500, direction: 'Inbound', access: 'Deny', protocol: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'AllowVnetOutBound', properties: { priority: 65000, direction: 'Outbound', access: 'Allow', protocol: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: 'VirtualNetwork', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'AllowInternetOutBound', properties: { priority: 65001, direction: 'Outbound', access: 'Allow', protocol: '*', sourceAddressPrefix: '*', destinationAddressPrefix: 'Internet', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'DenyAllOutBound', properties: { priority: 65500, direction: 'Outbound', access: 'Deny', protocol: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' } }
      ],
      provisioningState: 'Succeeded'
    }
  });
  setTa('in_nsgs', JSON.stringify({ value: nsgs }));
}

function _applyAddSubnet(ch, getTa, setTa) {
  const raw = safeParse(getTa('in_subnets'));
  const subs = raw ? ext(raw, ['value']) : [];
  const subId = ch.params.subnetId || (ch.params.vnetId + '/subnets/subnet-design-' + Date.now());
  ch.params.subnetId = subId;
  const subnet = {
    id: subId,
    name: ch.params.name || 'New-Subnet',
    type: 'Microsoft.Network/virtualNetworks/subnets',
    properties: {
      addressPrefix: ch.params.addressPrefix,
      provisioningState: 'Succeeded'
    },
    _vnetId: ch.params.vnetId,
    vnetName: ch.params.vnetName,
    addressPrefix: ch.params.addressPrefix
  };
  if (ch.params.nsgId) {
    subnet.properties.networkSecurityGroup = { id: ch.params.nsgId };
    subnet.nsgId = ch.params.nsgId;
  }
  if (ch.params.routeTableId) {
    subnet.properties.routeTable = { id: ch.params.routeTableId };
    subnet.routeTableId = ch.params.routeTableId;
  }
  subs.push(subnet);
  setTa('in_subnets', JSON.stringify({ value: subs }));
  ch._addedIds = [subId];
}

function _applySplitSubnet(ch, getTa, setTa) {
  const raw = safeParse(getTa('in_subnets'));
  const subs = raw ? ext(raw, ['value']) : [];
  const idx = subs.findIndex(s => s.id === ch.target.subnetId || s.name === ch.target.subnetName);
  if (idx < 0) return;
  const orig = subs[idx];
  const origPrefix = orig.addressPrefix || orig.properties?.addressPrefix || '';
  const halves = splitCIDR(origPrefix);
  if (!halves) return;
  if (!ch.params.newIds) ch.params.newIds = [orig.id + '-a', orig.id + '-b'];
  const sub1 = {
    ...orig,
    id: ch.params.newIds[0],
    name: (ch.params.names?.[0]) || gn(orig) + '-a',
    addressPrefix: halves[0],
    properties: { ...orig.properties, addressPrefix: halves[0] }
  };
  const sub2 = {
    ...orig,
    id: ch.params.newIds[1],
    name: (ch.params.names?.[1]) || gn(orig) + '-b',
    addressPrefix: halves[1],
    properties: { ...orig.properties, addressPrefix: halves[1] }
  };
  subs.splice(idx, 1, sub1, sub2);
  setTa('in_subnets', JSON.stringify({ value: subs }));
  ch._removedIds = [ch.target.subnetId];
  ch._addedIds = [sub1.id, sub2.id];
  // Migrate VMs by IP
  const vmRaw = safeParse(getTa('in_vms'));
  if (vmRaw) {
    const vms = ext(vmRaw, ['value']);
    vms.forEach(vm => {
      const nicIds = vm.properties?.networkProfile?.networkInterfaces || [];
      nicIds.forEach(nicRef => {
        if (nicRef._subnetId === ch.target.subnetId && nicRef._privateIp) {
          nicRef._subnetId = ipInCIDR(nicRef._privateIp, halves[0]) ? sub1.id : sub2.id;
        }
      });
    });
    setTa('in_vms', JSON.stringify({ value: vms }));
  }
}

function _applyAddNatGateway(ch, getTa, setTa) {
  const raw = safeParse(getTa('in_nat_gateways'));
  const nats = raw ? ext(raw, ['value']) : [];
  const id = ch.params.natGatewayId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Network/natGateways/nat-design-' + Date.now());
  ch.params.natGatewayId = id;
  nats.push({
    id: id,
    name: ch.params.name || 'New-NAT-Gateway',
    type: 'Microsoft.Network/natGateways',
    location: ch.params.location || _designLocation,
    properties: {
      provisioningState: 'Succeeded',
      publicIpAddresses: ch.params.publicIpIds ? ch.params.publicIpIds.map(pip => ({ id: pip })) : [],
      subnets: ch.params.subnetId ? [{ id: ch.params.subnetId }] : []
    },
    subnetId: ch.params.subnetId
  });
  setTa('in_nat_gateways', JSON.stringify({ value: nats }));
  ch._addedIds = [id];
}

function _applyAddRoute(ch, getTa, setTa) {
  const raw = safeParse(getTa('in_route_tables'));
  const rts = raw ? ext(raw, ['value']) : [];
  const rt = rts.find(r => r.id === ch.target.routeTableId || r.name === ch.target.routeTableName);
  if (!rt) return;
  if (!rt.properties) rt.properties = {};
  if (!rt.properties.routes) rt.properties.routes = [];
  rt.properties.routes.push({
    name: ch.params.routeName || 'route-' + Date.now(),
    properties: {
      addressPrefix: ch.params.addressPrefix,
      nextHopType: ch.params.nextHopType,
      nextHopIpAddress: ch.params.nextHopIpAddress || undefined,
      provisioningState: 'Succeeded'
    }
  });
  setTa('in_route_tables', JSON.stringify({ value: rts }));
  ch._modifiedIds = [ch.target.routeTableId];
}

function _applyAddResource(ch, getTa, setTa) {
  const type = ch.params.resourceType;
  if (type === 'VM') {
    const raw = safeParse(getTa('in_vms'));
    const vms = raw ? ext(raw, ['value']) : [];
    const id = ch.params.resourceId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Compute/virtualMachines/vm-design-' + Date.now());
    ch.params.resourceId = id;
    vms.push({
      id: id,
      name: ch.params.name || 'New-VM',
      type: 'Microsoft.Compute/virtualMachines',
      location: ch.params.location || _designLocation,
      properties: {
        vmId: id,
        hardwareProfile: { vmSize: ch.params.vmSize || 'Standard_B2s' },
        storageProfile: { osDisk: { osType: ch.params.osType || 'Linux' } },
        networkProfile: {
          networkInterfaces: [{
            id: id.replace('/virtualMachines/', '/networkInterfaces/') + '-nic',
            _subnetId: ch.params.subnetId,
            _privateIp: ch.params.privateIp || ''
          }]
        },
        provisioningState: 'Succeeded'
      },
      _subnetId: ch.params.subnetId,
      _vnetId: ch.params.vnetId
    });
    setTa('in_vms', JSON.stringify({ value: vms }));
    ch._addedIds = [id];
  } else if (type === 'SQLDatabase') {
    const raw = safeParse(getTa('in_sql'));
    const dbs = raw ? ext(raw, ['value']) : [];
    const id = ch.params.resourceId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Sql/servers/sql-design-' + Date.now());
    ch.params.resourceId = id;
    dbs.push({
      id: id,
      name: ch.params.name || 'new-sql-server',
      type: 'Microsoft.Sql/servers',
      location: ch.params.location || _designLocation,
      properties: {
        fullyQualifiedDomainName: (ch.params.name || 'new-sql-server') + '.database.windows.net',
        administratorLogin: 'sqladmin',
        state: 'Ready'
      },
      _subnetId: ch.params.subnetId,
      _vnetId: ch.params.vnetId
    });
    setTa('in_sql', JSON.stringify({ value: dbs }));
    ch._addedIds = [id];
  } else if (type === 'FunctionApp') {
    const raw = safeParse(getTa('in_functions'));
    const fns = raw ? ext(raw, ['value']) : [];
    const id = ch.params.resourceId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Web/sites/func-design-' + Date.now());
    ch.params.resourceId = id;
    fns.push({
      id: id,
      name: ch.params.name || 'new-function',
      type: 'Microsoft.Web/sites',
      kind: 'functionapp',
      location: ch.params.location || _designLocation,
      properties: {
        state: 'Running',
        defaultHostName: (ch.params.name || 'new-function') + '.azurewebsites.net',
        virtualNetworkSubnetId: ch.params.subnetId
      },
      _subnetId: ch.params.subnetId,
      _vnetId: ch.params.vnetId
    });
    setTa('in_functions', JSON.stringify({ value: fns }));
    ch._addedIds = [id];
  } else if (type === 'AKS') {
    const raw = safeParse(getTa('in_aks'));
    const clusters = raw ? ext(raw, ['value']) : [];
    const id = ch.params.resourceId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.ContainerService/managedClusters/aks-design-' + Date.now());
    ch.params.resourceId = id;
    clusters.push({
      id: id,
      name: ch.params.name || 'new-aks-cluster',
      type: 'Microsoft.ContainerService/managedClusters',
      location: ch.params.location || _designLocation,
      properties: {
        provisioningState: 'Succeeded',
        agentPoolProfiles: [{
          name: 'nodepool1',
          count: ch.params.nodeCount || 3,
          vmSize: ch.params.vmSize || 'Standard_DS2_v2',
          vnetSubnetID: ch.params.subnetId
        }],
        networkProfile: {
          networkPlugin: ch.params.networkPlugin || 'azure',
          serviceCidr: ch.params.serviceCidr || '10.0.0.0/16',
          dnsServiceIP: ch.params.dnsServiceIP || '10.0.0.10'
        }
      },
      _subnetId: ch.params.subnetId,
      _vnetId: ch.params.vnetId
    });
    setTa('in_aks', JSON.stringify({ value: clusters }));
    ch._addedIds = [id];
  } else if (type === 'AppService') {
    const raw = safeParse(getTa('in_appservices'));
    const apps = raw ? ext(raw, ['value']) : [];
    const id = ch.params.resourceId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Web/sites/app-design-' + Date.now());
    ch.params.resourceId = id;
    apps.push({
      id: id,
      name: ch.params.name || 'new-app',
      type: 'Microsoft.Web/sites',
      kind: 'app',
      location: ch.params.location || _designLocation,
      properties: {
        state: 'Running',
        defaultHostName: (ch.params.name || 'new-app') + '.azurewebsites.net',
        virtualNetworkSubnetId: ch.params.subnetId
      },
      _subnetId: ch.params.subnetId,
      _vnetId: ch.params.vnetId
    });
    setTa('in_appservices', JSON.stringify({ value: apps }));
    ch._addedIds = [id];
  } else if (type === 'Redis') {
    const raw = safeParse(getTa('in_redis'));
    const caches = raw ? ext(raw, ['value']) : [];
    const id = ch.params.resourceId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Cache/Redis/redis-design-' + Date.now());
    ch.params.resourceId = id;
    caches.push({
      id: id,
      name: ch.params.name || 'new-redis',
      type: 'Microsoft.Cache/Redis',
      location: ch.params.location || _designLocation,
      properties: {
        provisioningState: 'Succeeded',
        hostName: (ch.params.name || 'new-redis') + '.redis.cache.windows.net',
        port: 6380,
        sku: { name: ch.params.skuName || 'Standard', family: 'C', capacity: ch.params.capacity || 1 },
        subnetId: ch.params.subnetId
      },
      _subnetId: ch.params.subnetId,
      _vnetId: ch.params.vnetId
    });
    setTa('in_redis', JSON.stringify({ value: caches }));
    ch._addedIds = [id];
  }
}

function _applyAddNsg(ch, getTa, setTa) {
  const raw = safeParse(getTa('in_nsgs'));
  const nsgs = raw ? ext(raw, ['value']) : [];
  const id = ch.params.nsgId || ('/subscriptions/design/resourceGroups/' + (ch.params.resourceGroup || 'design-rg') + '/providers/Microsoft.Network/networkSecurityGroups/nsg-design-' + Date.now());
  ch.params.nsgId = id;
  const nsg = {
    id: id,
    name: ch.params.name || 'new-nsg',
    type: 'Microsoft.Network/networkSecurityGroups',
    location: ch.params.location || _designLocation,
    properties: {
      securityRules: [],
      defaultSecurityRules: [
        { name: 'AllowVnetInBound', properties: { priority: 65000, direction: 'Inbound', access: 'Allow', protocol: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: 'VirtualNetwork', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'DenyAllInBound', properties: { priority: 65500, direction: 'Inbound', access: 'Deny', protocol: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'AllowVnetOutBound', properties: { priority: 65000, direction: 'Outbound', access: 'Allow', protocol: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: 'VirtualNetwork', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'AllowInternetOutBound', properties: { priority: 65001, direction: 'Outbound', access: 'Allow', protocol: '*', sourceAddressPrefix: '*', destinationAddressPrefix: 'Internet', sourcePortRange: '*', destinationPortRange: '*' } },
        { name: 'DenyAllOutBound', properties: { priority: 65500, direction: 'Outbound', access: 'Deny', protocol: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' } }
      ],
      provisioningState: 'Succeeded'
    }
  };
  if (ch.params.securityRules) {
    ch.params.securityRules.forEach(r => {
      nsg.properties.securityRules.push({
        name: r.name || 'rule-' + Date.now(),
        properties: {
          priority: r.priority || 100,
          direction: r.direction || 'Inbound',
          access: r.access || 'Allow',
          protocol: r.protocol || 'Tcp',
          sourceAddressPrefix: r.sourceAddressPrefix || '*',
          destinationAddressPrefix: r.destinationAddressPrefix || '*',
          sourcePortRange: r.sourcePortRange || '*',
          destinationPortRange: r.destinationPortRange || '*',
          provisioningState: 'Succeeded'
        }
      });
    });
  }
  nsgs.push(nsg);
  setTa('in_nsgs', JSON.stringify({ value: nsgs }));
  ch._addedIds = [id];
}

function _applyRemoveResource(ch, getTa, setTa) {
  ch._removedIds = [ch.target.resourceId];
  const type = ch.target.resourceType;

  if (type === 'VM' || type === 'Microsoft.Compute/virtualMachines') {
    const raw = safeParse(getTa('in_vms')); if (!raw) return;
    const vms = ext(raw, ['value']);
    setTa('in_vms', JSON.stringify({ value: vms.filter(v => v.id !== ch.target.resourceId) }));
  } else if (type === 'SQLDatabase' || type === 'Microsoft.Sql/servers') {
    const raw = safeParse(getTa('in_sql'));
    const dbs = raw ? ext(raw, ['value']) : [];
    setTa('in_sql', JSON.stringify({ value: dbs.filter(d => d.id !== ch.target.resourceId) }));
  } else if (type === 'FunctionApp' || type === 'Microsoft.Web/sites') {
    const raw = safeParse(getTa('in_functions'));
    const fns = raw ? ext(raw, ['value']) : [];
    setTa('in_functions', JSON.stringify({ value: fns.filter(f => f.id !== ch.target.resourceId) }));
  } else if (type === 'subnet') {
    const raw = safeParse(getTa('in_subnets'));
    const subs = raw ? ext(raw, ['value']) : [];
    setTa('in_subnets', JSON.stringify({ value: subs.filter(s => s.id !== ch.target.resourceId) }));
  } else if (type === 'Microsoft.Network/natGateways') {
    const raw = safeParse(getTa('in_nat_gateways'));
    const nats = raw ? ext(raw, ['value']) : [];
    setTa('in_nat_gateways', JSON.stringify({ value: nats.filter(n => n.id !== ch.target.resourceId) }));
  } else if (type === 'Microsoft.Network/networkSecurityGroups') {
    const raw = safeParse(getTa('in_nsgs'));
    const nsgs = raw ? ext(raw, ['value']) : [];
    setTa('in_nsgs', JSON.stringify({ value: nsgs.filter(n => n.id !== ch.target.resourceId) }));
  } else if (type === 'AKS' || type === 'Microsoft.ContainerService/managedClusters') {
    const raw = safeParse(getTa('in_aks'));
    const clusters = raw ? ext(raw, ['value']) : [];
    setTa('in_aks', JSON.stringify({ value: clusters.filter(c => c.id !== ch.target.resourceId) }));
  } else if (type === 'Redis' || type === 'Microsoft.Cache/Redis') {
    const raw = safeParse(getTa('in_redis'));
    const caches = raw ? ext(raw, ['value']) : [];
    setTa('in_redis', JSON.stringify({ value: caches.filter(c => c.id !== ch.target.resourceId) }));
  } else if (type === 'AppService') {
    const raw = safeParse(getTa('in_appservices'));
    const apps = raw ? ext(raw, ['value']) : [];
    setTa('in_appservices', JSON.stringify({ value: apps.filter(a => a.id !== ch.target.resourceId) }));
  }
}

/**
 * Map of action names to apply functions.
 * Each apply fn signature: (change, getTa, setTa)
 *   getTa(id) => string   — read textarea value
 *   setTa(id, val)        — write textarea value
 */
export const _designApplyFns = {
  add_vnet: _applyAddVnet,
  add_subnet: _applyAddSubnet,
  split_subnet: _applySplitSubnet,
  add_nat_gateway: _applyAddNatGateway,
  add_route: _applyAddRoute,
  add_resource: _applyAddResource,
  add_nsg: _applyAddNsg,
  add_peering: null, // peering mutations handled inline for now
  remove_resource: _applyRemoveResource,
};

// ---------------------------------------------------------------------------
// CLI / Warning generators (pure logic, no DOM)
// ---------------------------------------------------------------------------

/**
 * Generate Azure CLI commands for a single design change.
 * @param {Object} ch - Design change object
 * @returns {string[]} Array of CLI command strings
 */
export function _generateCLI(ch) {
  const cmds = [];
  const rg = ch.params.resourceGroup || '$RESOURCE_GROUP';
  const loc = ch.params.location || _designLocation;

  if (ch.action === 'add_vnet') {
    cmds.push(`az network vnet create --resource-group ${rg} --name ${ch.params.name || 'new-vnet'} --address-prefixes ${ch.params.addressPrefix} --location ${loc}`);
    cmds.push('# Default NSG is NOT created automatically — create one explicitly if needed');
  }

  if (ch.action === 'add_subnet') {
    const vnetName = ch.params.vnetName || '$VNET_NAME';
    let cmd = `az network vnet subnet create --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.params.name || 'new-subnet'} --address-prefixes ${ch.params.addressPrefix}`;
    if (ch.params.nsgId) cmd += ` --network-security-group ${ch.params.nsgName || ch.params.nsgId}`;
    if (ch.params.routeTableId) cmd += ` --route-table ${ch.params.routeTableName || ch.params.routeTableId}`;
    cmds.push(cmd);
  }

  if (ch.action === 'split_subnet') {
    cmds.push('# Split subnet: delete original, create two new');
    const vnetName = ch.params.vnetName || '$VNET_NAME';
    cmds.push(`az network vnet subnet delete --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.target.subnetName || '$SUBNET_NAME'}`);
    const halves = splitCIDR(ch.target.addressPrefix);
    if (halves) {
      cmds.push(`az network vnet subnet create --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.params.names?.[0] || 'split-a'} --address-prefixes ${halves[0]}`);
      cmds.push(`az network vnet subnet create --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.params.names?.[1] || 'split-b'} --address-prefixes ${halves[1]}`);
    }
  }

  if (ch.action === 'add_nat_gateway') {
    cmds.push(`az network public-ip create --resource-group ${rg} --name ${(ch.params.name || 'nat') + '-pip'} --sku Standard --location ${loc}`);
    cmds.push(`az network nat gateway create --resource-group ${rg} --name ${ch.params.name || 'new-nat-gateway'} --public-ip-addresses ${(ch.params.name || 'nat') + '-pip'} --idle-timeout 10 --location ${loc}`);
    if (ch.params.subnetId || ch.params.subnetName) {
      cmds.push(`az network vnet subnet update --resource-group ${rg} --vnet-name $VNET_NAME --name ${ch.params.subnetName || '$SUBNET_NAME'} --nat-gateway ${ch.params.name || 'new-nat-gateway'}`);
    }
  }

  if (ch.action === 'add_route') {
    const rtName = ch.target.routeTableName || '$ROUTE_TABLE_NAME';
    let cmd = `az network route-table route create --resource-group ${rg} --route-table-name ${rtName} --name ${ch.params.routeName || 'new-route'} --address-prefix ${ch.params.addressPrefix} --next-hop-type ${ch.params.nextHopType}`;
    if (ch.params.nextHopIpAddress) cmd += ` --next-hop-ip-address ${ch.params.nextHopIpAddress}`;
    cmds.push(cmd);
  }

  if (ch.action === 'add_nsg') {
    cmds.push(`az network nsg create --resource-group ${rg} --name ${ch.params.name || 'new-nsg'} --location ${loc}`);
    if (ch.params.securityRules) {
      ch.params.securityRules.forEach(r => {
        cmds.push(`az network nsg rule create --resource-group ${rg} --nsg-name ${ch.params.name || 'new-nsg'} --name ${r.name || 'rule'} --priority ${r.priority || 100} --direction ${r.direction || 'Inbound'} --access ${r.access || 'Allow'} --protocol ${r.protocol || 'Tcp'} --source-address-prefixes "${r.sourceAddressPrefix || '*'}" --destination-address-prefixes "${r.destinationAddressPrefix || '*'}" --destination-port-ranges "${r.destinationPortRange || '*'}"`);
      });
    }
  }

  if (ch.action === 'add_resource') {
    if (ch.params.resourceType === 'VM') {
      cmds.push(`az vm create --resource-group ${rg} --name ${ch.params.name || 'new-vm'} --image ${ch.params.image || 'Ubuntu2204'} --size ${ch.params.vmSize || 'Standard_B2s'} --subnet ${ch.params.subnetName || '$SUBNET_NAME'} --vnet-name ${ch.params.vnetName || '$VNET_NAME'} --admin-username azureuser --generate-ssh-keys --location ${loc}`);
    }
    if (ch.params.resourceType === 'SQLDatabase') {
      cmds.push(`az sql server create --resource-group ${rg} --name ${ch.params.name || 'new-sql-server'} --admin-user sqladmin --admin-password $SQL_PASSWORD --location ${loc}`);
      cmds.push(`az sql db create --resource-group ${rg} --server ${ch.params.name || 'new-sql-server'} --name ${ch.params.dbName || 'defaultdb'} --service-objective ${ch.params.serviceObjective || 'S0'}`);
    }
    if (ch.params.resourceType === 'FunctionApp') {
      cmds.push(`az functionapp create --resource-group ${rg} --name ${ch.params.name || 'new-function'} --storage-account $STORAGE_ACCOUNT --runtime ${ch.params.runtime || 'node'} --functions-version 4 --os-type ${ch.params.osType || 'Linux'}`);
      if (ch.params.subnetId) cmds.push(`az functionapp vnet-integration add --resource-group ${rg} --name ${ch.params.name || 'new-function'} --vnet ${ch.params.vnetName || '$VNET_NAME'} --subnet ${ch.params.subnetName || '$SUBNET_NAME'}`);
    }
    if (ch.params.resourceType === 'AKS') {
      cmds.push(`az aks create --resource-group ${rg} --name ${ch.params.name || 'new-aks'} --node-count ${ch.params.nodeCount || 3} --node-vm-size ${ch.params.vmSize || 'Standard_DS2_v2'} --network-plugin ${ch.params.networkPlugin || 'azure'} --vnet-subnet-id ${ch.params.subnetId || '$SUBNET_ID'} --generate-ssh-keys --location ${loc}`);
    }
    if (ch.params.resourceType === 'AppService') {
      cmds.push(`az webapp create --resource-group ${rg} --name ${ch.params.name || 'new-app'} --plan $APP_SERVICE_PLAN`);
      if (ch.params.subnetId) cmds.push(`az webapp vnet-integration add --resource-group ${rg} --name ${ch.params.name || 'new-app'} --vnet ${ch.params.vnetName || '$VNET_NAME'} --subnet ${ch.params.subnetName || '$SUBNET_NAME'}`);
    }
    if (ch.params.resourceType === 'Redis') {
      cmds.push(`az redis create --resource-group ${rg} --name ${ch.params.name || 'new-redis'} --sku ${ch.params.skuName || 'Standard'} --vm-size ${ch.params.capacity || 'c1'} --location ${loc}`);
      if (ch.params.subnetId) cmds.push(`az redis update --resource-group ${rg} --name ${ch.params.name || 'new-redis'} --set subnetId=${ch.params.subnetId}`);
    }
  }

  if (ch.action === 'add_peering') {
    const localVnet = ch.params.localVnetName || '$LOCAL_VNET';
    const remoteVnet = ch.params.remoteVnetName || '$REMOTE_VNET';
    const remoteVnetId = ch.params.remoteVnetId || '$REMOTE_VNET_ID';
    cmds.push(`az network vnet peering create --resource-group ${rg} --name ${localVnet}-to-${remoteVnet} --vnet-name ${localVnet} --remote-vnet ${remoteVnetId} --allow-vnet-access`);
    cmds.push(`# Create reverse peering in remote VNet's resource group:`);
    cmds.push(`az network vnet peering create --resource-group $REMOTE_RG --name ${remoteVnet}-to-${localVnet} --vnet-name ${remoteVnet} --remote-vnet ${ch.params.localVnetId || '$LOCAL_VNET_ID'} --allow-vnet-access`);
  }

  if (ch.action === 'remove_resource') {
    const id = ch.target.resourceId;
    const name = ch.target.resourceName || id.split('/').pop();
    const t = ch.target.resourceType;
    if (t === 'VM' || t === 'Microsoft.Compute/virtualMachines')
      cmds.push(`az vm delete --resource-group ${rg} --name ${name} --yes`);
    if (t === 'SQLDatabase' || t === 'Microsoft.Sql/servers')
      cmds.push(`az sql server delete --resource-group ${rg} --name ${name} --yes`);
    if (t === 'FunctionApp' || t === 'Microsoft.Web/sites')
      cmds.push(`az functionapp delete --resource-group ${rg} --name ${name}`);
    if (t === 'subnet')
      cmds.push(`az network vnet subnet delete --resource-group ${rg} --vnet-name $VNET_NAME --name ${name}`);
    if (t === 'Microsoft.Network/natGateways')
      cmds.push(`az network nat gateway delete --resource-group ${rg} --name ${name}`);
    if (t === 'Microsoft.Network/networkSecurityGroups')
      cmds.push(`az network nsg delete --resource-group ${rg} --name ${name}`);
    if (t === 'AKS' || t === 'Microsoft.ContainerService/managedClusters')
      cmds.push(`az aks delete --resource-group ${rg} --name ${name} --yes`);
    if (t === 'Redis' || t === 'Microsoft.Cache/Redis')
      cmds.push(`az redis delete --resource-group ${rg} --name ${name} --yes`);
    if (t === 'AppService')
      cmds.push(`az webapp delete --resource-group ${rg} --name ${name}`);
  }

  return cmds;
}

/**
 * Generate high-level warnings for the design plan.
 * @returns {string[]} Array of warning strings
 */
export function _generateWarnings() {
  const w = [];
  const splits = _designChanges.filter(c => c.action === 'split_subnet');
  if (splits.length) w.push(splits.length + ' subnet split(s) require resource migration');
  const removes = _designChanges.filter(c => c.action === 'remove_resource');
  if (removes.length) w.push(removes.length + ' resource removal(s) — verify dependencies first');
  const noNsg = _designChanges.filter(c => c.action === 'add_subnet' && !c.params.nsgId);
  if (noNsg.length) w.push(noNsg.length + ' new subnet(s) without NSG — consider attaching one');
  return w;
}

/**
 * Import a previously exported design plan (JSON).
 * Requires enterDesignMode() and addDesignChange() to be provided as callbacks
 * since they have DOM dependencies.
 * @param {string|Object} json - Plan JSON string or object
 * @param {Function} enterFn - enterDesignMode callback
 * @param {Function} addChangeFn - addDesignChange callback
 */
export function importDesignPlan(json, enterFn, addChangeFn) {
  try {
    const plan = typeof json === 'string' ? JSON.parse(json) : json;
    if (!plan.changes || !Array.isArray(plan.changes)) { alert('Invalid plan format'); return; }
    if (!_designMode) enterFn();
    if (plan.location) _designLocation = plan.location;
    let imported = 0, blocked = 0;
    plan.changes.forEach(ch => {
      addChangeFn(ch);
      if (ch._invalid) blocked++; else imported++;
    });
    if (blocked > 0) alert('Imported ' + imported + ' changes, ' + blocked + ' blocked by validation errors. Check the change log for details.');
  } catch (e) { alert('Failed to import plan: ' + e.message); }
}

/**
 * Get available Azure locations for display.
 * @returns {string[]} Sorted list of Azure location names
 */
export function getAvailableLocations() {
  return Object.keys(_locationZones).sort();
}

/**
 * Get the number of availability zones for a location.
 * @param {string} location - Azure location name
 * @returns {number} Number of AZs (0 if no zonal support)
 */
export function getZoneCount(location) {
  return _locationZones[location] || 0;
}

// ---------------------------------------------------------------------------
// Window bridge: expose to inline code that still calls these functions
// ---------------------------------------------------------------------------
// Controlled access to design state — prevents unaudited external mutations
Object.defineProperty(window, '_designMode', {
  get() { return _designMode; },
  set(v) { _designMode = v; },
  configurable: true
});
Object.defineProperty(window, '_designChanges', {
  get() { return _designChanges; },
  set(v) { _designChanges = v; },
  configurable: true
});
Object.defineProperty(window, '_designBaseline', {
  get() { return _designBaseline; },
  set(v) { _designBaseline = v; },
  configurable: true
});
Object.defineProperty(window, '_designDebounce', {
  get() { return _designDebounce; },
  set(v) { _designDebounce = v; },
  configurable: true
});
Object.defineProperty(window, '_lastDesignValidation', {
  get() { return _lastDesignValidation; },
  set(v) { _lastDesignValidation = v; },
  configurable: true
});
Object.defineProperty(window, '_sidebarWasCollapsed', {
  get() { return _sidebarWasCollapsed; },
  set(v) { _sidebarWasCollapsed = v; },
  configurable: true
});
Object.defineProperty(window, '_designLocation', {
  get() { return _designLocation; },
  set(v) { _designLocation = v; },
  configurable: true
});
window._locationZones = _locationZones;
window._azureConstraints = _azureConstraints;
window._designApplyFns = _designApplyFns;
window.validateDesignChange = validateDesignChange;
window.validateDesignState = validateDesignState;
window._generateCLI = _generateCLI;
window._generateWarnings = _generateWarnings;
window.importDesignPlan = importDesignPlan;
window.getAvailableLocations = getAvailableLocations;
window.getZoneCount = getZoneCount;

// State sync helpers: inline code mutates the module state via these
window.getDesignMode = getDesignMode;
window.setDesignMode = setDesignMode;
window.getDesignChanges = getDesignChanges;
window.setDesignChanges = setDesignChanges;
window.getDesignBaseline = getDesignBaseline;
window.setDesignBaseline = setDesignBaseline;
window.getDesignDebounce = getDesignDebounce;
window.setDesignDebounce = setDesignDebounce;
window.getLastDesignValidation = getLastDesignValidation;
window.setLastDesignValidation = setLastDesignValidation;
window.getSidebarWasCollapsed = getSidebarWasCollapsed;
window.setSidebarWasCollapsed = setSidebarWasCollapsed;
window.getDesignLocation = getDesignLocation;
window.setDesignLocation = setDesignLocation;
