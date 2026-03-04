// Flow Tracing — pure logic extracted from index.html FLOW TRACING region
// Azure networking model: NIC-NSG -> Subnet-NSG -> UDR -> Peering -> Subnet-NSG -> NIC-NSG
// Zero SVG/DOM rendering — all render functions stay inline
// Imports network evaluation from the already-extracted network-rules module

import {
  evaluateNsgRules,
  evaluateNsgPath,
  evaluateRoute,
} from './network-rules.js';

import { ipInCIDR } from './cidr-engine.js';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let _flowMode = false;
let _flowSource = null;
let _flowTarget = null;
let _flowConfig = { protocol: 'Tcp', port: 443 };
let _flowPath = null;
let _flowBlocked = null;
let _flowStepIndex = -1;
let _flowSelecting = null;

// Multi-hop waypoint state
let _flowWaypoints = [];        // [{ref:{type,id}, config:{protocol,port}}]
let _flowLegs = [];             // [{source,target,config,result:{path,blocked}}]
let _flowActiveLeg = -1;        // which leg is expanded in detail, -1 = all
let _flowSelectingWaypoint = -1;
let _flowSuggestions = [];      // [{via:{type,id,name}, leg1Result, leg2Result, leg1Config}]

// ---------------------------------------------------------------------------
// State getters / setters
// ---------------------------------------------------------------------------
export function getFlowMode() { return _flowMode; }
export function setFlowMode(v) { _flowMode = v; }

export function getFlowSource() { return _flowSource; }
export function setFlowSource(v) { _flowSource = v; }

export function getFlowTarget() { return _flowTarget; }
export function setFlowTarget(v) { _flowTarget = v; }

export function getFlowConfig() { return _flowConfig; }
export function setFlowConfig(v) { _flowConfig = v; }

export function getFlowPath() { return _flowPath; }
export function setFlowPath(v) { _flowPath = v; }

export function getFlowBlocked() { return _flowBlocked; }
export function setFlowBlocked(v) { _flowBlocked = v; }

export function getFlowStepIndex() { return _flowStepIndex; }
export function setFlowStepIndex(v) { _flowStepIndex = v; }

export function getFlowSelecting() { return _flowSelecting; }
export function setFlowSelecting(v) { _flowSelecting = v; }

export function getFlowWaypoints() { return _flowWaypoints; }
export function setFlowWaypoints(v) { _flowWaypoints = v; }

export function getFlowLegs() { return _flowLegs; }
export function setFlowLegs(v) { _flowLegs = v; }

export function getFlowActiveLeg() { return _flowActiveLeg; }
export function setFlowActiveLeg(v) { _flowActiveLeg = v; }

export function getFlowSelectingWaypoint() { return _flowSelectingWaypoint; }
export function setFlowSelectingWaypoint(v) { _flowSelectingWaypoint = v; }

export function getFlowSuggestions() { return _flowSuggestions; }
export function setFlowSuggestions(v) { _flowSuggestions = v; }

/** Reset all flow state to initial values. */
export function resetFlowState() {
  _flowMode = false;
  _flowSource = null;
  _flowTarget = null;
  _flowConfig = { protocol: 'Tcp', port: 443 };
  _flowPath = null;
  _flowBlocked = null;
  _flowStepIndex = -1;
  _flowSelecting = null;
  _flowWaypoints = [];
  _flowLegs = [];
  _flowActiveLeg = -1;
  _flowSelectingWaypoint = -1;
  _flowSuggestions = [];
}

// ---------------------------------------------------------------------------
// Helper: extract an IP from a CIDR or IP string
// ---------------------------------------------------------------------------
function ipFromCidr(cidr) {
  if (!cidr || typeof cidr !== 'string') return null;
  return cidr.split('/')[0];
}

// ---------------------------------------------------------------------------
// Helper: get VNet address prefixes for a given VNet id
// ---------------------------------------------------------------------------
function getVnetPrefixes(vnetId, ctx) {
  if (!vnetId || !ctx) return [];
  var vnet = (ctx.vnets || []).find(function (v) { return v.id === vnetId; });
  if (!vnet) return [];
  var addrSpace = vnet.addressSpace || vnet.properties?.addressSpace || {};
  return addrSpace.addressPrefixes || [];
}

// ---------------------------------------------------------------------------
// Helper: find NIC NSG for a resource
// ---------------------------------------------------------------------------
function getNicNsg(nicId, ctx) {
  if (!nicId || !ctx) return null;
  var nic = (ctx.nics || []).find(function (n) { return n.id === nicId; });
  if (!nic) return null;
  var nsgRef = nic.networkSecurityGroup || (nic.properties && nic.properties.networkSecurityGroup);
  if (!nsgRef || !nsgRef.id) return null;
  return (ctx.nsgs || []).find(function (nsg) { return nsg.id === nsgRef.id; });
}

// ---------------------------------------------------------------------------
// Helper: find subnet NSG
// ---------------------------------------------------------------------------
function getSubnetNsg(subnetId, ctx) {
  if (!subnetId || !ctx) return null;
  return (ctx.subnetNsgs || {})[subnetId] || null;
}

// ---------------------------------------------------------------------------
// Helper: get UDR/route table for a subnet
// ---------------------------------------------------------------------------
function getSubnetRouteTable(subnetId, ctx) {
  if (!subnetId || !ctx) return null;
  return (ctx.subRT || {})[subnetId] || null;
}

// ---------------------------------------------------------------------------
// Helper: get resource name from Azure resource object
// ---------------------------------------------------------------------------
function azureName(resource, fallback) {
  if (!resource) return fallback || 'unknown';
  return resource.name || resource.Name || fallback || 'unknown';
}

// ---------------------------------------------------------------------------
// suggestPort — map resource type to a sensible default port
// ---------------------------------------------------------------------------
export function suggestPort(targetType, targetResource) {
  if (targetType === 'sqldb') return 1433;
  if (targetType === 'mysql') return 3306;
  if (targetType === 'postgresql') return 5432;
  if (targetType === 'cosmosdb') return 443;
  if (targetType === 'redis') return 6380;
  if (targetType === 'lb') return 443;
  if (targetType === 'appgw') return 443;
  if (targetType === 'vm') return 22;
  if (targetType === 'functionapp') return 443;
  if (targetType === 'containerapp') return 443;
  if (targetType === 'aks') return 443;
  return 443;
}

// ---------------------------------------------------------------------------
// hopTypeLabel — human-readable labels for hop types
// ---------------------------------------------------------------------------
const HOP_TYPE_LABELS = {
  'source': 'Source',
  'target': 'Target',
  'udr': 'Route Table (UDR)',
  'nic-nsg-outbound': 'NIC NSG Outbound',
  'nic-nsg-inbound': 'NIC NSG Inbound',
  'subnet-nsg-outbound': 'Subnet NSG Outbound',
  'subnet-nsg-inbound': 'Subnet NSG Inbound',
  'peering': 'VNet Peering',
  'vnet-gateway': 'VNet Gateway',
  'cross-vnet': 'Cross-VNet',
  'error': 'Error',
  'internet-check': 'Internet Route Check',
};

export function hopTypeLabel(type) {
  return HOP_TYPE_LABELS[type] || type;
}

// ---------------------------------------------------------------------------
// resolveNetworkPosition — map a resource reference to its network position
// Returns {subnetId, vnetId, cidr, nicNsg, subnetNsg, name, ip?, nicId?} or null
// ---------------------------------------------------------------------------
export function resolveNetworkPosition(type, id, ctx) {
  if (!ctx) return null;

  if (type === 'internet') {
    return { subnetId: null, vnetId: null, cidr: '0.0.0.0/0', nicNsg: null, subnetNsg: null, name: 'Internet', ip: '0.0.0.0' };
  }

  if (type === 'subnet') {
    var sub = (ctx.subnets || []).find(function (s) { return s.id === id; });
    if (!sub) return null;
    return {
      subnetId: sub.id,
      vnetId: sub.vnetId,
      cidr: sub.addressPrefix,
      nicNsg: null,
      subnetNsg: getSubnetNsg(sub.id, ctx),
      name: azureName(sub, sub.id),
    };
  }

  if (type === 'vm') {
    var vm = null;
    Object.keys(ctx.vmsBySub || {}).forEach(function (sid) {
      (ctx.vmsBySub[sid] || []).forEach(function (v) {
        if (v.id === id || v.name === id) vm = v;
      });
    });
    if (!vm) return null;
    var vmSubnetId = vm.subnetId || null;
    var vmNicId = vm.nicId || null;
    var vmNicNsg = getNicNsg(vmNicId, ctx);
    var vmSubnetNsg = getSubnetNsg(vmSubnetId, ctx);
    var vmVnetId = vmSubnetId ? ((ctx.subnets || []).find(function (s) { return s.id === vmSubnetId; }) || {}).vnetId : null;
    return {
      subnetId: vmSubnetId,
      vnetId: vmVnetId,
      cidr: vm.privateIpAddress ? vm.privateIpAddress + '/32' : null,
      nicNsg: vmNicNsg,
      subnetNsg: vmSubnetNsg,
      name: azureName(vm, id),
      ip: vm.privateIpAddress,
      nicId: vmNicId,
    };
  }

  if (type === 'sqldb' || type === 'mysql' || type === 'postgresql' || type === 'cosmosdb') {
    var db = null; var dbSid = null;
    Object.keys(ctx.dbBySub || {}).forEach(function (sid) {
      (ctx.dbBySub[sid] || []).forEach(function (d) {
        if (d.id === id || d.name === id) { db = d; dbSid = sid; }
      });
    });
    if (!db) return null;
    var dbVnet = ((ctx.subnets || []).find(function (s) { return s.id === dbSid; }) || {}).vnetId;
    var dbSubnetNsg = getSubnetNsg(dbSid, ctx);
    var dbSubCidr = dbSid ? ((ctx.subnets || []).find(function (s) { return s.id === dbSid; }) || {}).addressPrefix : null;
    return { subnetId: dbSid, vnetId: dbVnet, cidr: dbSubCidr, nicNsg: null, subnetNsg: dbSubnetNsg, name: azureName(db, id) };
  }

  if (type === 'lb' || type === 'appgw') {
    var lb = null; var lbSid = null;
    Object.keys(ctx.lbBySub || {}).forEach(function (sid) {
      (ctx.lbBySub[sid] || []).forEach(function (a) {
        if (a.id === id || a.name === id) { lb = a; lbSid = sid; }
      });
    });
    if (!lb) return null;
    var lbVnet = ((ctx.subnets || []).find(function (s) { return s.id === lbSid; }) || {}).vnetId;
    var lbNicNsg = getNicNsg(lb.nicId, ctx);
    var lbSubnetNsg = getSubnetNsg(lbSid, ctx);
    return { subnetId: lbSid, vnetId: lbVnet, cidr: null, nicNsg: lbNicNsg, subnetNsg: lbSubnetNsg, name: azureName(lb, id) };
  }

  if (type === 'functionapp') {
    var fn = null; var fnSid = null;
    Object.keys(ctx.funcAppBySub || {}).forEach(function (sid) {
      (ctx.funcAppBySub[sid] || []).forEach(function (f) {
        if (f.id === id || f.name === id) { fn = f; fnSid = sid; }
      });
    });
    if (!fn) return null;
    var fnVnet = ((ctx.subnets || []).find(function (s) { return s.id === fnSid; }) || {}).vnetId;
    var fnSubnetNsg = getSubnetNsg(fnSid, ctx);
    return { subnetId: fnSid, vnetId: fnVnet, cidr: null, nicNsg: null, subnetNsg: fnSubnetNsg, name: azureName(fn, id) };
  }

  if (type === 'containerapp' || type === 'aks') {
    var ca = null; var caSid = null;
    Object.keys(ctx.containerBySub || {}).forEach(function (sid) {
      (ctx.containerBySub[sid] || []).forEach(function (c) {
        if (c.id === id || c.name === id) { ca = c; caSid = sid; }
      });
    });
    if (!ca) return null;
    var caVnet = ((ctx.subnets || []).find(function (s) { return s.id === caSid; }) || {}).vnetId;
    var caSubnetNsg = getSubnetNsg(caSid, ctx);
    return { subnetId: caSid, vnetId: caVnet, cidr: null, nicNsg: null, subnetNsg: caSubnetNsg, name: azureName(ca, id) };
  }

  if (type === 'redis') {
    var redis = null; var redisVnet = null;
    (ctx.redisCaches || []).forEach(function (c) { if (c.id === id || c.name === id) redis = c; });
    if (!redis) return null;
    var redisMap = ctx.redisByVnet || {};
    var redisKeys = redisMap instanceof Map ? Array.from(redisMap.keys()) : Object.keys(redisMap);
    redisKeys.forEach(function (vid) {
      var arr = redisMap instanceof Map ? redisMap.get(vid) : redisMap[vid];
      (arr || []).forEach(function (c) { if (c.id === id || c.name === id) redisVnet = vid; });
    });
    var redisSid = null;
    if (redisVnet) (ctx.subnets || []).forEach(function (s) { if (!redisSid && s.vnetId === redisVnet) redisSid = s.id; });
    var redisSubCidr = redisSid ? ((ctx.subnets || []).find(function (s) { return s.id === redisSid; }) || {}).addressPrefix : null;
    var redisSubnetNsg = getSubnetNsg(redisSid, ctx);
    return { subnetId: redisSid, vnetId: redisVnet, cidr: redisSubCidr, nicNsg: null, subnetNsg: redisSubnetNsg, name: azureName(redis, id) };
  }

  return null;
}

// ---------------------------------------------------------------------------
// resolveClickTarget — map an SVG element to {type, id}
// ---------------------------------------------------------------------------
export function resolveClickTarget(el, ctx, buildResTreeFn) {
  if (!ctx) return null;

  // Internet globe node
  var inetNode = el.closest('.internet-node');
  if (inetNode) return { type: 'internet', id: 'internet' };

  var resNode = el.closest('.res-node');
  var subNode = el.closest('.subnet-node');

  if (resNode && subNode) {
    var subId = subNode.getAttribute('data-subnet-id');
    var resIdx = Array.from(subNode.querySelectorAll('.res-node')).indexOf(resNode);
    var tree = buildResTreeFn ? buildResTreeFn(subId, ctx) : null;
    if (tree && tree[resIdx]) {
      var res = tree[resIdx];
      if (res.type === 'VM') return { type: 'vm', id: res.rid || '' };
      if (res.type === 'LB') return { type: 'lb', id: res.rid || res.name };
      if (res.type === 'APPGW') return { type: 'appgw', id: res.rid || res.name };
      if (res.type === 'SQL') return { type: 'sqldb', id: res.rid || res.name };
      if (res.type === 'MYSQL') return { type: 'mysql', id: res.rid || res.name };
      if (res.type === 'PGSQL') return { type: 'postgresql', id: res.rid || res.name };
      if (res.type === 'COSMOS') return { type: 'cosmosdb', id: res.rid || res.name };
      if (res.type === 'FN') return { type: 'functionapp', id: res.rid || res.name };
      if (res.type === 'AKS') return { type: 'aks', id: res.rid || res.name };
      if (res.type === 'CONTAINER') return { type: 'containerapp', id: res.rid || res.name };
      if (res.type === 'REDIS') return { type: 'redis', id: res.rid || res.name };
      if (res.type === 'NIC') return { type: 'subnet', id: subId };
    }
    return { type: 'subnet', id: subId };
  }

  if (subNode) {
    return { type: 'subnet', id: subNode.getAttribute('data-subnet-id') };
  }

  return null;
}

// ---------------------------------------------------------------------------
// evaluateNsgHop — evaluate a single NSG (NIC or subnet level) and produce a hop
// Returns { hop, action, detail, rule }
// ---------------------------------------------------------------------------
function evaluateNsgHop(nsg, direction, protocol, port, srcIp, dstIp, vnetPrefixes, opts) {
  if (!nsg) {
    return { action: 'allow', detail: 'No NSG attached (all traffic allowed)', rule: null };
  }

  var srcPort = '*';
  var evalDirection = direction === 'inbound' ? 'Inbound' : 'Outbound';

  if (opts && opts.assumeAllow) {
    return { action: 'allow', detail: 'NSG ' + azureName(nsg) + ' (assumed allow for discovery)', rule: null };
  }

  var result = evaluateNsgRules(nsg, evalDirection, protocol, srcIp, srcPort, dstIp, port, { vnetPrefixes: vnetPrefixes });
  var action = result.action === 'Allow' ? 'allow' : 'deny';
  var ruleName = result.rule ? result.rule.name : 'unknown';
  var priority = result.priority || 0;
  var detail = azureName(nsg) + ': ' + ruleName + ' (priority ' + priority + ', ' + result.action + ')';

  return { action: action, detail: detail, rule: result.rule };
}

// ---------------------------------------------------------------------------
// evaluateUdrHop — evaluate UDR for a destination and produce a hop
// ---------------------------------------------------------------------------
function evaluateUdrHop(routeTable, dstIp, vnetPrefixes) {
  if (!routeTable && (!vnetPrefixes || vnetPrefixes.length === 0)) {
    return { action: 'allow', nextHopType: 'Internet', detail: 'No UDR, default system routes apply', rule: null };
  }

  var rt = routeTable || {};
  if (!rt.vnetPrefixes && vnetPrefixes) {
    rt = Object.assign({}, rt, { vnetPrefixes: vnetPrefixes });
  }

  var result = evaluateRoute(rt, dstIp);
  var nextHop = result.nextHopType || 'None';
  var routeName = result.route ? result.route.name : 'system';
  var isSystem = result.route ? result.route.isSystem : true;

  if (nextHop === 'None') {
    return {
      action: 'block',
      nextHopType: 'None',
      detail: 'Route ' + routeName + ' drops traffic (nextHopType: None)',
      rule: result.route,
    };
  }

  var detail = 'Route ' + routeName + ' -> ' + nextHop;
  if (result.nextHopIpAddress) detail += ' (' + result.nextHopIpAddress + ')';
  if (isSystem) detail += ' [system route]';

  return { action: 'allow', nextHopType: nextHop, detail: detail, rule: result.route };
}

// ---------------------------------------------------------------------------
// traceInternetToResource — path from Internet to a resource
// Azure: Internet -> Subnet-NSG-Inbound -> NIC-NSG-Inbound -> Target
// ---------------------------------------------------------------------------
export function traceInternetToResource(target, config, ctx, opts) {
  var path = []; var hopN = 1;
  var tgtPos = resolveNetworkPosition(target.type, target.id, ctx);
  if (!tgtPos) return { path: [{ hop: 1, type: 'error', id: '-', action: 'block', detail: 'Cannot resolve target' }], blocked: { hop: 1, reason: 'Target not found' } };

  path.push({ hop: hopN++, type: 'source', id: 'Internet', action: 'allow', detail: 'Source: Internet (0.0.0.0/0)' });

  var vnetId = tgtPos.vnetId;
  var vnetPrefixes = getVnetPrefixes(vnetId, ctx);

  // Check if target subnet has a route from Internet (not overridden by UDR)
  var tgtRT = getSubnetRouteTable(tgtPos.subnetId, ctx);
  var rtWithPrefixes = tgtRT ? Object.assign({}, tgtRT, { vnetPrefixes: vnetPrefixes }) : { vnetPrefixes: vnetPrefixes };
  var internetRoute = evaluateRoute(rtWithPrefixes, '0.0.0.0');
  var hasInternetRoute = internetRoute.nextHopType === 'Internet';

  if (!hasInternetRoute) {
    path.push({ hop: hopN++, type: 'internet-check', id: 'No Internet route', action: 'block', detail: 'Target subnet has UDR overriding default Internet route (nextHopType: ' + internetRoute.nextHopType + ')' });
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Target unreachable from Internet', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: 2, reason: 'Target subnet default route overridden by UDR', suggestion: 'Remove UDR override for 0.0.0.0/0 or use Application Gateway / Load Balancer' } };
  }
  path.push({ hop: hopN++, type: 'internet-check', id: 'Internet route', action: 'allow', detail: 'Target subnet has default Internet route' });

  // Subnet NSG inbound check
  var nsgOpts = opts && opts.discovery ? { assumeAllow: true } : null;
  var tgtIp = tgtPos.ip || ipFromCidr(tgtPos.cidr) || '10.0.0.1';
  var subNsgIn = evaluateNsgHop(tgtPos.subnetNsg, 'inbound', config.protocol, config.port, '0.0.0.0', tgtIp, vnetPrefixes, nsgOpts);
  path.push({ hop: hopN++, type: 'subnet-nsg-inbound', id: tgtPos.subnetNsg ? azureName(tgtPos.subnetNsg) : 'No Subnet NSG', action: subNsgIn.action, detail: 'Subnet NSG inbound from Internet', rule: subNsgIn.rule });
  if (subNsgIn.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by Subnet NSG', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: hopN - 2, reason: 'Subnet NSG denies inbound from Internet', suggestion: 'Add NSG inbound rule allowing ' + config.protocol + '/' + config.port + ' from Internet' } };
  }

  // NIC NSG inbound check
  var nicNsgIn = evaluateNsgHop(tgtPos.nicNsg, 'inbound', config.protocol, config.port, '0.0.0.0', tgtIp, vnetPrefixes, nsgOpts);
  path.push({ hop: hopN++, type: 'nic-nsg-inbound', id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : 'No NIC NSG', action: nicNsgIn.action, detail: 'NIC NSG inbound from Internet', rule: nicNsgIn.rule });
  if (nicNsgIn.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by NIC NSG', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: hopN - 2, reason: 'NIC NSG denies inbound ' + config.protocol + '/' + config.port + ' from Internet', suggestion: 'Add NIC NSG inbound rule allowing ' + config.protocol + '/' + config.port + ' from Internet' } };
  }

  path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'allow', detail: 'Target: ' + (tgtPos.name || target.id) + ' (' + target.type + ')', subnetId: tgtPos.subnetId });
  return { path: path, blocked: null };
}

// ---------------------------------------------------------------------------
// traceResourceToInternet — path from a resource outbound to the Internet
// Azure: Source -> NIC-NSG-Outbound -> Subnet-NSG-Outbound -> UDR -> Internet
// ---------------------------------------------------------------------------
export function traceResourceToInternet(source, config, ctx, opts) {
  var path = []; var hopN = 1;
  var srcPos = resolveNetworkPosition(source.type, source.id, ctx);
  if (!srcPos) return { path: [{ hop: 1, type: 'error', id: '-', action: 'block', detail: 'Cannot resolve source' }], blocked: { hop: 1, reason: 'Source not found' } };

  var vnetPrefixes = getVnetPrefixes(srcPos.vnetId, ctx);
  var srcIp = srcPos.ip || ipFromCidr(srcPos.cidr) || '10.0.0.1';

  path.push({ hop: hopN++, type: 'source', id: srcPos.name || source.id, action: 'allow', detail: 'Source: ' + (srcPos.name || source.id) + ' (' + source.type + ')', subnetId: srcPos.subnetId });

  // NIC NSG outbound check
  var nsgOpts = opts && opts.discovery ? { assumeAllow: true } : null;
  var nicNsgOut = evaluateNsgHop(srcPos.nicNsg, 'outbound', config.protocol, config.port, srcIp, '0.0.0.0', vnetPrefixes, nsgOpts);
  path.push({ hop: hopN++, type: 'nic-nsg-outbound', id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : 'No NIC NSG', action: nicNsgOut.action, detail: 'NIC NSG outbound to Internet', rule: nicNsgOut.rule });
  if (nicNsgOut.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: 'Internet', action: 'block', detail: 'Blocked by NIC NSG' });
    return { path: path, blocked: { hop: 2, reason: 'NIC NSG denies outbound', suggestion: 'Add NIC NSG outbound rule allowing ' + config.protocol + '/' + config.port + ' to Internet' } };
  }

  // Subnet NSG outbound check
  var subNsgOut = evaluateNsgHop(srcPos.subnetNsg, 'outbound', config.protocol, config.port, srcIp, '0.0.0.0', vnetPrefixes, nsgOpts);
  path.push({ hop: hopN++, type: 'subnet-nsg-outbound', id: srcPos.subnetNsg ? azureName(srcPos.subnetNsg) : 'No Subnet NSG', action: subNsgOut.action, detail: 'Subnet NSG outbound to Internet', rule: subNsgOut.rule });
  if (subNsgOut.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: 'Internet', action: 'block', detail: 'Blocked by Subnet NSG' });
    return { path: path, blocked: { hop: hopN - 2, reason: 'Subnet NSG denies outbound to Internet', suggestion: 'Add Subnet NSG outbound rule allowing ' + config.protocol + '/' + config.port + ' to Internet' } };
  }

  // UDR check for Internet route
  var srcRT = getSubnetRouteTable(srcPos.subnetId, ctx);
  var udrHop = evaluateUdrHop(srcRT, '8.8.8.8', vnetPrefixes);
  if (udrHop.nextHopType === 'Internet') {
    path.push({ hop: hopN++, type: 'udr', id: srcRT ? azureName(srcRT) : 'System Routes', action: 'allow', detail: 'Route to Internet via default route', rule: udrHop.rule ? (udrHop.rule.addressPrefix + ' -> ' + udrHop.nextHopType) : '0.0.0.0/0 -> Internet' });
  } else if (udrHop.nextHopType === 'VirtualAppliance') {
    path.push({ hop: hopN++, type: 'udr', id: srcRT ? azureName(srcRT) : 'UDR', action: 'allow', detail: 'Route to Internet via NVA (' + (udrHop.rule && udrHop.rule.nextHopIpAddress || 'VirtualAppliance') + ')', rule: udrHop.detail });
  } else if (udrHop.action === 'block') {
    path.push({ hop: hopN++, type: 'udr', id: 'No route', action: 'block', detail: 'No route to Internet (' + udrHop.detail + ')' });
    path.push({ hop: hopN++, type: 'target', id: 'Internet', action: 'block', detail: 'No Internet route' });
    return { path: path, blocked: { hop: hopN - 2, reason: 'No route to Internet in route table', suggestion: 'Add UDR route 0.0.0.0/0 with nextHopType Internet or VirtualAppliance' } };
  } else {
    path.push({ hop: hopN++, type: 'udr', id: srcRT ? azureName(srcRT) : 'UDR', action: 'allow', detail: udrHop.detail, rule: udrHop.detail });
  }

  path.push({ hop: hopN++, type: 'target', id: 'Internet', action: 'allow', detail: 'Target: Internet (0.0.0.0/0)' });
  return { path: path, blocked: null };
}

// ---------------------------------------------------------------------------
// traceFlowLeg — single-hop leg evaluation (dispatches to the right tracer)
// ---------------------------------------------------------------------------
export function traceFlowLeg(source, target, config, ctx, opts) {
  if (source.type === 'internet') return traceInternetToResource(target, config, ctx, opts);
  if (target.type === 'internet') return traceResourceToInternet(source, config, ctx, opts);
  return traceFlow(source, target, config, ctx);
}

// ---------------------------------------------------------------------------
// traceFlow — main flow evaluation engine (resource-to-resource within VNets)
// Azure order:
//   Same subnet: NIC-NSG-Out -> NIC-NSG-In
//   Same VNet, different subnet: NIC-NSG-Out -> Subnet-NSG-Out -> UDR -> Subnet-NSG-In -> NIC-NSG-In
//   Cross-VNet: NIC-NSG-Out -> Subnet-NSG-Out -> UDR -> Peering -> Subnet-NSG-In -> NIC-NSG-In
// ---------------------------------------------------------------------------
export function traceFlow(source, target, config, ctx) {
  var path = [];
  var srcPos = resolveNetworkPosition(source.type, source.id, ctx);
  var tgtPos = resolveNetworkPosition(target.type, target.id, ctx);
  if (!srcPos) { return { path: [{ hop: 1, type: 'error', id: '-', action: 'block', detail: 'Cannot resolve source position' }], blocked: { hop: 1, reason: 'Source not found' } }; }
  if (!tgtPos) { return { path: [{ hop: 1, type: 'error', id: '-', action: 'block', detail: 'Cannot resolve target position' }], blocked: { hop: 1, reason: 'Target not found' } }; }

  var hopN = 1;
  var srcVnetPrefixes = getVnetPrefixes(srcPos.vnetId, ctx);
  var tgtVnetPrefixes = getVnetPrefixes(tgtPos.vnetId, ctx);
  var srcIp = srcPos.ip || ipFromCidr(srcPos.cidr) || '10.0.0.1';
  var tgtIp = tgtPos.ip || ipFromCidr(tgtPos.cidr) || '10.0.0.2';

  path.push({ hop: hopN++, type: 'source', id: srcPos.name || source.id, action: 'allow', detail: 'Source: ' + (srcPos.name || source.id) + ' (' + source.type + ') in subnet ' + (srcPos.subnetId || 'unknown'), subnetId: srcPos.subnetId });

  // Same-subnet path: only NIC NSG checks
  if (srcPos.subnetId && srcPos.subnetId === tgtPos.subnetId) {
    // NIC NSG outbound
    var nicOut = evaluateNsgHop(srcPos.nicNsg, 'outbound', config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
    path.push({ hop: hopN++, type: 'nic-nsg-outbound', id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : 'No NIC NSG', action: nicOut.action, detail: 'Source NIC NSG outbound check', rule: nicOut.rule });
    if (nicOut.action === 'deny') {
      var nicInSkip = evaluateNsgHop(tgtPos.nicNsg, 'inbound', config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
      path.push({ hop: hopN++, type: 'nic-nsg-inbound', id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : 'No NIC NSG', action: 'skip', detail: 'Skipped (blocked upstream)', rule: nicInSkip.rule });
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Target: ' + (tgtPos.name || target.id), subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: 2, reason: 'Source NIC NSG denies outbound ' + config.protocol + '/' + config.port, suggestion: 'Add outbound rule to source NIC NSG allowing ' + config.protocol + '/' + config.port + ' to ' + tgtIp } };
    }
    // NIC NSG inbound
    var nicIn = evaluateNsgHop(tgtPos.nicNsg, 'inbound', config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
    path.push({ hop: hopN++, type: 'nic-nsg-inbound', id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : 'No NIC NSG', action: nicIn.action, detail: 'Target NIC NSG inbound check', rule: nicIn.rule });
    if (nicIn.action === 'deny') {
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Target: ' + (tgtPos.name || target.id), subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'Target NIC NSG denies inbound ' + config.protocol + '/' + config.port, suggestion: 'Add inbound rule to target NIC NSG allowing ' + config.protocol + '/' + config.port + ' from ' + srcIp } };
    }
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'allow', detail: 'Target: ' + (tgtPos.name || target.id) + ' (' + target.type + ')', subnetId: tgtPos.subnetId });
    return { path: path, blocked: null };
  }

  // Same-VNet, different-subnet path
  if (srcPos.vnetId && srcPos.vnetId === tgtPos.vnetId) {
    // NIC NSG outbound
    var nicOut2 = evaluateNsgHop(srcPos.nicNsg, 'outbound', config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
    path.push({ hop: hopN++, type: 'nic-nsg-outbound', id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : 'No NIC NSG', action: nicOut2.action, detail: 'Source NIC NSG outbound', rule: nicOut2.rule });
    if (nicOut2.action === 'deny') {
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by NIC NSG', subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'Source NIC NSG denies outbound', suggestion: 'Add NIC NSG outbound rule for ' + config.protocol + '/' + config.port } };
    }

    // Subnet NSG outbound
    var subNsgOut2 = evaluateNsgHop(srcPos.subnetNsg, 'outbound', config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
    path.push({ hop: hopN++, type: 'subnet-nsg-outbound', id: srcPos.subnetNsg ? azureName(srcPos.subnetNsg) : 'No Subnet NSG', action: subNsgOut2.action, detail: 'Source Subnet NSG outbound', rule: subNsgOut2.rule });
    if (subNsgOut2.action === 'deny') {
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by Subnet NSG', subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'Source Subnet NSG denies outbound traffic', suggestion: 'Add Subnet NSG outbound rule allowing ' + config.protocol + '/' + config.port } };
    }

    // UDR check
    var srcRT2 = getSubnetRouteTable(srcPos.subnetId, ctx);
    var udrHop2 = evaluateUdrHop(srcRT2, tgtIp, srcVnetPrefixes);
    path.push({ hop: hopN++, type: 'udr', id: srcRT2 ? azureName(srcRT2) : 'System Routes', action: udrHop2.action === 'block' ? 'block' : 'allow', detail: 'Route table lookup for ' + tgtIp + ': ' + udrHop2.detail, rule: udrHop2.detail });
    if (udrHop2.action === 'block') {
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Target unreachable', subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'Route table has no route to destination', suggestion: 'Add a UDR route to ' + tgtIp } };
    }

    // Subnet NSG inbound
    var subNsgIn2 = evaluateNsgHop(tgtPos.subnetNsg, 'inbound', config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
    path.push({ hop: hopN++, type: 'subnet-nsg-inbound', id: tgtPos.subnetNsg ? azureName(tgtPos.subnetNsg) : 'No Subnet NSG', action: subNsgIn2.action, detail: 'Target Subnet NSG inbound', rule: subNsgIn2.rule });
    if (subNsgIn2.action === 'deny') {
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by Subnet NSG', subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'Target Subnet NSG denies inbound traffic', suggestion: 'Add Subnet NSG inbound rule allowing ' + config.protocol + '/' + config.port + ' from ' + srcIp } };
    }

    // NIC NSG inbound
    var nicIn2 = evaluateNsgHop(tgtPos.nicNsg, 'inbound', config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
    path.push({ hop: hopN++, type: 'nic-nsg-inbound', id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : 'No NIC NSG', action: nicIn2.action, detail: 'Target NIC NSG inbound', rule: nicIn2.rule });
    if (nicIn2.action === 'deny') {
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by NIC NSG', subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'Target NIC NSG denies inbound', suggestion: 'Add NIC NSG inbound rule for ' + config.protocol + '/' + config.port + ' from source' } };
    }

    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'allow', detail: 'Target: ' + (tgtPos.name || target.id) + ' (' + target.type + ')', subnetId: tgtPos.subnetId });
    return { path: path, blocked: null };
  }

  // Cross-VNet: evaluate source-side controls first
  // NIC NSG outbound
  var nicOutX = evaluateNsgHop(srcPos.nicNsg, 'outbound', config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
  path.push({ hop: hopN++, type: 'nic-nsg-outbound', id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : 'No NIC NSG', action: nicOutX.action, detail: 'Source NIC NSG outbound', rule: nicOutX.rule });
  if (nicOutX.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by NIC NSG', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: hopN - 2, reason: 'Source NIC NSG denies outbound', suggestion: 'Add NIC NSG outbound rule for ' + config.protocol + '/' + config.port } };
  }

  // Subnet NSG outbound
  var subNsgOutX = evaluateNsgHop(srcPos.subnetNsg, 'outbound', config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
  path.push({ hop: hopN++, type: 'subnet-nsg-outbound', id: srcPos.subnetNsg ? azureName(srcPos.subnetNsg) : 'No Subnet NSG', action: subNsgOutX.action, detail: 'Source Subnet NSG outbound', rule: subNsgOutX.rule });
  if (subNsgOutX.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by Subnet NSG', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: hopN - 2, reason: 'Source Subnet NSG denies outbound traffic', suggestion: 'Add Subnet NSG outbound rule allowing ' + config.protocol + '/' + config.port } };
  }

  // UDR check
  var srcRTx = getSubnetRouteTable(srcPos.subnetId, ctx);
  var udrHopX = evaluateUdrHop(srcRTx, tgtIp, srcVnetPrefixes);
  path.push({ hop: hopN++, type: 'udr', id: srcRTx ? azureName(srcRTx) : 'System Routes', action: udrHopX.action === 'block' ? 'block' : 'allow', detail: 'Route table lookup for ' + tgtIp + ': ' + udrHopX.detail, rule: udrHopX.detail });
  if (udrHopX.action === 'block') {
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Target unreachable', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: hopN - 2, reason: 'Route table has no route to destination', suggestion: 'Add a route to ' + tgtIp + ' via peering or VNet Gateway' } };
  }

  // Cross-VNet connectivity check (VNet peering)
  var peeringRoute = null;
  (ctx.peerings || []).forEach(function (p) {
    var remoteVnet = p.remoteVnetId || (p.remoteVirtualNetwork && p.remoteVirtualNetwork.id) || '';
    var localVnet = p.localVnetId || p.vnetId || '';
    if ((localVnet === srcPos.vnetId && remoteVnet === tgtPos.vnetId) ||
        (localVnet === tgtPos.vnetId && remoteVnet === srcPos.vnetId)) {
      peeringRoute = p;
    }
  });

  if (peeringRoute) {
    var peeringState = peeringRoute.peeringState || 'Connected';
    if (peeringState !== 'Connected') {
      path.push({ hop: hopN++, type: 'peering', id: azureName(peeringRoute), action: 'block', detail: 'VNet Peering exists but state is ' + peeringState });
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Target unreachable', subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'VNet peering is not in Connected state', suggestion: 'Ensure both sides of the peering are in Connected state' } };
    }
    path.push({ hop: hopN++, type: 'peering', id: azureName(peeringRoute), action: 'allow', detail: 'VNet Peering between ' + srcPos.vnetId + ' and ' + tgtPos.vnetId, rule: 'Peering: ' + azureName(peeringRoute) });
  } else {
    // Check for VNet Gateway
    var gatewayRoute = false;
    (ctx.vnetGateways || []).forEach(function (gw) {
      if (gw.vnetId === srcPos.vnetId || gw.vnetId === tgtPos.vnetId) gatewayRoute = true;
    });
    if (gatewayRoute) {
      path.push({ hop: hopN++, type: 'vnet-gateway', id: 'VNet Gateway', action: 'allow', detail: 'VNet Gateway route between VNets' });
    } else {
      path.push({ hop: hopN++, type: 'cross-vnet', id: 'No route', action: 'block', detail: 'No peering or VNet Gateway connection between VNets' });
      path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Target unreachable', subnetId: tgtPos.subnetId });
      return { path: path, blocked: { hop: hopN - 2, reason: 'No connectivity between VNets', suggestion: 'Create a VNet peering or VNet Gateway connection' } };
    }
  }

  // Target-side controls (Subnet-NSG-in, NIC-NSG-in)
  var subNsgInX = evaluateNsgHop(tgtPos.subnetNsg, 'inbound', config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
  path.push({ hop: hopN++, type: 'subnet-nsg-inbound', id: tgtPos.subnetNsg ? azureName(tgtPos.subnetNsg) : 'No Subnet NSG', action: subNsgInX.action, detail: 'Target Subnet NSG inbound', rule: subNsgInX.rule });
  if (subNsgInX.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by Subnet NSG', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: hopN - 2, reason: 'Target Subnet NSG denies inbound traffic', suggestion: 'Add Subnet NSG inbound rule allowing ' + config.protocol + '/' + config.port + ' from ' + srcIp } };
  }

  var nicInX = evaluateNsgHop(tgtPos.nicNsg, 'inbound', config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
  path.push({ hop: hopN++, type: 'nic-nsg-inbound', id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : 'No NIC NSG', action: nicInX.action, detail: 'Target NIC NSG inbound (cross-VNet)', rule: nicInX.rule });
  if (nicInX.action === 'deny') {
    path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'block', detail: 'Blocked by NIC NSG', subnetId: tgtPos.subnetId });
    return { path: path, blocked: { hop: hopN - 2, reason: 'Target NIC NSG denies inbound from cross-VNet source', suggestion: 'Add NIC NSG inbound rule for ' + config.protocol + '/' + config.port } };
  }

  path.push({ hop: hopN++, type: 'target', id: tgtPos.name || target.id, action: 'allow', detail: 'Target: ' + (tgtPos.name || target.id) + ' (' + target.type + ')', subnetId: tgtPos.subnetId });
  return { path: path, blocked: null };
}

// ---------------------------------------------------------------------------
// findAlternatePaths — find alternate routes via intermediary resources
// ---------------------------------------------------------------------------
export function findAlternatePaths(source, target, config, ctx) {
  if (!ctx) return [];
  var tgtPos = resolveNetworkPosition(target.type, target.id, ctx);
  if (!tgtPos) return [];
  var vnetId = tgtPos.vnetId;
  var results = [];

  // Collect candidates: VMs + LBs in the target VNet (or any VNet if source is internet)
  var candidates = [];
  var isInternet = source.type === 'internet';

  // Check for Azure Bastion in any AzureBastionSubnet
  (ctx.subnets || []).forEach(function (sub) {
    if (sub.name && sub.name.toLowerCase() === 'azurebastionsubnet') {
      var bastionVnet = sub.vnetId;
      if (isInternet || bastionVnet === vnetId) {
        candidates.push({ ref: { type: 'bastion', id: sub.id }, name: 'Azure Bastion (' + (sub.vnetId || '') + ')', isPub: true, defaultPort: 443 });
      }
    }
  });

  // VMs (potential jump boxes)
  var allVms = [];
  Object.keys(ctx.vmsBySub || {}).forEach(function (sid) {
    (ctx.vmsBySub[sid] || []).forEach(function (vm) { allVms.push(vm); });
  });
  allVms.forEach(function (vm) {
    var vmVnet = vm.vnetId || ((ctx.subnets || []).find(function (s) { return s.id === vm.subnetId; }) || {}).vnetId;
    if (!isInternet && vmVnet !== vnetId) return;
    if (vm.id === (target.type === 'vm' ? target.id : '')) return;
    if (vm.id === (source.type === 'vm' ? source.id : '')) return;
    var isPub = vm.publicIpAddress || (ctx.pubSubs && ctx.pubSubs.has(vm.subnetId));
    candidates.push({ ref: { type: 'vm', id: vm.id || vm.name }, name: azureName(vm, vm.id), isPub: !!isPub, defaultPort: 22 });
  });

  // Load Balancers / App Gateways
  Object.keys(ctx.lbBySub || {}).forEach(function (sid) {
    var sub = (ctx.subnets || []).find(function (s) { return s.id === sid; });
    if (!sub || (!isInternet && sub.vnetId !== vnetId)) return;
    (ctx.lbBySub[sid] || []).forEach(function (lb) {
      if (lb.id === (target.type === 'lb' ? target.id : '')) return;
      candidates.push({ ref: { type: 'lb', id: lb.id || lb.name }, name: azureName(lb, lb.id), isPub: true, defaultPort: 443 });
    });
  });

  // Sort: public first, then by name
  candidates.sort(function (a, b) { return (b.isPub ? 1 : 0) - (a.isPub ? 1 : 0); });

  // Test each candidate (max 20 tested, max 5 results)
  var tested = 0;
  for (var i = 0; i < candidates.length && tested < 20 && results.length < 5; i++) {
    var cand = candidates[i];
    tested++;
    var leg1Config = { protocol: 'Tcp', port: cand.defaultPort };
    var leg1 = traceFlowLeg(source, cand.ref, leg1Config, ctx);
    if (leg1.blocked) continue;
    var leg2 = traceFlowLeg(cand.ref, target, config, ctx);
    if (leg2.blocked) continue;
    results.push({ via: { type: cand.ref.type, id: cand.ref.id, name: cand.name }, leg1Result: leg1, leg2Result: leg2, leg1Config: leg1Config });
  }
  return results;
}
