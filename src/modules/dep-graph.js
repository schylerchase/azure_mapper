// Dependency Graph / Blast Radius — pure logic
// Builds resource dependency graphs and computes blast radius for impact analysis.
// DOM display functions (showDependencies, blast highlighting) remain inline
// until they can be modernized with dom-builders.js in Phase 5.

import { rlCtx, mapG } from './state.js';
import { esc } from './utils.js';
import { showToast } from './dom-helpers.js';

// Module state
let depGraph = null;
let blastActive = false;

/**
 * Build a dependency graph from parsed Azure context.
 * @param {Object} ctx - parsed Azure resource context
 * @returns {Object} adjacency list: { resourceId: [{id, rel, strength}] }
 */
export function buildDependencyGraph(ctx) {
  if (!ctx) return {};
  const g = {};
  const addEdge = (from, to, rel, strength) => {
    if (!g[from]) g[from] = [];
    g[from].push({ id: to, rel, strength });
  };

  // VNet -> subnets, NAT gateways, private endpoints, UDRs, NSGs
  (ctx.vnets || []).forEach(v => {
    const vnetId = v.id;
    (ctx.subnets || []).filter(s => s.properties && s.properties.vnetId === vnetId).forEach(s => addEdge(vnetId, s.id, 'contains', 'hard'));
    (ctx.natGateways || []).filter(n => n.properties && n.properties.vnetId === vnetId).forEach(n => addEdge(vnetId, n.id, 'contains', 'hard'));
    (ctx.privateEndpoints || []).filter(e => e.properties && e.properties.vnetId === vnetId).forEach(e => addEdge(vnetId, e.id, 'contains', 'soft'));
    (ctx.udrs || []).filter(rt => rt.properties && rt.properties.vnetId === vnetId).forEach(rt => addEdge(vnetId, rt.id, 'contains', 'config'));
    (ctx.subnetNsgs || []).filter(n => n.properties && n.properties.vnetId === vnetId).forEach(n => addEdge(vnetId, n.id, 'contains', 'config'));
    (ctx.nsgs || []).filter(sg => sg.properties && sg.properties.vnetId === vnetId).forEach(sg => addEdge(vnetId, sg.id, 'contains', 'config'));
    // VNet peerings
    (ctx.peerings || []).filter(p => p.properties && (p.properties.localVnetId === vnetId || p.properties.remoteVnetId === vnetId)).forEach(p => addEdge(vnetId, p.id, 'peered_with', 'soft'));
  });

  // Subnet -> resources
  (ctx.subnets || []).forEach(sub => {
    const subId = sub.id;
    ((ctx.vmsBySub || {})[subId] || []).forEach(i => addEdge(subId, i.id, 'contains', 'hard'));
    ((ctx.sqlBySub || {})[subId] || []).forEach(r => addEdge(subId, r.id, 'contains', 'hard'));
    ((ctx.containersBySub || {})[subId] || []).forEach(e => addEdge(subId, e.id, 'contains', 'hard'));
    ((ctx.funcAppsBySub || {})[subId] || []).forEach(l => addEdge(subId, l.id, 'contains', 'hard'));
    ((ctx.agwBySub || {})[subId] || []).forEach(a => addEdge(subId, a.id, 'contains', 'hard'));
    // Subnet -> UDR
    const udr = (ctx.subUdr || {})[subId];
    if (udr) addEdge(subId, udr.id, 'associated', 'config');
    // Subnet -> NSG
    const nsg = (ctx.subNsg || {})[subId];
    if (nsg) addEdge(subId, nsg.id, 'associated', 'config');
    // Private endpoints in subnet
    (ctx.privateEndpoints || []).filter(e => e.properties && e.properties.subnetId === subId).forEach(e => addEdge(subId, e.id, 'contains', 'soft'));
    // NAT gateway attached to subnet
    const nat = (ctx.subNat || {})[subId];
    if (nat) addEdge(subId, nat.id, 'associated', 'config');
  });

  // VM -> NSGs + Managed Disks
  (ctx.vms || []).forEach(vm => {
    const vmId = vm.id;
    // NICs associated with VM
    (ctx.nics || []).filter(n => n.properties && n.properties.virtualMachine && n.properties.virtualMachine.id === vmId).forEach(nic => {
      addEdge(vmId, nic.id, 'attached', 'hard');
      // NIC -> NSG
      if (nic.properties && nic.properties.networkSecurityGroup) addEdge(nic.id, nic.properties.networkSecurityGroup.id, 'secured_by', 'soft');
    });
    // Managed disks
    (ctx.disks || []).filter(d => d.properties && d.managedBy === vmId).forEach(d => addEdge(vmId, d.id, 'attached', 'hard'));
  });

  // SQL Server -> NSGs
  (ctx.sqlServers || []).forEach(db => {
    if (db.properties && db.properties.networkSecurityGroupId) addEdge(db.id, db.properties.networkSecurityGroupId, 'secured_by', 'soft');
  });

  // App Gateway -> NSGs
  (ctx.appGateways || []).forEach(agw => {
    const agwId = agw.id;
    if (agw.properties && agw.properties.networkSecurityGroupId) addEdge(agwId, agw.properties.networkSecurityGroupId, 'secured_by', 'soft');
  });

  // NSG -> NSG references (config)
  (ctx.nsgs || []).forEach(sg => {
    const rules = (sg.properties && sg.properties.securityRules) || [];
    rules.forEach(r => {
      const src = r.properties && r.properties.sourceAddressPrefix;
      const dst = r.properties && r.properties.destinationAddressPrefix;
      // Reference to another NSG by resource ID
      if (src && src.startsWith('/subscriptions/') && src !== sg.id) addEdge(sg.id, src, 'references', 'config');
      if (dst && dst.startsWith('/subscriptions/') && dst !== sg.id) addEdge(sg.id, dst, 'references', 'config');
    });
  });

  // UDR -> gateways / next hops
  (ctx.udrs || []).forEach(rt => {
    const routes = (rt.properties && rt.properties.routes) || [];
    routes.forEach(r => {
      const hop = r.properties && r.properties.nextHopIpAddress;
      if (hop && hop !== 'VirtualNetworkGateway' && hop !== 'Internet') addEdge(rt.id, hop, 'routes_through', 'config');
      // Reference to virtual appliance or gateway by resource ID
      const hopType = r.properties && r.properties.nextHopType;
      if (hopType === 'VirtualAppliance' && hop) addEdge(rt.id, hop, 'routes_through', 'config');
    });
  });

  // VNet Peerings -> VNets
  (ctx.peerings || []).forEach(p => {
    if (p.properties && p.properties.localVnetId) addEdge(p.id, p.properties.localVnetId, 'connects', 'soft');
    if (p.properties && p.properties.remoteVnetId) addEdge(p.id, p.properties.remoteVnetId, 'connects', 'soft');
  });

  // NAT Gateway -> Subnet
  (ctx.natGateways || []).forEach(nat => {
    const subs = (nat.properties && nat.properties.subnets) || [];
    subs.forEach(s => addEdge(nat.id, s.id, 'attached_to', 'hard'));
  });

  depGraph = g;
  return g;
}

/**
 * BFS from resourceId to find all dependent resources within maxDepth hops.
 * @param {string} resourceId
 * @param {Object} graph - adjacency list from buildDependencyGraph
 * @param {number} [maxDepth=5]
 * @returns {{hard:Array, soft:Array, config:Array, all:Array}}
 */
export function getBlastRadius(resourceId, graph, maxDepth) {
  maxDepth = maxDepth || 5;
  const result = { hard: [], soft: [], config: [], all: [] };
  const visited = new Set([resourceId]);
  const queue = [{ id: resourceId, depth: 0 }];
  while (queue.length) {
    const { id, depth } = queue.shift();
    if (depth >= maxDepth) continue;
    const edges = graph[id] || [];
    edges.forEach(e => {
      if (visited.has(e.id)) return;
      visited.add(e.id);
      const entry = { id: e.id, rel: e.rel, strength: e.strength, depth: depth + 1, parent: id };
      result[e.strength] = (result[e.strength] || []);
      result[e.strength].push(entry);
      result.all.push(entry);
      queue.push({ id: e.id, depth: depth + 1 });
    });
  }
  return result;
}

/** Classify a resource ID by its ARM resource type. */
export function getResType(id) {
  if (!id) return 'Unknown';
  const low = id.toLowerCase();
  if (low.includes('/virtualnetworks/') && !low.includes('/subnets/')) return 'VNet';
  if (low.includes('/subnets/')) return 'Subnet';
  if (low.includes('/virtualmachines/')) return 'VM';
  if (low.includes('/networkinterfaces/')) return 'NIC';
  if (low.includes('/networksecuritygroups/')) return 'NSG';
  if (low.includes('/routetables/')) return 'UDR';
  if (low.includes('/natgateways/')) return 'NAT Gateway';
  if (low.includes('/privateendpoints/')) return 'Private Endpoint';
  if (low.includes('/applicationgateways/')) return 'App Gateway';
  if (low.includes('/loadbalancers/')) return 'Load Balancer';
  if (low.includes('/disks/')) return 'Managed Disk';
  if (low.includes('/virtualnetworkpeerings/')) return 'VNet Peering';
  if (low.includes('/virtualnetworkgateways/')) return 'VPN Gateway';
  const ctx = rlCtx;
  if (ctx) {
    if ((ctx.sqlServers || []).some(r => r.id === id)) return 'SQL Server';
    if ((ctx.functionApps || []).some(f => f.id === id)) return 'Function App';
    if ((ctx.containerInstances || []).some(e => e.id === id)) return 'Container Instance';
    if ((ctx.redisCaches || []).some(c => c.id === id)) return 'Redis Cache';
    if ((ctx.synapseWorkspaces || []).some(c => c.id === id)) return 'Synapse Workspace';
  }
  if (id.startsWith('/subscriptions/')) return 'Azure Resource';
  return 'Resource';
}

/** Look up a human-readable name for a resource ID. */
export function getResName(id) {
  const ctx = rlCtx;
  if (!ctx) return id;
  const v = (ctx.vnets || []).find(x => x.id === id);
  if (v) return v.name || id;
  const s = (ctx.subnets || []).find(x => x.id === id);
  if (s) return s.name || id;
  const i = (ctx.vms || []).find(x => x.id === id);
  if (i) return i.name || id;
  const sg = (ctx.nsgs || []).find(x => x.id === id);
  if (sg) return sg.name || id;
  return id;
}

/** Clear blast radius highlighting from the SVG. */
export function clearBlastRadius() {
  const mg = mapG;
  if (!blastActive || !mg) return;
  blastActive = false;
  mg.selectAll('.blast-dimmed,.blast-glow-hard,.blast-glow-soft,.blast-glow-config')
    .classed('blast-dimmed', false).classed('blast-glow-hard', false)
    .classed('blast-glow-soft', false).classed('blast-glow-config', false);
}

/** Reset the cached dependency graph (call after data changes). */
export function resetDepGraph() {
  depGraph = null;
}

/** Check if blast radius mode is active. */
export function isBlastActive() {
  return blastActive;
}

// Expose for inline code during transition
export { depGraph, blastActive };
