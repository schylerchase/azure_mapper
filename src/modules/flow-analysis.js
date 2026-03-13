// Flow Analysis — auto-discovery engine (pure logic)
// D3/SVG visualization (_renderFlowAnalysisOverlay, _renderTierBadges, etc.)
// remains inline until modernized in Phase 5.

import { traceInternetToResource, traceResourceToInternet, traceFlowLeg } from './flow-tracing.js';

function _traceInbound(target, config, ctx, opts) {
  return typeof traceInternetToResource === 'function'
    ? traceInternetToResource(target, config, ctx, opts)
    : { blocked: true, path: [] };
}
function _traceOutbound(source, config, ctx, opts) {
  return typeof traceResourceToInternet === 'function'
    ? traceResourceToInternet(source, config, ctx, opts)
    : { blocked: true, path: [] };
}
function _traceLeg(source, target, config, ctx, opts) {
  return typeof traceFlowLeg === 'function'
    ? traceFlowLeg(source, target, config, ctx, opts)
    : { blocked: true, path: [] };
}

// === Module State ===
let flowAnalysisMode = null; // null|'tiers'|'ingress'|'egress'|'bastion'|'all'
let flowAnalysisCache = null;
let faDashState = { section: 'all', search: '', sort: 'name', sortDir: 'asc', page: 1, perPage: 50 };
let faDashRows = null;

// === State Accessors ===
export function getFlowAnalysisMode() { return flowAnalysisMode; }
export function setFlowAnalysisMode(v) { flowAnalysisMode = v; }
export function getFlowAnalysisCache() { return flowAnalysisCache; }
export function setFlowAnalysisCache(v) { flowAnalysisCache = v; }
export function getFaDashState() { return faDashState; }
export function setFaDashState(v) { faDashState = v; }
export function getFaDashRows() { return faDashRows; }
export function setFaDashRows(v) { faDashRows = v; }

// === Pure Logic ===

/** Helper: get name from an Azure resource object. */
function _gn3(resource) {
  return resource.name || resource.Name || resource.id || 'unknown';
}

/**
 * Auto-discover all traffic flows in the infrastructure.
 * @param {Object} ctx - parsed Azure rlCtx
 * @returns {Object} {ingressPaths, egressPaths, accessTiers, bastionChains, bastions, hasNsgData, hasNsgEgress}
 */
export function discoverTrafficFlows(ctx) {
  if (!ctx) return null;
  const hasNsgData = (ctx.nsgs || []).length > 0;
  const hasNsgEgress = (ctx.nsgs || []).some(n =>
    (n.securityRules || []).some(r =>
      (r.direction || '').toLowerCase() === 'outbound'
    )
  );
  const ingressPaths = findIngressPaths(ctx);
  const egressPaths = findEgressPaths(ctx);
  const bastions = detectBastions(ctx);
  const bastionChains = findBastionChains(bastions, ctx);
  const accessTiers = classifyAllResources(ctx, ingressPaths, bastionChains);
  return { ingressPaths, egressPaths, accessTiers, bastionChains, bastions, hasNsgData, hasNsgEgress };
}

/** Find all internet-to-resource ingress paths. */
export function findIngressPaths(ctx) {
  const paths = [];

  // In Azure, any subnet with a default Internet route (not overridden by UDR) can receive inbound.
  // Check each subnet that has the default Internet route.
  (ctx.subnets || []).forEach(sub => {
    const isPublic = ctx.pubSubs && ctx.pubSubs.has(sub.id);
    if (!isPublic) return;

    const vnetId = sub.vnetId;

    // VMs in this subnet
    (ctx.vmsBySub[sub.id] || []).forEach(vm => {
      [443, 80, 22].forEach(port => {
        const r = _traceInbound({ type: 'vm', id: vm.id || vm.name }, { protocol: 'Tcp', port }, ctx, { discovery: true });
        if (!r.blocked) {
          paths.push({ from: 'internet', to: { type: 'vm', id: vm.id || vm.name }, toName: _gn3(vm), path: r.path, port, type: 'direct', vnetId });
        }
      });
    });

    // Load Balancers / App Gateways in this subnet
    (ctx.lbBySub[sub.id] || []).forEach(lb => {
      const r = _traceInbound({ type: 'lb', id: lb.id || lb.name }, { protocol: 'Tcp', port: 443 }, ctx, { discovery: true });
      if (!r.blocked) {
        paths.push({ from: 'internet', to: { type: 'lb', id: lb.id || lb.name }, toName: _gn3(lb), path: r.path, port: 443, type: 'loadbalancer', vnetId });
      }
    });
  });

  return paths;
}

/** Find resource-to-internet egress paths. */
export function findEgressPaths(ctx) {
  const paths = [];
  const checked = new Set();

  // Collect all VMs
  var allVms = [];
  Object.keys(ctx.vmsBySub || {}).forEach(sid => {
    (ctx.vmsBySub[sid] || []).forEach(vm => allVms.push({ vm, subnetId: sid }));
  });

  allVms.forEach(({ vm, subnetId }) => {
    if (checked.has(subnetId)) return;
    const r = _traceOutbound({ type: 'vm', id: vm.id || vm.name }, { protocol: 'Tcp', port: 443 }, ctx, { discovery: true });
    if (!r.blocked) {
      checked.add(subnetId);
      const viaType = r.path.some(h => h.detail && h.detail.includes('VirtualAppliance')) ? 'nva'
        : r.path.some(h => h.detail && h.detail.includes('VirtualNetworkGateway')) ? 'gateway'
        : 'internet';
      paths.push({
        from: { type: 'vm', id: vm.id || vm.name }, fromName: _gn3(vm),
        to: 'internet', subnetId,
        via: viaType
      });
    }
  });
  return paths;
}

/** Detect bastion/jump hosts: Azure Bastion subnets and VMs matching bastion naming patterns. */
export function detectBastions(ctx) {
  const bastions = [];
  const hasNsgData = (ctx.nsgs || []).length > 0;

  // Azure Bastion service detection (AzureBastionSubnet)
  (ctx.subnets || []).forEach(sub => {
    if (sub.name && sub.name.toLowerCase() === 'azurebastionsubnet') {
      bastions.push({
        type: 'bastion',
        id: sub.id,
        name: 'Azure Bastion (' + (sub.vnetId || '') + ')',
        subnetId: sub.id,
        vnetId: sub.vnetId,
        isAzureBastion: true,
      });
    }
  });

  // VM-based jump boxes (by name pattern or SSH NSG rules)
  var allVms = [];
  Object.keys(ctx.vmsBySub || {}).forEach(sid => {
    (ctx.vmsBySub[sid] || []).forEach(vm => allVms.push(vm));
  });

  allVms.forEach(vm => {
    const isPub = vm.publicIpAddress || (ctx.pubSubs && ctx.pubSubs.has(vm.subnetId));
    if (!isPub) return;
    const name = _gn3(vm);
    const nameMatch = /bastion|jump|ssh/i.test(name);

    if (hasNsgData) {
      // Check if VM's NIC or subnet NSG allows SSH (port 22) inbound
      const nicNsg = vm.nicId ? (ctx.nics || []).find(n => n.id === vm.nicId) : null;
      const nicNsgRef = nicNsg && (nicNsg.networkSecurityGroup || (nicNsg.properties && nicNsg.properties.networkSecurityGroup));
      const nicNsgObj = nicNsgRef ? (ctx.nsgs || []).find(n => n.id === nicNsgRef.id) : null;
      const subNsg = (ctx.subnetNsgs || {})[vm.subnetId];

      let hasSSH = false;
      [nicNsgObj, subNsg].forEach(nsg => {
        if (!nsg) return;
        (nsg.securityRules || []).forEach(rule => {
          if ((rule.direction || '').toLowerCase() !== 'inbound') return;
          if ((rule.access || '').toLowerCase() !== 'allow') return;
          const dstPorts = rule.destinationPortRange || rule.destinationPortRanges || '*';
          const portStr = Array.isArray(dstPorts) ? dstPorts.join(',') : String(dstPorts);
          if (portStr === '*' || portStr.includes('22')) hasSSH = true;
        });
      });

      if (!hasSSH && !nameMatch) return;
    } else {
      if (!nameMatch) return;
    }

    bastions.push({
      type: 'vm', id: vm.id || vm.name, name,
      subnetId: vm.subnetId,
      vnetId: vm.vnetId || ((ctx.subnets || []).find(s => s.id === vm.subnetId) || {}).vnetId,
    });
  });

  return bastions;
}

/** Trace bastion -> private resource chains. */
export function findBastionChains(bastions, ctx) {
  const chains = [];
  const hasNsgData = (ctx.nsgs || []).length > 0;

  bastions.forEach(bastion => {
    const targets = [];
    const testedSubs = new Set();

    // Collect all VMs
    var allVms = [];
    Object.keys(ctx.vmsBySub || {}).forEach(sid => {
      (ctx.vmsBySub[sid] || []).forEach(vm => allVms.push(vm));
    });

    allVms.forEach(vm => {
      if ((vm.id || vm.name) === bastion.id) return;
      const vmVnet = vm.vnetId || ((ctx.subnets || []).find(s => s.id === vm.subnetId) || {}).vnetId;
      if (vmVnet !== bastion.vnetId) return;
      // Skip VMs in public subnets
      if (ctx.pubSubs && ctx.pubSubs.has(vm.subnetId)) return;

      const name = _gn3(vm);
      if (!hasNsgData) {
        if (targets.length < 50) targets.push({ type: 'vm', id: vm.id || vm.name, name });
      } else if (!testedSubs.has(vm.subnetId)) {
        testedSubs.add(vm.subnetId);
        const sourceRef = bastion.isAzureBastion
          ? { type: 'subnet', id: bastion.subnetId }
          : { type: 'vm', id: bastion.id };
        const r = _traceLeg(sourceRef, { type: 'vm', id: vm.id || vm.name }, { protocol: 'Tcp', port: 22 }, ctx, { discovery: true });
        if (!r.blocked) targets.push({ type: 'vm', id: vm.id || vm.name, name });
      } else {
        targets.push({ type: 'vm', id: vm.id || vm.name, name });
      }
    });

    // Database resources
    Object.keys(ctx.dbBySub || {}).forEach(sid => {
      (ctx.dbBySub[sid] || []).forEach(db => {
        const dbVnet = ((ctx.subnets || []).find(s => s.id === sid) || {}).vnetId;
        if (dbVnet !== bastion.vnetId) return;
        const dbName = _gn3(db);
        if (!hasNsgData) {
          targets.push({ type: 'sqldb', id: db.id || db.name, name: dbName });
        } else {
          const port = db.port || 1433;
          const sourceRef = bastion.isAzureBastion
            ? { type: 'subnet', id: bastion.subnetId }
            : { type: 'vm', id: bastion.id };
          const r = _traceLeg(sourceRef, { type: 'sqldb', id: db.id || db.name }, { protocol: 'Tcp', port }, ctx, { discovery: true });
          if (!r.blocked) targets.push({ type: 'sqldb', id: db.id || db.name, name: dbName });
        }
      });
    });

    if (targets.length > 0) chains.push({ bastion, targets });
  });
  return chains;
}

/** Classify all resources into access tiers. */
export function classifyAllResources(ctx, ingressPaths, bastionChains) {
  const tiers = { internetFacing: [], bastionOnly: [], fullyPrivate: [], database: [] };
  const ingressSet = new Set();
  ingressPaths.forEach(p => { ingressSet.add(p.to.type + ':' + p.to.id); });
  const bastionSet = new Set();
  bastionChains.forEach(ch => { ch.targets.forEach(t => { bastionSet.add(t.type + ':' + t.id); }); });

  // VMs
  var allVms = [];
  Object.keys(ctx.vmsBySub || {}).forEach(sid => {
    (ctx.vmsBySub[sid] || []).forEach(vm => allVms.push(vm));
  });

  allVms.forEach(vm => {
    const key = 'vm:' + (vm.id || vm.name);
    const ref = { type: 'vm', id: vm.id || vm.name, name: _gn3(vm) };
    if (ingressSet.has(key)) { tiers.internetFacing.push(ref); return; }
    if (bastionSet.has(key)) { tiers.bastionOnly.push(ref); return; }
    tiers.fullyPrivate.push(ref);
  });

  // Load Balancers / App Gateways
  Object.keys(ctx.lbBySub || {}).forEach(sid => {
    (ctx.lbBySub[sid] || []).forEach(lb => {
      const key = 'lb:' + (lb.id || lb.name);
      const ref = { type: 'lb', id: lb.id || lb.name, name: _gn3(lb) };
      if (ingressSet.has(key)) { tiers.internetFacing.push(ref); return; }
      tiers.fullyPrivate.push(ref);
    });
  });

  // Function Apps (VNet-integrated)
  Object.keys(ctx.funcAppBySub || {}).forEach(sid => {
    (ctx.funcAppBySub[sid] || []).forEach(fn => {
      tiers.fullyPrivate.push({ type: 'functionapp', id: fn.id || fn.name, name: _gn3(fn) });
    });
  });

  // Databases (SQL, MySQL, PostgreSQL, CosmosDB)
  Object.keys(ctx.dbBySub || {}).forEach(sid => {
    (ctx.dbBySub[sid] || []).forEach(db => {
      tiers.database.push({ type: 'sqldb', id: db.id || db.name, name: _gn3(db) });
    });
  });

  // Redis caches
  (ctx.redisCaches || []).forEach(rc => {
    tiers.database.push({ type: 'redis', id: rc.id || rc.name, name: _gn3(rc) });
  });

  return tiers;
}

// Backward-compat aliases
export {
  flowAnalysisMode as _flowAnalysisMode,
  flowAnalysisCache as _flowAnalysisCache,
  faDashState as _faDashState,
  faDashRows as _faDashRows
};
