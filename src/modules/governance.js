// Governance & Inventory — state and pure logic (Azure Network Mapper)
// DOM rendering functions (_renderClassificationTab, _renderIAMTab, _openRulesEditor)
// currently live in diff-engine.js due to dual-state and unified dashboard coupling.
// See TODO in diff-engine.js for migration plan.

import { rlCtx, complianceFindings } from './state.js';
import { esc, gn, safeParse } from './utils.js';
import { analyzeRoleAssignments, findOverPrivileged, findOrphanedAssignments, classifyPermission, getScopeLevel, getRbacData } from './iam-engine.js';
import { escHtml } from './timeline.js';

// === Module State ===
let _govDashState = { tab: 'classification', filter: 'all', search: '', sort: 'tier', sortDir: 'asc', page: 1, perPage: 50 };
let _iamDashState = { filter: 'all', search: '', sort: 'name', sortDir: 'asc', page: 1, perPage: 50 };
let _classificationData = [];
let _classificationOverrides = {};
let _iamReviewData = [];
let _inventoryData = [];
let _invState = { typeFilter: 'all', regionFilter: 'all', accountFilter: 'all', vnetFilter: 'all', viewMode: 'flat', search: '', sort: 'type', sortDir: 'asc', page: 1, perPage: 50 };
let _appRegistry = [];
let _appAutoDiscovered = false;
let _appSummaryState = { search: '', sort: 'tier', sortDir: 'asc', adding: false, editing: -1 };
var _APP_TYPE_SUGGESTIONS = ['Web App', 'Database', 'Monitoring', 'CI/CD', 'Security', 'Analytics', 'Storage', 'Infrastructure'];
let _invToolbarRendered = false;

var _INV_TYPE_COLORS = {
  'VNet': '#7C3AED', 'Subnet': '#6366f1', 'VM': '#f97316', 'SQL Server': '#22d3ee',
  'Function App': '#f59e0b', 'Container Instance': '#10b981', 'App Gateway': '#ec4899',
  'Redis Cache': '#8b5cf6', 'Synapse Workspace': '#06b6d4', 'NSG': '#64748b',
  'UDR': '#64748b', 'NAT Gateway': '#34d399', 'Private Endpoint': '#34d399',
  'NIC': '#94a3b8', 'Managed Disk': '#fb923c', 'Snapshot': '#a78bfa',
  'Storage Account': '#f472b6', 'DNS Zone': '#38bdf8', 'WAF Policy': '#fbbf24',
  'Front Door': '#818cf8', 'VNet Peering': '#c084fc', 'VPN Connection': '#2dd4bf',
  'vWAN': '#67e8f9', 'AKS': '#818cf8', 'Firewall': '#ef4444', 'Bastion': '#34d399',
  'Load Balancer': '#3b82f6', 'Security Group': '#64748b'
};

var _INV_NO_MAP_TYPES = { 'Storage Account': 1, 'DNS Zone': 1, 'WAF Policy': 1, 'Front Door': 1, 'Snapshot': 1, 'vWAN': 1 };

let _invFilterCache = null;
let _invFilterKey = '';

var _DEFAULT_CLASS_RULES = [
  { pattern: 'prod|production', scope: 'vnet', tier: 'critical', weight: 100 },
  { pattern: 'pci|complian', scope: 'vnet', tier: 'critical', weight: 95 },
  { pattern: 'dr-|disaster|recovery', scope: 'vnet', tier: 'critical', weight: 90 },
  { pattern: 'hub|transit|shared.?serv|data.?platform|security', scope: 'vnet', tier: 'high', weight: 80 },
  { pattern: 'edge|proxy|waf|firewall', scope: 'vnet', tier: 'high', weight: 75 },
  { pattern: 'staging|stage|qa|uat', scope: 'vnet', tier: 'medium', weight: 50 },
  { pattern: 'management|mgmt|monitor', scope: 'vnet', tier: 'medium', weight: 45 },
  { pattern: 'dev|develop|sandbox|test|experiment', scope: 'vnet', tier: 'low', weight: 20 },
  { pattern: 'sql|database|db|synapse', scope: 'type', tier: 'critical', weight: 90 },
  { pattern: 'redis|cache', scope: 'type', tier: 'high', weight: 70 },
  { pattern: 'app.?gateway|loadbalancer|load.?balancer', scope: 'type', tier: 'high', weight: 65 },
  { pattern: 'function.?app|container|aks|kubernetes', scope: 'type', tier: 'medium', weight: 40 },
  { pattern: 'bastion|jump|ssh', scope: 'name', tier: 'medium', weight: 35 },
  { pattern: 'firewall|azure.?firewall', scope: 'type', tier: 'high', weight: 75 },
  // Tag-based rules — Environment tag is strongest classification signal
  { pattern: 'prod|production|prd', scope: 'tag:Environment', tier: 'critical', weight: 120 },
  { pattern: 'staging|stage|uat|qa', scope: 'tag:Environment', tier: 'medium', weight: 110 },
  { pattern: 'dev|develop|sandbox|test', scope: 'tag:Environment', tier: 'low', weight: 110 }
];
let _classificationRules = structuredClone(_DEFAULT_CLASS_RULES);
let _discoveredTags = {};

var _TIER_RPO_RTO = {
  critical: { rpo: 'Hourly', rto: '2-4 hours', priority: 1, color: '#ef4444' },
  high: { rpo: '6 hours', rto: '4-8 hours', priority: 2, color: '#f59e0b' },
  medium: { rpo: 'Daily', rto: '12 hours', priority: 3, color: '#22d3ee' },
  low: { rpo: 'Weekly', rto: '24 hours', priority: 4, color: '#64748b' }
};

// === State Accessors ===
export function getGovDashState() { return _govDashState; }
export function setGovDashState(v) { _govDashState = v; }
export function getIamDashState() { return _iamDashState; }
export function setIamDashState(v) { _iamDashState = v; }
export function getClassificationData() { return _classificationData; }
export function setClassificationData(v) { _classificationData = v; }
export function getClassificationOverrides() { return _classificationOverrides; }
export function setClassificationOverrides(v) { _classificationOverrides = v; }
export function getIamReviewData() { return _iamReviewData; }
export function setIamReviewData(v) { _iamReviewData = v; }
export function getInventoryData() { return _inventoryData; }
export function setInventoryData(v) { _inventoryData = v; }
export function getInvState() { return _invState; }
export function setInvState(v) { _invState = v; }
export function getAppRegistry() { return _appRegistry; }
export function setAppRegistry(v) { _appRegistry = v; }
export function getAppAutoDiscovered() { return _appAutoDiscovered; }
export function setAppAutoDiscovered(v) { _appAutoDiscovered = v; }
export function getAppSummaryState() { return _appSummaryState; }
export function setAppSummaryState(v) { _appSummaryState = v; }
export function getInvToolbarRendered() { return _invToolbarRendered; }
export function setInvToolbarRendered(v) { _invToolbarRendered = v; }
export function getInvFilterCache() { return _invFilterCache; }
export function setInvFilterCache(v) { _invFilterCache = v; }
export function getInvFilterKey() { return _invFilterKey; }
export function setInvFilterKey(v) { _invFilterKey = v; }
export function getClassificationRules() { return _classificationRules; }
export function setClassificationRules(v) { _classificationRules = v; }
export function getDiscoveredTags() { return _discoveredTags; }
export function setDiscoveredTags(v) { _discoveredTags = v; }

// === Pure Logic ===

/**
 * Build inventory data rows from the resource context.
 * Populates _inventoryData with enriched resource rows.
 */
function _buildInventoryData() {
  _inventoryData = [];
  var ctx = rlCtx; if (!ctx) return;
  var rows = [];
  var vnetNameMap = {};
  (ctx.vnets || []).forEach(function(v) { vnetNameMap[v.id] = v.name || v.id; });
  function tags(obj) { var m = {}; var t = obj.tags || {}; Object.keys(t).forEach(function(k) { m[k] = t[k]; }); return m; }
  function mkRow(id, type, name, obj, extra) {
    return { id: id, type: type, name: name,
      account: obj._accountLabel || obj._accountId || '', region: obj.location || obj._region || '',
      vnetId: extra.vnetId || '', vnetName: extra.vnetId ? vnetNameMap[extra.vnetId] || '' : '',
      subnetId: extra.subnetId || '', az: extra.az || '',
      state: extra.state || '', config: extra.config || '', tags: tags(obj),
      encrypted: extra.encrypted != null ? extra.encrypted : null, nsgCount: extra.nsgCount || 0,
      classificationTier: null, budrTier: null, budrStrategy: null, rto: null, rpo: null,
      compliancePass: 0, complianceFail: 0,
      _raw: obj, _related: extra.related || [] };
  }
  // Shared lookups: subnet->VNet, vm->VNet
  var subVnetMap = {}; (ctx.subnets || []).forEach(function(s) { if (s.id) subVnetMap[s.id] = (s.properties && s.properties.vnetId) || ''; });
  var vmVnetMap = {}; (ctx.vms || []).forEach(function(i) { if (i.id) vmVnetMap[i.id] = (i.properties && i.properties.vnetId) || subVnetMap[(i.properties && i.properties.subnetId)] || ''; });
  // 1. VNets
  (ctx.vnets || []).forEach(function(v) {
    var prefixes = ((v.properties && v.properties.addressSpace && v.properties.addressSpace.addressPrefixes) || []).join(', ');
    rows.push(mkRow(v.id, 'VNet', v.name || v.id, v, { vnetId: v.id, config: prefixes, state: (v.properties && v.properties.provisioningState) || '' }));
  });
  // 2. Subnets
  (ctx.subnets || []).forEach(function(s) {
    var prefix = (s.properties && s.properties.addressPrefix) || '';
    rows.push(mkRow(s.id, 'Subnet', s.name || s.id, s, { vnetId: (s.properties && s.properties.vnetId) || '', config: prefix, state: (s.properties && s.properties.provisioningState) || '' }));
  });
  // 3. VMs
  (ctx.vms || []).forEach(function(i) {
    var nsgs = [(i.properties && i.properties.nsgId)].filter(Boolean);
    rows.push(mkRow(i.id, 'VM', i.name || i.id, i, { vnetId: (i.properties && i.properties.vnetId) || subVnetMap[(i.properties && i.properties.subnetId)] || '', subnetId: (i.properties && i.properties.subnetId) || '', az: i.location || '', config: (i.properties && i.properties.hardwareProfile && i.properties.hardwareProfile.vmSize) || '', state: (i.properties && i.properties.provisioningState) || '', nsgCount: nsgs.length, related: nsgs }));
  });
  // 4. SQL Servers
  (ctx.sqlServers || []).forEach(function(db) {
    rows.push(mkRow(db.id, 'SQL Server', db.name || db.id, db, { vnetId: (db.properties && db.properties.vnetId) || '', config: (db.properties && db.properties.version) || '', state: (db.properties && db.properties.state) || '', encrypted: !!(db.properties && db.properties.storageEncrypted) }));
  });
  // 5. Function Apps
  (ctx.functionApps || []).forEach(function(fn) {
    var vnetId = (fn.properties && fn.properties.vnetId) || '';
    var subId = (fn.properties && fn.properties.subnetId) || '';
    rows.push(mkRow(fn.id, 'Function App', fn.name || fn.id, fn, { vnetId: vnetId, subnetId: subId, config: (fn.properties && fn.properties.siteConfig && fn.properties.siteConfig.linuxFxVersion) || '', state: (fn.properties && fn.properties.state) || 'Active' }));
  });
  // 6. Container Instances
  (ctx.containerInstances || []).forEach(function(ci) {
    var subId = (ci.properties && ci.properties.subnetId) || '';
    var vnetId = subVnetMap[subId] || '';
    var ctCount = (ci.properties && ci.properties.containers || []).length;
    rows.push(mkRow(ci.id, 'Container Instance', ci.name || ci.id, ci, { vnetId: vnetId, subnetId: subId, config: ctCount + ' container(s)', state: (ci.properties && ci.properties.provisioningState) || '' }));
  });
  // 7. App Gateways
  (ctx.appGateways || []).forEach(function(a) {
    rows.push(mkRow(a.id, 'App Gateway', a.name || a.id, a, { vnetId: (a.properties && a.properties.vnetId) || '', config: (a.properties && a.properties.sku && a.properties.sku.name) || '', state: (a.properties && a.properties.provisioningState) || '' }));
  });
  // 8. Redis Caches
  (ctx.redisCaches || []).forEach(function(rc) {
    rows.push(mkRow(rc.id, 'Redis Cache', rc.name || rc.id, rc, { vnetId: (rc.properties && rc.properties.vnetId) || '', config: (rc.properties && rc.properties.sku && rc.properties.sku.name) || '', state: (rc.properties && rc.properties.provisioningState) || '' }));
  });
  // 9. Synapse Workspaces
  (ctx.synapseWorkspaces || []).forEach(function(sw) {
    rows.push(mkRow(sw.id, 'Synapse Workspace', sw.name || sw.id, sw, { vnetId: '', config: (sw.properties && sw.properties.sqlAdministratorLogin) || '', state: (sw.properties && sw.properties.provisioningState) || '', encrypted: !!(sw.properties && sw.properties.encryption) }));
  });
  // 10. NSGs
  (ctx.nsgs || []).forEach(function(sg) {
    var rules = (sg.properties && sg.properties.securityRules) || [];
    var inCt = rules.filter(function(r) { return r.properties && r.properties.direction === 'Inbound'; }).length;
    var outCt = rules.filter(function(r) { return r.properties && r.properties.direction === 'Outbound'; }).length;
    rows.push(mkRow(sg.id, 'NSG', sg.name || sg.id, sg, { vnetId: (sg.properties && sg.properties.vnetId) || '', config: inCt + ' inbound / ' + outCt + ' outbound' }));
  });
  // 11. UDRs (Route Tables)
  (ctx.udrs || []).forEach(function(rt) {
    var ct = ((rt.properties && rt.properties.routes) || []).length;
    rows.push(mkRow(rt.id, 'UDR', rt.name || rt.id, rt, { vnetId: (rt.properties && rt.properties.vnetId) || '', config: ct + ' routes' }));
  });
  // 12. NAT Gateways
  (ctx.natGateways || []).forEach(function(n) {
    var subs = ((n.properties && n.properties.subnets) || []).map(function(s) { return s.id; });
    var vnetId = subs.length ? subVnetMap[subs[0]] || '' : '';
    rows.push(mkRow(n.id, 'NAT Gateway', n.name || n.id, n, { vnetId: vnetId, config: subs.length + ' subnet(s)', state: (n.properties && n.properties.provisioningState) || '' }));
  });
  // 13. Private Endpoints
  (ctx.privateEndpoints || []).forEach(function(e) {
    var subId = (e.properties && e.properties.subnetId) || '';
    rows.push(mkRow(e.id, 'Private Endpoint', e.name || e.id, e, { vnetId: (e.properties && e.properties.vnetId) || subVnetMap[subId] || '', subnetId: subId, config: (e.properties && e.properties.privateLinkServiceConnections && e.properties.privateLinkServiceConnections[0] && e.properties.privateLinkServiceConnections[0].properties && e.properties.privateLinkServiceConnections[0].properties.privateLinkServiceId) || '', state: (e.properties && e.properties.provisioningState) || '' }));
  });
  // 14. NICs
  (ctx.nics || []).forEach(function(e) {
    var subId = (e.properties && e.properties.ipConfigurations && e.properties.ipConfigurations[0] && e.properties.ipConfigurations[0].properties && e.properties.ipConfigurations[0].properties.subnetId) || '';
    rows.push(mkRow(e.id, 'NIC', e.name || e.id, e, { vnetId: subVnetMap[subId] || '', subnetId: subId, config: (e.properties && e.properties.ipConfigurations && e.properties.ipConfigurations[0] && e.properties.ipConfigurations[0].properties && e.properties.ipConfigurations[0].properties.privateIPAddress) || '', state: (e.properties && e.properties.provisioningState) || '' }));
  });
  // 15. Managed Disks
  (ctx.disks || []).forEach(function(vol) {
    var attVmId = (vol.managedBy) || '';
    var vnetId = attVmId ? vmVnetMap[attVmId] || '' : '';
    rows.push(mkRow(vol.id, 'Managed Disk', vol.name || vol.id, vol, { vnetId: vnetId, az: vol.location || '', config: ((vol.properties && vol.properties.diskSizeGB) || '') + 'GB ' + ((vol.properties && vol.properties.sku && vol.properties.sku.name) || ''), state: (vol.properties && vol.properties.diskState) || '', encrypted: !!(vol.properties && vol.properties.encryption && vol.properties.encryption.type), related: attVmId ? [attVmId] : [] }));
  });
  // 16. Snapshots
  (ctx.snapshots || []).forEach(function(snap) {
    rows.push(mkRow(snap.id, 'Snapshot', snap.name || snap.id, snap, { config: ((snap.properties && snap.properties.diskSizeGB) || '') + 'GB', state: (snap.properties && snap.properties.diskState) || '', encrypted: !!(snap.properties && snap.properties.encryption && snap.properties.encryption.type) }));
  });
  // 17. Storage Accounts
  (ctx.storageAccounts || []).forEach(function(b) {
    rows.push(mkRow(b.id, 'Storage Account', b.name || b.id, b, { config: (b.properties && b.properties.sku && b.properties.sku.name) || (b.sku && b.sku.name) || '' }));
  });
  // 18. DNS Zones
  (ctx.dnsZones || []).forEach(function(z) {
    var recs = ctx.dnsRecords && ctx.dnsRecords[z.id] ? ctx.dnsRecords[z.id].length : (z.properties && z.properties.numberOfRecordSets) || 0;
    var vis = (z.properties && z.properties.zoneType) || 'Public';
    rows.push(mkRow(z.id, 'DNS Zone', z.name || z.id, z, { config: recs + ' records ' + vis.toLowerCase() }));
  });
  // 19. WAF Policies
  (ctx.wafPolicies || []).forEach(function(w) {
    var ruleCount = ((w.properties && w.properties.customRules && w.properties.customRules.rules) || []).length;
    rows.push(mkRow(w.id, 'WAF Policy', w.name || w.id, w, { config: ruleCount + ' custom rules' }));
  });
  // 20. Front Doors
  (ctx.frontDoors || []).forEach(function(fd) {
    rows.push(mkRow(fd.id, 'Front Door', fd.name || fd.id, fd, { config: (fd.properties && fd.properties.resourceState) || '', state: (fd.properties && fd.properties.provisioningState) || '' }));
  });
  // 21. VNet Peerings
  (ctx.peerings || []).forEach(function(p) {
    var local = (p.properties && p.properties.localVnetId) || '';
    var remote = (p.properties && p.properties.remoteVnetId) || '';
    rows.push(mkRow(p.id, 'VNet Peering', p.name || p.id, p, { vnetId: local, config: (local ? vnetNameMap[local] || local : '') + '\u2194' + (remote ? vnetNameMap[remote] || remote : ''), state: (p.properties && p.properties.peeringState) || '' }));
  });
  // 22. VPN Connections
  (ctx.vpnConnections || []).forEach(function(v) {
    rows.push(mkRow(v.id, 'VPN Connection', v.name || v.id, v, { config: ((v.properties && v.properties.connectionType) || '') + ' ' + ((v.properties && v.properties.connectionStatus) || ''), state: (v.properties && v.properties.connectionStatus) || '' }));
  });
  // 23. vWANs
  (ctx.vwans || []).forEach(function(t) {
    rows.push(mkRow(t.id, 'vWAN', t.name || t.id, t, { config: (t.properties && t.properties.type) || '', state: (t.properties && t.properties.provisioningState) || '' }));
  });
  // 24. AKS Clusters
  (ctx.aksCluster || []).forEach(function(k) {
    rows.push(mkRow(k.id, 'AKS', k.name || k.id, k, { vnetId: (k.properties && k.properties.agentPoolProfiles && k.properties.agentPoolProfiles[0] && k.properties.agentPoolProfiles[0].vnetSubnetID && subVnetMap[k.properties.agentPoolProfiles[0].vnetSubnetID]) || '', config: (k.properties && k.properties.kubernetesVersion) || '', state: (k.properties && k.properties.provisioningState) || '' }));
  });
  // 25. Firewalls
  (ctx.firewalls || []).forEach(function(fw) {
    rows.push(mkRow(fw.id, 'Firewall', fw.name || fw.id, fw, { vnetId: (fw.properties && fw.properties.vnetId) || '', config: (fw.properties && fw.properties.sku && fw.properties.sku.name) || '', state: (fw.properties && fw.properties.provisioningState) || '' }));
  });
  // 26. Bastions
  (ctx.bastions || []).forEach(function(b) {
    rows.push(mkRow(b.id, 'Bastion', b.name || b.id, b, { vnetId: (b.properties && b.properties.vnetId) || '', config: (b.properties && b.properties.sku && b.properties.sku.name) || '', state: (b.properties && b.properties.provisioningState) || '' }));
  });
  // 27. Load Balancers
  (ctx.loadBalancers || []).forEach(function(lb) {
    rows.push(mkRow(lb.id, 'Load Balancer', lb.name || lb.id, lb, { vnetId: (lb.properties && lb.properties.vnetId) || '', config: (lb.sku && lb.sku.name) || '', state: (lb.properties && lb.properties.provisioningState) || '' }));
  });
  // === Enrichment pass ===
  // 1. Classification tier lookup
  var classMap = {};
  (_classificationData || []).forEach(function(c) { classMap[c.id] = c; });
  // 2. BUDR assessment lookup — use window bridge for cross-region data
  var budrAssessments = (typeof window !== 'undefined' && window._budrAssessments) || [];
  var budrMap = {};
  (budrAssessments || []).forEach(function(a) {
    budrMap[a.id] = { tier: a.profile ? a.profile.tier : null, strategy: a.profile ? a.profile.strategy : null, rto: a.profile ? a.profile.rto : null, rpo: a.profile ? a.profile.rpo : null };
  });
  // 3. Compliance findings lookup (count per resource)
  var compMap = {};
  (complianceFindings || []).forEach(function(f) {
    if (!f.resource) return;
    if (!compMap[f.resource]) compMap[f.resource] = { pass: 0, fail: 0 };
    if (f.status === 'PASS') compMap[f.resource].pass++;
    else compMap[f.resource].fail++;
  });
  // 4. Apply enrichment to all rows
  rows.forEach(function(r) {
    var cls = classMap[r.id];
    if (cls) r.classificationTier = cls.tier;
    var budr = budrMap[r.id];
    if (budr) { r.budrTier = budr.tier; r.budrStrategy = budr.strategy; r.rto = budr.rto; r.rpo = budr.rpo; }
    var comp = compMap[r.id];
    if (comp) { r.compliancePass = comp.pass; r.complianceFail = comp.fail; }
  });
  _inventoryData = rows;
}

/**
 * Filter and sort inventory items based on current _invState.
 * Uses _udashFilterByAccount from window bridge for account filtering.
 * @returns {Object[]} filtered/sorted inventory rows
 */
function _filterInventory() {
  var st = _invState;
  // _udashFilterByAccount is a global UI function — access via window bridge
  var filterFn = (typeof window !== 'undefined' && window._udashFilterByAccount) || function(x) { return x; };
  var items = filterFn(_inventoryData).slice();
  if (st.typeFilter !== 'all') items = items.filter(function(r) { return r.type === st.typeFilter; });
  if (st.regionFilter !== 'all') items = items.filter(function(r) { return r.region === st.regionFilter; });
  if (st.accountFilter !== 'all') items = items.filter(function(r) { return r.account === st.accountFilter; });
  if (st.vnetFilter !== 'all') items = items.filter(function(r) { return r.vnetId === st.vnetFilter; });
  if (st.search) {
    var q = st.search.toLowerCase();
    items = items.filter(function(r) {
      return (r.name || '').toLowerCase().indexOf(q) !== -1
        || (r.id || '').toLowerCase().indexOf(q) !== -1
        || (r.type || '').toLowerCase().indexOf(q) !== -1
        || (r.config || '').toLowerCase().indexOf(q) !== -1
        || (r.vnetName || '').toLowerCase().indexOf(q) !== -1
        || (r.region || '').toLowerCase().indexOf(q) !== -1
        || JSON.stringify(r.tags || {}).toLowerCase().indexOf(q) !== -1;
    });
  }
  var sortKey = st.sort; var dir = st.sortDir === 'asc' ? 1 : -1;
  items.sort(function(a, b) {
    if (sortKey === 'complianceFail') { return ((a.complianceFail || 0) - (b.complianceFail || 0)) * dir; }
    if (sortKey === 'tags') { return (Object.keys(a.tags || {}).length - Object.keys(b.tags || {}).length) * dir; }
    var av = (a[sortKey] || '').toString().toLowerCase();
    var bv = (b[sortKey] || '').toString().toLowerCase();
    return av < bv ? -dir : av > bv ? dir : 0;
  });
  return items;
}

/**
 * Extract tag map from an Azure resource object.
 * Azure tags are plain key-value objects (not arrays).
 * @param {Object} obj - Azure resource with tags property
 * @returns {Object} key-value map of tags
 */
function _getTagMap(obj) {
  var src = obj.tags || {};
  var m = {}; Object.keys(src).forEach(function(k) { m[k] = src[k] || ''; }); return m;
}

/**
 * Safely construct a RegExp, returning null on invalid patterns.
 * @param {string} pattern - regex pattern string
 * @returns {RegExp|null}
 */
function _safeRegex(pattern) {
  try {
    var re = new RegExp(pattern, 'i');
    if (/(\+|\*|\{)\s*\)(\+|\*|\{)/.test(pattern)) return null;
    return re;
  } catch (e) { return null; }
}

/**
 * Score a resource against classification rules.
 * @param {string} name - resource name
 * @param {string} type - resource type
 * @param {string} vnetName - VNet name for context
 * @param {Object[]} [rules] - classification rules (defaults to module rules)
 * @param {Object} [tagMap] - tag key-value map
 * @returns {{tier: string, weight: number}}
 */
function _scoreClassification(name, type, vnetName, rules, tagMap) {
  rules = rules || _classificationRules;
  tagMap = tagMap || {};
  var bestTier = 'low'; var bestWeight = -1;
  rules.forEach(function(rule) {
    if (rule.enabled === false) return;
    var p = rule.pattern; if (!p) return;
    p = p.replace(/^\|+|\|+$/g, '').replace(/\|{2,}/g, '|'); if (!p) return;
    var re = _safeRegex(p); if (!re) return;
    var text = '';
    if (rule.scope === 'any') text = (name || '') + ' ' + (type || '') + ' ' + (vnetName || '') + ' ' + Object.values(tagMap).join(' ');
    else if (rule.scope === 'vnet') text = vnetName || '';
    else if (rule.scope === 'type') text = type || '';
    else if (rule.scope === 'name') text = name || '';
    else if (rule.scope.indexOf('tag:') === 0) text = tagMap[rule.scope.substring(4)] || '';
    else text = (name || '') + ' ' + (type || '') + ' ' + (vnetName || '');
    if (re.test(text) && rule.weight > bestWeight) { bestWeight = rule.weight; bestTier = rule.tier; }
  });
  return { tier: bestTier, weight: bestWeight };
}

/**
 * Discover tag keys across all resource types in the context.
 * @param {Object} ctx - resource context
 * @returns {Object} tag key metadata (count, samples, types)
 */
function _discoverTagKeys(ctx) {
  if (!ctx) return {};
  var disc = {};
  function scan(arr, typeName) {
    (arr || []).forEach(function(obj) {
      var tagObj = obj.tags || {};
      Object.keys(tagObj).forEach(function(k) {
        if (!k || k.indexOf('microsoft:') === 0) return;
        if (!disc[k]) disc[k] = { count: 0, samples: [], types: {} };
        var d = disc[k]; d.count++; d.types[typeName] = true;
        var val = tagObj[k];
        if (d.samples.length < 5 && val && d.samples.indexOf(val) < 0) d.samples.push(val);
      });
    });
  }
  scan(ctx.vms, 'VM'); scan(ctx.sqlServers, 'SQL Server'); scan(ctx.redisCaches, 'Redis Cache');
  scan(ctx.appGateways, 'App Gateway'); scan(ctx.functionApps, 'Function App');
  scan(ctx.containerInstances, 'Container Instance'); scan(ctx.synapseWorkspaces, 'Synapse Workspace');
  scan(ctx.vnets, 'VNet'); scan(ctx.subnets, 'Subnet'); scan(ctx.nsgs, 'NSG');
  scan(ctx.storageAccounts, 'Storage Account'); scan(ctx.aksCluster, 'AKS');
  scan(ctx.firewalls, 'Firewall'); scan(ctx.bastions, 'Bastion'); scan(ctx.loadBalancers, 'Load Balancer');
  Object.keys(disc).forEach(function(k) { disc[k].types = Object.keys(disc[k].types); });
  return disc;
}

/**
 * Run the classification engine across all resources in context.
 * Populates _classificationData and _discoveredTags.
 * @param {Object} ctx - resource context
 * @returns {Object[]} classification results
 */
function runClassificationEngine(ctx) {
  if (!ctx) return [];
  var results = [];
  var vnetNameMap = {};
  (ctx.vnets || []).forEach(function(v) { vnetNameMap[v.id] = v.name || v.id; });
  // Build subnet->VNet lookup for resources that only have subnetId
  var subnetVnetMap = {};
  (ctx.subnets || []).forEach(function(s) { if (s.id && s.properties && s.properties.vnetId) subnetVnetMap[s.id] = s.properties.vnetId; });
  function resolveVnet(vnetId, subnetId) { return vnetId || subnetVnetMap[subnetId] || ''; }
  // Classify VMs
  (ctx.vms || []).forEach(function(inst) {
    var id = inst.id; var name = inst.name || id;
    var vnetId = resolveVnet((inst.properties && inst.properties.vnetId) || '', (inst.properties && inst.properties.subnetId) || '');
    var vnetName = vnetNameMap[vnetId] || '';
    var tm = _getTagMap(inst);
    var sc = _scoreClassification(name, 'vm', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'VM', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify SQL Servers
  (ctx.sqlServers || []).forEach(function(db) {
    var id = db.id; var name = db.name || id;
    var vnetId = (db.properties && db.properties.vnetId) || '';
    var vnetName = vnetNameMap[vnetId] || '';
    var tm = _getTagMap(db);
    var sc = _scoreClassification(name, 'sql', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'SQL Server', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Redis Caches
  (ctx.redisCaches || []).forEach(function(rc) {
    var id = rc.id; var name = rc.name || id;
    var vnetId = (rc.properties && rc.properties.vnetId) || '';
    var vnetName = vnetNameMap[vnetId] || '';
    var tm = _getTagMap(rc);
    var sc = _scoreClassification(name, 'redis', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Redis Cache', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify App Gateways
  (ctx.appGateways || []).forEach(function(agw) {
    var id = agw.id; var name = agw.name || id;
    var vnetId = (agw.properties && agw.properties.vnetId) || '';
    var vnetName = vnetNameMap[vnetId] || '';
    var tm = _getTagMap(agw);
    var sc = _scoreClassification(name, 'app-gateway', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'App Gateway', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Function Apps
  (ctx.functionApps || []).forEach(function(fn) {
    var id = fn.id; var name = fn.name || id;
    var vnetId = resolveVnet((fn.properties && fn.properties.vnetId) || '', (fn.properties && fn.properties.subnetId) || '');
    var vnetName = vnetNameMap[vnetId] || '';
    var tm = _getTagMap(fn);
    var sc = _scoreClassification(name, 'function-app', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Function App', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Container Instances
  (ctx.containerInstances || []).forEach(function(ci) {
    var id = ci.id; var name = ci.name || id;
    var subId = (ci.properties && ci.properties.subnetId) || '';
    var vnetId = resolveVnet('', subId);
    var vnetName = vnetNameMap[vnetId] || '';
    var tm = _getTagMap(ci);
    var sc = _scoreClassification(name, 'container', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Container Instance', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Synapse Workspaces
  (ctx.synapseWorkspaces || []).forEach(function(sw) {
    var id = sw.id; var name = sw.name || id; var tm = _getTagMap(sw);
    var sc = _scoreClassification(name, 'synapse', '', null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Synapse Workspace', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: '', vnetName: '', tags: tm });
  });
  // Classify NSGs
  (ctx.nsgs || []).forEach(function(sg) {
    var id = sg.id; var name = sg.name || id;
    var vnetId = (sg.properties && sg.properties.vnetId) || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(sg);
    var sc = _scoreClassification(name, 'nsg', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'NSG', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify VNets
  (ctx.vnets || []).forEach(function(v) {
    var id = v.id; var name = v.name || id; var tm = _getTagMap(v);
    var sc = _scoreClassification(name, 'vnet', name, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'VNet', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: id, vnetName: name, tags: tm });
  });
  // Classify Subnets
  (ctx.subnets || []).forEach(function(s) {
    var id = s.id; var name = s.name || id;
    var vnetId = (s.properties && s.properties.vnetId) || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(s);
    var sc = _scoreClassification(name, 'subnet', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Subnet', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify NAT Gateways
  (ctx.natGateways || []).forEach(function(ng) {
    var id = ng.id; var name = ng.name || id;
    var subs = ((ng.properties && ng.properties.subnets) || []);
    var firstSub = subs.length ? (subs[0].id || subs[0]) : '';
    var vnetId = subnetVnetMap[firstSub] || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(ng);
    var sc = _scoreClassification(name, 'nat-gateway', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'NAT Gateway', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Private Endpoints
  (ctx.privateEndpoints || []).forEach(function(pe) {
    var id = pe.id; var name = pe.name || id;
    var subId = (pe.properties && pe.properties.subnetId) || '';
    var vnetId = (pe.properties && pe.properties.vnetId) || subnetVnetMap[subId] || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(pe);
    var sc = _scoreClassification(name, 'private-endpoint', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Private Endpoint', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Storage Accounts
  (ctx.storageAccounts || []).forEach(function(b) {
    var id = b.id; var name = b.name || id; var tm = _getTagMap(b);
    var sc = _scoreClassification(name, 'storage', '', null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Storage Account', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: '', vnetName: '', tags: tm });
  });
  // Classify AKS Clusters
  (ctx.aksCluster || []).forEach(function(k) {
    var id = k.id; var name = k.name || id;
    var subId = (k.properties && k.properties.agentPoolProfiles && k.properties.agentPoolProfiles[0] && k.properties.agentPoolProfiles[0].vnetSubnetID) || '';
    var vnetId = subnetVnetMap[subId] || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(k);
    var sc = _scoreClassification(name, 'aks', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'AKS', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Firewalls
  (ctx.firewalls || []).forEach(function(fw) {
    var id = fw.id; var name = fw.name || id;
    var vnetId = (fw.properties && fw.properties.vnetId) || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(fw);
    var sc = _scoreClassification(name, 'firewall', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Firewall', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Bastions
  (ctx.bastions || []).forEach(function(b) {
    var id = b.id; var name = b.name || id;
    var vnetId = (b.properties && b.properties.vnetId) || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(b);
    var sc = _scoreClassification(name, 'bastion', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Bastion', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Classify Load Balancers
  (ctx.loadBalancers || []).forEach(function(lb) {
    var id = lb.id; var name = lb.name || id;
    var vnetId = (lb.properties && lb.properties.vnetId) || ''; var vnetName = vnetNameMap[vnetId] || ''; var tm = _getTagMap(lb);
    var sc = _scoreClassification(name, 'load-balancer', vnetName, null, tm);
    var tier = _classificationOverrides[id] || sc.tier; var meta = _TIER_RPO_RTO[tier];
    results.push({ id: id, name: name, type: 'Load Balancer', tier: tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: vnetId, vnetName: vnetName, tags: tm });
  });
  // Enrich classification data with account IDs from source resources
  var _clResAcct = {};
  (ctx.vms || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.sqlServers || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.redisCaches || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.appGateways || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.functionApps || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.containerInstances || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.nsgs || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.vnets || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.subnets || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.storageAccounts || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.aksCluster || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.firewalls || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.bastions || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  (ctx.loadBalancers || []).forEach(function(r) { _clResAcct[r.id] = r._accountId; });
  results.forEach(function(r) { if (_clResAcct[r.id]) r._accountId = _clResAcct[r.id]; });
  _classificationData = results;
  _discoveredTags = _discoverTagKeys(ctx);
  return results;
}

/**
 * Prepare RBAC review data from Azure role assignments and definitions.
 * Populates _iamReviewData with enriched principal rows.
 * @param {Object} rbacData - { roleAssignments, roleDefinitions }
 * @returns {Object[]} RBAC review items
 */
function prepareIAMReviewData(rbacData) {
  if (!rbacData) return [];
  var items = [];
  var assignments = rbacData.roleAssignments || [];
  var definitions = rbacData.roleDefinitions || [];
  var defMap = {};
  definitions.forEach(function(d) { defMap[d.id || d.name] = d; });
  // Known built-in role IDs
  var OWNER_ID = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635';
  var CONTRIBUTOR_ID = 'b24988ac-6180-42a0-ab88-20f7382dd24c';
  // Group assignments by principal
  var byPrincipal = {};
  assignments.forEach(function(a) {
    var pid = a.properties?.principalId || a.principalId || '';
    if (!byPrincipal[pid]) byPrincipal[pid] = { assignments: [], principalType: a.properties?.principalType || a.principalType || 'Unknown', principalId: pid };
    byPrincipal[pid].assignments.push(a);
  });
  Object.values(byPrincipal).forEach(function(principal) {
    var roleNames = [];
    var isAdmin = false;
    var hasWildcard = false;
    var scopes = [];
    var crossTenants = [];
    principal.assignments.forEach(function(a) {
      var roleDefId = a.properties?.roleDefinitionId || a.roleDefinitionId || '';
      var roleId = roleDefId.split('/').pop();
      var def = defMap[roleDefId] || defMap[roleId];
      var roleName = def?.properties?.roleName || def?.roleName || roleId;
      roleNames.push(roleName);
      var scope = a.properties?.scope || a.scope || '';
      scopes.push(scope);
      var scopeLevel = getScopeLevel(scope);
      // Admin detection
      if (roleId === OWNER_ID && (scopeLevel === 'subscription' || scopeLevel === 'managementGroup')) isAdmin = true;
      // Wildcard detection
      if (def) {
        var perms = def.properties?.permissions || def.permissions || [];
        perms.forEach(function(p) { if ((p.actions || []).includes('*')) hasWildcard = true; });
      }
      // Cross-tenant detection (Lighthouse)
      if (a._isLighthouse || a.properties?._isLighthouse) crossTenants.push(a._tenantId || '');
    });
    var findings = (complianceFindings || []).filter(function(f) { return f.framework === 'RBAC' && (f.resource === principal.principalId); });
    items.push({
      name: principal.principalId, // Azure doesn't always include display name in assignment data
      arn: principal.principalId, // Keep 'arn' field for backward compat with UI
      type: principal.principalType || 'Unknown',
      created: null,
      lastUsed: null,
      isAdmin: isAdmin,
      hasWildcard: hasWildcard,
      crossAccounts: crossTenants,
      policies: principal.assignments.length,
      policyNames: roleNames,
      permBoundary: '',
      findings: findings,
      _subscriptionId: (scopes[0] || '').split('/')[2] || '',
      _raw: principal
    });
  });
  _iamReviewData = items;
  return items;
}

// === EFFECTIVE PERMISSIONS ENGINE ===

/**
 * Match an Azure RBAC action pattern against an action string.
 * Supports wildcards (e.g., 'Microsoft.Compute/virtualMachines/*').
 * @param {string} pattern - Azure action pattern
 * @param {string} action - action to test
 * @returns {boolean}
 */
function matchAction(pattern, action) {
  if (!pattern || !action) return false;
  if (pattern === '*') return true;
  const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
  return re.test(action);
}

/**
 * Check if a scope encompasses another scope (Azure RBAC scope hierarchy).
 * @param {string} parentScope - higher scope (e.g., /subscriptions/xxx)
 * @param {string} childScope - resource scope to check
 * @returns {boolean}
 */
function scopeContains(parentScope, childScope) {
  if (!parentScope || !childScope) return false;
  if (parentScope === '/') return true;
  return childScope.toLowerCase().startsWith(parentScope.toLowerCase());
}

/**
 * Collect all RBAC permissions for a principal from role assignments.
 * @param {string} principalId - Azure AD principal ID
 * @param {Object} rbacData - { roleAssignments, roleDefinitions }
 * @returns {{ actions: string[], notActions: string[], dataActions: string[], notDataActions: string[], scopes: string[] }}
 */
function _collectPermissions(principalId, rbacData) {
  const result = { actions: [], notActions: [], dataActions: [], notDataActions: [], scopes: [] };
  const assignments = (rbacData.roleAssignments || []).filter(a => (a.properties?.principalId || a.principalId) === principalId);
  const defMap = {};
  (rbacData.roleDefinitions || []).forEach(d => { defMap[d.id || d.name] = d; });
  assignments.forEach(a => {
    const roleDefId = a.properties?.roleDefinitionId || a.roleDefinitionId || '';
    const def = defMap[roleDefId] || defMap[roleDefId.split('/').pop()];
    const scope = a.properties?.scope || a.scope || '';
    result.scopes.push(scope);
    if (def) {
      (def.properties?.permissions || def.permissions || []).forEach(p => {
        result.actions.push(...(p.actions || []));
        result.notActions.push(...(p.notActions || []));
        result.dataActions.push(...(p.dataActions || []));
        result.notDataActions.push(...(p.notDataActions || []));
      });
    }
  });
  return result;
}

/**
 * Check whether a principal can perform a specific action on a resource.
 * Azure RBAC: actions - notActions = effective permissions.
 * @param {string} principalId - Azure AD principal ID
 * @param {string} action - Azure action (e.g., 'Microsoft.Compute/virtualMachines/write')
 * @param {string} resourceScope - ARM resource ID/scope
 * @param {Object} rbacData - { roleAssignments, roleDefinitions }
 * @returns {{effect: string, reason: string}}
 */
function canDo(principalId, action, resourceScope, rbacData) {
  const perms = _collectPermissions(principalId, rbacData);
  // Check if any assignment scope covers this resource
  const coveredScopes = perms.scopes.filter(s => scopeContains(s, resourceScope));
  if (!coveredScopes.length) return { effect: 'IMPLICIT_DENY', reason: 'No role assignment at this scope' };
  // Check notActions first (deny takes precedence in Azure RBAC via deny assignments)
  if (perms.notActions.some(na => matchAction(na, action))) {
    return { effect: 'DENY', reason: 'Action excluded by notActions' };
  }
  // Check actions
  if (perms.actions.some(a => matchAction(a, action))) {
    return { effect: 'ALLOW', reason: 'Allowed by role assignment' };
  }
  return { effect: 'IMPLICIT_DENY', reason: 'No matching action in assigned roles' };
}

/**
 * Summarize all effective permissions for a principal.
 * Groups by Azure resource provider.
 * @param {string} principalId - Azure AD principal ID
 * @param {Object} rbacData - { roleAssignments, roleDefinitions }
 * @returns {{services: Object, isAdmin: boolean, hasWildcard: boolean}}
 */
function summarizePermissions(principalId, rbacData) {
  const perms = _collectPermissions(principalId, rbacData);
  const services = {}; let isAdmin = false; let hasWildcard = false;
  perms.actions.forEach(a => {
    if (a === '*') { isAdmin = true; hasWildcard = true; return; }
    const parts = a.split('/');
    const provider = parts[0] || 'ALL'; // e.g., 'Microsoft.Compute'
    if (!services[provider]) services[provider] = { allowed: [], denied: [] };
    const actionName = parts.slice(1).join('/');
    if (!services[provider].allowed.includes(actionName)) services[provider].allowed.push(actionName);
    if (a.includes('*')) hasWildcard = true;
  });
  perms.notActions.forEach(a => {
    const parts = a.split('/');
    const provider = parts[0] || 'ALL';
    if (!services[provider]) services[provider] = { allowed: [], denied: [] };
    const actionName = parts.slice(1).join('/');
    if (!services[provider].denied.includes(actionName)) services[provider].denied.push(actionName);
  });
  return { services, isAdmin, hasWildcard, permissionBoundary: null };
}

// === Window Bridge ===
// Expose all exports to window for inline callers that haven't migrated yet
if (typeof window !== 'undefined') {
  Object.assign(window, {
    // State variables — direct references (for backward compat reading)
    _govDashState, _iamDashState, _classificationData, _classificationOverrides,
    _iamReviewData, _inventoryData, _invState, _appRegistry, _appAutoDiscovered,
    _appSummaryState, _APP_TYPE_SUGGESTIONS, _invToolbarRendered,
    _INV_TYPE_COLORS, _INV_NO_MAP_TYPES, _invFilterCache, _invFilterKey,
    _DEFAULT_CLASS_RULES, _classificationRules, _discoveredTags, _TIER_RPO_RTO,
    // State accessors
    getGovDashState, setGovDashState, getIamDashState, setIamDashState,
    getClassificationData, setClassificationData,
    getClassificationOverrides, setClassificationOverrides,
    getIamReviewData, setIamReviewData, getInventoryData, setInventoryData,
    getInvState, setInvState, getAppRegistry, setAppRegistry,
    getAppAutoDiscovered, setAppAutoDiscovered,
    getAppSummaryState, setAppSummaryState,
    getInvToolbarRendered, setInvToolbarRendered,
    getInvFilterCache, setInvFilterCache, getInvFilterKey, setInvFilterKey,
    getClassificationRules, setClassificationRules,
    getDiscoveredTags, setDiscoveredTags,
    // Pure logic functions
    _buildInventoryData, _filterInventory, _getTagMap, _safeRegex,
    _scoreClassification, _discoverTagKeys, runClassificationEngine,
    prepareIAMReviewData, matchAction, scopeContains,
    _collectPermissions, canDo, summarizePermissions
  });
}

// === Backward Compat Exports ===
export {
  _govDashState, _iamDashState, _classificationData, _classificationOverrides,
  _iamReviewData, _inventoryData, _invState, _appRegistry, _appAutoDiscovered,
  _appSummaryState, _APP_TYPE_SUGGESTIONS, _invToolbarRendered,
  _INV_TYPE_COLORS, _INV_NO_MAP_TYPES, _invFilterCache, _invFilterKey,
  _DEFAULT_CLASS_RULES, _classificationRules, _discoveredTags, _TIER_RPO_RTO,
  _buildInventoryData, _filterInventory, _getTagMap, _safeRegex,
  _scoreClassification, _discoverTagKeys, runClassificationEngine,
  prepareIAMReviewData, matchAction, scopeContains,
  _collectPermissions, canDo, summarizePermissions
};
