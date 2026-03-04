// Multi-Tenant / Multi-Subscription — state and pure logic
// Azure Network Mapper — multi-tenant support for Azure hierarchy:
//   Tenant (Azure AD) > Management Group > Subscription > Resource Group > Resources
// Supports Azure Lighthouse delegated resource management.
// DOM rendering functions remain inline until modernized with dom-builders.js.

import { safeParse, ext, parseResourceId, getTenantFromResource } from './utils.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const AZURE_RESOURCE_ID_REGEX = /^\/subscriptions\/([^/]+)\/resourceGroups\/([^/]+)/i;
const TENANT_COLORS = [
  '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6',
  '#ec4899', '#14b8a6', '#f97316', '#6366f1', '#84cc16',
  '#06b6d4', '#e11d48', '#a855f7', '#22c55e', '#eab308'
];

// ---------------------------------------------------------------------------
// Module State
// ---------------------------------------------------------------------------
let multiViewMode = false;
let loadedContexts = [];  // [{tenantId, subscriptionId, subscriptionLabel, resourceGroup, textareas, rlCtx, color, visible, isLighthouse}]
let mergedCtx = null;
let singleCtxBackup = null;

// ---------------------------------------------------------------------------
// State Accessors
// ---------------------------------------------------------------------------
export function getMultiViewMode() { return multiViewMode; }
export function setMultiViewMode(v) { multiViewMode = v; }
export function getLoadedContexts() { return loadedContexts; }
export function setLoadedContexts(v) { loadedContexts = v; }
export function getMergedCtx() { return mergedCtx; }
export function setMergedCtx(v) { mergedCtx = v; }
export function getSingleCtxBackup() { return singleCtxBackup; }
export function setSingleCtxBackup(v) { singleCtxBackup = v; }

// ---------------------------------------------------------------------------
// Tenant / Subscription extraction helpers
// ---------------------------------------------------------------------------

/**
 * Extract subscription ID from an Azure ARM resource ID.
 * @param {string} resourceId - Full ARM resource ID
 * @returns {string} Subscription GUID or empty string
 */
function _extractSubscriptionId(resourceId) {
  if (!resourceId) return '';
  const match = resourceId.match(/\/subscriptions\/([^/]+)/i);
  return match ? match[1] : '';
}

/**
 * Extract resource group name from an Azure ARM resource ID.
 * @param {string} resourceId - Full ARM resource ID
 * @returns {string} Resource group name or empty string
 */
function _extractResourceGroup(resourceId) {
  if (!resourceId) return '';
  const match = resourceId.match(/\/resourceGroups\/([^/]+)/i);
  return match ? match[1] : '';
}

// ---------------------------------------------------------------------------
// Core exports
// ---------------------------------------------------------------------------

/**
 * Build tenant/subscription context from an array of Azure resources.
 * Groups resources by tenant and subscription, extracting hierarchy info
 * from ARM resource IDs and attached metadata.
 *
 * @param {Object[]} resources - Array of Azure ARM resource objects
 * @returns {{
 *   tenants: Map<string, {tenantId, displayName, subscriptions: Map<string, {subscriptionId, displayName, resourceGroups: Map<string, Object[]>, isLighthouse}>>},
 *   subscriptionToTenant: Map<string, string>,
 *   resourceGroupIndex: Map<string, string[]>
 * }}
 */
export function buildTenantContext(resources) {
  const tenants = new Map();
  const subscriptionToTenant = new Map();
  const resourceGroupIndex = new Map();

  (resources || []).forEach(r => {
    const subId = _extractSubscriptionId(r.id) || r._subscriptionId || '';
    const rgName = _extractResourceGroup(r.id) || r._resourceGroup || '';
    const tenantId = getTenantFromResource(r) || r._tenantId || 'default';
    const isLighthouse = r._isLighthouse === true;

    // Track subscription-to-tenant mapping
    if (subId && tenantId) subscriptionToTenant.set(subId, tenantId);

    // Ensure tenant entry exists
    if (!tenants.has(tenantId)) {
      tenants.set(tenantId, {
        tenantId,
        displayName: r._tenantDisplayName || tenantId,
        subscriptions: new Map(),
        isLighthouse: isLighthouse
      });
    }
    const tenant = tenants.get(tenantId);
    if (isLighthouse) tenant.isLighthouse = true;

    // Ensure subscription entry exists
    if (subId && !tenant.subscriptions.has(subId)) {
      tenant.subscriptions.set(subId, {
        subscriptionId: subId,
        displayName: r._subscriptionDisplayName || subId,
        resourceGroups: new Map(),
        isLighthouse: isLighthouse
      });
    }

    // Ensure resource group entry exists and add resource
    if (subId && rgName) {
      const sub = tenant.subscriptions.get(subId);
      if (!sub.resourceGroups.has(rgName)) sub.resourceGroups.set(rgName, []);
      sub.resourceGroups.get(rgName).push(r);

      // Global resource group index
      const rgKey = subId + '/' + rgName;
      if (!resourceGroupIndex.has(rgKey)) resourceGroupIndex.set(rgKey, []);
      resourceGroupIndex.get(rgKey).push(r.id || '');
    }

    // Tag resource with extracted context
    r._tenantId = tenantId;
    r._subscriptionId = subId;
    r._resourceGroup = rgName;
    r._isLighthouse = isLighthouse;
  });

  return { tenants, subscriptionToTenant, resourceGroupIndex };
}

/**
 * Get all loaded tenants with metadata.
 * @returns {Object[]} Array of {tenantId, displayName, subscriptionCount, resourceCount, isLighthouse, color}
 */
export function getTenants() {
  const tenantMap = new Map();
  loadedContexts.forEach(ctx => {
    const tid = ctx.tenantId || 'default';
    if (!tenantMap.has(tid)) {
      tenantMap.set(tid, {
        tenantId: tid,
        displayName: ctx.tenantDisplayName || tid,
        subscriptions: new Set(),
        resourceCount: 0,
        isLighthouse: ctx.isLighthouse || false,
        color: ctx.color || TENANT_COLORS[0]
      });
    }
    const t = tenantMap.get(tid);
    if (ctx.subscriptionId) t.subscriptions.add(ctx.subscriptionId);
    t.resourceCount += (ctx.rlCtx?.vnets?.length || 0) + (ctx.rlCtx?.subnets?.length || 0);
    if (ctx.isLighthouse) t.isLighthouse = true;
  });
  return [...tenantMap.values()].map(t => ({
    ...t,
    subscriptionCount: t.subscriptions.size,
    subscriptions: [...t.subscriptions]
  }));
}

/**
 * Get subscriptions, optionally filtered by tenant ID.
 * @param {string} [tenantId] - Optional tenant ID filter
 * @returns {Object[]} Array of {subscriptionId, displayName, tenantId, isLighthouse, color}
 */
export function getSubscriptions(tenantId) {
  const subMap = new Map();
  loadedContexts.forEach(ctx => {
    if (tenantId && ctx.tenantId !== tenantId) return;
    const sid = ctx.subscriptionId || '';
    if (!sid) return;
    if (!subMap.has(sid)) {
      subMap.set(sid, {
        subscriptionId: sid,
        displayName: ctx.subscriptionDisplayName || ctx.subscriptionLabel || sid,
        tenantId: ctx.tenantId || 'default',
        isLighthouse: ctx.isLighthouse || false,
        color: ctx.color || TENANT_COLORS[0],
        resourceGroups: new Set()
      });
    }
    if (ctx.resourceGroup) subMap.get(sid).resourceGroups.add(ctx.resourceGroup);
  });
  return [...subMap.values()].map(s => ({
    ...s,
    resourceGroups: [...s.resourceGroups]
  }));
}

/**
 * Assign distinct colors to each tenant for visual differentiation.
 * @param {string[]|Object[]} tenants - Array of tenant IDs or tenant objects
 * @returns {Map<string, string>} Map of tenantId to hex color
 */
export function assignTenantColors(tenants) {
  const colorMap = new Map();
  const ids = tenants.map(t => typeof t === 'string' ? t : t.tenantId);
  ids.forEach((tid, i) => {
    colorMap.set(tid, TENANT_COLORS[i % TENANT_COLORS.length]);
  });
  // Apply to loaded contexts
  loadedContexts.forEach(ctx => {
    if (ctx.tenantId && colorMap.has(ctx.tenantId)) {
      ctx.color = colorMap.get(ctx.tenantId);
    }
  });
  return colorMap;
}

/**
 * Check if a resource is from a Lighthouse-delegated tenant.
 * @param {Object} resource - Azure ARM resource object
 * @returns {boolean} True if resource is delegated via Lighthouse
 */
export function isLighthouse(resource) {
  if (!resource) return false;
  return resource._isLighthouse === true;
}

/**
 * Build an rlCtx directly from a {id: value} textarea map without DOM round-trip.
 * Values can be strings (web) or pre-parsed objects (Electron).
 * @param {Object} textareas - {textareaId: jsonString|object}
 * @param {string} subscriptionLabel
 * @returns {Object|null} rlCtx
 */
export function buildRlCtxFromData(textareas, subscriptionLabel) {
  try {
    function _val(id) {
      const v = textareas[id]; if (!v) return null;
      if (typeof v === 'string') { const p = safeParse(v); if (p !== null) textareas[id] = p; return p; }
      return v;
    }
    const userSubscription = subscriptionLabel || '';

    let vnets = ext(_val('in_vnets'), ['value']);
    let subnets = ext(_val('in_subnets'), ['value']);
    let nsgs = ext(_val('in_nsgs'), ['value']);
    let routeTables = ext(_val('in_route_tables'), ['value']);
    let nics = ext(_val('in_nics'), ['value']);
    let natGateways = ext(_val('in_nat_gateways'), ['value']);
    let publicIps = ext(_val('in_public_ips'), ['value']);
    let vms = ext(_val('in_vms'), ['value']);
    let lbs = ext(_val('in_lbs'), ['value']);
    let appGateways = ext(_val('in_app_gateways'), ['value']);
    let peerings = ext(_val('in_peerings'), ['value']);
    let vpnGateways = ext(_val('in_vpn_gateways'), ['value']);
    let firewalls = ext(_val('in_firewalls'), ['value']);
    let bastionHosts = ext(_val('in_bastion'), ['value']);
    let privateDnsZones = ext(_val('in_private_dns'), ['value']);
    let sqlServers = ext(_val('in_sql'), ['value']);
    let aksClusters = ext(_val('in_aks'), ['value']);
    let functionApps = ext(_val('in_functions'), ['value']);
    let appServices = ext(_val('in_appservices'), ['value']);
    let redisCaches = ext(_val('in_redis'), ['value']);
    let cosmosAccounts = ext(_val('in_cosmos'), ['value']);
    let storageAccounts = ext(_val('in_storage'), ['value']);
    let privateEndpoints = ext(_val('in_private_endpoints'), ['value']);
    let disks = ext(_val('in_disks'), ['value']);
    let wafPolicies = ext(_val('in_waf'), ['value']);

    function tagResource(r) {
      if (!r) return r;
      r._subscriptionId = _extractSubscriptionId(r.id) || r._subscriptionId || userSubscription || 'default';
      r._resourceGroup = _extractResourceGroup(r.id) || r._resourceGroup || '';
      r._tenantId = getTenantFromResource(r) || r._tenantId || '';
      r._location = r.location || '';
      return r;
    }

    [vnets, subnets, nsgs, routeTables, nics, natGateways, publicIps, vms, lbs, appGateways,
      peerings, vpnGateways, firewalls, bastionHosts, privateDnsZones, sqlServers, aksClusters,
      functionApps, appServices, redisCaches, cosmosAccounts, storageAccounts, privateEndpoints,
      disks, wafPolicies
    ].forEach(arr => arr.forEach(tagResource));

    // VNet location fallback from subnets
    const vnetLocation = {};
    subnets.forEach(s => {
      const vnetId = s._vnetId || '';
      if (vnetId && s._location) vnetLocation[vnetId] = s._location;
    });
    function fillLocation(r) {
      if (r && !r._location && r._vnetId && vnetLocation[r._vnetId]) r._location = vnetLocation[r._vnetId];
    }
    [nsgs, routeTables, nics, natGateways].forEach(arr => arr.forEach(fillLocation));

    // Build subscription/tenant indexes
    const _subscriptions = new Set();
    const _tenants = new Set();
    vnets.forEach(v => {
      if (v._subscriptionId && v._subscriptionId !== 'default') _subscriptions.add(v._subscriptionId);
      if (v._tenantId) _tenants.add(v._tenantId);
    });
    const _multiSubscription = _subscriptions.size > 1;
    const _multiTenant = _tenants.size > 1;

    // Build locations set
    const _locations = new Set();
    vnets.forEach(v => { if (v._location) _locations.add(v._location); });
    const _multiLocation = _locations.size > 1;

    // Build subnet-to-VNet mapping
    const vnetIds = new Set(vnets.map(v => v.id));
    subnets.forEach(s => {
      if (!s._vnetId) {
        // Derive VNet ID from subnet ID: everything before /subnets/
        const parts = (s.id || '').split('/subnets/');
        if (parts.length === 2) s._vnetId = parts[0];
      }
    });

    // Build resource-by-subnet maps
    const resourcesBySub = {};
    const vmBySub = {};
    const nicBySub = {};
    const lbBySub = {};

    nics.forEach(nic => {
      const ipConfigs = nic.properties?.ipConfigurations || [];
      ipConfigs.forEach(ipc => {
        const subnetId = ipc.properties?.subnet?.id || '';
        if (subnetId) {
          if (!nicBySub[subnetId]) nicBySub[subnetId] = [];
          nicBySub[subnetId].push(nic);
        }
      });
    });

    vms.forEach(vm => {
      const vmNics = vm.properties?.networkProfile?.networkInterfaces || [];
      vmNics.forEach(vmNic => {
        // Find the NIC to determine subnet
        const nic = nics.find(n => n.id === vmNic.id);
        if (nic) {
          const ipConfigs = nic.properties?.ipConfigurations || [];
          ipConfigs.forEach(ipc => {
            const subnetId = ipc.properties?.subnet?.id || '';
            if (subnetId) {
              if (!vmBySub[subnetId]) vmBySub[subnetId] = [];
              vmBySub[subnetId].push(vm);
              if (!resourcesBySub[subnetId]) resourcesBySub[subnetId] = [];
              resourcesBySub[subnetId].push(vm);
            }
          });
        }
      });
    });

    lbs.forEach(lb => {
      (lb.properties?.frontendIPConfigurations || []).forEach(fip => {
        const subnetId = fip.properties?.subnet?.id || '';
        if (subnetId) {
          if (!lbBySub[subnetId]) lbBySub[subnetId] = [];
          lbBySub[subnetId].push(lb);
        }
      });
    });

    // Build NSG-by-subnet map
    const nsgBySub = {};
    subnets.forEach(s => {
      const nsgId = s.properties?.networkSecurityGroup?.id || s.nsgId;
      if (nsgId) {
        const nsg = nsgs.find(n => n.id === nsgId);
        if (nsg) nsgBySub[s.id] = nsg;
      }
    });

    // Build route-table-by-subnet map
    const rtBySub = {};
    subnets.forEach(s => {
      const rtId = s.properties?.routeTable?.id || s.routeTableId;
      if (rtId) {
        const rt = routeTables.find(r => r.id === rtId);
        if (rt) rtBySub[s.id] = rt;
      }
    });

    // Build NSG-by-VNet map
    const nsgByVnet = {};
    nsgs.forEach(nsg => {
      const vnetId = nsg._vnetId || '';
      if (vnetId) {
        if (!nsgByVnet[vnetId]) nsgByVnet[vnetId] = [];
        nsgByVnet[vnetId].push(nsg);
      }
    });

    // Build private endpoint by subnet
    const peBySub = {};
    privateEndpoints.forEach(pe => {
      const subnetId = pe.properties?.subnet?.id || '';
      if (subnetId) {
        if (!peBySub[subnetId]) peBySub[subnetId] = [];
        peBySub[subnetId].push(pe);
      }
    });

    return {
      vnets, subnets, nsgs, routeTables, nics, natGateways, publicIps,
      vms, lbs, appGateways, peerings, vpnGateways, firewalls, bastionHosts,
      privateDnsZones, sqlServers, aksClusters, functionApps, appServices,
      redisCaches, cosmosAccounts, storageAccounts, privateEndpoints, disks, wafPolicies,
      resourcesBySub, vmBySub, nicBySub, lbBySub, nsgBySub, rtBySub, nsgByVnet, peBySub,
      _subscriptions, _tenants, _locations,
      _multiSubscription, _multiTenant, _multiLocation
    };
  } catch (e) {
    console.warn('buildRlCtxFromData error:', e);
    return null;
  }
}

/**
 * Merge new resources into an existing tenant context.
 * Used when loading additional subscriptions/tenants incrementally.
 *
 * @param {Object|null} existingCtx - Existing rlCtx (or null)
 * @param {Object[]} newResources - Array of new Azure ARM resources
 * @param {string} tenantLabel - Display label for the tenant/subscription
 * @returns {Object} Updated tenant context
 */
export function mergeTenantData(existingCtx, newResources, tenantLabel) {
  if (!existingCtx) {
    // Build fresh context from textareas-like object
    const textareas = {};
    // Group by resource type
    newResources.forEach(r => {
      const type = (r.type || '').toLowerCase();
      let key = 'in_misc';
      if (type.includes('virtualnetwork') && !type.includes('subnet')) key = 'in_vnets';
      else if (type.includes('subnet')) key = 'in_subnets';
      else if (type.includes('networksecuritygroup')) key = 'in_nsgs';
      else if (type.includes('routetable')) key = 'in_route_tables';
      else if (type.includes('networkinterface')) key = 'in_nics';
      else if (type.includes('natgateway')) key = 'in_nat_gateways';
      else if (type.includes('publicipaddress')) key = 'in_public_ips';
      else if (type.includes('virtualmachine')) key = 'in_vms';
      else if (type.includes('loadbalancer')) key = 'in_lbs';
      else if (type.includes('applicationgateway')) key = 'in_app_gateways';
      if (!textareas[key]) textareas[key] = { value: [] };
      textareas[key].value.push(r);
    });
    return buildRlCtxFromData(textareas, tenantLabel);
  }

  // Merge into existing context
  newResources.forEach(r => {
    r._tenantLabel = tenantLabel;
    const type = (r.type || '').toLowerCase();
    if (type.includes('virtualnetwork') && !type.includes('subnet')) existingCtx.vnets.push(r);
    else if (type.includes('subnet')) existingCtx.subnets.push(r);
    else if (type.includes('networksecuritygroup')) existingCtx.nsgs.push(r);
    else if (type.includes('virtualmachine')) existingCtx.vms.push(r);
    // ... extend for other types
  });

  return existingCtx;
}

/**
 * Get display name for a tenant ID.
 * @param {string} tenantId - Azure AD tenant GUID
 * @returns {string} Display name or truncated GUID
 */
export function getTenantDisplayName(tenantId) {
  if (!tenantId || tenantId === 'default') return 'Default Tenant';
  // Check loaded contexts for a friendly name
  const ctx = loadedContexts.find(c => c.tenantId === tenantId);
  if (ctx?.tenantDisplayName) return ctx.tenantDisplayName;
  // Truncate GUID for display
  if (tenantId.length > 12) return tenantId.substring(0, 8) + '...';
  return tenantId;
}

/**
 * Get display name for a subscription ID.
 * @param {string} subId - Azure subscription GUID
 * @returns {string} Display name or truncated GUID
 */
export function getSubscriptionDisplayName(subId) {
  if (!subId || subId === 'default') return 'Default Subscription';
  const ctx = loadedContexts.find(c => c.subscriptionId === subId);
  if (ctx?.subscriptionDisplayName || ctx?.subscriptionLabel) return ctx.subscriptionDisplayName || ctx.subscriptionLabel;
  if (subId.length > 12) return subId.substring(0, 8) + '...';
  return subId;
}

/**
 * Merge multiple subscription/tenant contexts into a single rlCtx.
 * @param {Array} contexts - array of {tenantId, subscriptionId, rlCtx, textareas, visible, color, ...}
 * @returns {Object|null} merged rlCtx
 */
export function mergeContexts(contexts) {
  const visible = contexts.filter(c => c.visible);
  if (!visible.length) return null;
  // Lazily rebuild rlCtx from textareas if previously released
  visible.forEach(c => { if (!c.rlCtx && c.textareas) c.rlCtx = buildRlCtxFromData(c.textareas, c.subscriptionLabel); });
  if (visible.length === 1) return visible[0].rlCtx;

  const merged = {
    vnets: [], subnets: [], nsgs: [], routeTables: [], nics: [], natGateways: [], publicIps: [],
    vms: [], lbs: [], appGateways: [], peerings: [], vpnGateways: [], firewalls: [], bastionHosts: [],
    privateDnsZones: [], sqlServers: [], aksClusters: [], functionApps: [], appServices: [],
    redisCaches: [], cosmosAccounts: [], storageAccounts: [], privateEndpoints: [], disks: [], wafPolicies: [],
    resourcesBySub: {}, vmBySub: {}, nicBySub: {}, lbBySub: {},
    nsgBySub: {}, rtBySub: {}, nsgByVnet: {}, peBySub: {},
    _subscriptions: new Set(), _tenants: new Set(), _locations: new Set(),
    _multiSubscription: true, _multiTenant: false, _multiLocation: false
  };

  visible.forEach(ctx => {
    const c = ctx.rlCtx; if (!c) return;
    const tag = (r) => {
      if (r) {
        r._subscriptionId = r._subscriptionId || ctx.subscriptionId;
        r._tenantId = r._tenantId || ctx.tenantId;
        r._subscriptionLabel = ctx.subscriptionLabel;
        r._ctxColor = ctx.color;
        r._isLighthouse = ctx.isLighthouse || r._isLighthouse || false;
      }
      return r;
    };

    const arrayKeys = [
      'vnets', 'subnets', 'nsgs', 'routeTables', 'nics', 'natGateways', 'publicIps',
      'vms', 'lbs', 'appGateways', 'peerings', 'vpnGateways', 'firewalls', 'bastionHosts',
      'privateDnsZones', 'sqlServers', 'aksClusters', 'functionApps', 'appServices',
      'redisCaches', 'cosmosAccounts', 'storageAccounts', 'privateEndpoints', 'disks', 'wafPolicies'
    ];
    arrayKeys.forEach(k => {
      if (c[k] && Array.isArray(c[k])) c[k].forEach(r => { tag(r); merged[k].push(r); });
    });

    if (c._subscriptions) c._subscriptions.forEach(s => merged._subscriptions.add(s));
    merged._subscriptions.add(ctx.subscriptionId);
    if (c._tenants) c._tenants.forEach(t => merged._tenants.add(t));
    if (ctx.tenantId) merged._tenants.add(ctx.tenantId);
    if (c._locations) c._locations.forEach(l => merged._locations.add(l));

    const mapKeys = [
      'resourcesBySub', 'vmBySub', 'nicBySub', 'lbBySub',
      'nsgBySub', 'rtBySub', 'nsgByVnet', 'peBySub'
    ];
    mapKeys.forEach(k => {
      if (!c[k]) return;
      const src = c[k];
      const keys = src instanceof Map ? [...src.keys()] : Object.keys(src);
      keys.forEach(key => {
        const val = src instanceof Map ? src.get(key) : src[key];
        if (Array.isArray(val)) {
          if (!merged[k][key]) merged[k][key] = [];
          val.forEach(v => merged[k][key].push(v));
        } else {
          if (!merged[k][key]) merged[k][key] = val;
        }
      });
    });
  });

  merged._multiTenant = merged._tenants.size > 1;
  merged._multiSubscription = merged._subscriptions.size > 1;
  merged._multiLocation = merged._locations.size > 1;
  return merged;
}

/**
 * Detect Azure location from a parsed rlCtx by looking at VNet or resource locations.
 * @param {Object} ctx - rlCtx object
 * @returns {string} Azure location or 'unknown'
 */
export function detectLocationFromCtx(ctx) {
  if (!ctx) return 'unknown';
  const vnet = (ctx.vnets || [])[0];
  if (vnet && vnet.location) return vnet.location;
  const vm = (ctx.vms || [])[0];
  if (vm && vm.location) return vm.location;
  return 'unknown';
}

// Backward-compat aliases
export {
  multiViewMode as _multiViewMode,
  loadedContexts as _loadedContexts,
  mergedCtx as _mergedCtx,
  singleCtxBackup as _singleCtxBackup
};
