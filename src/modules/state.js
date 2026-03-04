// Shared application state — ONLY cross-cutting variables used by 5+ regions.
// All domain-specific state lives in its owning module (design-mode.js, flow-tracing.js, etc.)

// Core resource context — the parsed Azure data object passed to every renderer.
// Field names mirror Azure resource categories collected from ARM / REST APIs.
export let rlCtx = null;
// rlCtx shape (all fields optional, populated by the ingestion layer):
// {
//   vnets            — Microsoft.Network/virtualNetworks
//   nsgs             — Microsoft.Network/networkSecurityGroups (NIC-level)
//   subnetNsgs       — Microsoft.Network/networkSecurityGroups (subnet-level)
//   udrs             — Microsoft.Network/routeTables (User Defined Routes)
//   natGateways      — Microsoft.Network/natGateways
//   privateEndpoints — Microsoft.Network/privateEndpoints
//   vms              — Microsoft.Compute/virtualMachines
//   sqlServers       — Microsoft.Sql/servers
//   functionApps     — Microsoft.Web/sites (kind: functionapp)
//   containerInstances — Microsoft.ContainerInstance/containerGroups
//   appGateways      — Microsoft.Network/applicationGateways
//   peerings         — Microsoft.Network/virtualNetworks/virtualNetworkPeerings
//   vpnConnections   — Microsoft.Network/connections
//   vwans            — Microsoft.Network/virtualWans
//   frontDoors       — Microsoft.Network/frontDoors
//   nics             — Microsoft.Network/networkInterfaces
//   disks            — Microsoft.Compute/disks (Managed Disks)
//   snapshots        — Microsoft.Compute/snapshots
//   storageAccounts  — Microsoft.Storage/storageAccounts
//   dnsZones         — Microsoft.Network/dnsZones
//   dnsRecords       — Microsoft.Network/dnsZones/<zone>/recordSets
//   wafPolicies      — Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies
//   rbac             — Microsoft.Authorization/roleAssignments + roleDefinitions
//   redisCaches      — Microsoft.Cache/redis
//   synapseWorkspaces — Microsoft.Synapse/workspaces
//   bastions         — Microsoft.Network/bastionHosts
//   firewalls        — Microsoft.Network/azureFirewalls
//   aksCluster       — Microsoft.ContainerService/managedClusters
//   vhubs            — Microsoft.Network/virtualHubs
//   networkWatchers  — Microsoft.Network/networkWatchers
//   asgs             — Microsoft.Network/applicationSecurityGroups
//   resourceGroups   — Microsoft.Resources/resourceGroups
// }

// D3 map references — used by topology, flow, diff, design, and navigation
export let mapSvg = null;
export let mapZoom = null;
export let mapG = null;

// Gateway name lookup — populated by topology renderer, read by firewall, flow, exports
export let gwNames = {};

// UI state — affects sidebar, canvas, and detail panel rendering
export let detailLevel = 0;    // 0=collapsed, 1=normal, 2=expanded
export let showNested = false;  // topology nesting toggle
export let gTxtScale = 1.0;    // global text scale factor

// Compliance findings — core data used by dashboard, exports, and reports
export let complianceFindings = [];

// Sidebar DOM reference — used throughout initialization and event handlers
export let sb = null;

// Azure environment context — populated during session load / ingestion
export let cloudEnv = '';         // e.g. 'AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud'
export let tenantId = '';         // Azure Active Directory tenant GUID
export let subscriptionId = '';   // Active subscription GUID

// Setters — ES modules can't reassign imported bindings, so consumers use these
export function setRlCtx(v)              { rlCtx = v; }
export function setMapSvg(v)             { mapSvg = v; }
export function setMapZoom(v)            { mapZoom = v; }
export function setMapG(v)               { mapG = v; }
export function setGwNames(v)            { gwNames = v; }
export function setDetailLevel(v)        { detailLevel = v; }
export function setShowNested(v)         { showNested = v; }
export function setGTxtScale(v)          { gTxtScale = v; }
export function setComplianceFindings(v) { complianceFindings = v; }
export function setSb(v)                 { sb = v; }
export function setCloudEnv(v)           { cloudEnv = v; }
export function setTenantId(v)           { tenantId = v; }
export function setSubscriptionId(v)     { subscriptionId = v; }
