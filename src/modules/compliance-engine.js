// Compliance checks engine for Azure Network Mapper
// Frameworks: CIS_AZURE, CAF, SOC2, PCI, BUDR, RBAC, FEDRAMP_MOD, FEDRAMP_HIGH, NIST_800_171, CMMC
// Runs automated compliance checks and generates findings per framework
// Each finding: { id, framework, severity, title, message, resource, resourceId, resourceType, remediation, checkovId }

import { sid } from './utils.js';
import { getCloudEnv, getComplianceFrameworks } from './cloud-env.js';
import { runBUDRChecks } from './budr-engine.js';
import { analyzeRoleAssignments, getRbacData } from './iam-engine.js';

// ============================================================================
// Checkov ID mapping — CKV_AZURE_* equivalents
// ============================================================================
const CKV_MAP = {
  'CIS-9':     'CKV_AZURE_9',    // NSG allows RDP from 0.0.0.0/0
  'CIS-10':    'CKV_AZURE_10',   // NSG allows SSH from 0.0.0.0/0
  'CIS-12':    'CKV_AZURE_12',   // NSG allows all inbound
  'CIS-34':    'CKV_AZURE_34',   // Storage public blob access
  'CIS-44':    'CKV_AZURE_44',   // Storage min TLS < 1.2
  'CIS-SQL-1': 'CKV_AZURE_28',   // SQL server publicly accessible
  'CIS-REDIS': 'CKV_AZURE_88',   // Redis not using TLS
  'CIS-AKS':   'CKV_AZURE_5',    // AKS RBAC not enabled
  'CIS-DDOS':  'CKV_AZURE_57',   // VNet without DDoS protection
  'CAF-NSG':   'CKV_AZURE_160',  // Subnet without NSG
  'CAF-UDR':   'CKV_AZURE_161',  // Subnet without route table
  'SOC2-TLS':  'CKV_AZURE_44',   // TLS 1.2 minimum on storage
  'SOC2-DISK': 'CKV_AZURE_93',   // Managed disk encryption
  'PCI-WAF':   'CKV_AZURE_120',  // App GW without WAF
  'PE-PENDING': 'CKV_AZURE_PE_1', // PE connection pending
  'PE-NO-DNS':  'CKV_AZURE_PE_2', // No matching private DNS zone
  'PE-DNS-UNLINKED': 'CKV_AZURE_PE_3', // DNS zone not linked to VNet
  'PE-NSG-POLICY':   'CKV_AZURE_PE_4', // Subnet NSG policies disabled
  'PE-ORPHAN':       'CKV_AZURE_PE_5', // PE connection failed/disconnected
};

// ============================================================================
// Module-level cache
// ============================================================================
let _complianceFindings = [];
let _complianceCacheData = null;

// ============================================================================
// Helpers — Azure NSG rule evaluation
// ============================================================================

/**
 * Extract security rules from an NSG resource object.
 * Azure NSGs carry rules under properties.securityRules or securityRules.
 */
function _getRules(nsg) {
  if (!nsg) return [];
  const props = nsg.properties || nsg;
  return props.securityRules || props.SecurityRules || [];
}

/**
 * Get the properties of an NSG rule (handles nested .properties pattern).
 */
function _ruleProps(rule) {
  return rule.properties || rule;
}

/**
 * Check if a source address prefix matches "any" (0.0.0.0/0 or * or Internet).
 */
function _isOpenSource(prefix) {
  if (!prefix) return false;
  const p = String(prefix).trim();
  return p === '*' || p === '0.0.0.0/0' || p === 'Internet' || p === 'Any' || p === '::/0';
}

/**
 * Check if any source address prefix in prefixes array is open.
 */
function _hasOpenSourcePrefixes(rule) {
  const rp = _ruleProps(rule);
  if (_isOpenSource(rp.sourceAddressPrefix)) return true;
  const prefixes = rp.sourceAddressPrefixes || [];
  return prefixes.some(p => _isOpenSource(p));
}

/**
 * Check if a rule covers a specific port number.
 */
function _coversPort(rule, port) {
  const rp = _ruleProps(rule);
  const ranges = _collectPortRanges(rp);
  return ranges.some(range => _portInRange(range, port));
}

/**
 * Collect all destination port ranges from a rule.
 */
function _collectPortRanges(rp) {
  const ranges = [];
  if (rp.destinationPortRange) ranges.push(rp.destinationPortRange);
  if (rp.destinationPortRanges) ranges.push(...rp.destinationPortRanges);
  return ranges;
}

/**
 * Check if a port falls within a port range string ("80", "80-443", "*").
 */
function _portInRange(range, port) {
  if (!range) return false;
  const r = String(range).trim();
  if (r === '*') return true;
  if (r.includes('-')) {
    const [lo, hi] = r.split('-').map(Number);
    return port >= lo && port <= hi;
  }
  return Number(r) === port;
}

/**
 * Check if a rule allows all ports (destinationPortRange = '*').
 */
function _isAllPorts(rule) {
  const rp = _ruleProps(rule);
  return rp.destinationPortRange === '*' ||
    (rp.destinationPortRanges || []).includes('*');
}

/**
 * Check if a rule uses UDP protocol.
 */
function _isUdp(rule) {
  const rp = _ruleProps(rule);
  const proto = (rp.protocol || '').toLowerCase();
  return proto === 'udp' || proto === '*';
}

/**
 * Check if a rule allows all protocols.
 */
function _isAllProtocols(rule) {
  const rp = _ruleProps(rule);
  return (rp.protocol || '').trim() === '*';
}

/**
 * Get the resource name for display. Azure resources use .name or last ID segment.
 */
function _rn(resource, fallback) {
  if (!resource) return fallback || '';
  return resource.name || sid(resource.id) || fallback || '';
}

/**
 * Get Azure resource type from the resource object.
 */
function _rtype(resource) {
  return resource?.type || '';
}

/**
 * Build a finding object in the standard format.
 */
function _finding(opts) {
  return {
    id: opts.id || '',
    framework: opts.framework || '',
    severity: opts.severity || 'MEDIUM',
    title: opts.title || '',
    message: opts.message || '',
    resource: opts.resource || '',
    resourceId: opts.resourceId || '',
    resourceType: opts.resourceType || '',
    remediation: opts.remediation || '',
    checkovId: CKV_MAP[opts.id] || opts.checkovId || '',
    control: opts.id || '',
    resourceName: opts.resource || '',
  };
}

/**
 * Get tags object from an Azure resource.
 */
function _getTags(resource) {
  if (!resource) return {};
  return resource.tags || resource.Tags || (resource.properties || {}).tags || {};
}

/**
 * Check if resource has any user-defined tags.
 */
function _hasTags(resource) {
  const tags = _getTags(resource);
  return Object.keys(tags).length > 0;
}

/**
 * Extract subnets from a VNet resource.
 */
function _getVnetSubnets(vnet) {
  if (!vnet) return [];
  const props = vnet.properties || vnet;
  return props.subnets || [];
}

/**
 * Get subnet properties.
 */
function _subnetProps(subnet) {
  return subnet.properties || subnet;
}

// ============================================================================
// CIS Azure Foundations 3.0 checks (~15)
// ============================================================================
function runCISAzureChecks(data) {
  const f = [];
  const nsgs = data.nsgs || [];
  const storageAccounts = data.storageAccounts || [];
  const sqlServers = data.sqlServers || [];
  const redisCaches = data.redisCaches || [];
  const aksClusters = data.aksClusters || [];
  const vnets = data.vnets || [];
  const bastionHosts = data.bastionHosts || [];
  const networkWatchers = data.networkWatchers || [];
  const regions = data._regions || [];

  // CIS-9: NSG allows RDP (3389) from 0.0.0.0/0
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction !== 'Inbound' || rp.access !== 'Allow') return;
      if (_coversPort(rule, 3389) && _hasOpenSourcePrefixes(rule)) {
        f.push(_finding({
          id: 'CIS-9', framework: 'CIS_AZURE', severity: 'HIGH',
          title: 'NSG allows RDP from 0.0.0.0/0',
          message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows RDP (3389) from any source`,
          resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
          remediation: 'Restrict RDP access to specific CIDR ranges or use Azure Bastion',
        }));
      }
    });
  });

  // CIS-10: NSG allows SSH (22) from 0.0.0.0/0
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction !== 'Inbound' || rp.access !== 'Allow') return;
      if (_coversPort(rule, 22) && _hasOpenSourcePrefixes(rule)) {
        f.push(_finding({
          id: 'CIS-10', framework: 'CIS_AZURE', severity: 'HIGH',
          title: 'NSG allows SSH from 0.0.0.0/0',
          message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows SSH (22) from any source`,
          resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
          remediation: 'Restrict SSH access to specific CIDR ranges or use Azure Bastion',
        }));
      }
    });
  });

  // CIS-12: NSG allows all inbound traffic
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction !== 'Inbound' || rp.access !== 'Allow') return;
      if (_isAllProtocols(rule) && _isAllPorts(rule) && _hasOpenSourcePrefixes(rule)) {
        f.push(_finding({
          id: 'CIS-12', framework: 'CIS_AZURE', severity: 'CRITICAL',
          title: 'NSG allows all inbound traffic',
          message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows all traffic from any source`,
          resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
          remediation: 'Remove or restrict rule to specific ports and source addresses',
        }));
      }
    });
  });

  // CIS-DB: NSG allows database ports (1433/3306/5432) from 0.0.0.0/0
  const dbPorts = [
    { port: 1433, name: 'SQL Server' },
    { port: 3306, name: 'MySQL' },
    { port: 5432, name: 'PostgreSQL' },
  ];
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction !== 'Inbound' || rp.access !== 'Allow') return;
      if (!_hasOpenSourcePrefixes(rule)) return;
      dbPorts.forEach(db => {
        if (_coversPort(rule, db.port)) {
          f.push(_finding({
            id: 'CIS-DB-' + db.port, framework: 'CIS_AZURE', severity: 'HIGH',
            title: `NSG allows ${db.name} port from 0.0.0.0/0`,
            message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows ${db.name} (${db.port}) from any source`,
            resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
            remediation: `Restrict ${db.name} access to application subnets only`,
          }));
        }
      });
    });
  });

  // CIS-UDP: NSG allows UDP from 0.0.0.0/0
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction !== 'Inbound' || rp.access !== 'Allow') return;
      const proto = (rp.protocol || '').toLowerCase();
      if (proto !== 'udp') return;
      if (_isAllPorts(rule) && _hasOpenSourcePrefixes(rule)) {
        f.push(_finding({
          id: 'CIS-UDP', framework: 'CIS_AZURE', severity: 'HIGH',
          title: 'NSG allows all UDP from 0.0.0.0/0',
          message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows all UDP traffic from any source`,
          resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
          remediation: 'Restrict UDP access to specific ports and source addresses',
        }));
      }
    });
  });

  // CIS-34: Storage account allows public blob access
  storageAccounts.forEach(sa => {
    const props = sa.properties || sa;
    const pubAccess = props.allowBlobPublicAccess ?? props.AllowBlobPublicAccess;
    if (pubAccess === true) {
      f.push(_finding({
        id: 'CIS-34', framework: 'CIS_AZURE', severity: 'HIGH',
        title: 'Storage account allows public blob access',
        message: `Storage account "${_rn(sa)}" allows anonymous public read access to blobs`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Set allowBlobPublicAccess to false on the storage account',
      }));
    }
  });

  // CIS-44: Storage account minimum TLS version < 1.2
  storageAccounts.forEach(sa => {
    const props = sa.properties || sa;
    const minTls = props.minimumTlsVersion || props.MinimumTlsVersion || '';
    if (minTls && minTls !== 'TLS1_2' && minTls !== 'TLS1_3') {
      f.push(_finding({
        id: 'CIS-44', framework: 'CIS_AZURE', severity: 'HIGH',
        title: 'Storage account minimum TLS < 1.2',
        message: `Storage account "${_rn(sa)}" uses ${minTls} — TLS 1.2 is the minimum secure version`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Set minimumTlsVersion to TLS1_2 on the storage account',
      }));
    }
  });

  // CIS-SQL-1: SQL server publicly accessible
  sqlServers.forEach(srv => {
    const props = srv.properties || srv;
    const fwRules = props.firewallRules || [];
    const hasOpenFw = fwRules.some(fw => {
      const fwp = fw.properties || fw;
      return fwp.startIpAddress === '0.0.0.0' && fwp.endIpAddress === '255.255.255.255';
    });
    const pubAccess = props.publicNetworkAccess || '';
    if (hasOpenFw || pubAccess.toLowerCase() === 'enabled') {
      f.push(_finding({
        id: 'CIS-SQL-1', framework: 'CIS_AZURE', severity: 'CRITICAL',
        title: 'SQL server publicly accessible',
        message: `SQL server "${_rn(srv)}" is accessible from the public internet`,
        resource: _rn(srv), resourceId: srv.id || '', resourceType: 'Microsoft.Sql/servers',
        remediation: 'Disable public network access; use private endpoints and restrict firewall rules',
      }));
    }
  });

  // CIS-REDIS: Redis cache not using TLS
  redisCaches.forEach(rc => {
    const props = rc.properties || rc;
    const nonSslPort = props.enableNonSslPort ?? props.EnableNonSslPort;
    const minTls = props.minimumTlsVersion || props.MinimumTlsVersion || '';
    if (nonSslPort === true || (minTls && minTls !== '1.2' && minTls !== '1.3')) {
      f.push(_finding({
        id: 'CIS-REDIS', framework: 'CIS_AZURE', severity: 'HIGH',
        title: 'Redis cache not enforcing TLS',
        message: `Redis cache "${_rn(rc)}" ${nonSslPort ? 'has non-SSL port enabled' : 'uses TLS version < 1.2'}`,
        resource: _rn(rc), resourceId: rc.id || '', resourceType: 'Microsoft.Cache/Redis',
        remediation: 'Disable non-SSL port and set minimumTlsVersion to 1.2',
      }));
    }
  });

  // CIS-AKS: AKS cluster RBAC not enabled
  aksClusters.forEach(aks => {
    const props = aks.properties || aks;
    const rbacEnabled = props.enableRBAC ?? (props.aadProfile && props.aadProfile.enableAzureRBAC);
    if (rbacEnabled === false || rbacEnabled === undefined) {
      f.push(_finding({
        id: 'CIS-AKS', framework: 'CIS_AZURE', severity: 'HIGH',
        title: 'AKS cluster RBAC not enabled',
        message: `AKS cluster "${_rn(aks)}" does not have Kubernetes RBAC enabled`,
        resource: _rn(aks), resourceId: aks.id || '', resourceType: 'Microsoft.ContainerService/managedClusters',
        remediation: 'Enable RBAC on the AKS cluster and integrate with Azure AD',
      }));
    }
  });

  // CIS-DDOS: VNet without DDoS protection plan
  vnets.forEach(vnet => {
    const props = vnet.properties || vnet;
    const ddos = props.enableDdosProtection || props.ddosProtectionPlan;
    if (!ddos) {
      f.push(_finding({
        id: 'CIS-DDOS', framework: 'CIS_AZURE', severity: 'MEDIUM',
        title: 'VNet without DDoS protection plan',
        message: `VNet "${_rn(vnet)}" does not have DDoS Protection Standard enabled`,
        resource: _rn(vnet), resourceId: vnet.id || '', resourceType: 'Microsoft.Network/virtualNetworks',
        remediation: 'Enable Azure DDoS Protection Standard on the VNet',
      }));
    }
  });

  // CIS-BASTION: Bastion not deployed in hub VNet
  const hubVnets = vnets.filter(v => {
    const n = (_rn(v) || '').toLowerCase();
    return n.includes('hub') || n.includes('shared') || n.includes('core') || n.includes('connectivity');
  });
  if (hubVnets.length > 0 && bastionHosts.length === 0) {
    hubVnets.forEach(hub => {
      f.push(_finding({
        id: 'CIS-BASTION', framework: 'CIS_AZURE', severity: 'HIGH',
        title: 'Bastion not deployed in hub VNet',
        message: `Hub VNet "${_rn(hub)}" has no Azure Bastion host deployed — RDP/SSH jump host missing`,
        resource: _rn(hub), resourceId: hub.id || '', resourceType: 'Microsoft.Network/virtualNetworks',
        remediation: 'Deploy Azure Bastion in the hub VNet for secure remote access without public IPs',
      }));
    });
  }

  // CIS-NW: Network Watcher not deployed per region
  if (regions.length > 0) {
    const watcherRegions = new Set(
      networkWatchers.map(nw => (nw.location || '').toLowerCase())
    );
    regions.forEach(region => {
      const r = region.toLowerCase();
      if (!watcherRegions.has(r)) {
        f.push(_finding({
          id: 'CIS-NW', framework: 'CIS_AZURE', severity: 'MEDIUM',
          title: 'Network Watcher not deployed in region',
          message: `Region "${region}" does not have a Network Watcher deployed`,
          resource: region, resourceId: '', resourceType: 'Microsoft.Network/networkWatchers',
          remediation: 'Deploy Network Watcher in each active region for network monitoring and diagnostics',
        }));
      }
    });
  }

  // ── Private Endpoint checks ──
  const privateEndpoints = data.privateEndpoints || data.vpces || [];
  const dnsZones = data.dnsZones || data.zones || [];

  // PE group ID → expected private DNS zone name
  const PE_DNS_MAP = {
    sqlServer: 'privatelink.database.windows.net',
    blob: 'privatelink.blob.core.windows.net',
    table: 'privatelink.table.core.windows.net',
    queue: 'privatelink.queue.core.windows.net',
    file: 'privatelink.file.core.windows.net',
    web: 'privatelink.web.core.windows.net',
    dfs: 'privatelink.dfs.core.windows.net',
    vault: 'privatelink.vaultcore.azure.net',
    redisCache: 'privatelink.redis.cache.windows.net',
    namespace: 'privatelink.servicebus.windows.net',
    cosmosdb: 'privatelink.documents.azure.com',
    registry: 'privatelink.azurecr.io',
    sites: 'privatelink.azurewebsites.net',
    mysqlServer: 'privatelink.mysql.database.azure.com',
    postgresqlServer: 'privatelink.postgres.database.azure.com',
    Sql: 'privatelink.sql.azuresynapse.net',
    Dev: 'privatelink.dev.azuresynapse.net',
    searchService: 'privatelink.search.windows.net',
    account: 'privatelink.cognitiveservices.azure.com',
  };

  // Build set of available private DNS zone names and their VNet links
  const dnsZonesByName = {};
  dnsZones.forEach(z => {
    const props = z.properties || z._azure?.properties || {};
    const name = z.name || z.Name || '';
    if (name) dnsZonesByName[name.toLowerCase()] = { zone: z, links: props.virtualNetworkLinks || [] };
  });

  privateEndpoints.forEach(pe => {
    const props = pe.properties || pe._azure?.properties || {};
    const conn = (props.privateLinkServiceConnections || [])[0];
    const connProps = conn?.properties || {};
    const state = connProps.privateLinkServiceConnectionState?.status || '';
    const groupId = (connProps.groupIds || [])[0] || '';
    const subnetId = props.subnet?.id || '';
    const vnetId = subnetId ? subnetId.split('/subnets/')[0] : '';
    const peName = _rn(pe);

    // PE-PENDING: Connection pending approval
    if (state === 'Pending') {
      f.push(_finding({
        id: 'PE-PENDING', framework: 'CIS_AZURE', severity: 'HIGH',
        title: 'Private Endpoint connection pending approval',
        message: `PE "${peName}" has a pending connection — traffic will not flow until approved`,
        resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
        remediation: 'Approve the private endpoint connection on the target resource or remove the PE if not needed',
      }));
    }

    // PE-ORPHAN: Connection failed or rejected
    if (state === 'Rejected' || state === 'Disconnected' || state === 'Failed') {
      f.push(_finding({
        id: 'PE-ORPHAN', framework: 'CIS_AZURE', severity: 'MEDIUM',
        title: 'Private Endpoint connection ' + state.toLowerCase(),
        message: `PE "${peName}" has a ${state.toLowerCase()} connection — endpoint is orphaned and should be cleaned up`,
        resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
        remediation: 'Remove the orphaned private endpoint or re-create the connection to the target service',
      }));
    }

    // PE-NO-DNS: No matching private DNS zone for this PE's group ID
    if (groupId) {
      const expectedZone = PE_DNS_MAP[groupId];
      if (expectedZone && !dnsZonesByName[expectedZone.toLowerCase()]) {
        f.push(_finding({
          id: 'PE-NO-DNS', framework: 'CIS_AZURE', severity: 'HIGH',
          title: 'No private DNS zone for Private Endpoint',
          message: `PE "${peName}" (${groupId}) requires DNS zone "${expectedZone}" but none exists — DNS resolution will fail`,
          resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
          remediation: 'Create private DNS zone "' + expectedZone + '" and link it to the PE\'s VNet',
        }));
      }

      // PE-DNS-UNLINKED: DNS zone exists but PE's VNet is not linked
      if (expectedZone && vnetId) {
        const zoneInfo = dnsZonesByName[expectedZone.toLowerCase()];
        if (zoneInfo) {
          const linked = zoneInfo.links.some(link => {
            const linkVnet = link.properties?.virtualNetwork?.id || link.id || '';
            return linkVnet.toLowerCase() === vnetId.toLowerCase();
          });
          if (!linked) {
            f.push(_finding({
              id: 'PE-DNS-UNLINKED', framework: 'CIS_AZURE', severity: 'HIGH',
              title: 'Private DNS zone not linked to PE VNet',
              message: `PE "${peName}" is in VNet "${vnetId.split('/').pop()}" but DNS zone "${expectedZone}" is not linked to that VNet — resolution will use public DNS`,
              resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
              remediation: 'Add a virtual network link from "' + expectedZone + '" to VNet "' + vnetId.split('/').pop() + '"',
            }));
          }
        }
      }
    }

    // PE-NSG-POLICY: Subnet has NSG but network policies disabled
    if (subnetId) {
      const subnet = (data.subnets || []).find(s => (s.id || s.SubnetId || '') === subnetId);
      if (subnet) {
        const subProps = subnet.properties || {};
        const hasNsg = !!subProps.networkSecurityGroup;
        const policyDisabled = subProps.privateEndpointNetworkPolicies === 'Disabled' || !subProps.privateEndpointNetworkPolicies;
        if (hasNsg && policyDisabled) {
          f.push(_finding({
            id: 'PE-NSG-POLICY', framework: 'CIS_AZURE', severity: 'MEDIUM',
            title: 'NSG cannot filter Private Endpoint traffic',
            message: `Subnet "${_rn(subnet)}" has an NSG but PE network policies are disabled — NSG rules will not apply to PE "${peName}"`,
            resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
            remediation: 'Enable privateEndpointNetworkPolicies on the subnet to allow NSG filtering of PE traffic',
          }));
        }
      }
    }
  });

  return f;
}

// ============================================================================
// CAF (Cloud Adoption Framework) checks (~15)
// ============================================================================
function runCAFChecks(data) {
  const f = [];
  const vnets = data.vnets || [];
  const subnets = data.subnets || [];
  const nsgs = data.nsgs || [];
  const routeTables = data.routeTables || [];
  const peerings = data.peerings || [];
  const firewalls = data.firewalls || [];
  const privateDnsZones = data.privateDnsZones || [];
  const vms = data.vms || [];
  const publicIps = data.publicIps || [];
  const loadBalancers = data.loadBalancers || [];
  const appGateways = data.appGateways || [];
  const diagnosticSettings = data.diagnosticSettings || [];
  const resourceLocks = data.resourceLocks || [];
  const allResources = data.allResources || [];

  // Build lookup: subnet ID -> NSG ID
  const subnetNsgMap = new Map();
  subnets.forEach(sub => {
    const sp = _subnetProps(sub);
    const nsgRef = sp.networkSecurityGroup;
    if (nsgRef && nsgRef.id) subnetNsgMap.set(sub.id || sub.name, nsgRef.id);
  });

  // Build lookup: subnet ID -> route table ID
  const subnetRtMap = new Map();
  subnets.forEach(sub => {
    const sp = _subnetProps(sub);
    const rtRef = sp.routeTable;
    if (rtRef && rtRef.id) subnetRtMap.set(sub.id || sub.name, rtRef.id);
  });

  // CAF-NSG: Subnet without NSG associated
  subnets.forEach(sub => {
    const subName = sub.name || sid(sub.id) || '';
    // Skip gateway/bastion/firewall subnets that don't need NSGs
    const lowerName = subName.toLowerCase();
    if (lowerName === 'gatewaysubnet' || lowerName === 'azurebastionsubnet' ||
        lowerName === 'azurefirewallsubnet' || lowerName === 'azurefirewallmanagementsubnet' ||
        lowerName === 'routeserversubnet') return;
    const sp = _subnetProps(sub);
    const nsgRef = sp.networkSecurityGroup;
    if (!nsgRef || !nsgRef.id) {
      f.push(_finding({
        id: 'CAF-NSG', framework: 'CAF', severity: 'HIGH',
        title: 'Subnet without NSG',
        message: `Subnet "${subName}" has no Network Security Group associated`,
        resource: subName, resourceId: sub.id || '', resourceType: 'Microsoft.Network/virtualNetworks/subnets',
        remediation: 'Associate an NSG with this subnet to enforce network access controls',
      }));
    }
  });

  // CAF-UDR: Subnet without route table
  subnets.forEach(sub => {
    const subName = sub.name || sid(sub.id) || '';
    const lowerName = subName.toLowerCase();
    if (lowerName === 'gatewaysubnet' || lowerName === 'azurebastionsubnet' ||
        lowerName === 'routeserversubnet') return;
    const sp = _subnetProps(sub);
    const rtRef = sp.routeTable;
    if (!rtRef || !rtRef.id) {
      f.push(_finding({
        id: 'CAF-UDR', framework: 'CAF', severity: 'MEDIUM',
        title: 'Subnet without route table',
        message: `Subnet "${subName}" has no User Defined Route (UDR) table — uses default system routes`,
        resource: subName, resourceId: sub.id || '', resourceType: 'Microsoft.Network/virtualNetworks/subnets',
        remediation: 'Associate a route table for traffic control; route Internet traffic through a firewall',
      }));
    }
  });

  // CAF-EMPTY: VNet without subnets
  vnets.forEach(vnet => {
    const subs = _getVnetSubnets(vnet);
    if (subs.length === 0) {
      f.push(_finding({
        id: 'CAF-EMPTY', framework: 'CAF', severity: 'LOW',
        title: 'VNet without subnets',
        message: `VNet "${_rn(vnet)}" has no subnets configured — unused VNet`,
        resource: _rn(vnet), resourceId: vnet.id || '', resourceType: 'Microsoft.Network/virtualNetworks',
        remediation: 'Add subnets for workload segmentation or remove the unused VNet',
      }));
    }
  });

  // CAF-HUB: No hub-spoke topology detected
  const hasHub = vnets.some(v => {
    const n = (_rn(v) || '').toLowerCase();
    return n.includes('hub') || n.includes('core') || n.includes('connectivity');
  });
  if (vnets.length > 2 && !hasHub && (peerings.length > 0 || vnets.length > 3)) {
    f.push(_finding({
      id: 'CAF-HUB', framework: 'CAF', severity: 'MEDIUM',
      title: 'No hub-spoke topology detected',
      message: `${vnets.length} VNets found but no hub VNet identified — consider hub-spoke architecture`,
      resource: 'Topology', resourceId: '', resourceType: 'Microsoft.Network/virtualNetworks',
      remediation: 'Implement hub-spoke topology with centralized firewall, DNS, and shared services',
    }));
  }

  // CAF-PEER: Peering without forwarded traffic enabled
  peerings.forEach(peer => {
    const props = peer.properties || peer;
    if (props.allowForwardedTraffic === false) {
      f.push(_finding({
        id: 'CAF-PEER', framework: 'CAF', severity: 'MEDIUM',
        title: 'Peering without forwarded traffic',
        message: `Peering "${_rn(peer)}" does not allow forwarded traffic — spoke-to-spoke routing via hub will fail`,
        resource: _rn(peer), resourceId: peer.id || '', resourceType: 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings',
        remediation: 'Enable allowForwardedTraffic on peering to support transitive routing via hub firewall',
      }));
    }
  });

  // CAF-FW: Missing Azure Firewall in hub
  if (hasHub && firewalls.length === 0) {
    f.push(_finding({
      id: 'CAF-FW', framework: 'CAF', severity: 'HIGH',
      title: 'Missing Azure Firewall in hub',
      message: 'Hub VNet detected but no Azure Firewall deployed — no centralized traffic inspection',
      resource: 'Hub VNet', resourceId: '', resourceType: 'Microsoft.Network/azureFirewalls',
      remediation: 'Deploy Azure Firewall (or NVA) in the hub VNet for centralized traffic control',
    }));
  }

  // CAF-DNS: No private DNS zones configured
  if (privateDnsZones.length === 0 && vnets.length > 0) {
    f.push(_finding({
      id: 'CAF-DNS', framework: 'CAF', severity: 'LOW',
      title: 'No private DNS zones configured',
      message: 'No Azure Private DNS zones found — PaaS private endpoints require private DNS for resolution',
      resource: 'DNS', resourceId: '', resourceType: 'Microsoft.Network/privateDnsZones',
      remediation: 'Create private DNS zones for Azure services (e.g., privatelink.blob.core.windows.net)',
    }));
  }

  // CAF-PIP: VMs using public IPs directly
  const vmPublicIps = new Set();
  publicIps.forEach(pip => {
    const props = pip.properties || pip;
    const ipConfig = props.ipConfiguration;
    if (ipConfig && ipConfig.id && ipConfig.id.toLowerCase().includes('/networkinterfaces/')) {
      vmPublicIps.add(sid(ipConfig.id));
    }
  });
  vms.forEach(vm => {
    const props = vm.properties || vm;
    const nics = (props.networkProfile || {}).networkInterfaces || [];
    nics.forEach(nic => {
      const nicName = sid(nic.id);
      if (vmPublicIps.has(nicName)) {
        f.push(_finding({
          id: 'CAF-PIP', framework: 'CAF', severity: 'MEDIUM',
          title: 'VM using public IP directly',
          message: `VM "${_rn(vm)}" has a public IP assigned — use Azure Bastion or Load Balancer instead`,
          resource: _rn(vm), resourceId: vm.id || '', resourceType: 'Microsoft.Compute/virtualMachines',
          remediation: 'Remove public IP; access VMs via Azure Bastion, VPN, or Load Balancer',
        }));
      }
    });
  });

  // CAF-PROBE: Load balancer without health probes
  loadBalancers.forEach(lb => {
    const props = lb.properties || lb;
    const probes = props.probes || [];
    const rules = props.loadBalancingRules || [];
    if (rules.length > 0 && probes.length === 0) {
      f.push(_finding({
        id: 'CAF-PROBE', framework: 'CAF', severity: 'HIGH',
        title: 'Load balancer without health probes',
        message: `Load balancer "${_rn(lb)}" has rules but no health probes configured`,
        resource: _rn(lb), resourceId: lb.id || '', resourceType: 'Microsoft.Network/loadBalancers',
        remediation: 'Add health probes to detect unhealthy backends and prevent routing traffic to failed instances',
      }));
    }
  });

  // CAF-AGSCALE: App Gateway without autoscaling
  appGateways.forEach(ag => {
    const props = ag.properties || ag;
    const autoscale = props.autoscaleConfiguration;
    if (!autoscale) {
      f.push(_finding({
        id: 'CAF-AGSCALE', framework: 'CAF', severity: 'LOW',
        title: 'Application Gateway without autoscaling',
        message: `Application Gateway "${_rn(ag)}" does not have autoscaling configured`,
        resource: _rn(ag), resourceId: ag.id || '', resourceType: 'Microsoft.Network/applicationGateways',
        remediation: 'Enable autoscaling on Application Gateway v2 for dynamic capacity management',
      }));
    }
  });

  // CAF-DIAG: No diagnostic settings on NSGs
  const nsgIds = new Set(nsgs.map(n => (n.id || '').toLowerCase()));
  const diagResourceIds = new Set(
    diagnosticSettings.map(d => ((d.properties || d).resourceId || d.resourceId || '').toLowerCase())
  );
  nsgs.forEach(nsg => {
    const nsgId = (nsg.id || '').toLowerCase();
    if (nsgId && !diagResourceIds.has(nsgId)) {
      f.push(_finding({
        id: 'CAF-DIAG', framework: 'CAF', severity: 'MEDIUM',
        title: 'NSG without diagnostic settings',
        message: `NSG "${_rn(nsg)}" has no diagnostic settings — flow logs and events not captured`,
        resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
        remediation: 'Enable diagnostic settings to send NSG flow logs to Log Analytics or Storage',
      }));
    }
  });

  // CAF-LOCK: Missing resource locks on production resources
  if (resourceLocks.length === 0 && allResources.length > 10) {
    f.push(_finding({
      id: 'CAF-LOCK', framework: 'CAF', severity: 'MEDIUM',
      title: 'No resource locks detected',
      message: 'No resource locks found — production resources can be accidentally deleted',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/locks',
      remediation: 'Apply CanNotDelete locks on critical resources (VNets, firewalls, databases)',
    }));
  }

  // CAF-TAG: Missing tags on resources
  const untagged = [];
  [...vnets, ...vms, ...(data.storageAccounts || []), ...nsgs].forEach(r => {
    if (!_hasTags(r) && r.id) untagged.push(_rn(r));
  });
  if (untagged.length > 0) {
    f.push(_finding({
      id: 'CAF-TAG', framework: 'CAF', severity: 'LOW',
      title: 'Resources without tags',
      message: `${untagged.length} resource(s) missing tags — cost tracking and ownership unclear`,
      resource: 'Multiple', resourceId: '', resourceType: 'Various',
      remediation: 'Apply tagging policy (Environment, Owner, CostCenter, Application)',
    }));
  }

  // CAF-NAME: Missing naming convention compliance
  const badNames = [];
  [...vnets, ...nsgs].forEach(r => {
    const name = _rn(r) || '';
    if (name && !/^[a-z]/.test(name) && name.length > 0) {
      badNames.push(name);
    }
  });
  if (badNames.length > 3) {
    f.push(_finding({
      id: 'CAF-NAME', framework: 'CAF', severity: 'LOW',
      title: 'Naming convention non-compliance',
      message: `${badNames.length} resources do not follow lowercase naming convention`,
      resource: 'Multiple', resourceId: '', resourceType: 'Various',
      remediation: 'Adopt CAF naming convention: {resource-type}-{workload}-{environment}-{region}-{instance}',
    }));
  }

  // CAF-CIDR: VNet address space too large
  vnets.forEach(vnet => {
    const props = vnet.properties || vnet;
    const addrSpaces = props.addressSpace?.addressPrefixes || [];
    addrSpaces.forEach(cidr => {
      const mask = parseInt((cidr || '').split('/')[1], 10);
      if (mask && mask < 16) {
        f.push(_finding({
          id: 'CAF-CIDR', framework: 'CAF', severity: 'LOW',
          title: 'VNet address space too large',
          message: `VNet "${_rn(vnet)}" uses ${cidr} (/${mask}) — larger than /16 wastes IP space`,
          resource: _rn(vnet), resourceId: vnet.id || '', resourceType: 'Microsoft.Network/virtualNetworks',
          remediation: 'Use /16 or smaller address spaces; plan CIDR allocation to avoid overlap',
        }));
      }
    });
  });

  return f;
}


// ============================================================================
// RBAC checks (~8)
// ============================================================================
function runRBACChecks(data) {
  const f = [];
  const roleAssignments = data.roleAssignments || [];
  const roleDefinitions = data.roleDefinitions || [];
  const servicePrincipals = data.servicePrincipals || [];

  // Build role definition lookup by ID
  const roleDefMap = new Map();
  roleDefinitions.forEach(rd => {
    const props = rd.properties || rd;
    const roleId = rd.id || rd.name || '';
    roleDefMap.set(roleId, props);
    if (props.roleName) roleDefMap.set(props.roleName, props);
  });

  // Track subscription-level owners
  let subscriptionOwnerCount = 0;
  const orphanedAssignments = [];
  const guestPrivileged = [];

  roleAssignments.forEach(ra => {
    const props = ra.properties || ra;
    const roleDef = props.roleDefinitionId || '';
    const scope = props.scope || '';
    const principalId = props.principalId || '';
    const principalType = (props.principalType || '').toLowerCase();

    // Resolve role name
    const rd = roleDefMap.get(roleDef) || roleDefMap.get(sid(roleDef)) || {};
    const roleName = rd.roleName || sid(roleDef) || '';

    // RBAC-OWNER: Owner role assigned at subscription scope
    if (roleName === 'Owner' && scope && !scope.includes('/resourceGroups/')) {
      subscriptionOwnerCount++;
      f.push(_finding({
        id: 'RBAC-OWNER', framework: 'RBAC', severity: 'HIGH',
        title: 'Owner role at subscription scope',
        message: `Principal "${principalId}" has Owner role at subscription scope`,
        resource: principalId, resourceId: ra.id || '', resourceType: 'Microsoft.Authorization/roleAssignments',
        remediation: 'Limit Owner assignments to resource groups; use Contributor where possible',
      }));
    }

    // RBAC-SP-OWNER: Service principal with Owner role
    if (roleName === 'Owner' && principalType === 'serviceprincipal') {
      f.push(_finding({
        id: 'RBAC-SP-OWNER', framework: 'RBAC', severity: 'HIGH',
        title: 'Service principal with Owner role',
        message: `Service principal "${principalId}" has Owner role — excessive for automation`,
        resource: principalId, resourceId: ra.id || '', resourceType: 'Microsoft.Authorization/roleAssignments',
        remediation: 'Assign Contributor or custom role with least-privilege permissions',
      }));
    }

    // RBAC-ORPHAN: Track for orphaned detection (principalType unknown/deleted)
    if (principalType === '' || principalType === 'unknown') {
      orphanedAssignments.push(ra);
    }

    // RBAC-GUEST: Guest users with privileged roles
    if (principalType === 'guest' || principalType === 'guestuser') {
      const privilegedRoles = ['Owner', 'Contributor', 'User Access Administrator'];
      if (privilegedRoles.includes(roleName)) {
        guestPrivileged.push({ principalId, roleName });
      }
    }

    // RBAC-NOCOND: Role assignment without condition (for privileged roles)
    const condition = props.condition || '';
    const privileged = ['Owner', 'User Access Administrator', 'Role Based Access Control Administrator'];
    if (privileged.includes(roleName) && !condition) {
      f.push(_finding({
        id: 'RBAC-NOCOND', framework: 'RBAC', severity: 'MEDIUM',
        title: 'Privileged role without condition',
        message: `"${roleName}" assigned to "${principalId}" without ABAC condition constraints`,
        resource: principalId, resourceId: ra.id || '', resourceType: 'Microsoft.Authorization/roleAssignments',
        remediation: 'Add conditions to limit scope of privileged role assignments (ABAC)',
      }));
    }
  });

  // RBAC-CUSTOM-STAR: Custom role with * actions
  roleDefinitions.forEach(rd => {
    const props = rd.properties || rd;
    if (props.roleType !== 'CustomRole' && props.type !== 'CustomRole') return;
    const perms = props.permissions || [];
    perms.forEach(perm => {
      const actions = perm.actions || [];
      if (actions.includes('*')) {
        f.push(_finding({
          id: 'RBAC-CUSTOM-STAR', framework: 'RBAC', severity: 'CRITICAL',
          title: 'Custom role with wildcard actions',
          message: `Custom role "${props.roleName || _rn(rd)}" has "*" in actions — equivalent to Owner`,
          resource: props.roleName || _rn(rd), resourceId: rd.id || '', resourceType: 'Microsoft.Authorization/roleDefinitions',
          remediation: 'Scope custom role actions to specific resource providers and operations',
        }));
      }
    });
  });

  // RBAC-ORPHAN: Orphaned role assignments (deleted principals)
  if (orphanedAssignments.length > 0) {
    f.push(_finding({
      id: 'RBAC-ORPHAN', framework: 'RBAC', severity: 'MEDIUM',
      title: 'Orphaned role assignments',
      message: `${orphanedAssignments.length} role assignment(s) reference deleted or unknown principals`,
      resource: 'Multiple', resourceId: '', resourceType: 'Microsoft.Authorization/roleAssignments',
      remediation: 'Remove role assignments for deleted principals to maintain clean RBAC state',
    }));
  }

  // RBAC-OWNERS: Too many subscription-level owners (>3)
  if (subscriptionOwnerCount > 3) {
    f.push(_finding({
      id: 'RBAC-OWNERS', framework: 'RBAC', severity: 'HIGH',
      title: 'Too many subscription owners',
      message: `${subscriptionOwnerCount} principals have Owner role at subscription scope (max recommended: 3)`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/roleAssignments',
      remediation: 'Reduce subscription-level Owner assignments to 3 or fewer; use PIM for just-in-time access',
    }));
  }

  // RBAC-GUEST: Guest users with privileged roles
  guestPrivileged.forEach(g => {
    f.push(_finding({
      id: 'RBAC-GUEST', framework: 'RBAC', severity: 'HIGH',
      title: 'Guest user with privileged role',
      message: `Guest user "${g.principalId}" has "${g.roleName}" role`,
      resource: g.principalId, resourceId: '', resourceType: 'Microsoft.Authorization/roleAssignments',
      remediation: 'Review guest access; remove privileged roles from external users',
    }));
  });

  // RBAC-CLASSIC: Classic administrators still present
  const classicAdmins = data.classicAdmins || [];
  if (classicAdmins.length > 0) {
    f.push(_finding({
      id: 'RBAC-CLASSIC', framework: 'RBAC', severity: 'MEDIUM',
      title: 'Classic administrators present',
      message: `${classicAdmins.length} classic administrator(s) found — legacy access model`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/classicAdministrators',
      remediation: 'Migrate classic administrators to Azure RBAC role assignments',
    }));
  }

  return f;
}

// ============================================================================
// SOC2 checks (~6)
// ============================================================================
function runSOC2Checks(data) {
  const f = [];
  const storageAccts = data.storageAccounts || [];
  const managedDisks = data.managedDisks || [];
  const nsgs = data.nsgs || [];
  const monitorConfig = data.monitorConfig || {};
  const keyVaults = data.keyVaults || [];
  const diagnosticSettings = data.diagnosticSettings || [];

  // SOC2-TLS: TLS 1.2 minimum on storage accounts
  storageAccts.forEach(sa => {
    const props = sa.properties || sa;
    const minTls = props.minimumTlsVersion || '';
    if (!minTls || (minTls !== 'TLS1_2' && minTls !== 'TLS1_3')) {
      f.push(_finding({
        id: 'SOC2-TLS', framework: 'SOC2', severity: 'HIGH',
        title: 'Storage account TLS < 1.2',
        message: `Storage account "${_rn(sa)}" does not enforce TLS 1.2 minimum — data in transit at risk`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Set minimumTlsVersion to TLS1_2 on all storage accounts',
      }));
    }
  });

  // SOC2-DISK: Encryption at rest for managed disks
  managedDisks.forEach(disk => {
    const props = disk.properties || disk;
    const encryption = props.encryption || {};
    const encType = encryption.type || props.encryptionSettingsCollection?.enabled;
    if (!encType && !props.encryptionSettingsCollection) {
      f.push(_finding({
        id: 'SOC2-DISK', framework: 'SOC2', severity: 'HIGH',
        title: 'Managed disk without encryption',
        message: `Managed disk "${_rn(disk)}" may not have encryption at rest configured`,
        resource: _rn(disk), resourceId: disk.id || '', resourceType: 'Microsoft.Compute/disks',
        remediation: 'Enable server-side encryption with platform-managed or customer-managed keys',
      }));
    }
  });

  // SOC2-FLOWLOG: NSG flow logs not enabled
  const nsgFlowLogs = data.nsgFlowLogs || [];
  const nsgWithFlowLog = new Set(
    nsgFlowLogs.map(fl => {
      const props = fl.properties || fl;
      return (props.targetResourceId || '').toLowerCase();
    })
  );
  nsgs.forEach(nsg => {
    const nsgId = (nsg.id || '').toLowerCase();
    if (nsgId && !nsgWithFlowLog.has(nsgId)) {
      f.push(_finding({
        id: 'SOC2-FLOWLOG', framework: 'SOC2', severity: 'HIGH',
        title: 'NSG flow logs not enabled',
        message: `NSG "${_rn(nsg)}" does not have flow logs enabled — insufficient audit trail`,
        resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
        remediation: 'Enable NSG flow logs (v2) and send to Log Analytics for retention and analysis',
      }));
    }
  });

  // SOC2-MONITOR: No Azure Monitor configured
  const logAnalytics = data.logAnalyticsWorkspaces || [];
  if (logAnalytics.length === 0 && diagnosticSettings.length === 0) {
    f.push(_finding({
      id: 'SOC2-MONITOR', framework: 'SOC2', severity: 'HIGH',
      title: 'No Azure Monitor / Log Analytics configured',
      message: 'No Log Analytics workspaces or diagnostic settings found — insufficient monitoring',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.OperationalInsights/workspaces',
      remediation: 'Deploy Log Analytics workspace and enable diagnostic settings on all resources',
    }));
  }

  // SOC2-KV-RBAC: Key Vault not using RBAC
  keyVaults.forEach(kv => {
    const props = kv.properties || kv;
    const rbac = props.enableRbacAuthorization;
    if (rbac !== true) {
      f.push(_finding({
        id: 'SOC2-KV-RBAC', framework: 'SOC2', severity: 'MEDIUM',
        title: 'Key Vault not using RBAC authorization',
        message: `Key Vault "${_rn(kv)}" uses access policies instead of RBAC — less auditable`,
        resource: _rn(kv), resourceId: kv.id || '', resourceType: 'Microsoft.KeyVault/vaults',
        remediation: 'Enable RBAC authorization mode for centralized access management and audit logging',
      }));
    }
  });

  // SOC2-SA-ENC: Storage account without infrastructure encryption
  storageAccts.forEach(sa => {
    const props = sa.properties || sa;
    const enc = props.encryption || {};
    if (!enc.requireInfrastructureEncryption && !enc.services) {
      f.push(_finding({
        id: 'SOC2-SA-ENC', framework: 'SOC2', severity: 'MEDIUM',
        title: 'Storage account without explicit encryption settings',
        message: `Storage account "${_rn(sa)}" has no explicit encryption configuration`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Enable infrastructure encryption and customer-managed keys for enhanced protection',
      }));
    }
  });

  return f;
}

// ============================================================================
// PCI DSS 4.0 checks (~8)
// ============================================================================
function runPCIChecks(data) {
  const f = [];
  const nsgs = data.nsgs || [];
  const sqlServers = data.sqlServers || [];
  const sqlDatabases = data.sqlDatabases || [];
  const managedDisks = data.managedDisks || [];
  const appGateways = data.appGateways || [];
  const storageAccounts = data.storageAccounts || [];
  const securityCenter = data.securityCenter || {};
  const nsgFlowLogs = data.nsgFlowLogs || [];
  const logAnalytics = data.logAnalyticsWorkspaces || [];

  // PCI-SEG: Network segmentation (PCI subnet isolated)
  const subnets = data.subnets || [];
  const pciSubnets = subnets.filter(s => {
    const name = (s.name || '').toLowerCase();
    return name.includes('pci') || name.includes('payment') || name.includes('cardholder');
  });
  pciSubnets.forEach(sub => {
    const sp = _subnetProps(sub);
    const nsgRef = sp.networkSecurityGroup;
    if (!nsgRef || !nsgRef.id) {
      f.push(_finding({
        id: 'PCI-SEG', framework: 'PCI', severity: 'CRITICAL',
        title: 'PCI subnet without NSG',
        message: `PCI-scoped subnet "${sub.name || sid(sub.id)}" has no NSG — network segmentation violation`,
        resource: sub.name || sid(sub.id), resourceId: sub.id || '', resourceType: 'Microsoft.Network/virtualNetworks/subnets',
        remediation: 'Apply strict NSG rules isolating cardholder data environment from other subnets',
      }));
    }
  });

  // PCI-SQL: SQL databases publicly accessible
  sqlServers.forEach(srv => {
    const props = srv.properties || srv;
    const pubAccess = props.publicNetworkAccess || '';
    if (pubAccess.toLowerCase() === 'enabled') {
      f.push(_finding({
        id: 'PCI-SQL', framework: 'PCI', severity: 'CRITICAL',
        title: 'SQL server publicly accessible',
        message: `SQL server "${_rn(srv)}" has public network access enabled — CDE exposure`,
        resource: _rn(srv), resourceId: srv.id || '', resourceType: 'Microsoft.Sql/servers',
        remediation: 'Disable public access; use private endpoints for database connectivity',
      }));
    }
  });

  // PCI-ENCRYPT: Unencrypted data at rest
  managedDisks.forEach(disk => {
    const props = disk.properties || disk;
    const enc = props.encryption || {};
    if (enc.type === 'EncryptionAtRestWithPlatformKey' || !enc.type) {
      // Platform-managed keys are minimum — but CMK is preferred for PCI
      if (!enc.diskEncryptionSetId) {
        f.push(_finding({
          id: 'PCI-ENCRYPT', framework: 'PCI', severity: 'HIGH',
          title: 'Disk without customer-managed encryption',
          message: `Managed disk "${_rn(disk)}" uses platform-managed keys — CMK required for PCI`,
          resource: _rn(disk), resourceId: disk.id || '', resourceType: 'Microsoft.Compute/disks',
          remediation: 'Enable encryption with customer-managed keys via Disk Encryption Set',
        }));
      }
    }
  });

  // PCI-WAF: App Gateway without WAF SKU
  appGateways.forEach(ag => {
    const props = ag.properties || ag;
    const sku = props.sku || {};
    const tier = (sku.tier || sku.name || '').toLowerCase();
    if (!tier.includes('waf')) {
      f.push(_finding({
        id: 'PCI-WAF', framework: 'PCI', severity: 'HIGH',
        title: 'Application Gateway without WAF',
        message: `Application Gateway "${_rn(ag)}" uses "${sku.tier || sku.name || 'Standard'}" tier — WAF required for PCI`,
        resource: _rn(ag), resourceId: ag.id || '', resourceType: 'Microsoft.Network/applicationGateways',
        remediation: 'Upgrade to WAF_v2 SKU and enable OWASP rule sets for web application protection',
        checkovId: 'CKV_AZURE_120',
      }));
    }
  });

  // PCI-IDS: Missing intrusion detection (no Azure Defender / Microsoft Defender)
  const defenderPlans = data.defenderPlans || [];
  if (defenderPlans.length === 0) {
    f.push(_finding({
      id: 'PCI-IDS', framework: 'PCI', severity: 'HIGH',
      title: 'No Microsoft Defender plans enabled',
      message: 'No Microsoft Defender for Cloud plans found — intrusion detection requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Security/pricings',
      remediation: 'Enable Microsoft Defender for Cloud on all resource types (servers, SQL, storage, etc.)',
    }));
  }

  // PCI-STORAGE: Cardholder data in unencrypted storage
  storageAccounts.forEach(sa => {
    const props = sa.properties || sa;
    const enc = props.encryption || {};
    if (!enc.keySource && !enc.services) {
      f.push(_finding({
        id: 'PCI-STORAGE', framework: 'PCI', severity: 'CRITICAL',
        title: 'Storage account without encryption configuration',
        message: `Storage account "${_rn(sa)}" has no explicit encryption — data at rest violation`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Enable encryption with customer-managed keys for cardholder data storage',
      }));
    }
  });

  // PCI-REVIEW: Missing access reviews (no PIM or access reviews configured)
  const accessReviews = data.accessReviews || [];
  if (accessReviews.length === 0) {
    f.push(_finding({
      id: 'PCI-REVIEW', framework: 'PCI', severity: 'MEDIUM',
      title: 'No access reviews configured',
      message: 'No Azure AD access reviews found — periodic access review required for PCI',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/accessReviewScheduleDefinitions',
      remediation: 'Configure quarterly access reviews for privileged roles via Azure AD PIM',
    }));
  }

  // PCI-LOG: Insufficient logging
  if (logAnalytics.length === 0 && nsgFlowLogs.length === 0) {
    f.push(_finding({
      id: 'PCI-LOG', framework: 'PCI', severity: 'HIGH',
      title: 'Insufficient logging for PCI compliance',
      message: 'No Log Analytics workspace or NSG flow logs — audit trail requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.OperationalInsights/workspaces',
      remediation: 'Deploy Log Analytics and enable diagnostic settings with 1-year retention',
    }));
  }

  return f;
}

// ============================================================================
// BUDR (Backup, Uptime, Disaster Recovery) checks (~10)
// ============================================================================
function runBUDRAzureChecks(data) {
  const f = [];
  const vms = data.vms || [];
  const sqlServers = data.sqlServers || [];
  const sqlDatabases = data.sqlDatabases || [];
  const recoveryVaults = data.recoveryVaults || [];
  const vnets = data.vnets || [];
  const availabilitySets = data.availabilitySets || [];
  const managedDisks = data.managedDisks || [];
  const storageAccounts = data.storageAccounts || [];
  const aksClusters = data.aksClusters || [];
  const functionApps = data.functionApps || [];
  const redisCaches = data.redisCaches || [];
  const backupPolicies = data.backupPolicies || [];
  const backupItems = data.backupItems || [];

  // Build set of protected VM IDs
  const protectedVmIds = new Set();
  backupItems.forEach(bi => {
    const props = bi.properties || bi;
    const sourceId = (props.sourceResourceId || props.virtualMachineId || '').toLowerCase();
    if (sourceId) protectedVmIds.add(sourceId);
  });

  // BUDR-VM-BAK: VM without backup policy
  vms.forEach(vm => {
    const vmId = (vm.id || '').toLowerCase();
    if (!protectedVmIds.has(vmId)) {
      f.push(_finding({
        id: 'BUDR-VM-BAK', framework: 'BUDR', severity: 'HIGH',
        title: 'VM without backup policy',
        message: `VM "${_rn(vm)}" is not protected by Azure Backup`,
        resource: _rn(vm), resourceId: vm.id || '', resourceType: 'Microsoft.Compute/virtualMachines',
        remediation: 'Enable Azure Backup for the VM via Recovery Services Vault',
      }));
    }
  });

  // BUDR-SQL-RET: SQL without long-term retention
  sqlDatabases.forEach(db => {
    const props = db.properties || db;
    const ltr = props.longTermRetentionPolicy || props.longTermRetention;
    const hasLtr = ltr && (ltr.weeklyRetention || ltr.monthlyRetention || ltr.yearlyRetention);
    if (!hasLtr) {
      f.push(_finding({
        id: 'BUDR-SQL-RET', framework: 'BUDR', severity: 'MEDIUM',
        title: 'SQL database without long-term retention',
        message: `SQL database "${_rn(db)}" has no long-term backup retention configured`,
        resource: _rn(db), resourceId: db.id || '', resourceType: 'Microsoft.Sql/servers/databases',
        remediation: 'Configure long-term retention (LTR) policy for weekly/monthly/yearly backups',
      }));
    }
  });

  // BUDR-RSV: No Recovery Services Vault
  if (recoveryVaults.length === 0 && vms.length > 0) {
    f.push(_finding({
      id: 'BUDR-RSV', framework: 'BUDR', severity: 'HIGH',
      title: 'No Recovery Services Vault',
      message: `${vms.length} VM(s) found but no Recovery Services Vault — no centralized backup infrastructure`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.RecoveryServices/vaults',
      remediation: 'Create a Recovery Services Vault and configure backup policies for all VMs',
    }));
  }

  // BUDR-REGION: Single-region deployment (no DR)
  const deployedRegions = new Set();
  [...vms, ...vnets, ...sqlServers].forEach(r => {
    if (r.location) deployedRegions.add(r.location.toLowerCase());
  });
  if (deployedRegions.size === 1 && vms.length > 3) {
    const region = [...deployedRegions][0];
    f.push(_finding({
      id: 'BUDR-REGION', framework: 'BUDR', severity: 'HIGH',
      title: 'Single-region deployment',
      message: `All resources deployed in "${region}" — no geographic disaster recovery capability`,
      resource: region, resourceId: '', resourceType: 'Various',
      remediation: 'Implement cross-region DR strategy using Azure Site Recovery or geo-replication',
    }));
  }

  // BUDR-AVAIL: Missing availability set/zone
  vms.forEach(vm => {
    const props = vm.properties || vm;
    const hasAvailSet = props.availabilitySet && props.availabilitySet.id;
    const hasZone = (vm.zones || []).length > 0;
    if (!hasAvailSet && !hasZone) {
      f.push(_finding({
        id: 'BUDR-AVAIL', framework: 'BUDR', severity: 'MEDIUM',
        title: 'VM without availability set or zone',
        message: `VM "${_rn(vm)}" has no availability set or availability zone — single point of failure`,
        resource: _rn(vm), resourceId: vm.id || '', resourceType: 'Microsoft.Compute/virtualMachines',
        remediation: 'Deploy VMs in availability zones or availability sets for HA',
      }));
    }
  });

  // BUDR-SNAP: No snapshot policy for disks
  const snapshots = data.snapshots || [];
  const disksWithSnap = new Set(
    snapshots.map(s => {
      const props = s.properties || s;
      return (props.creationData?.sourceResourceId || '').toLowerCase();
    }).filter(Boolean)
  );
  managedDisks.forEach(disk => {
    const diskId = (disk.id || '').toLowerCase();
    const props = disk.properties || disk;
    if (props.diskState === 'Attached' && !disksWithSnap.has(diskId)) {
      f.push(_finding({
        id: 'BUDR-SNAP', framework: 'BUDR', severity: 'MEDIUM',
        title: 'Managed disk without snapshots',
        message: `Attached disk "${_rn(disk)}" has no snapshots — point-in-time recovery unavailable`,
        resource: _rn(disk), resourceId: disk.id || '', resourceType: 'Microsoft.Compute/disks',
        remediation: 'Create a snapshot policy or use Azure Backup for automatic disk snapshots',
      }));
    }
  });

  // BUDR-GEO: Storage account without geo-redundancy
  storageAccounts.forEach(sa => {
    const props = sa.properties || sa;
    const sku = sa.sku || {};
    const replication = (sku.name || sku.tier || '').toUpperCase();
    if (replication.includes('LRS') || replication.includes('ZRS')) {
      f.push(_finding({
        id: 'BUDR-GEO', framework: 'BUDR', severity: 'MEDIUM',
        title: 'Storage account without geo-redundancy',
        message: `Storage account "${_rn(sa)}" uses ${replication} — no geographic redundancy`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Use GRS or RA-GRS replication for critical data; GZRS for zone + geo redundancy',
      }));
    }
  });

  // BUDR-AKS-PDB: AKS without pod disruption budget indication
  aksClusters.forEach(aks => {
    const props = aks.properties || aks;
    const agentPools = props.agentPoolProfiles || [];
    const singleNode = agentPools.every(ap => (ap.count || 1) <= 1);
    if (singleNode) {
      f.push(_finding({
        id: 'BUDR-AKS-PDB', framework: 'BUDR', severity: 'MEDIUM',
        title: 'AKS cluster with single-node pools',
        message: `AKS cluster "${_rn(aks)}" has single-node agent pools — no pod disruption budget effective`,
        resource: _rn(aks), resourceId: aks.id || '', resourceType: 'Microsoft.ContainerService/managedClusters',
        remediation: 'Scale agent pools to 2+ nodes and configure PodDisruptionBudgets for workloads',
      }));
    }
  });

  // BUDR-FUNC: Function app without deployment slots
  functionApps.forEach(fa => {
    const props = fa.properties || fa;
    const slots = props.siteConfig?.numberOfWorkers || 0;
    const slotNames = data.deploymentSlots || [];
    const faSlots = slotNames.filter(s => {
      const sId = (s.id || '').toLowerCase();
      const faId = (fa.id || '').toLowerCase();
      return sId.includes(faId);
    });
    if (faSlots.length === 0) {
      f.push(_finding({
        id: 'BUDR-FUNC', framework: 'BUDR', severity: 'LOW',
        title: 'Function app without deployment slots',
        message: `Function app "${_rn(fa)}" has no deployment slots — no zero-downtime deployment`,
        resource: _rn(fa), resourceId: fa.id || '', resourceType: 'Microsoft.Web/sites',
        remediation: 'Create staging deployment slot for blue-green deployments and rollback capability',
      }));
    }
  });

  // BUDR-REDIS: Redis without data persistence
  redisCaches.forEach(rc => {
    const props = rc.properties || rc;
    const sku = rc.sku || props.sku || {};
    const tier = (sku.name || sku.family || '').toLowerCase();
    const rdbEnabled = props.redisConfiguration?.['rdb-backup-enabled'] === 'true';
    const aofEnabled = props.redisConfiguration?.['aof-backup-enabled'] === 'true';
    // Basic/Standard tiers do not support persistence
    if (tier.includes('premium') && !rdbEnabled && !aofEnabled) {
      f.push(_finding({
        id: 'BUDR-REDIS', framework: 'BUDR', severity: 'MEDIUM',
        title: 'Redis cache without data persistence',
        message: `Premium Redis cache "${_rn(rc)}" has no RDB or AOF persistence — data loss on restart`,
        resource: _rn(rc), resourceId: rc.id || '', resourceType: 'Microsoft.Cache/Redis',
        remediation: 'Enable RDB snapshots or AOF persistence for durable caching',
      }));
    }
  });

  return f;
}

// ============================================================================
// FedRAMP / NIST 800-171 / CMMC checks (government clouds only)
// ============================================================================
function runFedRAMPChecks(data, framework) {
  const f = [];
  const roleAssignments = data.roleAssignments || [];
  const logAnalytics = data.logAnalyticsWorkspaces || [];
  const nsgs = data.nsgs || [];
  const nsgFlowLogs = data.nsgFlowLogs || [];
  const storageAccounts = data.storageAccounts || [];
  const keyVaults = data.keyVaults || [];
  const vms = data.vms || [];
  const mfaConfig = data.mfaConfig || {};
  const conditionalAccessPolicies = data.conditionalAccessPolicies || [];
  const managedDisks = data.managedDisks || [];
  const firewalls = data.firewalls || [];
  const defenderPlans = data.defenderPlans || [];

  // AC-2: Account management controls
  const roleCount = roleAssignments.length;
  if (roleCount > 100) {
    f.push(_finding({
      id: 'FEDRAMP-AC2', framework, severity: 'MEDIUM',
      title: 'AC-2: Large number of role assignments',
      message: `${roleCount} role assignments found — review for inactive or excessive access`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/roleAssignments',
      remediation: 'Conduct quarterly access reviews; remove stale assignments; use PIM for JIT access',
    }));
  }

  // AC-6: Least privilege
  const ownerAssignments = roleAssignments.filter(ra => {
    const props = ra.properties || ra;
    const roleId = (props.roleDefinitionId || '').toLowerCase();
    return roleId.includes('owner') || roleId.endsWith('/8e3af657-a8ff-443c-a75c-2fe8c4bcb635');
  });
  if (ownerAssignments.length > 5) {
    f.push(_finding({
      id: 'FEDRAMP-AC6', framework, severity: 'HIGH',
      title: 'AC-6: Excessive Owner role assignments',
      message: `${ownerAssignments.length} Owner role assignments — violates least privilege principle`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/roleAssignments',
      remediation: 'Reduce Owner assignments; use Contributor or custom roles with scoped permissions',
    }));
  }

  // AU-2: Audit events — verify logging infrastructure
  if (logAnalytics.length === 0) {
    f.push(_finding({
      id: 'FEDRAMP-AU2', framework, severity: 'CRITICAL',
      title: 'AU-2: No audit logging infrastructure',
      message: 'No Log Analytics workspace found — audit event collection requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.OperationalInsights/workspaces',
      remediation: 'Deploy Log Analytics workspace; enable Azure Activity Log and resource diagnostic settings',
    }));
  }

  // CM-7: Least functionality — check for overly permissive NSG rules
  let openRuleCount = 0;
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction === 'Inbound' && rp.access === 'Allow' &&
          _isAllProtocols(rule) && _isAllPorts(rule) && _hasOpenSourcePrefixes(rule)) {
        openRuleCount++;
      }
    });
  });
  if (openRuleCount > 0) {
    f.push(_finding({
      id: 'FEDRAMP-CM7', framework, severity: 'HIGH',
      title: 'CM-7: Overly permissive network rules',
      message: `${openRuleCount} NSG rule(s) allow all inbound traffic — least functionality violated`,
      resource: 'NSGs', resourceId: '', resourceType: 'Microsoft.Network/networkSecurityGroups',
      remediation: 'Remove or restrict all "allow any" inbound rules to specific required ports and sources',
    }));
  }

  // IA-2: Multi-factor authentication
  const hasMfaPolicy = conditionalAccessPolicies.some(p => {
    const props = p.properties || p;
    const gc = props.grantControls || {};
    return (gc.builtInControls || []).includes('mfa');
  });
  if (!hasMfaPolicy && conditionalAccessPolicies.length > 0) {
    f.push(_finding({
      id: 'FEDRAMP-IA2', framework, severity: 'CRITICAL',
      title: 'IA-2: No MFA conditional access policy',
      message: 'No conditional access policy enforcing MFA found — identification/authentication gap',
      resource: 'Azure AD', resourceId: '', resourceType: 'Microsoft.Authorization/conditionalAccessPolicies',
      remediation: 'Create conditional access policy requiring MFA for all users on sensitive operations',
    }));
  }

  // SC-7: Boundary protection — firewall presence
  if (firewalls.length === 0 && nsgs.length > 0) {
    f.push(_finding({
      id: 'FEDRAMP-SC7', framework, severity: 'HIGH',
      title: 'SC-7: No centralized boundary protection',
      message: 'No Azure Firewall deployed — boundary protection relies only on NSGs',
      resource: 'Network', resourceId: '', resourceType: 'Microsoft.Network/azureFirewalls',
      remediation: 'Deploy Azure Firewall for centralized boundary protection and traffic inspection',
    }));
  }

  // SC-28: Protection of data at rest
  const unencryptedDisks = managedDisks.filter(d => {
    const props = d.properties || d;
    const enc = props.encryption || {};
    return !enc.type && !enc.diskEncryptionSetId;
  });
  if (unencryptedDisks.length > 0) {
    f.push(_finding({
      id: 'FEDRAMP-SC28', framework, severity: 'HIGH',
      title: 'SC-28: Unprotected data at rest',
      message: `${unencryptedDisks.length} managed disk(s) without explicit encryption — data at rest protection gap`,
      resource: 'Multiple', resourceId: '', resourceType: 'Microsoft.Compute/disks',
      remediation: 'Enable encryption with customer-managed keys for all managed disks',
    }));
  }

  // SI-4: Information system monitoring
  if (defenderPlans.length === 0) {
    f.push(_finding({
      id: 'FEDRAMP-SI4', framework, severity: 'HIGH',
      title: 'SI-4: No system monitoring',
      message: 'No Microsoft Defender for Cloud plans enabled — continuous monitoring requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Security/pricings',
      remediation: 'Enable Microsoft Defender for Cloud on all resource types for continuous monitoring',
    }));
  }

  return f;
}

// ============================================================================
// Cache management
// ============================================================================

export function getComplianceFindings() {
  return _complianceFindings;
}

export function clearComplianceCache() {
  _complianceCacheData = null;
  _complianceFindings = [];
}

// Backward-compat alias
export function invalidateComplianceCache() {
  clearComplianceCache();
}

// ============================================================================
// Main entry point — runs all applicable checks based on cloud environment
// ============================================================================

/**
 * Run all compliance checks against the provided Azure data.
 * @param {Object} data - Parsed Azure resource data context
 * @param {string} [cloudEnv] - Cloud environment override (defaults to current)
 * @returns {Array} Array of compliance findings
 */
export function runComplianceChecks(data, cloudEnv) {
  // Cache: skip if same data reference and we already have findings
  if (_complianceCacheData === data && _complianceFindings.length > 0) {
    return _complianceFindings;
  }
  _complianceCacheData = data;

  // Determine which frameworks to run
  const env = cloudEnv || getCloudEnv();
  const frameworks = getComplianceFrameworks(env);

  const findings = [];

  // Always run core frameworks
  if (frameworks.includes('CIS')) {
    findings.push(...runCISAzureChecks(data));
  }
  if (frameworks.includes('CAF')) {
    findings.push(...runCAFChecks(data));
  }
  // RBAC checks are handled by the IAM engine (analyzeRoleAssignments) below.
  // The legacy runRBACChecks() produced duplicate findings with different control IDs
  // (RBAC-OWNER vs RBAC-1, RBAC-SP-OWNER vs RBAC-2, etc.). Removed to prevent duplicates.
  if (frameworks.includes('SOC2')) {
    findings.push(...runSOC2Checks(data));
  }
  if (frameworks.includes('PCI')) {
    findings.push(...runPCIChecks(data));
  }
  if (frameworks.includes('BUDR')) {
    findings.push(...runBUDRAzureChecks(data));
  }

  // Government cloud frameworks
  if (frameworks.includes('FEDRAMP_MOD')) {
    findings.push(...runFedRAMPChecks(data, 'FEDRAMP_MOD'));
  }
  if (frameworks.includes('FEDRAMP_HIGH')) {
    findings.push(...runFedRAMPChecks(data, 'FEDRAMP_HIGH'));
  }
  if (frameworks.includes('NIST_800_171')) {
    findings.push(...runFedRAMPChecks(data, 'NIST_800_171'));
  }
  if (frameworks.includes('CMMC')) {
    findings.push(...runFedRAMPChecks(data, 'CMMC'));
  }

  // Run external BUDR engine (backup assessments with RTO/RPO)
  try {
    const budrFindings = runBUDRChecks(data);
    if (budrFindings && budrFindings.length > 0) {
      findings.push(...budrFindings);
    }
  } catch (e) {
    console.warn('BUDR engine checks failed:', e);
  }

  // Run IAM/RBAC engine if data available
  try {
    const rbacData = getRbacData();
    if (rbacData) {
      const assignments = rbacData.roleAssignments || rbacData;
      const definitions = rbacData.roleDefinitions || [];
      if (Array.isArray(assignments) && assignments.length) {
        const rbacFindings = analyzeRoleAssignments(assignments, definitions);
        findings.push(...rbacFindings);
      }
    }
  } catch (e) {
    console.warn('IAM compliance checks failed:', e);
  }

  // Annotate findings with CKV IDs
  findings.forEach(finding => {
    if (!finding.checkovId && CKV_MAP[finding.id]) {
      finding.checkovId = CKV_MAP[finding.id];
    }
    // Ensure control field is set for backward compatibility
    if (!finding.control) finding.control = finding.id;
    if (!finding.resourceName) finding.resourceName = finding.resource;
  });

  _complianceFindings = findings;

  // Sync to window for inline code compatibility
  if (typeof window !== 'undefined') {
    window._complianceFindings = _complianceFindings;
  }

  return _complianceFindings;
}
