// CIS Azure Foundations compliance checks.

import { _getRules, _ruleProps, _hasOpenSourcePrefixes, _coversPort, _isAllPorts, _isAllProtocols, _rn, _finding } from './compliance-rule-primitives.js';

export function runCISAzureChecks(data) {
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

  // Single pass: CIS-9 (RDP), CIS-10 (SSH), CIS-12 (all inbound), CIS-DB (database ports), CIS-UDP (all UDP)
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
      const openSrc = _hasOpenSourcePrefixes(rule);
      if (!openSrc) return;

      // CIS-9: RDP from internet
      if (_coversPort(rule, 3389)) {
        f.push(_finding({
          id: 'CIS-9', framework: 'CIS_AZURE', severity: 'HIGH',
          title: 'NSG allows RDP from 0.0.0.0/0',
          message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows RDP (3389) from any source`,
          resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
          remediation: 'Restrict RDP access to specific CIDR ranges or use Azure Bastion',
        }));
      }

      // CIS-10: SSH from internet
      if (_coversPort(rule, 22) && ((rp.protocol || '').trim().toLowerCase() === 'tcp' || _isAllProtocols(rule))) {
        f.push(_finding({
          id: 'CIS-10', framework: 'CIS_AZURE', severity: 'HIGH',
          title: 'NSG allows SSH from 0.0.0.0/0',
          message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows SSH (22) from any source`,
          resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
          remediation: 'Restrict SSH access to specific CIDR ranges or use Azure Bastion',
        }));
      }

      // CIS-12: All inbound traffic
      if (_isAllProtocols(rule) && _isAllPorts(rule)) {
        f.push(_finding({
          id: 'CIS-12', framework: 'CIS_AZURE', severity: 'CRITICAL',
          title: 'NSG allows all inbound traffic',
          message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows all traffic from any source`,
          resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
          remediation: 'Remove or restrict rule to specific ports and source addresses',
        }));
      }

      // CIS-DB: Database ports from internet
      dbPorts.forEach(db => {
        if (_coversPort(rule, db.port) && ((rp.protocol || '').trim().toLowerCase() === 'tcp' || _isAllProtocols(rule))) {
          f.push(_finding({
            id: 'CIS-DB-' + db.port, framework: 'CIS_AZURE', severity: 'HIGH',
            title: `NSG allows ${db.name} port from 0.0.0.0/0`,
            message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows ${db.name} (${db.port}) from any source`,
            resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
            remediation: `Restrict ${db.name} access to application subnets only`,
          }));
        }
      });

      // CIS-UDP: All UDP from internet
      const proto = (rp.protocol || '').toLowerCase();
      if (proto === 'udp' && _isAllPorts(rule)) {
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
        message: `Storage account "${_rn(sa)}" uses ${minTls}: TLS 1.2 is the minimum secure version`,
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
        message: `Hub VNet "${_rn(hub)}" has no Azure Bastion host deployed: RDP/SSH jump host missing`,
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
    const connections = [...(props.privateLinkServiceConnections || []), ...(props.manualPrivateLinkServiceConnections || [])];
    const connectionProps = connections.map(conn => conn.properties || conn);
    const states = new Set(connectionProps.map(conn => conn.privateLinkServiceConnectionState?.status || ''));
    const orphanState = [...states].find(state => ['Rejected', 'Disconnected', 'Failed'].includes(state));
    const groupIds = new Set(connectionProps.flatMap(conn => conn.groupIds || []));
    const subnetId = props.subnet?.id || '';
    const vnetId = subnetId ? subnetId.split('/subnets/')[0] : '';
    const peName = _rn(pe);

    // PE-PENDING: Connection pending approval
    if (states.has('Pending')) {
      f.push(_finding({
        id: 'PE-PENDING', framework: 'CIS_AZURE', severity: 'HIGH',
        title: 'Private Endpoint connection pending approval',
        message: `PE "${peName}" has a pending connection: traffic will not flow until approved`,
        resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
        remediation: 'Approve the private endpoint connection on the target resource or remove the PE if not needed',
      }));
    }

    // PE-ORPHAN: Connection failed or rejected
    if (orphanState) {
      f.push(_finding({
        id: 'PE-ORPHAN', framework: 'CIS_AZURE', severity: 'MEDIUM',
        title: 'Private Endpoint connection ' + orphanState.toLowerCase(),
        message: `PE "${peName}" has a ${orphanState.toLowerCase()} connection: endpoint is orphaned and should be cleaned up`,
        resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
        remediation: 'Remove the orphaned private endpoint or re-create the connection to the target service',
      }));
    }

    // PE-NO-DNS: No matching private DNS zone for this PE's group ID
    groupIds.forEach(groupId => {
      const expectedZone = PE_DNS_MAP[groupId];
      if (expectedZone && !dnsZonesByName[expectedZone.toLowerCase()]) {
        f.push(_finding({
          id: 'PE-NO-DNS', framework: 'CIS_AZURE', severity: 'HIGH',
          title: 'No private DNS zone for Private Endpoint',
          message: `PE "${peName}" (${groupId}) requires DNS zone "${expectedZone}" but none exists: DNS resolution will fail`,
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
              message: `PE "${peName}" is in VNet "${vnetId.split('/').pop()}" but DNS zone "${expectedZone}" is not linked to that VNet: resolution will use public DNS`,
              resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
              remediation: 'Add a virtual network link from "' + expectedZone + '" to VNet "' + vnetId.split('/').pop() + '"',
            }));
          }
        }
      }
    });

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
            message: `Subnet "${_rn(subnet)}" has an NSG but PE network policies are disabled: NSG rules will not apply to PE "${peName}"`,
            resource: peName, resourceId: pe.id || '', resourceType: 'Microsoft.Network/privateEndpoints',
            remediation: 'Enable privateEndpointNetworkPolicies on the subnet to allow NSG filtering of PE traffic',
          }));
        }
      }
    }
  });

  return f;
}
