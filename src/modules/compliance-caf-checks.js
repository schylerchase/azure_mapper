// Cloud Adoption Framework compliance checks.

import { _rn, _finding, _hasTags, _getVnetSubnets, _subnetProps } from './compliance-rule-primitives.js';

export function runCAFChecks(data) {
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
        message: `Subnet "${subName}" has no User Defined Route (UDR) table: uses default system routes`,
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
        message: `VNet "${_rn(vnet)}" has no subnets configured: unused VNet`,
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
      message: `${vnets.length} VNets found but no hub VNet identified: consider hub-spoke architecture`,
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
        message: `Peering "${_rn(peer)}" does not allow forwarded traffic: spoke-to-spoke routing via hub will fail`,
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
      message: 'Hub VNet detected but no Azure Firewall deployed: no centralized traffic inspection',
      resource: 'Hub VNet', resourceId: '', resourceType: 'Microsoft.Network/azureFirewalls',
      remediation: 'Deploy Azure Firewall (or NVA) in the hub VNet for centralized traffic control',
    }));
  }

  // CAF-DNS: No private DNS zones configured
  if (privateDnsZones.length === 0 && vnets.length > 0) {
    f.push(_finding({
      id: 'CAF-DNS', framework: 'CAF', severity: 'LOW',
      title: 'No private DNS zones configured',
      message: 'No Azure Private DNS zones found: PaaS private endpoints require private DNS for resolution',
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
          message: `VM "${_rn(vm)}" has a public IP assigned: use Azure Bastion or Load Balancer instead`,
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
        message: `NSG "${_rn(nsg)}" has no diagnostic settings: flow logs and events not captured`,
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
      message: 'No resource locks found: production resources can be accidentally deleted',
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
      message: `${untagged.length} resource(s) missing tags: cost tracking and ownership unclear`,
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
          message: `VNet "${_rn(vnet)}" uses ${cidr} (/${mask}): larger than /16 wastes IP space`,
          resource: _rn(vnet), resourceId: vnet.id || '', resourceType: 'Microsoft.Network/virtualNetworks',
          remediation: 'Use /16 or smaller address spaces; plan CIDR allocation to avoid overlap',
        }));
      }
    });
  });

  return f;
}
