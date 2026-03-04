// Demo data generator for Azure Network Mapper
// Generates realistic enterprise hub-spoke Azure topology with compliance findings
// Extracted from index.html for modularization

/**
 * Generate demonstration Azure infrastructure data
 * Uses seeded PRNG for deterministic output across reloads
 * @returns {Object} Azure infrastructure data (VNets, subnets, VMs, NSGs, etc.)
 */
export function generateDemo() {
  // Seeded PRNG for deterministic demo data (reproducible across reloads)
  let _seed = 12345;
  const _random = () => { _seed = ((_seed * 1664525 + 1013904223) | 0); return ((_seed >>> 0) / 0x100000000); };

  const SUB_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
  const TENANT_ID = 't1e2n3a4-n5t6-7890-abcd-tenant1234567';
  const LH_SUB_ID = 'c9d8e7f6-5a4b-3c2d-1e0f-lighthouse12345';
  const LH_TENANT_ID = 'l1h2t3e4-5678-90ab-cdef-lighthouse6789';
  const LOCATION = 'eastus2';

  function rid(rg, provider, type, name) {
    return '/subscriptions/' + SUB_ID + '/resourceGroups/' + rg + '/providers/' + provider + '/' + type + '/' + name;
  }
  function lhrid(rg, provider, type, name) {
    return '/subscriptions/' + LH_SUB_ID + '/resourceGroups/' + rg + '/providers/' + provider + '/' + type + '/' + name;
  }

  let _uid = 1;
  function uuid() {
    const h = '0123456789abcdef';
    let u = '';
    for (let i = 0; i < 32; i++) {
      if (i === 8 || i === 12 || i === 16 || i === 20) u += '-';
      u += h[Math.floor(_random() * 16)];
    }
    return u;
  }
  function nid(prefix) { return prefix + '-' + String(_uid++).padStart(5, '0'); }

  // ─── Resource Groups ───
  const resourceGroups = [
    { name: 'rg-hub-networking', location: LOCATION, tags: { environment: 'shared', purpose: 'hub-networking', costCenter: 'IT-NET-001' } },
    { name: 'rg-prod-workloads', location: LOCATION, tags: { environment: 'production', purpose: 'workloads', costCenter: 'BU-PROD-100' } },
    { name: 'rg-staging-workloads', location: LOCATION, tags: { environment: 'staging', purpose: 'workloads', costCenter: 'BU-STG-200' } },
    { name: 'rg-dev-workloads', location: LOCATION, tags: { environment: 'development', purpose: 'workloads', costCenter: 'BU-DEV-300' } },
    { name: 'rg-data-platform', location: LOCATION, tags: { environment: 'production', purpose: 'data-services', costCenter: 'BU-DATA-400' } },
    { name: 'rg-pci-compliant', location: LOCATION, tags: { environment: 'production', purpose: 'pci-dss', costCenter: 'BU-PCI-500' } },
  ];

  // ─── VNet Definitions ───
  const vnetDefs = [
    {
      name: 'vnet-hub', rg: 'rg-hub-networking', cidr: '10.0.0.0/16',
      subnets: [
        { name: 'AzureFirewallSubnet', cidr: '10.0.0.0/26' },
        { name: 'AzureBastionSubnet', cidr: '10.0.1.0/26' },
        { name: 'GatewaySubnet', cidr: '10.0.2.0/27' },
        { name: 'SharedServices', cidr: '10.0.3.0/24' },
        { name: 'Management', cidr: '10.0.4.0/24' },
        { name: 'DNS', cidr: '10.0.5.0/24' },
      ]
    },
    {
      name: 'vnet-prod', rg: 'rg-prod-workloads', cidr: '10.1.0.0/16',
      subnets: [
        { name: 'Web', cidr: '10.1.1.0/24' },
        { name: 'App', cidr: '10.1.2.0/24' },
        { name: 'Data', cidr: '10.1.3.0/24' },
        { name: 'AKS', cidr: '10.1.4.0/22' },
        { name: 'Functions', cidr: '10.1.8.0/24' },
      ]
    },
    {
      name: 'vnet-staging', rg: 'rg-staging-workloads', cidr: '10.2.0.0/16',
      subnets: [
        { name: 'Web', cidr: '10.2.1.0/24' },
        { name: 'App', cidr: '10.2.2.0/24' },
        { name: 'Data', cidr: '10.2.3.0/24' },
      ]
    },
    {
      name: 'vnet-dev', rg: 'rg-dev-workloads', cidr: '10.3.0.0/16',
      subnets: [
        { name: 'Dev', cidr: '10.3.1.0/24' },
        { name: 'Test', cidr: '10.3.2.0/24' },
        { name: 'Sandbox', cidr: '10.3.3.0/24' },
      ]
    },
    {
      name: 'vnet-data', rg: 'rg-data-platform', cidr: '10.4.0.0/16',
      subnets: [
        { name: 'SQL', cidr: '10.4.1.0/24' },
        { name: 'Redis', cidr: '10.4.2.0/24' },
        { name: 'Storage', cidr: '10.4.3.0/24' },
        { name: 'Synapse', cidr: '10.4.4.0/24' },
      ]
    },
    {
      name: 'vnet-pci', rg: 'rg-pci-compliant', cidr: '10.5.0.0/16',
      subnets: [
        { name: 'PCI-Web', cidr: '10.5.1.0/24' },
        { name: 'PCI-App', cidr: '10.5.2.0/24' },
        { name: 'PCI-Data', cidr: '10.5.3.0/24' },
      ]
    },
    {
      name: 'vnet-lighthouse-customer', rg: 'rg-lighthouse-customer', cidr: '172.16.0.0/16',
      subnets: [
        { name: 'Customer-Web', cidr: '172.16.1.0/24' },
        { name: 'Customer-App', cidr: '172.16.2.0/24' },
      ],
      _isLighthouse: true, _tenantId: LH_TENANT_ID, _subscriptionId: LH_SUB_ID
    }
  ];

  // ─── Build VNets and Subnets ───
  const vnets = [];
  const allSubnets = [];
  const subnetMap = {};

  vnetDefs.forEach(vd => {
    const isLH = vd._isLighthouse || false;
    const subId = isLH ? LH_SUB_ID : SUB_ID;
    const vnetId = '/subscriptions/' + subId + '/resourceGroups/' + vd.rg + '/providers/Microsoft.Network/virtualNetworks/' + vd.name;

    const subnetRefs = [];
    vd.subnets.forEach(sd => {
      const subnetId = vnetId + '/subnets/' + sd.name;
      const subnetObj = {
        id: subnetId,
        name: sd.name,
        properties: {
          addressPrefix: sd.cidr,
          provisioningState: 'Succeeded',
          privateEndpointNetworkPolicies: 'Disabled',
          privateLinkServiceNetworkPolicies: 'Enabled',
        },
        _vnetName: vd.name,
        _rgName: vd.rg,
      };
      if (isLH) {
        subnetObj._isLighthouse = true;
        subnetObj._tenantId = LH_TENANT_ID;
      }
      subnetRefs.push(subnetObj);
      allSubnets.push(subnetObj);
      subnetMap[sd.name + '@' + vd.name] = subnetObj;
    });

    const vnetObj = {
      id: vnetId,
      name: vd.name,
      type: 'Microsoft.Network/virtualNetworks',
      location: LOCATION,
      properties: {
        addressSpace: { addressPrefixes: [vd.cidr] },
        subnets: subnetRefs,
        provisioningState: 'Succeeded',
        enableDdosProtection: vd.name === 'vnet-hub' || vd.name === 'vnet-prod',
      },
      tags: vd._isLighthouse ? { environment: 'customer', managedBy: 'lighthouse' } : (resourceGroups.find(r => r.name === vd.rg) || {}).tags || {},
    };
    if (isLH) {
      vnetObj._isLighthouse = true;
      vnetObj._tenantId = LH_TENANT_ID;
      vnetObj._subscriptionId = LH_SUB_ID;
    }
    vnets.push(vnetObj);
  });

  // ─── NSGs ───
  const nsgs = [];

  function makeNsg(name, rg, rules) {
    const nsgId = rid(rg, 'Microsoft.Network', 'networkSecurityGroups', name);
    const defaultRules = [
      { name: 'AllowVnetInBound', properties: { priority: 65000, direction: 'Inbound', access: 'Allow', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: 'VirtualNetwork' } },
      { name: 'AllowAzureLoadBalancerInBound', properties: { priority: 65001, direction: 'Inbound', access: 'Allow', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'AzureLoadBalancer', destinationAddressPrefix: '*' } },
      { name: 'DenyAllInBound', properties: { priority: 65500, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
      { name: 'AllowVnetOutBound', properties: { priority: 65000, direction: 'Outbound', access: 'Allow', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: 'VirtualNetwork' } },
      { name: 'AllowInternetOutBound', properties: { priority: 65001, direction: 'Outbound', access: 'Allow', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: 'Internet' } },
      { name: 'DenyAllOutBound', properties: { priority: 65500, direction: 'Outbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
    ];
    const nsgObj = {
      id: nsgId,
      name: name,
      type: 'Microsoft.Network/networkSecurityGroups',
      location: LOCATION,
      properties: {
        securityRules: rules,
        defaultSecurityRules: defaultRules,
        provisioningState: 'Succeeded',
      },
      tags: (resourceGroups.find(r => r.name === rg) || {}).tags || {},
    };
    nsgs.push(nsgObj);
    return nsgObj;
  }

  // hub-mgmt-nsg
  makeNsg('hub-mgmt-nsg', 'rg-hub-networking', [
    { name: 'AllowSSHFromBastion', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '22', sourceAddressPrefix: '10.0.1.0/26', destinationAddressPrefix: '*' } },
    { name: 'AllowRDPFromBastion', properties: { priority: 110, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '3389', sourceAddressPrefix: '10.0.1.0/26', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // hub-dns-nsg
  makeNsg('hub-dns-nsg', 'rg-hub-networking', [
    { name: 'AllowDNSFromVnet', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: '*', sourcePortRange: '*', destinationPortRange: '53', sourceAddressPrefix: '10.0.0.0/8', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // prod-web-nsg
  makeNsg('prod-web-nsg', 'rg-prod-workloads', [
    { name: 'AllowHTTPS', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '443', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
    { name: 'AllowHTTP', properties: { priority: 110, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '80', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
    { name: 'AllowHealthProbes', properties: { priority: 120, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '65200-65535', sourceAddressPrefix: 'AzureLoadBalancer', destinationAddressPrefix: '*' } },
    { name: 'AllowAppGatewayHealth', properties: { priority: 130, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '8080', sourceAddressPrefix: 'GatewayManager', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // prod-app-nsg
  makeNsg('prod-app-nsg', 'rg-prod-workloads', [
    { name: 'AllowPort8080FromWeb', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '8080', sourceAddressPrefix: '10.1.1.0/24', destinationAddressPrefix: '*' } },
    { name: 'AllowHTTPSFromWeb', properties: { priority: 110, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '443', sourceAddressPrefix: '10.1.1.0/24', destinationAddressPrefix: '*' } },
    { name: 'AllowHealthProbes', properties: { priority: 120, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'AzureLoadBalancer', destinationAddressPrefix: '*' } },
    { name: 'DenyInternetInbound', properties: { priority: 200, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'Internet', destinationAddressPrefix: '*' } },
  ]);

  // prod-data-nsg
  makeNsg('prod-data-nsg', 'rg-prod-workloads', [
    { name: 'AllowSQLFromApp', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '1433', sourceAddressPrefix: '10.1.2.0/24', destinationAddressPrefix: '*' } },
    { name: 'AllowRedisFromApp', properties: { priority: 110, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '6380', sourceAddressPrefix: '10.1.2.0/24', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // prod-aks-nsg
  makeNsg('prod-aks-nsg', 'rg-prod-workloads', [
    { name: 'AllowAPIServer', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '443', sourceAddressPrefix: 'AzureCloud', destinationAddressPrefix: '*' } },
    { name: 'AllowKubelet', properties: { priority: 110, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '10250', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: '*' } },
    { name: 'AllowNodePorts', properties: { priority: 120, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '30000-32767', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // staging-web-nsg
  makeNsg('staging-web-nsg', 'rg-staging-workloads', [
    { name: 'AllowHTTPS', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '443', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
    { name: 'AllowHTTP', properties: { priority: 110, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '80', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // staging-app-nsg
  makeNsg('staging-app-nsg', 'rg-staging-workloads', [
    { name: 'AllowPort8080FromWeb', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '8080', sourceAddressPrefix: '10.2.1.0/24', destinationAddressPrefix: '*' } },
    { name: 'DenyInternetInbound', properties: { priority: 200, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'Internet', destinationAddressPrefix: '*' } },
  ]);

  // dev-nsg -- intentionally permissive (compliance violation)
  makeNsg('dev-nsg', 'rg-dev-workloads', [
    { name: 'AllowSSHFromVnet', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '22', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: '*' } },
    { name: 'AllowAllFromVnet', properties: { priority: 200, direction: 'Inbound', access: 'Allow', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: '*' } },
  ]);

  // data-sql-nsg
  makeNsg('data-sql-nsg', 'rg-data-platform', [
    { name: 'AllowSQLFromProd', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '1433', sourceAddressPrefix: '10.1.0.0/16', destinationAddressPrefix: '*' } },
    { name: 'AllowSQLFromData', properties: { priority: 110, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '1433', sourceAddressPrefix: '10.4.0.0/16', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // data-redis-nsg
  makeNsg('data-redis-nsg', 'rg-data-platform', [
    { name: 'AllowRedisFromProd', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '6380', sourceAddressPrefix: '10.1.0.0/16', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // pci-web-nsg
  makeNsg('pci-web-nsg', 'rg-pci-compliant', [
    { name: 'AllowHTTPSOnly', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '443', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
    { name: 'DenyAllElse', properties: { priority: 101, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // pci-app-nsg
  makeNsg('pci-app-nsg', 'rg-pci-compliant', [
    { name: 'AllowFromPCIWeb', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '8443', sourceAddressPrefix: '10.5.1.0/24', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // pci-data-nsg
  makeNsg('pci-data-nsg', 'rg-pci-compliant', [
    { name: 'AllowSQLFromPCIApp', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourcePortRange: '*', destinationPortRange: '1433', sourceAddressPrefix: '10.5.2.0/24', destinationAddressPrefix: '*' } },
    { name: 'DenyAllInbound', properties: { priority: 4096, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: '*', destinationAddressPrefix: '*' } },
  ]);

  // Associate NSGs with subnets
  const nsgAssociations = {
    'Management@vnet-hub': 'hub-mgmt-nsg',
    'SharedServices@vnet-hub': 'hub-mgmt-nsg',
    'DNS@vnet-hub': 'hub-dns-nsg',
    'Web@vnet-prod': 'prod-web-nsg',
    'App@vnet-prod': 'prod-app-nsg',
    'Data@vnet-prod': 'prod-data-nsg',
    'AKS@vnet-prod': 'prod-aks-nsg',
    'Web@vnet-staging': 'staging-web-nsg',
    'App@vnet-staging': 'staging-app-nsg',
    'Dev@vnet-dev': 'dev-nsg',
    'Test@vnet-dev': 'dev-nsg',
    'Sandbox@vnet-dev': 'dev-nsg',
    'SQL@vnet-data': 'data-sql-nsg',
    'Redis@vnet-data': 'data-redis-nsg',
    'PCI-Web@vnet-pci': 'pci-web-nsg',
    'PCI-App@vnet-pci': 'pci-app-nsg',
    'PCI-Data@vnet-pci': 'pci-data-nsg',
  };

  Object.entries(nsgAssociations).forEach(([key, nsgName]) => {
    const subnet = subnetMap[key];
    const nsg = nsgs.find(n => n.name === nsgName);
    if (subnet && nsg) {
      subnet.properties.networkSecurityGroup = { id: nsg.id };
    }
  });

  // ─── Route Tables (UDRs) ───
  const routeTables = [];

  const prodUdr = {
    id: rid('rg-prod-workloads', 'Microsoft.Network', 'routeTables', 'prod-udr'),
    name: 'prod-udr',
    type: 'Microsoft.Network/routeTables',
    location: LOCATION,
    properties: {
      disableBgpRoutePropagation: false,
      routes: [
        { name: 'DefaultToFirewall', properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.0.4', provisioningState: 'Succeeded' } },
        { name: 'RFC1918ToVnet', properties: { addressPrefix: '10.0.0.0/8', nextHopType: 'VnetLocal', provisioningState: 'Succeeded' } },
      ],
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'production' },
  };
  routeTables.push(prodUdr);

  const pciUdr = {
    id: rid('rg-pci-compliant', 'Microsoft.Network', 'routeTables', 'pci-udr'),
    name: 'pci-udr',
    type: 'Microsoft.Network/routeTables',
    location: LOCATION,
    properties: {
      disableBgpRoutePropagation: true,
      routes: [
        { name: 'DefaultToFirewall', properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.0.4', provisioningState: 'Succeeded' } },
        { name: 'HubToFirewall', properties: { addressPrefix: '10.0.0.0/16', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.0.4', provisioningState: 'Succeeded' } },
        { name: 'ProdToFirewall', properties: { addressPrefix: '10.1.0.0/16', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.0.4', provisioningState: 'Succeeded' } },
        { name: 'BlockDataDirect', properties: { addressPrefix: '10.4.0.0/16', nextHopType: 'None', provisioningState: 'Succeeded' } },
      ],
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'pci', compliance: 'pci-dss' },
  };
  routeTables.push(pciUdr);

  // dev-udr: intentionally NO custom routes (compliance violation)
  const devUdr = {
    id: rid('rg-dev-workloads', 'Microsoft.Network', 'routeTables', 'dev-udr'),
    name: 'dev-udr',
    type: 'Microsoft.Network/routeTables',
    location: LOCATION,
    properties: {
      disableBgpRoutePropagation: false,
      routes: [],
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'development' },
  };
  routeTables.push(devUdr);

  const stagingUdr = {
    id: rid('rg-staging-workloads', 'Microsoft.Network', 'routeTables', 'staging-udr'),
    name: 'staging-udr',
    type: 'Microsoft.Network/routeTables',
    location: LOCATION,
    properties: {
      disableBgpRoutePropagation: false,
      routes: [
        { name: 'DefaultToFirewall', properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.0.4', provisioningState: 'Succeeded' } },
      ],
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'staging' },
  };
  routeTables.push(stagingUdr);

  // Associate UDRs with subnets
  const udrAssociations = {
    'Web@vnet-prod': 'prod-udr',
    'App@vnet-prod': 'prod-udr',
    'Data@vnet-prod': 'prod-udr',
    'AKS@vnet-prod': 'prod-udr',
    'Functions@vnet-prod': 'prod-udr',
    'PCI-Web@vnet-pci': 'pci-udr',
    'PCI-App@vnet-pci': 'pci-udr',
    'PCI-Data@vnet-pci': 'pci-udr',
    'Dev@vnet-dev': 'dev-udr',
    'Test@vnet-dev': 'dev-udr',
    'Sandbox@vnet-dev': 'dev-udr',
    'Web@vnet-staging': 'staging-udr',
    'App@vnet-staging': 'staging-udr',
    'Data@vnet-staging': 'staging-udr',
  };

  Object.entries(udrAssociations).forEach(([key, udrName]) => {
    const subnet = subnetMap[key];
    const udr = routeTables.find(r => r.name === udrName);
    if (subnet && udr) {
      subnet.properties.routeTable = { id: udr.id };
    }
  });

  // ─── NICs & VMs ───
  const VM_SIZES = ['Standard_D2s_v3', 'Standard_D4s_v3', 'Standard_B2ms', 'Standard_B4ms', 'Standard_D8s_v3', 'Standard_E2s_v3', 'Standard_F2s_v2', 'Standard_DS2_v2'];
  const OS_LINUX = { publisher: 'Canonical', offer: 'UbuntuServer', sku: '22_04-lts-gen2', version: 'latest' };
  const OS_WIN = { publisher: 'MicrosoftWindowsServer', offer: 'WindowsServer', sku: '2022-datacenter-g2', version: 'latest' };
  const VM_STATES = ['PowerState/running', 'PowerState/running', 'PowerState/running', 'PowerState/running', 'PowerState/deallocated'];

  const nics = [];
  const vms = [];
  const publicIps = [];

  const vmDefs = [
    // Hub VMs
    { name: 'vm-hub-mgmt-01', rg: 'rg-hub-networking', subnet: 'Management@vnet-hub', size: 'Standard_B2ms', os: 'linux', ip: '10.0.4.10' },
    { name: 'vm-hub-mgmt-02', rg: 'rg-hub-networking', subnet: 'Management@vnet-hub', size: 'Standard_B2ms', os: 'windows', ip: '10.0.4.11' },
    { name: 'vm-hub-dns-01', rg: 'rg-hub-networking', subnet: 'DNS@vnet-hub', size: 'Standard_B2ms', os: 'linux', ip: '10.0.5.10' },
    { name: 'vm-hub-dns-02', rg: 'rg-hub-networking', subnet: 'DNS@vnet-hub', size: 'Standard_B2ms', os: 'linux', ip: '10.0.5.11' },
    // Prod VMs
    { name: 'vm-prod-web-01', rg: 'rg-prod-workloads', subnet: 'Web@vnet-prod', size: 'Standard_D4s_v3', os: 'linux', ip: '10.1.1.10' },
    { name: 'vm-prod-web-02', rg: 'rg-prod-workloads', subnet: 'Web@vnet-prod', size: 'Standard_D4s_v3', os: 'linux', ip: '10.1.1.11' },
    { name: 'vm-prod-app-01', rg: 'rg-prod-workloads', subnet: 'App@vnet-prod', size: 'Standard_D8s_v3', os: 'linux', ip: '10.1.2.10' },
    { name: 'vm-prod-app-02', rg: 'rg-prod-workloads', subnet: 'App@vnet-prod', size: 'Standard_D8s_v3', os: 'linux', ip: '10.1.2.11' },
    { name: 'vm-prod-app-03', rg: 'rg-prod-workloads', subnet: 'App@vnet-prod', size: 'Standard_D4s_v3', os: 'linux', ip: '10.1.2.12' },
    // Staging VMs
    { name: 'vm-stg-web-01', rg: 'rg-staging-workloads', subnet: 'Web@vnet-staging', size: 'Standard_B4ms', os: 'linux', ip: '10.2.1.10' },
    { name: 'vm-stg-app-01', rg: 'rg-staging-workloads', subnet: 'App@vnet-staging', size: 'Standard_B4ms', os: 'linux', ip: '10.2.2.10' },
    // Dev VMs -- compliance: missing tags, no backup
    { name: 'vm-dev-01', rg: 'rg-dev-workloads', subnet: 'Dev@vnet-dev', size: 'Standard_B2ms', os: 'linux', ip: '10.3.1.10', _hasPublicIp: true, _noTags: true },
    { name: 'vm-dev-02', rg: 'rg-dev-workloads', subnet: 'Dev@vnet-dev', size: 'Standard_B2ms', os: 'linux', ip: '10.3.1.11', _noTags: true },
    { name: 'vm-dev-win-01', rg: 'rg-dev-workloads', subnet: 'Test@vnet-dev', size: 'Standard_D2s_v3', os: 'windows', ip: '10.3.2.10', _noTags: true },
    // Data platform
    { name: 'vm-data-etl-01', rg: 'rg-data-platform', subnet: 'Synapse@vnet-data', size: 'Standard_E2s_v3', os: 'linux', ip: '10.4.4.10' },
    // PCI VMs
    { name: 'vm-pci-web-01', rg: 'rg-pci-compliant', subnet: 'PCI-Web@vnet-pci', size: 'Standard_D4s_v3', os: 'linux', ip: '10.5.1.10' },
    { name: 'vm-pci-app-01', rg: 'rg-pci-compliant', subnet: 'PCI-App@vnet-pci', size: 'Standard_D4s_v3', os: 'linux', ip: '10.5.2.10' },
    { name: 'vm-pci-app-02', rg: 'rg-pci-compliant', subnet: 'PCI-App@vnet-pci', size: 'Standard_D4s_v3', os: 'linux', ip: '10.5.2.11' },
  ];

  vmDefs.forEach(vd => {
    const subnetObj = subnetMap[vd.subnet];
    if (!subnetObj) return;
    const osRef = vd.os === 'windows' ? OS_WIN : OS_LINUX;
    const nicName = vd.name + '-nic';
    const nicId = rid(vd.rg, 'Microsoft.Network', 'networkInterfaces', nicName);
    const vmId = rid(vd.rg, 'Microsoft.Compute', 'virtualMachines', vd.name);
    const state = VM_STATES[Math.floor(_random() * VM_STATES.length)];

    // Public IP (compliance violation for dev VM)
    let pipId = null;
    if (vd._hasPublicIp) {
      const pipName = vd.name + '-pip';
      pipId = rid(vd.rg, 'Microsoft.Network', 'publicIPAddresses', pipName);
      const octA = Math.floor(_random() * 200) + 20;
      const octB = Math.floor(_random() * 255);
      const octC = Math.floor(_random() * 255);
      const octD = Math.floor(_random() * 254) + 1;
      publicIps.push({
        id: pipId,
        name: pipName,
        type: 'Microsoft.Network/publicIPAddresses',
        location: LOCATION,
        properties: {
          publicIPAllocationMethod: 'Static',
          publicIPAddressVersion: 'IPv4',
          ipAddress: octA + '.' + octB + '.' + octC + '.' + octD,
          provisioningState: 'Succeeded',
          ipConfiguration: { id: nicId + '/ipConfigurations/ipconfig1' },
        },
        sku: { name: 'Standard', tier: 'Regional' },
        tags: {},
      });
    }

    // NIC
    const ipConfig = {
      name: 'ipconfig1',
      properties: {
        privateIPAddress: vd.ip,
        privateIPAllocationMethod: 'Static',
        subnet: { id: subnetObj.id },
        primary: true,
        provisioningState: 'Succeeded',
      },
    };
    if (pipId) {
      ipConfig.properties.publicIPAddress = { id: pipId };
    }

    const nicObj = {
      id: nicId,
      name: nicName,
      type: 'Microsoft.Network/networkInterfaces',
      location: LOCATION,
      properties: {
        ipConfigurations: [ipConfig],
        enableAcceleratedNetworking: vd.size.includes('D4') || vd.size.includes('D8') || vd.size.includes('E2'),
        enableIPForwarding: false,
        provisioningState: 'Succeeded',
        virtualMachine: { id: vmId },
      },
      tags: vd._noTags ? {} : ((resourceGroups.find(r => r.name === vd.rg) || {}).tags || {}),
    };
    nics.push(nicObj);

    // VM
    const vmObj = {
      id: vmId,
      name: vd.name,
      type: 'Microsoft.Compute/virtualMachines',
      location: LOCATION,
      properties: {
        vmId: uuid(),
        hardwareProfile: { vmSize: vd.size },
        storageProfile: {
          imageReference: osRef,
          osDisk: {
            osType: vd.os === 'windows' ? 'Windows' : 'Linux',
            name: vd.name + '-osdisk',
            createOption: 'FromImage',
            diskSizeGB: vd.os === 'windows' ? 128 : 64,
            managedDisk: { storageAccountType: 'Premium_LRS', id: rid(vd.rg, 'Microsoft.Compute', 'disks', vd.name + '-osdisk') },
          },
          dataDisks: vd.subnet.includes('Data') || vd.subnet.includes('SQL') || vd.subnet.includes('Synapse') ? [
            { lun: 0, name: vd.name + '-datadisk-0', diskSizeGB: 512, createOption: 'Empty', managedDisk: { storageAccountType: 'Premium_LRS' } },
          ] : [],
        },
        osProfile: {
          computerName: vd.name,
          adminUsername: vd.os === 'windows' ? 'azadmin' : 'azureuser',
        },
        networkProfile: {
          networkInterfaces: [{ id: nicId, properties: { primary: true } }],
        },
        provisioningState: 'Succeeded',
        instanceView: { statuses: [{ code: state, displayStatus: state.replace('PowerState/', '') }] },
      },
      tags: vd._noTags ? {} : ((resourceGroups.find(r => r.name === vd.rg) || {}).tags || {}),
    };
    vms.push(vmObj);
  });

  // ─── Azure Firewall ───
  const firewallPipId = rid('rg-hub-networking', 'Microsoft.Network', 'publicIPAddresses', 'pip-azfw');
  publicIps.push({
    id: firewallPipId,
    name: 'pip-azfw',
    type: 'Microsoft.Network/publicIPAddresses',
    location: LOCATION,
    properties: {
      publicIPAllocationMethod: 'Static',
      publicIPAddressVersion: 'IPv4',
      ipAddress: '20.85.100.1',
      provisioningState: 'Succeeded',
    },
    sku: { name: 'Standard', tier: 'Regional' },
    tags: { environment: 'shared', purpose: 'firewall' },
  });

  const azureFirewall = {
    id: rid('rg-hub-networking', 'Microsoft.Network', 'azureFirewalls', 'azfw-hub'),
    name: 'azfw-hub',
    type: 'Microsoft.Network/azureFirewalls',
    location: LOCATION,
    properties: {
      sku: { name: 'AZFW_VNet', tier: 'Premium' },
      ipConfigurations: [{
        name: 'azfw-ipconfig',
        properties: {
          privateIPAddress: '10.0.0.4',
          publicIPAddress: { id: firewallPipId },
          subnet: { id: vnets[0].id + '/subnets/AzureFirewallSubnet' },
          provisioningState: 'Succeeded',
        },
      }],
      threatIntelMode: 'Deny',
      firewallPolicy: { id: rid('rg-hub-networking', 'Microsoft.Network', 'firewallPolicies', 'azfw-policy') },
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'shared', purpose: 'hub-networking' },
  };

  // ─── Bastion ───
  const bastionPipId = rid('rg-hub-networking', 'Microsoft.Network', 'publicIPAddresses', 'pip-bastion');
  publicIps.push({
    id: bastionPipId,
    name: 'pip-bastion',
    type: 'Microsoft.Network/publicIPAddresses',
    location: LOCATION,
    properties: {
      publicIPAllocationMethod: 'Static',
      publicIPAddressVersion: 'IPv4',
      ipAddress: '20.85.100.2',
      provisioningState: 'Succeeded',
    },
    sku: { name: 'Standard', tier: 'Regional' },
    tags: { environment: 'shared', purpose: 'bastion' },
  });

  const bastion = {
    id: rid('rg-hub-networking', 'Microsoft.Network', 'bastionHosts', 'bastion-hub'),
    name: 'bastion-hub',
    type: 'Microsoft.Network/bastionHosts',
    location: LOCATION,
    properties: {
      ipConfigurations: [{
        name: 'bastion-ipconfig',
        properties: {
          publicIPAddress: { id: bastionPipId },
          subnet: { id: vnets[0].id + '/subnets/AzureBastionSubnet' },
          provisioningState: 'Succeeded',
        },
      }],
      dnsName: 'bst-hub-' + SUB_ID.slice(0, 8) + '.' + LOCATION + '.bastion.azure.com',
      scaleUnits: 2,
      provisioningState: 'Succeeded',
    },
    sku: { name: 'Standard' },
    tags: { environment: 'shared', purpose: 'bastion' },
  };

  // ─── VPN Gateway ───
  const vpnGwPipId = rid('rg-hub-networking', 'Microsoft.Network', 'publicIPAddresses', 'pip-vpngw');
  publicIps.push({
    id: vpnGwPipId,
    name: 'pip-vpngw',
    type: 'Microsoft.Network/publicIPAddresses',
    location: LOCATION,
    properties: {
      publicIPAllocationMethod: 'Static',
      publicIPAddressVersion: 'IPv4',
      ipAddress: '20.85.100.3',
      provisioningState: 'Succeeded',
    },
    sku: { name: 'Standard', tier: 'Regional' },
    tags: { environment: 'shared', purpose: 'vpn-gateway' },
  });

  const vpnGateway = {
    id: rid('rg-hub-networking', 'Microsoft.Network', 'virtualNetworkGateways', 'vpngw-hub'),
    name: 'vpngw-hub',
    type: 'Microsoft.Network/virtualNetworkGateways',
    location: LOCATION,
    properties: {
      gatewayType: 'Vpn',
      vpnType: 'RouteBased',
      sku: { name: 'VpnGw2', tier: 'VpnGw2', capacity: 2 },
      ipConfigurations: [{
        name: 'vpngw-ipconfig',
        properties: {
          publicIPAddress: { id: vpnGwPipId },
          subnet: { id: vnets[0].id + '/subnets/GatewaySubnet' },
          provisioningState: 'Succeeded',
        },
      }],
      enableBgp: true,
      bgpSettings: { asn: 65515, bgpPeeringAddress: '10.0.2.30', peerWeight: 0 },
      vpnClientConfiguration: { vpnClientProtocols: ['IkeV2', 'OpenVPN'] },
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'shared', purpose: 'vpn-gateway' },
  };

  const localNetworkGateway = {
    id: rid('rg-hub-networking', 'Microsoft.Network', 'localNetworkGateways', 'lng-onprem-dc'),
    name: 'lng-onprem-dc',
    type: 'Microsoft.Network/localNetworkGateways',
    location: LOCATION,
    properties: {
      localNetworkAddressSpace: { addressPrefixes: ['192.168.0.0/16', '172.20.0.0/16'] },
      gatewayIpAddress: '203.0.113.50',
      bgpSettings: { asn: 65001, bgpPeeringAddress: '192.168.1.1', peerWeight: 0 },
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'shared', purpose: 'on-premises' },
  };

  const vpnConnection = {
    id: rid('rg-hub-networking', 'Microsoft.Network', 'connections', 'conn-onprem-dc'),
    name: 'conn-onprem-dc',
    type: 'Microsoft.Network/connections',
    location: LOCATION,
    properties: {
      connectionType: 'IPsec',
      connectionProtocol: 'IKEv2',
      virtualNetworkGateway1: { id: vpnGateway.id },
      localNetworkGateway2: { id: localNetworkGateway.id },
      connectionStatus: 'Connected',
      ingressBytesTransferred: 28475839201,
      egressBytesTransferred: 15293847102,
      enableBgp: true,
      usePolicyBasedTrafficSelectors: false,
      ipsecPolicies: [{ saLifeTimeSeconds: 27000, saDataSizeKilobytes: 102400000, ipsecEncryption: 'AES256', ipsecIntegrity: 'SHA256', ikeEncryption: 'AES256', ikeIntegrity: 'SHA256', dhGroup: 'DHGroup14', pfsGroup: 'PFS2048' }],
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'shared', purpose: 'vpn-connection' },
  };

  // ─── NAT Gateways ───
  const natGateways = [];

  const prodNatPipId = rid('rg-prod-workloads', 'Microsoft.Network', 'publicIPAddresses', 'pip-natgw-prod');
  publicIps.push({
    id: prodNatPipId, name: 'pip-natgw-prod', type: 'Microsoft.Network/publicIPAddresses', location: LOCATION,
    properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4', ipAddress: '20.85.101.10', provisioningState: 'Succeeded' },
    sku: { name: 'Standard', tier: 'Regional' }, tags: { environment: 'production' },
  });

  natGateways.push({
    id: rid('rg-prod-workloads', 'Microsoft.Network', 'natGateways', 'natgw-prod-web'),
    name: 'natgw-prod-web',
    type: 'Microsoft.Network/natGateways',
    location: LOCATION,
    properties: {
      publicIpAddresses: [{ id: prodNatPipId }],
      subnets: [{ id: subnetMap['Web@vnet-prod'].id }],
      idleTimeoutInMinutes: 10,
      provisioningState: 'Succeeded',
    },
    sku: { name: 'Standard' },
    tags: { environment: 'production' },
  });

  const stgNatPipId = rid('rg-staging-workloads', 'Microsoft.Network', 'publicIPAddresses', 'pip-natgw-stg');
  publicIps.push({
    id: stgNatPipId, name: 'pip-natgw-stg', type: 'Microsoft.Network/publicIPAddresses', location: LOCATION,
    properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4', ipAddress: '20.85.101.11', provisioningState: 'Succeeded' },
    sku: { name: 'Standard', tier: 'Regional' }, tags: { environment: 'staging' },
  });

  natGateways.push({
    id: rid('rg-staging-workloads', 'Microsoft.Network', 'natGateways', 'natgw-stg-web'),
    name: 'natgw-stg-web',
    type: 'Microsoft.Network/natGateways',
    location: LOCATION,
    properties: {
      publicIpAddresses: [{ id: stgNatPipId }],
      subnets: [{ id: subnetMap['Web@vnet-staging'].id }],
      idleTimeoutInMinutes: 10,
      provisioningState: 'Succeeded',
    },
    sku: { name: 'Standard' },
    tags: { environment: 'staging' },
  });

  // Associate NAT gateways with subnets
  subnetMap['Web@vnet-prod'].properties.natGateway = { id: natGateways[0].id };
  subnetMap['Web@vnet-staging'].properties.natGateway = { id: natGateways[1].id };

  // ─── App Gateways ───
  const appGateways = [];

  const agwProdPipId = rid('rg-prod-workloads', 'Microsoft.Network', 'publicIPAddresses', 'pip-agw-prod');
  publicIps.push({
    id: agwProdPipId, name: 'pip-agw-prod', type: 'Microsoft.Network/publicIPAddresses', location: LOCATION,
    properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4', ipAddress: '20.85.102.10', provisioningState: 'Succeeded' },
    sku: { name: 'Standard', tier: 'Regional' }, tags: { environment: 'production' },
  });

  appGateways.push({
    id: rid('rg-prod-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-prod'),
    name: 'agw-prod',
    type: 'Microsoft.Network/applicationGateways',
    location: LOCATION,
    properties: {
      sku: { name: 'WAF_v2', tier: 'WAF_v2', capacity: 2 },
      gatewayIPConfigurations: [{ name: 'agw-ipconfig', properties: { subnet: { id: subnetMap['Web@vnet-prod'].id } } }],
      frontendIPConfigurations: [
        { name: 'agw-frontend-pip', properties: { publicIPAddress: { id: agwProdPipId } } },
        { name: 'agw-frontend-priv', properties: { privateIPAddress: '10.1.1.200', privateIPAllocationMethod: 'Static', subnet: { id: subnetMap['Web@vnet-prod'].id } } },
      ],
      frontendPorts: [
        { name: 'port-443', properties: { port: 443 } },
        { name: 'port-80', properties: { port: 80 } },
      ],
      backendAddressPools: [
        { name: 'prod-app-pool', properties: { backendAddresses: [{ ipAddress: '10.1.2.10' }, { ipAddress: '10.1.2.11' }, { ipAddress: '10.1.2.12' }] } },
      ],
      backendHttpSettingsCollection: [
        { name: 'https-settings', properties: { port: 8080, protocol: 'Https', cookieBasedAffinity: 'Disabled', requestTimeout: 30, probe: { id: rid('rg-prod-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-prod') + '/probes/health-probe' } } },
      ],
      httpListeners: [
        { name: 'https-listener', properties: { frontendIPConfiguration: { id: rid('rg-prod-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-prod') + '/frontendIPConfigurations/agw-frontend-pip' }, frontendPort: { id: rid('rg-prod-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-prod') + '/frontendPorts/port-443' }, protocol: 'Https' } },
      ],
      requestRoutingRules: [
        { name: 'rule-https', properties: { ruleType: 'Basic', priority: 100, httpListener: { id: rid('rg-prod-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-prod') + '/httpListeners/https-listener' }, backendAddressPool: { id: rid('rg-prod-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-prod') + '/backendAddressPools/prod-app-pool' }, backendHttpSettings: { id: rid('rg-prod-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-prod') + '/backendHttpSettingsCollection/https-settings' } } },
      ],
      webApplicationFirewallConfiguration: { enabled: true, firewallMode: 'Prevention', ruleSetType: 'OWASP', ruleSetVersion: '3.2', requestBodyCheck: true, maxRequestBodySizeInKb: 128, fileUploadLimitInMb: 100 },
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'production' },
  });

  // Staging App Gateway: Standard_v2 without WAF (compliance violation)
  const agwStgPipId = rid('rg-staging-workloads', 'Microsoft.Network', 'publicIPAddresses', 'pip-agw-stg');
  publicIps.push({
    id: agwStgPipId, name: 'pip-agw-stg', type: 'Microsoft.Network/publicIPAddresses', location: LOCATION,
    properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4', ipAddress: '20.85.102.11', provisioningState: 'Succeeded' },
    sku: { name: 'Standard', tier: 'Regional' }, tags: { environment: 'staging' },
  });

  appGateways.push({
    id: rid('rg-staging-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-staging'),
    name: 'agw-staging',
    type: 'Microsoft.Network/applicationGateways',
    location: LOCATION,
    properties: {
      sku: { name: 'Standard_v2', tier: 'Standard_v2', capacity: 1 },
      gatewayIPConfigurations: [{ name: 'agw-ipconfig', properties: { subnet: { id: subnetMap['Web@vnet-staging'].id } } }],
      frontendIPConfigurations: [
        { name: 'agw-frontend-pip', properties: { publicIPAddress: { id: agwStgPipId } } },
      ],
      frontendPorts: [
        { name: 'port-443', properties: { port: 443 } },
        { name: 'port-80', properties: { port: 80 } },
      ],
      backendAddressPools: [
        { name: 'stg-app-pool', properties: { backendAddresses: [{ ipAddress: '10.2.2.10' }] } },
      ],
      backendHttpSettingsCollection: [
        { name: 'http-settings', properties: { port: 8080, protocol: 'Http', cookieBasedAffinity: 'Disabled', requestTimeout: 30 } },
      ],
      httpListeners: [
        { name: 'http-listener', properties: { frontendIPConfiguration: { id: rid('rg-staging-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-staging') + '/frontendIPConfigurations/agw-frontend-pip' }, frontendPort: { id: rid('rg-staging-workloads', 'Microsoft.Network', 'applicationGateways', 'agw-staging') + '/frontendPorts/port-80' }, protocol: 'Http' } },
      ],
      requestRoutingRules: [
        { name: 'rule-http', properties: { ruleType: 'Basic', priority: 100 } },
      ],
      // No webApplicationFirewallConfiguration -- intentional compliance violation
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'staging' },
  });

  // ─── Load Balancers ───
  const loadBalancers = [];

  loadBalancers.push({
    id: rid('rg-prod-workloads', 'Microsoft.Network', 'loadBalancers', 'lb-prod-app'),
    name: 'lb-prod-app',
    type: 'Microsoft.Network/loadBalancers',
    location: LOCATION,
    properties: {
      frontendIPConfigurations: [{
        name: 'lb-frontend',
        properties: {
          privateIPAddress: '10.1.2.100',
          privateIPAllocationMethod: 'Static',
          subnet: { id: subnetMap['App@vnet-prod'].id },
          provisioningState: 'Succeeded',
        },
      }],
      backendAddressPools: [{
        name: 'prod-app-backend',
        properties: {
          loadBalancerBackendAddresses: [
            { name: 'vm-prod-app-01', properties: { ipAddress: '10.1.2.10' } },
            { name: 'vm-prod-app-02', properties: { ipAddress: '10.1.2.11' } },
            { name: 'vm-prod-app-03', properties: { ipAddress: '10.1.2.12' } },
          ],
          provisioningState: 'Succeeded',
        },
      }],
      loadBalancingRules: [{
        name: 'rule-https',
        properties: { frontendPort: 443, backendPort: 8080, protocol: 'Tcp', enableFloatingIP: false, idleTimeoutInMinutes: 4, enableTcpReset: true, loadDistribution: 'Default', provisioningState: 'Succeeded' },
      }],
      probes: [{
        name: 'health-probe',
        properties: { protocol: 'Https', port: 8080, requestPath: '/health', intervalInSeconds: 15, numberOfProbes: 2, provisioningState: 'Succeeded' },
      }],
      provisioningState: 'Succeeded',
    },
    sku: { name: 'Standard', tier: 'Regional' },
    tags: { environment: 'production' },
  });

  // ─── Private Endpoints ───
  const privateEndpoints = [];

  function makePe(name, rg, subnetKey, targetId, groupIds, ip) {
    const peId = rid(rg, 'Microsoft.Network', 'privateEndpoints', name);
    const subnet = subnetMap[subnetKey];
    if (!subnet) return;

    const peNicName = name + '-nic';
    const peNicId = rid(rg, 'Microsoft.Network', 'networkInterfaces', peNicName);
    nics.push({
      id: peNicId, name: peNicName, type: 'Microsoft.Network/networkInterfaces', location: LOCATION,
      properties: {
        ipConfigurations: [{ name: 'pe-ipconfig', properties: { privateIPAddress: ip, privateIPAllocationMethod: 'Static', subnet: { id: subnet.id }, primary: true, provisioningState: 'Succeeded' } }],
        enableAcceleratedNetworking: false, enableIPForwarding: false, provisioningState: 'Succeeded',
      },
      tags: {},
    });

    privateEndpoints.push({
      id: peId, name: name, type: 'Microsoft.Network/privateEndpoints', location: LOCATION,
      properties: {
        subnet: { id: subnet.id },
        privateLinkServiceConnections: [{
          name: name + '-conn',
          properties: { privateLinkServiceId: targetId, groupIds: groupIds, privateLinkServiceConnectionState: { status: 'Approved', description: 'Auto-approved' }, provisioningState: 'Succeeded' },
        }],
        customDnsConfigs: [{ fqdn: name + '.privatelink.database.windows.net', ipAddresses: [ip] }],
        networkInterfaces: [{ id: peNicId }],
        provisioningState: 'Succeeded',
      },
      tags: {},
    });
  }

  // SQL private endpoints
  const sqlServerId = rid('rg-data-platform', 'Microsoft.Sql', 'servers', 'sql-data-prod');
  makePe('pe-sql-data', 'rg-data-platform', 'SQL@vnet-data', sqlServerId, ['sqlServer'], '10.4.1.10');
  makePe('pe-sql-prod', 'rg-prod-workloads', 'Data@vnet-prod', sqlServerId, ['sqlServer'], '10.1.3.10');

  // Redis private endpoint
  const redisId = rid('rg-data-platform', 'Microsoft.Cache', 'redis', 'redis-data-prod');
  makePe('pe-redis-data', 'rg-data-platform', 'Redis@vnet-data', redisId, ['redisCache'], '10.4.2.10');

  // Storage private endpoint
  const storageId = rid('rg-data-platform', 'Microsoft.Storage', 'storageAccounts', 'stdataprodblob');
  makePe('pe-storage-blob', 'rg-data-platform', 'Storage@vnet-data', storageId, ['blob'], '10.4.3.10');

  // Key Vault private endpoint
  const kvId = rid('rg-hub-networking', 'Microsoft.KeyVault', 'vaults', 'kv-hub-shared');
  makePe('pe-keyvault', 'rg-hub-networking', 'SharedServices@vnet-hub', kvId, ['vault'], '10.0.3.10');

  // PCI SQL private endpoint
  const pciSqlId = rid('rg-pci-compliant', 'Microsoft.Sql', 'servers', 'sql-pci');
  makePe('pe-sql-pci', 'rg-pci-compliant', 'PCI-Data@vnet-pci', pciSqlId, ['sqlServer'], '10.5.3.10');

  // ─── AKS Cluster ───
  const aksCluster = {
    id: rid('rg-prod-workloads', 'Microsoft.ContainerService', 'managedClusters', 'aks-prod'),
    name: 'aks-prod',
    type: 'Microsoft.ContainerService/managedClusters',
    location: LOCATION,
    properties: {
      kubernetesVersion: '1.28.5',
      dnsPrefix: 'aks-prod-dns',
      fqdn: 'aks-prod-dns-' + SUB_ID.slice(0, 8) + '.hcp.' + LOCATION + '.azmk8s.io',
      agentPoolProfiles: [{
        name: 'system',
        count: 3,
        vmSize: 'Standard_D4s_v3',
        osType: 'Linux',
        osSKU: 'AzureLinux',
        mode: 'System',
        vnetSubnetID: subnetMap['AKS@vnet-prod'].id,
        maxPods: 110,
        enableAutoScaling: true,
        minCount: 3,
        maxCount: 10,
        provisioningState: 'Succeeded',
      }, {
        name: 'userpool',
        count: 5,
        vmSize: 'Standard_D8s_v3',
        osType: 'Linux',
        osSKU: 'AzureLinux',
        mode: 'User',
        vnetSubnetID: subnetMap['AKS@vnet-prod'].id,
        maxPods: 110,
        enableAutoScaling: true,
        minCount: 3,
        maxCount: 20,
        provisioningState: 'Succeeded',
      }],
      networkProfile: {
        networkPlugin: 'azure',
        networkPolicy: 'calico',
        serviceCidr: '10.200.0.0/16',
        dnsServiceIP: '10.200.0.10',
        loadBalancerSku: 'standard',
        outboundType: 'userDefinedRouting',
      },
      addonProfiles: {
        azureKeyvaultSecretsProvider: { enabled: true },
        azurepolicy: { enabled: true },
        omsagent: { enabled: true, config: { logAnalyticsWorkspaceResourceID: rid('rg-hub-networking', 'Microsoft.OperationalInsights', 'workspaces', 'law-hub') } },
      },
      aadProfile: { managed: true, enableAzureRBAC: true, tenantID: TENANT_ID },
      provisioningState: 'Succeeded',
      powerState: { code: 'Running' },
    },
    identity: { type: 'SystemAssigned', principalId: uuid(), tenantId: TENANT_ID },
    sku: { name: 'Base', tier: 'Standard' },
    tags: { environment: 'production', team: 'platform' },
  };

  // ─── Function Apps ───
  const functionApps = [];

  functionApps.push({
    id: rid('rg-prod-workloads', 'Microsoft.Web', 'sites', 'func-prod-processor'),
    name: 'func-prod-processor',
    type: 'Microsoft.Web/sites',
    kind: 'functionapp,linux',
    location: LOCATION,
    properties: {
      state: 'Running',
      defaultHostName: 'func-prod-processor.azurewebsites.net',
      httpsOnly: true,
      serverFarmId: rid('rg-prod-workloads', 'Microsoft.Web', 'serverfarms', 'asp-prod-functions'),
      virtualNetworkSubnetId: subnetMap['Functions@vnet-prod'].id,
      siteConfig: {
        linuxFxVersion: 'DOTNET-ISOLATED|8.0',
        ftpsState: 'Disabled',
        minTlsVersion: '1.2',
        vnetRouteAllEnabled: true,
      },
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'production' },
  });

  functionApps.push({
    id: rid('rg-prod-workloads', 'Microsoft.Web', 'sites', 'func-prod-eventhandler'),
    name: 'func-prod-eventhandler',
    type: 'Microsoft.Web/sites',
    kind: 'functionapp,linux',
    location: LOCATION,
    properties: {
      state: 'Running',
      defaultHostName: 'func-prod-eventhandler.azurewebsites.net',
      httpsOnly: true,
      serverFarmId: rid('rg-prod-workloads', 'Microsoft.Web', 'serverfarms', 'asp-prod-functions'),
      virtualNetworkSubnetId: subnetMap['Functions@vnet-prod'].id,
      siteConfig: {
        linuxFxVersion: 'Node|20',
        ftpsState: 'Disabled',
        minTlsVersion: '1.2',
        vnetRouteAllEnabled: true,
      },
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'production' },
  });

  // ─── SQL Servers & Databases ───
  const sqlServers = [];
  const sqlDatabases = [];

  sqlServers.push({
    id: sqlServerId,
    name: 'sql-data-prod',
    type: 'Microsoft.Sql/servers',
    location: LOCATION,
    properties: {
      fullyQualifiedDomainName: 'sql-data-prod.database.windows.net',
      administratorLogin: 'sqladmin',
      version: '12.0',
      state: 'Ready',
      publicNetworkAccess: 'Disabled',
      minimalTlsVersion: '1.2',
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'production', purpose: 'data-platform' },
  });

  ['db-orders', 'db-customers', 'db-analytics'].forEach(dbName => {
    sqlDatabases.push({
      id: sqlServerId + '/databases/' + dbName,
      name: dbName,
      type: 'Microsoft.Sql/servers/databases',
      location: LOCATION,
      properties: {
        status: 'Online',
        collation: 'SQL_Latin1_General_CP1_CI_AS',
        maxSizeBytes: 268435456000,
        currentServiceObjectiveName: dbName === 'db-analytics' ? 'GP_Gen5_8' : 'GP_Gen5_4',
        requestedServiceObjectiveName: dbName === 'db-analytics' ? 'GP_Gen5_8' : 'GP_Gen5_4',
        zoneRedundant: dbName !== 'db-analytics',
        readScale: 'Enabled',
        earliestRestoreDate: '2026-02-01T00:00:00Z',
        catalogCollation: 'SQL_Latin1_General_CP1_CI_AS',
        isInfraEncryptionEnabled: true,
        provisioningState: 'Succeeded',
      },
      sku: { name: dbName === 'db-analytics' ? 'GP_Gen5' : 'GP_Gen5', tier: 'GeneralPurpose', capacity: dbName === 'db-analytics' ? 8 : 4 },
      tags: { environment: 'production' },
    });
  });

  // PCI SQL server
  sqlServers.push({
    id: pciSqlId,
    name: 'sql-pci',
    type: 'Microsoft.Sql/servers',
    location: LOCATION,
    properties: {
      fullyQualifiedDomainName: 'sql-pci.database.windows.net',
      administratorLogin: 'pciadmin',
      version: '12.0',
      state: 'Ready',
      publicNetworkAccess: 'Disabled',
      minimalTlsVersion: '1.2',
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'pci', compliance: 'pci-dss' },
  });

  sqlDatabases.push({
    id: pciSqlId + '/databases/db-cardholder',
    name: 'db-cardholder',
    type: 'Microsoft.Sql/servers/databases',
    location: LOCATION,
    properties: {
      status: 'Online',
      collation: 'SQL_Latin1_General_CP1_CI_AS',
      maxSizeBytes: 107374182400,
      currentServiceObjectiveName: 'BC_Gen5_4',
      zoneRedundant: true,
      readScale: 'Enabled',
      isInfraEncryptionEnabled: true,
      provisioningState: 'Succeeded',
    },
    sku: { name: 'BC_Gen5', tier: 'BusinessCritical', capacity: 4 },
    tags: { environment: 'pci', compliance: 'pci-dss' },
  });

  // ─── Redis Caches ───
  const redisCaches = [];

  redisCaches.push({
    id: redisId,
    name: 'redis-data-prod',
    type: 'Microsoft.Cache/redis',
    location: LOCATION,
    properties: {
      hostName: 'redis-data-prod.redis.cache.windows.net',
      port: 6379,
      sslPort: 6380,
      provisioningState: 'Succeeded',
      redisVersion: '6.0',
      sku: { name: 'Premium', family: 'P', capacity: 2 },
      enableNonSslPort: false,
      minimumTlsVersion: '1.2',
      publicNetworkAccess: 'Disabled',
      replicasPerMaster: 1,
      subnetId: subnetMap['Redis@vnet-data'].id,
    },
    tags: { environment: 'production' },
  });

  redisCaches.push({
    id: rid('rg-staging-workloads', 'Microsoft.Cache', 'redis', 'redis-staging'),
    name: 'redis-staging',
    type: 'Microsoft.Cache/redis',
    location: LOCATION,
    properties: {
      hostName: 'redis-staging.redis.cache.windows.net',
      port: 6379,
      sslPort: 6380,
      provisioningState: 'Succeeded',
      redisVersion: '6.0',
      sku: { name: 'Standard', family: 'C', capacity: 1 },
      enableNonSslPort: false,
      minimumTlsVersion: '1.2',
      publicNetworkAccess: 'Enabled',
    },
    tags: { environment: 'staging' },
  });

  // ─── Storage Accounts ───
  const storageAccounts = [];

  // Compliant storage
  storageAccounts.push({
    id: storageId,
    name: 'stdataprodblob',
    type: 'Microsoft.Storage/storageAccounts',
    location: LOCATION,
    properties: {
      primaryEndpoints: { blob: 'https://stdataprodblob.blob.core.windows.net/', file: 'https://stdataprodblob.file.core.windows.net/', table: 'https://stdataprodblob.table.core.windows.net/', queue: 'https://stdataprodblob.queue.core.windows.net/' },
      provisioningState: 'Succeeded',
      supportsHttpsTrafficOnly: true,
      minimumTlsVersion: 'TLS1_2',
      allowBlobPublicAccess: false,
      networkAcls: { bypass: 'AzureServices', defaultAction: 'Deny', virtualNetworkRules: [{ id: subnetMap['Storage@vnet-data'].id, action: 'Allow' }], ipRules: [] },
      encryption: { services: { blob: { enabled: true, keyType: 'Account' }, file: { enabled: true, keyType: 'Account' } }, keySource: 'Microsoft.Storage' },
    },
    sku: { name: 'Standard_ZRS', tier: 'Standard' },
    kind: 'StorageV2',
    tags: { environment: 'production' },
  });

  // Compliance violation: TLS 1.0
  storageAccounts.push({
    id: rid('rg-dev-workloads', 'Microsoft.Storage', 'storageAccounts', 'stdevlegacy001'),
    name: 'stdevlegacy001',
    type: 'Microsoft.Storage/storageAccounts',
    location: LOCATION,
    properties: {
      primaryEndpoints: { blob: 'https://stdevlegacy001.blob.core.windows.net/' },
      provisioningState: 'Succeeded',
      supportsHttpsTrafficOnly: false,
      minimumTlsVersion: 'TLS1_0',
      allowBlobPublicAccess: false,
      networkAcls: { bypass: 'AzureServices', defaultAction: 'Allow', virtualNetworkRules: [], ipRules: [] },
      encryption: { services: { blob: { enabled: true, keyType: 'Account' } }, keySource: 'Microsoft.Storage' },
    },
    sku: { name: 'Standard_LRS', tier: 'Standard' },
    kind: 'StorageV2',
    tags: {},
  });

  // Compliance violation: public blob access enabled
  storageAccounts.push({
    id: rid('rg-dev-workloads', 'Microsoft.Storage', 'storageAccounts', 'stdevpublic002'),
    name: 'stdevpublic002',
    type: 'Microsoft.Storage/storageAccounts',
    location: LOCATION,
    properties: {
      primaryEndpoints: { blob: 'https://stdevpublic002.blob.core.windows.net/' },
      provisioningState: 'Succeeded',
      supportsHttpsTrafficOnly: true,
      minimumTlsVersion: 'TLS1_2',
      allowBlobPublicAccess: true,
      networkAcls: { bypass: 'AzureServices', defaultAction: 'Allow', virtualNetworkRules: [], ipRules: [] },
      encryption: { services: { blob: { enabled: true, keyType: 'Account' } }, keySource: 'Microsoft.Storage' },
    },
    sku: { name: 'Standard_LRS', tier: 'Standard' },
    kind: 'StorageV2',
    tags: {},
  });

  // PCI storage
  storageAccounts.push({
    id: rid('rg-pci-compliant', 'Microsoft.Storage', 'storageAccounts', 'stpciaudit'),
    name: 'stpciaudit',
    type: 'Microsoft.Storage/storageAccounts',
    location: LOCATION,
    properties: {
      primaryEndpoints: { blob: 'https://stpciaudit.blob.core.windows.net/' },
      provisioningState: 'Succeeded',
      supportsHttpsTrafficOnly: true,
      minimumTlsVersion: 'TLS1_2',
      allowBlobPublicAccess: false,
      networkAcls: { bypass: 'None', defaultAction: 'Deny', virtualNetworkRules: [{ id: subnetMap['PCI-Data@vnet-pci'].id, action: 'Allow' }], ipRules: [] },
      encryption: { services: { blob: { enabled: true, keyType: 'Account' } }, keySource: 'Microsoft.Keyvault', keyvaultproperties: { keyvaulturi: 'https://kv-pci.vault.azure.net/', keyname: 'pci-storage-key' } },
      immutableStorageWithVersioning: { enabled: true },
    },
    sku: { name: 'Standard_GRS', tier: 'Standard' },
    kind: 'StorageV2',
    tags: { environment: 'pci', compliance: 'pci-dss' },
  });

  // Hub shared storage
  storageAccounts.push({
    id: rid('rg-hub-networking', 'Microsoft.Storage', 'storageAccounts', 'sthubdiag'),
    name: 'sthubdiag',
    type: 'Microsoft.Storage/storageAccounts',
    location: LOCATION,
    properties: {
      primaryEndpoints: { blob: 'https://sthubdiag.blob.core.windows.net/' },
      provisioningState: 'Succeeded',
      supportsHttpsTrafficOnly: true,
      minimumTlsVersion: 'TLS1_2',
      allowBlobPublicAccess: false,
      networkAcls: { bypass: 'AzureServices,Logging,Metrics', defaultAction: 'Deny', virtualNetworkRules: [], ipRules: [] },
      encryption: { services: { blob: { enabled: true, keyType: 'Account' } }, keySource: 'Microsoft.Storage' },
    },
    sku: { name: 'Standard_LRS', tier: 'Standard' },
    kind: 'StorageV2',
    tags: { environment: 'shared', purpose: 'diagnostics' },
  });

  // ─── VNet Peerings ───
  const peerings = [];
  const hubVnet = vnets[0];
  const spokePairs = [
    { spoke: vnets[1], name: 'prod' },
    { spoke: vnets[2], name: 'staging' },
    { spoke: vnets[3], name: 'dev' },
    { spoke: vnets[4], name: 'data' },
    { spoke: vnets[5], name: 'pci' },
  ];

  spokePairs.forEach(sp => {
    // Hub -> Spoke
    peerings.push({
      id: hubVnet.id + '/virtualNetworkPeerings/peer-hub-to-' + sp.name,
      name: 'peer-hub-to-' + sp.name,
      type: 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings',
      properties: {
        peeringState: 'Connected',
        peeringSyncLevel: 'FullyInSync',
        remoteVirtualNetwork: { id: sp.spoke.id },
        allowVirtualNetworkAccess: true,
        allowForwardedTraffic: true,
        allowGatewayTransit: true,
        useRemoteGateways: false,
        remoteAddressSpace: { addressPrefixes: sp.spoke.properties.addressSpace.addressPrefixes },
        provisioningState: 'Succeeded',
      },
      _localVnetId: hubVnet.id,
      _remoteVnetId: sp.spoke.id,
    });

    // Spoke -> Hub
    peerings.push({
      id: sp.spoke.id + '/virtualNetworkPeerings/peer-' + sp.name + '-to-hub',
      name: 'peer-' + sp.name + '-to-hub',
      type: 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings',
      properties: {
        peeringState: 'Connected',
        peeringSyncLevel: 'FullyInSync',
        remoteVirtualNetwork: { id: hubVnet.id },
        allowVirtualNetworkAccess: true,
        allowForwardedTraffic: true,
        allowGatewayTransit: false,
        useRemoteGateways: true,
        remoteAddressSpace: { addressPrefixes: hubVnet.properties.addressSpace.addressPrefixes },
        provisioningState: 'Succeeded',
      },
      _localVnetId: sp.spoke.id,
      _remoteVnetId: hubVnet.id,
    });
  });

  // ─── RBAC Role Assignments ───
  const roleAssignments = [];

  // Subscription Owner (compliance violation: over-privileged)
  roleAssignments.push({
    id: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleAssignments/' + uuid(),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
      principalId: uuid(),
      principalType: 'User',
      scope: '/subscriptions/' + SUB_ID,
      createdOn: '2024-01-15T00:00:00Z',
      updatedOn: '2024-01-15T00:00:00Z',
      createdBy: null,
      updatedBy: null,
    },
    _roleName: 'Owner',
    _principalName: 'admin@contoso.com',
    _scope: '/subscriptions/' + SUB_ID,
  });

  // Contributor on prod RG
  roleAssignments.push({
    id: rid('rg-prod-workloads', 'Microsoft.Authorization', 'roleAssignments', uuid()),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c',
      principalId: uuid(),
      principalType: 'Group',
      scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-prod-workloads',
      createdOn: '2024-02-01T00:00:00Z',
    },
    _roleName: 'Contributor',
    _principalName: 'sg-prod-contributors',
    _scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-prod-workloads',
  });

  // Reader on dev RG
  roleAssignments.push({
    id: rid('rg-dev-workloads', 'Microsoft.Authorization', 'roleAssignments', uuid()),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7',
      principalId: uuid(),
      principalType: 'Group',
      scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-dev-workloads',
      createdOn: '2024-03-01T00:00:00Z',
    },
    _roleName: 'Reader',
    _principalName: 'sg-dev-readers',
    _scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-dev-workloads',
  });

  // Network Contributor on hub RG
  roleAssignments.push({
    id: rid('rg-hub-networking', 'Microsoft.Authorization', 'roleAssignments', uuid()),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7',
      principalId: uuid(),
      principalType: 'Group',
      scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-hub-networking',
      createdOn: '2024-01-20T00:00:00Z',
    },
    _roleName: 'Network Contributor',
    _principalName: 'sg-network-admins',
    _scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-hub-networking',
  });

  // Custom role with wildcard (compliance violation)
  roleAssignments.push({
    id: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleAssignments/' + uuid(),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/' + uuid(),
      principalId: uuid(),
      principalType: 'ServicePrincipal',
      scope: '/subscriptions/' + SUB_ID,
      createdOn: '2024-06-01T00:00:00Z',
    },
    _roleName: 'Custom-SuperAdmin',
    _principalName: 'sp-legacy-automation',
    _scope: '/subscriptions/' + SUB_ID,
    _customRoleActions: ['*'],
    _customRoleNotActions: [],
  });

  // Guest user with Contributor (compliance violation)
  roleAssignments.push({
    id: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleAssignments/' + uuid(),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c',
      principalId: uuid(),
      principalType: 'User',
      scope: '/subscriptions/' + SUB_ID,
      createdOn: '2024-07-15T00:00:00Z',
    },
    _roleName: 'Contributor',
    _principalName: 'guest_vendor@external.com',
    _principalIsGuest: true,
    _scope: '/subscriptions/' + SUB_ID,
  });

  // AKS managed identity role
  roleAssignments.push({
    id: rid('rg-prod-workloads', 'Microsoft.Authorization', 'roleAssignments', uuid()),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7',
      principalId: aksCluster.identity.principalId,
      principalType: 'ServicePrincipal',
      scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-prod-workloads',
      createdOn: '2024-04-01T00:00:00Z',
    },
    _roleName: 'Network Contributor',
    _principalName: 'aks-prod-identity',
    _scope: '/subscriptions/' + SUB_ID + '/resourceGroups/rg-prod-workloads',
  });

  // Key Vault Secrets User
  roleAssignments.push({
    id: rid('rg-hub-networking', 'Microsoft.Authorization', 'roleAssignments', uuid()),
    name: uuid(),
    type: 'Microsoft.Authorization/roleAssignments',
    properties: {
      roleDefinitionId: '/subscriptions/' + SUB_ID + '/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6',
      principalId: uuid(),
      principalType: 'Group',
      scope: kvId,
      createdOn: '2024-05-01T00:00:00Z',
    },
    _roleName: 'Key Vault Secrets User',
    _principalName: 'sg-app-developers',
    _scope: kvId,
  });

  // ─── DNS Zones ───
  const dnsZones = [
    { id: rid('rg-hub-networking', 'Microsoft.Network', 'privateDnsZones', 'contoso.internal'), name: 'contoso.internal', type: 'Microsoft.Network/privateDnsZones', location: 'global', properties: { numberOfRecordSets: 45, maxNumberOfRecordSets: 25000, provisioningState: 'Succeeded' }, tags: { environment: 'shared' } },
    { id: rid('rg-hub-networking', 'Microsoft.Network', 'privateDnsZones', 'privatelink.database.windows.net'), name: 'privatelink.database.windows.net', type: 'Microsoft.Network/privateDnsZones', location: 'global', properties: { numberOfRecordSets: 8, provisioningState: 'Succeeded' }, tags: { environment: 'shared' } },
    { id: rid('rg-hub-networking', 'Microsoft.Network', 'privateDnsZones', 'privatelink.redis.cache.windows.net'), name: 'privatelink.redis.cache.windows.net', type: 'Microsoft.Network/privateDnsZones', location: 'global', properties: { numberOfRecordSets: 3, provisioningState: 'Succeeded' }, tags: { environment: 'shared' } },
    { id: rid('rg-hub-networking', 'Microsoft.Network', 'privateDnsZones', 'privatelink.blob.core.windows.net'), name: 'privatelink.blob.core.windows.net', type: 'Microsoft.Network/privateDnsZones', location: 'global', properties: { numberOfRecordSets: 5, provisioningState: 'Succeeded' }, tags: { environment: 'shared' } },
    { id: rid('rg-hub-networking', 'Microsoft.Network', 'privateDnsZones', 'privatelink.vaultcore.azure.net'), name: 'privatelink.vaultcore.azure.net', type: 'Microsoft.Network/privateDnsZones', location: 'global', properties: { numberOfRecordSets: 2, provisioningState: 'Succeeded' }, tags: { environment: 'shared' } },
  ];

  // ─── Key Vault ───
  const keyVaults = [{
    id: kvId,
    name: 'kv-hub-shared',
    type: 'Microsoft.KeyVault/vaults',
    location: LOCATION,
    properties: {
      vaultUri: 'https://kv-hub-shared.vault.azure.net/',
      tenantId: TENANT_ID,
      sku: { family: 'A', name: 'premium' },
      enabledForDeployment: true,
      enabledForDiskEncryption: true,
      enabledForTemplateDeployment: true,
      enableSoftDelete: true,
      softDeleteRetentionInDays: 90,
      enableRbacAuthorization: true,
      enablePurgeProtection: true,
      publicNetworkAccess: 'Disabled',
      networkAcls: { bypass: 'AzureServices', defaultAction: 'Deny', ipRules: [], virtualNetworkRules: [] },
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'shared', purpose: 'key-management' },
  }];

  // ─── Synapse Workspace ───
  const synapseWorkspaces = [{
    id: rid('rg-data-platform', 'Microsoft.Synapse', 'workspaces', 'synapse-data-prod'),
    name: 'synapse-data-prod',
    type: 'Microsoft.Synapse/workspaces',
    location: LOCATION,
    properties: {
      defaultDataLakeStorage: { accountUrl: 'https://stdataprodblob.dfs.core.windows.net', filesystem: 'synapse' },
      sqlAdministratorLogin: 'synapseadmin',
      managedVirtualNetwork: 'default',
      connectivityEndpoints: { dev: 'https://synapse-data-prod.dev.azuresynapse.net', sql: 'synapse-data-prod.sql.azuresynapse.net', sqlOnDemand: 'synapse-data-prod-ondemand.sql.azuresynapse.net', web: 'https://web.azuresynapse.net?workspace=%2fsubscriptions%2f' + SUB_ID + '%2fresourceGroups%2frg-data-platform%2fproviders%2fMicrosoft.Synapse%2fworkspaces%2fsynapse-data-prod' },
      managedResourceGroupName: 'rg-synapse-managed',
      publicNetworkAccess: 'Disabled',
      provisioningState: 'Succeeded',
    },
    identity: { type: 'SystemAssigned', principalId: uuid(), tenantId: TENANT_ID },
    tags: { environment: 'production', purpose: 'analytics' },
  }];

  // ─── Log Analytics Workspace ───
  const logAnalyticsWorkspaces = [{
    id: rid('rg-hub-networking', 'Microsoft.OperationalInsights', 'workspaces', 'law-hub'),
    name: 'law-hub',
    type: 'Microsoft.OperationalInsights/workspaces',
    location: LOCATION,
    properties: {
      sku: { name: 'PerGB2018' },
      retentionInDays: 90,
      workspaceCapping: { dailyQuotaGb: 10 },
      publicNetworkAccessForIngestion: 'Enabled',
      publicNetworkAccessForQuery: 'Enabled',
      provisioningState: 'Succeeded',
    },
    tags: { environment: 'shared', purpose: 'monitoring' },
  }];

  // ─── Assemble return object ───
  // Map to AWS-like structure for backward compatibility with existing consumers
  // The keys match what the rest of the codebase expects from generateDemo()
  return {
    // Core networking
    vpcs: { Vpcs: vnets.map(v => ({
      VpcId: v.id,
      CidrBlock: v.properties.addressSpace.addressPrefixes[0],
      State: 'available',
      Tags: [{ Key: 'Name', Value: v.name }],
      _azure: v,
    }))},
    subnets: { Subnets: allSubnets.map(s => ({
      SubnetId: s.id,
      VpcId: s._vnetName ? vnets.find(v => v.name === s._vnetName)?.id : '',
      CidrBlock: s.properties.addressPrefix,
      AvailabilityZone: LOCATION,
      MapPublicIpOnLaunch: false,
      Tags: [{ Key: 'Name', Value: s._vnetName + '-' + s.name }],
      _azure: s,
    }))},
    rts: { RouteTables: routeTables.map(rt => ({
      RouteTableId: rt.id,
      VpcId: '',
      Routes: (rt.properties.routes || []).map(r => ({
        DestinationCidrBlock: r.properties.addressPrefix,
        GatewayId: r.properties.nextHopType === 'VnetLocal' ? 'local' : undefined,
        NatGatewayId: r.properties.nextHopType === 'VirtualAppliance' ? r.properties.nextHopIpAddress : undefined,
      })),
      Associations: [],
      Tags: [{ Key: 'Name', Value: rt.name }],
      _azure: rt,
    }))},
    sgs: { SecurityGroups: nsgs.map(nsg => ({
      GroupId: nsg.id,
      GroupName: nsg.name,
      VpcId: '',
      IpPermissions: (nsg.properties.securityRules || []).filter(r => r.properties.direction === 'Inbound').map(r => ({
        IpProtocol: r.properties.protocol === '*' ? '-1' : r.properties.protocol.toLowerCase(),
        FromPort: r.properties.destinationPortRange === '*' ? 0 : parseInt(r.properties.destinationPortRange) || 0,
        ToPort: r.properties.destinationPortRange === '*' ? 65535 : parseInt((r.properties.destinationPortRange || '').split('-').pop()) || 0,
        IpRanges: [{ CidrIp: r.properties.sourceAddressPrefix }],
      })),
      IpPermissionsEgress: (nsg.properties.securityRules || []).filter(r => r.properties.direction === 'Outbound').map(r => ({
        IpProtocol: r.properties.protocol === '*' ? '-1' : r.properties.protocol.toLowerCase(),
        IpRanges: [{ CidrIp: r.properties.destinationAddressPrefix }],
      })),
      Tags: [{ Key: 'Name', Value: nsg.name }],
      _azure: nsg,
    }))},
    nacls: { NetworkAcls: [] },
    igws: { InternetGateways: [] },
    nats: { NatGateways: natGateways.map(ng => ({
      NatGatewayId: ng.id,
      VpcId: '',
      SubnetId: (ng.properties.subnets || [])[0]?.id || '',
      State: 'available',
      Tags: [{ Key: 'Name', Value: ng.name }],
      _azure: ng,
    }))},
    ec2: { Reservations: [{ Instances: vms.map(vm => ({
      InstanceId: vm.id,
      SubnetId: nics.find(n => n.properties.virtualMachine?.id === vm.id)?.properties.ipConfigurations[0]?.properties.subnet?.id || '',
      InstanceType: vm.properties.hardwareProfile.vmSize,
      PrivateIpAddress: nics.find(n => n.properties.virtualMachine?.id === vm.id)?.properties.ipConfigurations[0]?.properties.privateIPAddress || '',
      Placement: { AvailabilityZone: LOCATION },
      State: { Name: vm.properties.instanceView?.statuses[0]?.code === 'PowerState/running' ? 'running' : 'stopped', Code: vm.properties.instanceView?.statuses[0]?.code === 'PowerState/running' ? 16 : 80 },
      Tags: [{ Key: 'Name', Value: vm.name }],
      _azure: vm,
    }))}]},
    albs: { LoadBalancers: [
      ...loadBalancers.map(lb => ({
        LoadBalancerArn: lb.id,
        LoadBalancerName: lb.name,
        Type: 'network',
        Scheme: 'internal',
        VpcId: '',
        AvailabilityZones: [],
        State: { Code: 'active' },
        DNSName: lb.name + '.' + LOCATION + '.cloudapp.azure.com',
        _azure: lb,
      })),
      ...appGateways.map(ag => ({
        LoadBalancerArn: ag.id,
        LoadBalancerName: ag.name,
        Type: 'application',
        Scheme: 'internet-facing',
        VpcId: '',
        AvailabilityZones: [],
        State: { Code: 'active' },
        DNSName: ag.name + '.' + LOCATION + '.cloudapp.azure.com',
        _azure: ag,
      })),
    ]},
    vpces: { VpcEndpoints: privateEndpoints.map(pe => ({
      VpcEndpointId: pe.id,
      VpcId: '',
      ServiceName: (pe.properties.privateLinkServiceConnections[0]?.properties.groupIds || [])[0] || '',
      VpcEndpointType: 'Interface',
      State: 'available',
      SubnetIds: [pe.properties.subnet.id],
      Tags: [{ Key: 'Name', Value: pe.name }],
      _azure: pe,
    }))},
    peer: { VpcPeeringConnections: peerings.map(p => ({
      VpcPeeringConnectionId: p.id,
      Status: { Code: p.properties.peeringState === 'Connected' ? 'active' : 'pending' },
      RequesterVpcInfo: { VpcId: p._localVnetId, CidrBlock: '' },
      AccepterVpcInfo: { VpcId: p._remoteVnetId, CidrBlock: '' },
      Tags: [{ Key: 'Name', Value: p.name }],
      _azure: p,
    }))},
    vpn: { VpnConnections: [{
      VpnConnectionId: vpnConnection.id,
      State: 'available',
      VpnGatewayId: vpnGateway.id,
      CustomerGatewayId: localNetworkGateway.id,
      Tags: [{ Key: 'Name', Value: vpnConnection.name }],
      _azure: vpnConnection,
    }]},
    vols: { Volumes: [] },
    snaps: { Snapshots: [] },
    s3: { Buckets: storageAccounts.map(sa => ({
      Name: sa.name,
      CreationDate: '2025-01-15',
      _azure: sa,
    }))},
    r53: { HostedZones: dnsZones.map(dz => ({
      Id: dz.id,
      Name: dz.name,
      Config: { PrivateZone: true },
      ResourceRecordSetCount: dz.properties.numberOfRecordSets || 0,
      _azure: dz,
    }))},
    r53records: { ResourceRecordSets: [] },
    tgs: { TargetGroups: [] },
    enis: { NetworkInterfaces: nics.map(nic => ({
      NetworkInterfaceId: nic.id,
      SubnetId: nic.properties.ipConfigurations[0]?.properties.subnet?.id || '',
      VpcId: '',
      InterfaceType: 'interface',
      Status: 'in-use',
      Attachment: {
        InstanceId: nic.properties.virtualMachine?.id || '',
        Status: 'attached',
      },
      _azure: nic,
    }))},
    waf: { WebACLs: appGateways.filter(ag => ag.properties.webApplicationFirewallConfiguration).map(ag => ({
      Name: ag.name + '-waf',
      Id: ag.id,
      ARN: ag.id,
      Description: ag.name + ' WAF configuration',
      DefaultAction: { Allow: {} },
      Rules: [
        { Name: 'OWASP-3.2', Priority: 1 },
        { Name: 'BotProtection', Priority: 2 },
      ],
      ResourceArns: [ag.id],
      _azure: ag.properties.webApplicationFirewallConfiguration,
    }))},
    rds: { DBInstances: sqlServers.map(srv => ({
      DBInstanceIdentifier: srv.name,
      DBInstanceClass: 'GeneralPurpose',
      Engine: 'azure-sql',
      DBInstanceStatus: 'available',
      MultiAZ: true,
      AllocatedStorage: 256,
      Endpoint: { Address: srv.properties.fullyQualifiedDomainName, Port: 1433 },
      DBSubnetGroup: { VpcId: '', DBSubnetGroupName: srv.name + '-subnet' },
      StorageEncrypted: true,
      AvailabilityZone: LOCATION,
      _azure: srv,
      _databases: sqlDatabases.filter(db => db.id.startsWith(srv.id)),
    }))},
    ecs: { services: [{
      serviceName: aksCluster.name,
      clusterArn: aksCluster.id,
      status: 'ACTIVE',
      desiredCount: aksCluster.properties.agentPoolProfiles.reduce((a, p) => a + p.count, 0),
      runningCount: aksCluster.properties.agentPoolProfiles.reduce((a, p) => a + p.count, 0),
      launchType: 'KUBERNETES',
      _azure: aksCluster,
    }]},
    lambda: { Functions: functionApps.map(fa => ({
      FunctionName: fa.name,
      Runtime: fa.properties.siteConfig?.linuxFxVersion || 'unknown',
      FunctionArn: fa.id,
      State: fa.properties.state === 'Running' ? 'Active' : 'Inactive',
      LastModified: '2026-01-20T00:00:00Z',
      VpcConfig: {
        VpcId: '',
        SubnetIds: [fa.properties.virtualNetworkSubnetId].filter(Boolean),
        SecurityGroupIds: [],
      },
      _azure: fa,
    }))},
    elasticache: { CacheClusters: redisCaches.map(rc => ({
      CacheClusterId: rc.name,
      Engine: 'redis',
      CacheNodeType: rc.properties.sku.name + '_' + rc.properties.sku.family + rc.properties.sku.capacity,
      CacheClusterStatus: 'available',
      NumCacheNodes: 1,
      VpcId: '',
      CacheNodes: [{ CacheNodeId: '0001', CacheNodeStatus: 'available', Endpoint: { Address: rc.properties.hostName, Port: rc.properties.sslPort } }],
      _azure: rc,
    }))},
    redshift: { Clusters: synapseWorkspaces.map(sw => ({
      ClusterIdentifier: sw.name,
      NodeType: 'synapse-workspace',
      ClusterStatus: 'available',
      DBName: 'synapse',
      Endpoint: { Address: sw.properties.connectivityEndpoints?.sql || '', Port: 1433 },
      VpcId: '',
      Encrypted: true,
      _azure: sw,
    }))},
    tgwatt: { TransitGatewayAttachments: [] },
    cf: { DistributionList: { Items: [] } },
    iam: {
      RoleDetailList: roleAssignments.filter(r => r._roleName !== 'Reader' && r._roleName !== 'Key Vault Secrets User').map(ra => ({
        RoleName: ra._roleName + ' (' + ra._principalName + ')',
        Arn: ra.id,
        CreateDate: ra.properties.createdOn || '2024-01-01T00:00:00Z',
        AssumeRolePolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Azure: ra._principalName }, Action: 'AssumeRole' }] },
        RolePolicyList: ra._customRoleActions ? [{ PolicyName: ra._roleName, PolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ra._customRoleActions, Resource: '*' }] } }] : [],
        AttachedManagedPolicies: [{ PolicyArn: ra.properties.roleDefinitionId, PolicyName: ra._roleName }],
        RoleLastUsed: { LastUsedDate: new Date().toISOString() },
        _azure: ra,
      })),
      UserDetailList: [],
      Policies: [],
    },

    // Azure-native data (full fidelity)
    _azure: {
      subscriptionId: SUB_ID,
      tenantId: TENANT_ID,
      location: LOCATION,
      resourceGroups: resourceGroups,
      vnets: vnets,
      subnets: allSubnets,
      nsgs: nsgs,
      routeTables: routeTables,
      vms: vms,
      nics: nics,
      publicIps: publicIps,
      natGateways: natGateways,
      appGateways: appGateways,
      loadBalancers: loadBalancers,
      privateEndpoints: privateEndpoints,
      peerings: peerings,
      azureFirewall: azureFirewall,
      bastion: bastion,
      vpnGateway: vpnGateway,
      localNetworkGateway: localNetworkGateway,
      vpnConnection: vpnConnection,
      aksCluster: aksCluster,
      functionApps: functionApps,
      sqlServers: sqlServers,
      sqlDatabases: sqlDatabases,
      redisCaches: redisCaches,
      storageAccounts: storageAccounts,
      keyVaults: keyVaults,
      dnsZones: dnsZones,
      synapseWorkspaces: synapseWorkspaces,
      logAnalyticsWorkspaces: logAnalyticsWorkspaces,
      roleAssignments: roleAssignments,
      lighthouse: {
        subscriptionId: LH_SUB_ID,
        tenantId: LH_TENANT_ID,
        vnet: vnets.find(v => v._isLighthouse),
      },
    },
  };
}
