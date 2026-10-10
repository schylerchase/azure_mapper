import { _loc, _proto, _armTags, _armId, _nsgSelectors, _natPublicIps, _subnetNatId, _selectIacData, _iacExportBlock } from "./iac-resource-formatters.js";

// ============================================================
// 2. ARM TEMPLATE GENERATION
// ============================================================

export function generateARM(data, options) {
  if (!data) return { code: '{}', warnings: [], stats: {} };
  const opts = options || {};
  data = _selectIacData(data, opts);
  const blocked = _iacExportBlock(data, 'arm');
  if (blocked) return blocked;
  const warnings = [];

  const vnets = data.vnets || [];
  const nsgs = (data.nsgs || []).concat(data.subnetNsgs || []);
  const udrs = data.udrs || [];
  const natGateways = data.natGateways || [];
  const vms = data.vms || [];
  const nics = data.nics || [];
  const disks = data.disks || [];
  const peerings = data.peerings || [];
  const firewalls = data.firewalls || [];
  const bastions = data.bastions || [];

  // Deduplicate NSGs
  const nsgMap = new Map();
  nsgs.forEach(n => { if (n.id) nsgMap.set(n.id.toLowerCase(), n); });
  const uniqueNsgs = Array.from(nsgMap.values());

  const primaryLocation = vnets.length ? _loc(vnets[0]) : 'eastus';

  const template = {
    '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    contentVersion: '1.0.0.0',
    parameters: {
      location: {
        type: 'string',
        defaultValue: vnets[0]?.location || '[resourceGroup().location]',
        metadata: { description: 'Azure region for all resources' }
      },
      adminUsername: {
        type: 'string',
        defaultValue: 'azureadmin',
        metadata: { description: 'Admin username for VMs' }
      },
      adminPassword: {
        type: 'securestring',
        metadata: { description: 'Admin password for VMs' }
      }
    },
    variables: {},
    resources: [],
    outputs: {}
  };

  const resources = template.resources;
  const seen = new Set();

  // --- NSGs ---
  uniqueNsgs.forEach(nsg => {
    const secRules = ((nsg.properties || nsg).securityRules || []).map(rule => {
      const rp = rule.properties || rule;
      const armRule = {
        name: rule.name || 'rule',
        properties: {
          priority: rp.priority || 100,
          direction: rp.direction || 'Inbound',
          access: rp.access || 'Allow',
          protocol: _proto(rp.protocol),
          ..._nsgSelectors(rp)
        }
      };
      return armRule;
    });

    resources.push({
      type: 'Microsoft.Network/networkSecurityGroups',
      apiVersion: '2023-04-01',
      name: nsg.name || 'nsg',
      location: '[parameters(\'location\')]',
      tags: _armTags(nsg),
      properties: {
        securityRules: secRules
      }
    });
  });

  // --- Route Tables ---
  udrs.forEach(udr => {
    const routes = ((udr.properties || udr).routes || []).map(route => {
      const rp = route.properties || route;
      const armRoute = {
        name: route.name || 'route',
        properties: {
          addressPrefix: rp.addressPrefix || '0.0.0.0/0',
          nextHopType: rp.nextHopType || 'None'
        }
      };
      if (rp.nextHopIpAddress) armRoute.properties.nextHopIpAddress = rp.nextHopIpAddress;
      return armRoute;
    });

    resources.push({
      type: 'Microsoft.Network/routeTables',
      apiVersion: '2023-04-01',
      name: udr.name || 'rt',
      location: '[parameters(\'location\')]',
      tags: _armTags(udr),
      properties: {
        disableBgpRoutePropagation: (udr.properties || udr).disableBgpRoutePropagation || false,
        routes: routes
      }
    });
  });

  // --- Virtual Networks (with inline subnets) ---
  vnets.forEach(vnet => {
    const addrSpace = (vnet.properties || vnet).addressSpace?.addressPrefixes || ['10.0.0.0/16'];
    const subnets = ((vnet.properties || vnet).subnets || []).map(sub => {
      const sp = sub.properties || sub;
      const armSub = {
        name: sub.name || 'subnet',
        properties: {
          ...(sp.addressPrefixes?.length ? { addressPrefixes: sp.addressPrefixes.slice() } : { addressPrefix: sp.addressPrefix || '10.0.0.0/24' })
        }
      };
      if (sp.networkSecurityGroup?.id) {
        const nsgName = sp.networkSecurityGroup.id.split('/').pop();
        armSub.properties.networkSecurityGroup = {
          id: '[resourceId(\'Microsoft.Network/networkSecurityGroups\', \'' + nsgName + '\')]'
        };
      }
      if (sp.routeTable?.id) {
        const rtName = sp.routeTable.id.split('/').pop();
        armSub.properties.routeTable = {
          id: '[resourceId(\'Microsoft.Network/routeTables\', \'' + rtName + '\')]'
        };
      }
      const natId = _subnetNatId(sub, natGateways);
      if (natId) armSub.properties.natGateway = { id: '[resourceId(\'Microsoft.Network/natGateways\', \'' + natId.split('/').pop() + '\')]' };
      const svcEndpoints = sp.serviceEndpoints || [];
      if (svcEndpoints.length) {
        armSub.properties.serviceEndpoints = svcEndpoints.map(se => ({ service: se.service }));
      }
      const delegations = sp.delegations || [];
      if (delegations.length) {
        armSub.properties.delegations = delegations.map(d => ({
          name: d.name || 'delegation',
          properties: { serviceName: d.properties?.serviceName || '' }
        }));
      }
      return armSub;
    });

    const dependsOn = [];
    uniqueNsgs.forEach(nsg => dependsOn.push('[resourceId(\'Microsoft.Network/networkSecurityGroups\', \'' + nsg.name + '\')]'));
    udrs.forEach(udr => dependsOn.push('[resourceId(\'Microsoft.Network/routeTables\', \'' + udr.name + '\')]'));
    natGateways.forEach(nat => dependsOn.push('[resourceId(\'Microsoft.Network/natGateways\', \'' + nat.name + '\')]'));

    if (vnet._iacExistingParent) {
      subnets.forEach(subnet => resources.push({
        type: 'Microsoft.Network/virtualNetworks/subnets', apiVersion: '2023-04-01',
        name: (vnet.name || 'vnet') + '/' + subnet.name,
        dependsOn, properties: subnet.properties
      }));
      return;
    }

    resources.push({
      type: 'Microsoft.Network/virtualNetworks',
      apiVersion: '2023-04-01',
      name: vnet.name || 'vnet',
      location: '[parameters(\'location\')]',
      tags: _armTags(vnet),
      dependsOn: dependsOn,
      properties: {
        addressSpace: { addressPrefixes: addrSpace },
        subnets: subnets
      }
    });
  });

  // --- NAT Public IPs and Gateways ---
  _natPublicIps(data).forEach(pip => {
    resources.push({
      type: 'Microsoft.Network/publicIPAddresses', apiVersion: '2023-04-01',
      name: pip.name || pip.id.split('/').pop(), location: '[parameters(\'location\')]',
      sku: { name: pip.sku?.name || 'Standard' }, tags: _armTags(pip),
      properties: { publicIPAllocationMethod: (pip.properties || pip).publicIPAllocationMethod || 'Static' }
    });
  });
  natGateways.forEach(nat => {
    const np = nat.properties || nat;
    const publicIpAddresses = (np.publicIpAddresses || []).filter(pip => pip.id).map(pip => ({ id: '[resourceId(\'Microsoft.Network/publicIPAddresses\', \'' + pip.id.split('/').pop() + '\')]' }));
    const publicIpPrefixes = (np.publicIpPrefixes || []).filter(prefix => prefix.id).map(prefix => ({ id: prefix.id }));
    resources.push({
      type: 'Microsoft.Network/natGateways',
      apiVersion: '2023-04-01',
      name: nat.name || 'natgw',
      location: '[parameters(\'location\')]',
      tags: _armTags(nat),
      sku: { name: nat.sku?.name || 'Standard' },
      dependsOn: publicIpAddresses.map(pip => pip.id),
      properties: {
        idleTimeoutInMinutes: np.idleTimeoutInMinutes || 4,
        ...(publicIpAddresses.length ? { publicIpAddresses } : {}),
        ...(publicIpPrefixes.length ? { publicIpPrefixes } : {})
      }
    });
  });

  // --- Network Interfaces ---
  nics.forEach(nic => {
    const np = nic.properties || nic;
    const ipConfigs = (np.ipConfigurations || []).map(ipc => {
      const ipcProps = ipc.properties || ipc;
      const armIpc = {
        name: ipc.name || 'ipconfig',
        properties: {
          privateIPAllocationMethod: ipcProps.privateIPAllocationMethod || 'Dynamic'
        }
      };
      if (ipcProps.privateIPAddressVersion) armIpc.properties.privateIPAddressVersion = ipcProps.privateIPAddressVersion;
      if (typeof ipcProps.primary === 'boolean') armIpc.properties.primary = ipcProps.primary;
      if (ipcProps.publicIPAddress?.id) armIpc.properties.publicIPAddress = { id: ipcProps.publicIPAddress.id };
      if (ipcProps.subnet?.id) {
        const parts = ipcProps.subnet.id.split('/');
        const vnetName = parts[parts.indexOf('virtualNetworks') + 1] || 'vnet';
        const subName = parts[parts.indexOf('subnets') + 1] || 'subnet';
        armIpc.properties.subnet = {
          id: '[resourceId(\'Microsoft.Network/virtualNetworks/subnets\', \'' + vnetName + '\', \'' + subName + '\')]'
        };
      }
      if (ipcProps.privateIPAddress && ipcProps.privateIPAllocationMethod === 'Static') {
        armIpc.properties.privateIPAddress = ipcProps.privateIPAddress;
      }
      return armIpc;
    });

    const nicDeps = [];
    vnets.forEach(v => nicDeps.push('[resourceId(\'Microsoft.Network/virtualNetworks\', \'' + v.name + '\')]'));
    const nsgId = np.networkSecurityGroup?.id;
    const nsgRef = nsgId && '[resourceId(\'Microsoft.Network/networkSecurityGroups\', \'' + nsgId.split('/').pop() + '\')]';
    if (nsgRef) nicDeps.push(nsgRef);

    resources.push({
      type: 'Microsoft.Network/networkInterfaces',
      apiVersion: '2023-04-01',
      name: nic.name || 'nic',
      location: '[parameters(\'location\')]',
      tags: _armTags(nic),
      dependsOn: nicDeps,
      properties: {
        ipConfigurations: ipConfigs,
        ...(nsgRef ? { networkSecurityGroup: { id: nsgRef } } : {})
      }
    });
  });

  // --- Virtual Machines ---
  vms.forEach(vm => {
    const vmp = vm.properties || vm;
    const osProfile = vmp.osProfile || {};
    const isWindows = !!(osProfile.windowsConfiguration || (vmp.storageProfile?.osDisk?.osType || '').toLowerCase() === 'windows');
    const imgRef = vmp.storageProfile?.imageReference || {};
    const osDisk = vmp.storageProfile?.osDisk || {};
    const attachedOs = String(osDisk.createOption || '').toLowerCase() === 'attach';
    const nicRefs = (vmp.networkProfile?.networkInterfaces || []).map(n => {
      const nicName = n.id ? n.id.split('/').pop() : 'nic';
      const generated = nics.some(nic => String(nic.id || '').toLowerCase() === String(n.id || '').toLowerCase());
      const primary = (n.properties || n).primary;
      return { id: generated ? '[resourceId(\'Microsoft.Network/networkInterfaces\', \'' + nicName + '\')]' : n.id,
        ...(typeof primary === 'boolean' ? { properties: { primary } } : {}) };
    });
    const vmDeps = nicRefs.map(n => n.id.replaceAll('[', '').replaceAll(']', '').replace('resourceId', '[resourceId'));
    const diskDeps = [];
    const dataDisks = (vmp.storageProfile?.dataDisks || []).map(disk => {
      const ref = { ...disk, ...(disk.managedDisk?.id ? { createOption: 'Attach' } : {}) };
      const generated = disks.find(resource => String(resource.id || '').toLowerCase() === String(disk.managedDisk?.id || '').toLowerCase());
      if (generated) {
        const id = '[resourceId(\'Microsoft.Compute/disks\', \'' + generated.name + '\')]';
        ref.managedDisk = { ...disk.managedDisk, id };
        diskDeps.push(id);
      }
      return ref;
    });

    const vmResource = {
      type: 'Microsoft.Compute/virtualMachines',
      apiVersion: '2023-07-01',
      name: vm.name || 'vm',
      location: '[parameters(\'location\')]',
      tags: _armTags(vm),
      dependsOn: nics.map(n => '[resourceId(\'Microsoft.Network/networkInterfaces\', \'' + n.name + '\')]').concat(diskDeps),
      properties: {
        hardwareProfile: { vmSize: vmp.hardwareProfile?.vmSize || 'Standard_B2s' },
        storageProfile: {
          ...(!attachedOs ? { imageReference: imgRef.id ? { id: imgRef.id } : {
            publisher: imgRef.publisher || (isWindows ? 'MicrosoftWindowsServer' : 'Canonical'),
            offer: imgRef.offer || (isWindows ? 'WindowsServer' : '0001-com-ubuntu-server-jammy'),
            sku: imgRef.sku || (isWindows ? '2022-datacenter-g2' : '22_04-lts-gen2'),
            version: imgRef.version || 'latest'
          } } : {}),
          osDisk: attachedOs ? { ...osDisk, createOption: 'Attach', managedDisk: { ...osDisk.managedDisk } } : {
            createOption: osDisk.createOption || 'FromImage',
            managedDisk: {
              storageAccountType: osDisk.managedDisk?.storageAccountType || 'Standard_LRS'
            }
          },
          ...(dataDisks.length ? { dataDisks } : {})
        },
        ...(!attachedOs ? { osProfile: {
          computerName: vm.name || 'vm',
          adminUsername: '[parameters(\'adminUsername\')]',
          adminPassword: '[parameters(\'adminPassword\')]'
        } } : {}),
        networkProfile: {
          networkInterfaces: nicRefs
        }
      }
    };
    resources.push(vmResource);
  });

  // --- Managed Disks ---
  disks.forEach(disk => {
    const dp = disk.properties || disk;
    resources.push({
      type: 'Microsoft.Compute/disks',
      apiVersion: '2023-04-02',
      name: disk.name || 'disk',
      location: '[parameters(\'location\')]',
      tags: _armTags(disk),
      sku: { name: dp.accountType || disk.sku?.name || 'Standard_LRS' },
      properties: {
        creationData: { ...(dp.creationData || {}), createOption: dp.creationData?.createOption || 'Empty' },
        diskSizeGB: dp.diskSizeGB || 128
      }
    });
  });

  // --- Azure Firewall ---
  firewalls.forEach(fw => {
    const fwp = fw.properties || {};
    const ipConfigs = (fwp.ipConfigurations || []).map(ipc => ({
      name: ipc.name || 'fw-ipconfig',
      properties: {
        subnet: ipc.properties?.subnet ? { id: ipc.properties.subnet.id } : undefined,
        publicIPAddress: ipc.properties?.publicIPAddress ? { id: ipc.properties.publicIPAddress.id } : undefined
      }
    }));
    resources.push({
      type: 'Microsoft.Network/azureFirewalls',
      apiVersion: '2023-04-01',
      name: fw.name || 'firewall',
      location: '[parameters(\'location\')]',
      tags: _armTags(fw),
      properties: {
        sku: { name: fw.sku?.name || 'AZFW_VNet', tier: fw.sku?.tier || 'Standard' },
        ipConfigurations: ipConfigs
      }
    });
  });

  // --- Bastion Host ---
  bastions.forEach(bast => {
    const bp = bast.properties || {};
    const ipConfigs = (bp.ipConfigurations || []).map(ipc => ({
      name: ipc.name || 'bastion-ipconfig',
      properties: {
        subnet: ipc.properties?.subnet ? { id: ipc.properties.subnet.id } : undefined,
        publicIPAddress: ipc.properties?.publicIPAddress ? { id: ipc.properties.publicIPAddress.id } : undefined
      }
    }));
    resources.push({
      type: 'Microsoft.Network/bastionHosts',
      apiVersion: '2023-04-01',
      name: bast.name || 'bastion',
      location: '[parameters(\'location\')]',
      tags: _armTags(bast),
      properties: {
        ipConfigurations: ipConfigs
      }
    });
  });

  // --- VNet Peerings ---
  peerings.forEach(peer => {
    const pp = peer.properties || {};
    const srcVnetId = peer._sourceVnetId || peer.id?.split('/virtualNetworkPeerings/')[0] || '';
    const srcVnetName = srcVnetId.split('/').pop() || 'vnet';
    resources.push({
      type: 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings',
      apiVersion: '2023-04-01',
      name: srcVnetName + '/' + (peer.name || 'peering'),
      dependsOn: ['[resourceId(\'Microsoft.Network/virtualNetworks\', \'' + srcVnetName + '\')]'],
      properties: {
        remoteVirtualNetwork: { id: pp.remoteVirtualNetwork?.id || '' },
        allowVirtualNetworkAccess: pp.allowVirtualNetworkAccess !== false,
        allowForwardedTraffic: pp.allowForwardedTraffic === true,
        allowGatewayTransit: pp.allowGatewayTransit === true,
        useRemoteGateways: pp.useRemoteGateways === true
      }
    });
  });

  // --- Outputs ---
  vnets.forEach(vnet => {
    template.outputs[_armId(vnet.name, 'vnet', seen) + 'Id'] = {
      type: 'string',
      value: '[resourceId(\'Microsoft.Network/virtualNetworks\', \'' + (vnet.name || 'vnet') + '\')]'
    };
  });

  // Count and warn
  if (resources.length > 750) warnings.push('Resource count (' + resources.length + ') approaching ARM 800-resource limit. Consider linked templates.');
  if (vms.length) warnings.push('VM passwords must be provided at deployment. Use Key Vault references for production.');

  const code = JSON.stringify(template, null, 2);
  return {
    code,
    warnings,
    stats: { resources: resources.length }
  };
}
