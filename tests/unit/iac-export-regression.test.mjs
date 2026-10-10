import { it } from 'node:test';
import assert from 'node:assert/strict';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';
import { _selectIacData } from '../../src/modules/iac-resource-formatters.js';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const nsgId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web';
const asgId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/apps';
const ruleData = properties => ({ nsgs: [{ id: nsgId, name: 'web', properties: { securityRules: [{ name: 'restricted', properties: { priority: 100, access: 'Allow', direction: 'Inbound', protocol: 'Tcp', ...properties } }] } }] });

it('preserves augmented NSG prefixes and port arrays in all three IaC formats', () => {
  const data = ruleData({ sourceAddressPrefixes: ['10.1.0.0/16', '10.2.0.0/16'], destinationAddressPrefixes: ['10.3.0.0/16'], sourcePortRanges: ['1024-2048', '3000'], destinationPortRanges: ['443', '8443'] });
  const tf = generateTerraform(data).code;
  assert.match(tf, /source_address_prefixes = \["10.1.0.0\/16", "10.2.0.0\/16"\]/);
  assert.match(tf, /destination_port_ranges = \["443", "8443"\]/);
  assert.doesNotMatch(tf, /source_address_prefix\s*=|destination_port_range\s*=/);
  const arm = JSON.parse(generateARM(data).code).resources[0].properties.securityRules[0].properties;
  assert.deepEqual(arm.sourceAddressPrefixes, ['10.1.0.0/16', '10.2.0.0/16']);
  assert.deepEqual(arm.destinationPortRanges, ['443', '8443']);
  assert.equal(arm.sourceAddressPrefix, undefined);
  const bicep = generateBicep(data).code;
  assert.match(bicep, /destinationPortRanges: \[\s*'443'\s*'8443'/);
  assert.doesNotMatch(bicep, /sourceAddressPrefix:|destinationPortRange:/);
});

it('preserves application security group selectors without wildcard address selectors', () => {
  const data = ruleData({ sourceApplicationSecurityGroups: [{ id: asgId }], destinationApplicationSecurityGroups: [{ id: asgId }], destinationPortRange: '443' });
  const tf = generateTerraform(data).code;
  assert.match(tf, /source_application_security_group_ids = \[/);
  assert.doesNotMatch(tf, /source_address_prefix\s*=/);
  const arm = JSON.parse(generateARM(data).code).resources[0].properties.securityRules[0].properties;
  assert.deepEqual(arm.sourceApplicationSecurityGroups, [{ id: asgId }]);
  assert.equal(arm.sourceAddressPrefix, undefined);
  assert.match(generateBicep(data).code, /sourceApplicationSecurityGroups: \[\s*\{ id:/);
});

it('retains singular NSG selectors for ordinary rules', () => {
  const properties = { sourceAddressPrefix: '10.0.0.0/8', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '22' };
  const arm = JSON.parse(generateARM(ruleData(properties)).code).resources[0].properties.securityRules[0].properties;
  for (const [key, value] of Object.entries(properties)) assert.equal(arm[key], value);
});

const vnetId = name => '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/' + name;
const vnet = name => ({ id: vnetId(name), name, properties: { addressSpace: { addressPrefixes: ['10.0.0.0/16'] }, subnets: [{ id: vnetId(name) + '/subnets/workload', name: 'workload', properties: { addressPrefix: '10.0.0.0/24', networkSecurityGroup: { id: nsgId } } }] } });

it('restricts all IaC formats to the chosen VNet and its referenced NSG', () => {
  const data = { vnets: [vnet('chosen'), vnet('unrelated')], ...ruleData({}) };
  for (const generate of [generateTerraform, generateARM, generateBicep]) {
    const code = generate(data, { scopeVpcId: vnetId('chosen') }).code;
    assert.match(code, /chosen/);
    assert.doesNotMatch(code, /unrelated/);
    assert.match(code, /web/);
  }
});

it('exports no observed resources in Design Only without design changes', () => {
  const data = { vnets: [vnet('observed')], ...ruleData({}) };
  for (const generate of [generateTerraform, generateARM, generateBicep]) {
    const result = generate(data, { mode: 'create', designResourceIds: [] });
    assert.doesNotMatch(result.code, /observed|restricted/);
  }
  const selected = _selectIacData(data, { designOnly: true, designResourceIds: [vnetId('observed') + '/subnets/workload'] });
  assert.equal(selected.vnets.length, 1);
  assert.equal(selected.vnets[0].properties.subnets.length, 1);
  assert.equal(selected.nsgs.length, 0);
});

it('allocates distinct Terraform labels and references for identically named VNets and subnets', () => {
  const first = vnet('shared');
  const second = JSON.parse(JSON.stringify(first).replaceAll('/resourceGroups/rg/', '/resourceGroups/other/'));
  const code = generateTerraform({ vnets: [first, second] }).code;
  const labels = [...code.matchAll(/resource "([^"]+)" "([^"]+)"/g)].map(match => match[1] + '.' + match[2]);
  assert.equal(new Set(labels).size, labels.length);
  assert.match(code, /virtual_network_name = azurerm_virtual_network.shared.name/);
  assert.match(code, /virtual_network_name = azurerm_virtual_network.shared_2.name/);
});

it('does not emit undeclared Terraform variables when variables are disabled', () => {
  const vms = [{ id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/server', name: 'server', properties: { osProfile: {} } }];
  const code = generateTerraform({ vms }, { variables: false }).code;
  assert.doesNotMatch(code, /var\./);
  assert.match(code, /admin_password\s*= "CHANGE_ME_P@ssw0rd!"/);
});

it('IaC runtime offers HCL for Terraform and downloads Bicep with its proper extension', () => {
  const elements = new Map();
  const handlers = new Map();
  const node = id => {
    if (!elements.has(id)) elements.set(id, { value: '', checked: true, parentElement: { style: {} }, style: {}, classList: { add() {}, remove() {} }, addEventListener(type, handler) { handlers.set(id + ':' + type, handler); } });
    return elements.get(id);
  };
  let downloaded;
  const sandbox = { Blob, document: { getElementById: node, querySelectorAll: () => [], addEventListener() {} }, _getMain: () => null, AppDownloads: { saveBlob(blob, name) { downloaded = { blob, name }; } }, AppRenderContext: { createRenderContext: () => ({ rlCtx: { vnets: [vnet('chosen')] } }) }, esc: String };
  vm.createContext(sandbox);
  vm.runInContext(readFileSync('src/modules/iac-generator-runtime.js', 'utf8'), sandbox);
  sandbox.openIacModal('terraform');
  assert.equal(node('iacFormat').innerHTML, '<option value="hcl">HCL</option>');
  vm.runInContext("_iacType='bicep';_iacOutput='param location string';", sandbox);
  handlers.get('iacDownload:click')();
  assert.equal(downloaded.name, 'main.bicep');
  vm.runInContext("_iacType='terraform';", sandbox);
  node('iacFormat').value = 'json';
  handlers.get('iacDownload:click')();
  assert.equal(downloaded.name, 'main.tf');
});

for (const wrapped of [false, true]) {
  for (const reverseNat of [false, true]) {
    it(`preserves native ${wrapped ? 'ARM' : 'CLI'} NIC/NSG, NAT bindings and dual-stack prefixes (${reverseNat ? 'NAT subnet references' : 'subnet NAT reference'})`, () => {
      const resource = (id, name, properties) => ({ id, name, ...(wrapped ? { properties } : properties) });
      const rid = (type, name) => '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/' + type + '/' + name;
      const netId = vnetId('net'), subnetId = netId + '/subnets/workload';
      const natId = rid('natGateways', 'nat'), pipIds = ['egress', 'egress2'].map(name => rid('publicIPAddresses', name));
      const prefixes = ['10.0.1.0/24', 'fd00:1234:5678:1::/64'];
      const subnet = resource(subnetId, 'workload', { addressPrefixes: prefixes, ...(!reverseNat ? { natGateway: { id: natId } } : {}) });
      const data = {
        vnets: [resource(netId, 'net', { addressSpace: { addressPrefixes: ['10.0.0.0/16', 'fd00:1234:5678::/48'] }, subnets: [subnet] })],
        nsgs: [resource(nsgId, 'web', { securityRules: [] })],
        nics: [resource(rid('networkInterfaces', 'nic'), 'nic', { networkSecurityGroup: { id: nsgId }, ipConfigurations: [resource(undefined, 'primary', { subnet: { id: subnetId }, privateIPAllocationMethod: 'Dynamic' })] })],
        natGateways: [resource(natId, 'nat', { idleTimeoutInMinutes: 8, publicIpAddresses: pipIds.map(id => ({ id })), ...(reverseNat ? { subnets: [{ id: subnetId }] } : {}) })],
        publicIps: [resource(pipIds[0], 'egress', { publicIPAllocationMethod: 'Static' })]
      };
      for (const options of [undefined, { scopeVpcId: netId }]) {
        const tf = generateTerraform(data, options).code;
        assert.match(tf, /resource "azurerm_network_interface_security_group_association"[\s\S]*network_interface_id\s*= azurerm_network_interface.nic.id\s*network_security_group_id\s*= azurerm_network_security_group.web.id/);
        assert.match(tf, /resource "azurerm_subnet_nat_gateway_association"[\s\S]*subnet_id\s*= azurerm_subnet.net_workload.id\s*nat_gateway_id\s*= azurerm_nat_gateway.nat.id/);
        assert.equal((tf.match(/resource "azurerm_nat_gateway_public_ip_association"/g) || []).length, 2);
        for (const name of ['egress', 'egress2']) assert.match(tf, new RegExp('public_ip_address_id\\s*= azurerm_public_ip.' + name + '.id'));
        assert.ok(tf.includes(prefixes[1]));
        const resources = JSON.parse(generateARM(data, options).code).resources;
        const get = type => resources.find(r => r.type.endsWith('/' + type));
        assert.match(get('networkInterfaces').properties.networkSecurityGroup.id, /networkSecurityGroups.*web/);
        assert.ok(get('networkInterfaces').dependsOn.includes(get('networkInterfaces').properties.networkSecurityGroup.id));
        const armSubnet = get('virtualNetworks').properties.subnets[0].properties;
        assert.deepEqual(armSubnet.addressPrefixes, prefixes);
        assert.equal(armSubnet.addressPrefix, undefined);
        assert.match(armSubnet.natGateway.id, /natGateways.*nat/);
        assert.ok(get('virtualNetworks').dependsOn.includes(armSubnet.natGateway.id));
        const armNat = get('natGateways');
        assert.equal(armNat.properties.idleTimeoutInMinutes, 8);
        assert.equal(armNat.properties.publicIpAddresses.length, 2);
        assert.deepEqual(armNat.dependsOn, armNat.properties.publicIpAddresses.map(ip => ip.id));
        assert.equal(resources.filter(r => r.type.endsWith('/publicIPAddresses')).length, 2);
        const bicep = generateBicep(data, options).code;
        assert.match(bicep, /networkSecurityGroup: \{ id: web.id \}/);
        assert.match(bicep, /natGateway: \{ id: nat.id \}/);
        assert.match(bicep, /publicIpAddresses: \[\s*\{ id: egress.id \}\s*\{ id: egress2.id \}/);
        assert.match(bicep, /addressPrefixes: \[\s*'10.0.1.0\/24'\s*'fd00:1234:5678:1::\/64'/);
        assert.doesNotMatch(bicep, /addressPrefix:/);
      }
    });
  }
}

it('reconciles standalone design subnets in full exports and references an existing parent in Design Only', () => {
  const parent = vnet('observed');
  const added = { id: 'subnet-design-added', name: 'added', VpcId: parent.id, addressPrefix: '10.0.2.0/24' };
  const data = { vnets: [parent], subnets: [parent.properties.subnets[0], added] };
  for (const generate of [generateTerraform, generateARM, generateBicep]) {
    assert.match(generate(data).code, /10\.0\.2\.0\/24/);
  }
  const options = { mode: 'create', designResourceIds: [added.id] };
  const tf = generateTerraform(data, options).code;
  assert.match(tf, /data "azurerm_virtual_network" "observed"/);
  assert.doesNotMatch(tf, /resource "azurerm_virtual_network"|workload/);
  assert.match(tf, /virtual_network_name = data.azurerm_virtual_network.observed.name/);
  const arm = JSON.parse(generateARM(data, options).code).resources;
  assert.equal(arm.length, 1);
  assert.equal(arm[0].type, 'Microsoft.Network/virtualNetworks/subnets');
  assert.equal(arm[0].name, 'observed/added');
  assert.equal(arm[0].properties.addressPrefix, added.addressPrefix);
  const bicep = generateBicep(data, options).code;
  assert.match(bicep, /Microsoft.Network\/virtualNetworks@2023-04-01' existing =/);
  assert.doesNotMatch(bicep, /workload/);
  assert.match(bicep, /parent: observed/);
  assert.equal(parent.properties.subnets.length, 1, 'selection must not mutate the source VNet');
});

for (const wrapped of [false, true]) {
  it(`preserves a native ${wrapped ? 'ARM' : 'CLI'} NAT public IP prefix reference in scoped and full exports`, () => {
    const net = vnet('prefix-net');
    const natId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/natGateways/egress';
    const prefixId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPPrefixes/egress-prefix';
    net.properties.subnets[0].properties.natGateway = { id: natId };
    const properties = { publicIpAddresses: [], publicIpPrefixes: [{ id: prefixId }], idleTimeoutInMinutes: 8 };
    const data = { vnets: [net], natGateways: [{ id: natId, name: 'egress', ...(wrapped ? { properties } : properties) }] };
    for (const options of [undefined, { scopeVpcId: net.id }]) {
      const tf = generateTerraform(data, options).code;
      assert.match(tf, /azurerm_nat_gateway_public_ip_prefix_association/);
      assert.ok(tf.includes('public_ip_prefix_id = "' + prefixId + '"'));
      const nat = JSON.parse(generateARM(data, options).code).resources.find(r => r.type.endsWith('/natGateways'));
      assert.deepEqual(nat.properties.publicIpPrefixes, [{ id: prefixId }]);
      const bicep = generateBicep(data, options).code;
      assert.match(bicep, /publicIpPrefixes: \[/);
      assert.ok(bicep.includes("{ id: '" + prefixId + "' }"));
    }
  });
}

it('clearly blocks ARM/Bicep exports spanning multiple resource groups and permits a single selected scope', () => {
  const first = vnet('shared');
  const second = JSON.parse(JSON.stringify(first).replaceAll('/resourceGroups/rg/', '/resourceGroups/other/'));
  for (const generate of [generateARM, generateBicep]) {
    const result = generate({ vnets: [first, second] });
    assert.equal(result.blocked, true);
    assert.equal(result.code, '');
    assert.match(result.warnings.join(' '), /one subscription\/resource group/);
    const scoped = generate({ vnets: [first, second] }, { scopeVpcId: first.id });
    assert.notEqual(scoped.blocked, true);
    assert.ok(scoped.code);
  }
});

it('blocks unconfigured design VMs in every format until NIC and image input is provided', () => {
  const machine = { id: 'vm-design-1', name: 'planned', _designCreated: true, properties: { hardwareProfile: { vmSize: 'Standard_B2ms' } } };
  for (const generate of [generateTerraform, generateARM, generateBicep]) {
    const result = generate({ vms: [machine] });
    assert.equal(result.blocked, true);
    assert.equal(result.code, '');
    assert.match(result.warnings.join(' '), /planned.*network interface.*OS image/);
  }
  machine.properties.networkProfile = { networkInterfaces: [{ id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/planned-nic' }] };
  machine.properties.storageProfile = { imageReference: { id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/images/image' } };
  for (const generate of [generateTerraform, generateARM, generateBicep]) assert.notEqual(generate({ vms: [machine] }).blocked, true);
  assert.match(generateTerraform({ vms: [machine] }).code, /source_image_id =/);
  const arm = JSON.parse(generateARM({ vms: [machine] }).code).resources[0].properties;
  assert.deepEqual(arm.storageProfile.imageReference, machine.properties.storageProfile.imageReference);
  assert.deepEqual(arm.networkProfile.networkInterfaces, machine.properties.networkProfile.networkInterfaces);
  assert.ok(generateBicep({ vms: [machine] }).code.includes("id: '" + machine.properties.storageProfile.imageReference.id + "'"));
});

it('shows blocked IaC requirements in the preview and clears a previously downloadable result', async () => {
  const elements = new Map();
  const node = id => {
    if (!elements.has(id)) elements.set(id, { value: '', checked: true, parentElement: { style: {} }, style: {}, classList: { add() {}, remove() {} }, addEventListener() {} });
    return elements.get(id);
  };
  const blocked = { code: '', warnings: ['VM "<unsafe>" needs a network interface and an OS image'], stats: {}, blocked: true };
  const sandbox = { document: { getElementById: node, querySelectorAll: () => [], addEventListener() {} }, _getMain: () => null, AppModules: { IacGenerator: { generateTerraform: () => blocked } }, AppRenderContext: { createRenderContext: () => ({ rlCtx: { vnets: [vnet('chosen')] } }) }, esc: value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') };
  vm.createContext(sandbox);
  vm.runInContext(readFileSync('src/modules/iac-generator-runtime.js', 'utf8'), sandbox);
  vm.runInContext("_iacOutput='stale code';", sandbox);
  await sandbox.generateIacPreview();
  assert.equal(vm.runInContext('_iacOutput', sandbox), '');
  assert.match(node('iacPreview').innerHTML, /Export blocked.*Resolve the requirements/);
  assert.match(node('iacPreview').innerHTML, /&lt;unsafe&gt;.*network interface/);
  assert.doesNotMatch(node('iacPreview').innerHTML, /<unsafe>/);
});
