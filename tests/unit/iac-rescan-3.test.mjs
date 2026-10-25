import { it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';
import { _selectIacData } from '../../src/modules/iac-resource-formatters.js';

const subscription = '00000000-0000-0000-0000-000000000001';
const otherSubscription = '00000000-0000-0000-0000-000000000002';
const rid = (type, name, sub = subscription, rg = 'rg') => `/subscriptions/${sub}/resourceGroups/${rg}/providers/${type}/${name}`;
const netId = rid('Microsoft.Network/virtualNetworks', 'net');
const subnetId = netId + '/subnets/workload';
const pipId = rid('Microsoft.Network/publicIPAddresses', 'pip');
const nicId = rid('Microsoft.Network/networkInterfaces', 'nic');
const diskId = rid('Microsoft.Compute/disks', 'data-disk');
const machineId = rid('Microsoft.Compute/virtualMachines', 'vm');
const generators = [generateTerraform, generateARM, generateBicep];

it('blocks cross-subscription Terraform instead of generating colliding physical VNets; selected scope and same-subscription groups work', () => {
  const net = { id: netId, name: 'net', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } };
  const other = { ...net, id: rid('Microsoft.Network/virtualNetworks', 'net', otherSubscription), addressSpace: { addressPrefixes: ['10.1.0.0/16'] } };
  const blocked = generateTerraform({ vnets: [net, other] });
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.code, '');
  assert.match(blocked.warnings.join(' '), /one subscription.*Select a VNet/);
  const selected = generateTerraform({ vnets: [net, other] }, { scopeVpcId: net.id });
  assert.notEqual(selected.blocked, true);
  assert.equal((selected.code.match(/resource "azurerm_virtual_network"/g) || []).length, 1);
  assert.notEqual(generateTerraform({ vnets: [net, { ...other, id: rid('Microsoft.Network/virtualNetworks', 'net', subscription, 'other-rg') }] }).blocked, true);
});

for (const wrapped of [false, true]) {
  const resource = (id, name, props) => ({ id, name, ...(wrapped ? { properties: props } : props) });
  const subnet = resource(subnetId, 'workload', { addressPrefixes: ['10.0.1.0/24', 'fd00:1234:5678:1::/64'] });
  const net = resource(netId, 'net', { addressSpace: { addressPrefixes: ['10.0.0.0/16', 'fd00:1234:5678::/48'] }, subnets: [subnet] });

  it(`preserves native ${wrapped ? 'ARM' : 'CLI'} NIC public IP, Dynamic IPv6 and primary settings without changing source order`, () => {
    const ipv6 = resource(undefined, 'ip6', { subnet: { id: subnetId }, privateIPAllocationMethod: 'Dynamic', privateIPAddressVersion: 'IPv6', primary: false });
    const ipv4 = resource(undefined, 'ip4', { subnet: { id: subnetId }, privateIPAllocationMethod: 'Static', privateIPAddress: '10.0.1.4', privateIPAddressVersion: 'IPv4', primary: true, publicIPAddress: { id: pipId } });
    const nic = resource(nicId, 'nic', { ipConfigurations: [ipv6, ipv4] });
    const data = { vnets: [net], nics: [nic] };
    const tf = generateTerraform(data).code;
    const blocks = [...tf.matchAll(/ip_configuration \{([\s\S]*?)\n  }/g)].map(match => match[1]);
    assert.equal(blocks.length, 2);
    assert.match(blocks[0], /name\s*= "ip4"/);
    assert.match(blocks[0], /primary\s*= true/);
    assert.ok(blocks[0].includes(pipId));
    assert.match(blocks[1], /private_ip_address_version\s*= "IPv6"/);
    assert.match(blocks[1], /primary\s*= false/);
    assert.match(blocks[1], /private_ip_address_allocation\s*= "Dynamic"/);
    const armNic = JSON.parse(generateARM(data).code).resources.find(resource => resource.type === 'Microsoft.Network/networkInterfaces');
    assert.equal(armNic.properties.ipConfigurations[0].properties.privateIPAddressVersion, 'IPv6');
    assert.equal(armNic.properties.ipConfigurations[0].properties.primary, false);
    assert.equal(armNic.properties.ipConfigurations[1].properties.primary, true);
    assert.equal(armNic.properties.ipConfigurations[1].properties.publicIPAddress.id, pipId);
    const bicep = generateBicep(data).code;
    assert.ok(bicep.includes("publicIPAddress: { id: '" + pipId + "' }"));
    assert.match(bicep, /privateIPAddressVersion: 'IPv6'\s+primary: false/);
    assert.match(bicep, /privateIPAddressVersion: 'IPv4'\s+primary: true/);
    assert.equal((nic.properties || nic).ipConfigurations[0].name, 'ip6');
  });

  for (const alias of ['volumes', 'managedDisks']) {
    it(`exports ${wrapped ? 'ARM' : 'CLI'} disks from active ${alias} and retains their VM attachments at the native LUN`, () => {
      const machine = resource(machineId, 'vm', { hardwareProfile: { vmSize: 'Standard_B2s' }, storageProfile: { imageReference: { id: rid('Microsoft.Compute/images', 'base') }, dataDisks: [{ name: 'data-disk', lun: 3, caching: 'ReadOnly', createOption: 'Empty', managedDisk: { id: diskId } }] } });
      const disk = resource(diskId, 'data-disk', { diskSizeGB: 256, creationData: { createOption: 'Empty' } });
      const data = { vnets: [net], vms: [machine], [alias]: [disk] };
      const tf = generateTerraform(data).code;
      assert.match(tf, /resource "azurerm_managed_disk" "data_disk"/);
      assert.match(tf, /resource "azurerm_virtual_machine_data_disk_attachment"[\s\S]*managed_disk_id\s*= azurerm_managed_disk.data_disk.id\s*virtual_machine_id\s*= azurerm_linux_virtual_machine.vm.id\s*lun\s*= 3\s*caching\s*= "ReadOnly"/);
      const arm = JSON.parse(generateARM(data).code).resources;
      const armDisk = arm.find(resource => resource.type === 'Microsoft.Compute/disks');
      assert.equal(armDisk.properties.diskSizeGB, 256);
      const armMachine = arm.find(resource => resource.type === 'Microsoft.Compute/virtualMachines');
      const attached = armMachine.properties.storageProfile.dataDisks[0];
      assert.equal(attached.createOption, 'Attach');
      assert.equal(attached.lun, 3);
      assert.equal(attached.caching, 'ReadOnly');
      assert.match(attached.managedDisk.id, /resourceId.*Microsoft.Compute\/disks.*data-disk/);
      assert.ok(armMachine.dependsOn.includes(attached.managedDisk.id));
      const bicep = generateBicep(data).code;
      assert.match(bicep, /dataDisks: \[[\s\S]*lun: 3\s*createOption: 'Attach'\s*caching: 'ReadOnly'\s*managedDisk: \{ id: data_disk.id }/);
      assert.match(bicep, /resource data_disk 'Microsoft.Compute\/disks@/);
      assert.equal(machine.storageProfile?.dataDisks[0].createOption || machine.properties.storageProfile.dataDisks[0].createOption, 'Empty');
    });
  }
}

it('retains existing data-disk IDs when the disk is outside the collected set, and scopes collection aliases to the selected VM', () => {
  const machine = { id: machineId, name: 'vm', storageProfile: { imageReference: { id: rid('Microsoft.Compute/images', 'base') }, dataDisks: [{ name: 'existing', lun: 0, caching: 'None', createOption: 'Attach', managedDisk: { id: diskId } }] } };
  const data = { vms: [machine] };
  assert.ok(generateTerraform(data).code.includes('managed_disk_id    = "' + diskId.toLowerCase() + '"'));
  assert.equal(JSON.parse(generateARM(data).code).resources[0].properties.storageProfile.dataDisks[0].managedDisk.id, diskId);
  assert.ok(generateBicep(data).code.includes("managedDisk: { id: '" + diskId + "' }"));
  const attached = { id: diskId, name: 'attached' }, unrelated = { id: rid('Microsoft.Compute/disks', 'unrelated'), name: 'unrelated' };
  machine.networkProfile = { networkInterfaces: [{ id: nicId }] };
  const selected = _selectIacData({ vnets: [{ id: netId, name: 'net' }], subnets: [{ id: subnetId, name: 'workload' }], nics: [{ id: nicId, name: 'nic', ipConfigurations: [{ subnet: { id: subnetId } }] }], vms: [machine], volumes: [attached, unrelated] }, { scopeVpcId: netId });
  assert.deepEqual(selected.disks.map(disk => disk.id), [diskId]);
});

it('retains Copy-disk source references once the active collection is exported', () => {
  const sourceId = rid('Microsoft.Compute/disks', 'source');
  const data = { managedDisks: [{ id: diskId, name: 'copied', creationData: { createOption: 'Copy', sourceResourceId: sourceId }, diskSizeGB: 256 }] };
  assert.ok(generateTerraform(data).code.includes('source_resource_id   = "' + sourceId + '"'));
  assert.equal(JSON.parse(generateARM(data).code).resources[0].properties.creationData.sourceResourceId, sourceId);
  assert.ok(generateBicep(data).code.includes("sourceResourceId: '" + sourceId + "'"));
});

const designSource = readFileSync('src/modules/design-mode-runtime.js', 'utf8');
it('removing a native subnet also removes it from all three generated outputs', () => {
  const subnet = { id: subnetId, name: 'removed', addressPrefix: '10.0.1.0/24' };
  const inputs = { in_subnets: { value: JSON.stringify({ value: [subnet] }) }, in_vnets: { value: JSON.stringify({ value: [{ id: netId, name: 'net', properties: { addressSpace: { addressPrefixes: ['10.0.0.0/16'] }, subnets: [subnet] } }] }) } };
  const sandbox = { document: { getElementById: id => inputs[id] }, gv: id => inputs[id].value, safeParse: JSON.parse, ext: value => Array.isArray(value) ? value : value.value || [], designResourceType: value => value, designGatewayType: value => value };
  vm.createContext(sandbox);
  const applySource = designSource.slice(designSource.indexOf('const _designApplyFns='), designSource.indexOf('// Azure location'));
  vm.runInContext(applySource + '\nthis.applyFns=_designApplyFns;', sandbox);
  sandbox.applyFns.remove_resource({ target: { ResourceId: subnetId.toUpperCase(), ResourceType: 'Subnet' } });
  const data = { vnets: JSON.parse(inputs.in_vnets.value).value, subnets: JSON.parse(inputs.in_subnets.value).value };
  for (const generate of generators) assert.doesNotMatch(generate(data).code, /removed|10\.0\.1\.0\/24/);
});

it('retains FromImage and imported VHD sources in native managed disk exports', () => {
  const imageId = rid('Microsoft.Compute/images', 'base');
  const accountId = rid('Microsoft.Storage/storageAccounts', 'images');
  const uri = 'https://example.invalid/vhds/base.vhd';
  for (const creationData of [{ createOption: 'FromImage', imageReference: { id: imageId } }, { createOption: 'Import', sourceUri: uri, storageAccountId: accountId }]) {
    const data = { volumes: [{ id: diskId, name: 'image-disk', diskSizeGB: 128, creationData }] };
    const tf = generateTerraform(data).code;
    const arm = JSON.parse(generateARM(data).code).resources[0].properties.creationData;
    const bicep = generateBicep(data).code;
    assert.deepEqual(arm, creationData);
    if (creationData.createOption === 'FromImage') {
      assert.ok(tf.includes('image_reference_id   = "' + imageId + '"'));
      assert.ok(bicep.includes("imageReference: { id: '" + imageId + "' }"));
    } else {
      assert.ok(tf.includes('source_uri           = "' + uri + '"'));
      assert.ok(tf.includes('storage_account_id   = "' + accountId + '"'));
      assert.ok(bicep.includes("sourceUri: '" + uri + "'"));
      assert.ok(bicep.includes("storageAccountId: '" + accountId + "'"));
    }
  }
});

const cliSource = designSource.slice(designSource.indexOf('function _generateCLI(ch){'), designSource.indexOf('function _generateWarnings(){'));
function generateDesignCli(change) {
  const sandbox = { designGatewayType: value => value, designResourceType: value => value };
  vm.createContext(sandbox);
  vm.runInContext(cliSource, sandbox);
  return Array.from(sandbox._generateCLI(change));
}

it('design NAT CLI attaches to the exact selected native subnet after creating its public IP and NAT', () => {
  const cmds = generateDesignCli({ action: 'add_gateway', params: { GatewayType: 'NAT', Name: 'planned-nat', SubnetId: subnetId } });
  assert.equal(cmds.length, 3);
  assert.match(cmds[0], /network public-ip create/);
  assert.match(cmds[1], /network nat gateway create/);
  assert.match(cmds[2], /network vnet subnet update --name 'workload' --resource-group 'rg' --vnet-name 'net' --nat-gateway 'planned-nat'/);
  for (const cmd of cmds) assert.ok(cmd.includes("--subscription '" + subscription + "'"));
  const pending = generateDesignCli({ action: 'add_gateway', params: { GatewayType: 'NAT', Name: 'new-nat', SubnetId: 'subnet-design-1' } });
  assert.match(pending[2], /--name \$SUBNET_NAME.*--resource-group \$RESOURCE_GROUP.*--vnet-name \$VNET_NAME/);
});

it('design NSG CLI uses quoted wildcards for All, retaining port zero and ranges for specific rules', () => {
  const cmds = generateDesignCli({ action: 'add_security_group', params: { Name: 'nsg', IngressRules: [{ Protocol: '-1', FromPort: -1, ToPort: -1, CidrIp: '*' }, { Protocol: 'tcp', FromPort: 0, ToPort: 0 }, { Protocol: 'udp', FromPort: 1000, ToPort: 2000 }] } });
  assert.match(cmds[1], /--protocol '\*' --destination-port-ranges '\*' --source-address-prefixes '\*'/);
  assert.doesNotMatch(cmds[1], /--destination-port-ranges -1/);
  assert.match(cmds[2], /--destination-port-ranges '0'/);
  assert.match(cmds[3], /--destination-port-ranges '1000-2000'/);
});
