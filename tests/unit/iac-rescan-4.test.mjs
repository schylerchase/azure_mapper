import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';

const root = '/subscriptions/sub/resourceGroups/rg/providers/';
const nicIds = ['secondary', 'primary'].map(name => root + 'Microsoft.Network/networkInterfaces/' + name);
const diskId = root + 'Microsoft.Compute/disks/specialized-os';
const image = { publisher: 'Canonical', offer: '0001-com-ubuntu-server-jammy', sku: '22_04-lts-gen2', version: 'latest' };
function vm(properties) {
  return { id: root + 'Microsoft.Compute/virtualMachines/app', name: 'app', location: 'eastus', properties };
}
const getArmVm = data => JSON.parse(generateARM(data).code).resources.find(resource => resource.type.endsWith('/virtualMachines')).properties;

for (const wrapped of [false, true]) {
  it(`retains an explicit primary VM NIC with ${wrapped ? 'ARM' : 'CLI'} reference properties`, () => {
    const refs = nicIds.map((id, index) => ({ id, ...(wrapped ? { properties: { primary: index === 1 } } : { primary: index === 1 }) }));
    const data = { vms: [vm({ networkProfile: { networkInterfaces: refs }, storageProfile: { imageReference: image } })] };
    const before = structuredClone(data);
    const tf = generateTerraform(data, { variables: false }).code;
    const nicList = tf.match(/network_interface_ids = \[([\s\S]*?)\]/)[1];
    assert.ok(nicList.indexOf(nicIds[1].toLowerCase()) < nicList.indexOf(nicIds[0].toLowerCase()));
    assert.deepEqual(getArmVm(data).networkProfile.networkInterfaces, nicIds.map((id, index) => ({ id, properties: { primary: index === 1 } })));
    const bicep = generateBicep(data).code;
    for (const [index, id] of nicIds.entries()) assert.ok(bicep.includes("id: '" + id + "'\n          properties: { primary: " + (index === 1) + ' }'));
    assert.deepEqual(data, before, 'export must not reorder the imported NIC references');
  });
}

for (const osType of ['Linux', 'Windows']) {
  it(`preserves a specialized ${osType} OS disk in ARM/Bicep and blocks unsupported Terraform`, () => {
    const osDisk = { name: 'specialized-os', osType, caching: 'ReadWrite', createOption: 'Attach', managedDisk: { id: diskId, storageAccountType: 'Premium_LRS' }, diskSizeGB: 64 };
    const data = { vms: [vm({ hardwareProfile: { vmSize: 'Standard_D2s_v5' }, networkProfile: { networkInterfaces: [{ id: nicIds[1], properties: { primary: true } }] }, storageProfile: { osDisk } })] };
    const tf = generateTerraform(data);
    assert.equal(tf.blocked, true);
    assert.equal(tf.code, '');
    assert.match(tf.warnings.join(' '), /app.*existing OS disk.*Export ARM\/Bicep/);
    const arm = getArmVm(data);
    assert.deepEqual(arm.storageProfile.osDisk, osDisk);
    assert.equal(arm.storageProfile.imageReference, undefined);
    assert.equal(arm.osProfile, undefined);
    const bicep = generateBicep(data).code;
    for (const text of ["createOption: 'Attach'", "osType: '" + osType + "'", "id: '" + diskId + "'", "caching: 'ReadWrite'", 'diskSizeGB: 64']) assert.ok(bicep.includes(text));
    assert.doesNotMatch(bicep, /imageReference:|osProfile:/);
    data.vms[0]._designCreated = true;
    for (const generate of [generateARM, generateBicep]) assert.notEqual(generate(data).blocked, true, 'an attached disk design VM does not require a new OS image');
  });
}

it('requires an existing managed OS disk ID for Attach exports', () => {
  const data = { vms: [vm({ storageProfile: { osDisk: { createOption: 'Attach', osType: 'Linux' } } })] };
  for (const generate of [generateTerraform, generateARM, generateBicep]) {
    const result = generate(data);
    assert.equal(result.blocked, true);
    assert.equal(result.code, '');
    assert.match(result.warnings.join(' '), /managed OS disk ID/);
  }
});

it('keeps arbitrary tag keys and values as literal HCL/Bicep strings', () => {
  const tags = { Owner: 'Ops\nPlatform\r\t', Template: '${1+1} %{ if true }', Path: 'C:\\ops\\new', 'quote"\'\\\n${key}': '"\'\\\u0000\b\f', Zero: 0, False: false };
  const data = { vnets: [{ id: root + 'Microsoft.Network/virtualNetworks/net', name: 'net', location: 'eastus', tags, properties: { addressSpace: { addressPrefixes: ['10.0.0.0/16'] } } }] };
  const tf = generateTerraform(data, { variables: false }).code;
  assert.ok(tf.includes('Owner = "Ops\\nPlatform\\r\\t"'));
  assert.ok(tf.includes('Template = "$${1+1} %%{ if true }"'));
  assert.ok(tf.includes('Path = "C:\\\\ops\\\\new"'));
  assert.ok(tf.includes('"quote\\"\'\\\\\\n$${key}" = "\\"\'\\\\\\u0000\\u0008\\u000c"'));
  assert.ok(tf.includes('Zero = "0"'));
  assert.ok(tf.includes('False = "false"'));
  const bicep = generateBicep(data).code;
  assert.ok(bicep.includes("Owner: 'Ops\\nPlatform\\r\\t'"));
  assert.ok(bicep.includes("Template: '\\${1+1} %{ if true }'"));
  assert.ok(bicep.includes("Path: 'C:\\\\ops\\\\new'"));
  assert.ok(bicep.includes("'quote\"\\'\\\\\\n\\${key}': '\"\\'\\\\\\u{0}\\u{8}\\u{c}'"));
  assert.ok(bicep.includes("Zero: '0'"));
  assert.ok(bicep.includes("False: 'false'"));
  assert.deepEqual(JSON.parse(generateARM(data).code).resources[0].tags, tags);
});
