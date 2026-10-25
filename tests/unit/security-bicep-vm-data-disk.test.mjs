import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';

const root = '/subscriptions/sub/resourceGroups/rg/providers/';
const vmId = root + 'Microsoft.Compute/virtualMachines/app';
const diskId = root + 'Microsoft.Compute/disks/data';
const netId = root + 'Microsoft.Network/virtualNetworks/net';
const nicId = root + 'Microsoft.Network/networkInterfaces/nic';
const imageId = root + 'Microsoft.Compute/images/base';
const shape = (id, name, properties, wrapped) => ({ id, name, ...(wrapped ? { properties } : properties) });
const vm = (dataDisks, wrapped) => shape(vmId, 'app', {
  storageProfile: { imageReference: { id: imageId }, dataDisks },
  networkProfile: { networkInterfaces: [{ id: nicId }] }
}, wrapped);
const invalid = ['0', '12', '', "'", '0\n1', '\r\t\u0000', {}, [], true, false, NaN, Infinity, -Infinity, 0.5, -1, Number.MAX_SAFE_INTEGER + 1];

for (const wrapped of [false, true]) {
  it(`blocks malformed imported ${wrapped ? 'ARM' : 'CLI'} VM data-disk numeric fields before emitting Bicep`, () => {
    for (const field of ['lun', 'diskSizeGB']) {
      const values = field === 'lun' ? [...invalid, null, undefined] : [...invalid, 0];
      for (const value of values) {
        const data = { vms: [vm([{ lun: 0, diskSizeGB: 32, [field]: value }], wrapped)] };
        const before = structuredClone(data);
        const result = generateBicep(data);
        assert.equal(result.blocked, true, `${field}: ${String(value)}`);
        assert.equal(result.code, '');
        assert.deepEqual(result.stats, {});
        assert.match(result.warnings.join(' '), new RegExp('app.*data disk 1.*' + field));
        assert.deepEqual(data, before);
      }
    }
  });

  it(`preserves numeric LUNs and optional sizes for ${wrapped ? 'ARM' : 'CLI'} VM data disks`, () => {
    const disks = [
      { lun: 0, diskSizeGB: 1 },
      { lun: 3, diskSizeGB: 256 },
      { lun: 4 },
      { lun: 5, diskSizeGB: null },
      { lun: 6, diskSizeGB: undefined },
      { lun: Number.MAX_SAFE_INTEGER, diskSizeGB: Number.MAX_SAFE_INTEGER }
    ];
    const data = { vms: [vm(disks, wrapped)] };
    const before = structuredClone(data);
    const result = generateBicep(data);
    assert.notEqual(result.blocked, true);
    for (const disk of disks) assert.ok(result.code.includes('lun: ' + disk.lun + '\n'));
    assert.equal((result.code.match(/diskSizeGB:/g) || []).length, 3);
    for (const size of [1, 256, Number.MAX_SAFE_INTEGER]) assert.ok(result.code.includes('diskSizeGB: ' + size + '\n'));
    assert.deepEqual(data, before);
    assert.notEqual(generateBicep({ vms: [vm(undefined, wrapped)] }).blocked, true);
  });

  it(`validates ${wrapped ? 'ARM' : 'CLI'} design VM data disks too`, () => {
    const machine = { ...vm([{ lun: '0' }], wrapped), _designCreated: true };
    const result = generateBicep({ vms: [machine] });
    assert.equal(result.blocked, true);
    assert.equal(result.code, '');
    assert.match(result.warnings.join(' '), /data disk 1.*lun/);
  });
}

for (const alias of ['disks', 'managedDisks', 'volumes']) {
  it(`keeps VM data-disk validation with the ${alias} collection`, () => {
    const data = { vms: [vm([{ lun: 0, managedDisk: { id: diskId } }], false)], [alias]: [{ id: diskId, name: 'data' }] };
    const result = generateBicep(data);
    assert.notEqual(result.blocked, true);
    assert.match(result.code, /lun: 0\s+createOption: 'Attach'\s+managedDisk: \{ id: data.id }/);
    data.vms[0].storageProfile.dataDisks[0].lun = '0';
    assert.equal(generateBicep(data).code, '');
    assert.equal(generateBicep(data).blocked, true);
  });
}

it('preserves disk alias precedence and validates the VM attachment independently', () => {
  const data = {
    vms: [vm([{ lun: 0, managedDisk: { id: diskId } }], false)],
    disks: [], managedDisks: [{ id: diskId, name: 'ignoredManaged' }], volumes: [{ id: diskId, name: 'ignoredVolume' }]
  };
  const before = structuredClone(data);
  const result = generateBicep(data);
  assert.notEqual(result.blocked, true);
  assert.doesNotMatch(result.code, /resource ignored/);
  assert.ok(result.code.includes("managedDisk: { id: '" + diskId + "' }"));
  assert.deepEqual(data, before);
  data.vms[0].storageProfile.dataDisks[0].diskSizeGB = '32';
  assert.equal(generateBicep(data).blocked, true);
});

it('checks only VMs selected for export, including VMs selected through their NIC', () => {
  const selected = vm([{ lun: 0 }], false);
  const excluded = { ...vm([{ lun: '0' }], false), id: vmId + '-other', name: 'excluded', networkProfile: {} };
  const data = {
    vnets: [{ id: netId, name: 'net' }],
    nics: [{ id: nicId, name: 'nic', ipConfigurations: [{ subnet: { id: netId + '/subnets/app' } }] }],
    vms: [selected, excluded]
  };
  const options = { scopeVpcId: netId };
  const before = structuredClone(data);
  assert.equal(generateBicep(data).blocked, true);
  const result = generateBicep(data, options);
  assert.notEqual(result.blocked, true);
  assert.match(result.code, /resource app 'Microsoft.Compute\/virtualMachines/);
  assert.doesNotMatch(result.code, /resource excluded /);
  assert.deepEqual(data, before);
  selected.storageProfile.dataDisks[0].lun = '0';
  assert.equal(generateBicep(data, options).blocked, true);
  assert.equal(generateBicep(data, options).code, '');
});

it('keeps the Bicep VM data-disk size guard independent of ARM and Terraform', () => {
  // Terraform attachments emit the LUN but do not emit diskSizeGB.
  const data = { vms: [vm([{ lun: 0, diskSizeGB: '32', managedDisk: { id: diskId } }], false)] };
  const before = structuredClone(data);
  assert.equal(generateBicep(data).blocked, true);
  assert.equal(generateBicep(data).code, '');
  for (const generate of [generateARM, generateTerraform]) {
    const result = generate(data);
    assert.notEqual(result.blocked, true);
    assert.ok(result.code.length > 0);
  }
  const arm = JSON.parse(generateARM(data).code).resources.find(resource => resource.type.endsWith('/virtualMachines'));
  assert.equal(arm.properties.storageProfile.dataDisks[0].lun, 0);
  assert.equal(arm.properties.storageProfile.dataDisks[0].diskSizeGB, '32');
  assert.deepEqual(data, before);
});
