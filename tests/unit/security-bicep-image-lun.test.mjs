import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';

const root = '/subscriptions/sub/resourceGroups/rg/providers/';
const diskId = root + 'Microsoft.Compute/disks/data';
const imageId = root + 'Microsoft.Compute/images/base';
const netId = root + 'Microsoft.Network/virtualNetworks/net';
const nicId = root + 'Microsoft.Network/networkInterfaces/nic';
const vmId = root + 'Microsoft.Compute/virtualMachines/app';
const disk = (imageReference, wrapped) => ({
  id: diskId, name: 'data',
  ...(wrapped ? { properties: { creationData: { createOption: 'FromImage', imageReference } } } : { creationData: { createOption: 'FromImage', imageReference } })
});
const invalid = ['0', '12', '', "'", '0\n1', '\r\t\u0000', {}, [], true, false, NaN, Infinity, -Infinity, 0.5, -1, Number.MAX_SAFE_INTEGER + 1];

for (const wrapped of [false, true]) {
  for (const alias of ['disks', 'managedDisks', 'volumes']) {
    it(`blocks malformed ${wrapped ? 'ARM' : 'CLI'} image LUNs from ${alias} before emitting Bicep`, () => {
      for (const lun of invalid) {
        const data = { [alias]: [disk({ id: imageId, lun }, wrapped)] };
        const before = structuredClone(data);
        const result = generateBicep(data);
        assert.equal(result.blocked, true, String(lun));
        assert.equal(result.code, '');
        assert.deepEqual(result.stats, {});
        assert.match(result.warnings.join(' '), /data.*creationData\.imageReference\.lun/);
        assert.deepEqual(data, before);
      }
    });

    it(`preserves zero, nonzero, and absent ${wrapped ? 'ARM' : 'CLI'} image LUNs from ${alias}`, () => {
      for (const image of [{ id: imageId }, { id: imageId, lun: undefined }, { id: imageId, lun: null }, ...[0, 3, Number.MAX_SAFE_INTEGER].map(lun => ({ id: imageId, lun }))]) {
        const data = { [alias]: [disk(image, wrapped)] };
        const before = structuredClone(data);
        const result = generateBicep(data);
        assert.notEqual(result.blocked, true);
        assert.ok(result.code.includes("imageReference: { id: '" + imageId + "'" + (image.lun != null ? ', lun: ' + image.lun : '') + ' }'));
        assert.deepEqual(data, before);
      }
    });
  }

  it(`does not validate an image LUN that ${wrapped ? 'ARM' : 'CLI'} disk export will not emit`, () => {
    for (const image of [undefined, null, {}, { lun: '0' }, { id: '', lun: '0' }]) {
      const data = { disks: [disk(image, wrapped)] };
      const before = structuredClone(data);
      const result = generateBicep(data);
      assert.notEqual(result.blocked, true);
      assert.doesNotMatch(result.code, /imageReference:/);
      assert.deepEqual(data, before);
    }
  });
}

it('validates only the active disk alias and preserves nullish alias precedence', () => {
  const valid = disk({ id: imageId, lun: 0 }, false);
  const malformed = disk({ id: imageId, lun: '0' }, false);
  for (const data of [
    { disks: [], managedDisks: [malformed], volumes: [malformed] },
    { disks: [valid], managedDisks: [malformed], volumes: [malformed] },
    { disks: null, managedDisks: [valid], volumes: [malformed] },
    { managedDisks: [], volumes: [malformed] },
    { disks: null, managedDisks: null, volumes: [valid] }
  ]) {
    const before = structuredClone(data);
    assert.notEqual(generateBicep(data).blocked, true);
    assert.deepEqual(data, before);
  }
  for (const data of [
    { disks: [malformed], managedDisks: [valid], volumes: [valid] },
    { disks: null, managedDisks: [malformed], volumes: [valid] },
    { disks: null, managedDisks: null, volumes: [malformed] }
  ]) {
    assert.equal(generateBicep(data).blocked, true);
    assert.equal(generateBicep(data).code, '');
  }
});

for (const alias of ['disks', 'managedDisks', 'volumes']) {
  it(`validates only selected ${alias}, including dependencies attached to a selected VM`, () => {
    const selected = disk({ id: imageId, lun: 0 }, false);
    const excluded = { ...disk({ id: imageId, lun: '0' }, false), id: diskId + '-excluded', name: 'excluded' };
    const data = {
      vnets: [{ id: netId, name: 'net' }],
      nics: [{ id: nicId, name: 'nic', ipConfigurations: [{ subnet: { id: netId + '/subnets/app' } }] }],
      vms: [{ id: vmId, name: 'app', networkProfile: { networkInterfaces: [{ id: nicId }] }, storageProfile: { dataDisks: [{ lun: 0, managedDisk: { id: diskId } }] } }],
      [alias]: [selected, excluded]
    };
    const before = structuredClone(data);
    const options = { scopeVpcId: netId };
    assert.equal(generateBicep(data).blocked, true);
    const result = generateBicep(data, options);
    assert.notEqual(result.blocked, true);
    assert.match(result.code, /resource data 'Microsoft.Compute\/disks/);
    assert.doesNotMatch(result.code, /resource excluded /);
    assert.deepEqual(data, before);
    selected.creationData.imageReference.lun = '0';
    assert.equal(generateBicep(data, options).blocked, true);
    assert.equal(generateBicep(data, options).code, '');
  });
}

it('leaves ARM and Terraform image-LUN exports unchanged', () => {
  const data = { managedDisks: [disk({ id: imageId, lun: '0' }, true)] };
  const before = structuredClone(data);
  for (const generate of [generateARM, generateTerraform]) {
    const result = generate(data);
    assert.notEqual(result.blocked, true);
    assert.ok(result.code.length > 0);
  }
  const arm = JSON.parse(generateARM(data).code).resources.find(resource => resource.type.endsWith('/disks'));
  assert.equal(arm.properties.creationData.imageReference.lun, '0');
  assert.deepEqual(data, before);
});
