import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';

const root = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/';
function fixture(lun, caching, nested, attached = true) {
  const disk = { lun, caching, ...(attached ? { managedDisk: { id: root + 'disks/data' } } : {}) };
  const props = { storageProfile: { dataDisks: [disk] } };
  return { vms: [{ id: root + 'virtualMachines/vm', name: 'vm', ...(nested ? { properties: props } : props) }] };
}

for (const nested of [false, true]) {
  it(`rejects non-integer attachment LUNs before emitting HCL (${nested})`, () => {
    for (const value of ['0', '0 " sample', '0\n sample', '${sample}', null, undefined, false, {}, [], -1, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
      const data = fixture(value, 'None', nested);
      const before = structuredClone(data);
      const result = generateTerraform(data);
      assert.equal(result.blocked, true, String(value));
      assert.equal(result.code, '');
      assert.match(result.warnings.join(' '), /data-disk LUN.*nonnegative integer/);
      assert.deepEqual(data, before);
    }
  });
  it(`rejects non-enum attachment caching (${nested})`, () => {
    for (const value of ['None " sample', 'ReadOnly\n sample', '${sample}', '%{sample}', 'readwrite', 1, false, {}, ['None']]) {
      const result = generateTerraform(fixture(0, value, nested));
      assert.equal(result.blocked, true, String(value));
      assert.equal(result.code, '');
      assert.match(result.warnings.join(' '), /data-disk caching.*None.*ReadOnly.*ReadWrite/);
    }
  });
  it(`retains numeric LUNs, supported caching and defaults (${nested})`, () => {
    for (const lun of [0, 3]) for (const caching of ['None', 'ReadOnly', 'ReadWrite', undefined, null, '']) {
      const data = fixture(lun, caching, nested);
      const before = structuredClone(data);
      const result = generateTerraform(data);
      assert.notEqual(result.blocked, true);
      assert.ok(result.code.includes('  lun                = ' + lun));
      assert.ok(result.code.includes('  caching            = "' + (caching || 'None') + '"'));
      assert.deepEqual(data, before);
    }
  });
}

it('does not validate unused data-disk fields or alter ARM JSON output', () => {
  assert.notEqual(generateTerraform(fixture('unused', 'unused', false, false)).blocked, true);
  assert.notEqual(generateARM(fixture('0', 'None', false)).blocked, true);
  assert.notEqual(generateTerraform(fixture('unused', 'None', false), { scopeVpcId: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/other' }).blocked, true);
});
