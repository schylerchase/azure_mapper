import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ext } from '../../src/modules/utils.js';
import { _normalizeAzureResources } from '../../src/modules/normalization.js';

const EXPORT_DIR = join(import.meta.dirname, '../../azure-export-00b800a2-140e-4a89-94f9-ed6aab746a51-20260330-105511');

function loadAndParse(filename) {
  const raw = readFileSync(join(EXPORT_DIR, filename), 'utf8');
  return ext(JSON.parse(raw), ['value']);
}

describe('Integration: Azure export normalization (R1.6)', () => {
  it('normalizes VNets with VpcId and CidrBlock', () => {
    const vnets = loadAndParse('vnets.json');
    const d = { vpcs: vnets };
    _normalizeAzureResources(d);
    assert.ok(d.vpcs.length > 0, 'should have at least one VNet');
    const v = d.vpcs[0];
    assert.ok(v.VpcId, 'VNet should have VpcId set');
    assert.ok(v.CidrBlock, 'VNet should have CidrBlock set');
  });

  it('normalizes subnets with SubnetId, VpcId, CidrBlock', () => {
    const subnets = loadAndParse('subnets.json');
    const d = { subnets };
    _normalizeAzureResources(d);
    assert.ok(d.subnets.length > 0, 'should have at least one subnet');
    const s = d.subnets[0];
    assert.ok(s.SubnetId, 'Subnet should have SubnetId set');
    assert.ok(s.CidrBlock || s.addressPrefix, 'Subnet should have CidrBlock or addressPrefix');
  });

  it('normalizes NSGs with GroupId and IpPermissions', () => {
    const nsgs = loadAndParse('nsgs.json');
    const d = { sgs: nsgs };
    _normalizeAzureResources(d);
    assert.ok(d.sgs.length > 0, 'should have at least one NSG');
    const nsg = d.sgs[0];
    assert.ok(nsg.GroupId, 'NSG should have GroupId set');
    assert.ok(Array.isArray(nsg.IpPermissions), 'NSG should have IpPermissions array');
  });

  it('all normalized VNets have Tags array', () => {
    const vnets = loadAndParse('vnets.json');
    const d = { vpcs: vnets };
    _normalizeAzureResources(d);
    d.vpcs.forEach((v, i) => {
      assert.ok(Array.isArray(v.Tags), `VNet ${i} should have Tags array`);
    });
  });

  it('normalized VNets have properties self-reference', () => {
    const vnets = loadAndParse('vnets.json');
    const d = { vpcs: vnets };
    _normalizeAzureResources(d);
    const v = d.vpcs[0];
    assert.strictEqual(v.properties, v, 'VNet properties should be self-reference');
  });
});
