import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';

const root = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/';
function fixture(version, nested, nestedIp = nested) {
  const props = { privateIPAddressVersion: version, privateIPAllocationMethod: 'Dynamic' };
  const ip = { name: 'primary', ...(nestedIp ? { properties: props } : props) };
  const nicProps = { ipConfigurations: [ip] };
  return { nics: [{ id: root + 'networkInterfaces/nic', name: 'nic', ...(nested ? { properties: nicProps } : nicProps) }] };
}

for (const nested of [false, true]) for (const nestedIp of [false, true]) {
  it(`rejects non-enum IP versions before HCL generation (${nested}/${nestedIp})`, () => {
    for (const value of ['IPv4 " sample', 'IPv6\n sample', '${sample}', '%{sample}', 'ipv4', 'IPv5', 4, false, {}, ['IPv4']]) {
      const data = fixture(value, nested, nestedIp);
      const before = structuredClone(data);
      const result = generateTerraform(data);
      assert.equal(result.blocked, true, JSON.stringify(value));
      assert.equal(result.code, '');
      assert.match(result.warnings.join(' '), /IP address version.*IPv4.*IPv6/);
      assert.deepEqual(data, before);
    }
  });
  it(`retains IPv4, IPv6 and default behavior (${nested}/${nestedIp})`, () => {
    for (const value of ['IPv4', 'IPv6', undefined, null, '']) {
      const result = generateTerraform(fixture(value, nested, nestedIp));
      assert.notEqual(result.blocked, true);
      assert.ok(result.code.includes('private_ip_address_version    = "' + (value || 'IPv4') + '"'));
    }
  });
}

it('validates only selected Terraform NICs without changing Bicep literal handling', () => {
  const data = fixture('IPv4 " sample', false);
  assert.notEqual(generateBicep(data).blocked, true);
  const result = generateTerraform(data, { scopeVpcId: root + 'virtualNetworks/other' });
  assert.notEqual(result.blocked, true);
  assert.doesNotMatch(result.code, /resource "azurerm_network_interface"/);
});
