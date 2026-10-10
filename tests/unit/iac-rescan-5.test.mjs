import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';

const root = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/';
for (const wrapped of [false, true]) {
  it(`retains a native ${wrapped ? 'ARM' : 'CLI'} NIC's existing subnet reference when no subnet is collected`, () => {
    const vnetId = root + 'virtualNetworks/imported';
    const existingSubnetId = root + 'virtualNetworks/existing/subnets/app';
    const shape = (id, name, properties) => ({ id, name, ...(wrapped ? { properties } : properties) });
    const data = {
      vnets: [shape(vnetId, 'imported', { addressSpace: { addressPrefixes: ['10.0.0.0/16'] } })],
      nics: [shape(root + 'networkInterfaces/nic', 'nic', { ipConfigurations: [shape(undefined, 'primary', { privateIPAllocationMethod: 'Dynamic', privateIPAddressVersion: 'IPv4', subnet: { id: existingSubnetId } })] })]
    };
    const before = structuredClone(data);
    const bicep = generateBicep(data).code;
    assert.ok(bicep.includes("subnet: { id: '" + existingSubnetId + "' }"));
    assert.ok(generateTerraform(data).code.toLowerCase().includes(existingSubnetId.toLowerCase()));
    const arm = JSON.parse(generateARM(data).code).resources.find(resource => resource.type.endsWith('/networkInterfaces'));
    assert.match(arm.properties.ipConfigurations[0].properties.subnet.id, /virtualNetworks\/subnets.*existing.*app/);
    assert.deepEqual(data, before);

    const collectedSubnetId = vnetId + '/subnets/app';
    const subnet = shape(collectedSubnetId, 'app', { addressPrefix: '10.0.1.0/24' });
    (data.vnets[0].properties || data.vnets[0]).subnets = [subnet];
    const ipConfig = (data.nics[0].properties || data.nics[0]).ipConfigurations[0];
    (ipConfig.properties || ipConfig).subnet.id = collectedSubnetId;
    const normal = generateBicep(data).code;
    assert.match(normal, /subnet: \{\s*id: app.id\s*\}/);
    assert.ok(!normal.includes("subnet: { id: '" + collectedSubnetId + "' }"), 'collected subnets retain symbolic dependencies');
  });
}
