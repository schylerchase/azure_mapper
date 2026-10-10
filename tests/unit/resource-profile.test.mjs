import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const ResourceProfile = require('../../src/modules/resource-profile.js');
const source = readFileSync('src/modules/resource-profile.js', 'utf8');

describe('resource-profile module boundary', () => {
  it('stays pure and does not pull in navigation or DOM wiring', () => {
    const forbidden = [
      'document.',
      'window.',
      '_rlCtx',
      'AppRenderContext',
      'ResourceNavigation',
      'MapViewport',
      'openDetailForSearch'
    ];

    for (const token of forbidden) {
      assert.equal(source.includes(token), false, `resource-profile.js should not contain runtime token ${token}`);
    }
  });
});

describe('resolveResourceType', () => {
  it('resolves ARM ids and collection-backed Azure resource types', () => {
    const ctx = {
      sqlServers: [{ id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/sql-a' }],
      functionApps: [{ name: 'func-a' }],
      nsgs: [{ id: 'nsg-a' }]
    };

    assert.equal(ResourceProfile.resolveResourceType(ctx, '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub'), 'VNet');
    assert.equal(ResourceProfile.resolveResourceType(ctx, '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub/subnets/web'), 'Subnet');
    assert.equal(ResourceProfile.resolveResourceType(ctx, '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/api'), 'VM');
    assert.equal(ResourceProfile.resolveResourceType(ctx, 'func-a'), 'Function App');
    assert.equal(ResourceProfile.resolveResourceType(ctx, 'nsg-a'), 'NSG');
  });
});

describe('buildResourceProfile', () => {
  it('builds a VNet profile with subnet count and nearby subnet links', () => {
    const ctx = {
      vnets: [{
        id: 'vnet-1',
        name: 'hub-vnet',
        location: 'eastus',
        properties: { addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }
      }],
      subnets: [
        { id: 'subnet-1', name: 'web', properties: { vnetId: 'vnet-1' } },
        { id: 'subnet-2', name: 'data', properties: { vnetId: 'vnet-1' } }
      ]
    };

    const profile = ResourceProfile.buildResourceProfile(ctx, 'vnet-1');

    assert.equal(profile.type, 'VNet');
    assert.equal(profile.name, 'hub-vnet');
    assert.deepEqual(profile.details, [
      ['Address Space', '10.0.0.0/16'],
      ['Location', 'eastus'],
      ['Subnets', '2']
    ]);
    assert.deepEqual(profile.nearby.map(item => item.id), ['subnet-1', 'subnet-2']);
  });

  it('builds a subnet profile with VNet relation, nearby VMs, and filtered findings', () => {
    const ctx = {
      subnets: [{
        id: 'subnet-1',
        SubnetId: 'subnet-1',
        name: 'web',
        CidrBlock: '10.0.1.0/24',
        VpcId: 'vnet-1',
        AvailabilityZone: 'eastus-1'
      }],
      instances: [
        { InstanceId: 'vm-1', name: 'api', SubnetId: 'subnet-1' },
        { InstanceId: 'vm-2', name: 'worker', SubnetId: 'subnet-2' }
      ]
    };
    const findings = [
      { resource: 'subnet-1', message: 'included' },
      { resource: 'subnet-1', message: 'muted', muted: true },
      { resource: 'other', message: 'ignored' }
    ];

    const profile = ResourceProfile.buildResourceProfile(ctx, 'subnet-1', findings, finding => !finding.muted);

    assert.equal(profile.type, 'Subnet');
    assert.deepEqual(profile.details, [
      ['Address Prefix', '10.0.1.0/24'],
      ['Location', 'eastus-1'],
      ['VNet', 'vnet-1']
    ]);
    assert.deepEqual(profile.related, [{ id: 'vnet-1', name: 'vnet-1', type: 'VNet' }]);
    assert.deepEqual(profile.nearby, [{ id: 'vm-1', name: 'api', type: 'VM' }]);
    assert.deepEqual(profile.findings.map(finding => finding.message), ['included']);
  });

  it('builds a generic resource profile with network relations', () => {
    const ctx = {
      functionApps: [{
        id: 'func-1',
        name: 'orders-api',
        location: 'westus',
        properties: {
          provisioningState: 'Succeeded',
          subnetId: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub/subnets/app'
        }
      }]
    };

    const profile = ResourceProfile.buildResourceProfile(ctx, 'func-1');

    assert.equal(profile.type, 'Function App');
    assert.equal(profile.name, 'orders-api');
    assert.ok(profile.details.some(row => row[0] === 'State' && row[1] === 'Succeeded'));
    assert.deepEqual(profile.related, [{
      id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub/subnets/app',
      name: 'app',
      type: 'Subnet'
    }]);
  });
});
