import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const GovernanceInventoryModel = require('../../src/modules/governance-inventory-model.js');
const source = readFileSync('src/modules/governance-inventory-model.js', 'utf8');

describe('governance inventory model boundary', () => {
  it('stays pure and does not pull in DOM or runtime bridge wiring', () => {
    const forbidden = [
      'document.',
      'window.',
      '_rlCtx',
      '_complianceFindings',
      '_escHtml',
      '_showToast',
      'downloadBlob',
      'AppRenderContext',
      'AppNotifications',
      'AppDownloads'
    ];

    for (const token of forbidden) {
      assert.equal(source.includes(token), false, `governance-inventory-model.js should not contain runtime token ${token}`);
    }
  });
});

describe('GovernanceInventoryModel', () => {
  const ctx = {
    vpcs: [],
    vnets: [{
      VpcId: 'vnet-hub',
      CidrBlock: '10.0.0.0/16',
      State: 'available',
      _subscriptionId: 'sub-a',
      _region: 'eastus',
      Tags: { Name: 'Hub VNet', environment: 'prod' }
    }],
    pubSubs: new Set(['subnet-app']),
    subnets: [{
      SubnetId: 'subnet-app',
      VpcId: 'vnet-hub',
      CidrBlock: '10.0.1.0/24',
      AvailabilityZone: '1',
      State: 'available',
      _subscriptionId: 'sub-a',
      _region: 'eastus',
      Tags: [{ Key: 'Name', Value: 'App Subnet' }]
    }],
    vms: [{
      InstanceId: 'vm-web',
      VpcId: 'vnet-hub',
      SubnetId: 'subnet-app',
      InstanceType: 'Standard_D2s_v5',
      State: { Name: 'running' },
      SecurityGroups: [{ GroupId: 'nsg-web' }],
      _subscriptionId: 'sub-a',
      _region: 'eastus',
      Tags: { Name: 'Frontend VM' }
    }],
    nsgs: [{
      GroupId: 'nsg-web',
      GroupName: 'web-nsg',
      VpcId: 'vnet-hub',
      IpPermissions: [{ FromPort: 443 }],
      IpPermissionsEgress: [{}],
      _subscriptionId: 'sub-a',
      _region: 'eastus'
    }],
    udrs: [{
      RouteTableId: 'udr-web',
      VpcId: 'vnet-hub',
      Routes: [{ DestinationCidrBlock: '0.0.0.0/0' }],
      _subscriptionId: 'sub-a',
      _region: 'eastus',
      Tags: { Name: 'web-udr' }
    }],
    appGateways: [{
      LoadBalancerName: 'agw-web',
      VpcId: 'vnet-hub',
      Type: 'application',
      Scheme: 'internet-facing',
      _subscriptionId: 'sub-a',
      _region: 'eastus'
    }],
    redisCaches: [{
      CacheClusterId: 'redis-web',
      VpcId: 'vnet-hub',
      Engine: 'redis',
      CacheNodeType: 'Premium',
      CacheClusterStatus: 'available',
      _subscriptionId: 'sub-a',
      _region: 'eastus'
    }],
    synapseWorkspaces: [{
      ClusterIdentifier: 'synapse-prod',
      VpcId: 'vnet-hub',
      NodeType: 'DW100c',
      NumberOfNodes: 1,
      ClusterStatus: 'online',
      Encrypted: true,
      _subscriptionId: 'sub-a',
      _region: 'eastus'
    }],
    functionApps: [{
      FunctionName: 'func-worker',
      VpcConfig: { VpcId: 'vnet-hub', SubnetIds: ['subnet-app'] },
      Runtime: 'node',
      MemorySize: 512,
      State: 'Active',
      _subscriptionId: 'sub-a',
      _region: 'eastus'
    }],
    firewalls: [{
      InternetGatewayId: 'fw-hub',
      Attachments: [{ VpcId: 'vnet-hub', State: 'attached' }],
      _subscriptionId: 'sub-a',
      _region: 'eastus',
      Tags: { Name: 'Hub Firewall' }
    }],
    natGateways: [{
      NatGatewayId: 'nat-hub',
      VpcId: 'vnet-hub',
      SubnetId: 'subnet-app',
      State: 'available',
      _subscriptionId: 'sub-a',
      _region: 'eastus'
    }],
    privateEndpoints: [{
      VpcEndpointId: 'pe-storage',
      VpcId: 'vnet-hub',
      ServiceName: 'Microsoft.Storage',
      State: 'available',
      _subscriptionId: 'sub-a',
      _region: 'eastus'
    }]
  };

  it('builds Azure-named inventory rows with classification, BUDR, and compliance enrichment', () => {
    const rows = GovernanceInventoryModel.buildInventoryData(ctx, {
      classificationData: [{ id: 'subnet-app', tier: 'restricted' }],
      budrAssessments: [{
        id: 'vm-web',
        profile: { tier: 'tier1', strategy: 'snapshot', rto: '4h', rpo: '15m' }
      }],
      complianceFindings: [
        { resource: 'subnet-app', status: 'FAIL' },
        { resource: 'vm-web', status: 'PASS' },
        { resource: 'vm-web', status: 'FAIL' }
      ]
    });

    assert.deepEqual(
      rows.map(row => row.type),
      ['VNet', 'Subnet', 'VM', 'Function App', 'App Gateway', 'Redis Cache', 'Synapse', 'NSG', 'UDR', 'Azure Firewall', 'NAT GW', 'Private Endpoint']
    );

    const subnet = rows.find(row => row.id === 'subnet-app');
    assert.equal(subnet.name, 'App Subnet');
    assert.equal(subnet.vpcName, 'Hub VNet');
    assert.equal(subnet.config, '10.0.1.0/24 public');
    assert.equal(subnet.classificationTier, 'restricted');
    assert.equal(subnet.complianceFail, 1);

    const vm = rows.find(row => row.id === 'vm-web');
    assert.equal(vm.name, 'Frontend VM');
    assert.equal(vm.vpcName, 'Hub VNet');
    assert.equal(vm.budrTier, 'tier1');
    assert.equal(vm.budrStrategy, 'snapshot');
    assert.equal(vm.rto, '4h');
    assert.equal(vm.rpo, '15m');
    assert.equal(vm.compliancePass, 1);
    assert.equal(vm.complianceFail, 1);
    assert.deepEqual(vm._related, ['nsg-web']);
  });

  it('filters, searches, scopes by account, and sorts inventory rows without runtime state', () => {
    const rows = GovernanceInventoryModel.buildInventoryData(ctx);
    const filtered = GovernanceInventoryModel.filterInventory(
      rows,
      { typeFilter: 'VM', vpcFilter: 'vnet-hub', search: 'frontend', sort: 'name', sortDir: 'asc' },
      items => items.filter(row => row.account === 'sub-a')
    );

    assert.deepEqual(filtered.map(row => row.id), ['vm-web']);

    const routeRows = GovernanceInventoryModel.filterInventory(
      rows,
      { typeFilter: 'UDR', search: 'web', sort: 'type', sortDir: 'desc' }
    );

    assert.deepEqual(routeRows.map(row => row.id), ['udr-web']);
  });
});
