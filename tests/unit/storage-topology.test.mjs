import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const StorageTopology = require('../../src/modules/storage-topology.js');
const source = readFileSync('src/modules/storage-topology.js', 'utf8');

describe('storage-topology module boundary', () => {
  it('does not pull in detail-panel or search overlay state', () => {
    const forbidden = [
      '_rlCtx',
      'openSubnetPanel',
      'openGatewayPanel',
      'SearchPanel',
      'detailPanel'
    ];

    for (const token of forbidden) {
      assert.equal(source.includes(token), false, `storage-topology.js should not contain runtime token ${token}`);
    }
  });
});

describe('_buildStorageTopology', () => {
  it('connects storage accounts to subnets through VNet rules and private endpoints', () => {
    const storageId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/data';
    const account = {
      id: storageId,
      name: 'data',
      sku: { name: 'Standard_LRS' },
      kind: 'StorageV2',
      properties: {
        networkAcls: {
          defaultAction: 'Deny',
          virtualNetworkRules: [{ id: 'subnet-rule', action: 'Allow' }]
        },
        primaryEndpoints: { blob: 'https://data.blob.core.windows.net/' },
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_2'
      }
    };
    const privateEndpoint = {
      SubnetId: 'subnet-private-endpoint',
      properties: {
        privateLinkServiceConnections: [{
          properties: {
            privateLinkServiceId: storageId,
            groupIds: ['blob']
          }
        }]
      }
    };

    const topology = StorageTopology._buildStorageTopology([account], [privateEndpoint]);

    assert.deepEqual(Object.keys(topology.bySub).sort(), ['subnet-private-endpoint', 'subnet-rule']);
    assert.equal(topology.bySub['subnet-rule'][0].via, 'VNet rule');
    assert.equal(topology.bySub['subnet-private-endpoint'][0].via, 'Private Endpoint');
    assert.equal(topology.linksByStorageId[storageId.toLowerCase()].length, 2);
  });
});

describe('_storageInfo', () => {
  it('classifies private storage with explicit network links', () => {
    const storageId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/data';
    const account = {
      id: storageId,
      name: 'data',
      sku: { name: 'Standard_LRS' },
      properties: {
        networkAcls: { defaultAction: 'Deny' },
        primaryEndpoints: { blob: 'https://data.blob.core.windows.net/' },
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_2'
      }
    };
    const topology = {
      linksByStorageId: {
        [storageId.toLowerCase()]: [{ subnetId: 'subnet-private-endpoint', via: 'Private Endpoint' }]
      }
    };

    const info = StorageTopology._storageInfo(account, topology);

    assert.equal(info.access, 'Deny by default + Private Endpoint');
    assert.equal(info.severity, 'private');
    assert.equal(info.hasPe, true);
    assert.deepEqual(info.services, ['blob']);
  });

  it('flags public blob or weak transport settings as risk', () => {
    const info = StorageTopology._storageInfo({
      name: 'open',
      properties: {
        networkAcls: { defaultAction: 'Allow' },
        allowBlobPublicAccess: true,
        supportsHttpsTrafficOnly: false,
        minimumTlsVersion: 'TLS1_0'
      }
    }, { linksByStorageId: { open: [] } });

    assert.equal(info.access, 'Public blob');
    assert.equal(info.severity, 'risk');
    assert.equal(info.publicBlob, true);
    assert.equal(info.httpsOnly, false);
  });
});
