import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const SubnetResourceTree = require('../../src/modules/subnet-resource-tree.js');
const source = readFileSync('src/modules/subnet-resource-tree.js', 'utf8');

describe('subnet-resource-tree module boundary', () => {
  it('does not pull in detail-panel DOM, map, or search navigation state', () => {
    const forbidden = [
      'document.',
      'window.',
      '_rlCtx',
      '_mapSvg',
      '_mapG',
      'openSubnetPanel',
      'openGatewayPanel',
      'SearchPanel',
      'detailPanel'
    ];

    for (const token of forbidden) {
      assert.equal(source.includes(token), false, `subnet-resource-tree.js should not contain runtime token ${token}`);
    }
  });
});

describe('buildResTree', () => {
  it('builds a subnet inventory with nested VM attachments and storage posture', () => {
    const tree = SubnetResourceTree.buildResTree('subnet-1', {
      showNested: true,
      instBySub: {
        'subnet-1': [{
          InstanceId: 'vm-00000001',
          InstanceType: 'Standard_D2s_v5',
          PrivateIpAddress: '10.0.1.4',
          State: { Name: 'running' },
          Tags: [{ Key: 'Name', Value: 'api-vm' }],
          SecurityGroups: [{ GroupName: 'web-nsg' }]
        }]
      },
      eniByInst: {
        'vm-00000001': [{ NetworkInterfaceId: 'nic-00000001', PrivateIpAddress: '10.0.1.4' }]
      },
      eniBySub: {
        'subnet-1': [
          { NetworkInterfaceId: 'nic-00000001', PrivateIpAddress: '10.0.1.4' },
          { NetworkInterfaceId: 'nic-standalone', PrivateIpAddress: '10.0.1.9', Groups: [{ GroupName: 'ops-nsg' }] }
        ]
      },
      volByInst: {
        'vm-00000001': [{ VolumeId: 'disk-1', Size: 64, VolumeType: 'Premium_LRS' }]
      },
      snapByVol: {
        'disk-1': [{ SnapshotId: 'snap-1' }]
      },
      storageBySub: {
        'subnet-1': [{
          via: 'Private Endpoint',
          detail: 'blob',
          account: {
            id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/data',
            name: 'data'
          }
        }]
      }
    });

    assert.deepEqual(tree.map(item => item.type), ['VM', 'NIC', 'STG']);
    assert.equal(tree[0].name, 'api-vm');
    assert.deepEqual(tree[0].children.map(child => child.type), ['NIC', 'VOL']);
    assert.equal(tree[1].rid, 'nic-standalone');
    assert.equal(tree[2].fullType, 'Storage Account');
    assert.equal(tree[2].ip, 'Private Endpoint');
  });

  it('supports flat mode without VM child resources', () => {
    const tree = SubnetResourceTree.buildResTree('subnet-1', {
      showNested: false,
      instBySub: {
        'subnet-1': [{ InstanceId: 'vm-00000001', State: { Name: 'running' } }]
      },
      eniByInst: {
        'vm-00000001': [{ NetworkInterfaceId: 'nic-00000001' }]
      },
      eniBySub: {
        'subnet-1': [{ NetworkInterfaceId: 'nic-00000001' }]
      },
      volByInst: {
        'vm-00000001': [{ VolumeId: 'disk-1', Size: 64 }]
      }
    });

    assert.equal(tree.length, 1);
    assert.equal(tree[0].type, 'VM');
    assert.deepEqual(tree[0].children, []);
  });
});

describe('subMaxChildren', () => {
  it('returns the largest nested child count in a subnet tree', () => {
    const max = SubnetResourceTree.subMaxChildren('subnet-1', {
      showNested: true,
      instBySub: {
        'subnet-1': [{ InstanceId: 'vm-00000001' }]
      },
      eniByInst: {
        'vm-00000001': [{ NetworkInterfaceId: 'nic-00000001' }]
      },
      volByInst: {
        'vm-00000001': [
          { VolumeId: 'disk-1', Size: 64 },
          { VolumeId: 'disk-2', Size: 128 }
        ]
      }
    });

    assert.equal(max, 3);
  });
});
