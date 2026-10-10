import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const SearchIndex = require('../../src/modules/search-index.js');
const source = readFileSync('src/modules/search-index.js', 'utf8');

describe('search-index module boundary', () => {
  it('stays pure and does not pull in overlay or detail-panel wiring', () => {
    const forbidden = [
      'document.',
      'window.',
      '_rlCtx',
      'ResourceNavigation',
      'openSearch',
      'closeSearch',
      'detailPanel'
    ];

    for (const token of forbidden) {
      assert.equal(source.includes(token), false, `search-index.js should not contain runtime token ${token}`);
    }
  });
});

describe('buildSearchIndex', () => {
  it('indexes Azure network resources with names, ids, CIDRs, and account labels', () => {
    const index = SearchIndex.buildSearchIndex({
      vpcs: [{
        VpcId: 'vnet-1',
        CidrBlock: '10.0.0.0/16',
        Tags: [{ Key: 'Name', Value: 'Hub VNet' }],
        _accountLabel: 'prod'
      }],
      subnets: [{
        SubnetId: 'subnet-1',
        CidrBlock: '10.0.1.0/24',
        Tags: [{ Key: 'Name', Value: 'Web Subnet' }],
        _subscriptionId: 'sub-123'
      }],
      instances: [{
        InstanceId: 'vm-1',
        InstanceType: 'Standard_D2s_v5',
        name: 'api-vm'
      }],
      sgs: [{
        GroupId: 'nsg-1',
        GroupName: 'web-nsg',
        VpcId: 'vnet-1'
      }]
    });

    assert.deepEqual(index.map(item => item.type), ['VNet', 'Subnet', 'VM', 'NSG']);
    assert.deepEqual(index[0], {
      type: 'VNet',
      name: 'Hub VNet',
      id: 'vnet-1',
      extra: '10.0.0.0/16',
      acct: 'prod',
      searchStr: 'vnet hub vnet vnet-1 10.0.0.0/16'
    });
    assert.equal(index[1].acct, 'sub-123');
    assert.equal(index[2].extra, 'Standard_D2s_v5');
  });
});

describe('findSearchMatches', () => {
  it('matches case-insensitively and honors the result limit', () => {
    const index = SearchIndex.buildSearchIndex({
      vpcs: [
        { VpcId: 'hub-vnet', CidrBlock: '10.0.0.0/16' },
        { VpcId: 'spoke-vnet', CidrBlock: '10.1.0.0/16' }
      ],
      subnets: [
        { SubnetId: 'hub-web-subnet', CidrBlock: '10.0.1.0/24' }
      ]
    });

    const matches = SearchIndex.findSearchMatches(index, 'HUB', 1);

    assert.equal(matches.length, 1);
    assert.equal(matches[0].id, 'hub-vnet');
  });

  it('returns no matches for an empty query', () => {
    const index = SearchIndex.buildSearchIndex({
      vpcs: [{ VpcId: 'hub-vnet', CidrBlock: '10.0.0.0/16' }]
    });

    assert.deepEqual(SearchIndex.findSearchMatches(index, ''), []);
  });
});
