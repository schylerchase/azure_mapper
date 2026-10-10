import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const FirewallDashboardModel = require('../../src/modules/firewall-dashboard-model.js');
const source = readFileSync('src/modules/firewall-dashboard-model.js', 'utf8');

describe('firewall dashboard model boundary', () => {
  it('stays pure and does not pull in DOM or runtime bridge wiring', () => {
    const forbidden = [
      'document.',
      'window.',
      '_rlCtx',
      '_showToast',
      '_escHtml',
      'firewallRuntimeData',
      'openUnifiedDash'
    ];

    for (const token of forbidden) {
      assert.equal(source.includes(token), false, `firewall-dashboard-model.js should not contain runtime token ${token}`);
    }
  });
});

describe('FirewallDashboardModel', () => {
  const ctx = {
    vnets: [
      { VpcId: 'vnet-hub', Tags: [{ Key: 'Name', Value: 'Hub VNet' }] },
      { VpcId: 'vnet-spoke', Tags: [{ Key: 'Name', Value: 'Spoke VNet' }] }
    ],
    nsgs: [
      {
        GroupId: 'nsg-web',
        GroupName: 'web-nsg',
        VpcId: 'vnet-hub',
        Description: 'web tier',
        _subscriptionId: 'sub-a',
        IpPermissions: [{ IpRanges: [{ CidrIp: '0.0.0.0/0' }] }],
        IpPermissionsEgress: []
      },
      {
        GroupId: 'nsg-spoke',
        GroupName: 'spoke-nsg',
        VpcId: 'vnet-spoke',
        _subscriptionId: 'sub-b',
        IpPermissions: [],
        IpPermissionsEgress: []
      }
    ],
    subnetNsgs: [{
      NetworkAclId: 'nacl-hub',
      VpcId: 'vnet-hub',
      _subscriptionId: 'sub-a',
      Entries: [
        { RuleNumber: 100, Egress: false },
        { RuleNumber: 32767, Egress: false },
        { RuleNumber: 100, Egress: true }
      ]
    }],
    udrs: [{
      RouteTableId: 'rt-hub',
      VpcId: 'vnet-hub',
      _subscriptionId: 'sub-a',
      Routes: [{ DestinationCidrBlock: '0.0.0.0/0' }]
    }]
  };

  it('builds firewall resource rows, summary metrics, filters, sorting, and VNet groups', () => {
    const view = FirewallDashboardModel.buildViewModel(
      ctx,
      { search: '', vpcFilter: 'all', sort: 'severity', sortDir: 'asc', cardFilter: 'findings', groupBy: 'vpc' },
      'all',
      {
        complianceLookup: {
          'nsg-web': { worst: 'HIGH', count: 2, findings: [{ severity: 'HIGH' }] },
          'rt-hub': { worst: 'LOW', count: 1, findings: [{ severity: 'LOW' }] }
        },
        editCount: id => id === 'rt-hub' ? 1 : 0,
        totalEdits: 1,
        accountFilter: rows => rows.filter(row => row._subscriptionId !== 'sub-b'),
        nameForResource: (resource, fallback) => {
          const tag = (resource.Tags || []).find(t => t.Key === 'Name');
          return tag ? tag.Value : resource.GroupName || fallback;
        }
      }
    );

    assert.deepEqual(view.rows.map(row => row.id), ['nsg-web', 'nacl-hub', 'rt-hub']);
    assert.equal(view.summary.resources, 3);
    assert.equal(view.summary.securityGroups, 1);
    assert.equal(view.summary.subnetNsgs, 1);
    assert.equal(view.summary.routeTables, 1);
    assert.equal(view.summary.totalFindings, 3);
    assert.equal(view.summary.worstSeverity, 'HIGH');
    assert.equal(view.summary.openIngress, 1);
    assert.equal(view.summary.totalEdits, 1);

    assert.deepEqual(view.filteredRows.map(row => row.id), ['nsg-web', 'rt-hub']);
    assert.equal(view.groups.length, 1);
    assert.equal(view.groups[0].label, 'Hub VNet');
    assert.equal(view.groups[0].stats.findings, 3);
    assert.equal(view.groups[0].stats.open, 1);
    assert.deepEqual(view.columns.map(col => col.k), ['type', 'name', 'vpc', 'rules', 'severity', 'edits']);
  });

  it('builds VNet filter options from runtime data without DOM access', () => {
    const options = FirewallDashboardModel.buildVnetOptions(ctx, {
      nameForResource: (resource, fallback) => resource.Tags?.[0]?.Value || fallback
    });

    assert.deepEqual(options, [
      { id: 'vnet-hub', label: 'Hub VNet' },
      { id: 'vnet-spoke', label: 'Spoke VNet' }
    ]);
  });
});
