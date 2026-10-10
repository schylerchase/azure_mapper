import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { runCISAzureChecks } from '../../src/modules/compliance-cis-azure-checks.js';
import { runBUDRChecks as runPublicBUDRChecks, budrAssessments } from '../../src/modules/budr-engine.js';
import { _normalizeAzureResources } from '../../src/modules/normalization.js';

const base = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/assessment/providers/';
const connection = (status, groupIds = []) => ({ properties: { privateLinkServiceConnectionState: { status }, groupIds } });
const endpoint = (name, properties) => ({ id: base + 'Microsoft.Network/privateEndpoints/' + name, name, properties });
const gateway = (tier, zones) => ({
  id: base + 'Microsoft.Network/applicationGateways/gateway', name: 'gateway',
  type: 'Microsoft.Network/applicationGateways', location: 'uncollected-region',
  properties: { sku: { tier, name: tier } }, ...(zones === undefined ? {} : { zones })
});

function registryRunner() {
  const sandbox = vm.createContext({ structuredClone });
  vm.runInContext(readFileSync('src/modules/governance-classification.js', 'utf8') + '\n' + readFileSync('src/modules/budr-report-registry.js', 'utf8'), sandbox);
  return ctx => ({ findings: sandbox.runBUDRChecks(ctx), assessments: vm.runInContext('_budrAssessments', sandbox) });
}

describe('fourth rescan compliance evidence', () => {
  it('reports pending and rejected automatic and manual connections, while leaving approved connections clear', () => {
    for (const key of ['privateLinkServiceConnections', 'manualPrivateLinkServiceConnections']) {
      for (const [status, expected] of [['Pending', 'PE-PENDING'], ['Rejected', 'PE-ORPHAN'], ['Disconnected', 'PE-ORPHAN'], ['Failed', 'PE-ORPHAN'], ['Approved', null]]) {
        const findings = runCISAzureChecks({ privateEndpoints: [endpoint('pe', { [key]: [connection(status)] })] });
        assert.deepEqual(findings.map(f => f.id), expected ? [expected] : []);
      }
    }
  });

  it('retains later connection states and all manual DNS groups without duplicating state findings', () => {
    const findings = runCISAzureChecks({ privateEndpoints: [endpoint('pe', {
      privateLinkServiceConnections: [connection('Approved')],
      manualPrivateLinkServiceConnections: [connection('Pending', ['blob', 'file']), connection('Pending', ['blob'])]
    })] });
    assert.equal(findings.filter(f => f.id === 'PE-PENDING').length, 1);
    assert.equal(findings.filter(f => f.id === 'PE-NO-DNS').length, 2);
    assert.ok(findings.some(f => f.message.includes('privatelink.file.core.windows.net')));
    assert.deepEqual(runCISAzureChecks({ privateEndpoints: [endpoint('empty', {})] }), []);
  });

  it('reports SSH only when an open-source inbound allow rule permits TCP port 22', () => {
    for (const [protocol, expected] of [['Tcp', true], ['tCp', true], ['*', true], ['Udp', false], ['Icmp', false], ['', false]]) {
      for (const portProperties of [{ destinationPortRange: '22' }, { destinationPortRanges: ['20-24'] }]) {
        const findings = runCISAzureChecks({ nsgs: [{ name: 'nsg', properties: { securityRules: [{ name: 'rule', properties: {
          protocol, direction: 'Inbound', access: 'Allow', sourceAddressPrefix: '::/0', ...portProperties
        } }] } }] });
        assert.equal(findings.some(f => f.id === 'CIS-10'), expected, protocol);
      }
    }
  });
});

describe('fourth rescan App Gateway zone evidence in both engines', () => {
  it('does not claim a default v2 gateway is single-zone when regional support is uncollected', () => {
    for (const run of [registryRunner(), ctx => ({ findings: runPublicBUDRChecks(ctx), assessments: budrAssessments })]) {
      for (const tier of ['Standard_v2', 'WAF_v2']) {
        for (const zones of [undefined, []]) {
          const agw = gateway(tier, zones);
          // Legacy normalization can derive AvailabilityZones from frontend subnets;
          // subnet count is not evidence of Application Gateway zone placement.
          agw.frontendIPConfigurations = [{ subnet: { id: 'subnet' } }];
          _normalizeAzureResources({ albs: [agw] });
          const ctx = { appGateways: [agw] };
          const { findings, assessments } = run(ctx);
          assert.equal(assessments[0].profile.tier, 'unknown');
          assert.equal(assessments[0].profile.rto, 'Unknown');
          assert.equal(assessments[0].signals.ZoneCount, 'Unknown');
          assert.equal(findings.some(f => f.control === 'BUDR-HA-6'), false);
          assert.equal(assessments[0].compliance.status, 'unknown');
          assert.ok(ctx.assessmentGaps.appGatewayZones);
        }
      }
    }
  });

  it('preserves explicit single-zone warnings and multizone protection', () => {
    for (const run of [registryRunner(), ctx => ({ findings: runPublicBUDRChecks(ctx), assessments: budrAssessments })]) {
      for (const [zones, tier, warning] of [[['1'], 'partial', true], [['1', '2'], 'protected', false]]) {
        const { findings, assessments } = run({ appGateways: [gateway('Standard_v2', zones)] });
        assert.equal(assessments[0].profile.tier, tier);
        assert.equal(assessments[0].signals.ZoneCount, zones.length);
        assert.equal(findings.some(f => f.control === 'BUDR-HA-6'), warning);
      }
    }
  });
});
