import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runCISAzureChecks } from '../../src/modules/compliance-cis-azure-checks.js';

const nsg = (port, protocol, extra = {}) => ({
  id: '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/assessment/providers/Microsoft.Network/networkSecurityGroups/database',
  name: 'database', type: 'Microsoft.Network/networkSecurityGroups',
  properties: { securityRules: [{ name: 'allow', properties: {
    direction: 'Inbound', access: 'Allow', protocol,
    sourceAddressPrefix: 'Internet', sourcePortRange: '*',
    destinationAddressPrefix: '*', destinationPortRange: String(port), ...extra
  } }] }
});

describe('fifth rescan database transport evidence', () => {
  for (const port of [1433, 3306, 5432]) {
    it(`reports database port ${port} only for TCP or all-protocol permissions`, () => {
      for (const protocol of ['Tcp', '*', 'Udp', 'Icmp']) {
        for (const portShape of [{}, { destinationPortRange: undefined, destinationPortRanges: [`${port - 1}-${port + 1}`] }]) {
          const findings = runCISAzureChecks({ nsgs: [nsg(port, protocol, portShape)] });
          assert.equal(findings.some(f => f.control === `CIS-DB-${port}`), protocol === 'Tcp' || protocol === '*', protocol);
        }
      }
    });
  }

  it('retains the all-UDP warning without claiming TCP database exposure', () => {
    const findings = runCISAzureChecks({ nsgs: [nsg('*', 'Udp')] });
    assert.equal(findings.some(f => f.control === 'CIS-UDP'), true);
    assert.equal(findings.some(f => f.control.startsWith('CIS-DB-')), false);
    assert.equal(findings.some(f => f.control === 'CIS-10'), false);
  });
});
