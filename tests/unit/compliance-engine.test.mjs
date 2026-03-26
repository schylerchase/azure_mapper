import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  runComplianceChecks, clearComplianceCache, getComplianceFindings
} from '../../src/modules/compliance-engine.js';
import { setCloudEnv } from '../../src/modules/cloud-env.js';

// Ensure cloud environment is set before tests (default: commercial)
setCloudEnv('commercial');

// ---------------------------------------------------------------------------
// Helpers — build minimal Azure resource fixtures
// ---------------------------------------------------------------------------

function makeNsg(name, rules = []) {
  return {
    name,
    id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/${name}`,
    type: 'Microsoft.Network/networkSecurityGroups',
    properties: { securityRules: rules }
  };
}

function makeRule(overrides = {}) {
  return {
    name: overrides.name || 'test-rule',
    properties: {
      direction: 'Inbound',
      access: 'Allow',
      protocol: overrides.protocol || 'Tcp',
      sourceAddressPrefix: overrides.source || '*',
      sourceAddressPrefixes: overrides.sourcePrefixes || [],
      destinationAddressPrefix: overrides.dest || '*',
      destinationPortRange: overrides.port || '*',
      destinationPortRanges: overrides.ports || [],
      priority: overrides.priority || 100,
      ...overrides.extra
    }
  };
}

function makeVnet(name, subnets = [], addressPrefixes = ['10.0.0.0/16']) {
  return {
    name,
    id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/${name}`,
    type: 'Microsoft.Network/virtualNetworks',
    properties: {
      addressSpace: { addressPrefixes },
      subnets: subnets.map((s, i) => ({
        name: s.name || `subnet-${i}`,
        id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/${name}/subnets/${s.name || `subnet-${i}`}`,
        properties: {
          addressPrefix: s.addressPrefix || `10.0.${i}.0/24`,
          networkSecurityGroup: s.nsgId ? { id: s.nsgId } : undefined,
          routeTable: s.routeTableId ? { id: s.routeTableId } : undefined,
          ...s.extra
        }
      }))
    }
  };
}

function makeStorage(name, overrides = {}) {
  return {
    name,
    id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/${name}`,
    type: 'Microsoft.Storage/storageAccounts',
    properties: {
      minimumTlsVersion: overrides.tls || 'TLS1_2',
      allowBlobPublicAccess: overrides.publicBlob ?? false,
      encryption: overrides.encryption || { services: { blob: { enabled: true }, file: { enabled: true } } },
      supportsHttpsTrafficOnly: overrides.httpsOnly ?? true,
      ...overrides.extra
    }
  };
}

function makeSqlServer(name, overrides = {}) {
  return {
    name,
    id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/${name}`,
    type: 'Microsoft.Sql/servers',
    properties: {
      publicNetworkAccess: overrides.publicAccess || 'Disabled',
      ...overrides.extra
    }
  };
}

function makeAppGw(name, overrides = {}) {
  return {
    name,
    id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/applicationGateways/${name}`,
    type: 'Microsoft.Network/applicationGateways',
    properties: {
      webApplicationFirewallConfiguration: overrides.waf || undefined,
      firewallPolicy: overrides.firewallPolicy || undefined,
      frontendPorts: overrides.frontendPorts || [],
      httpListeners: overrides.httpListeners || [],
      ...overrides.extra
    }
  };
}

function makeRedis(name, overrides = {}) {
  return {
    name,
    id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cache/redis/${name}`,
    type: 'Microsoft.Cache/redis',
    properties: {
      enableNonSslPort: overrides.nonSsl ?? false,
      minimumTlsVersion: overrides.tls || '1.2',
      ...overrides.extra
    }
  };
}

// ---------------------------------------------------------------------------
// Setup — clear cache before each test to prevent cross-test interference
// ---------------------------------------------------------------------------

beforeEach(() => {
  clearComplianceCache();
});

// ============================================================================
// CIS Azure checks
// ============================================================================

describe('CIS: NSG rule checks', () => {
  it('CIS-9: flags NSG allowing RDP (3389) from 0.0.0.0/0', () => {
    const data = {
      nsgs: [makeNsg('open-rdp-nsg', [
        makeRule({ name: 'allow-rdp', port: '3389', source: '*' })
      ])]
    };
    const findings = runComplianceChecks(data);
    const rdpFindings = findings.filter(f => f.id === 'CIS-9');
    assert.ok(rdpFindings.length > 0, 'Should flag open RDP');
    assert.equal(rdpFindings[0].severity, 'HIGH');
    assert.ok(rdpFindings[0].resource.includes('open-rdp-nsg'));
  });

  it('CIS-10: flags NSG allowing SSH (22) from 0.0.0.0/0', () => {
    const data = {
      nsgs: [makeNsg('open-ssh-nsg', [
        makeRule({ name: 'allow-ssh', port: '22', source: '*' })
      ])]
    };
    const findings = runComplianceChecks(data);
    const sshFindings = findings.filter(f => f.id === 'CIS-10');
    assert.ok(sshFindings.length > 0, 'Should flag open SSH');
    assert.equal(sshFindings[0].severity, 'HIGH');
  });

  it('CIS-12: flags NSG allowing all inbound traffic', () => {
    const data = {
      nsgs: [makeNsg('allow-all-nsg', [
        makeRule({ name: 'allow-all', port: '*', source: '*', protocol: '*' })
      ])]
    };
    const findings = runComplianceChecks(data);
    const allFindings = findings.filter(f => f.id === 'CIS-12');
    assert.ok(allFindings.length > 0, 'Should flag allow-all rule');
    assert.equal(allFindings[0].severity, 'CRITICAL');
  });

  it('does not flag NSG with restricted source', () => {
    const data = {
      nsgs: [makeNsg('restricted-nsg', [
        makeRule({ name: 'allow-rdp-restricted', port: '3389', source: '10.0.1.0/24' })
      ])]
    };
    const findings = runComplianceChecks(data);
    const rdpFindings = findings.filter(f => f.id === 'CIS-9');
    assert.equal(rdpFindings.length, 0, 'Should not flag restricted RDP');
  });

  it('does not flag Deny rules', () => {
    const data = {
      nsgs: [makeNsg('deny-nsg', [
        makeRule({ name: 'deny-all', port: '*', source: '*', extra: { access: 'Deny' } })
      ])]
    };
    const findings = runComplianceChecks(data);
    const cisFindings = findings.filter(f => f.id === 'CIS-12');
    assert.equal(cisFindings.length, 0, 'Should not flag Deny rules');
  });

  it('CIS-DB: flags open database ports (1433, 3306, 5432)', () => {
    const data = {
      nsgs: [makeNsg('db-nsg', [
        makeRule({ name: 'allow-sql', port: '1433', source: '*' }),
        makeRule({ name: 'allow-mysql', port: '3306', source: '*' }),
        makeRule({ name: 'allow-postgres', port: '5432', source: '*' }),
      ])]
    };
    const findings = runComplianceChecks(data);
    // CIS-DB IDs include the port: CIS-DB-1433, CIS-DB-3306, CIS-DB-5432
    const dbFindings = findings.filter(f => f.id && f.id.startsWith('CIS-DB'));
    assert.equal(dbFindings.length, 3, 'Should flag all 3 open DB ports');
  });

  it('flags open RDP via sourceAddressPrefixes array', () => {
    const data = {
      nsgs: [makeNsg('prefixes-nsg', [
        makeRule({
          name: 'allow-rdp-prefixes',
          port: '3389',
          source: '',
          sourcePrefixes: ['10.0.0.0/8', '0.0.0.0/0']
        })
      ])]
    };
    const findings = runComplianceChecks(data);
    const rdpFindings = findings.filter(f => f.id === 'CIS-9');
    assert.ok(rdpFindings.length > 0, 'Should detect open source in prefixes array');
  });
});

describe('CIS: Storage checks', () => {
  it('CIS-34: flags storage with public blob access', () => {
    const data = {
      storageAccounts: [makeStorage('publicstore', { publicBlob: true })]
    };
    const findings = runComplianceChecks(data);
    const blobFindings = findings.filter(f => f.id === 'CIS-34');
    assert.ok(blobFindings.length > 0, 'Should flag public blob access');
  });

  it('CIS-44: flags storage with TLS < 1.2', () => {
    const data = {
      storageAccounts: [makeStorage('oldtls', { tls: 'TLS1_0' })]
    };
    const findings = runComplianceChecks(data);
    const tlsFindings = findings.filter(f => f.id === 'CIS-44');
    assert.ok(tlsFindings.length > 0, 'Should flag old TLS');
  });

  it('does not flag compliant storage', () => {
    const data = {
      storageAccounts: [makeStorage('goodstore', { tls: 'TLS1_2', publicBlob: false })]
    };
    const findings = runComplianceChecks(data);
    const storageFindings = findings.filter(f => f.id === 'CIS-34' || f.id === 'CIS-44');
    assert.equal(storageFindings.length, 0, 'Compliant storage should have no CIS findings');
  });
});

describe('CIS: SQL Server checks', () => {
  it('CIS-SQL-1: flags publicly accessible SQL server', () => {
    const data = {
      sqlServers: [makeSqlServer('public-sql', { publicAccess: 'Enabled' })]
    };
    const findings = runComplianceChecks(data);
    const sqlFindings = findings.filter(f => f.id === 'CIS-SQL-1');
    assert.ok(sqlFindings.length > 0, 'Should flag public SQL server');
  });

  it('does not flag SQL server with disabled public access', () => {
    const data = {
      sqlServers: [makeSqlServer('private-sql', { publicAccess: 'Disabled' })]
    };
    const findings = runComplianceChecks(data);
    const sqlFindings = findings.filter(f => f.id === 'CIS-SQL-1');
    assert.equal(sqlFindings.length, 0);
  });
});

describe('CIS: Redis checks', () => {
  it('CIS-REDIS: flags Redis with non-SSL port enabled', () => {
    const data = {
      redisCaches: [makeRedis('insecure-redis', { nonSsl: true })]
    };
    const findings = runComplianceChecks(data);
    const redisFindings = findings.filter(f => f.id === 'CIS-REDIS');
    assert.ok(redisFindings.length > 0, 'Should flag non-SSL Redis');
  });
});

// ============================================================================
// CAF (Cloud Adoption Framework) checks
// ============================================================================

describe('CAF: Subnet checks', () => {
  // CAF uses data.subnets (flat array from az network vnet subnet list),
  // not nested under vnets[].properties.subnets

  function makeSubnet(name, opts = {}) {
    return {
      name,
      id: `/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/${name}`,
      properties: {
        addressPrefix: opts.addressPrefix || '10.0.1.0/24',
        networkSecurityGroup: opts.nsgId ? { id: opts.nsgId } : undefined,
        routeTable: opts.routeTableId ? { id: opts.routeTableId } : undefined,
      }
    };
  }

  it('CAF-NSG: flags subnet without NSG', () => {
    const data = { subnets: [makeSubnet('no-nsg-subnet')] };
    const findings = runComplianceChecks(data);
    const nsgFindings = findings.filter(f => f.id === 'CAF-NSG');
    assert.ok(nsgFindings.length > 0, 'Should flag subnet without NSG');
  });

  it('CAF-UDR: flags subnet without route table', () => {
    const data = { subnets: [makeSubnet('no-udr-subnet')] };
    const findings = runComplianceChecks(data);
    const udrFindings = findings.filter(f => f.id === 'CAF-UDR');
    assert.ok(udrFindings.length > 0, 'Should flag subnet without UDR');
  });

  it('does not flag GatewaySubnet for missing NSG/UDR', () => {
    const data = { subnets: [makeSubnet('GatewaySubnet')] };
    const findings = runComplianceChecks(data);
    const gwFindings = findings.filter(f =>
      (f.id === 'CAF-NSG' || f.id === 'CAF-UDR') &&
      f.message && f.message.includes('GatewaySubnet')
    );
    assert.equal(gwFindings.length, 0, 'GatewaySubnet should be excluded from NSG/UDR checks');
  });

  it('does not flag subnet with NSG attached', () => {
    const nsgId = '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/my-nsg';
    const data = { subnets: [makeSubnet('secured-subnet', { nsgId })] };
    const findings = runComplianceChecks(data);
    const nsgFindings = findings.filter(f =>
      f.id === 'CAF-NSG' && f.message && f.message.includes('secured-subnet')
    );
    assert.equal(nsgFindings.length, 0, 'Subnet with NSG should not be flagged');
  });
});

// ============================================================================
// SOC2 checks
// ============================================================================

describe('SOC2: TLS and encryption checks', () => {
  it('SOC2-TLS: flags storage with TLS < 1.2', () => {
    // SOC2-TLS checks minimumTlsVersion, not supportsHttpsTrafficOnly
    const data = {
      storageAccounts: [makeStorage('oldtls', { tls: 'TLS1_0' })]
    };
    const findings = runComplianceChecks(data);
    const tlsFindings = findings.filter(f => f.id === 'SOC2-TLS');
    assert.ok(tlsFindings.length > 0, 'Should flag TLS < 1.2 storage');
  });

  it('SOC2-DISK: flags managed disk without encryption settings', () => {
    // SOC2-DISK uses data.managedDisks (not data.disks)
    // Flags when encryption.type is missing AND no encryptionSettingsCollection
    const data = {
      managedDisks: [{
        name: 'bare-disk',
        id: '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/bare-disk',
        properties: {}
      }]
    };
    const findings = runComplianceChecks(data);
    const diskFindings = findings.filter(f => f.id === 'SOC2-DISK');
    assert.ok(diskFindings.length > 0, 'Should flag disk without encryption config');
  });
});

// ============================================================================
// PCI checks
// ============================================================================

describe('PCI: Network segmentation checks', () => {
  it('PCI-WAF: flags App Gateway without WAF', () => {
    const data = {
      appGateways: [makeAppGw('no-waf-gw')]
    };
    const findings = runComplianceChecks(data);
    const wafFindings = findings.filter(f => f.id === 'PCI-WAF');
    assert.ok(wafFindings.length > 0, 'Should flag App GW without WAF');
  });

  it('does not flag App Gateway with WAF_v2 SKU', () => {
    // PCI-WAF checks sku.tier containing 'waf', not webApplicationFirewallConfiguration
    const data = {
      appGateways: [makeAppGw('waf-gw', {
        extra: { sku: { tier: 'WAF_v2', name: 'WAF_v2' } }
      })]
    };
    const findings = runComplianceChecks(data);
    const wafFindings = findings.filter(f => f.id === 'PCI-WAF');
    assert.equal(wafFindings.length, 0, 'WAF_v2 App GW should not be flagged');
  });
});

// ============================================================================
// Integration / cross-cutting
// ============================================================================

describe('runComplianceChecks: integration', () => {
  it('returns empty array for empty data', () => {
    const findings = runComplianceChecks({});
    assert.ok(Array.isArray(findings));
  });

  it('all findings have required fields', () => {
    const data = {
      nsgs: [makeNsg('test-nsg', [
        makeRule({ name: 'allow-all', port: '*', source: '*', protocol: '*' })
      ])],
      storageAccounts: [makeStorage('teststore', { publicBlob: true, tls: 'TLS1_0' })],
      vnets: [makeVnet('test-vnet', [{ name: 'bare-subnet' }])]
    };
    const findings = runComplianceChecks(data);
    assert.ok(findings.length > 0, 'Should produce findings from mixed data');
    for (const f of findings) {
      assert.ok(f.framework, `Missing framework on ${f.id}`);
      assert.ok(f.severity, `Missing severity on ${f.id}`);
      assert.ok(f.id || f.control, `Missing id/control on finding`);
    }
  });

  it('cache returns same reference on second call with same data', () => {
    const data = { nsgs: [makeNsg('nsg-1', [])] };
    const first = runComplianceChecks(data);
    const second = runComplianceChecks(data);
    assert.equal(first, second, 'Cached result should be same reference');
  });

  it('clearComplianceCache resets findings', () => {
    const data = { nsgs: [makeNsg('nsg-1', [])] };
    runComplianceChecks(data);
    clearComplianceCache();
    const findings = getComplianceFindings();
    assert.equal(findings.length, 0, 'Cache should be cleared');
  });

  it('checkovId is annotated on findings that have CKV mapping', () => {
    const data = {
      nsgs: [makeNsg('rdp-nsg', [
        makeRule({ name: 'open-rdp', port: '3389', source: '*' })
      ])]
    };
    const findings = runComplianceChecks(data);
    const rdpFinding = findings.find(f => f.id === 'CIS-9');
    assert.ok(rdpFinding, 'Should have CIS-9 finding');
    assert.equal(rdpFinding.checkovId, 'CKV_AZURE_9');
  });

  it('handles null/undefined data fields gracefully', () => {
    const data = {
      nsgs: null,
      vnets: undefined,
      storageAccounts: null,
      sqlServers: undefined,
    };
    // Should not throw
    const findings = runComplianceChecks(data);
    assert.ok(Array.isArray(findings));
  });
});
