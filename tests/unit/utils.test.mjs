import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  safeParse, ext, esc, gn, sid, clsGw, isShared, gcv, gch,
  parseResourceId, getTenantFromResource
} from '../../src/modules/utils.js';

describe('safeParse', () => {
  it('parses valid JSON', () => {
    assert.deepEqual(safeParse('{"a":1}'), { a: 1 });
  });
  it('parses JSON array', () => {
    assert.deepEqual(safeParse('[1,2,3]'), [1, 2, 3]);
  });
  it('returns null for empty/null input', () => {
    assert.equal(safeParse(null), null);
    assert.equal(safeParse(''), null);
    assert.equal(safeParse('   '), null);
  });
  it('extracts JSON objects from mixed text', () => {
    const result = safeParse('junk {"a":1} more junk {"b":2}');
    assert.deepEqual(result, [{ a: 1 }, { b: 2 }]);
  });
  it('returns null for completely invalid text', () => {
    assert.equal(safeParse('no json here'), null);
  });
  it('rejects input exceeding 50 MB', () => {
    // Build a string just over the limit (50 MB + 1 byte)
    const oversize = 'x'.repeat(50 * 1024 * 1024 + 1);
    assert.equal(safeParse(oversize), null);
  });
});

describe('ext', () => {
  it('extracts nested properties', () => {
    const r = { securityRules: [{ priority: 100 }], defaultSecurityRules: [{ priority: 65000 }] };
    const result = ext(r, ['securityRules', 'defaultSecurityRules']);
    assert.equal(result.length, 2);
  });
  it('handles array of resources', () => {
    const resources = [{ properties: { addressPrefix: '10.0.0.0/24' } }, { properties: { addressPrefix: '10.0.1.0/24' } }];
    const result = ext(resources, ['properties']);
    assert.equal(result.length, 2);
  });
  it('returns empty array for null', () => {
    assert.deepEqual(ext(null, ['properties']), []);
  });
});

describe('esc', () => {
  it('escapes HTML entities', () => {
    assert.equal(esc('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
  });
  it('escapes ampersand', () => {
    assert.equal(esc('a & b'), 'a &amp; b');
  });
  it('escapes single quotes', () => {
    assert.equal(esc("it's"), 'it&#39;s');
  });
  it('handles null/undefined', () => {
    assert.equal(esc(null), '');
    assert.equal(esc(undefined), '');
  });
});

describe('gn', () => {
  it('returns resource.name', () => {
    const resource = { name: 'hub-vnet', id: '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet' };
    assert.equal(gn(resource), 'hub-vnet');
  });
  it('falls back to last segment of ARM id when name is absent', () => {
    const resource = { id: '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet' };
    assert.equal(gn(resource), 'hub-vnet');
  });
  it('returns empty string for resource with no name or id', () => {
    assert.equal(gn({}), '');
  });
  it('escapes the returned value', () => {
    const resource = { name: '<b>bold</b>' };
    assert.equal(gn(resource), '&lt;b&gt;bold&lt;/b&gt;');
  });
});

describe('sid', () => {
  it('returns last segment of ARM resource ID', () => {
    assert.equal(
      sid('/subscriptions/abc/resourceGroups/prod/providers/Microsoft.Network/virtualNetworks/hub-vnet'),
      'hub-vnet'
    );
  });
  it('returns last segment of a short path', () => {
    assert.equal(sid('/subscriptions/abc'), 'abc');
  });
  it('returns empty for null', () => {
    assert.equal(sid(null), '');
  });
  it('returns empty for empty string', () => {
    assert.equal(sid(''), '');
  });
});

describe('clsGw', () => {
  it('classifies azureFirewalls', () => assert.equal(clsGw('Microsoft.Network/azureFirewalls'), 'fw'));
  it('classifies bastionHosts', () => assert.equal(clsGw('Microsoft.Network/bastionHosts'), 'bastion'));
  it('classifies natGateways', () => assert.equal(clsGw('Microsoft.Network/natGateways'), 'nat'));
  it('classifies virtualNetworkGateways', () => assert.equal(clsGw('Microsoft.Network/virtualNetworkGateways'), 'vpn'));
  it('classifies applicationGateways', () => assert.equal(clsGw('Microsoft.Network/applicationGateways'), 'appgw'));
  it('classifies privateLinkServices', () => assert.equal(clsGw('Microsoft.Network/privateLinkServices'), 'pe'));
  it('defaults to GW for unknown type', () => assert.equal(clsGw('Microsoft.Network/unknownResource'), 'GW'));
  it('defaults to GW for null', () => assert.equal(clsGw(null), 'GW'));
});

describe('isShared', () => {
  it('fw is shared', () => assert.equal(isShared('fw'), true));
  it('bastion is shared', () => assert.equal(isShared('bastion'), true));
  it('vpn is shared', () => assert.equal(isShared('vpn'), true));
  it('nat is shared', () => assert.equal(isShared('nat'), true));
  it('appgw is not shared', () => assert.equal(isShared('appgw'), false));
  it('pe is not shared', () => assert.equal(isShared('pe'), false));
  it('full ARM type for azureFirewalls is shared', () => assert.equal(isShared('Microsoft.Network/azureFirewalls'), true));
});

describe('gcv', () => {
  it('returns CSS var for fw', () => assert.equal(gcv('fw'), 'var(--fw-color)'));
  it('returns CSS var for bastion', () => assert.equal(gcv('bastion'), 'var(--bastion-color)'));
  it('returns CSS var for nat', () => assert.equal(gcv('nat'), 'var(--nat-color)'));
  it('returns CSS var for vpn', () => assert.equal(gcv('vpn'), 'var(--vpn-color)'));
  it('returns muted for unknown', () => assert.equal(gcv('UNKNOWN'), 'var(--text-muted)'));
});

describe('gch', () => {
  it('returns hex for fw', () => assert.equal(gch('fw'), '#ef4444'));
  it('returns hex for bastion', () => assert.equal(gch('bastion'), '#10b981'));
  it('returns hex for nat', () => assert.equal(gch('nat'), '#f59e0b'));
  it('returns hex for vpn', () => assert.equal(gch('vpn'), '#3b82f6'));
  it('returns default hex for unknown', () => assert.equal(gch('UNKNOWN'), '#4a5e80'));
});

describe('parseResourceId', () => {
  const fullId = '/subscriptions/sub-123/resourceGroups/prod-rg/providers/Microsoft.Network/virtualNetworks/hub-vnet';

  it('extracts subscriptionId', () => {
    assert.equal(parseResourceId(fullId).subscriptionId, 'sub-123');
  });
  it('extracts resourceGroup', () => {
    assert.equal(parseResourceId(fullId).resourceGroup, 'prod-rg');
  });
  it('extracts provider', () => {
    assert.equal(parseResourceId(fullId).provider, 'Microsoft.Network');
  });
  it('extracts resourceType', () => {
    assert.equal(parseResourceId(fullId).resourceType, 'virtualNetworks');
  });
  it('extracts name', () => {
    assert.equal(parseResourceId(fullId).name, 'hub-vnet');
  });
  it('extracts subType and subName for nested resources', () => {
    const subnetId = '/subscriptions/sub-123/resourceGroups/prod-rg/providers/Microsoft.Network/virtualNetworks/hub-vnet/subnets/default';
    const r = parseResourceId(subnetId);
    assert.equal(r.subType, 'subnets');
    assert.equal(r.subName, 'default');
  });
  it('returns empty fields for null', () => {
    const r = parseResourceId(null);
    assert.equal(r.subscriptionId, '');
    assert.equal(r.resourceGroup, '');
  });
  it('returns empty fields for invalid/short path', () => {
    const r = parseResourceId('/subscriptions/abc');
    assert.equal(r.subscriptionId, '');
  });
});

describe('getTenantFromResource', () => {
  it('returns empty string for null', () => {
    assert.equal(getTenantFromResource(null), '');
  });
  it('returns tenantId from resource.tenantId', () => {
    assert.equal(getTenantFromResource({ tenantId: 'tenant-abc' }), 'tenant-abc');
  });
  it('returns tenantId from resource.identity.tenantId', () => {
    assert.equal(getTenantFromResource({ identity: { tenantId: 'tenant-xyz' } }), 'tenant-xyz');
  });
  it('returns tenantId from resource.extendedProperties.tenantId', () => {
    assert.equal(getTenantFromResource({ extendedProperties: { tenantId: 'tenant-ext' } }), 'tenant-ext');
  });
  it('returns empty string when no tenant info present', () => {
    assert.equal(getTenantFromResource({ name: 'hub-vnet' }), '');
  });
});
