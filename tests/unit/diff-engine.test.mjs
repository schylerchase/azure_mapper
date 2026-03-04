import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  _DIFF_KEYS, _DIFF_VOLATILE, _DIFF_STRUCTURAL,
  normalizeResource, normalizeNSG, classifyChange, _fieldDiff, computeDiff
} from '../../src/modules/diff-engine.js';

describe('constants', () => {
  it('_DIFF_KEYS has expected Azure resource types', () => {
    assert.ok(_DIFF_KEYS.vnets);
    assert.ok(_DIFF_KEYS.subnets);
    assert.ok(_DIFF_KEYS.vms);
    assert.ok(_DIFF_KEYS.nsgs);
  });
  it('_DIFF_KEYS uses "id" as primary key for all resource types', () => {
    for (const [, pk] of Object.entries(_DIFF_KEYS)) {
      assert.equal(pk, 'id');
    }
  });
  it('_DIFF_VOLATILE contains Azure volatile fields', () => {
    assert.ok(_DIFF_VOLATILE.has('etag'));
    assert.ok(_DIFF_VOLATILE.has('lastModifiedTime'));
    assert.ok(_DIFF_VOLATILE.has('provisioningTime'));
  });
  it('_DIFF_STRUCTURAL contains Azure structural fields', () => {
    assert.ok(_DIFF_STRUCTURAL.has('addressPrefix'));
    assert.ok(_DIFF_STRUCTURAL.has('location'));
    assert.ok(_DIFF_STRUCTURAL.has('priority'));
  });
});

describe('normalizeResource', () => {
  it('strips volatile fields', () => {
    const r = {
      id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet',
      etag: 'W/"abc123"',
      location: 'eastus'
    };
    const n = normalizeResource(r);
    assert.equal(n.id, r.id);
    assert.equal(n.location, 'eastus');
    assert.equal(n.etag, undefined);
  });
  it('strips lastModifiedTime', () => {
    const r = { id: 'res-1', lastModifiedTime: '2024-01-01T00:00:00Z', location: 'westus' };
    const n = normalizeResource(r);
    assert.equal(n.lastModifiedTime, undefined);
    assert.equal(n.location, 'westus');
  });
  it('sorts object keys deterministically', () => {
    const r = { Z: 1, A: 2, M: 3 };
    const n = normalizeResource(r);
    assert.deepEqual(Object.keys(n), ['A', 'M', 'Z']);
  });
  it('sorts arrays', () => {
    const r = { tags: [{ key: 'Z' }, { key: 'A' }] };
    const n = normalizeResource(r);
    // After sorting, the array items should be sorted by their JSON representation
    const keys = n.tags.map(t => t.key);
    assert.deepEqual(keys, ['A', 'Z']);
  });
  it('does not mutate original', () => {
    const r = { id: 'vnet-1', etag: 'original-etag' };
    normalizeResource(r);
    assert.equal(r.etag, 'original-etag');
  });
});

describe('normalizeNSG', () => {
  it('sorts securityRules by direction and priority', () => {
    const nsg = {
      id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg',
      properties: {
        securityRules: [
          { name: 'rule-200', properties: { priority: 200, direction: 'Inbound' } },
          { name: 'rule-100', properties: { priority: 100, direction: 'Inbound' } }
        ]
      }
    };
    const n = normalizeNSG(nsg);
    assert.ok(n.properties.securityRules);
    // After sort, rule-100 should come before rule-200
    const priorities = n.properties.securityRules.map(r => r.properties.priority);
    assert.ok(priorities[0] <= priorities[1]);
  });
  it('handles NSG without securityRules', () => {
    const nsg = { id: 'nsg-1', properties: {} };
    const n = normalizeNSG(nsg);
    assert.ok(n);
  });
});

describe('classifyChange', () => {
  it('addressPrefix is structural', () => assert.equal(classifyChange('addressPrefix'), 'structural'));
  it('location is structural', () => assert.equal(classifyChange('location'), 'structural'));
  it('priority is structural', () => assert.equal(classifyChange('priority'), 'structural'));
  it('tags is metadata', () => assert.equal(classifyChange('tags'), 'metadata'));
  it('name is metadata', () => assert.equal(classifyChange('name'), 'metadata'));
  it('description is metadata', () => assert.equal(classifyChange('description'), 'metadata'));
  it('unknown field defaults to structural', () => assert.equal(classifyChange('someNewField'), 'structural'));
});

describe('_fieldDiff', () => {
  it('returns empty for identical objects', () => {
    const a = { x: 1, y: 'hello' };
    const b = { x: 1, y: 'hello' };
    assert.deepEqual(_fieldDiff(a, b, ''), []);
  });
  it('detects changed structural value', () => {
    const a = { location: 'eastus' };
    const b = { location: 'westus' };
    const d = _fieldDiff(a, b, '');
    assert.equal(d.length, 1);
    assert.equal(d[0].field, 'location');
    assert.equal(d[0].kind, 'structural');
  });
  it('detects added field', () => {
    const a = { id: 'vnet-1' };
    const b = { id: 'vnet-1', tags: { env: 'prod' } };
    const d = _fieldDiff(a, b, '');
    assert.equal(d.length, 1);
    assert.equal(d[0].field, 'tags');
  });
  it('detects removed field', () => {
    const a = { id: 'vnet-1', location: 'eastus' };
    const b = { id: 'vnet-1' };
    const d = _fieldDiff(a, b, '');
    assert.equal(d.length, 1);
  });
  it('classifies top-level "tags" key as metadata when value type changes', () => {
    // When tags goes from absent to present, the diff entry is for the key "tags" itself
    const a = { id: 'vnet-1' };
    const b = { id: 'vnet-1', tags: { env: 'prod' } };
    const d = _fieldDiff(a, b, '');
    // The added "tags" field at the top level should classify as metadata
    assert.ok(d.some(f => f.field === 'tags' && f.kind === 'metadata'));
  });
});

describe('computeDiff', () => {
  it('returns empty results for identical snapshots', () => {
    const snap = {
      vnets: [{ id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet', location: 'eastus' }],
      subnets: []
    };
    const r = computeDiff(snap, snap);
    assert.equal(r.total.added, 0);
    assert.equal(r.total.removed, 0);
    assert.equal(r.total.modified, 0);
    assert.equal(r.total.unchanged, 1);
  });

  it('detects added resource', () => {
    const baseline = { vnets: [], subnets: [] };
    const vnetId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/new-vnet';
    const current = {
      vnets: [{ id: vnetId, location: 'eastus' }],
      subnets: []
    };
    const r = computeDiff(baseline, current);
    assert.equal(r.total.added, 1);
    assert.equal(r.added[0].key, vnetId);
  });

  it('detects removed resource', () => {
    const vnetId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/old-vnet';
    const baseline = {
      vnets: [{ id: vnetId, location: 'eastus' }],
      subnets: []
    };
    const current = { vnets: [], subnets: [] };
    const r = computeDiff(baseline, current);
    assert.equal(r.total.removed, 1);
    assert.equal(r.removed[0].key, vnetId);
  });

  it('detects modified resource', () => {
    const vnetId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet';
    const baseline = {
      vnets: [{ id: vnetId, location: 'eastus' }],
      subnets: []
    };
    const current = {
      vnets: [{ id: vnetId, location: 'westus' }],
      subnets: []
    };
    const r = computeDiff(baseline, current);
    assert.equal(r.total.modified, 1);
    assert.ok(r.modified[0].hasStructural);
  });

  it('ignores volatile fields in diff', () => {
    const vnetId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet';
    const baseline = {
      vnets: [{ id: vnetId, location: 'eastus', etag: 'W/"old"', lastModifiedTime: '2024-01-01T00:00:00Z' }],
      subnets: []
    };
    const current = {
      vnets: [{ id: vnetId, location: 'eastus', etag: 'W/"new"', lastModifiedTime: '2025-01-01T00:00:00Z' }],
      subnets: []
    };
    const r = computeDiff(baseline, current);
    assert.equal(r.total.unchanged, 1);
    assert.equal(r.total.modified, 0);
  });

  it('adding a top-level "name" field is metadata-only (hasStructural = false)', () => {
    const vnetId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub-vnet';
    const baseline = {
      vnets: [{ id: vnetId, location: 'eastus' }],
      subnets: []
    };
    const current = {
      vnets: [{ id: vnetId, location: 'eastus', name: 'hub-vnet' }],
      subnets: []
    };
    const r = computeDiff(baseline, current);
    assert.equal(r.total.modified, 1);
    // "name" is classified as metadata — no structural change
    assert.equal(r.modified[0].hasStructural, false);
  });
});
