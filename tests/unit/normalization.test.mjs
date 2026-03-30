import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  _normalizeAzureResources,
  _normTags,
  matchFile,
  fileMap,
  _friendlyFolderLabel,
} from '../../src/modules/normalization.js';

// ─── R1.1: _normalizeAzureResources ─────────────────────────────────────────

describe('_normalizeAzureResources', () => {
  it('maps VNet id to VpcId and addressPrefixes[0] to CidrBlock', () => {
    const d = {
      vpcs: [{
        id: '/subscriptions/x/providers/Microsoft.Network/virtualNetworks/hub',
        addressSpace: { addressPrefixes: ['10.0.0.0/16'] },
        name: 'hub',
      }],
    };
    _normalizeAzureResources(d);
    assert.equal(d.vpcs[0].VpcId, '/subscriptions/x/providers/Microsoft.Network/virtualNetworks/hub');
    assert.equal(d.vpcs[0].CidrBlock, '10.0.0.0/16');
  });

  it('maps subnet id to SubnetId, derives VpcId, maps addressPrefix to CidrBlock', () => {
    const d = {
      subnets: [{
        id: '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub/subnets/default',
        addressPrefix: '10.0.1.0/24',
        name: 'default',
      }],
    };
    _normalizeAzureResources(d);
    const s = d.subnets[0];
    assert.equal(s.SubnetId, '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub/subnets/default');
    assert.equal(s.CidrBlock, '10.0.1.0/24');
    assert.equal(s.VpcId, '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub');
  });

  it('maps NSG securityRules to IpPermissions with FromPort, ToPort, IpProtocol', () => {
    const d = {
      sgs: [{
        id: '/subs/x/.../nsg1',
        name: 'nsg1',
        securityRules: [{
          direction: 'Inbound',
          protocol: 'TCP',
          destinationPortRange: '443',
          sourceAddressPrefix: '*',
        }],
        defaultSecurityRules: [],
      }],
    };
    _normalizeAzureResources(d);
    const nsg = d.sgs[0];
    assert.ok(Array.isArray(nsg.IpPermissions), 'IpPermissions should be an array');
    assert.equal(nsg.IpPermissions.length, 1);
    assert.equal(nsg.IpPermissions[0].FromPort, 443);
    assert.equal(nsg.IpPermissions[0].ToPort, 443);
    assert.equal(nsg.IpPermissions[0].IpProtocol, 'tcp');
  });

  it('maps NIC ipConfigurations to NetworkInterfaceId, SubnetId, VpcId', () => {
    const d = {
      enis: [{
        id: '/subs/x/.../nic1',
        ipConfigurations: [{
          subnet: {
            id: '/subs/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub/subnets/default',
          },
        }],
      }],
    };
    _normalizeAzureResources(d);
    const nic = d.enis[0];
    assert.equal(nic.NetworkInterfaceId, '/subs/x/.../nic1');
    assert.equal(nic.SubnetId, '/subs/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub/subnets/default');
    assert.equal(nic.VpcId, '/subs/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/hub');
  });

  it('sets properties self-reference so r.properties === r', () => {
    const d = {
      vpcs: [{ id: '/subs/x/vnets/hub', addressSpace: { addressPrefixes: ['10.1.0.0/16'] }, name: 'hub' }],
    };
    _normalizeAzureResources(d);
    const vpc = d.vpcs[0];
    assert.equal(vpc.properties, vpc, 'properties should be a self-reference');
    assert.equal(vpc.properties.addressSpace.addressPrefixes[0], '10.1.0.0/16');
  });

  it('does not throw on empty data object', () => {
    assert.doesNotThrow(() => _normalizeAzureResources({}));
  });

  it('does not throw when arrays are empty', () => {
    assert.doesNotThrow(() => _normalizeAzureResources({ vpcs: [], subnets: [], sgs: [] }));
  });
});

// ─── R1.3: _normTags ─────────────────────────────────────────────────────────

describe('_normTags', () => {
  it('converts Azure tags object to [{Key,Value}] array', () => {
    const r = { tags: { Environment: 'prod', Owner: 'team-a' } };
    _normTags(r);
    assert.ok(Array.isArray(r.Tags), 'Tags should be an array');
    assert.equal(r.Tags.length, 2);
    const envTag = r.Tags.find(t => t.Key === 'Environment');
    assert.ok(envTag, 'Environment tag should exist');
    assert.equal(envTag.Value, 'prod');
    const ownerTag = r.Tags.find(t => t.Key === 'Owner');
    assert.ok(ownerTag, 'Owner tag should exist');
    assert.equal(ownerTag.Value, 'team-a');
  });

  it('falls back to [{Key:"Name",Value:resource.name}] when no tags and has name', () => {
    const r = { name: 'my-vnet' };
    _normTags(r);
    assert.deepEqual(r.Tags, [{ Key: 'Name', Value: 'my-vnet' }]);
  });

  it('does not throw on null input', () => {
    assert.doesNotThrow(() => _normTags(null));
  });

  it('does not overwrite existing Tags array', () => {
    const r = { Tags: [{ Key: 'A', Value: 'B' }] };
    _normTags(r);
    assert.equal(r.Tags.length, 1);
    assert.equal(r.Tags[0].Key, 'A');
  });

  it('produces empty Tags array for empty tags object', () => {
    const r = { tags: {} };
    _normTags(r);
    assert.deepEqual(r.Tags, []);
  });
});

// ─── R1.4: _friendlyFolderLabel ─────────────────────────────────────────────

describe('_friendlyFolderLabel', () => {
  it('extracts label from named subscription folder', () => {
    const result = _friendlyFolderLabel('azure-export-lmat-PROD-20260330-075242');
    assert.equal(result, 'lmat-PROD');
  });

  it('truncates GUID subscription ID to first 13 chars plus ellipsis', () => {
    const result = _friendlyFolderLabel('azure-export-00b800a2-140e-4a89-94f9-ed6aab746a51-20260330-105511');
    assert.equal(result, '00b800a2-140e...');
  });

  it('returns short folder name as-is (under 30 chars, no azure-export prefix)', () => {
    const result = _friendlyFolderLabel('my-folder');
    assert.equal(result, 'my-folder');
  });

  it('truncates long folder names exceeding 30 characters', () => {
    const result = _friendlyFolderLabel('a-very-long-folder-name-that-exceeds-thirty-characters');
    assert.ok(typeof result === 'string', 'result should be a string');
    assert.ok(result.endsWith('...'), 'result should end with ...');
    assert.ok(result.length <= 30, 'result should be at most 30 chars');
  });

  it('returns null for null input', () => {
    assert.equal(_friendlyFolderLabel(null), null);
  });
});

// ─── R1.5: matchFile ────────────────────────────────────────────────────────

describe('matchFile', () => {
  it('returns in_vnets for vnets.json', () => {
    assert.equal(matchFile('vnets.json', null), 'in_vnets');
  });

  it('returns in_subnets for subnets.json', () => {
    assert.equal(matchFile('subnets.json', null), 'in_subnets');
  });

  it('returns in_nsgs for nsgs.json', () => {
    assert.equal(matchFile('nsgs.json', null), 'in_nsgs');
  });

  it('returns in_nics for nics.json', () => {
    assert.equal(matchFile('nics.json', null), 'in_nics');
  });

  it('returns in_pubips for public-ips.json', () => {
    assert.equal(matchFile('public-ips.json', null), 'in_pubips');
  });

  it('returns in_udrs for route-tables.json (flat array format)', () => {
    const content = '[{"id":"/subs/x/routeTables/rt1","disableBgpRoutePropagation":false,"routes":[]}]';
    assert.equal(matchFile('route-tables.json', content), 'in_udrs');
  });

  it('returns in_vnets via content fallback for unknown filename with addressSpace key', () => {
    const content = '{"addressSpace":{"addressPrefixes":["10.0.0.0/8"]},"name":"hub"}';
    assert.equal(matchFile('UNKNOWN.json', content), 'in_vnets');
  });

  it('returns null for completely unknown file with no matching content', () => {
    assert.equal(matchFile('random.json', '{"foo":"bar"}'), null);
  });

  it('fileMap has exactly 69 entries', () => {
    assert.equal(fileMap.length, 69);
  });
});
