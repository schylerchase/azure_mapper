import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  protocolMatch, portMatch, addressMatch,
  evaluateNsgRules, evaluateNsgPath, evaluateRoute, classifySubnet
} from '../../src/modules/network-rules.js';

describe('protocolMatch', () => {
  it('* matches anything', () => assert.equal(protocolMatch('*', 'Tcp'), true));
  it('Tcp matches Tcp (case-insensitive)', () => assert.equal(protocolMatch('Tcp', 'tcp'), true));
  it('Udp matches Udp', () => assert.equal(protocolMatch('Udp', 'Udp'), true));
  it('Tcp does not match Udp', () => assert.equal(protocolMatch('Tcp', 'Udp'), false));
  it('Icmp matches icmp', () => assert.equal(protocolMatch('Icmp', 'icmp'), true));
  it('returns false for null rule protocol', () => assert.equal(protocolMatch(null, 'Tcp'), false));
  it('returns false for null query protocol', () => assert.equal(protocolMatch('Tcp', null), false));
});

describe('portMatch', () => {
  it('* matches any port', () => assert.equal(portMatch('*', 443), true));
  it('exact port matches', () => assert.equal(portMatch('443', 443), true));
  it('exact port does not match different port', () => assert.equal(portMatch('443', 80), false));
  it('range 80-443 matches 443', () => assert.equal(portMatch('80-443', 443), true));
  it('range 80-443 matches 80', () => assert.equal(portMatch('80-443', 80), true));
  it('range 80-443 does not match 8080', () => assert.equal(portMatch('80-443', 8080), false));
  it('comma-separated ports match', () => assert.equal(portMatch('22,80,443', 80), true));
  it('comma-separated with range matches', () => assert.equal(portMatch('22,100-200', 150), true));
  it('null/undefined returns true (no restriction)', () => assert.equal(portMatch(null, 443), true));
  it('empty string returns true', () => assert.equal(portMatch('', 443), true));
});

describe('addressMatch', () => {
  it('* matches any address', () => assert.equal(addressMatch('*', '1.2.3.4'), true));
  it('CIDR match includes address', () => assert.equal(addressMatch('10.0.0.0/24', '10.0.0.5'), true));
  it('CIDR match excludes address outside range', () => assert.equal(addressMatch('10.0.0.0/24', '10.0.1.5'), false));
  it('exact IP match', () => assert.equal(addressMatch('10.0.0.1', '10.0.0.1'), true));
  it('exact IP no match', () => assert.equal(addressMatch('10.0.0.1', '10.0.0.2'), false));
  it('VirtualNetwork service tag matches RFC1918 address (no vnetPrefixes)', () => {
    assert.equal(addressMatch('VirtualNetwork', '10.0.0.1'), true);
  });
  it('VirtualNetwork service tag does not match public IP (no vnetPrefixes)', () => {
    assert.equal(addressMatch('VirtualNetwork', '8.8.8.8'), false);
  });
  it('VirtualNetwork with explicit vnetPrefixes matches address in prefix', () => {
    assert.equal(addressMatch('VirtualNetwork', '172.31.0.5', ['172.31.0.0/16']), true);
  });
  it('VirtualNetwork with explicit vnetPrefixes rejects address outside prefix', () => {
    assert.equal(addressMatch('VirtualNetwork', '10.0.0.1', ['172.31.0.0/16']), false);
  });
  it('AzureLoadBalancer matches 168.63.129.16', () => {
    assert.equal(addressMatch('AzureLoadBalancer', '168.63.129.16'), true);
  });
  it('AzureLoadBalancer does not match other IPs', () => {
    assert.equal(addressMatch('AzureLoadBalancer', '10.0.0.1'), false);
  });
  it('Internet matches public IP (no vnetPrefixes)', () => {
    assert.equal(addressMatch('Internet', '8.8.8.8'), true);
  });
  it('Internet does not match RFC1918 (no vnetPrefixes)', () => {
    assert.equal(addressMatch('Internet', '192.168.1.1'), false);
  });
  it('returns false for null ruleAddress', () => assert.equal(addressMatch(null, '10.0.0.1'), false));
  it('returns false for null queryAddress', () => assert.equal(addressMatch('*', null), false));
});

describe('evaluateNsgRules', () => {
  it('returns Deny from default DenyAllInBound when no custom rules match', () => {
    const nsg = { securityRules: [] };
    const r = evaluateNsgRules(nsg, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.equal(r.action, 'Deny');
    assert.equal(r.priority, 65500);
  });

  it('custom Allow rule at priority 100 takes precedence', () => {
    const nsg = {
      securityRules: [{
        name: 'allow-https',
        priority: 100,
        direction: 'Inbound',
        access: 'Allow',
        protocol: 'Tcp',
        sourceAddressPrefix: '*',
        sourcePortRange: '*',
        destinationAddressPrefix: '*',
        destinationPortRange: '443'
      }]
    };
    const r = evaluateNsgRules(nsg, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.equal(r.action, 'Allow');
    assert.equal(r.priority, 100);
  });

  it('deny rule at lower priority number wins over allow at higher priority', () => {
    const nsg = {
      securityRules: [
        {
          name: 'deny-ssh',
          priority: 100,
          direction: 'Inbound',
          access: 'Deny',
          protocol: 'Tcp',
          sourceAddressPrefix: '*',
          sourcePortRange: '*',
          destinationAddressPrefix: '*',
          destinationPortRange: '22'
        },
        {
          name: 'allow-all',
          priority: 200,
          direction: 'Inbound',
          access: 'Allow',
          protocol: '*',
          sourceAddressPrefix: '*',
          sourcePortRange: '*',
          destinationAddressPrefix: '*',
          destinationPortRange: '*'
        }
      ]
    };
    const r = evaluateNsgRules(nsg, 'Inbound', 'Tcp', '10.0.0.1', '12345', '10.0.0.5', '22');
    assert.equal(r.action, 'Deny');
    assert.equal(r.priority, 100);
  });

  it('filters by direction — Outbound rule does not match Inbound query', () => {
    const nsg = {
      securityRules: [{
        name: 'allow-outbound',
        priority: 100,
        direction: 'Outbound',
        access: 'Allow',
        protocol: 'Tcp',
        sourceAddressPrefix: '*',
        sourcePortRange: '*',
        destinationAddressPrefix: '*',
        destinationPortRange: '443'
      }]
    };
    // Inbound query should not match the outbound rule; falls through to default DenyAll
    const r = evaluateNsgRules(nsg, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.equal(r.action, 'Deny');
  });

  it('default AllowVNetInBound at 65000 allows VNet-to-VNet (RFC1918) traffic', () => {
    const nsg = { securityRules: [] };
    // Source is RFC1918 — matches VirtualNetwork service tag
    const r = evaluateNsgRules(nsg, 'Inbound', 'Tcp', '10.0.1.5', '12345', '10.0.0.1', '443');
    assert.equal(r.action, 'Allow');
    assert.equal(r.priority, 65000);
  });

  it('null nsg uses only defaults', () => {
    const r = evaluateNsgRules(null, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.equal(r.action, 'Deny');
    assert.equal(r.priority, 65500);
  });

  it('Outbound default AllowInternetOutBound at 65001 allows outbound Internet', () => {
    const nsg = { securityRules: [] };
    const r = evaluateNsgRules(nsg, 'Outbound', 'Tcp', '10.0.0.1', '12345', '8.8.8.8', '443');
    assert.equal(r.action, 'Allow');
    assert.equal(r.priority, 65001);
  });
});

describe('evaluateNsgPath', () => {
  const allowAllNsg = {
    securityRules: [{
      name: 'allow-all',
      priority: 100,
      direction: 'Inbound',
      access: 'Allow',
      protocol: '*',
      sourceAddressPrefix: '*',
      sourcePortRange: '*',
      destinationAddressPrefix: '*',
      destinationPortRange: '*'
    }]
  };

  it('no NSGs on either level — both default Allow', () => {
    const r = evaluateNsgPath(null, null, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.equal(r.allowed, true);
  });

  it('inbound: both NIC and subnet NSG must allow', () => {
    const denyNsg = {
      securityRules: [{
        name: 'deny-all',
        priority: 100,
        direction: 'Inbound',
        access: 'Deny',
        protocol: '*',
        sourceAddressPrefix: '*',
        sourcePortRange: '*',
        destinationAddressPrefix: '*',
        destinationPortRange: '*'
      }]
    };
    const r = evaluateNsgPath(allowAllNsg, denyNsg, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.equal(r.allowed, false);
  });

  it('inbound: subnet allow and NIC allow both needed', () => {
    const r = evaluateNsgPath(allowAllNsg, allowAllNsg, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.equal(r.allowed, true);
  });

  it('returns nicResult and subnetResult', () => {
    const r = evaluateNsgPath(null, null, 'Inbound', 'Tcp', '8.8.8.8', '12345', '10.0.0.1', '443');
    assert.ok(r.nicResult);
    assert.ok(r.subnetResult);
  });
});

describe('evaluateRoute', () => {
  it('returns VNetLocal for traffic within VNet address space', () => {
    const rt = {
      vnetPrefixes: ['10.0.0.0/16'],
      routes: []
    };
    const r = evaluateRoute(rt, '10.0.1.5');
    assert.equal(r.nextHopType, 'VNetLocal');
  });

  it('returns Internet for public IP with no UDR override', () => {
    const rt = {
      vnetPrefixes: ['10.0.0.0/16'],
      routes: []
    };
    const r = evaluateRoute(rt, '8.8.8.8');
    assert.equal(r.nextHopType, 'Internet');
  });

  it('UDR VirtualAppliance overrides default route', () => {
    const rt = {
      vnetPrefixes: ['10.0.0.0/16'],
      routes: [{
        name: 'force-tunnel',
        addressPrefix: '0.0.0.0/0',
        nextHopType: 'VirtualAppliance',
        nextHopIpAddress: '10.0.0.4'
      }]
    };
    const r = evaluateRoute(rt, '8.8.8.8');
    assert.equal(r.nextHopType, 'VirtualAppliance');
    assert.equal(r.nextHopIpAddress, '10.0.0.4');
  });

  it('UDR None (drop) route', () => {
    const rt = {
      vnetPrefixes: ['10.0.0.0/16'],
      routes: [{
        name: 'drop-specific',
        addressPrefix: '0.0.0.0/0',
        nextHopType: 'None',
        nextHopIpAddress: null
      }]
    };
    const r = evaluateRoute(rt, '8.8.8.8');
    assert.equal(r.nextHopType, 'None');
  });

  it('longest prefix match wins — more specific UDR preferred over default', () => {
    const rt = {
      vnetPrefixes: [],
      routes: [
        { name: 'default', addressPrefix: '0.0.0.0/0', nextHopType: 'Internet', nextHopIpAddress: null },
        { name: 'specific', addressPrefix: '203.0.113.0/24', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.0.4' }
      ]
    };
    const r = evaluateRoute(rt, '203.0.113.5');
    assert.equal(r.nextHopType, 'VirtualAppliance');
  });

  it('returns None for no matching route', () => {
    const rt = { routes: [], vnetPrefixes: [] };
    // With empty prefixes, default system routes still handle 0.0.0.0/0 → Internet
    // So this should route to Internet
    const r = evaluateRoute(rt, '1.2.3.4');
    assert.equal(r.nextHopType, 'Internet');
  });

  it('returns None for null destinationIp', () => {
    const r = evaluateRoute({}, null);
    assert.equal(r.nextHopType, 'None');
  });
});

describe('classifySubnet', () => {
  it('classifies subnet as public when default route goes to Internet', () => {
    // No UDR override — default system route sends 0.0.0.0/0 to Internet
    const r = classifySubnet({}, { vnetPrefixes: ['10.0.0.0/16'], routes: [] });
    assert.equal(r.classification, 'public');
  });

  it('classifies subnet as private when UDR routes through VirtualAppliance', () => {
    const rt = {
      vnetPrefixes: ['10.0.0.0/16'],
      routes: [{
        name: 'force-tunnel',
        addressPrefix: '0.0.0.0/0',
        nextHopType: 'VirtualAppliance',
        nextHopIpAddress: '10.0.0.4'
      }]
    };
    const r = classifySubnet({}, rt);
    assert.equal(r.classification, 'private');
  });

  it('classifies subnet as private when UDR drops traffic (None)', () => {
    const rt = {
      vnetPrefixes: ['10.0.0.0/16'],
      routes: [{
        name: 'drop',
        addressPrefix: '0.0.0.0/0',
        nextHopType: 'None',
        nextHopIpAddress: null
      }]
    };
    const r = classifySubnet({}, rt);
    assert.equal(r.classification, 'private');
  });

  it('includes a reason string', () => {
    const r = classifySubnet({}, { vnetPrefixes: [], routes: [] });
    assert.ok(typeof r.reason === 'string' && r.reason.length > 0);
  });
});
