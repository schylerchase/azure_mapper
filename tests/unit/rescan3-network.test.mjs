import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import { ipInCIDR } from '../../src/modules/cidr-engine.js';
import { addressMatch, evaluateNsgRules } from '../../src/modules/network-rules.js';
import { _normalizeAzureResources } from '../../src/modules/normalization.js';

function runtime() {
  const context = vm.createContext({ Set, Map, console, evaluateNsgRules,
    document: { getElementById: () => ({ addEventListener() {} }), addEventListener() {} },
    _isIgwRoute: target => target === 'Internet', _gwTypeLabel: target => target });
  for (const name of ['flow-tracing-runtime', 'dependency-graph-runtime']) {
    vm.runInContext(readFileSync(`src/modules/${name}.js`, 'utf8'), context);
  }
  return context;
}

test('T01 IPv6 CIDRs match full 128-bit prefixes and reject invalid or other-family addresses', () => {
  for (const [ip, cidr, expected] of [
    ['fd00:1234:5678:1::4', 'fd00:1234:5678:1::/64', true],
    ['FD00:1234:5678:0001:0:0:0:FFFF', 'fd00:1234:5678:1::/64', true],
    ['fd00:1234:5678:2::4', 'fd00:1234:5678:1::/64', false],
    ['::', '::/128', true], ['::1', '::/128', false], ['ffff::1', '::/0', true],
    ['::ffff:192.0.2.1', '::ffff:c000:200/120', true],
    ['::ffff:192.0.3.1', '::ffff:c000:200/120', false],
    ['10.0.0.1', '::/0', false], ['::1', '0.0.0.0/0', false],
    ['fd00::1', 'fd00::/129', false], ['fd00::1', 'fd00::/64x', false],
    ['fd00::1', 'fd00::1/64', false], ['fd00:::1', 'fd00::/64', false],
    ['1:2:3:4:5:6:7:8:9', '::/0', false], ['1::2::3', '::/0', false],
  ]) assert.equal(ipInCIDR(ip, cidr), expected, `${ip} in ${cidr}`);
  assert.equal(addressMatch('fd00::4', 'FD00:0:0:0:0:0:0:4'), true);
  const group = { securityRules: [
    { name: 'deny-prefix', priority: 100, direction: 'Inbound', access: 'Deny', protocol: '*',
      sourceAddressPrefix: 'fd00:1234:5678:1::/64', destinationAddressPrefix: 'fd00:1234:5678:2::/64',
      sourcePortRange: '*', destinationPortRange: '*' },
    { name: 'allow-later', priority: 200, direction: 'Inbound', access: 'Allow', protocol: '*',
      sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' },
  ] };
  const result = evaluateNsgRules(group, 'Inbound', 'Tcp', 'fd00:1234:5678:1::4', 50000, 'fd00:1234:5678:2::5', 443);
  assert.equal(result.action, 'Deny');
  assert.equal(result.rule.name, 'deny-prefix');
});

const base = '/subscriptions/test/resourceGroups/rg/providers/';
function nativeNetwork() {
  const vnetId = base + 'Microsoft.Network/virtualNetworks/net';
  const subnetId = vnetId + '/subnets/app';
  const groupId = base + 'Microsoft.Network/networkSecurityGroups/allow';
  const data = {
    vpcs: [{ id: vnetId, addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }],
    subnets: [{ id: subnetId, addressPrefix: '10.0.1.0/24', networkSecurityGroup: { id: groupId.toUpperCase() } }],
    sgs: [{ id: groupId, name: 'allow', securityRules: ['Inbound', 'Outbound'].map(direction => ({
      name: 'allow-' + direction, direction, access: 'Allow', priority: 200, protocol: '*',
      sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' })) }],
    enis: ['a', 'b'].map((name, i) => ({ id: base + 'Microsoft.Network/networkInterfaces/' + name,
      ipConfigurations: [{ primary: true, privateIPAddress: '10.0.1.' + (4 + i), subnet: { id: i ? subnetId : subnetId.toUpperCase() } }] })),
    instances: ['a', 'b'].map(name => ({ id: base + 'Microsoft.Compute/virtualMachines/' + name,
      networkProfile: { networkInterfaces: [{ id: base + 'Microsoft.Network/networkInterfaces/' + name }] } })),
  };
  _normalizeAzureResources(data);
  return { ...data, nsgs: data.sgs, vms: data.instances, instBySub: { [subnetId]: data.instances }, subRT: {} };
}
const source = { type: 'instance', id: base + 'Microsoft.Compute/virtualMachines/a' };
const target = { type: 'instance', id: base + 'Microsoft.Compute/virtualMachines/b' };
const config = { protocol: 'tcp', port: 443, sourcePort: 50000 };

test('T02 same-subnet traffic honors specific and equal-prefix blackholes but keeps broader system-local routes', () => {
  const r = runtime(), ctx = nativeNetwork(), subnetId = ctx.subnets[0].SubnetId;
  for (const prefix of ['0.0.0.0/0', '10.0.0.0/8']) {
    ctx.subRT[subnetId] = { Routes: [{ DestinationCidrBlock: prefix, GatewayId: 'None' }] };
    assert.equal(r.traceFlow(source, target, config, ctx).blocked, null);
  }
  for (const prefix of ['10.0.1.5/32', '10.0.1.0/24', '10.0.0.0/16']) {
    ctx.subRT[subnetId] = { Routes: [{ DestinationCidrBlock: prefix, GatewayId: 'None' }] };
    const result = r.traceFlow(source, target, config, ctx);
    assert.ok(result.blocked);
    assert.ok(result.path.some(hop => hop.type === 'route-table' && hop.action === 'block'));
  }
});

test('T20 case-variant native ARM subnet and NSG references join imported resources without changing native IDs', () => {
  const r = runtime(), ctx = nativeNetwork();
  assert.equal(ctx.instances[0].SubnetId, ctx.subnets[0].id);
  assert.equal(ctx.instances[0].VpcId, ctx.vpcs[0].id);
  assert.equal(ctx.enis[0].ipConfigurations[0].subnet.id, ctx.subnets[0].id.toUpperCase());
  assert.equal(ctx.subnets[0].networkSecurityGroup.id, ctx.sgs[0].id.toUpperCase());
  assert.equal(r.traceFlow(source, target, config, ctx).blocked, null);
  ctx.sgs[0].securityRules.unshift({ ...ctx.sgs[0].securityRules[0], name: 'deny-first', priority: 100, access: 'Deny' });
  assert.match(r.traceFlow(source, target, config, ctx).blocked.reason, /denies inbound/);
});

test('T21 native OS/data disks and managedBy/mapping evidence produce unique hard dependencies and disk blast radius', () => {
  const r = runtime(), vmId = source.id;
  const ids = ['os', 'data', 'mapped'].map(name => base + 'Microsoft.Compute/disks/' + name);
  const machine = { id: vmId, storageProfile: { osDisk: { managedDisk: { id: ids[0].toUpperCase() } },
    dataDisks: [{ managedDisk: { id: ids[1] } }] }, BlockDeviceMappings: [{ Ebs: { VolumeId: ids[0] } }] };
  const disks = ids.map(id => ({ id, managedBy: vmId }));
  for (const volByInst of [{ [vmId]: disks }, new Map([[vmId, disks]])]) {
    const graph = r.buildDependencyGraph({ vms: [machine], volumes: disks, volByInst });
    assert.equal(graph[vmId].length, 3);
    assert.deepEqual(new Set(graph[vmId].map(edge => edge.id)), new Set(ids));
    assert.ok(graph[vmId].every(edge => edge.rel === 'attached' && edge.strength === 'hard'));
    for (const id of ids) assert.ok(r.getBlastRadius(id, graph).hard.some(edge => edge.id === vmId));
  }
  const graph = r.buildDependencyGraph({ vms: [{ id: vmId }], volumes: [{ id: ids[2], managedBy: vmId }] });
  assert.equal(graph[vmId][0].id, ids[2]);
});
