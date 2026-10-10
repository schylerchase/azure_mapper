import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import { _normalizeAzureResources } from '../../src/modules/normalization.js';
import { evaluateNsgRules, hasExplicitOutbound } from '../../src/modules/network-rules.js';

function runtime() {
  const context = vm.createContext({ console, Set, Map, evaluateNsgRules, hasExplicitOutbound,
    document: { getElementById: () => ({ addEventListener() {} }), addEventListener() {} },
    _isIgwRoute: target => target === 'Internet', _isNatRoute: () => false,
    _gwTypeLabel: target => target });
  vm.runInContext(readFileSync('src/modules/flow-tracing-runtime.js', 'utf8'), context);
  return context;
}
const config = { protocol: 'tcp', port: 443, sourcePort: 50000 };
function network(cross = false) {
  const group = { id: 'allow', name: 'allow', securityRules: ['Inbound', 'Outbound'].map(direction => ({
    name: 'allow-' + direction, direction, access: 'Allow', priority: 100, protocol: '*',
    sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*' })) };
  _normalizeAzureResources({ sgs: [group] });
  return { vpcs: [{ VpcId: 'a', CidrBlock: '10.0.0.0/16' }, ...(cross ? [{ VpcId: 'b', CidrBlock: '10.1.0.0/16' }] : [])],
    subnets: [{ SubnetId: 'sa', VpcId: 'a', CidrBlock: '10.0.1.0/24' }, { SubnetId: 'sb', VpcId: cross ? 'b' : 'a', CidrBlock: cross ? '10.1.1.0/24' : '10.0.2.0/24' }],
    nsgs: [group], peerings: [], pubSubs: new Set(['sa']), subRT: {},
    instBySub: { sa: [{ InstanceId: 'source', SubnetId: 'sa', VpcId: 'a', PrivateIpAddress: '10.0.1.4', SecurityGroups: [{ GroupId: 'allow' }] }],
      sb: [{ InstanceId: 'target', SubnetId: 'sb', VpcId: cross ? 'b' : 'a', PrivateIpAddress: cross ? '10.1.1.4' : '10.0.2.4', SecurityGroups: [{ GroupId: 'allow' }] }] } };
}
const source = { type: 'instance', id: 'source' }, target = { type: 'instance', id: 'target' };

test('S22 active route tracing merges VNet system routes with custom routes', () => {
  const r = runtime(), ctx = network();
  for (const DestinationCidrBlock of ['10.20.0.0/16', '0.0.0.0/0']) {
    ctx.subRT.sa = { Routes: [{ DestinationCidrBlock, GatewayId: 'None' }] };
    assert.equal(r.traceFlow(source, target, config, ctx).blocked, null);
  }
  // Equal-prefix UDRs and more-specific UDRs must still override local routing.
  for (const DestinationCidrBlock of ['10.0.0.0/16', '10.0.2.0/24']) {
    ctx.subRT.sa = { Routes: [{ DestinationCidrBlock, GatewayId: 'None' }] };
    assert.ok(r.traceFlow(source, target, config, ctx).blocked);
  }
});

test('S23 Internet ingress requires a public endpoint, even with an Internet UDR', () => {
  const r = runtime(), ctx = network();
  const internet = { type: 'internet', id: 'internet' };
  ctx.subRT.sa = { Routes: [{ DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'Internet' }] };
  assert.match(r._traceFlowLeg(internet, source, config, ctx).blocked.reason, /Public IP/);
  ctx.instBySub.sa[0].hasPublicIp = true;
  assert.equal(r._traceFlowLeg(internet, source, config, ctx).blocked, null);
  ctx.instBySub.sa[0].hasPublicIp = false;
  ctx.instBySub.sa[0].PublicIpAddress = '203.0.113.7';
  assert.equal(r._traceFlowLeg(internet, source, config, ctx).blocked, null);
  ctx.albBySub = { sa: [{ LoadBalancerName: 'frontend', frontendIPConfigurations: [{ publicIPAddress: { id: 'pip' } }] }] };
  assert.equal(r._traceFlowLeg(internet, { type: 'alb', id: 'frontend' }, config, ctx).blocked, null);
});

test('S24 native flattened and ARM peering IDs determine the local VNet', () => {
  const local = '/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/a';
  const remote = local.replace(/\/a$/, '/b');
  for (const wrapped of [false, true]) {
    const properties = { remoteVirtualNetwork: { id: remote }, peeringState: 'Connected', allowVirtualNetworkAccess: true };
    const peer = { id: local + '/virtualNetworkPeerings/a-b', ...(wrapped ? { properties } : properties) };
    _normalizeAzureResources({ peerings: [peer] });
    assert.equal(peer.RequesterVpcInfo.VpcId, local);
    assert.equal(peer.AccepterVpcInfo.VpcId, remote);
    const r = runtime(), ctx = network(true);
    ctx.vpcs[0].VpcId = ctx.subnets[0].VpcId = ctx.instBySub.sa[0].VpcId = local;
    ctx.vpcs[1].VpcId = ctx.subnets[1].VpcId = ctx.instBySub.sb[0].VpcId = remote;
    ctx.peerings = [peer];
    assert.equal(r.traceFlow(source, target, config, ctx).blocked, null);
  }
});

test('S25 cross-VNet tracing rejects disconnected, unknown and access-disabled peerings', () => {
  const r = runtime(), ctx = network(true);
  const peer = { RequesterVpcInfo: { VpcId: 'a' }, AccepterVpcInfo: { VpcId: 'b' }, Status: { Code: 'Connected' }, allowVirtualNetworkAccess: true };
  ctx.peerings = [peer];
  assert.equal(r.traceFlow(source, target, config, ctx).blocked, null);
  for (const Code of ['Disconnected', 'Initiated', '']) {
    peer.Status.Code = Code;
    assert.match(r.traceFlow(source, target, config, ctx).blocked.reason, /not confirmed Connected/);
  }
  peer.Status.Code = 'Connected'; peer.allowVirtualNetworkAccess = false;
  assert.match(r.traceFlow(source, target, config, ctx).blocked.reason, /disables virtual network access/);
  peer.Status.Code = 'active'; delete peer.allowVirtualNetworkAccess;
  assert.equal(r.traceFlow(source, target, config, ctx).blocked, null);
});
