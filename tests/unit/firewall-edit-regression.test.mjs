import { it } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { generateTerraform } from '../../src/modules/iac-terraform-generator.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';
import { generateBicep } from '../../src/modules/iac-bicep-generator.js';
const require = createRequire(import.meta.url);
const { _normalizeAzureResources } = require('../../src/modules/normalization.js');
const { evaluateNsgRules } = require('../../src/modules/network-rules.js');
const id = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web';
const rtId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/routeTables/routes';

function runtime(nsg, udRs = []) {
  _normalizeAzureResources({ sgs: [nsg], rts: udRs });
  const ctx = { nsgs: [nsg], subnetNsgs: [], udrs: udRs, subnets: [] };
  const genericNode = { classList: { contains() { return false; } }, addEventListener() {} };
  const notices = [];
  const sandbox = { structuredClone, document: { getElementById: () => genericNode }, AppRenderContext: { createRenderContext: () => ({ rlCtx: ctx, securityGroupsById: new Map([[nsg.GroupId, nsg]]) }) }, AppNotifications: { show: message => notices.push(message) } };
  vm.createContext(sandbox);
  for (const path of ['firewall-change-set.js', 'firewall-editor-runtime.js']) vm.runInContext(readFileSync('src/modules/' + path, 'utf8'), sandbox);
  function act(action, fields = {}, attributes = {}) {
    const form = { querySelector: selector => { const key = selector.match(/data-field="([^"]+)"/)?.[1]; return key in fields ? { value: fields[key], classList: { add() {}, remove() {} } } : null; }, querySelectorAll: () => [] };
    const attr = { 'data-fw-action': action, 'data-sg-id': id, 'data-rt-id': rtId, 'data-direction': 'ingress', ...attributes };
    const el = { getAttribute: key => attr[key] ?? null, closest: selector => selector === '[data-fw-form]' ? form : null };
    sandbox._fwHandleAction({ target: { closest: () => el }, stopPropagation() {} }, null, null, null);
  }
  return { sandbox, ctx, act, notices };
}

function sg(properties = {}) {
  return { id, name: 'web', securityRules: [{ name: 'restricted', priority: 100, access: 'Allow', direction: 'Inbound', protocol: 'Tcp', sourcePortRange: '*', sourceAddressPrefix: '10.0.0.0/8', destinationAddressPrefix: '*', destinationPortRange: '22', ...properties }] };
}

it('actual SG save, delete and undo keep native NSG evaluation in sync without duplicate rules', () => {
  const nsg = sg();
  const { sandbox, act } = runtime(nsg);
  act('save-sg', { protocol: 'tcp', portFrom: '8443', portTo: '8443', source: '10.0.0.0/8' }, { 'data-editing': '0' });
  assert.equal(nsg.IpPermissions.length, 1);
  assert.equal(nsg.securityRules.length, 1);
  assert.equal(nsg.securityRules[0].destinationPortRange, '8443');
  const evaluate = port => evaluateNsgRules(nsg, 'Inbound', 'Tcp', '10.1.2.3', 1234, '203.0.113.4', port).action;
  assert.equal(String(evaluate(8443)).toLowerCase(), 'allow');
  assert.equal(String(evaluate(22)).toLowerCase(), 'deny');
  sandbox._fwUndo();
  assert.equal(nsg.IpPermissions.length, 1);
  assert.equal(nsg.securityRules.length, 1);
  assert.equal(nsg.securityRules[0].destinationPortRange, '22');
  assert.equal(String(evaluate(22)).toLowerCase(), 'allow');
  act('delete-sg', {}, { 'data-rule-idx': '0' });
  assert.equal(nsg.IpPermissions.length, 0);
  assert.equal(nsg.securityRules.length, 0);
  sandbox._fwUndo();
  assert.equal(nsg.IpPermissions.length, 1);
  assert.equal(nsg.securityRules.length, 1);
});

it('actual SG edit retains augmented selectors, outbound direction, access, name and priority in CLI', () => {
  const asg = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/apps';
  const nsg = sg({ access: 'Deny', direction: 'Outbound', sourceAddressPrefix: undefined, sourceAddressPrefixes: ['10.1.0.0/16', '10.2.0.0/16'], destinationAddressPrefix: undefined, destinationApplicationSecurityGroups: [{ id: asg }], sourcePortRange: undefined, sourcePortRanges: ['1024-2048', '3000'], destinationPortRange: undefined, destinationPortRanges: ['443', '8443'] });
  const { sandbox, act, notices } = runtime(nsg);
  const original = nsg.IpPermissionsEgress[0];
  act('save-sg', { protocol: 'tcp', portFrom: String(original.FromPort), portTo: String(original.ToPort), source: asg }, { 'data-editing': '0', 'data-direction': 'egress' });
  assert.deepEqual(notices, []);
  assert.equal(nsg.securityRules.length, 1);
  assert.equal(nsg.securityRules[0].access, 'Deny');
  assert.equal(nsg.securityRules[0].priority, 100);
  assert.deepEqual(Array.from(nsg.securityRules[0].destinationPortRanges), ['443', '8443']);
  const commands = sandbox._fwGenerateCli();
  assert.equal(commands.length, 1);
  const command = commands[0];
  assert.match(command, /--nsg-name 'web' --resource-group 'rg'/);
  assert.match(command, /--subscription 'sub'/);
  assert.match(command, /--name 'restricted' --priority 100 --direction 'Outbound'/);
  assert.match(command, /--access 'Deny'/);
  assert.match(command, /--source-address-prefixes '10.1.0.0\/16' '10.2.0.0\/16'/);
  assert.match(command, /--source-port-ranges '1024-2048' '3000'/);
  assert.match(command, /--destination-port-ranges '443' '8443'/);
  assert.ok(command.includes("--destination-asgs '" + asg + "'"));
});

it('new NSG rules receive an unused required custom priority and preserve all entered prefixes', () => {
  const nsg = sg();
  const { sandbox, act } = runtime(nsg);
  act('save-sg', { protocol: 'tcp', portFrom: '443', portTo: '443', source: '10.1.0.0/16, 10.2.0.0/16' });
  assert.equal(nsg.securityRules.length, 2);
  assert.equal(nsg.securityRules[1].priority, 101);
  const command = sandbox._fwGenerateCli()[0];
  assert.match(command, /--priority 101/);
  assert.match(command, /--source-address-prefixes '10.1.0.0\/16' '10.2.0.0\/16'/);
  sandbox._fwUndo();
  assert.equal(nsg.securityRules.length, 1);
});

it('route CLI retains native next-hop enums and appliance addresses and rejects resource IDs as IPs', () => {
  const { sandbox } = runtime(sg());
  for (const type of ['Internet', 'None', 'VnetLocal', 'VirtualNetworkGateway']) {
    const command = sandbox._fwGenerateCli([{ type: 'route', resourceId: rtId, action: 'add', rule: { DestinationCidrBlock: '0.0.0.0/0', GatewayId: type, _azRoute: { name: 'default', properties: { addressPrefix: '0.0.0.0/0', nextHopType: type } } } }])[0];
    assert.match(command, /--route-table-name 'routes' --resource-group 'rg'/);
    assert.ok(command.endsWith('--next-hop-type ' + type));
  }
  const command = sandbox._fwRouteCmd('routes', 'rg', { DestinationCidrBlock: '0.0.0.0/0', _azRoute: { name: 'appliance', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.1.4' } });
  assert.match(command, /--next-hop-type VirtualAppliance --next-hop-ip-address '10.0.1.4'/);
  const invalid = sandbox._fwRouteCmd('routes', 'rg', { DestinationCidrBlock: '0.0.0.0/0', NatGatewayId: '/subscriptions/sub/providers/Microsoft.Network/natGateways/nat' });
  assert.ok(invalid.startsWith('# Route'));
  assert.doesNotMatch(invalid, /--next-hop-ip-address/);
});

it('actual route save and undo preserve native appliance details without stale or duplicate routes', () => {
  const route = { name: 'appliance', addressPrefix: '0.0.0.0/0', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.1.4' };
  const rt = { id: rtId, name: 'routes', routes: [route] };
  const { sandbox, act } = runtime(sg(), [rt]);
  act('save-rt', { dest: '10.3.0.0/16', target: 'VirtualAppliance', nextHopIp: '10.0.2.4' }, { 'data-editing': '0' });
  assert.equal(rt.Routes.length, 1);
  assert.equal(rt.routes.length, 1);
  assert.equal(rt.routes[0].addressPrefix, '10.3.0.0/16');
  assert.equal(rt.routes[0].nextHopIpAddress, '10.0.2.4');
  assert.match(sandbox._fwGenerateCli()[0], /--next-hop-ip-address '10.0.2.4'/);
  sandbox._fwUndo();
  assert.equal(rt.Routes.length, 1);
  assert.equal(rt.routes.length, 1);
  assert.equal(rt.routes[0].addressPrefix, '0.0.0.0/0');
  assert.equal(rt.routes[0].nextHopIpAddress, '10.0.1.4');
});

it('Save, Undo and Reset preserve outbound deny rules and appliance routes in every IaC format', () => {
  const nsg = sg({ priority: 220, access: 'Deny', direction: 'Outbound', destinationAddressPrefix: '203.0.113.0/24' });
  const rt = { id: rtId, name: 'routes', routes: [{ name: 'appliance', addressPrefix: '10.3.0.0/16', nextHopType: 'VirtualAppliance', nextHopIpAddress: '10.0.1.4' }] };
  const { sandbox, ctx, act } = runtime(nsg, [rt]);
  function verify(port, prefix, nextHop) {
    const resources = JSON.parse(generateARM(ctx).code).resources;
    const rule = resources.find(r => r.type.endsWith('/networkSecurityGroups')).properties.securityRules[0];
    assert.deepEqual(rule.properties, { priority: 220, direction: 'Outbound', access: 'Deny', protocol: 'Tcp', sourcePortRange: '*', sourceAddressPrefix: '10.0.0.0/8', destinationPortRange: port, destinationAddressPrefix: '203.0.113.0/24' });
    assert.deepEqual(resources.find(r => r.type.endsWith('/routeTables')).properties.routes[0].properties, { addressPrefix: prefix, nextHopType: 'VirtualAppliance', nextHopIpAddress: nextHop });
    const tf = generateTerraform(ctx).code;
    assert.match(tf, /priority\s*= 220/);
    assert.match(tf, /direction\s*= "Outbound"/);
    assert.match(tf, /access\s*= "Deny"/);
    assert.ok(tf.includes('destination_port_range = "' + port + '"'));
    assert.ok(tf.includes('address_prefix      = "' + prefix + '"'));
    assert.ok(tf.includes('next_hop_in_ip_address = "' + nextHop + '"'));
    const bicep = generateBicep(ctx).code;
    for (const value of ["priority: 220", "direction: 'Outbound'", "access: 'Deny'", "destinationPortRange: '" + port + "'", "addressPrefix: '" + prefix + "'", "nextHopIpAddress: '" + nextHop + "'"]) assert.ok(bicep.includes(value), value);
  }
  const edit = () => {
    act('save-sg', { protocol: 'tcp', portFrom: '8443', portTo: '8443', source: '203.0.113.0/24' }, { 'data-editing': '0', 'data-direction': 'egress' });
    act('save-rt', { dest: '10.4.0.0/16', target: 'VirtualAppliance', nextHopIp: '10.0.2.4' }, { 'data-editing': '0' });
  };
  verify('22', '10.3.0.0/16', '10.0.1.4');
  edit();
  verify('8443', '10.4.0.0/16', '10.0.2.4');
  sandbox._fwUndo();
  sandbox._fwUndo();
  verify('22', '10.3.0.0/16', '10.0.1.4');
  edit();
  sandbox._fwResetAll();
  verify('22', '10.3.0.0/16', '10.0.1.4');
  assert.equal(sandbox.firewallSecurityGroup(id), ctx.nsgs[0]);
  act('save-sg', { protocol: 'tcp', portFrom: '443', portTo: '443', source: '203.0.113.0/24' }, { 'data-editing': '0', 'data-direction': 'egress' });
  verify('443', '10.3.0.0/16', '10.0.1.4');
});
