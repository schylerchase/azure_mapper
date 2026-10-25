import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import { _normalizeAzureResources } from '../../src/modules/normalization.js';
import { evaluateNsgRules, hasExplicitOutbound } from '../../src/modules/network-rules.js';
import { runComplianceChecks } from '../../src/modules/compliance-engine.js';
import { ext, safeParse } from '../../src/modules/utils.js';
import { parseRBACData } from '../../src/modules/iam-engine.js';

function runtime(files, extra = {}) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { value: '', textContent: '', innerHTML: '', style: {},
      classList: { add() {}, remove() {}, contains() { return false; } }, addEventListener() {},
      querySelectorAll() { return []; }, appendChild() {}, insertBefore() {}, focus() {} });
    return elements.get(id);
  };
  const context = vm.createContext({ console, structuredClone, Set, Map, Date, JSON,
    SNAP_KEY: 'snapshots', NOTES_KEY: 'notes', MAX_SNAPSHOTS: 20,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    evaluateNsgRules, hasExplicitOutbound, _normalizeAzureResources, ext, safeParse, parseRBACData,
    parseIAMData: raw => raw, detectAccountId: r => (r.id || '').split('/')[2] || '',
    detectRegion: r => r.location || '', _isIgwRoute: target => target === 'Internet',
    _isNatRoute: target => target === 'VirtualAppliance', _gwTypeLabel: target => target,
    ...extra });
  for (const file of files) vm.runInContext(readFileSync('src/modules/' + file + '.js', 'utf8'), context);
  return { context, elements, run: code => vm.runInContext(code, context) };
}

function nsg(rules) {
  const group = { id: 'nsg', name: 'test-nsg', securityRules: rules };
  _normalizeAzureResources({ sgs: [group] });
  return group;
}
const https = { name: 'https', priority: 200, direction: 'Inbound', access: 'Allow', protocol: 'Tcp',
  sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '443' };

test('F01 active tracing honors a higher-priority deny, including discovery mode', () => {
  const r = runtime(['flow-tracing-runtime']);
  const group = nsg([https, { ...https, name: 'deny', priority: 100, access: 'Deny' }]);
  const outcome = r.context.evaluateSG([group], 'inbound', 'tcp', 443, '0.0.0.0/0', { assumeAllow: true });
  assert.equal(outcome.action, 'deny');
  assert.match(outcome.rule, /priority 100/);
  const traced = r.context._traceInternetToResource({ type: 'instance', id: 'vm' }, { protocol: 'tcp', port: 443 }, {
    nsgs: [group], subnets: [{ SubnetId: 's', VpcId: 'v' }], pubSubs: new Set(['s']),
    instBySub: { s: [{ InstanceId: 'vm', SubnetId: 's', PrivateIpAddress: '10.0.1.5', hasPublicIp: true, SecurityGroups: [{ GroupId: 'nsg' }] }] }
  }, { discovery: true });
  assert.ok(traced.blocked);
  const ctx = { nsgs: [group], subnets: [{ SubnetId: 's', VpcId: 'v' }],
    instBySub: { s: ['source', 'target'].map(InstanceId => ({ InstanceId, SubnetId: 's',
      PrivateIpAddress: InstanceId === 'source' ? '10.0.1.4' : '10.0.1.5', SecurityGroups: [{ GroupId: 'nsg' }] })) } };
  const local = r.context._traceFlowLeg({ type: 'instance', id: 'source' }, { type: 'instance', id: 'target' },
    { protocol: 'tcp', port: 443 }, ctx, { discovery: true });
  assert.match(local.blocked.reason, /inbound/);
});

test('F01 active tracing preserves augmented ports, addresses, direction and ASG membership', () => {
  const r = runtime(['flow-tracing-runtime']);
  const group = nsg([{ ...https, sourceAddressPrefix: undefined, destinationPortRange: undefined,
    sourceAddressPrefixes: ['10.1.0.0/16', '10.2.0.0/16'], destinationPortRanges: ['443', '8443'],
    destinationAddressPrefix: '10.3.0.5', sourceApplicationSecurityGroups: [{ id: 'asg' }] },
    { ...https, name: 'deny-rest', priority: 4096, access: 'Deny', destinationPortRange: '*' }]);
  const opts = { sourceAddress: '10.2.1.1', destinationAddress: '10.3.0.5', sourceAsgIds: ['asg'] };
  assert.equal(r.context.evaluateSG([group], 'inbound', 'tcp', 8443, '10.2.1.1/32', opts).action, 'allow');
  assert.equal(r.context.evaluateSG([group], 'inbound', 'tcp', 22, '10.2.1.1/32', opts).action, 'deny');
  assert.equal(r.context.evaluateSG([group], 'inbound', 'tcp', 8443, '10.2.1.1/32', { ...opts, sourceAsgIds: [] }).action, 'deny');
  assert.equal(r.context.evaluateSG([group], 'inbound', 'tcp', 8443, '10.2.1.1/32', { ...opts, destinationAddress: '10.3.0.6' }).action, 'deny');
  assert.equal(r.context.evaluateSG([group], 'outbound', 'tcp', 8443, '10.2.1.1/32', opts).matchedSg, 'nsg');
});

test('F03 merge retains flat CLI arrays and mixed value wrappers', () => {
  const r = runtime(['multi-account-runtime']);
  const a = [{ id: 'account-a-vnet' }], b = [{ id: 'account-b-vnet' }];
  for (const [left, right] of [[a, b], [a, { value: b }], [{ value: a }, b]]) {
    const merged = r.context._mergeResourcePayloads(left, right);
    assert.deepEqual(JSON.parse(JSON.stringify(merged)), [...a, ...b]);
  }
  assert.deepEqual(JSON.parse(JSON.stringify(r.context._mergeResourcePayloads({ value: a }, { value: b }))), { value: [...a, ...b] });
});

test('F11 render context construction preserves string and object inputs and stays serializable', () => {
  const r = runtime(['multi-account-runtime']);
  for (const asString of [true, false]) {
    const raw = [{ id: '/subscriptions/a/providers/Microsoft.Network/virtualNetworks/hub', name: 'hub', location: 'eastus', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }];
    const textareas = { in_vnets: asString ? JSON.stringify(raw) : raw };
    const before = JSON.stringify(textareas);
    const result = r.context._buildRlCtxFromData(textareas, 'a');
    assert.ok(result);
    assert.equal(result.vpcs.length, 1);
    assert.equal(JSON.stringify(textareas), before);
    assert.doesNotThrow(() => JSON.stringify(result.vpcs));
  }
});

test('F06 note categories are allow-listed before imported notes render as markup', () => {
  const r = runtime(['timeline-notes-view']);
  r.context.document.getElementById('notesCatFilter').value = 'all';
  r.run('_notesLoaded=true; _annotations={resource:[{text:"note",category:"\\\"><img src=x onerror=evil()>"}]}');
  r.context._renderNotesPanel();
  const html = r.elements.get('notesPanelBody').innerHTML;
  assert.match(html, /cat-info/);
  assert.doesNotMatch(html, /<img|onerror/);
  assert.equal(r.context._getAllNotes()[0].category, 'info');
});

test('F13 joins native wrapped NIC data to a flat VM without an exported SubnetId', () => {
  const subnet = '/subscriptions/a/providers/Microsoft.Network/virtualNetworks/hub/subnets/default';
  const d = { instances: [{ id: 'vm', networkProfile: { networkInterfaces: [{ id: 'NIC' }] } }],
    enis: [{ id: 'nic', properties: { networkSecurityGroup: { id: 'nsg' }, ipConfigurations: [{ properties: { subnet: { id: subnet }, privateIPAddress: '10.0.1.5', applicationSecurityGroups: [{ id: 'asg' }] } }] } }] };
  _normalizeAzureResources(d);
  assert.equal(d.instances[0].SubnetId, subnet);
  assert.equal(d.instances[0].VpcId, subnet.split('/subnets/')[0]);
  assert.equal(d.instances[0].PrivateIpAddress, '10.0.1.5');
  assert.deepEqual(d.instances[0].SecurityGroups, [{ GroupId: 'nsg' }]);
  assert.deepEqual(d.instances[0]._asgIds, ['asg']);
});

test('F12 search and flow discovery consume the published Azure context collections', () => {
  const r = runtime(['search-index', 'flow-tracing-runtime', 'flow-analysis-runtime']);
  const group = nsg([https]);
  const instance = { InstanceId: 'vm', SubnetId: 's', VpcId: 'v', PrivateIpAddress: '10.0.1.5', hasPublicIp: true, SecurityGroups: [{ GroupId: 'nsg' }] };
  const ctx = { vnets: [{ VpcId: 'v', CidrBlock: '10.0.0.0/16' }], subnets: [{ SubnetId: 's', VpcId: 'v' }],
    vms: [instance], nsgs: [group], pubSubs: new Set(['s']), instBySub: { s: [instance] },
    sqlServers: [{ DBInstanceIdentifier: 'sql' }], functionApps: [{ FunctionName: 'function' }] };
  const search = r.context.SearchIndex.buildSearchIndex(ctx);
  for (const type of ['VNet', 'VM', 'NSG', 'Subnet', 'SQL', 'Function App']) assert.equal(search.filter(item => item.type === type).length, 1);
  const flows = r.context.discoverTrafficFlows(ctx);
  assert.equal(flows.ingressPaths.length, 1);
  assert.equal(flows.egressPaths.length, 1);
  assert.equal(flows.accessTiers.internetFacing.length, 1);
  assert.equal(flows.accessTiers.database.length, 1);
});

test('F14 lowercase native DNS names are available to both map renderers', () => {
  const d = { zones: [{ id: 'zone', name: 'internal.example', zoneType: 'Private' }] };
  _normalizeAzureResources(d);
  assert.equal(d.zones[0].Name, 'internal.example');
  assert.equal(d.zones[0].Config.PrivateZone, true);
});

test('F15 matching native VnetLocal/Internet/None routes do not throw or change next hop', () => {
  const r = runtime(['flow-tracing-runtime']);
  for (const [GatewayId, type] of [['VnetLocal', 'local'], ['Internet', 'igw'], ['None', 'blackhole']]) {
    const result = r.context.evaluateRouteTable({ Routes: [{ DestinationCidrBlock: '10.0.0.0/16', GatewayId }] }, '10.0.1.5');
    assert.equal(result.type, type);
  }
});

test('F16 storage private endpoints and VNet rules do not conceal public network access', () => {
  const r = runtime(['storage-topology']);
  const storage = { id: 'storage', publicNetworkAccess: 'Enabled', networkAcls: { defaultAction: 'Allow', virtualNetworkRules: [{ id: 'subnet' }] } };
  const topology = { linksByStorageId: { storage: [{ via: 'Private Endpoint' }] } };
  const info = r.context._storageInfo(storage, topology);
  assert.equal(info.severity, 'open');
  assert.match(info.access, /Public network.*Private Endpoint/);
  storage.publicNetworkAccess = 'Disabled';
  assert.equal(r.context._storageInfo(storage, topology).severity, 'private');
});

test('F17 flat native storage flags survive compatibility normalization', () => {
  const r = runtime(['storage-topology']);
  const storage = { name: 'storage', supportsHttpsTrafficOnly: false, allowBlobPublicAccess: true };
  _normalizeAzureResources({ s3bk: [storage] });
  const info = r.context._storageInfo(storage);
  assert.equal(info.httpsOnly, false);
  assert.equal(info.publicBlob, true);
  assert.equal(info.severity, 'risk');
});

test('F24 equal-length input edits produce new snapshots but identical input does not', () => {
  const input = { id: 'in_vnets', value: '{"location":"eastus2"}' };
  const r = runtime(['timeline-notes-view'], { document: { getElementById: () => ({ value: '', style: {}, addEventListener() {}, classList: { add() {}, remove() {} } }), querySelectorAll: () => [input] } });
  r.run('_saveSnapshots=()=>{}; _renderTimeline=()=>{}');
  const first = r.context.takeSnapshot('first');
  input.value = '{"location":"westus2"}';
  const second = r.context.takeSnapshot('second');
  assert.ok(first && second);
  assert.notEqual(first.checksum, second.checksum);
  assert.equal(r.context.takeSnapshot('same'), null);
});

test('R02 unknown source ports evaluate the complete ordered policy without bypassing Deny', () => {
  const group = nsg([{ ...https, name: 'deny-range', direction: 'Outbound', priority: 100, access: 'Deny', sourcePortRange: '0-65535' },
    { ...https, name: 'allow-later', direction: 'Outbound', priority: 200 }]);
  const r = runtime(['flow-tracing-runtime']);
  assert.equal(r.context.evaluateSG([group], 'outbound', 'tcp', 443, '8.8.8.8').action, 'deny');
  const limited = { securityRules: [{ ...https, sourcePortRange: '1024-49151' }] };
  const unknown = evaluateNsgRules(limited, 'Inbound', 'Tcp', '8.8.8.8', '*', '10.0.1.5', 443);
  assert.equal(unknown.action, 'Deny');
  assert.equal(unknown.sourcePortRequired, true);
  assert.equal(evaluateNsgRules(limited, 'Inbound', 'Tcp', '8.8.8.8', 25000, '10.0.1.5', 443).action, 'Allow');
  const joined = { securityRules: [{ ...https, sourcePortRanges: ['0-32767', '32768-65535'], sourcePortRange: undefined }] };
  assert.equal(evaluateNsgRules(joined, 'Inbound', 'Tcp', '8.8.8.8', '*', '10.0.1.5', 443).action, 'Allow');
});

test('R03 native UDR references survive context construction and block the active egress trace', () => {
  const subnet = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/virtualNetworks/v/subnets/s';
  const table = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/routeTables/deny';
  const r = runtime(['multi-account-runtime', 'flow-tracing-runtime']);
  for (const reverseReference of [false, true]) {
    const ctx = r.context._buildRlCtxFromData({
      in_vnets: [{ id: subnet.split('/subnets/')[0], name: 'v', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }],
      in_subnets: [{ id: subnet, name: 's', addressPrefix: '10.0.1.0/24', ...(reverseReference ? { routeTable: { id: table.toUpperCase() } } : {}) }],
      in_udrs: [{ id: table, name: 'deny', ...(reverseReference ? {} : { subnets: [{ id: subnet }] }),
        properties: { routes: [{ name: 'drop', properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'None' } }] } }],
      in_nics: [{ id: 'nic', name: 'nic', ipConfigurations: [{ subnet: { id: subnet }, privateIPAddress: '10.0.1.5', publicIPAddress: { id: 'pip' } }] }],
      in_vms: [{ id: 'vm', name: 'vm', networkProfile: { networkInterfaces: [{ id: 'nic' }] } }]
    }, 'test');
    assert.ok(ctx.subRT[subnet]);
    const result = r.context._traceResourceToInternet({ type: 'instance', id: 'vm' }, { protocol: 'tcp', port: 443 }, ctx);
    assert.match(result.blocked.reason, /UDR blackholes/);
  }
});

test('R16 executive contexts expose the same Azure resources and compliance controls as grid contexts', () => {
  const state = {};
  const r = runtime(['topology-renderer'], { AppRenderContext: { createRenderContext: () => state },
    _runComplianceWithCache: ctx => runComplianceChecks(ctx) });
  const group = { id: 'nsg', name: 'open', securityRules: [{ ...https, destinationPortRange: '22' }] };
  const input = { vpcs: [{ id: 'v', name: 'v' }], sgs: [group], instances: [{ id: 'vm' }], subnets: [],
    rts: [], enis: [], s3bk: [], volumes: [] };
  const canonical = r.context.topologyPublishRuntimeContext(input);
  assert.equal(canonical.vnets, input.vpcs);
  assert.equal(canonical.nsgs, input.sgs);
  assert.equal(canonical.vms, input.instances);
  assert.equal(state.rlCtx, canonical);
  assert.ok(r.context.topologyComplianceFindings(canonical).some(f => f.control === 'CIS-10'));
  assert.ok(r.context.topologyComplianceFindings(input).some(f => f.control === 'CIS-10'));
});

test('R24 private subnet egress requires an explicit outbound method', () => {
  const r = runtime(['flow-tracing-runtime']);
  const ctx = { subnets: [{ SubnetId: 's', VpcId: 'v', defaultOutboundAccess: false }],
    instBySub: { s: [{ InstanceId: 'vm', SubnetId: 's', VpcId: 'v', PrivateIpAddress: '10.0.1.5', hasPublicIp: false }] },
    subRT: {}, nsgs: [] };
  assert.match(r.context._traceResourceToInternet({ type: 'instance', id: 'vm' }, { protocol: 'tcp', port: 443 }, ctx).blocked.reason, /Default outbound access is disabled/);
  ctx.subnets[0].natGateway = { id: 'nat' };
  assert.equal(r.context._traceResourceToInternet({ type: 'instance', id: 'vm' }, { protocol: 'tcp', port: 443 }, ctx).blocked, null);
  delete ctx.subnets[0].natGateway;
  ctx.instBySub.s[0].hasPublicIp = true;
  assert.equal(r.context._traceResourceToInternet({ type: 'instance', id: 'vm' }, { protocol: 'tcp', port: 443 }, ctx).blocked, null);
});

test('R25 an absent NSG allows outbound while an unresolved attached NSG stays unassessed', () => {
  const r = runtime(['flow-tracing-runtime']);
  assert.equal(r.context.evaluateSG([], 'outbound', 'tcp', 443, '8.8.8.8').action, 'allow');
  assert.equal(r.context.evaluateSG([], 'outbound', 'tcp', 443, '8.8.8.8', { assumeAllow: true }).action, 'allow');
  const missing = r.context.flowSecurityGroups({ nsgs: [] }, ['missing-nsg']);
  const result = r.context.evaluateSG(missing, 'outbound', 'tcp', 443, '8.8.8.8');
  assert.match(result.rule, /data unavailable/);
  assert.equal(result.action, 'deny');
});

