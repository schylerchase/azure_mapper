import { it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import vm from 'node:vm';
const require = createRequire(import.meta.url);
const { _normalizeAzureResources } = require('../../src/modules/normalization.js');
const { safeParse, ext } = require('../../src/modules/utils.js');
const source = file => readFileSync('src/modules/' + file, 'utf8');
const vid = name => '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/' + name;

function diagramSandbox(inputs = {}) {
  const notices = [];
  const handlers = new Map();
  const sandbox = { console, crypto: { randomUUID }, _normalizeAzureResources, safeParse, ext, gv: id => JSON.stringify(inputs[id] || []), _isIgwRoute: value => value === 'Internet', clsGw: value => value === 'Internet' ? 'IGW' : 'GW',
    gn: (resource, fallback) => resource.name || fallback, sid: id => String(id).split('/').pop(), tw: text => String(text).length * 8, _showNested: false, gwNames: {},
    exportUtilitiesNotify: message => notices.push(message), document: { getElementById: id => ({ value: '', addEventListener(type, fn) { handlers.set(id + ':' + type, fn); } }) } };
  vm.createContext(sandbox);
  return { sandbox, notices, handlers };
}

it('Lucid collects native Azure CLI arrays into real VNet/subnet relationships', () => {
  const id = vid('native');
  const { sandbox } = diagramSandbox({ in_vnets: [{ id, name: 'native', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }], in_subnets: [{ id: id + '/subnets/workload', name: 'workload', addressPrefix: '10.0.0.0/24' }] });
  vm.runInContext(source('lucid-network-export-data.js'), sandbox);
  const data = sandbox.LucidNetworkExportData.collect();
  assert.equal(data.activeVpcs.length, 1);
  assert.equal(data.activeVpcs[0].VpcId, id);
  assert.equal(data.subByVnet[id][0].SubnetId, id + '/subnets/workload');
});

it('landing-zone export omits unknown edges and adds evidenced Internet and peering edges', () => {
  const hub = vid('hub'), spoke = vid('spoke');
  const inputs = { in_vnets: [{ id: hub, name: 'hub' }, { id: spoke, name: 'spoke' }], in_subnets: [{ id: hub + '/subnets/workload', name: 'workload' }, { id: spoke + '/subnets/workload', name: 'workload' }] };
  const { sandbox, notices } = diagramSandbox(inputs);
  vm.runInContext(source('lucid-network-export-data.js'), sandbox);
  vm.runInContext(source('lucid-landing-zone-export.js'), sandbox);
  const ctx = () => Object.assign(sandbox.LucidNetworkExportData.collect(), { gn: sandbox.gn, sid: sandbox.sid, tw: sandbox.tw, COL: {}, gwColors2: {}, gwFills: {}, ICON_MAP: {} });
  let result = sandbox.buildLandingZoneLayout(ctx());
  assert.deepEqual(notices, []);
  assert.ok(result);
  let ids = result.doc.pages[0].lines.map(line => line.id);
  assert.equal(ids.some(id => id.startsWith('hub_inet_') || id.startsWith('hub_spoke_')), false);
  inputs.in_udrs = [{ id: 'rt', VpcId: hub, Associations: [{ SubnetId: hub + '/subnets/workload' }], Routes: [{ DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'Internet', State: 'active' }] }];
  inputs.in_peer = [{ id: hub + '/virtualNetworkPeerings/to-spoke', remoteVirtualNetwork: { id: spoke }, peeringState: 'Connected' }];
  result = sandbox.buildLandingZoneLayout(ctx());
  assert.ok(result);
  ids = result.doc.pages[0].lines.map(line => line.id);
  assert.equal(ids.filter(id => id.startsWith('hub_inet_')).length, 3);
  assert.equal(ids.filter(id => id.startsWith('hub_spoke_')).length, 1);
});

it('Visio export produces a drawing with RBAC data loaded and native CLI network inputs', async () => {
  const id = vid('native');
  const { sandbox, handlers, notices } = diagramSandbox({ in_vnets: [{ id, name: 'native' }], in_subnets: [{ id: id + '/subnets/workload', name: 'workload', addressPrefix: '10.0.0.0/24' }] });
  let download;
  const zipFiles = new Map();
  sandbox._iamData = { roleAssignments: [{ roleDefinitionName: 'Owner' }] };
  sandbox.JSZip = class { folder() { return this; } file(path, value) { zipFiles.set(path, value); return this; } generateAsync() { return Promise.resolve('drawing'); } };
  sandbox.exportUtilitiesDownload = (blob, name) => { download = { blob, name }; };
  vm.runInContext(source('vsdx-network-export.js'), sandbox);
  handlers.get('expVsdx:click')();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(notices, []);
  assert.equal(download.name, 'azure-network-map.vsdx');
  assert.match(zipFiles.get('page1.xml'), /native/);
});

it('Lucid and Visio render native Connected peerings inferred from their IDs and omit disconnected peerings', async () => {
  const hub = vid('hub'), spoke = vid('spoke');
  const inputs = {
    in_vnets: [{ id: hub, name: 'hub' }, { id: spoke, name: 'spoke' }],
    in_subnets: [{ id: hub + '/subnets/workload', name: 'workload' }, { id: spoke + '/subnets/workload', name: 'workload' }],
    in_peer: [{ id: hub + '/virtualNetworkPeerings/to-spoke', name: 'to-spoke', remoteVirtualNetwork: { id: spoke }, peeringState: 'Connected' }]
  };
  const { sandbox, handlers, notices } = diagramSandbox(inputs);
  const zipFiles = new Map();
  sandbox.ICON_MAP = {};
  sandbox.JSZip = class { folder() { return this; } file(path, value) { zipFiles.set(path, value); return this; } generateAsync() { return Promise.resolve('drawing'); } };
  sandbox.exportUtilitiesDownload = () => {};
  for (const file of ['lucid-network-export-data.js', 'lucid-network-export.js', 'vsdx-network-export.js']) vm.runInContext(source(file), sandbox);
  for (const state of ['Connected', 'connected', 'active', 'Disconnected', 'Initiated']) {
    inputs.in_peer[0].peeringState = state;
    const connected = ['Connected', 'connected', 'active'].includes(state);
    const lucidLines = sandbox.buildLucidExport().doc.pages[0].lines;
    assert.equal(lucidLines.filter(line => (line.customData || []).some(field => /Peering/.test(field.key))).length, connected ? 1 : 0, state);
    handlers.get('expVsdx:click')();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal((zipFiles.get('page1.xml').match(/NameU="Conn\./g) || []).length, connected ? 1 : 0, state);
  }
  assert.deepEqual(notices, []);
});

it('both Lucid layouts render flattened CLI Function Apps in their integrated subnet', () => {
  const id = vid('native'), subnetId = id + '/subnets/workload';
  const { sandbox, notices } = diagramSandbox({
    in_vnets: [{ id, name: 'native' }], in_subnets: [{ id: subnetId, name: 'workload', addressPrefix: '10.0.1.0/24' }],
    in_funcapps: [{ id: '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/functions', name: 'functions', kind: 'functionapp', siteConfig: { linuxFxVersion: 'NODE|20' }, virtualNetworkSubnetId: subnetId }]
  });
  sandbox.ICON_MAP = {};
  for (const file of ['lucid-network-export-data.js', 'lucid-network-export.js', 'lucid-landing-zone-export.js']) vm.runInContext(source(file), sandbox);
  const data = sandbox.LucidNetworkExportData.collect();
  assert.equal(data.lambdaFns.length, 1);
  assert.equal(data.lambdaBySub[subnetId][0].FunctionName, 'functions');
  const standard = sandbox.buildLucidExport();
  const landing = sandbox.buildLandingZoneLayout(Object.assign(data, { gn: sandbox.gn, sid: sandbox.sid, tw: sandbox.tw, COL: {}, gwColors2: {}, gwFills: {}, ICON_MAP: {} }));
  for (const result of [standard, landing]) {
    assert.ok(result.doc.pages[0].shapes.some(shape => JSON.stringify(shape).includes('functions')));
  }
  assert.deepEqual(notices, []);
});

it('PNG export resolves external stylesheet paint without an inline style element', () => {
  let click, downloaded, drawn = false;
  const cloneRoot = { style: { values: {}, setProperty(key, value) { this.values[key] = value; } }, removeAttribute() {}, insertBefore() {} };
  const clone = { style: { values: {}, setProperty(key, value) { this.values[key] = value; } }, setAttribute() {}, querySelector: () => cloneRoot, querySelectorAll: () => [cloneRoot] };
  const root = { getBBox: () => ({ x: 0, y: 0, width: 100, height: 100 }) };
  const svg = { querySelector: () => root, querySelectorAll: () => [root], cloneNode: () => clone };
  const sandbox = { btoa, unescape, encodeURIComponent, getComputedStyle: () => ({ getPropertyValue: key => key === 'fill' ? 'rgb(10, 20, 30)' : '' }),
    document: { documentElement: { dataset: { theme: 'light' } }, getElementById: id => id === 'mapSvg' ? svg : { addEventListener(type, fn) { click = fn; } }, querySelector() { throw new Error('Inline style lookup is unavailable'); }, createElementNS: () => ({ setAttribute() {} }), createElement: () => ({ getContext: () => ({ fillRect() {}, drawImage() { drawn = true; } }), toBlob: fn => fn('png') }) },
    XMLSerializer: class { serializeToString() { return '<svg/>'; } }, Image: class { set src(value) { this.onload(); } }, exportUtilitiesDownload(blob, name) { downloaded = { blob, name }; } };
  vm.createContext(sandbox);
  vm.runInContext(source('map-png-export.js'), sandbox);
  click();
  assert.equal(cloneRoot.style.values.fill, 'rgb(10, 20, 30)');
  assert.equal(drawn, true);
  assert.equal(downloaded.name, 'azure-network-map.png');
});
