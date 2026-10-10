const { test, expect } = require('@playwright/test');
const { readFileSync } = require('node:fs');
const base = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/';
const vnet = base + 'virtualNetworks/v', subnet = vnet + '/subnets/s', nsg = base + 'networkSecurityGroups/nsg', nic = base + 'networkInterfaces/nic';
const vm = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/vm';
const rule = (direction, overrides = {}) => ({ name: direction, priority: 100, direction, access: 'Allow', protocol: '*',
  sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '*', ...overrides });
function inputs() {
  return { in_vnets: [{ id: vnet, name: 'v', location: 'eastus', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }],
    in_subnets: [{ id: subnet, name: 's', addressPrefix: '10.0.1.0/24', networkSecurityGroup: { id: nsg } }],
    in_nics: [{ id: nic, name: 'nic', networkSecurityGroup: { id: nsg }, ipConfigurations: [{ primary: true, subnet: { id: subnet }, privateIPAddress: '10.0.1.5', publicIPAddress: { id: base + 'publicIPAddresses/pip' } }] }],
    in_vms: [{ id: vm, name: 'vm', networkProfile: { networkInterfaces: [{ id: nic }] } }],
    in_nsgs: [{ id: nsg, name: 'nsg', securityRules: [rule('Inbound'), rule('Outbound')] }] };
}
async function load(page, data, layout = 'grid') {
  await page.goto('http://localhost:8377/');
  await page.locator('#loadProjectInput').setInputFiles({ name: 'rescan.azuremap', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({ _format: 'azuremap', textareas: data, layout })) });
  await expect(page.locator(layout === 'executive' ? '#mapSvg .map-root' : '.vpc-group')).toHaveCount(layout === 'executive' ? 1 : data.in_vnets.length);
  await expect(page.locator('#loadingOverlay')).toBeHidden();
}
async function trace(page) {
  return page.evaluate(vm => _traceResourceToInternet({ type: 'instance', id: vm }, { protocol: 'tcp', port: 443 },
    AppRenderContext.createRenderContext().rlCtx), vm);
}

function sameSubnetPair() {
  const data = inputs();
  data.in_nics.push({ id: nic + '-other', ipConfigurations: [{ primary: true, subnet: { id: subnet }, privateIPAddress: '10.0.1.6' }] });
  data.in_vms.push({ id: vm + '-other', name: 'other', networkProfile: { networkInterfaces: [{ id: nic + '-other' }] } });
  return data;
}
const pairTrace = page => page.evaluate(([source, target]) => traceFlow({ type: 'instance', id: source },
  { type: 'instance', id: target }, { protocol: 'tcp', port: 443, sourcePort: 50000 }, flowRuntimeData()), [vm, vm + '-other']);

test('T01 dual-stack subnet tracing applies an IPv6 CIDR Deny before a later Allow', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const data = inputs(), other = vnet + '/subnets/other';
  delete data.in_vms;
  delete data.in_nics;
  data.in_vnets[0].addressSpace.addressPrefixes.push('fd00:1234:5678::/48');
  delete data.in_subnets[0].addressPrefix;
  data.in_subnets[0].addressPrefixes = ['fd00:1234:5678:1::/64', '10.0.1.0/24'];
  data.in_subnets.push({ id: other, name: 'other', addressPrefixes: ['fd00:1234:5678:2::/64', '10.0.2.0/24'], networkSecurityGroup: { id: nsg } });
  data.in_nsgs[0].securityRules = [rule('Inbound', { name: 'deny-ipv6', access: 'Deny', priority: 100,
    sourceAddressPrefix: 'fd00:1234:5678:1::/64', destinationAddressPrefix: 'fd00:1234:5678:2::/64' }),
    rule('Inbound', { priority: 200 }), rule('Outbound')];
  await load(page, data);
  const result = await page.evaluate(([a, b]) => traceFlow({ type: 'subnet', id: a }, { type: 'subnet', id: b },
    { protocol: 'tcp', port: 443, sourcePort: 50000 }, flowRuntimeData()), [subnet, other]);
  expect(result.blocked.reason).toContain('denies inbound');
  expect(result.path.find(hop => hop.action === 'deny').rule).toContain('deny-ipv6');
  expect(errors).toEqual([]);
});

test('T02 same-subnet VM tracing evaluates the target-specific UDR blackhole', async ({ page }) => {
  const data = sameSubnetPair(), route = base + 'routeTables/drop';
  data.in_subnets[0].routeTable = { id: route };
  data.in_udrs = [{ id: route, routes: [{ addressPrefix: '10.0.1.6/32', nextHopType: 'None' }] }];
  await load(page, data);
  const result = await pairTrace(page);
  expect(result.blocked).not.toBeNull();
  expect(result.path).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'route-table', action: 'block' })]));
});

test('T20 case-variant ARM subnet and NSG bindings retain VM placement and correct tracing', async ({ page }) => {
  const data = sameSubnetPair();
  data.in_subnets[0].networkSecurityGroup.id = nsg.toUpperCase();
  data.in_nics[0].ipConfigurations[0].subnet.id = subnet.toUpperCase();
  await load(page, data);
  const positions = await page.evaluate(vm => {
    const ctx = AppRenderContext.createRenderContext().rlCtx;
    return { subnet: ctx.vms.find(r => r.id === vm).SubnetId, count: (ctx.instBySub[ctx.subnets[0].SubnetId] || []).length };
  }, vm);
  expect(positions).toEqual({ subnet, count: 2 });
  expect((await pairTrace(page)).blocked).toBeNull();
});

test('T21 attached native managed disks appear in the dependency overlay and disk blast radius', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const data = inputs(), disk = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Compute/disks/os';
  data.in_vms[0].storageProfile = { osDisk: { name: 'os', managedDisk: { id: disk } } };
  data.in_disks = [{ id: disk, name: 'os', managedBy: vm, diskSizeGb: 32, sku: { name: 'Premium_LRS' } }];
  await load(page, data);
  const result = await page.evaluate(([vm, disk]) => {
    const graph = buildDependencyGraph(AppRenderContext.createRenderContext().rlCtx);
    showDependencies(vm);
    return { edges: graph[vm], affected: getBlastRadius(disk, graph).hard.map(edge => edge.id) };
  }, [vm, disk]);
  expect(result.edges).toEqual(expect.arrayContaining([expect.objectContaining({ id: disk, rel: 'attached', strength: 'hard' })]));
  expect(result.affected).toContain(vm);
  await expect(page.locator('#depOverlay')).toHaveClass(/open/);
  await expect(page.locator('#depBody .dep-node[data-id="' + disk + '"]')).toHaveCount(1);
  await expect(page.locator('#depBody')).toContainText('os');
  expect(errors).toEqual([]);
});
test('unknown source ports cannot bypass Deny and the trace panel resolves conditional policy', async ({ page }) => {
  const data = inputs();
  data.in_nsgs[0].securityRules = [
    rule('Outbound', { name: 'deny-all-source-ports', access: 'Deny', sourcePortRange: '0-65535', destinationPortRange: '443' }),
    rule('Outbound', { name: 'allow-later', priority: 200, destinationPortRange: '443' }) ];
  await load(page, data);
  expect((await trace(page)).blocked).not.toBeNull();
  data.in_nsgs[0].securityRules = [
    rule('Outbound', { name: 'allow-limited', sourcePortRange: '1024-49151', destinationPortRange: '443' }),
    rule('Outbound', { name: 'deny-other', priority: 200, access: 'Deny', destinationPortRange: '443' }) ];
  await load(page, data);
  await page.evaluate(vm => { enterFlowMode({ type: 'instance', id: vm }); _flowTarget = { type: 'internet', id: 'Internet' }; _executeTrace(); }, vm);
  await expect(page.locator('#dpBody')).toContainText('policy varies by source port');
  await page.locator('#flowSourcePortInput').fill('25000');
  await page.locator('#flowRetraceBtn').click();
  await expect(page.locator('#dpSub')).toContainText('ALLOWED');
  await page.locator('#flowSourcePortInput').fill('60000');
  await page.locator('#flowRetraceBtn').click();
  await expect(page.locator('#dpSub')).toContainText('BLOCKED');
});
test('native route-table references attach the UDR and enforce a blackhole route', async ({ page }) => {
  const data = inputs(), route = base + 'routeTables/deny';
  data.in_subnets[0].routeTable = { id: route };
  data.in_udrs = [{ id: route, name: 'deny', routes: [{ name: 'drop', addressPrefix: '0.0.0.0/0', nextHopType: 'None' }] }];
  await load(page, data);
  expect(await page.evaluate(subnet => !!AppRenderContext.createRenderContext().rlCtx.subRT[subnet], subnet)).toBe(true);
  expect((await trace(page)).blocked.reason).toContain('UDR blackholes');
});
test('executive and grid layouts assess the same native resources and retain gap disclosures', async ({ page }) => {
  const data = inputs();
  await load(page, data);
  const grid = await page.evaluate(() => AppRenderContext.createRenderContext().complianceFindings.map(f => f.control || f.id).sort());
  expect(grid).toContain('CIS-10');
  await load(page, data, 'executive');
  const executive = await page.evaluate(() => ({ controls: AppRenderContext.createRenderContext().complianceFindings.map(f => f.control || f.id).sort(),
    vms: AppRenderContext.createRenderContext().rlCtx.vms.length, gaps: Object.keys(AppRenderContext.createRenderContext().rlCtx.assessmentGaps).length }));
  expect(executive.controls).toEqual(grid);
  expect(executive.vms).toBe(1);
  expect(executive.gaps).toBeGreaterThan(0);
});
test('private subnet egress needs an explicit method and an absent NSG does not invent outbound denial', async ({ page }) => {
  const data = inputs();
  data.in_subnets[0].defaultOutboundAccess = false;
  delete data.in_nics[0].ipConfigurations[0].publicIPAddress;
  await load(page, data);
  expect((await trace(page)).blocked.reason).toContain('Default outbound access is disabled');
  data.in_subnets[0].natGateway = { id: base + 'natGateways/nat' };
  await load(page, data);
  expect((await trace(page)).blocked).toBeNull();
  const noNsg = inputs();
  delete noNsg.in_subnets[0].networkSecurityGroup;
  delete noNsg.in_nics[0].networkSecurityGroup;
  noNsg.in_nsgs = [];
  await load(page, noNsg);
  expect((await trace(page)).blocked).toBeNull();
});

test('intra-VNet tracing preserves system routes and honors matching UDR overrides', async ({ page }) => {
  const data = inputs(), otherSubnet = vnet + '/subnets/other', otherVm = vm + '-other';
  data.in_subnets.push({ id: otherSubnet, name: 'other', addressPrefix: '10.0.2.0/24', networkSecurityGroup: { id: nsg } });
  data.in_nics.push({ id: nic + '-other', ipConfigurations: [{ subnet: { id: otherSubnet }, privateIPAddress: '10.0.2.4' }] });
  data.in_vms.push({ id: otherVm, name: 'other', networkProfile: { networkInterfaces: [{ id: nic + '-other' }] } });
  const route = base + 'routeTables/custom';
  data.in_subnets[0].routeTable = { id: route };
  const localTrace = () => page.evaluate(([source, target]) => traceFlow({ type: 'instance', id: source },
    { type: 'instance', id: target }, { protocol: 'tcp', port: 443, sourcePort: 50000 }, flowRuntimeData()), [vm, otherVm]);
  for (const addressPrefix of ['10.20.0.0/16', '0.0.0.0/0']) {
    data.in_udrs = [{ id: route, routes: [{ addressPrefix, nextHopType: 'None' }] }];
    await load(page, data);
    expect((await localTrace()).blocked).toBeNull();
  }
  data.in_udrs[0].routes[0].addressPrefix = '10.0.2.0/24';
  await load(page, data);
  expect((await localTrace()).blocked).not.toBeNull();
});

test('an outbound Internet UDR does not expose a VM without a public endpoint', async ({ page }) => {
  const data = inputs(), route = base + 'routeTables/internet';
  delete data.in_nics[0].ipConfigurations[0].publicIPAddress;
  data.in_subnets[0].routeTable = { id: route };
  data.in_udrs = [{ id: route, routes: [{ addressPrefix: '0.0.0.0/0', nextHopType: 'Internet' }] }];
  await load(page, data);
  const ingress = await page.evaluate(vm => _traceFlowLeg({ type: 'internet', id: 'internet' }, { type: 'instance', id: vm },
    { protocol: 'tcp', port: 443, sourcePort: 50000 }, flowRuntimeData()), vm);
  expect(ingress.blocked.reason).toContain('Public IP');
});

test('native peering IDs resolve while state and access still constrain tracing', async ({ page }) => {
  const data = inputs(), remote = base + 'virtualNetworks/remote', remoteSubnet = remote + '/subnets/s', remoteVm = vm + '-remote';
  data.in_vnets.push({ id: remote, name: 'remote', addressSpace: { addressPrefixes: ['10.1.0.0/16'] } });
  data.in_subnets.push({ id: remoteSubnet, name: 'remote', addressPrefix: '10.1.1.0/24', networkSecurityGroup: { id: nsg } });
  data.in_nics.push({ id: nic + '-remote', ipConfigurations: [{ subnet: { id: remoteSubnet }, privateIPAddress: '10.1.1.4' }] });
  data.in_vms.push({ id: remoteVm, name: 'remote', networkProfile: { networkInterfaces: [{ id: nic + '-remote' }] } });
  data.in_peer = [{ id: vnet + '/virtualNetworkPeerings/remote', peeringState: 'Connected',
    allowVirtualNetworkAccess: true, remoteVirtualNetwork: { id: remote } }];
  const crossTrace = () => page.evaluate(([source, target]) => traceFlow({ type: 'instance', id: source },
    { type: 'instance', id: target }, { protocol: 'tcp', port: 443, sourcePort: 50000 }, flowRuntimeData()), [vm, remoteVm]);
  await load(page, data);
  expect((await crossTrace()).blocked).toBeNull();
  data.in_peer[0].peeringState = 'Disconnected';
  await load(page, data);
  expect((await crossTrace()).blocked.reason).toContain('not confirmed Connected');
  data.in_peer[0].peeringState = 'Connected'; data.in_peer[0].allowVirtualNetworkAccess = false;
  await load(page, data);
  expect((await crossTrace()).blocked.reason).toContain('disables virtual network access');
});

test('browser export-script downloads exactly match the canonical collection scripts', async ({ page }) => {
  await load(page, inputs());
  for (const [button, filename] of [['dlBash', 'export-azure-data.sh'], ['dlPowershell', 'export-azure-data.ps1']]) {
    const pending = page.waitForEvent('download');
    await page.locator('#dlExportScript').click();
    await page.locator('#' + button).click();
    const download = await pending;
    expect(download.suggestedFilename()).toBe(filename);
    expect(readFileSync(await download.path())).toEqual(readFileSync(filename));
  }
});

