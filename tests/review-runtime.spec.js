const { test, expect } = require('@playwright/test');
const { loadDemo } = require('./helpers');

const vnet = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/virtualNetworks/hub';
const subnet = vnet + '/subnets/default';
const nsg = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/networkSecurityGroups/deny';
const nic = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/networkInterfaces/nic';
const vm = '/subscriptions/test/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/vm';
const nativeInputs = {
  in_vnets: [{ id: vnet, name: 'hub', location: 'eastus', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }],
  in_subnets: [{ id: subnet, name: 'default', addressPrefix: '10.0.1.0/24', networkSecurityGroup: { id: nsg } }],
  in_nics: [{ id: nic, name: 'nic', ipConfigurations: [{ primary: true, subnet: { id: subnet }, privateIPAddress: '10.0.1.5', publicIPAddress: { id: 'public-ip' } }], networkSecurityGroup: { id: nsg } }],
  in_vms: [{ id: vm, name: 'vm', location: 'eastus', hardwareProfile: { vmSize: 'Standard_B2ms' }, networkProfile: { networkInterfaces: [{ id: nic }] } }],
  in_nsgs: [{ id: nsg, name: 'deny', securityRules: [
    { name: 'allow', priority: 200, access: 'Allow', direction: 'Inbound', protocol: 'Tcp', sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '443' },
    { name: 'deny', priority: 100, access: 'Deny', direction: 'Inbound', protocol: 'Tcp', sourceAddressPrefix: '*', destinationAddressPrefix: '*', sourcePortRange: '*', destinationPortRange: '443' }
  ] }],
  in_dnsz: [{ id: '/subscriptions/test/providers/Microsoft.Network/privateDnsZones/internal.example', name: 'internal.example', zoneType: 'Private' }]
};

async function loadProject(page, project) {
  await page.goto('http://localhost:8377/index.html');
  await page.locator('#loadProjectInput').setInputFiles({ name: 'review.azuremap', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(project)) });
  await expect(page.locator('.vpc-group')).toHaveCount(project.accounts ? 2 : 1);
  await expect(page.locator('#loadingOverlay')).toBeHidden();
}

test('native Azure upload joins VMs/NICs, renders DNS, indexes resources and honors Deny', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await loadProject(page, { _format: 'azuremap', _version: '1.0', textareas: nativeInputs });
  const result = await page.evaluate(vmId => {
    const ctx = AppRenderContext.createRenderContext().rlCtx;
    const index = SearchPanel.buildIndex(ctx);
    const trace = _traceInternetToResource({ type: 'instance', id: vmId }, { protocol: 'tcp', port: 443 }, ctx, { discovery: true });
    const lucid = LucidNetworkExportData.collect();
    return { vmSubnet: ctx.vms[0].SubnetId, mapped: Object.values(ctx.instBySub).flat().length,
      types: index.map(item => item.type), dns: ctx.zones[0].Name, blocked: !!trace.blocked, blockReason: trace.blocked && trace.blocked.reason,
      activeLucid: lucid.activeVpcs.length, lucidVms: Object.values(lucid.instBySub).flat().length,
      flowResources: Object.values(discoverTrafficFlows(ctx).accessTiers).flat().length };
  }, vm);
  expect(result.vmSubnet).toBe(subnet);
  expect(result.mapped).toBe(1);
  expect(result.types).toEqual(expect.arrayContaining(['VNet', 'Subnet', 'VM', 'NSG']));
  expect(result.dns).toBe('internal.example');
  expect(result.blocked).toBe(true);
  expect(result.blockReason).toMatch(/NSG denies inbound/);
  expect(result.activeLucid).toBe(1);
  expect(result.lucidVms).toBe(1);
  expect(result.flowResources).toBeGreaterThan(0);
  await page.locator('#sidebarToggle').click();
  for (const type of ['VNets', 'NSGs', 'VMs', 'NICs', 'DNS']) {
    await page.locator('.stat-chip[data-type="' + type + '"]').click();
    await expect(page.locator('#dpSub')).toContainText('1 total');
    await expect(page.locator('#rlItems .dp-row')).toHaveCount(1);
    await page.locator('#dpClose').click();
  }
  expect(errors).toEqual([]);
});

test('merged flat CLI inputs survive display, browser Save and Exit Merge', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const account = id => {
    const idVnet = vnet.replace('/test/', '/' + id + '/');
    return { id, label: id, textareas: { in_vnets: JSON.stringify([{ ...nativeInputs.in_vnets[0], id: idVnet }]),
      in_subnets: JSON.stringify([{ ...nativeInputs.in_subnets[0], id: idVnet + '/subnets/default' }]) } };
  };
  await loadProject(page, { _format: 'azuremap', _version: '2.0', textareas: {}, multiViewMode: true, accounts: [account('a'), account('b')] });
  await expect.poll(() => page.evaluate(() => JSON.parse(document.getElementById('in_vnets').value).length)).toBe(2);
  const pending = page.waitForEvent('download');
  await page.locator('#saveProjectBtn').click();
  const download = await pending;
  const stream = await download.createReadStream();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  const saved = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  expect(saved.accounts).toHaveLength(2);
  for (const account of saved.accounts) expect(account.textareas.in_vnets).toHaveLength(1);
  await page.locator('#mergeExitBtn').click();
  await expect(page.locator('#mergeBanner')).toBeHidden();
  await expect(page.locator('.vpc-group')).toHaveCount(2);
  expect(errors).toEqual([]);
});

test('imported note categories render safely and equal-length edits retain snapshots', async ({ page }) => {
  await loadProject(page, { _format: 'azuremap', textareas: nativeInputs,
    annotations: { [vm]: [{ text: 'review note', category: '\"><img id="category-breakout" src="x">', created: '2026-10-10T00:00:00Z' }] } });
  await page.locator('#notesBtn').click();
  await expect(page.locator('.note-cat-badge')).toHaveText('info');
  await expect(page.locator('#category-breakout')).toHaveCount(0);
  const snapshots = await page.evaluate(() => {
    takeSnapshot('before');
    document.getElementById('in_vnets').value = document.getElementById('in_vnets').value.replace('eastus', 'westus');
    const changed = takeSnapshot('changed');
    return { changed: !!changed, unchanged: takeSnapshot('unchanged') === null };
  });
  expect(snapshots).toEqual({ changed: true, unchanged: true });
});

test('PNG export works with production external stylesheets', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await loadDemo(page);
  await page.locator('#ebToggle').click();
  const pending = page.waitForEvent('download');
  await page.locator('#expPng').click();
  const download = await pending;
  expect(download.suggestedFilename()).toMatch(/\.png$/);
  expect(await download.failure()).toBeNull();
  expect(errors).toEqual([]);
});

test('corrected design types reach the rendered native resource collections', async ({ page }) => {
  await loadProject(page, { _format: 'azuremap', textareas: nativeInputs });
  await page.evaluate(({ vnet, subnet }) => {
    enterDesignMode();
    for (const ResourceType of ['Redis', 'FunctionApp', 'Synapse']) addDesignChange({ action: 'add_resource', target: { SubnetId: subnet }, params: { ResourceType, VpcId: vnet, SubnetId: subnet, Name: 'design-' + ResourceType } });
    addDesignChange({ action: 'add_gateway', target: { VpcId: vnet }, params: { GatewayType: 'AZFW', VpcId: vnet, SubnetId: subnet, Name: 'design-firewall' } });
  }, { vnet, subnet });
  await expect.poll(() => page.evaluate(() => {
    const ctx = AppRenderContext.createRenderContext().rlCtx;
    return [ctx.redisCaches.length, ctx.functionApps.length, ctx.synapseWorkspaces.length, ctx.firewalls.length];
  })).toEqual([1, 1, 1, 1]);
});
