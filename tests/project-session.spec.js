const { test, expect } = require('@playwright/test');
const fs = require('fs');

const subscriptions = ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333'];
function project(index, name) {
  const id = `/subscriptions/${subscriptions[index]}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/${name}`;
  return { _format: 'azuremap', _version: '1.0', accountLabel: name, textareas: { in_vnets: [{ id, name, location: 'eastus', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }] }, designMode: false, designChanges: [] };
}

test.beforeEach(async ({ page }) => {
  await page.goto('http://localhost:8377/index.html', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => typeof _loadProjectData === 'function');
});

test('single project replaces a previous merge in the rendered map and saved project', async ({ page }) => {
  const a = project(0, 'old-a'), b = project(1, 'old-b');
  const merged = { ...a, _version: '2.0', multiViewMode: true, accounts: [{ id: subscriptions[0], label: 'Old A', textareas: a.textareas }, { id: subscriptions[1], label: 'Old B', textareas: b.textareas }] };
  await page.evaluate(data => _loadProjectData(data), merged);
  await expect.poll(() => page.evaluate(() => _multiViewMode)).toBe(true);
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).length)).toBe(2);
  await page.evaluate(data => _loadProjectData(data), project(2, 'new-c'));
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['new-c']);
  const saved = await page.evaluate(async () => {
    let result;
    AppProjectFiles.saveText = async text => { result = JSON.parse(text); return null; };
    await saveProject();
    return { version: result._version, accounts: result.accounts, names: result.textareas.in_vnets.map(vnet => vnet.name), merged: _multiViewMode };
  });
  expect(saved).toEqual({ version: '1.0', accounts: undefined, names: ['new-c'], merged: false });
  await expect(page.locator('#mergeBanner')).toBeHidden();
});

test('switching projects cancels a pending design edit and gives the new design session its own baseline', async ({ page }) => {
  await page.evaluate(data => _loadProjectData(data), project(0, 'project-a'));
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['project-a']);
  await page.evaluate(() => {
    enterDesignMode();
    addDesignChange({ action: 'add_security_group', target: {}, params: { Name: 'old-design-nsg', IngressRules: [] } });
  });
  await page.evaluate(data => _loadProjectData(data), project(1, 'project-b'));
  await expect(page.locator('#designToggle')).toHaveText('Design');
  const state = await page.evaluate(() => ({ design: _designMode, baseline: _designBaseline, pending: _designDebounce, changes: _designChanges.length }));
  expect(state).toEqual({ design: false, baseline: null, pending: null, changes: 0 });
  await page.locator('#designToggle').click();
  await page.locator('#designToggle').click();
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['project-b']);
  expect(await page.locator('#in_nsgs').inputValue()).toBe('');
});

test('native subnet Split and NSG form apply the accepted native resources', async ({ page }) => {
  const data = project(0, 'native-vnet');
  const vnetId = data.textareas.in_vnets[0].id;
  const subnetId = vnetId + '/subnets/original';
  const nativeSubnet = { id: subnetId, name: 'original', addressPrefix: '10.0.0.0/24' };
  data.textareas.in_subnets = [nativeSubnet];
  data.textareas.in_vnets[0].subnets = [nativeSubnet];
  data.textareas.in_nics = [{ id: 'native-nic', name: 'native-nic', ipConfigurations: [{ privateIPAddress: '10.0.0.200', subnet: { id: subnetId } }] }];
  await page.evaluate(projectData => _loadProjectData(projectData), data);
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.subnets || []).length)).toBe(1);
  await page.evaluate(() => {
    enterDesignMode();
    showDesignForm('split_subnet', { subnet: AppRenderContext.createRenderContext().rlCtx.subnets[0] });
  });
  await page.locator('#df_name_a').fill('first-half');
  await page.locator('#df_name_b').fill('second-half');
  await page.locator('#df_ok').click();
  await expect.poll(() => page.evaluate(() => JSON.parse(document.getElementById('in_subnets').value).value?.length || 0)).toBe(2);
  const split = await page.evaluate(() => ({ subnets: JSON.parse(document.getElementById('in_subnets').value).value, added: _designChanges[0]._addedIds, nic: JSON.parse(document.getElementById('in_nics').value)[0] }));
  expect(split.subnets.map(subnet => subnet.addressPrefix)).toEqual(['10.0.0.0/25', '10.0.0.128/25']);
  expect(split.added).toEqual([vnetId + '/subnets/first-half', vnetId + '/subnets/second-half']);
  expect(split.nic.ipConfigurations[0].subnet.id).toBe(vnetId + '/subnets/second-half');
  await page.evaluate(() => showDesignForm('add_security_group', { vpc: AppRenderContext.createRenderContext().rlCtx.vnets[0] }));
  await page.locator('#df_sgname').fill('web-nsg');
  await page.locator('#df_sgr_port_0').fill('443');
  await page.locator('#df_sgr_cidr_0').fill('10.0.0.0/8');
  await page.locator('#df_ok').click();
  await expect.poll(() => page.evaluate(() => JSON.parse(document.getElementById('in_nsgs').value || '{}').value?.[0]?.securityRules?.[0]?.destinationPortRange)).toBe('443');
  expect(await page.evaluate(() => JSON.parse(document.getElementById('in_nsgs').value).value[0].securityRules[0].sourceAddressPrefix)).toBe('10.0.0.0/8');
});

test('design Save and Load replay an added VM once and Undo returns to the original baseline', async ({ page }) => {
  const data = project(0, 'design-roundtrip');
  const vnetId = data.textareas.in_vnets[0].id;
  data.textareas.in_subnets = [{ id: vnetId + '/subnets/default', name: 'default', addressPrefix: '10.0.1.0/24' }];
  await page.evaluate(value => _loadProjectData(value), data);
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.subnets?.length || 0)).toBe(1);
  await page.evaluate(() => { enterDesignMode(); showDesignForm('add_resource', { subnet: AppRenderContext.createRenderContext().rlCtx.subnets[0] }); });
  await page.locator('#df_resname').fill('roundtrip-vm');
  await page.locator('#df_ok').click();
  await expect.poll(() => page.evaluate(() => JSON.parse(document.getElementById('in_vms').value || '{}').value?.length || 0)).toBe(1);
  const saved = await page.evaluate(async () => { let saved; AppProjectFiles.saveText = async text => { saved = JSON.parse(text); return null; }; await saveProject(); return saved; });
  expect(saved.textareas.in_vms).toBeUndefined();
  await page.evaluate(value => _loadProjectData(value), saved);
  await expect.poll(() => page.evaluate(() => JSON.parse(document.getElementById('in_vms').value || '{}').value?.length || 0)).toBe(1);
  await page.evaluate(() => undoLastChange());
  await expect.poll(() => page.locator('#in_vms').inputValue()).toBe('');
});

test('programmatically loaded project replaces recovery inputs before the Restore banner is used', async ({ page }) => {
  await page.locator('#in_vnets').fill(JSON.stringify(project(0, 'typed-a').textareas.in_vnets));
  await page.evaluate(() => { renderMap(); _autoSaveSession(); });
  await page.evaluate(value => _loadProjectData(value), project(1, 'loaded-b'));
  await expect.poll(() => page.evaluate(() => JSON.parse(JSON.parse(sessionStorage.getItem('azureMapper_session')).in_vnets)[0].name)).toBe('loaded-b');
  await page.reload();
  await page.locator('#restoreYes').click();
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['loaded-b']);
});

test('history buttons suspend a merge, Return restores it, and Restore commits only the historical account', async ({ page }) => {
  const a = project(0, 'history-a'), b = project(1, 'history-b');
  await page.evaluate(value => _loadProjectData(value), a);
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBe(1);
  await page.evaluate(({ a, b }) => { takeSnapshot('single account'); addAccountContext(a, 'A'); addAccountContext(b, 'B'); enterMultiView(); }, { a, b });
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBe(2);
  await page.evaluate(() => _viewSnapshot(0));
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['history-a']);
  await expect(page.locator('#mergeBanner')).toBeHidden();
  await page.locator('#historyReturn').click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBe(2);
  await expect(page.locator('#mergeBanner')).toBeVisible();
  await page.evaluate(() => _viewSnapshot(0));
  await page.locator('#historyRestore').click();
  const saved = await page.evaluate(async () => { let saved; AppProjectFiles.saveText = async text => { saved = JSON.parse(text); return null; }; await saveProject(); return { merged: _multiViewMode, accounts: _loadedContexts.length, project: saved }; });
  expect(saved.merged).toBe(false);
  expect(saved.accounts).toBe(0);
  expect(saved.project._version).toBe('1.0');
  expect(saved.project.textareas.in_vnets.map(vnet => vnet.name)).toEqual(['history-a']);
});

test('browser script buttons download the exact canonical collector assets', async ({ page }) => {
  for (const [id, name] of [['dlBash', 'export-azure-data.sh'], ['dlPowershell', 'export-azure-data.ps1']]) {
    const downloadEvent = page.waitForEvent('download');
    await page.evaluate(id => document.getElementById(id).click(), id);
    const download = await downloadEvent;
    expect(download.suggestedFilename()).toBe(name);
    expect(fs.readFileSync(await download.path(), 'utf8')).toBe(fs.readFileSync(name, 'utf8'));
  }
});

test('opening a project without overrides recomputes the BUDR profile after a dashboard override', async ({ page }) => {
  const a = project(0, 'override-a');
  a.textareas.in_vms = [{ id: 'shared-vm', name: 'shared-vm', properties: { provisioningState: 'Succeeded', storageProfile: { osDisk: { managedDisk: { id: 'shared-disk' } } } }, tags: {} }];
  a.textareas.in_snaps = [];
  await page.evaluate(value => _loadProjectData(value), a);
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['override-a']);
  await page.locator('#budrBtn').click();
  await page.locator('.budr-cfg-btn[data-rid="shared-vm"]').click();
  const form = page.locator('.budr-override-form[data-rid="shared-vm"]');
  await form.locator('.budr-ov-strategy').selectOption('critical');
  await form.locator('.budr-ov-rto').fill('5 min');
  await form.locator('.budr-ov-rpo').fill('0');
  await form.locator('.budr-ov-save').click();
  expect(await page.evaluate(() => _budrAssessments.find(a => a.id === 'shared-vm').profile.tier)).toBe('protected');
  await page.evaluate(value => _loadProjectData(value), { ...a, accountLabel: 'override-b', textareas: { ...a.textareas, in_vnets: project(1, 'override-b').textareas.in_vnets } });
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['override-b']);
  await page.locator('#budrBtn').click();
  const assessment = await page.evaluate(() => { const a = _budrAssessments.find(a => a.id === 'shared-vm'); return { overridden: !!a.overridden, profile: a.profile, overrides: _budrOverrides }; });
  expect(assessment.overrides).toEqual({});
  expect(assessment.overridden).toBe(false);
  expect(assessment.profile).toMatchObject({ tier: 'at_risk', strategy: 'cold', rto: '~8 hr', rpo: 'total loss' });
});

test('T07 Clear cancels a just-confirmed design form before its pending apply restores data', async ({ page }) => {
  await page.evaluate(value => _loadProjectData(value), project(0, 'clear-baseline'));
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBe(1);
  await page.locator('#designToggle').click();
  await page.locator('#designBannerClose').click();
  await page.locator('#sidebarToggle').click();
  await expect(page.locator('.sidebar')).not.toHaveClass(/collapsed/);
  await page.evaluate(() => showDesignForm('add_security_group', { vpc: AppRenderContext.createRenderContext().rlCtx.vnets[0] }));
  await page.locator('#df_sgname').fill('pending-nsg');
  await page.locator('#df_ok').click();
  await page.locator('#clearBtn').click();
  await expect(page.locator('#designToggle')).toHaveText('Design');
  await page.waitForTimeout(600);
  expect(await page.locator('#in_vnets').inputValue()).toBe('');
  expect(await page.locator('#in_nsgs').inputValue()).toBe('');
  expect(await page.evaluate(() => ({ context: AppRenderContext.createRenderContext().rlCtx, pending: _designDebounce, changes: _designChanges.length }))).toEqual({ context: null, pending: null, changes: 0 });
});

test('T18 all hidden merge accounts show an empty map and can be shown again', async ({ page }) => {
  const a = project(0, 'visible-a'), b = project(1, 'visible-b');
  await page.evaluate(({ a, b }) => _loadProjectData({ ...a, _version: '2.0', multiViewMode: true, accounts: [{ label: 'A', textareas: a.textareas }, { label: 'B', textareas: b.textareas }] }), { a, b });
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBe(2);
  await page.locator('.merge-acct-chip').nth(0).click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBe(1);
  await page.locator('.merge-acct-chip').nth(1).click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx)).toBe(null);
  await expect(page.locator('#mapSvg [data-vnet-id]')).toHaveCount(0);
  await expect(page.locator('.merge-acct-chip.hidden-chip')).toHaveCount(2);
  await expect(page.locator('#statsBar')).toBeHidden();
  await page.locator('.merge-acct-chip').nth(0).click();
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['visible-a']);
});

test('T06 a completed native scan replaces merged contexts instead of retaining their old map', async ({ page }) => {
  await page.addInitScript(() => {
    window.__scanListeners = {};
    window.electronAPI = {};
    for (const name of ['onScanProgress', 'onScanComplete', 'onScanError', 'onMenuSave', 'onMenuSaveAs', 'onMenuScanAzure', 'onProjectLoad', 'onImportFolder', 'onUpdateAvailable', 'onUpdateDownloadProgress', 'onUpdateDownloaded', 'onUpdateError']) {
      window.electronAPI[name] = callback => { window.__scanListeners[name] = callback; return () => {}; };
    }
  });
  await page.reload();
  await page.waitForFunction(() => typeof _loadProjectData === 'function');
  const a = project(0, 'old-a'), b = project(1, 'old-b'), c = project(2, 'scan-c');
  await page.evaluate(({ a, b }) => _loadProjectData({ ...a, _version: '2.0', multiViewMode: true, accounts: [{ label: 'A', textareas: a.textareas }, { label: 'B', textareas: b.textareas }] }), { a, b });
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBe(2);
  await page.evaluate(c => { document.getElementById('scanProfile').value = c.accountLabel; window.__scanListeners.onScanComplete({ code: 0, outDir: 'new-scan', files: { vnets: JSON.stringify(c.textareas.in_vnets) } }); }, c);
  await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name))).toEqual(['scan-c']);
  expect(await page.evaluate(() => ({ merge: _multiViewMode, accounts: _loadedContexts.length }))).toEqual({ merge: false, accounts: 0 });
  await expect(page.locator('#mapSvg [data-vnet-id]')).toHaveCount(1);
  expect(JSON.parse(await page.locator('#in_vnets').inputValue())[0].name).toBe('scan-c');
});
