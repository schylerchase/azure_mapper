const { test, expect } = require('@playwright/test');

const vnet = '/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/network';
const project = { _format: 'azuremap', _version: '1.0', designMode: false, annotations: {}, textareas: { in_vnets: [{ id: vnet, name: 'snapshot-original', location: 'eastus', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }] } };

test.use({ viewport: { width: 1800, height: 1000 } });
test.beforeEach(async ({ page }) => {
  await page.goto('http://localhost:8377/');
  await page.locator('#loadProjectInput').setInputFiles({ name: 'history.azuremap', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(project)) });
  await expect(page.locator('#loadingOverlay')).toBeHidden();
  await expect(page.locator('.vpc-group')).toHaveCount(1);
  await page.locator('#in_vnets').fill(JSON.stringify([{ ...project.textareas.in_vnets[0], name: 'keep-current' }]));
  await page.locator('#renderBtn').click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.[0]?.name)).toBe('keep-current');
});

async function viewHistory(page) {
  await page.locator('#timelineBtn').click();
  await page.locator('.timeline-dot').first().click();
  await page.locator('#timelineClose').click();
  await expect(page.locator('#historyBanner')).toBeVisible();
}

async function state(page) {
  return page.evaluate(() => ({ history: _viewingHistory, design: _designMode, baseline: _designBaseline, pending: !!_designDebounce, changes: _designChanges.length, name: AppRenderContext.createRenderContext().rlCtx?.vnets?.[0]?.name }));
}

test('Return discards a historical Design baseline before a subsequent Design exit', async ({ page }) => {
  await viewHistory(page);
  await page.locator('#designToggle').click();
  await page.locator('#historyReturn').click();
  await expect.poll(() => state(page)).toEqual({ history: false, design: false, baseline: null, pending: false, changes: 0, name: 'keep-current' });
  await page.locator('#designToggle').click();
  await page.locator('#designBannerClose').click();
  await page.locator('#designToggle').click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.[0]?.name)).toBe('keep-current');
});

test('Return cancels a pending historical design edit without overwriting current inputs', async ({ page }) => {
  await viewHistory(page);
  await page.locator('#designToggle').click();
  await page.evaluate(() => {
    addDesignChange({ action: 'add_security_group', target: {}, params: { Name: 'historical-only', IngressRules: [] } });
    _returnToCurrent();
  });
  await expect.poll(() => state(page)).toEqual({ history: false, design: false, baseline: null, pending: false, changes: 0, name: 'keep-current' });
  await page.waitForTimeout(450);
  await expect(page.locator('#in_nsgs')).toHaveValue('');
  expect((await state(page)).name).toBe('keep-current');
});

test('current design work is suspended for history and restored with its original baseline', async ({ page }) => {
  await page.locator('#designToggle').click();
  await page.evaluate(() => addDesignChange({ action: 'add_security_group', target: {}, params: { Name: 'current-draft', IngressRules: [] } }));
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.nsgs?.[0]?.name)).toBe('current-draft');
  await page.locator('#designBannerClose').click();
  await viewHistory(page);
  expect((await state(page)).design).toBe(false);
  await page.locator('#historyReturn').click();
  await expect.poll(() => page.evaluate(() => ({ design: _designMode, changes: _designChanges.length, name: AppRenderContext.createRenderContext().rlCtx?.vnets?.[0]?.name, nsg: AppRenderContext.createRenderContext().rlCtx?.nsgs?.[0]?.name }))).toEqual({ design: true, changes: 1, name: 'keep-current', nsg: 'current-draft' });
  await page.locator('#designBannerClose').click();
  await page.locator('#designToggle').click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.[0]?.name)).toBe('keep-current');
  await expect(page.locator('#in_nsgs')).toHaveValue('');
});

test('a pending current design edit resumes after Return while Restore commits the snapshot', async ({ page }) => {
  await page.locator('#designToggle').click();
  await page.evaluate(() => {
    addDesignChange({ action: 'add_security_group', target: {}, params: { Name: 'pending-current', IngressRules: [] } });
    _viewSnapshot(0);
    _returnToCurrent();
  });
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.nsgs?.[0]?.name)).toBe('pending-current');
  expect((await state(page)).name).toBe('keep-current');
  await page.locator('#designBannerClose').click();
  await viewHistory(page);
  await page.locator('#designToggle').click();
  await page.locator('#historyRestore').click();
  await expect.poll(() => state(page)).toEqual({ history: false, design: false, baseline: null, pending: false, changes: 0, name: 'snapshot-original' });
  await expect(page.locator('#in_nsgs')).toHaveValue('');
});
