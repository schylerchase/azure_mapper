const { test, expect } = require('@playwright/test');
const { loadDemo, openDashTab } = require('./helpers');

const OWNER_ASSIGNMENT = {
  id: '/subscriptions/native-sub/providers/Microsoft.Authorization/roleAssignments/owner-grant',
  scope: '/subscriptions/native-sub', principalId: 'native-principal',
  principalDisplayName: 'Native Owner Principal', principalType: 'User',
  roleDefinitionId: '/subscriptions/native-sub/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
};

async function uploadJSON(page, name, value) {
  // Demo starts in merge mode, whose map intentionally uses its prebuilt context.
  // These tests replace a single-account collector input through the real UI.
  if(await page.locator('#mergeExitBtn').isVisible()){
    await page.locator('#mergeExitBtn').click();
    await expect(page.locator('#mergeBanner')).toBeHidden();
    await expect(page.locator('#loadingOverlay')).toBeHidden();
  }
  await page.locator('#fileInput').setInputFiles({
    name, mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)),
  });
  await expect(page.locator('#uploadStatus')).toContainText('1 of 1 files loaded');
}

async function captureHTMLReport(page) {
  await page.evaluate(() => {
    window.__reviewReport = null;
    window.AppDownloads.saveBlob = async (blob, name) => {
      window.__reviewReport = { name, text: await blob.text() };
    };
  });
  await page.locator('#rptExportHTML').click();
  await expect.poll(() => page.evaluate(() => window.__reviewReport)).not.toBeNull();
  return page.evaluate(() => window.__reviewReport.text);
}

async function importReport(page, value) {
  const json = JSON.stringify({ _rptFormat: 'azuremapper-report', _rptVersion: '1.0', ...value }).replace(/</g, '\\u003c');
  await page.locator('#importReportInput').setInputFiles({
    name: 'review-report.html', mimeType: 'text/html',
    buffer: Buffer.from(`<html><body><script type="application/json" id="rpt-embedded-data">${json}</script></body></html>`),
  });
  await expect.poll(() => page.evaluate(() => _importedReportData && _importedReportData.title)).toBe(value.title);
  await expect(page.locator('#rptTitle')).toHaveValue(value.title);
}

test.describe('Review results production regressions', () => {
  test.beforeEach(async ({ page }) => { await loadDemo(page); });

  test('native RBAC upload reaches Owner findings, principal review, and report', async ({ page }) => {
    await uploadJSON(page, 'role-assignments.json', [OWNER_ASSIGNMENT]);
    await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().complianceFindings
      .some(f => f.control === 'RBAC-1' && f.resourceId.endsWith('/owner-grant') && f._subscriptionId === 'native-sub'))).toBe(true);
    await openDashTab(page, 'iam');
    await expect(page.locator('#udashBody')).toContainText('Native Owner Principal');
    await expect(page.locator('#udashBody')).toContainText('Owner @ /subscriptions/native-sub');
    const principal = await page.evaluate(() => _iamReviewData.find(r => r.name === 'Native Owner Principal'));
    expect(principal).toMatchObject({ provider: 'azure', roleName: 'Owner', scope: '/subscriptions/native-sub', hasMFA: null });
    await openDashTab(page, 'reports');
    const html = await captureHTMLReport(page);
    expect(html).toContain('Native Owner Principal');
    expect(html).toContain('/subscriptions/native-sub');
    expect(html).toContain('Azure RBAC Assignments');
  });

  test('equal-length storage edit refreshes compliance and inventory joins', async ({ page }) => {
    const id = await page.evaluate(() => {
      const first = AppRenderContext.createRenderContext().rlCtx.vnets[0];
      return `/subscriptions/${first._subscriptionId}/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/reviewstore`;
    });
    const storage = [{ id, name: 'reviewstore', location: 'eastus2', minimumTlsVersion: 'TLS1_0',
      enableHttpsTrafficOnly: true, allowBlobPublicAccess: false, publicNetworkAccess: 'Disabled' }];
    await uploadJSON(page, 'storage-accounts.json', storage);
    await expect.poll(() => page.evaluate(id => AppRenderContext.createRenderContext().complianceFindings
      .some(f => f.id === 'CIS-44' && f.resourceId === id), id)).toBe(true);
    await openDashTab(page, 'inventory');
    const previous = await page.evaluate(id => _inventoryData.find(r => r.id === id).complianceFail, id);
    expect(previous).toBeGreaterThan(0);
    await page.locator('#udashClose').click();
    const before = JSON.stringify(storage);
    storage[0].minimumTlsVersion = 'TLS1_2';
    const after = JSON.stringify(storage);
    expect(after.length).toBe(before.length);
    await page.locator('#in_storage').fill(after);
    await page.locator('#renderBtn').click();
    await expect.poll(() => page.evaluate(id => AppRenderContext.createRenderContext().complianceFindings
      .some(f => f.id === 'CIS-44' && f.resourceId === id), id)).toBe(false);
    await openDashTab(page, 'inventory');
    const current = await page.evaluate(id => _inventoryData.find(r => r.id === id).complianceFail, id);
    expect(current).toBeLessThan(previous);
  });

  test('HTML export keeps delimiter text inside embedded JSON and round-trips it', async ({ page }) => {
    await openDashTab(page, 'reports');
    const title = '</script><p id="review-outside">review text</p>&<';
    await page.locator('#rptTitle').fill(title);
    const html = await captureHTMLReport(page);
    const parsed = await page.evaluate(html => {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      return { outside: !!doc.getElementById('review-outside'),
        title: JSON.parse(doc.getElementById('rpt-embedded-data').textContent).title };
    }, html);
    expect(parsed).toEqual({ outside: false, title });
    await page.locator('#importReportInput').setInputFiles({ name: 'roundtrip.html', mimeType: 'text/html', buffer: Buffer.from(html) });
    await expect.poll(() => page.evaluate(() => _importedReportData && _importedReportData.title)).toBe(title);
  });

  test('partial report import clears earlier principals, apps, and subscriptions', async ({ page }) => {
    await openDashTab(page, 'reports');
    await importReport(page, { title: 'Report A', findings: [],
      iamReviewData: [{ name: 'Old Principal', arn: 'old', type: 'User', findings: [], crossAccounts: [], policies: 1 }],
      appRegistry: [{ id: 'old-app', name: 'Old Application', resources: [], tier: 'low' }],
      contexts: [{ accountId: 'old-sub', accountLabel: 'Old subscription' }],
      enabledModules: ['exec-summary', 'iam-review', 'app-summary'] });
    expect(await page.evaluate(() => _iamReviewData.map(r => r.name))).toEqual(['Old Principal']);
    await importReport(page, { title: 'Report B', findings: [], enabledModules: ['exec-summary'] });
    const state = await page.evaluate(() => ({ principals: _iamReviewData.length, apps: _appRegistry.length,
      contexts: _loadedContexts.length, embedded: JSON.parse(_rptEmbedDataBlob(['exec-summary']).split('\n')[2]) }));
    expect(state.principals).toBe(0);
    expect(state.apps).toBe(0);
    expect(state.contexts).toBe(0);
    expect(state.embedded.iamReviewData).toEqual([]);
    expect(state.embedded.appRegistry).toEqual([]);
    expect(state.embedded.contexts).toEqual([]);
  });

  test('uncollected supplemental evidence is visible as not assessed', async ({ page }) => {
    await openDashTab(page, 'compliance');
    await expect(page.locator('.comp-assessment-gaps')).toContainText('Not assessed');
    await expect(page.locator('.comp-assessment-gaps')).toContainText('defenderPlans');
    const findings = await page.evaluate(() => AppRenderContext.createRenderContext().complianceFindings.map(f => f.id));
    expect(findings).not.toContain('PCI-IDS');
    expect(findings).not.toContain('PCI-REVIEW');
    expect(findings).not.toContain('SOC2-MONITOR');
    await openDashTab(page, 'reports');
    const html = await captureHTMLReport(page);
    expect(html).toContain('Not assessed (data unavailable)');
  });
});

test('pending merge sidebar fills cannot overwrite a subsequent native upload', async ({ page }) => {
  // Hold idle work until a later upload completes, making the race deterministic.
  // Rendering still runs through the browser's real animation frames and callbacks.
  await page.addInitScript(() => {
    window.__reviewIdleQueue = [];
    let nextId = 1;
    window.requestIdleCallback = callback => {
      const id = nextId++;
      window.__reviewIdleQueue.push({ id, callback });
      return id;
    };
    window.cancelIdleCallback = id => {
      window.__reviewIdleQueue = window.__reviewIdleQueue.filter(task => task.id !== id);
    };
  });
  await loadDemo(page);
  await expect(page.locator('#mergeExitBtn')).toBeVisible();
  await uploadJSON(page, 'role-assignments.json', [OWNER_ASSIGNMENT]);
  await expect(page.locator('#loadingOverlay')).toBeHidden();
  await expect(page.locator('#in_rbac')).toHaveValue(JSON.stringify([OWNER_ASSIGNMENT]));
  const drained = await page.evaluate(() => {
    let count = 0;
    while(window.__reviewIdleQueue.length && count < 500){
      window.__reviewIdleQueue.shift().callback({ didTimeout: false, timeRemaining: () => 50 });
      count++;
    }
    return { count, remaining: window.__reviewIdleQueue.length };
  });
  expect(drained.count).toBeGreaterThan(0);
  expect(drained.remaining).toBe(0);
  await expect(page.locator('#in_rbac')).toHaveValue(JSON.stringify([OWNER_ASSIGNMENT]));
  await page.locator('#renderBtn').click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().complianceFindings
    .some(f => f.control === 'RBAC-1' && f.resourceId.endsWith('/owner-grant') && f._subscriptionId === 'native-sub'))).toBe(true);
});
