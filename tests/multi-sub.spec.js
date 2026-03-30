const { test, expect } = require('@playwright/test');
const path = require('path');
const { loadDemo, captureErrors } = require('./helpers');

const FIXTURE = path.resolve(__dirname, 'fixtures/multi-sub.azuremap');

/**
 * Load multi-subscription data via the hidden file input (#addAccountInput).
 * Waits for account cards to appear in #accountPanelBody.
 */
async function loadMultiSub(page) {
  await page.locator('#addAccountInput').setInputFiles(FIXTURE);
  // Wait for _renderAccountPanel() to populate account cards
  await page.locator('#accountPanelBody .account-card').first().waitFor({ state: 'attached', timeout: 10000 });
}

test.describe('Multi-Subscription Import (R2.4)', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
  });

  test('loading multi-sub file adds two account context cards', async ({ page }) => {
    await loadMultiSub(page);

    const cardCount = await page.locator('#accountPanelBody .account-card').count();
    expect(cardCount).toBeGreaterThanOrEqual(2);
  });

  test('account panel shows separate cards with correct labels', async ({ page }) => {
    await loadMultiSub(page);

    // Open the account panel
    await page.evaluate(() => openAccountPanel());
    await page.locator('#accountPanel.open').waitFor({ state: 'visible', timeout: 5000 });

    const cards = page.locator('#accountPanelBody .account-card');
    const cardCount = await cards.count();
    expect(cardCount).toBeGreaterThanOrEqual(2);

    const panelText = await page.locator('#accountPanelBody').textContent();
    expect(panelText).toMatch(/Production/i);
    expect(panelText).toMatch(/Development/i);
  });

  test('merge view renders VNets from both subscriptions', async ({ page }) => {
    await loadMultiSub(page);

    const errors = await captureErrors(page, async () => {
      await page.evaluate(() => enterMultiView());
      // Wait for merge banner to appear
      await page.locator('#mergeBanner').waitFor({ state: 'visible', timeout: 10000 });
      // Wait for VNet groups to render
      await page.locator('.vpc-group').first().waitFor({ state: 'attached', timeout: 15000 });
    });

    expect(errors).toEqual([]);

    const vnetCount = await page.locator('.vpc-group').count();
    // Each subscription has 2 VNets = 4 total in merged view
    expect(vnetCount).toBeGreaterThanOrEqual(2);

    // Merge banner should be visible
    await expect(page.locator('#mergeBanner')).toBeVisible();
  });

  test('merge view shows no console errors', async ({ page }) => {
    await loadMultiSub(page);

    const errors = await captureErrors(page, async () => {
      await page.evaluate(() => enterMultiView());
      await page.locator('#mergeBanner').waitFor({ state: 'visible', timeout: 10000 });
      await page.locator('.vpc-group').first().waitFor({ state: 'attached', timeout: 15000 });
    });

    expect(errors).toEqual([]);
  });

  test('exiting merge view hides the merge banner', async ({ page }) => {
    await loadMultiSub(page);

    await page.evaluate(() => enterMultiView());
    await page.locator('#mergeBanner').waitFor({ state: 'visible', timeout: 10000 });

    await page.evaluate(() => exitMultiView());
    await page.locator('#mergeBanner').waitFor({ state: 'hidden', timeout: 5000 });

    await expect(page.locator('#mergeBanner')).not.toBeVisible();
  });
});
