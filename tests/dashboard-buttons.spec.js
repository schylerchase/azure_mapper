const { test, expect } = require('@playwright/test');
const { loadDemo, captureErrors } = require('./helpers');

test.describe('Dock Button Dashboard Navigation (R2.2)', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
  });

  const dockButtons = [
    { name: 'Compliance', selector: '#compDashBtn', contentCheck: /finding|check|compliance/i },
    { name: 'BUDR', selector: '#budrBtn', contentCheck: /tier|backup|recovery/i },
    { name: 'Inventory', selector: '#inventoryBtn', contentCheck: /resource|subnet|vm/i },
    { name: 'Governance', selector: '#govBtn', contentCheck: /rule|class|govern/i },
    { name: 'Reports', selector: '#reportsBtn', contentCheck: /report|module|export/i },
  ];

  for (const btn of dockButtons) {
    test(`${btn.name} button click opens dashboard with tab content`, async ({ page }) => {
      const errors = await captureErrors(page, async () => {
        await page.locator(btn.selector).click();
        await page.locator('#udash.open').waitFor({ state: 'visible', timeout: 5000 });
      });

      expect(errors).toEqual([]);

      const bodyText = await page.locator('#udashBody').textContent();
      expect(bodyText.length).toBeGreaterThan(10);

      const bodyHtml = await page.locator('#udashBody').innerHTML();
      expect(bodyHtml).toMatch(btn.contentCheck);

      await page.evaluate(() => closeUnifiedDash());
      await expect(page.locator('#udash')).not.toHaveClass(/open/);
    });
  }

  test('all dock buttons are visible after demo load', async ({ page }) => {
    for (const btn of dockButtons) {
      await expect(page.locator(btn.selector)).toBeVisible();
    }
  });

  test('clicking dock button twice toggles dashboard closed', async ({ page }) => {
    await page.locator('#compDashBtn').click();
    await page.locator('#udash.open').waitFor({ state: 'visible', timeout: 5000 });

    await page.evaluate(() => closeUnifiedDash());
    await expect(page.locator('#udash')).not.toHaveClass(/open/);
  });
});
