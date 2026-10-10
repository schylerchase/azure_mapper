const { test, expect } = require('@playwright/test');
const { loadDemo, clickSubnet, captureErrors } = require('./helpers');

test.describe('Design Mode', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
  });

  test('subnet toolbar opens add-resource form without transient window globals', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await page.evaluate(() => enterDesignMode());
      await clickSubnet(page, 0);

      const detailPanel = page.locator('#detailPanel.open');
      await expect(detailPanel.locator('.design-toolbar')).toBeVisible();
      await detailPanel.locator('.design-toolbar button', { hasText: '+ Resource' }).click();

      await expect(detailPanel.locator('#df_resname')).toBeVisible();
      await detailPanel.locator('#df_resname').fill('design-test-vm');
      await detailPanel.locator('#df_ok').click();
    });

    expect(errors).toEqual([]);
    await expect.poll(() => page.evaluate(() => _designChanges.length)).toBe(1);
    await expect(page.locator('#changeLog')).toBeVisible();
    await expect.poll(() => page.evaluate(() => typeof window._dtCtx)).toBe('undefined');
  });
});
