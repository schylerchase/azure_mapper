const { test, expect } = require('@playwright/test');
const { loadDemo, captureErrors } = require('./helpers');

test.describe('Dependency Graph', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
  });

  test('dependency overlay and blast radius use Azure-native runtime data without console errors', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      const resourceId = await page.evaluate(() => {
        const ctx = AppRenderContext.createRenderContext().rlCtx;
        const vnet = (ctx.vnets || [])[0];
        const id = vnet && (vnet.VpcId || vnet.id);
        if (id) showDependencies(id);
        return id || null;
      });

      expect(resourceId).not.toBeNull();
      await page.locator('#depOverlay.open').waitFor({ state: 'visible', timeout: 5000 });
      await expect(page.locator('#depBody .dep-node[data-id]').first()).toBeVisible();

      await page.locator('#depBlastBtn').click();
      await expect(page.locator('#depOverlay')).not.toHaveClass(/open/);
      await page.locator('.blast-dimmed').first().waitFor({ state: 'attached', timeout: 5000 });

      await page.evaluate(() => _clearBlastRadius());
      await expect(page.locator('.blast-dimmed')).toHaveCount(0);
    });

    expect(errors).toEqual([]);
  });
});
