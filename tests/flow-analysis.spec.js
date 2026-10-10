const { test, expect } = require('@playwright/test');
const { loadDemo, captureErrors } = require('./helpers');

test.describe('Flow Analysis', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
  });

  test('flow analysis renders banner, overlay, and dashboard without console errors', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await page.evaluate(() => enterFlowAnalysis());
      await page.locator('#flowAnalysisBanner').waitFor({ state: 'visible' });
      await page.locator('#detailPanel.open .flow-panel').waitFor({ state: 'visible' });
      await page.locator('#faDashBtn').click();
      await page.locator('#faDashOverlay').waitFor({ state: 'visible' });
    });

    expect(errors).toEqual([]);
    await expect(page.locator('#flowAnalysisBanner')).toBeVisible();
    await expect(page.locator('.main')).toHaveClass(/flow-active/);
    await expect(page.locator('#faDashOverlay')).toBeVisible();
    await expect(page.locator('#faDashTableWrap table')).toBeVisible();
  });

  test('flow context menu stays inside the viewport', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await page.evaluate(() => {
        const node = document.querySelector('.subnet-node');
        if (!node) return;
        node.dispatchEvent(new MouseEvent('contextmenu', {
          bubbles: true,
          cancelable: true,
          clientX: 100000,
          clientY: 100000,
        }));
      });
      await page.locator('#flowContextMenu').waitFor({ state: 'visible' });
    });

    expect(errors).toEqual([]);
    const menuBox = await page.locator('#flowContextMenu').boundingBox();
    const viewport = page.viewportSize();
    expect(menuBox).not.toBeNull();
    expect(viewport).not.toBeNull();
    expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(viewport.width + 1);
    expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(viewport.height + 1);
  });
});
