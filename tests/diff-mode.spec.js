const { test, expect } = require('@playwright/test');
const { loadDemo, captureErrors } = require('./helpers');

async function enterMutatedDiffMode(page) {
  return page.evaluate(() => {
    const ctx = AppRenderContext.createRenderContext().rlCtx;
    const baseline = structuredClone(ctx);
    baseline._srcName = 'baseline';
    if (!baseline.vnets || !baseline.vnets.length) {
      throw new Error('demo data did not expose vnets for diff comparison');
    }
    baseline.vnets[0].CidrBlock = '10.250.0.0/16';
    enterDiffMode(baseline);
    return {
      added: _diffResults.total.added,
      removed: _diffResults.total.removed,
      modified: _diffResults.total.modified,
    };
  });
}

test.describe('Diff Mode', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
  });

  test('snapshot comparison opens banner and dashboard without console errors', async ({ page }) => {
    let totals;
    const errors = await captureErrors(page, async () => {
      totals = await enterMutatedDiffMode(page);
      await page.locator('#diffBanner').waitFor({ state: 'visible' });
      await page.locator('#diffDash.open').waitFor({ state: 'visible' });
    });

    expect(errors).toEqual([]);
    expect(totals.modified).toBeGreaterThan(0);
    await expect(page.locator('#diffBanner')).toBeVisible();
    await expect(page.locator('.main')).toHaveClass(/diff-active/);
    await expect(page.locator('#diffDash')).toHaveClass(/open/);
    await expect(page.locator('#diffDashBody table')).toBeVisible();
  });

  test('diff detail opens from the compare dashboard', async ({ page }) => {
    await enterMutatedDiffMode(page);
    await page.locator('#diffDash.open').waitFor({ state: 'visible' });
    await page.locator('.dd-detail-btn').first().click();
    await expect(page.locator('#detailPanel.open')).toBeVisible();
    await expect(page.locator('.dp-diff-badge')).toBeVisible();
  });
});
