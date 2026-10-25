const { test, expect } = require('@playwright/test');
const { loadDemo, captureErrors } = require('./helpers');

test.describe('Storage account topology', () => {
  test('demo maps storage accounts into subnet topology and summary cards', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await loadDemo(page);
    });
    expect(errors).toEqual([]);

    await page.locator('#btnExpand').click();
    await page.locator('.res-node').first().waitFor({ state: 'attached', timeout: 5000 });

    const result = await page.evaluate(() => {
      const storageSection = document.querySelector('.s3-section');
      const subnetWithStorage = Array.from(document.querySelectorAll('.subnet-node'))
        .find(node => Array.from(node.querySelectorAll('text')).some(t => t.textContent === 'STG'));
      if (subnetWithStorage) {
        subnetWithStorage.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      }
      return {
        hasStorageSection: !!storageSection,
        storageSectionText: storageSection ? storageSection.textContent : '',
        storageNodeCount: Array.from(document.querySelectorAll('.res-node text'))
          .filter(t => t.textContent === 'STG').length,
        pillAlignment: Array.from(document.querySelectorAll('.s3-section .storage-pill')).map(pill => {
          const rect = pill.querySelector('rect');
          const text = pill.querySelector('text');
          if (!rect || !text) return null;
          const rb = rect.getBoundingClientRect();
          const tb = text.getBoundingClientRect();
          return {
            baseline: text.getAttribute('dominant-baseline'),
            delta: Math.abs((rb.top + rb.height / 2) - (tb.top + tb.height / 2)),
          };
        }).filter(Boolean),
      };
    });

    expect(result.hasStorageSection).toBe(true);
    expect(result.storageSectionText).toContain('private/VNet');
    expect(result.storageSectionText).toMatch(/BLOB|FILE|QUEUE|TABLE/);
    expect(result.storageNodeCount).toBeGreaterThan(0);
    expect(result.pillAlignment.length).toBeGreaterThan(0);
    expect(result.pillAlignment.every(p => p.baseline === 'central')).toBe(true);
    expect(Math.max(...result.pillAlignment.map(p => p.delta))).toBeLessThanOrEqual(3);
    await expect(page.locator('#detailPanel.open')).toBeVisible();
    await expect(page.locator('#detailPanel')).toContainText('Storage Accounts');
  });
});
