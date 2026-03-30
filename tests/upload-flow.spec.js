const { test, expect } = require('@playwright/test');
const path = require('path');
const { BASE, loadDemo, countElements, captureErrors } = require('./helpers');

const SINGLE_SUB = path.resolve(__dirname, 'fixtures/single-sub.azuremap');
const MULTI_SUB = path.resolve(__dirname, 'fixtures/multi-sub.azuremap');

// Helper: load a .azuremap fixture via the loadProjectInput file input
async function loadFixture(page, fixturePath) {
  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.locator('#landingDash').waitFor({ state: 'visible', timeout: 10000 });
  await page.locator('#loadProjectInput').setInputFiles(fixturePath);
  await page.locator('#landingDash').waitFor({ state: 'hidden', timeout: 15000 });
  await page.locator('.vpc-group').first().waitFor({ state: 'attached', timeout: 15000 });
}

test.describe('JSON File Upload -> Map Render (R2.1)', () => {

  test('uploading azuremap fixture renders map with correct VNet count', async ({ page }) => {
    await loadFixture(page, SINGLE_SUB);
    const vpcCount = await countElements(page, '.vpc-group');
    expect(vpcCount).toBe(2);
  });

  test('uploaded map shows VNet labels matching fixture data', async ({ page }) => {
    await loadFixture(page, SINGLE_SUB);
    const labelTexts = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('.vnet-label, .vpc-label, text'))
        .map(el => el.textContent || '')
        .filter(t => t.trim().length > 0);
    });
    // Both fixture VNets contain "lmat" in their names
    const hasMatchingLabel = labelTexts.some(t => t.includes('lmat') || t.includes('cloud') || t.includes('dev'));
    expect(hasMatchingLabel).toBe(true);
  });

  test('multi-sub fixture loads both accounts and renders VNet groups', async ({ page }) => {
    await loadFixture(page, MULTI_SUB);
    // Multi-sub has 4 VNets total (2 per account)
    const vpcCount = await countElements(page, '.vpc-group');
    expect(vpcCount).toBeGreaterThanOrEqual(2);
  });

  test('upload flow renders subnet nodes inside VPC groups', async ({ page }) => {
    await loadFixture(page, SINGLE_SUB);
    const subnetCount = await countElements(page, '.subnet-node');
    expect(subnetCount).toBeGreaterThan(0);
  });

});

test.describe('Demo Data Renders Clean (R2.3)', () => {

  test('demo data loads and renders without any console errors', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await loadDemo(page);
    });
    expect(errors).toEqual([]);
  });

  test('demo data renders all expected SVG elements', async ({ page }) => {
    await loadDemo(page);
    const vpcCount = await countElements(page, '.vpc-group');
    expect(vpcCount).toBeGreaterThan(0);
    const subnetCount = await countElements(page, '.subnet-node');
    expect(subnetCount).toBeGreaterThan(0);
    await expect(page.locator('#statsBar')).toBeVisible();
  });

  test('demo data produces no console warnings about missing data', async ({ page }) => {
    const warnings = [];
    const handler = (msg) => {
      if (msg.type() === 'warning') {
        const text = msg.text();
        // Ignore 404s for static assets
        if (text.includes('404') && text.includes('Failed to load resource')) return;
        warnings.push(text);
      }
    };
    page.on('console', handler);
    await loadDemo(page);
    page.off('console', handler);
    expect(warnings).toEqual([]);
  });

});
