const { test, expect } = require('@playwright/test');
const { loadDemo, openDashTab, captureErrors } = require('./helpers');

test.describe('Export Functions', () => {
  async function interceptReportSave(page) {
    await page.evaluate(() => {
      window._testLastBlob = null;
      window._origReportSaveBlob = window.AppDownloads.saveBlob;
      window.AppDownloads.saveBlob = function(blob, name) {
        window._testLastBlob = { size: blob.size, name: name, type: blob.type };
      };
    });
  }

  async function restoreReportSave(page) {
    await page.evaluate(() => {
      window.AppDownloads.saveBlob = window._origReportSaveBlob;
    });
  }

  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
    // Open reports tab to make export buttons available
    await openDashTab(page, 'reports');
  });

  async function expectIacPreview(page, buttonSelector, scopeLabel) {
    if (await page.locator('#udashClose').isVisible()) {
      await page.locator('#udashClose').click();
    }

    await page.locator('#ebToggle').click();
    await expect(page.locator(buttonSelector)).toBeVisible();
    await page.locator(buttonSelector).click();
    await expect(page.locator('#iacModal')).toHaveClass(/open/);
    if (scopeLabel) await page.locator('#iacScope').selectOption({ label: scopeLabel });
    await page.locator('#iacGenerate').click();
    await expect(page.locator('#iacPreview pre')).toBeVisible({ timeout: 15000 });

    const preview = await page.locator('#iacPreview').innerText();
    expect(preview).not.toContain('No data loaded');
    expect(preview.length).toBeGreaterThan(100);

    if (scopeLabel) {
      await page.locator('#iacScope').selectOption('all');
      await page.locator('#iacGenerate').click();
      await expect(page.locator('#iacPreview .iac-empty')).toContainText('Export blocked');
      await expect(page.locator('#iacPreview .iac-warn')).toContainText(buttonSelector === '#expTerraform' ? 'one subscription at a time' : 'one subscription/resource group');
      await expect(page.locator('#iacPreview pre')).toHaveCount(0);
    }

    await page.locator('#iacClose').click();
    await expect(page.locator('#iacModal')).not.toHaveClass(/open/);
  }

  test('IaC Terraform preview generates without runtime bridge errors', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await expectIacPreview(page, '#expTerraform', 'vnet-dev');
    });

    expect(errors).toEqual([]);
  });

  test('IaC Bicep preview lazy-loads generator without runtime bridge errors', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await expectIacPreview(page, '#expBicep', 'vnet-dev');
    });

    expect(errors).toEqual([]);
  });

  test('Lucid map export uses the download adapter', async ({ page }) => {
    if (await page.locator('#udashClose').isVisible()) {
      await page.locator('#udashClose').click();
    }

    await interceptReportSave(page);

    const errors = await captureErrors(page, async () => {
      await page.locator('#ebToggle').click();
      await expect(page.locator('#expLucidDl')).toBeVisible();
      await page.locator('#expLucidDl').click();
      await page.waitForFunction(() => window._testLastBlob !== null, { timeout: 20000 });
    });

    expect(errors).toEqual([]);

    const blob = await page.evaluate(() => window._testLastBlob);
    expect(blob).not.toBeNull();
    expect(blob.name).toContain('.lucid');
    expect(blob.size).toBeGreaterThan(1000);

    await restoreReportSave(page);
  });

  test('report builder shows all three export buttons', async ({ page }) => {
    await expect(page.locator('#rptExportHTML')).toBeVisible();
    await expect(page.locator('#rptExportXLSX')).toBeVisible();
    await expect(page.locator('#rptExportDOCX')).toBeVisible();
  });

  test('report builder has module toggles', async ({ page }) => {
    // Should have report module cards in the body
    const body = await page.locator('#udashBody').innerHTML();
    // Module IDs from the codebase
    const expectedModules = ['summary', 'compliance', 'budr', 'inventory'];
    for (const mod of expectedModules) {
      expect(body).toContain(mod);
    }
  });

  test('HTML report generates without errors', async ({ page }) => {
    // Enable all modules and ensure at least one is available
    const hasEnabled = await page.evaluate(() => _rptEnabledModules().length > 0);
    if (!hasEnabled) return;

    // Intercept the named download adapter to prevent file dialog.
    await interceptReportSave(page);

    const errors = await captureErrors(page, async () => {
      await page.locator('#rptExportHTML').click();
      // Wait for generation to complete
      await page.waitForFunction(
        () => document.getElementById('rptExportHTML').textContent !== 'Generating...',
        { timeout: 15000 }
      );
    });

    expect(errors).toEqual([]);

    // Verify a blob was produced
    const blob = await page.evaluate(() => window._testLastBlob);
    expect(blob).not.toBeNull();
    expect(blob.size).toBeGreaterThan(100);

    // Restore original
    await restoreReportSave(page);
  });

  test('XLSX export generates without errors', async ({ page }) => {
    const hasEnabled = await page.evaluate(() => _rptEnabledModules().length > 0);
    if (!hasEnabled) return;

    await interceptReportSave(page);

    const errors = await captureErrors(page, async () => {
      await page.locator('#rptExportXLSX').click();
      await page.waitForFunction(
        () => {
          var btn = document.getElementById('rptExportXLSX');
          return btn.textContent !== 'Loading...' && btn.textContent !== 'Generating...';
        },
        { timeout: 30000 }
      );
    });

    expect(errors).toEqual([]);
    const blob = await page.evaluate(() => window._testLastBlob);
    expect(blob).not.toBeNull();
    expect(blob.size).toBeGreaterThan(1000);

    await restoreReportSave(page);
  });

  test('DOCX export (executive tone) generates without errors', async ({ page }) => {
    const hasEnabled = await page.evaluate(() => _rptEnabledModules().length > 0);
    if (!hasEnabled) return;

    await interceptReportSave(page);

    // Set tone to executive
    await page.selectOption('#rptDocxTone', 'executive');

    const errors = await captureErrors(page, async () => {
      await page.locator('#rptExportDOCX').click();
      await page.waitForFunction(
        () => {
          var btn = document.getElementById('rptExportDOCX');
          return btn.textContent !== 'Generating...';
        },
        { timeout: 20000 }
      );
    });

    expect(errors).toEqual([]);
    const blob = await page.evaluate(() => window._testLastBlob);
    expect(blob).not.toBeNull();
    expect(blob.size).toBeGreaterThan(1000);
    expect(blob.name).toContain('.docx');

    await restoreReportSave(page);
  });

  test('DOCX export (technical tone) generates without errors', async ({ page }) => {
    const hasEnabled = await page.evaluate(() => _rptEnabledModules().length > 0);
    if (!hasEnabled) return;

    await interceptReportSave(page);

    await page.selectOption('#rptDocxTone', 'technical');

    const errors = await captureErrors(page, async () => {
      await page.locator('#rptExportDOCX').click();
      await page.waitForFunction(
        () => {
          var btn = document.getElementById('rptExportDOCX');
          return btn.textContent !== 'Generating...';
        },
        { timeout: 30000 }
      );
    });

    expect(errors).toEqual([]);
    const blob = await page.evaluate(() => window._testLastBlob);
    expect(blob).not.toBeNull();
    // Technical should be larger than executive
    expect(blob.size).toBeGreaterThan(5000);

    await restoreReportSave(page);
  });
});
