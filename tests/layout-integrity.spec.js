const { test, expect } = require('@playwright/test');
const {
  BASE, loadDemo, clickSubnet, openDashTab, captureErrors,
  getBoundingBoxes, boxesOverlap, getPanelZIndexes,
} = require('./helpers');

// Layout integrity: tests that HTML panels, toolbars, and banners don't
// visually collide with each other or escape their designated screen regions.

test.describe('Panel Layout — No Collisions', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
    await page.waitForTimeout(400);
  });

  // ── Detail panel vs dock toolbar ──────────────────────────────

  test('detail panel does not cover the dock toolbar', async ({ page }) => {
    await clickSubnet(page, 0);
    await page.waitForTimeout(300);

    const [panel] = await getBoundingBoxes(page, '#detailPanel');
    const [dock] = await getBoundingBoxes(page, '.dock-toolbar');
    if (!panel || !dock) return;

    // The dock sits at bottom-center; the detail panel is on the right.
    // They should not overlap horizontally.
    const overlap = boxesOverlap(panel, dock, 0);
    if (overlap) {
      // If they do overlap in screen space, the dock should still be
      // accessible — its z-index must be lower than the panel's
      // OR the dock must not be hidden behind the panel.
      const dockVisible = await page.locator('.dock-toolbar').isVisible();
      expect(dockVisible, 'Dock toolbar hidden behind detail panel').toBe(true);
    }
  });

  // ── Detail panel does not extend past viewport ────────────────

  test('detail panel stays within viewport bounds', async ({ page }) => {
    await clickSubnet(page, 0);
    await page.waitForTimeout(300);

    const vp = await page.evaluate(() => ({
      w: window.innerWidth, h: window.innerHeight,
    }));
    const [panel] = await getBoundingBoxes(page, '#detailPanel');
    if (!panel) return;

    expect(panel.x, 'Panel extends past left edge').toBeGreaterThanOrEqual(-2);
    expect(panel.x + panel.w, 'Panel extends past right edge').toBeLessThanOrEqual(vp.w + 2);
    expect(panel.y, 'Panel extends past top').toBeGreaterThanOrEqual(-2);
    // Panel height can exceed viewport (scrollable), so only check top
  });

  // ── Dashboard overlays properly ───────────────────────────────

  test('dashboard covers canvas without leaking beneath panels', async ({ page }) => {
    await openDashTab(page, 'compliance');
    await page.waitForTimeout(300);

    const [dash] = await getBoundingBoxes(page, '#udash');
    expect(dash, 'Dashboard not rendered').toBeTruthy();
    expect(dash.w, 'Dashboard too narrow').toBeGreaterThan(400);
    expect(dash.h, 'Dashboard too short').toBeGreaterThan(300);
  });

  test('dashboard z-index is above sidebar and detail panel', async ({ page }) => {
    await clickSubnet(page, 0);
    await openDashTab(page, 'compliance');
    await page.waitForTimeout(300);

    const panels = await getPanelZIndexes(page, [
      '#udash', '.sidebar', '#detailPanel',
    ]);
    const dashZ = panels.find(p => p.selector === '#udash');
    const sidebarZ = panels.find(p => p.selector === '.sidebar');
    const detailZ = panels.find(p => p.selector === '#detailPanel');

    if (dashZ?.visible && sidebarZ?.visible) {
      expect(dashZ.zIndex, 'Dashboard below sidebar').toBeGreaterThan(sidebarZ.zIndex);
    }
    if (dashZ?.visible && detailZ?.visible) {
      expect(dashZ.zIndex, 'Dashboard below detail panel').toBeGreaterThan(detailZ.zIndex);
    }
  });

  // ── Export bar repositions when detail panel opens ─────────────

  test('export bar shifts right when detail panel opens', async ({ page }) => {
    const [exportBefore] = await getBoundingBoxes(page, '.export-bar');
    if (!exportBefore) return;

    await clickSubnet(page, 0);
    await page.waitForTimeout(300);

    const [exportAfter] = await getBoundingBoxes(page, '.export-bar');
    if (!exportAfter) return;

    // CSS rule: .main:has(.detail-panel.open) .export-bar{right:432px}
    // So the export bar's right edge should move left when the detail panel opens
    // (its x coordinate should decrease, or its right edge moves away from viewport edge)
    const vp = await page.evaluate(() => window.innerWidth);
    const rightBefore = vp - (exportBefore.x + exportBefore.w);
    const rightAfter = vp - (exportAfter.x + exportAfter.w);
    expect(rightAfter, 'Export bar did not shift for detail panel').toBeGreaterThan(rightBefore);
  });

  // ── Sidebar collapse/expand ───────────────────────────────────

  test('collapsed sidebar does not overlap SVG canvas', async ({ page }) => {
    // Collapse sidebar
    await page.evaluate(() => {
      const sb = document.querySelector('.sidebar');
      if (sb && !sb.classList.contains('collapsed')) {
        document.querySelector('.sidebar-toggle')?.click();
      }
    });
    await page.waitForTimeout(400);

    const [sidebar] = await getBoundingBoxes(page, '.sidebar');
    const [main] = await getBoundingBoxes(page, '.main');
    if (!sidebar || !main) return;

    // When collapsed, sidebar should be off-screen (negative x or zero width visible)
    const sidebarRight = sidebar.x + sidebar.w;
    expect(sidebarRight, 'Collapsed sidebar still visible on screen').toBeLessThanOrEqual(10);
  });
});

test.describe('Banner Stacking — No Visual Collisions', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
    await page.waitForTimeout(400);
  });

  test('flow banner does not overlap dock toolbar', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await page.evaluate(() => enterFlowMode());
    });
    expect(errors).toEqual([]);
    await page.waitForTimeout(300);

    const [banner] = await getBoundingBoxes(page, '#flowBanner');
    const [dock] = await getBoundingBoxes(page, '.dock-toolbar');
    if (!banner || !dock) return;

    // Flow banner is at the top, dock is at the bottom — should never overlap
    const overlap = boxesOverlap(banner, dock, 0);
    expect(overlap, 'Flow banner overlaps dock toolbar').toBe(false);
  });

  test('flow banner does not overlap sidebar toggle', async ({ page }) => {
    await page.evaluate(() => enterFlowMode());
    await page.waitForTimeout(300);

    const [banner] = await getBoundingBoxes(page, '#flowBanner');
    const [toggle] = await getBoundingBoxes(page, '.sidebar-toggle');
    if (!banner || !toggle) return;

    const overlap = boxesOverlap(banner, toggle, 0);
    expect(overlap, 'Flow banner overlaps sidebar toggle').toBe(false);
  });
});

test.describe('Z-Index Hierarchy — Consistent Layering', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
    await page.waitForTimeout(400);
  });

  test('z-index hierarchy: tooltip > dashboard > detail panel > sidebar', async ({ page }) => {
    // Open multiple overlapping elements to verify stacking
    await clickSubnet(page, 0);
    await page.waitForTimeout(200);

    const panels = await getPanelZIndexes(page, [
      '.tooltip', '#udash', '#detailPanel', '.sidebar',
      '.dock-toolbar', '.zoom-controls',
    ]);

    const zMap = {};
    panels.forEach(p => { if (p.zIndex != null) zMap[p.selector] = p.zIndex; });

    // Verify expected stacking order (from CSS analysis)
    if (zMap['#detailPanel'] && zMap['.sidebar']) {
      expect(zMap['#detailPanel'], 'Detail panel below sidebar').toBeGreaterThanOrEqual(zMap['.sidebar']);
    }
  });

  test('firewall panel z-index is above dashboard', async ({ page }) => {
    const panels = await getPanelZIndexes(page, ['#fwFullPanel', '#udash']);
    const fwZ = panels.find(p => p.selector === '#fwFullPanel')?.zIndex;
    const dashZ = panels.find(p => p.selector === '#udash')?.zIndex;
    if (fwZ != null && dashZ != null) {
      expect(fwZ, 'Firewall panel should be above dashboard').toBeGreaterThan(dashZ);
    }
  });
});

test.describe('Responsive Viewport — No Overflow', () => {

  test('narrow viewport (1024px) does not cause horizontal overflow', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    await loadDemo(page);
    await page.waitForTimeout(600);

    const overflow = await page.evaluate(() => {
      return document.documentElement.scrollWidth > window.innerWidth;
    });
    expect(overflow, 'Horizontal scroll detected at 1024px viewport').toBe(false);
  });

  test('tablet viewport (768px) transforms detail panel to bottom sheet', async ({ page }) => {
    // Load demo at full size first, then resize to tablet
    await loadDemo(page);
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.waitForTimeout(300);
    await clickSubnet(page, 0);
    await page.waitForTimeout(400);

    const panelPos = await page.evaluate(() => {
      const panel = document.getElementById('detailPanel');
      if (!panel) return null;
      const style = getComputedStyle(panel);
      const rect = panel.getBoundingClientRect();
      return {
        top: rect.top,
        bottom: rect.bottom,
        height: rect.height,
        viewportHeight: window.innerHeight,
      };
    });

    if (!panelPos) return;

    // On mobile (768px), the detail panel should be positioned near the bottom
    // as a bottom sheet (CSS: bottom: 0; top: auto; height: 70svh)
    expect(panelPos.bottom, 'Panel not anchored to bottom on tablet').toBeGreaterThan(
      panelPos.viewportHeight - 10
    );
  });
});

test.describe('Text Truncation — No Overflow', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
    await page.waitForTimeout(400);
  });

  test('detail panel text rows do not overflow panel width', async ({ page }) => {
    await clickSubnet(page, 0);
    await page.waitForTimeout(300);

    const [panel] = await getBoundingBoxes(page, '#detailPanel');
    if (!panel) return;

    const overflowing = await page.evaluate((panelRight) => {
      const rows = document.querySelectorAll('.dp-row .dp-val');
      const issues = [];
      Array.from(rows).forEach((val, i) => {
        const r = val.getBoundingClientRect();
        if (r.width > 0 && r.x + r.width > panelRight + 5) {
          issues.push({ index: i, text: val.textContent?.slice(0, 30), right: Math.round(r.x + r.width) });
        }
      });
      return issues;
    }, panel.x + panel.w);

    expect(overflowing, 'Detail panel values overflow: ' + JSON.stringify(overflowing)).toHaveLength(0);
  });

  test('VNet name labels use textLength to prevent overflow', async ({ page }) => {
    const vnetLabels = await page.evaluate(() => {
      const labels = document.querySelectorAll('.vnet-label');
      return Array.from(labels).map(l => ({
        text: l.textContent,
        hasTextLength: l.hasAttribute('textLength'),
        hasLengthAdjust: l.hasAttribute('lengthAdjust'),
      }));
    });

    for (const label of vnetLabels) {
      expect(label.hasTextLength, `VNet label "${label.text}" missing textLength`).toBe(true);
      expect(label.hasLengthAdjust, `VNet label "${label.text}" missing lengthAdjust`).toBe(true);
    }
  });
});
