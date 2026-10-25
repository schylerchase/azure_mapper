const { test, expect } = require('@playwright/test');
const { loadDemo, clickSubnet, captureErrors } = require('./helpers');

test.describe('Detail Panel (Subnet)', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
  });

  test('clicking a subnet opens the detail panel', async ({ page }) => {
    const errors = await captureErrors(page, async () => {
      await clickSubnet(page, 0);
    });
    expect(errors).toEqual([]);
    await expect(page.locator('#detailPanel')).toHaveClass(/open/);
  });

  test('detail panel shows subnet title', async ({ page }) => {
    await clickSubnet(page, 0);
    const title = await page.locator('#dpTitle').textContent();
    expect(title.length).toBeGreaterThan(3);
  });

  test('detail panel has collapsible sections', async ({ page }) => {
    await clickSubnet(page, 0);
    const sections = await page.locator('.dp-sec-hdr').count();
    expect(sections).toBeGreaterThan(0);
  });

  test('detail panel opens as side panel (not fullscreen)', async ({ page }) => {
    await clickSubnet(page, 0);
    await expect(page.locator('#detailPanel')).toHaveClass(/open/);
    await expect(page.locator('#detailPanel')).not.toHaveClass(/fullscreen/);
  });

  test('fullscreen toggle works', async ({ page }) => {
    await clickSubnet(page, 0);
    await expect(page.locator('#detailPanel')).not.toHaveClass(/fullscreen/);

    // Click fullscreen toggle to enter fullscreen
    await page.locator('#dpFullscreen').dispatchEvent('click');
    await expect(page.locator('#detailPanel')).toHaveClass(/fullscreen/);

    // Click again to exit
    await page.locator('#dpFullscreen').dispatchEvent('click');
    await expect(page.locator('#detailPanel')).not.toHaveClass(/fullscreen/);
  });

  test('closing detail panel removes open class', async ({ page }) => {
    await clickSubnet(page, 0);
    await page.locator('#dpClose').click();
    await expect(page.locator('#detailPanel')).not.toHaveClass(/open/);
  });

  test('clicking different subnets updates panel content', async ({ page }) => {
    const subnetCount = await page.evaluate(() =>
      document.querySelectorAll('.subnet-node').length
    );
    if (subnetCount < 2) return;

    await clickSubnet(page, 0);
    const title1 = await page.locator('#dpTitle').textContent();

    // Close and open different subnet
    await page.locator('#dpClose').click();
    await page.locator('#detailPanel').waitFor({ state: 'hidden', timeout: 3000 }).catch(() => {});
    await clickSubnet(page, 1);
    const title2 = await page.locator('#dpTitle').textContent();

    expect(title1).not.toEqual(title2);
  });

  test('search result opens detail panel through resource navigation owner', async ({ page }) => {
    const target = await page.evaluate(() => {
      const ctx = typeof _rlCtx !== 'undefined' ? _rlCtx : window._rlCtx;
      const subnet = (ctx && ctx.subnets || [])[0];
      if (!subnet) return null;
      const id = subnet.id || subnet.SubnetId;
      return {
        id,
        query: subnet.name || subnet.SubnetId || (id || '').split('/').pop(),
      };
    });
    expect(target).not.toBeNull();

    const errors = await captureErrors(page, async () => {
      await page.evaluate(() => SearchPanel.open());
      await page.locator('#searchInput').fill(target.query);
      await page.locator('#searchResults > div').first().waitFor({ state: 'visible', timeout: 5000 });
      await page.locator('#searchResults > div').first().click();
      await page.locator('#detailPanel.open').waitFor({ state: 'visible', timeout: 5000 });
    });

    expect(errors).toEqual([]);
    await expect(page.locator('#searchOverlay')).toBeHidden();
    await expect(page.locator('#detailPanel')).toHaveClass(/open/);
  });

  test('map viewport resolves selector-hostile resource ids by resource id', async ({ page }) => {
    const result = await page.evaluate(() => {
      const nav = AppRenderContext.createRenderContext();
      const mapG = nav.mapG;
      if (!mapG || !mapG.node) return { zoomed: false, flashed: false };

      const id = 'subnet-"quoted"\\west]';
      const node = mapG.append('g')
        .attr('class', 'subnet-node test-selector-hostile')
        .attr('data-subnet-id', id);
      node.append('rect')
        .attr('x', 25)
        .attr('y', 25)
        .attr('width', 40)
        .attr('height', 30)
        .attr('stroke', '#000');

      try {
        const zoomed = MapViewport.zoomToResource(id, { duration: 0, highlight: false });
        const flashed = MapViewport.flashResource(id);
        return {
          zoomed: !!(zoomed && zoomed.element && zoomed.element.getAttribute('data-subnet-id') === id),
          flashed
        };
      } finally {
        node.remove();
      }
    });

    expect(result).toEqual({ zoomed: true, flashed: true });
  });

  test('resource list go-to uses the map viewport resource interface', async ({ page }) => {
    await page.evaluate(() => {
      window.__zoomedResources = [];
      const originalZoomToResource = MapViewport.zoomToResource.bind(MapViewport);
      MapViewport.zoomToResource = function(id, options) {
        window.__zoomedResources.push(String(id));
        return originalZoomToResource(id, options);
      };
      openResourceList('Subnets');
    });

    const navButton = page.locator('.dp-nav-btn[data-nav]').first();
    await navButton.waitFor({ state: 'visible', timeout: 5000 });
    const navId = await navButton.getAttribute('data-nav-id');
    expect(navId).toBeTruthy();

    await navButton.click();

    await expect.poll(() => page.evaluate(() => window.__zoomedResources || [])).toContain(navId);
  });

  test('section collapse/expand toggles without crashing', async ({ page }) => {
    await clickSubnet(page, 0);
    const headerCount = await page.locator('.dp-sec-hdr').count();
    if (headerCount === 0) return;

    // Click first section header to toggle
    await page.locator('.dp-sec-hdr').first().click();
    // Panel should still be open (no crash)
    await expect(page.locator('#detailPanel')).toHaveClass(/open/);
  });
});
