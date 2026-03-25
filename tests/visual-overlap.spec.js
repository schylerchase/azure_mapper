const { test, expect } = require('@playwright/test');
const {
  loadDemo, captureErrors,
  getBoundingBoxes, findOverlaps, getTextBounds, isContainedIn,
} = require('./helpers');

// SVG topology visual regression: detect overlapping elements, colliding text,
// and layout violations that the screenshot-based tests in visual.spec.js
// would miss (pixel diffs don't distinguish "intentional overlap" from bugs).

test.describe('SVG Topology — No Overlaps', () => {
  test.beforeEach(async ({ page }) => {
    await loadDemo(page);
    // Let D3 layout fully stabilize (debounced render + rAF)
    await page.waitForTimeout(600);
  });

  // ── VNet bounding boxes ───────────────────────────────────────

  test('VNet groups do not overlap each other', async ({ page }) => {
    const boxes = await getBoundingBoxes(page, '.vpc-group > rect');
    expect(boxes.length).toBeGreaterThanOrEqual(2);

    const overlaps = findOverlaps(boxes, 4); // 4px tolerance for anti-aliased strokes
    expect(overlaps, formatOverlaps('VNet', overlaps)).toHaveLength(0);
  });

  test('VNet groups have reasonable dimensions', async ({ page }) => {
    // Use the main VNet border rect (first rect child, which has width/height attrs)
    const boxes = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('.vpc-group')).map((g, i) => {
        const r = g.querySelector('rect[width]');
        if (!r) return null;
        const w = parseFloat(r.getAttribute('width'));
        const h = parseFloat(r.getAttribute('height'));
        return { index: i, w, h };
      }).filter(b => b !== null);
    });
    for (const b of boxes) {
      expect(b.w, `VNet ${b.index} width`).toBeGreaterThan(100);
      expect(b.h, `VNet ${b.index} height`).toBeGreaterThan(40);
    }
  });

  // ── Subnet nodes within VNets ─────────────────────────────────

  test('subnet nodes do not overlap within their parent VNet', async ({ page }) => {
    // Group subnets by their parent VNet
    const subnetsByVnet = await page.evaluate(() => {
      const groups = {};
      document.querySelectorAll('.vpc-group').forEach((vg, vi) => {
        const subs = vg.querySelectorAll('.subnet-node');
        const rects = Array.from(subs).map((s, si) => {
          const r = s.getBoundingClientRect();
          return {
            index: si,
            id: s.getAttribute('data-subnet-id') || '',
            x: Math.round(r.x), y: Math.round(r.y),
            w: Math.round(r.width), h: Math.round(r.height),
          };
        }).filter(b => b.w > 0 && b.h > 0);
        if (rects.length > 0) groups[`vnet-${vi}`] = rects;
      });
      return groups;
    });

    for (const [vnet, subs] of Object.entries(subnetsByVnet)) {
      const overlaps = findOverlaps(subs, 2);
      expect(overlaps, formatOverlaps(`Subnets in ${vnet}`, overlaps)).toHaveLength(0);
    }
  });

  test('all subnet nodes are contained within their parent VNet rect', async ({ page }) => {
    const violations = await page.evaluate(() => {
      const issues = [];
      document.querySelectorAll('.vpc-group').forEach((vg, vi) => {
        const vnetRect = vg.querySelector('rect');
        if (!vnetRect) return;
        const vr = vnetRect.getBoundingClientRect();
        const parent = { x: vr.x, y: vr.y, w: vr.width, h: vr.height };

        vg.querySelectorAll('.subnet-node').forEach((sn, si) => {
          const sr = sn.getBoundingClientRect();
          const child = { x: sr.x, y: sr.y, w: sr.width, h: sr.height };
          // 4px tolerance for borders
          if (child.x < parent.x - 4 || child.y < parent.y - 4 ||
              child.x + child.w > parent.x + parent.w + 4 ||
              child.y + child.h > parent.y + parent.h + 4) {
            issues.push({ vnet: vi, subnet: si, subnetId: sn.getAttribute('data-subnet-id') });
          }
        });
      });
      return issues;
    });
    expect(violations, 'Subnets escaping their parent VNet: ' + JSON.stringify(violations)).toHaveLength(0);
  });

  // ── Gateway circles ───────────────────────────────────────────

  test('gateway circles do not overlap each other', async ({ page }) => {
    // Test the circle elements directly (not the full <g> which includes labels)
    const boxes = await getBoundingBoxes(page, '.gw-node circle');
    if (boxes.length < 2) return;
    const overlaps = findOverlaps(boxes, 2);
    expect(overlaps, formatOverlaps('Gateway circle', overlaps)).toHaveLength(0);
  });

  test('shared gateway labels do not overlap each other', async ({ page }) => {
    const boxes = await getBoundingBoxes(page, '.gw-node .gw-label-bg');
    if (boxes.length < 2) return;
    const overlaps = findOverlaps(boxes, 1);
    expect(overlaps, formatOverlaps('Gateway label', overlaps)).toHaveLength(0);
  });

  test('gateway labels do not overlap gateway circles', async ({ page }) => {
    const gwCircles = await getBoundingBoxes(page, '.gw-node circle');
    const gwLabels = await getBoundingBoxes(page, '.gw-label-bg');
    if (gwCircles.length === 0 || gwLabels.length === 0) return;

    // Labels should be positioned below or beside circles, not on top
    const overlaps = [];
    for (const label of gwLabels) {
      for (const circle of gwCircles) {
        // Allow overlap only if the label belongs to this gateway (vertically close)
        const verticalDist = Math.abs((label.y + label.h / 2) - (circle.y + circle.h / 2));
        if (verticalDist < 5) continue; // same gateway's label — expected proximity

        if (label.x < circle.x + circle.w && label.x + label.w > circle.x &&
            label.y < circle.y + circle.h && label.y + label.h > circle.y) {
          overlaps.push({ label, circle });
        }
      }
    }
    expect(overlaps, 'Gateway labels overlapping unrelated circles').toHaveLength(0);
  });

  // ── SVG text collisions ───────────────────────────────────────

  test('VNet labels do not overlap each other', async ({ page }) => {
    const labels = await getTextBounds(page, '#mapSvg');
    const vnetLabels = labels.filter(l => l.class.includes('vnet-label'));
    if (vnetLabels.length < 2) return;

    const overlaps = findOverlaps(vnetLabels, 2);
    expect(overlaps, formatTextOverlaps('VNet label', overlaps)).toHaveLength(0);
  });

  test('subnet labels do not overlap each other within a VNet', async ({ page }) => {
    const allLabels = await page.evaluate(() => {
      const result = {};
      document.querySelectorAll('.vpc-group').forEach((vg, vi) => {
        const texts = vg.querySelectorAll('.subnet-label');
        const bounds = Array.from(texts).map((t, i) => {
          const r = t.getBoundingClientRect();
          return {
            index: i, text: t.textContent?.slice(0, 30) || '',
            x: Math.round(r.x), y: Math.round(r.y),
            w: Math.round(r.width), h: Math.round(r.height),
          };
        }).filter(b => b.w > 0 && b.h > 0);
        if (bounds.length > 1) result[`vnet-${vi}`] = bounds;
      });
      return result;
    });

    for (const [vnet, labels] of Object.entries(allLabels)) {
      const overlaps = findOverlaps(labels, 1);
      expect(overlaps, formatTextOverlaps(`Subnet labels in ${vnet}`, overlaps)).toHaveLength(0);
    }
  });

  test('route labels do not overlap each other', async ({ page }) => {
    const labels = await getBoundingBoxes(page, '.route-label-bg');
    if (labels.length < 2) return;

    const overlaps = findOverlaps(labels, 1);
    expect(overlaps, formatOverlaps('Route label', overlaps)).toHaveLength(0);
  });

  test('peering labels do not overlap VNet rects', async ({ page }) => {
    const peeringLabels = await getBoundingBoxes(page, '.peering-label-g');
    const vnets = await getBoundingBoxes(page, '.vpc-group > rect');
    if (peeringLabels.length === 0 || vnets.length === 0) return;

    const overlaps = [];
    for (const pl of peeringLabels) {
      for (const vn of vnets) {
        // Peering labels sit between VNets on the connecting line
        // They should NOT overlap the VNet rects themselves
        if (pl.x < vn.x + vn.w - 4 && pl.x + pl.w > vn.x + 4 &&
            pl.y < vn.y + vn.h - 4 && pl.y + pl.h > vn.y + 4) {
          overlaps.push({ label: pl, vnet: vn });
        }
      }
    }
    expect(overlaps, 'Peering labels overlapping VNet rects').toHaveLength(0);
  });

  // ── Region labels ─────────────────────────────────────────────

  test('region labels do not overlap VNet headers', async ({ page }) => {
    const regionLabels = await getBoundingBoxes(page, '.region-label');
    const vnetLabels = await getTextBounds(page, '#mapSvg');
    const vnetTitles = vnetLabels.filter(l => l.class.includes('vnet-label'));

    if (regionLabels.length === 0 || vnetTitles.length === 0) return;

    const overlaps = [];
    for (const rl of regionLabels) {
      for (const vt of vnetTitles) {
        if (rl.x < vt.x + vt.w && rl.x + rl.w > vt.x &&
            rl.y < vt.y + vt.h && rl.y + rl.h > vt.y) {
          overlaps.push({ region: rl, vnetTitle: vt });
        }
      }
    }
    expect(overlaps, 'Region labels overlapping VNet headers').toHaveLength(0);
  });

  // ── Layout mode transitions ───────────────────────────────────

  test('executive layout has no VNet overlaps', async ({ page }) => {
    await page.evaluate(() => {
      const sel = document.getElementById('layoutMode');
      if (sel) { sel.value = 'executive'; sel.dispatchEvent(new Event('change')); }
    });
    await page.waitForTimeout(1500);

    const boxes = await getBoundingBoxes(page, '.vpc-group > rect');
    if (boxes.length < 2) return;
    const overlaps = findOverlaps(boxes, 4);
    expect(overlaps, formatOverlaps('Executive VNet', overlaps)).toHaveLength(0);
  });

  test('landing zone layout has no VNet overlaps', async ({ page }) => {
    await page.evaluate(() => {
      const sel = document.getElementById('layoutMode');
      if (sel) { sel.value = 'landing-zone'; sel.dispatchEvent(new Event('change')); }
    });
    await page.waitForTimeout(1500);

    const boxes = await getBoundingBoxes(page, '.vpc-group > rect');
    if (boxes.length < 2) return;
    const overlaps = findOverlaps(boxes, 4);
    expect(overlaps, formatOverlaps('Landing zone VNet', overlaps)).toHaveLength(0);
  });

  // ── Resource icons inside subnets ─────────────────────────────

  test('resource icons stay within subnet bounds', async ({ page }) => {
    const violations = await page.evaluate(() => {
      const issues = [];
      document.querySelectorAll('.subnet-node').forEach((sn, si) => {
        const sr = sn.getBoundingClientRect();
        sn.querySelectorAll('.res-icon').forEach((ri, ri_i) => {
          const rr = ri.getBoundingClientRect();
          if (rr.width === 0 || rr.height === 0) return;
          if (rr.x < sr.x - 2 || rr.y < sr.y - 2 ||
              rr.x + rr.width > sr.x + sr.width + 2 ||
              rr.y + rr.height > sr.y + sr.height + 2) {
            issues.push({ subnet: si, resource: ri_i });
          }
        });
      });
      return issues;
    });
    expect(violations, 'Resources escaping subnet bounds').toHaveLength(0);
  });

  // ── No zero-size rendered elements ────────────────────────────

  test('no zero-dimension SVG rects in topology', async ({ page }) => {
    const zeroRects = await page.evaluate(() => {
      const issues = [];
      document.querySelectorAll('#mapSvg rect').forEach((r, i) => {
        const w = parseFloat(r.getAttribute('width'));
        const h = parseFloat(r.getAttribute('height'));
        if ((w === 0 || h === 0) && r.getAttribute('class') !== 'alphaClamp') {
          issues.push({ index: i, class: r.getAttribute('class'), width: w, height: h });
        }
      });
      return issues;
    });
    expect(zeroRects, 'Zero-dimension rects found: ' + JSON.stringify(zeroRects)).toHaveLength(0);
  });
});

// ── Formatting helpers ──────────────────────────────────────────

function formatOverlaps(label, overlaps) {
  if (overlaps.length === 0) return '';
  return `${label} overlaps found:\n` + overlaps.map(o =>
    `  [${o.a.index}] (${o.a.x},${o.a.y} ${o.a.w}x${o.a.h}) ↔ [${o.b.index}] (${o.b.x},${o.b.y} ${o.b.w}x${o.b.h})`
  ).join('\n');
}

function formatTextOverlaps(label, overlaps) {
  if (overlaps.length === 0) return '';
  return `${label} text overlaps:\n` + overlaps.map(o =>
    `  "${o.a.text}" ↔ "${o.b.text}"`
  ).join('\n');
}
