const { expect } = require('@playwright/test');

const BASE = 'http://localhost:8377/index.html';

/**
 * Navigate to the app and load demo data.
 * Waits for the landing page to disappear and SVG VPC groups to render.
 */
async function loadDemo(page) {
  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.locator('#landingDash').waitFor({ state: 'visible', timeout: 10000 });
  await page.locator('#loadDemo').click();
  await page.locator('#landingDash').waitFor({ state: 'hidden', timeout: 15000 });
  await page.locator('.vpc-group').first().waitFor({ state: 'attached', timeout: 15000 });
  return page;
}

/**
 * Count elements matching a selector.
 */
async function countElements(page, selector) {
  return page.locator(selector).count();
}

/**
 * Open the unified dashboard to a specific tab.
 */
async function openDashTab(page, tabId) {
  await page.evaluate((id) => openUnifiedDash(id), tabId);
  await page.locator('#udash.open').waitFor({ state: 'visible', timeout: 5000 });
}

/**
 * Click a subnet node in the SVG by dispatching a click event.
 * Playwright can't natively click SVG <g> elements, so we use evaluate.
 * Returns the subnet ID that was clicked.
 */
async function clickSubnet(page, index = 0) {
  const subnetId = await page.evaluate((idx) => {
    const nodes = document.querySelectorAll('.subnet-node');
    if (!nodes[idx]) return null;
    nodes[idx].dispatchEvent(new MouseEvent('click', { bubbles: true }));
    return nodes[idx].getAttribute('data-subnet-id');
  }, index);
  // Wait for detail panel to open
  if (subnetId) {
    await page.locator('#detailPanel.open').waitFor({ state: 'visible', timeout: 5000 });
  }
  return subnetId;
}

/**
 * Get all console errors during a callback.
 * Filters out 404 errors for static assets (favicon, logo, etc.)
 */
async function captureErrors(page, fn) {
  const errors = [];
  const handler = (msg) => {
    if (msg.type() === 'error') {
      const text = msg.text();
      // Ignore 404s for static assets — expected when serving locally
      if (text.includes('404') && text.includes('Failed to load resource')) return;
      errors.push(text);
    }
  };
  page.on('console', handler);
  await fn();
  page.off('console', handler);
  return errors;
}

// ── Visual regression helpers ──────────────────────────────────────

/**
 * Get bounding boxes for all elements matching a selector (in SVG or DOM).
 * Uses getBoundingClientRect for DOM elements and getBBox + CTM for SVG.
 */
async function getBoundingBoxes(page, selector) {
  return page.evaluate((sel) => {
    const els = document.querySelectorAll(sel);
    return Array.from(els).map((el, i) => {
      const rect = el.getBoundingClientRect();
      return {
        index: i,
        id: el.id || el.getAttribute('data-subnet-id') || el.getAttribute('data-vnet-id') || '',
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        w: Math.round(rect.width),
        h: Math.round(rect.height),
      };
    }).filter(b => b.w > 0 && b.h > 0);
  }, selector);
}

/**
 * Check whether two bounding boxes overlap (with optional margin tolerance).
 * Returns true if a and b overlap by more than margin pixels.
 */
function boxesOverlap(a, b, margin = 0) {
  return (
    a.x < b.x + b.w - margin &&
    a.x + a.w > b.x + margin &&
    a.y < b.y + b.h - margin &&
    a.y + a.h > b.y + margin
  );
}

/**
 * Find all overlapping pairs in an array of bounding boxes.
 * Returns array of { a, b } pairs that overlap beyond the given margin.
 */
function findOverlaps(boxes, margin = 0) {
  const overlaps = [];
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      if (boxesOverlap(boxes[i], boxes[j], margin)) {
        overlaps.push({ a: boxes[i], b: boxes[j] });
      }
    }
  }
  return overlaps;
}

/**
 * Get bounding boxes of SVG <text> elements within a parent selector.
 * Returns screen-space rects using getBoundingClientRect on the text nodes.
 */
async function getTextBounds(page, parentSelector) {
  return page.evaluate((sel) => {
    const parent = sel ? document.querySelector(sel) : document;
    if (!parent) return [];
    const texts = parent.querySelectorAll('text');
    return Array.from(texts).map((t, i) => {
      const rect = t.getBoundingClientRect();
      return {
        index: i,
        text: t.textContent?.slice(0, 40) || '',
        class: t.getAttribute('class') || '',
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        w: Math.round(rect.width),
        h: Math.round(rect.height),
      };
    }).filter(b => b.w > 0 && b.h > 0);
  }, parentSelector);
}

/**
 * Check that a child element is fully contained within a parent element.
 */
function isContainedIn(child, parent, tolerance = 2) {
  return (
    child.x >= parent.x - tolerance &&
    child.y >= parent.y - tolerance &&
    child.x + child.w <= parent.x + parent.w + tolerance &&
    child.y + child.h <= parent.y + parent.h + tolerance
  );
}

/**
 * Get computed z-index for visible panel elements.
 */
async function getPanelZIndexes(page, selectors) {
  return page.evaluate((sels) => {
    return sels.map(sel => {
      const el = document.querySelector(sel);
      if (!el) return { selector: sel, visible: false, zIndex: null };
      const style = getComputedStyle(el);
      const visible = style.display !== 'none' && style.visibility !== 'hidden';
      return {
        selector: sel,
        visible,
        zIndex: parseInt(style.zIndex) || 0,
        rect: (() => {
          const r = el.getBoundingClientRect();
          return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
        })(),
      };
    });
  }, selectors);
}

module.exports = {
  BASE, loadDemo, countElements, openDashTab, clickSubnet, captureErrors,
  getBoundingBoxes, boxesOverlap, findOverlaps, getTextBounds, isContainedIn, getPanelZIndexes,
};
