const { test, expect } = require('@playwright/test');
const { loadDemo } = require('./helpers');

test.describe('Readability', () => {
  test('core theme text colors meet contrast targets on dark surfaces', async ({ page }) => {
    await loadDemo(page);

    const results = await page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const colors = {
        primary: root.getPropertyValue('--text-primary').trim(),
        secondary: root.getPropertyValue('--text-secondary').trim(),
        muted: root.getPropertyValue('--text-muted').trim(),
        panel: root.getPropertyValue('--panel-bg').trim(),
        bg: root.getPropertyValue('--bg-primary').trim(),
      };

      function parseColor(value) {
        const probe = document.createElement('span');
        probe.style.color = value;
        document.body.appendChild(probe);
        const rgb = getComputedStyle(probe).color;
        probe.remove();
        const nums = rgb.match(/[\d.]+/g).map(Number);
        return nums.slice(0, 3);
      }

      function relLum(rgb) {
        const c = rgb.map(v => {
          v /= 255;
          return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        });
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
      }

      function contrast(a, b) {
        const l1 = relLum(parseColor(a));
        const l2 = relLum(parseColor(b));
        return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      }

      return {
        secondaryOnBg: contrast(colors.secondary, colors.bg),
        mutedOnBg: contrast(colors.muted, colors.bg),
        mutedOnPanel: contrast(colors.muted, colors.panel),
      };
    });

    expect(results.secondaryOnBg).toBeGreaterThanOrEqual(4.5);
    expect(results.mutedOnBg).toBeGreaterThanOrEqual(4.5);
    expect(results.mutedOnPanel).toBeGreaterThanOrEqual(4.5);
  });

  test('map annotation labels render at readable size and weight', async ({ page }) => {
    await loadDemo(page);

    const labels = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('.route-label-g text, .peering-label-g text')).map(t => {
        const style = getComputedStyle(t);
        return {
          text: t.textContent,
          size: parseFloat(style.fontSize),
          weight: parseInt(style.fontWeight, 10),
          fill: t.getAttribute('fill') || style.fill,
        };
      });
    });

    expect(labels.length).toBeGreaterThan(0);
    for (const label of labels) {
      expect(label.size, label.text).toBeGreaterThanOrEqual(9);
      expect(label.weight, label.text).toBeGreaterThanOrEqual(700);
      expect(label.fill, label.text).not.toBe('var(--text-muted)');
    }
  });
});
