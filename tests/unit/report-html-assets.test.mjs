import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const assetSource = readFileSync('src/modules/report-html-assets.js', 'utf8');
const sectionSource = readFileSync('src/modules/report-render-functions.js', 'utf8');

describe('report HTML asset owner boundary', () => {
  it('keeps exported report CSS, table controls, and style serialization in report-html-assets.js', () => {
    const expected = [
      'function _rptCSS(',
      'function _rptInteractiveCSS(',
      'function _rptInteractiveJS(',
      'function _rptBuildToolbar(',
      'function _rptBuildSvgUri(',
      'function _rptCollectStyles('
    ];

    for (const token of expected) {
      assert.equal(assetSource.includes(token), true, `report-html-assets.js should contain ${token}`);
    }
  });

  it('does not mix report section rendering or export generation into the asset owner', () => {
    const forbidden = [
      'function _rptExecSummary(',
      'function _rptCompliance(',
      'function _rptInventory(',
      'function _rptActionPlan(',
      'async function _generateReport(',
      'async function _generateDocx(',
      'async function _generateXlsx(',
      'function _rptBuildXlsx'
    ];

    for (const token of forbidden) {
      assert.equal(assetSource.includes(token), false, `report-html-assets.js should not contain ${token}`);
    }
  });

  it('keeps report section renderers free of HTML asset scaffolding', () => {
    const forbidden = [
      'function _rptCSS(',
      'function _rptInteractiveCSS(',
      'function _rptInteractiveJS(',
      'function _rptBuildToolbar(',
      'function _rptCollectStyles('
    ];

    for (const token of forbidden) {
      assert.equal(sectionSource.includes(token), false, `report-render-functions.js should not contain ${token}`);
    }
  });

  it('keeps the report section renderer under the large-file threshold', () => {
    assert.ok(sectionSource.split(/\r?\n/).length < 1200, 'report-render-functions.js should stay below 1200 lines');
  });

  it('keeps exported report interactions browser-neutral', () => {
    assert.equal(assetSource.includes('window.'), false, 'report-html-assets.js should not hard-code exported report interactions to window');
    assert.equal(assetSource.includes('globalThis.addEventListener("scroll"'), true, 'back-to-top scroll listener should use the generated report global object');
  });
});
