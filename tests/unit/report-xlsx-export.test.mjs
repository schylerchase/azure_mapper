import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const builderSource = readFileSync('src/modules/report-builder.js', 'utf8');
const xlsxSource = readFileSync('src/modules/report-xlsx-export.js', 'utf8');

describe('report XLSX export owner boundary', () => {
  it('keeps XLSX workbook loading, builders, and exports in report-xlsx-export.js', () => {
    const expected = [
      'function _loadSheetJS(',
      'const _XLSX_COLORS=',
      'function _xlsxAddSheet(',
      'function _rptBuildXlsxSummary(',
      'function _rptBuildXlsxCompliance(',
      'function _rptBuildXlsxBUDR(',
      'function _rptBuildXlsxInventory(',
      'function _rptBuildXlsxActionPlan(',
      'function _rptBuildXlsxAppSummary(',
      'function _rptBuildXlsxIAMReview(',
      'function _rptBuildXlsxClassification(',
      'function _rptBuildXlsxFirewall(',
      'async function _xlsxPostProcess(',
      'async function _exportComplianceXlsx(',
      'async function _exportFullXlsx(',
      'async function _generateXlsx('
    ];

    for (const token of expected) {
      assert.equal(xlsxSource.includes(token), true, `report-xlsx-export.js should contain ${token}`);
    }
  });

  it('does not mix dashboard, HTML, CSV, or DOCX ownership into the XLSX owner', () => {
    const forbidden = [
      'function openReportBuilder(',
      'function _renderReportsTab(',
      'function _renderRptPicker(',
      'function _renderRptPreview(',
      'async function _generateReport(',
      'function _exportFullHTML(',
      'function _exportFullCSV(',
      'async function _generateDocx(',
      'function _docxBuildBody('
    ];

    for (const token of forbidden) {
      assert.equal(xlsxSource.includes(token), false, `report-xlsx-export.js should not contain ${token}`);
    }
  });

  it('keeps report-builder.js free of XLSX workbook ownership', () => {
    const forbidden = [
      'function _loadSheetJS(',
      'function _xlsxAddSheet(',
      'function _rptBuildXlsx',
      'async function _exportFullXlsx(',
      'async function _generateXlsx('
    ];

    for (const token of forbidden) {
      assert.equal(builderSource.includes(token), false, `report-builder.js should not contain ${token}`);
    }
  });

  it('keeps both report export owners under the large-file threshold', () => {
    assert.ok(builderSource.split(/\r?\n/).length < 1200, 'report-builder.js should stay below 1200 lines');
    assert.ok(xlsxSource.split(/\r?\n/).length < 1200, 'report-xlsx-export.js should stay below 1200 lines');
  });

  it('keeps report export owners on explicit adapters instead of bridge globals', () => {
    const forbidden = /_rlCtx|_complianceFindings|_showToast|downloadBlob|window\./;
    assert.equal(forbidden.test(builderSource), false, 'report-builder.js should use report export adapters');
    assert.equal(forbidden.test(xlsxSource), false, 'report-xlsx-export.js should use report XLSX adapters');
    assert.equal(builderSource.includes('function reportExportRuntime('), true);
    assert.equal(builderSource.includes('function reportSaveBlob('), true);
    assert.equal(xlsxSource.includes('function reportXlsxRuntime('), true);
    assert.equal(xlsxSource.includes('function reportSheetJS('), true);
  });
});
