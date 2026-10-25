import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const dashboardSource = readFileSync('src/modules/report-dashboard.js', 'utf8');
const builderSource = readFileSync('src/modules/report-builder.js', 'utf8');
const xlsxSource = readFileSync('src/modules/report-xlsx-export.js', 'utf8');

describe('report dashboard owner boundary', () => {
  it('keeps dashboard UI in report-dashboard.js', () => {
    const expected = [
      'function openReportBuilder(',
      'function _renderReportsTab(',
      'function _renderRptPicker(',
      'function _renderRptPreview(',
      'function _rptInitInteractive(',
      'function _rptEnabledModules(',
      'function _rptUpdateFooterStats(',
      'function _updateLogoPreview(',
      'function reportDashboardRuntimeContext(',
      'function reportDashboardRuntimeData(',
      'function reportDashboardComplianceRows(',
      'function reportDashboardNotify('
    ];

    for (const token of expected) {
      assert.equal(dashboardSource.includes(token), true, `report-dashboard.js should contain ${token}`);
    }
  });

  it('does not define export generators in the dashboard owner', () => {
    const forbidden = [
      'async function _generateReport(',
      'async function _generateXlsx(',
      'async function _generateDocx(',
      'function _rptBuildXlsx',
      'function _docxBuildBody(',
      '_rlCtx',
      '_complianceFindings',
      '_showToast',
      'downloadBlob',
      'window.'
    ];

    for (const token of forbidden) {
      assert.equal(dashboardSource.includes(token), false, `report-dashboard.js should not contain ${token}`);
    }
  });

  it('keeps HTML and DOCX export generation in report-builder.js without dashboard entry points', () => {
    assert.equal(builderSource.includes('async function _generateReport('), true);
    assert.equal(builderSource.includes('async function _generateDocx('), true);
    assert.equal(builderSource.includes('async function _generateXlsx('), false);
    assert.equal(builderSource.includes('function _rptBuildXlsx'), false);
    assert.equal(builderSource.includes('function openReportBuilder('), false);
    assert.equal(builderSource.includes('function _renderReportsTab('), false);
    assert.equal(builderSource.includes('function _renderRptPicker('), false);
    assert.equal(builderSource.includes('function _renderRptPreview('), false);
  });

  it('keeps XLSX workbook generation in report-xlsx-export.js without dashboard entry points', () => {
    assert.equal(xlsxSource.includes('async function _generateXlsx('), true);
    assert.equal(xlsxSource.includes('async function _exportFullXlsx('), true);
    assert.equal(xlsxSource.includes('function _rptBuildXlsxSummary('), true);
    assert.equal(xlsxSource.includes('function openReportBuilder('), false);
    assert.equal(xlsxSource.includes('function _renderReportsTab('), false);
    assert.equal(xlsxSource.includes('async function _generateDocx('), false);
  });
});
