import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const createDesktopAzureAdapter = require('../../src/modules/desktop-azure-adapter.js');
const adapterSource = readFileSync('src/modules/desktop-azure-adapter.js', 'utf8');

describe('DesktopAzureAdapter', () => {
  it('stays focused on Electron API access instead of app workflow state', () => {
    assert.doesNotMatch(adapterSource, /document\./);
    assert.doesNotMatch(adapterSource, /_rlCtx/);
    assert.doesNotMatch(adapterSource, /_showToast/);
    assert.doesNotMatch(adapterSource, /AppNotifications/);
    assert.doesNotMatch(adapterSource, /renderMap/);
    assert.doesNotMatch(adapterSource, /importFolder/);
    assert.doesNotMatch(adapterSource, /saveProject/);
  });

  it('reports unavailable and returns safe fallbacks without Electron', async () => {
    const adapter = createDesktopAzureAdapter({});

    assert.equal(adapter.isAvailable(), false);
    assert.deepEqual(await adapter.scanAzure({ subscription: 'sub-1' }), {
      success: false,
      error: 'Desktop scan is not available'
    });
    assert.equal(await adapter.openFolder(), null);
    assert.deepEqual(await adapter.exportBUDRXlsx('{}'), {
      error: 'Desktop XLSX export is not available'
    });
    assert.equal(adapter.subscribe('onScanProgress', () => {}), null);
  });

  it('delegates scan, export, folder, update, and subscription calls to electronAPI', async () => {
    const calls = [];
    const unsubscribe = () => {};
    const adapter = createDesktopAzureAdapter({
      electronAPI: {
        scanAzure: options => {
          calls.push(['scanAzure', options]);
          return Promise.resolve({ success: true });
        },
        abortScan: () => calls.push(['abortScan']),
        openFolder: () => {
          calls.push(['openFolder']);
          return Promise.resolve({ files: {} });
        },
        exportBUDRXlsx: jsonText => {
          calls.push(['exportBUDRXlsx', jsonText]);
          return Promise.resolve({ path: 'budr.xlsx' });
        },
        downloadUpdate: () => calls.push(['downloadUpdate']),
        installUpdate: () => calls.push(['installUpdate']),
        onScanProgress: callback => {
          calls.push(['onScanProgress', callback]);
          return unsubscribe;
        }
      }
    });

    assert.equal(adapter.isAvailable(), true);
    assert.deepEqual(await adapter.scanAzure({ subscription: 'sub-1' }), { success: true });
    adapter.abortScan();
    assert.deepEqual(await adapter.openFolder(), { files: {} });
    assert.deepEqual(await adapter.exportBUDRXlsx('{"ok":true}'), { path: 'budr.xlsx' });
    adapter.downloadUpdate();
    adapter.installUpdate();
    assert.equal(adapter.subscribe('onScanProgress', () => {}), unsubscribe);

    assert.deepEqual(calls.map(call => call[0]), [
      'scanAzure',
      'abortScan',
      'openFolder',
      'exportBUDRXlsx',
      'downloadUpdate',
      'installUpdate',
      'onScanProgress'
    ]);
    assert.deepEqual(calls[0][1], { subscription: 'sub-1' });
    assert.deepEqual(calls[3][1], '{"ok":true}');
  });
});
