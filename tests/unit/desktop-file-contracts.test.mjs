import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

const require = createRequire(import.meta.url);
const { scanPaths } = require('../../main-utils.js');
const source = file => fs.readFileSync(file, 'utf8');

function desktopFixture({ canceled = false, writeError = null } = {}) {
  const handlers = {}, writes = [], dialogs = [];
  const selectedPath = path.join(os.tmpdir(), 'selected-project.azuremap');
  let api;
  const electron = {
    app: { whenReady: () => ({ then() {} }), on() {} },
    ipcMain: { handle: (name, callback) => { handlers[name] = callback; }, on() {} },
    dialog: { showSaveDialog: async (_window, options) => {
      dialogs.push(options);
      return { canceled, filePath: canceled ? undefined : selectedPath };
    } },
    Menu: {}, session: {}, BrowserWindow: function () {},
    contextBridge: { exposeInMainWorld: (_name, value) => { api = value; } },
    ipcRenderer: { invoke: (name, payload) => Promise.resolve(handlers[name](null, payload)), on() {}, send() {}, removeListener() {} }
  };
  vm.runInNewContext(source('main.js'), {
    require: name => name === 'electron' ? electron : name === 'fs' ? { ...fs,
      writeFileSync(file, data) { if (writeError) throw new Error(writeError); writes.push({ file, data }); }
    } : require(name.startsWith('./') ? '../../' + name.slice(2) : name),
    process, Buffer, console, __dirname: process.cwd(), setTimeout() {}
  });
  vm.runInNewContext(source('preload.js'), { require: () => electron });
  const window = { electronAPI: api };
  vm.runInNewContext(source('src/modules/project-file-access.js'), { window, Promise, Blob });
  return { files: window.AppProjectFiles, api, writes, dialogs, handlers, selectedPath };
}

describe('Desktop project file contracts', () => {
  it('reads only the two canonical bundled export scripts through native IPC', async () => {
    const fixture = desktopFixture();
    for (const name of ['export-azure-data.sh', 'export-azure-data.ps1']) {
      assert.equal(await fixture.api.readExportScript(name), source(name));
    }
    await assert.rejects(fixture.handlers['file:read-export-script'](null, '../package.json'), /Invalid export script name/);
    await assert.rejects(fixture.handlers['file:read-export-script'](null, 'package.json'), /Invalid export script name/);
  });
  it('selects an absolute path, saves successfully, and reuses that path', async () => {
    const fixture = desktopFixture();
    assert.equal(await fixture.files.saveText('{}', 'my-project.azuremap'), fixture.selectedPath);
    assert.equal(await fixture.files.saveText('{"edited":true}', 'my-project.azuremap'), fixture.selectedPath);
    assert.equal(fixture.dialogs.length, 1);
    assert.equal(fixture.dialogs[0].defaultPath, 'my-project.azuremap');
    assert.deepEqual(fixture.writes, [
      { file: fixture.selectedPath, data: '{}' }, { file: fixture.selectedPath, data: '{"edited":true}' }
    ]);
  });

  it('cancels without a write and surfaces native write errors', async () => {
    const canceled = desktopFixture({ canceled: true });
    assert.equal(await canceled.files.saveText('{}', 'project.azuremap'), null);
    assert.equal(canceled.writes.length, 0);
    const failure = desktopFixture({ writeError: 'Disk unavailable' });
    await assert.rejects(failure.files.saveText('{}', 'project.azuremap'), /Disk unavailable/);
  });

  it('uses the exact explicit Save As path without another dialog', async () => {
    const fixture = desktopFixture();
    const target = path.join(os.tmpdir(), 'another-project.azuremap');
    assert.equal(await fixture.files.saveText('{}', 'ignored.azuremap', 'application/json', target), target);
    assert.equal(fixture.writes[0].file, target);
    assert.equal(fixture.dialogs.length, 0);
  });

  it('connects native Save As, project open, and folder import events to renderer actions', () => {
    const subscriptions = {}, saved = [], loaded = [], paths = [], imported = [];
    const elements = new Map();
    const context = {
      _isElectron: true,
      DesktopAzureAdapter: { subscribe(name, callback) { subscriptions[name] = callback; } },
      saveProject: value => saved.push(value), _loadProjectData: value => loaded.push(value),
      AppProjectFiles: { setNativePath: value => paths.push(value) },
      importFolder: value => imported.push(value), AppNotifications: { show() {} },
      document: { getElementById(id) {
        if (!elements.has(id)) elements.set(id, { style: {}, addEventListener() {}, click() {} });
        return elements.get(id);
      } }
    };
    vm.runInNewContext(source('src/modules/electron-azure-actions.js'), context);
    subscriptions.onMenuSave();
    subscriptions.onMenuSaveAs('/fixture/new.azuremap');
    subscriptions.onProjectLoad({ data: '{"_format":"azuremap"}', filePath: '/fixture/open.azuremap' });
    const files = { vnets: '[]' };
    subscriptions.onImportFolder(files);
    assert.deepEqual(saved, [undefined, '/fixture/new.azuremap']);
    assert.equal(JSON.stringify(loaded), '[{"_format":"azuremap"}]');
    assert.deepEqual(paths, ['/fixture/open.azuremap']);
    assert.deepEqual(imported, [files]);
  });

  it('ignores malformed scanner metadata while validating resource JSON', async () => {
    const fixture = desktopFixture();
    // Evaluate the actual main-process reader with an in-memory folder boundary.
    const fragment = source('main.js').slice(source('main.js').indexOf('function readJsonFolder('), source('main.js').indexOf('function createWindow('));
    const context = { path, MAX_IPC_TEXT_BYTES: 1000,
      fs: { readdirSync: () => ['_export-log.json', 'vnets.json'],
        statSync: () => ({ isFile: () => true, size: 2 }),
        readFileSync: file => path.basename(file) === '_export-log.json' ? '{"bytes":,}' : '[]' }
    };
    vm.createContext(context);
    vm.runInContext(fragment, context);
    assert.equal(JSON.stringify(context.readJsonFolder('fixture')), '{"vnets":"[]"}');
    context.fs.readFileSync = () => '{invalid';
    assert.throws(() => context.readJsonFolder('fixture'), /JSON|property|Unexpected/);
    assert.equal(fixture.writes.length, 0);
  });
});

describe('Packaged scan paths', () => {
  it('places the Bash script outside ASAR and runs a harmless child in a writable directory', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mapper-scan-path-regression-'));
    try {
      const paths = scanPaths({ isPackaged: true, resourcesPath: root, appDir: path.join(root, 'app.asar'), userDataDir: root });
      assert.equal(paths.scriptPath, path.join(root, 'export-azure-data.sh'));
      assert.equal(paths.cwd, path.join(root, 'azure-scans'));
      fs.mkdirSync(paths.cwd);
      const result = spawnSync(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], { cwd: paths.cwd, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr || String(result.error));
      assert.equal(result.stdout, paths.cwd);
    } finally {
      assert.ok(path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(root).startsWith('mapper-scan-path-regression-'));
      fs.rmSync(root, { recursive: true, force: true });
    }
    const pkg = JSON.parse(source('package.json'));
    assert.ok(pkg.build.extraResources.includes('export-azure-data.sh'));
  });
});

describe('Bash export metadata', () => {
  const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
  it('preserves named subscriptions and parent arguments in all child export commands', { skip: !fs.existsSync(bash) }, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mapper-child-export-regression-'));
    try {
      const text = source('export-azure-data.sh').replace(/\r/g, '');
      const helpers = text.slice(text.indexOf('merge_json() {'), text.indexOf('# --- Write export log ---'));
      const calls = [...text.matchAll(/iterate_export "(?:Subnets|VNet Peerings|Private DNS Zone Links|SQL Databases)"[^\n]*\\\n[^\n]+/g)].map(match => match[0]);
      assert.equal(calls.length, 4);
      const parentName = 'parent name; $(printf unsafe)';
      const groupName = "resource group ' with spaces";
      const parents = JSON.stringify([{ name: parentName, resourceGroup: groupName }]);
      const script = [
        'set -euo pipefail', 'EXPORTED=0; EMPTY=0',
        'OUTDIR=' + "'" + root.replaceAll('\\', '/').replaceAll("'", "'\\''") + "'",
        'SUB="My Subscription"; COMMON=(--subscription "$SUB" --only-show-errors)',
        'VNET_JSON=' + "'" + parents.replaceAll("'", "'\\''") + "'",
        'PDNS_ZONE_JSON="$VNET_JSON"; SQL_SERVER_JSON="$VNET_JSON"',
        'log_entry() { :; }',
        'az() { python3 -c \'import json,sys; print(json.dumps([{"argv":sys.argv[1:]}]))\' "$@"; }',
        helpers, ...calls,
        'printf "COUNTERS:%s:%s\\n" "$EXPORTED" "$EMPTY"'
      ].join('\n');
      const result = spawnSync(bash, ['--noprofile', '--norc'], { input: script, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /COUNTERS:4:0/);
      for (const file of ['subnets.json', 'peerings.json', 'private-dns-links.json', 'sql-databases.json']) {
        const [item] = JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
        assert.equal(item.argv[item.argv.indexOf('--subscription') + 1], 'My Subscription');
        assert.ok(item.argv.includes(parentName), file);
        assert.equal(item.argv[item.argv.indexOf('-g') + 1], groupName);
      }
    } finally {
      assert.ok(path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(root).startsWith('mapper-child-export-regression-'));
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
  it('serializes skipped errors, unknown counts, and JSON delimiters correctly', { skip: !fs.existsSync(bash) }, () => {
    const text = source('export-azure-data.sh');
    const start = text.indexOf('log_entry() {');
    const body = text.slice(start, text.indexOf('# --- Helper: export az command', start)).replace(/\r/g, '');
    const script = 'EXPORT_LOG="["\n' + body + '\nlog_entry "Restricted resource" "nsgs.json" "SKIPPED" "" "" \'Forbidden "quoted" \\ path\'\nlog_entry "Unknown count" "vms.json" "OK" "123" "?"\nprintf "%s]\\n" "${EXPORT_LOG%,}"\n';
    const result = spawnSync(bash, ['--noprofile', '--norc'], { input: script, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), [
      { label: 'Restricted resource', file: 'nsgs.json', status: 'SKIPPED', detail: 'Forbidden "quoted" \\ path' },
      { label: 'Unknown count', file: 'vms.json', status: 'OK', bytes: 123 }
    ]);
  });
});
