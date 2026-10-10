import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { spawn, spawnSync } from 'node:child_process';

function buildFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mapper-build-regression-'));
  fs.mkdirSync(path.join(root, 'src/modules'), { recursive: true });
  fs.mkdirSync(path.join(root, 'libs'));
  fs.symlinkSync(path.resolve('node_modules'), path.join(root, 'node_modules'), 'junction');
  fs.copyFileSync('build.js', path.join(root, 'build.js'));
  fs.copyFileSync('src/modules/app-compatibility-publisher.js', path.join(root, 'src/modules/app-compatibility-publisher.js'));
  fs.writeFileSync(path.join(root, 'src/main.js'), "import {installLazyBundleLoaders} from './modules/app-compatibility-publisher.js'; installLazyBundleLoaders();");
  fs.writeFileSync(path.join(root, 'src/app-core.js'), 'var coreVersion = 1;');
  fs.writeFileSync(path.join(root, 'src/d3-custom.js'), 'export const version = "d3-original";');
  fs.writeFileSync(path.join(root, 'src/modules/demo-data.js'), 'export function generateDemo(){return "demo-original";}');
  fs.writeFileSync(path.join(root, 'src/modules/iac-generator.js'), 'export function generateTerraform(){return "iac-original";}');
  fs.writeFileSync(path.join(root, 'index.html'), '<script src="dist/app.bundle.js?v=old"></script><script src="dist/app-core.js?v=old"></script>');
  return root;
}

function removeFixture(root) {
  const resolved = path.resolve(root);
  const prefix = path.resolve(os.tmpdir()) + path.sep;
  assert.ok(resolved.startsWith(prefix) && path.basename(resolved).startsWith('mapper-build-regression-'));
  fs.rmSync(resolved, { recursive: true, force: true });
}

async function waitFor(check) {
  const end = Date.now() + 10000;
  while (Date.now() < end) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.fail('Timed out waiting for build output');
}

async function lazyPaths(root) {
  const scripts = [];
  const window = { document: { createElement: () => ({}), head: { appendChild(script) {
    scripts.push(script.src);
    if (script.src.includes('demo-data')) window.DemoDataModule = { generateDemo() {} };
    else window.IacGeneratorModule = {};
    script.onload();
  } } } };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'dist/app.bundle.js'), 'utf8'), { window, console });
  await window._loadDemoData();
  await window._loadIacGenerator();
  return scripts;
}

test('production lazy bundle URLs change with their content and propagate to the app hash', async () => {
  const root = buildFixture();
  try {
    const build = () => {
      const result = spawnSync(process.execPath, ['build.js', '--production'], { cwd: root, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr || String(result.error));
    };
    build();
    const original = await lazyPaths(root);
    const originalHtml = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
    assert.match(original[0], /^dist\/demo-data\.bundle\.js\?v=[a-f0-9]{8}$/);
    assert.match(original[1], /^dist\/iac-generator\.bundle\.js\?v=[a-f0-9]{8}$/);
    fs.writeFileSync(path.join(root, 'src/modules/demo-data.js'), 'export function generateDemo(){return "demo-upgraded";}');
    fs.writeFileSync(path.join(root, 'src/modules/iac-generator.js'), 'export function generateTerraform(){return "iac-upgraded";}');
    build();
    const upgraded = await lazyPaths(root);
    assert.notEqual(upgraded[0], original[0]);
    assert.notEqual(upgraded[1], original[1]);
    assert.notEqual(fs.readFileSync(path.join(root, 'index.html'), 'utf8'), originalHtml);
  } finally { removeFixture(root); }
});

test('a cold watch creates every bundle and rebuilds lazy, D3, and core outputs', async () => {
  const root = buildFixture();
  const child = spawn(process.execPath, ['build.js', '--watch'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  let diagnostics = '';
  child.stderr.on('data', data => { diagnostics += data; });
  child.stdout.on('data', () => {});
  const outputs = ['dist/app.bundle.js', 'dist/app-core.js', 'dist/demo-data.bundle.js', 'dist/iac-generator.bundle.js', 'libs/d3.custom.min.js'];
  try {
    await waitFor(() => outputs.every(file => fs.existsSync(path.join(root, file))));
    fs.writeFileSync(path.join(root, 'src/modules/demo-data.js'), 'export function generateDemo(){return "demo-watched";}');
    fs.writeFileSync(path.join(root, 'src/modules/iac-generator.js'), 'export function generateTerraform(){return "iac-watched";}');
    fs.writeFileSync(path.join(root, 'src/d3-custom.js'), 'export const version = "d3-watched";');
    fs.writeFileSync(path.join(root, 'src/app-core.js'), 'var coreVersion = "core-watched";');
    await waitFor(() => [
      ['dist/demo-data.bundle.js', 'demo-watched'], ['dist/iac-generator.bundle.js', 'iac-watched'],
      ['libs/d3.custom.min.js', 'd3-watched'], ['dist/app-core.js', 'core-watched']
    ].every(([file, marker]) => fs.readFileSync(path.join(root, file), 'utf8').includes(marker)));
    assert.equal(child.exitCode, null, diagnostics);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      const stopped = new Promise(resolve => child.once('close', resolve));
      child.kill();
      await stopped;
    }
    removeFixture(root);
  }
});
