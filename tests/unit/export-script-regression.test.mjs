import assert from 'node:assert/strict';
import { it } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';

const repo = process.cwd();
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
const pwsh = process.platform === 'win32' ? 'C:/Users/schyl/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe' : (process.env.PATH || '').split(path.delimiter).map(dir => path.join(dir, 'pwsh')).find(file => fs.existsSync(file));
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";

function cliFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mapper-export-script-regression-'));
  // Each recursive sweep must use the same source snapshot even if another task edits the collector.
  for (const script of ['export-azure-data.sh', 'export-azure-data.ps1']) fs.copyFileSync(path.join(repo, script), path.join(root, script));
  const stub = path.join(root, 'stub-az.cjs');
  fs.writeFileSync(stub, `const a=process.argv.slice(2),c=a.join(' ');const output=x=>console.log(JSON.stringify(x));
    if(c.includes('account show')){if(a.includes('--query'))console.log('sub-a');else output({id:'sub-a'});}
    else if(c.includes('account set')){}
    else if(c.includes('resource list')&&a.includes('--query'))console.log('eastus\\nwestus');
    else if(c.includes('network vnet list'))output(['eastus','westus'].map((location,i)=>({id:'vnet-'+location,name:'vnet-'+location,resourceGroup:'rg',location,addressSpace:{addressPrefixes:['10.'+i+'.0.0/16']}})));
    else if(c.includes('network nsg list'))output([{id:'nsg-only',name:'nsg-only',location:'eastus',securityRules:[]}]);
    else if(c.includes('role assignment list'))output([{id:'assignment-global',principalId:'owner-one',scope:'/subscriptions/sub-a',roleDefinitionId:'owner-role'}]);
    else if(c.includes('network private-dns zone list')||c.includes('Microsoft.Network/privateDnsZones'))output([{id:'dns-global',name:'private.test',resourceGroup:'rg',location:'global'}]);
    else if(c.includes('network dns zone list'))output([]);
    else if(c.includes('resource list')&&a.includes('--resource-type')){const type=a[a.indexOf('--resource-type')+1];const selected=a.includes('-g')?a[a.indexOf('-g')+1]:null;output(['rg-one','rg-two'].filter(rg=>!selected||rg===selected).map(resourceGroup=>({id:'/subscriptions/sub-a/resourceGroups/'+resourceGroup+'/providers/'+type+'/one',name:'one',resourceGroup,location:'eastus'})));}
    else if(c.includes('network vnet subnet list')||c.includes('network vnet peering list')){if(!a.includes('--vnet-name')||!a.includes('-g')){console.error('missing VNet parent');process.exit(2);}output([{id:'child-'+a[a.indexOf('--vnet-name')+1]}]);}
    else if(c.includes('network private-dns record-set list')||c.includes('network private-dns link vnet list')){if(!a.includes('--zone-name')||!a.includes('-g')){console.error('missing DNS parent');process.exit(2);}output([{id:'record-global'}]);}
    else output([]);`);
  const wrapper = path.join(root, 'wrapper.sh');
  fs.writeFileSync(wrapper, `az(){ ${quote(process.execPath.replaceAll('\\', '/'))} ${quote(stub.replaceAll('\\', '/'))} "$@"; }\nexport -f az\nbash "$@"\n`);
  fs.writeFileSync(path.join(root, 'az.cmd'), `@echo off\r\n"${process.execPath}" "${stub}" %*\r\n`);
  const env = { ...process.env };
  const pathKey = Object.keys(env).find(key => key.toLowerCase() === 'path') || 'PATH';
  env[pathKey] = root + path.delimiter + env[pathKey];
  return { root, runShell: args => spawnSync(bash, [wrapper, path.join(root, 'export-azure-data.sh').replaceAll('\\', '/'), ...args], { cwd: root, encoding: 'utf8' }),
    runPowerShell: args => spawnSync(pwsh, ['-NoProfile', '-File', path.join(root, 'export-azure-data.ps1'), '-MaxParallel', '2', ...args], { cwd: root, env, encoding: 'utf8' }),
    read: (dir, name) => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8').replace(/^\uFEFF/, '')),
    cleanup() { assert.ok(path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(root).startsWith('mapper-export-script-regression-')); fs.rmSync(root, { recursive: true, force: true }); } };
}

it('browser export download returns the canonical packaged asset without an inline collector', async () => {
  const source = fs.readFileSync('src/modules/session-event-wiring.js', 'utf8');
  const start = source.indexOf('async function sessionDownloadExportScript(');
  const end = source.indexOf("document.getElementById('fileInput').addEventListener", start);
  const listeners = {}, downloads = [];
  const context = { Blob, document: { getElementById: id => ({ style: {}, addEventListener: (_event, callback) => { listeners[id] = callback; } }) },
    fetch: async url => ({ ok: true, text: async () => fs.readFileSync(url.slice(2), 'utf8') }),
    sessionSaveBlob: (blob, name) => downloads.push({ blob, name }), sessionNotify() {} };
  vm.runInNewContext(source.slice(start, end), context);
  await listeners.dlBash(); await listeners.dlPowershell();
  for (const download of downloads) assert.equal(await download.blob.text(), fs.readFileSync(download.name, 'utf8'));
  assert.equal(downloads.length, 2);
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  assert.ok(pkg.build.files.includes('export-azure-data.sh') && pkg.build.files.includes('export-azure-data.ps1'));
});

it('Electron export downloads use the native asset bridge instead of file URL fetch', async () => {
  const source = fs.readFileSync('src/modules/session-event-wiring.js', 'utf8');
  const start = source.indexOf('async function sessionDownloadExportScript(');
  const end = source.indexOf("document.getElementById('fileInput').addEventListener", start);
  const downloads = [];
  const context = { Blob, document: { getElementById: () => ({ style: {}, addEventListener() {} }) },
    DesktopAzureAdapter: { isAvailable: () => true, readExportScript: async name => fs.readFileSync(name, 'utf8') },
    fetch() { throw new Error('file URL fetch must not be used'); }, sessionSaveBlob: (blob, name) => downloads.push({ blob, name }),
    sessionNotify(message) { assert.doesNotMatch(message, /failed/); } };
  vm.runInNewContext(source.slice(start, end), context);
  await context.sessionDownloadExportScript('export-azure-data.ps1', 'text/plain');
  assert.equal(await downloads[0].blob.text(), fs.readFileSync('export-azure-data.ps1', 'utf8'));
});

it('Bash regional and all-location exports scope resources, retain global evidence once, and collect child resources', { skip: !fs.existsSync(bash) }, () => {
  const fixture = cliFixture();
  try {
    const single = path.join(fixture.root, 'single');
    const result = fixture.runShell(['-s', 'My Subscription', '-r', 'eastus', '-o', single.replaceAll('\\', '/')]);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.deepEqual(fixture.read(single, 'vnets.json').map(vnet => vnet.location), ['eastus']);
    assert.equal(fixture.read(single, 'nsgs.json').length, 1);
    assert.equal(fixture.read(single, 'role-assignments.json').length, 1);
    assert.equal(fixture.read(single, 'subnets.json').length, 1);
    assert.equal(fixture.read(single, 'peerings.json').length, 1);
    assert.equal(fixture.read(single, 'dns-records.json').length, 1);
    const all = path.join(fixture.root, 'all');
    const sweep = fixture.runShell(['-s', 'sub-a', '-a', '-o', all.replaceAll('\\', '/')]);
    assert.equal(sweep.status, 0, sweep.stderr || sweep.stdout);
    for (const region of ['eastus', 'westus']) assert.deepEqual(fixture.read(path.join(all, 'sub-a', region), 'vnets.json').map(vnet => vnet.location), [region]);
    assert.equal(fixture.read(path.join(all, 'sub-a/eastus'), 'role-assignments.json').length, 1);
    assert.equal(fixture.read(path.join(all, 'sub-a/westus'), 'role-assignments.json').length, 0);
  } finally { fixture.cleanup(); }
});

it('PowerShell regional and all-location exports preserve singleton collections, global evidence, and child parents', { skip: !pwsh || !fs.existsSync(pwsh) }, () => {
  const fixture = cliFixture();
  try {
    const single = path.join(fixture.root, 'single');
    const result = fixture.runPowerShell(['-Subscription', 'sub-a', '-Location', 'eastus', '-OutputDir', single]);
    assert.equal(result.status, 0, result.stderr || result.stdout || String(result.error));
    assert.deepEqual(fixture.read(single, 'vnets.json').map(vnet => vnet.location), ['eastus']);
    for (const file of ['nsgs.json', 'role-assignments.json', 'subnets.json', 'peerings.json', 'dns-records.json']) assert.equal(fixture.read(single, file).length, 1, file);
    const all = path.join(fixture.root, 'all');
    const sweep = fixture.runPowerShell(['-Subscription', 'sub-a', '-AllLocations', '-OutputDir', all]);
    assert.equal(sweep.status, 0, sweep.stderr || sweep.stdout);
    for (const region of ['eastus', 'westus']) assert.deepEqual(fixture.read(path.join(all, 'sub-a', region), 'vnets.json').map(vnet => vnet.location), [region]);
    assert.equal(fixture.read(path.join(all, 'sub-a/eastus'), 'role-assignments.json').length, 1);
    assert.equal(fixture.read(path.join(all, 'sub-a/westus'), 'role-assignments.json').length, 0);
  } finally { fixture.cleanup(); }
});

it('T19 PowerShell generic resource exports respect the selected resource group', { skip: !pwsh || !fs.existsSync(pwsh) }, () => {
  const fixture = cliFixture();
  try {
    const output = path.join(fixture.root, 'group');
    const result = fixture.runPowerShell(['-Subscription', 'sub-a', '-ResourceGroup', 'rg-one', '-OutputDir', output]);
    assert.equal(result.status, 0, result.stderr || result.stdout || String(result.error));
    for (const file of ['vpn-connections.json', 'vnet-gateways.json', 'disks.json', 'app-insights.json', 'arc-machines.json']) {
      assert.deepEqual(fixture.read(output, file).map(resource => resource.resourceGroup), ['rg-one'], file);
    }
  } finally { fixture.cleanup(); }
});
