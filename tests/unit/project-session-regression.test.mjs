import assert from 'node:assert/strict';
import { it } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';
import { ext, safeParse } from '../../src/modules/utils.js';

function projectFixture() {
  const elements = new Map(), timers = new Map();
  let timerId = 0, saved;
  const element = id => {
    if (!elements.has(id)) {
      const classes = new Set();
      elements.set(id, { id, value: '', style: {}, className: 'ji', textContent: '',
        classList: { add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name) },
        addEventListener() {}, dispatchEvent() {}, querySelector() { return null; } });
    }
    return elements.get(id);
  };
  const inputs = [element('in_vnets'), element('in_subnets')];
  const render = { rlCtx: null };
  const context = {
    document: { getElementById: element, querySelectorAll: () => inputs, querySelector: () => element('sidebar'), addEventListener() {} },
    AppRenderContext: { createRenderContext: () => render },
    AppProjectFiles: { setNativePath() {}, hasNativeFileAccess: () => false, saveText: async text => { saved = JSON.parse(text); return null; } },
    AppNotifications: { show() {} },
    setTimeout: callback => { const id = ++timerId; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id),
    _getMain: () => element('main'),
    _prebuiltCtx: null, _annotations: {}, _budrOverrides: {}, _isElectron: false,
    _importedReportData: null, _iamData: null, _iamReviewData: [], _appRegistry: [], _parseCache: {},
    _complianceDataFP: '', _complianceCachedFindings: null, _snapshots: [],
    _budrFindings: [], _budrAssessments: [], _budrCachedFindings: null, _budrCachedAssessments: null,
    _saveSnapshots() {}, _saveAnnotations() {}, _autoSaveSession() {}, _renderNoteBadges() {}, _renderComplianceBadges() {},
    loadPrefs: () => ({}), savePrefs() {}, renderCalls: 0, console, Date, JSON, Blob, Event, ext, safeParse,
    gv: id => element(id).value, GovernanceClassification: { reset() {} }
  };
  vm.createContext(context);
  for (const file of ['multi-account-runtime.js', 'design-mode-runtime.js', 'project-file-io.js']) {
    vm.runInContext(fs.readFileSync('src/modules/' + file, 'utf8'), context);
  }
  vm.runInContext(`
    _renderAccountPanel=()=>{};renderChangeLog=()=>{};
    renderMap=done=>{renderCalls++;AppRenderContext.createRenderContext().rlCtx={vnets:JSON.parse(document.getElementById('in_vnets').value||'[]')};if(done)done()};
    this.sessionState=()=>({design:_designMode,baseline:_designBaseline,debounce:_designDebounce,changes:_designChanges.length,merge:_multiViewMode,accounts:_loadedContexts.length,merged:_mergedCtx,backup:_singleCtxBackup,prebuilt:_prebuiltCtx});
  `, context);
  return { context, element, timers, render, saved: () => saved, run: code => vm.runInContext(code, context) };
}

it('loading a single project clears previous merged accounts before rendering and saving', async () => {
  const fixture = projectFixture();
  fixture.element('in_vnets').value = '[{"name":"old-a"},{"name":"old-b"}]';
  fixture.run(`_multiViewMode=true;_loadedContexts=[{accountId:'old-a'},{accountId:'old-b'}];_mergedCtx={vnets:[{name:'old-a'},{name:'old-b'}]};_singleCtxBackup={vnets:[{name:'old-a'}]};_prebuiltCtx=_mergedCtx;`);
  fixture.context._loadProjectData({ _format: 'azuremap', _version: '1.0', accountLabel: 'new', textareas: { in_vnets: [{ name: 'new-c' }] }, designMode: false });
  const state = fixture.context.sessionState();
  assert.equal(state.merge, false);
  assert.equal(state.accounts, 0);
  assert.equal(state.merged, null);
  assert.equal(state.backup, null);
  assert.equal(state.prebuilt, null);
  assert.equal(fixture.context.renderCalls, 1);
  assert.deepEqual(fixture.render.rlCtx.vnets.map(vnet => vnet.name), ['new-c']);
  await fixture.context.saveProject();
  assert.equal(fixture.saved()._version, '1.0');
  assert.equal(fixture.saved().accounts, undefined);
  assert.deepEqual(fixture.saved().textareas.in_vnets.map(vnet => vnet.name), ['new-c']);
});

it('project switching discards the old design baseline and cancels pending edits', () => {
  const fixture = projectFixture();
  fixture.element('in_vnets').value = '[{"name":"project-a"}]';
  fixture.context.enterDesignMode();
  fixture.run(`_designChanges=[{action:'old-change'}];_designDebounce=setTimeout(()=>{document.getElementById('in_vnets').value='[{"name":"old-debounce"}]'},300);`);
  fixture.context._loadProjectData({ _format: 'azuremap', _version: '1.0', textareas: { in_vnets: [{ name: 'project-b' }] }, designMode: false });
  const state = fixture.context.sessionState();
  assert.equal(state.design, false);
  assert.equal(state.baseline, null);
  assert.equal(state.debounce, null);
  assert.equal(state.changes, 0);
  assert.equal(fixture.timers.size, 0);
  fixture.context.exitDesignMode();
  assert.equal(JSON.parse(fixture.element('in_vnets').value)[0].name, 'project-b');
});

it('a new design project captures its own baseline', () => {
  const fixture = projectFixture();
  fixture.element('in_vnets').value = '[{"name":"project-a"}]';
  fixture.context.enterDesignMode();
  fixture.context._loadProjectData({ _format: 'azuremap', _version: '1.0', textareas: { in_vnets: [{ name: 'project-b' }] }, designMode: true, designChanges: [] });
  assert.equal(fixture.context.sessionState().design, true);
  fixture.element('in_vnets').value = '[{"name":"edited-b"}]';
  fixture.context.exitDesignMode();
  assert.equal(JSON.parse(fixture.element('in_vnets').value)[0].name, 'project-b');
});

it('saving a design persists the original baseline alongside its changes', async () => {
  const fixture = projectFixture();
  fixture.element('in_vnets').value = '[{"name":"original-vnet"}]';
  fixture.context.enterDesignMode();
  fixture.element('in_vnets').value = '[{"name":"original-vnet"},{"name":"design-vnet"}]';
  fixture.run(`_designChanges=[{id:'one',action:'add_vpc',target:{},params:{Name:'design-vnet',CidrBlock:'10.1.0.0/16'}}]`);
  await fixture.context.saveProject();
  assert.deepEqual(fixture.saved().textareas.in_vnets.map(vnet => vnet.name), ['original-vnet']);
  assert.equal(fixture.saved().designChanges.length, 1);
  assert.equal(fixture.saved().designMode, true);
  assert.deepEqual(JSON.parse(fixture.element('in_vnets').value).map(vnet => vnet.name), ['original-vnet', 'design-vnet']);
});

it('a project with no overrides or labels replaces previous project metadata', () => {
  const fixture = projectFixture();
  fixture.context._budrOverrides = { shared: { strategy: 'critical', rto: '5 min', rpo: '0' } };
  fixture.context._budrAssessments = [{ id: 'shared', overridden: true, profile: { tier: 'protected' } }];
  fixture.context._budrCachedAssessments = fixture.context._budrAssessments;
  fixture.context._budrFindings = [{ resource: 'old' }];
  fixture.context._budrCachedFindings = fixture.context._budrFindings;
  fixture.element('accountLabel').value = 'previous project';
  fixture.element('hubVpcName').value = 'previous hub';
  fixture.context._loadProjectData({ _format: 'azuremap', textareas: { in_vnets: [] }, accountLabel: '', hubVpcName: '', designMode: false });
  assert.equal(JSON.stringify(fixture.context._budrOverrides), '{}');
  assert.equal(fixture.context._budrAssessments.length, 0);
  assert.equal(fixture.context._budrFindings.length, 0);
  assert.equal(fixture.context._budrCachedAssessments, null);
  assert.equal(fixture.context._budrCachedFindings, null);
  assert.equal(fixture.element('accountLabel').value, '');
  assert.equal(fixture.element('hubVpcName').value, '');
});

it('T04 removing a subnet updates standalone and embedded native VNet collections', () => {
  const fixture = projectFixture();
  const id = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/deleted';
  const retained = { id: id.replace('/deleted', '/retained'), name: 'retained', addressPrefix: '10.0.2.0/24' };
  for (const nested of [false, true]) {
    const vnet = { id: id.split('/subnets/')[0], name: 'v', ...(nested ? { properties: { subnets: [{ id, name: 'deleted' }, retained] } } : { subnets: [{ id, name: 'deleted' }, retained] }) };
    fixture.element('in_vnets').value = JSON.stringify([vnet]);
    fixture.element('in_subnets').value = JSON.stringify({ value: [{ id, SubnetId: id }, retained] });
    fixture.run(`_designApplyFns.remove_resource({target:{ResourceId:${JSON.stringify(id.toUpperCase())},ResourceType:'Subnet'}})`);
    assert.deepEqual(JSON.parse(fixture.element('in_subnets').value).value.map(s => s.id), [retained.id]);
    const saved = JSON.parse(fixture.element('in_vnets').value)[0];
    assert.deepEqual((saved.properties || saved).subnets.map(s => s.id), [retained.id]);
  }
});

it('T06 native scan completion replaces the prior merged/design session before rendering', () => {
  const fixture = projectFixture(), listeners = {};
  fixture.context._isElectron = true;
  fixture.context.DesktopAzureAdapter = { subscribe: (name, callback) => { listeners[name] = callback; } };
  fixture.context.matchFile = name => name === 'vnets' ? 'in_vnets' : null;
  fixture.element('scanProfile').value = 'new-subscription';
  fixture.element('layoutMode').value = 'grid';
  fixture.element('in_vnets').value = '[{"name":"old-a"},{"name":"old-b"}]';
  fixture.context.enterDesignMode();
  fixture.run(`_multiViewMode=true;_loadedContexts=[{accountId:'old-a'},{accountId:'old-b'}];_mergedCtx={vpcs:[{name:'old-a'},{name:'old-b'}]};_singleCtxBackup=_mergedCtx;_prebuiltCtx=_mergedCtx;`);
  vm.runInContext(fs.readFileSync('src/modules/electron-azure-actions.js', 'utf8'), fixture.context);
  listeners.onScanComplete({ code: 0, outDir: 'scan-new', files: { vnets: '[{"name":"new-c"}]' } });
  for (const callback of [...fixture.timers.values()]) callback();
  const state = fixture.context.sessionState();
  assert.equal(state.merge, false);
  assert.equal(state.design, false);
  assert.equal(state.accounts, 0);
  assert.equal(state.prebuilt, null);
  assert.deepEqual(fixture.render.rlCtx.vnets.map(vnet => vnet.name), ['new-c']);
  assert.equal(fixture.element('accountLabel').value, 'new-subscription');
});

it('T07 Clear cancels pending design application without restoring its baseline', () => {
  const fixture = projectFixture();
  fixture.context.d3 = { select: () => ({ selectAll() { return this; }, remove() { return this; }, style() { return this; } }) };
  fixture.context._closeAllDashboardsExcept = () => {};
  fixture.context.sessionSetData = value => { fixture.render.rlCtx = value; };
  fixture.context.sessionResetComplianceRows = () => {};
  const source = fs.readFileSync('src/modules/session-event-wiring.js', 'utf8');
  vm.runInContext(source.slice(source.indexOf('function clearLoadedSession(){'), source.indexOf("document.getElementById('clearBtn').addEventListener")), fixture.context);
  fixture.element('in_vnets').value = '[{"name":"baseline"}]';
  fixture.context.enterDesignMode();
  fixture.run(`_designChanges=[{action:'add_security_group',target:{},params:{Name:'pending-nsg'}}];_designDebounce=setTimeout(applyDesignChanges,300);`);
  fixture.context.clearLoadedSession();
  const state = fixture.context.sessionState();
  assert.equal(state.design, false);
  assert.equal(state.baseline, null);
  assert.equal(state.debounce, null);
  assert.equal(state.changes, 0);
  assert.equal(fixture.timers.size, 0);
  assert.equal(fixture.element('in_vnets').value, '');
  assert.equal(fixture.render.rlCtx, null);
});

it('T18 hiding the last visible context clears active data while retaining accounts for Show', () => {
  const fixture = projectFixture();
  fixture.run(`_renderMergeBannerChips=()=>{this.hiddenFlags=_loadedContexts.map(c=>!c.visible)};_multiViewMode=true;_loadedContexts=[{visible:false},{visible:true}];_mergedCtx={vpcs:[{name:'old-b'}]};_singleCtxBackup=_mergedCtx;_prebuiltCtx=_mergedCtx;`);
  fixture.element('in_vnets').value = '[{"name":"old-b"}]';
  fixture.context._iamData = { old: true };
  fixture.context.toggleAccountVisibility(1);
  const state = fixture.context.sessionState();
  assert.equal(state.merge, true);
  assert.equal(state.accounts, 2);
  assert.equal(state.merged, null);
  assert.equal(state.prebuilt, null);
  assert.equal(state.backup, null);
  assert.equal(fixture.context._iamData, null);
  assert.deepEqual(Array.from(fixture.context.hiddenFlags), [true, true]);
  assert.equal(fixture.element('in_vnets').value, '');
  assert.equal(fixture.render.rlCtx.vnets.length, 0);
  assert.equal(fixture.element('statsBar').style.display, 'none');
});

it('forced recovery save replaces prior programmatic inputs and removes absent collections', () => {
  const source = fs.readFileSync('src/modules/session-event-wiring.js', 'utf8');
  const inputs = [{ id: 'in_vnets', value: '[{"name":"loaded-b"}]' }, { id: 'in_nsgs', value: '' }];
  const store = new Map([['azureMapper_session', '{"in_vnets":"[{\\"name\\":\\"typed-a\\"}]","in_nsgs":"[{}]","_ts":1}']]);
  const context = { document: { querySelectorAll: () => inputs, getElementById: id => inputs.find(el => el.id === id) || { value: '' } },
    sessionStorage: { getItem: key => store.get(key), setItem: (key, value) => store.set(key, value) }, _rptState: {}, console, Date };
  vm.createContext(context);
  vm.runInContext(source.slice(0, source.indexOf('function _restoreSession()')), context);
  context._autoSaveSession(true);
  const saved = JSON.parse(store.get('azureMapper_session'));
  assert.equal(saved.in_vnets, '[{"name":"loaded-b"}]');
  assert.equal(saved.in_nsgs, undefined);
  assert.ok(saved._ts > 1);
});

it('history viewing suspends merged accounts, Return restores them, and Restore commits the snapshot alone', () => {
  const elements = new Map();
  const element = id => { if (!elements.has(id)) elements.set(id, { id, value: '', style: {}, classList: { remove() {} } }); return elements.get(id); };
  const input = element('in_vnets'); input.value = '[{"name":"current-a"},{"name":"current-b"}]';
  const accounts = [{ accountId: 'a' }, { accountId: 'b' }];
  const context = { SNAP_KEY: 'snapshots', MAX_SNAPSHOTS: 5, document: { getElementById: element, querySelectorAll: selector => selector === '.ji' ? [input] : [] },
    _annotations: {}, _multiViewMode: true, _loadedContexts: accounts, _mergedCtx: {}, _singleCtxBackup: { name: 'original-single' }, _prebuiltCtx: {},
    structuredClone, Date, JSON, renderMap(done) { if (done) done(); }, _renderAccountPanel() {}, _autoSaveSession(force) { context.recoverySaved = force; },
    _ensureNotesLoaded() {}, _saveAnnotations() {}, _renderNotesPanel() {},
    exitMultiView() { context._multiViewMode = false; element('mergeBanner').style.display = 'none'; },
    enterMultiView() { context._multiViewMode = true; element('mergeBanner').style.display = 'flex'; } };
  vm.createContext(context);
  const source = fs.readFileSync('src/modules/timeline-notes-view.js', 'utf8');
  vm.runInContext(source.slice(0, source.indexOf('function openTimeline()')), context);
  vm.runInContext(`_snapshots=[{textareas:{in_vnets:'[{"name":"history-a"}]'},accountLabel:'',layout:'grid',timestamp:new Date().toISOString(),label:'old'}]`, context);
  context._viewSnapshot(0);
  assert.equal(context._multiViewMode, false);
  assert.equal(context._loadedContexts.length, 0);
  assert.equal(context._mergedCtx, null);
  assert.equal(context._prebuiltCtx, null);
  assert.equal(element('mergeBanner').style.display, 'none');
  assert.equal(input.value, '[{"name":"history-a"}]');
  context._returnToCurrent();
  assert.equal(context._multiViewMode, true);
  assert.equal(context._loadedContexts, accounts);
  assert.equal(input.value, '[{"name":"current-a"},{"name":"current-b"}]');
  assert.equal(context._singleCtxBackup.name, 'original-single');
  context._viewSnapshot(0);
  context._restoreSnapshot();
  assert.equal(context._multiViewMode, false);
  assert.equal(context._loadedContexts.length, 0);
  assert.equal(input.readOnly, false);
  assert.equal(context.recoverySaved, true);
});
