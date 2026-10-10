import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const MODULES_DIR = join(import.meta.dirname, '../../src/modules');
const PROJECT_ROOT = join(MODULES_DIR, '../..');

function lineCount(content) {
  return content.trimEnd().split(/\r?\n/).length;
}

function readAppCoreRuntimeSource() {
  const manifest = readFileSync(join(PROJECT_ROOT, 'src/app-core.js'), 'utf8');
  const regionPaths = Array.from(
    manifest.matchAll(/^\/\/ @app-core-region:\s*(.+)$/gm),
    match => match[1].trim()
  );
  if (regionPaths.length === 0) return manifest;
  return [
    manifest,
    ...regionPaths.map(regionPath => readFileSync(join(PROJECT_ROOT, regionPath), 'utf8'))
  ].join('\n');
}

const STALE_PATTERNS = [
  { pattern: /_rlCtx\.vpcs\b/, name: '_rlCtx.vpcs' },
  { pattern: /_rlCtx\.sgs\b/, name: '_rlCtx.sgs' },
  { pattern: /_rlCtx\.nacls\b/, name: '_rlCtx.nacls' },
  { pattern: /_rlCtx\.enis\b/, name: '_rlCtx.enis' },
  { pattern: /_rlCtx\.igws\b/, name: '_rlCtx.igws' },
  { pattern: /_rlCtx\.nats[^G]/, name: '_rlCtx.nats (not natGateways)' },
  { pattern: /_rlCtx\.vpces\b/, name: '_rlCtx.vpces' },
  { pattern: /_rlCtx\.instances\b/, name: '_rlCtx.instances' },
  { pattern: /_rlCtx\.albs\b/, name: '_rlCtx.albs' },
  { pattern: /_rlCtx\.rdsInstances\b/, name: '_rlCtx.rdsInstances' },
  { pattern: /_rlCtx\.ecsServices\b/, name: '_rlCtx.ecsServices' },
  { pattern: /_rlCtx\.lambdaFns\b/, name: '_rlCtx.lambdaFns' },
  { pattern: /_rlCtx\.ecacheClusters\b/, name: '_rlCtx.ecacheClusters' },
  { pattern: /_rlCtx\.redshiftClusters\b/, name: '_rlCtx.redshiftClusters' },
];

describe('_rlCtx key regression (R1.8)', () => {
  it('no src/modules/*.js file uses stale AWS-internal _rlCtx key names', () => {
    const files = readdirSync(MODULES_DIR).filter(f => f.endsWith('.js'));
    const violations = [];

    for (const file of files) {
      const content = readFileSync(join(MODULES_DIR, file), 'utf8');
      const lines = content.split('\n');

      for (const { pattern, name } of STALE_PATTERNS) {
        lines.forEach((line, idx) => {
          if (pattern.test(line)) {
            violations.push(`${file}:${idx + 1} — stale key ${name}`);
          }
        });
      }
    }

    assert.strictEqual(
      violations.length,
      0,
      `Found ${violations.length} stale _rlCtx key references:\n${violations.join('\n')}`
    );
  });

  it('correct Azure-named runtime context keys exist in codebase', () => {
    const expectedKeys = [
      'vnets', 'subnets', 'nsgs', 'nics', 'natGateways',
      'privateEndpoints', 'vms', 'appGateways', 'firewalls',
      'sqlServers', 'redisCaches'
    ];
    // Read the expanded app-core runtime source: manifest plus declared region files.
    const appCore = readAppCoreRuntimeSource();
    for (const key of expectedKeys) {
      const keyPattern = new RegExp(`(?:_rlCtx|\\b\\w+Ctx|\\bctx|\\bc)\\.${key}\\b`);
      assert.ok(
        keyPattern.test(appCore),
        `Expected runtime context key ${key} to be used in app-core.js`
      );
    }
  });

  it('feature runtimes use named owner variables instead of globalThis adapter fallbacks', () => {
    const featureFiles = [
      'budr-dashboard.js',
      'compliance-dashboard-runtime.js',
      'governance-inventory-runtime.js',
      'diff-mode-runtime.js',
      'flow-tracing-panel.js',
      'flow-tracing-runtime.js',
      'flow-analysis-panel.js',
      'flow-analysis-dashboard.js',
      'flow-analysis-runtime.js',
      'firewall-change-set.js',
      'timeline-notes-view.js',
      'iac-generator-runtime.js',
      'diff-snapshot-compare.js',
      'dependency-graph-runtime.js',
      'report-xlsx-export.js',
      'session-event-wiring.js'
    ];

    for (const file of featureFiles) {
      const content = readFileSync(join(MODULES_DIR, file), 'utf8');
      assert.equal(content.includes('globalThis.'), false, `${file} should not read adapter owners through globalThis fallbacks`);
      assert.equal(content.includes('typeof globalThis'), false, `${file} should not branch on globalThis for adapter access`);
    }
  });
});

describe('App shell adapter structure (R1.8 structural check)', () => {
  it('main.js delegates browser compatibility publishing to a named owner', () => {
    const main = readFileSync(join(PROJECT_ROOT, 'src/main.js'), 'utf8');
    const publisher = readFileSync(join(MODULES_DIR, 'app-compatibility-publisher.js'), 'utf8');

    assert.ok(main.includes("from './modules/app-compatibility-publisher.js'"), 'main.js should import the compatibility publisher');
    assert.ok(main.includes('const appModules = {'), 'main.js should only assemble the module map');
    assert.ok(main.includes('publishLegacyAppModules(appModules)'), 'main.js should delegate global AppModules publication');
    assert.ok(main.includes('ensureLegacyComplianceFindings()'), 'main.js should delegate compliance bridge initialization');
    assert.ok(main.includes('installLazyBundleLoaders()'), 'main.js should delegate lazy bundle loader installation');
    assert.equal(main.includes('window.AppModules'), false, 'main.js should not write AppModules directly');
    assert.equal(main.includes('Object.assign(window'), false, 'main.js should not publish modules directly to window');
    assert.equal(main.includes('window._loadDemoData'), false, 'main.js should not install the demo lazy-loader directly');
    assert.equal(main.includes('window._loadIacGenerator'), false, 'main.js should not install the IaC lazy-loader directly');
    assert.equal(main.includes('document.head.appendChild'), false, 'main.js should not own lazy script injection');

    assert.ok(publisher.includes('export function publishLegacyAppModules('), 'publisher should own AppModules publication');
    assert.ok(publisher.includes('export function ensureLegacyComplianceFindings('), 'publisher should own legacy compliance initialization');
    assert.ok(publisher.includes('export function installLazyBundleLoaders('), 'publisher should own lazy loader installation');
    assert.ok(publisher.includes('root._loadDemoData'), 'publisher should install the demo lazy-loader');
    assert.ok(publisher.includes('root._loadIacGenerator'), 'publisher should install the IaC lazy-loader');
    assert.ok(publisher.includes('Object.assign(root, modules)'), 'publisher should own legacy global publication');
    assert.ok(lineCount(publisher) <= 80, 'app-compatibility-publisher.js should stay a small compatibility boundary');
  });

  it('app-shell.js keeps shell wiring separate from render-context and desktop bridges', () => {
    const shell = readFileSync(join(MODULES_DIR, 'app-shell.js'), 'utf8');
    const renderContext = readFileSync(join(MODULES_DIR, 'render-context.js'), 'utf8');
    const desktopAdapter = readFileSync(join(MODULES_DIR, 'desktop-azure-adapter.js'), 'utf8');

    assert.ok(shell.includes('function appShellRenderContext('), 'app-shell.js should read runtime context through a local adapter');
    assert.ok(shell.includes('function appShellSetComplianceFindings('), 'app-shell.js should write compliance rows through render-context');
    assert.ok(shell.includes('function appShellEsc('), 'app-shell.js should own shell markup escaping without the legacy bridge name');
    assert.ok(shell.includes('GovernanceClassification.reset()'), 'app-shell.js should reset classification rows through the classification owner');
    assert.ok(renderContext.includes('let _rlCtx = null;'), 'render-context.js should own the render context bridge state');
    assert.ok(renderContext.includes('var _sgById = new Map();'), 'render-context.js should own the NSG lookup bridge state');
    assert.ok(renderContext.includes('let _mapSvg = null, _mapZoom = null, _mapG = null;'), 'render-context.js should own map reference bridge state');
    assert.ok(renderContext.includes('var _complianceFindings ='), 'render-context.js should own compliance finding bridge state');
    assert.ok(desktopAdapter.includes('var _isElectron = DesktopAzureAdapter.isAvailable();'), 'desktop-azure-adapter.js should own desktop detection');

    assert.equal(shell.includes('_rlCtx'), false, 'app-shell.js should not own the render context global directly');
    assert.equal(shell.includes('_sgById'), false, 'app-shell.js should not own the NSG lookup global directly');
    assert.equal(shell.includes('_mapG'), false, 'app-shell.js should not own map group references directly');
    assert.equal(shell.includes('_complianceFindings'), false, 'app-shell.js should not own compliance finding globals directly');
    assert.equal(shell.includes('_classificationData'), false, 'app-shell.js should not reset classification state directly');
    assert.equal(shell.includes('_escHtml'), false, 'app-shell.js should not call the legacy escape bridge directly');
    assert.equal(shell.includes('_isElectron'), false, 'app-shell.js should not own desktop detection');
    assert.equal(shell.includes('window.'), false, 'app-shell.js should not call browser globals directly');
  });
});

describe('Compliance engine structure (R1.8 structural check)', () => {
  it('keeps compliance dispatch and cache separate from framework policy checks', () => {
    const engine = readFileSync(join(MODULES_DIR, 'compliance-engine.js'), 'utf8');

    assert.ok(lineCount(engine) <= 180, 'compliance-engine.js should stay a small dispatcher/cache owner');
    assert.ok(engine.includes('runFrameworkChecks'), 'compliance-engine.js should own framework dispatch');
    assert.ok(engine.includes('appendBudrEngineFindings'), 'compliance-engine.js should append external BUDR engine findings');
    assert.ok(engine.includes('appendIamFindings'), 'compliance-engine.js should append IAM/RBAC engine findings');
    assert.ok(engine.includes('publishComplianceFindings'), 'compliance-engine.js should own the legacy compliance publish point');
    assert.ok(engine.includes("from './compliance-cis-azure-checks.js'"), 'CIS checks should live in their framework owner');
    assert.ok(engine.includes("from './compliance-caf-checks.js'"), 'CAF checks should live in their framework owner');
    assert.ok(engine.includes("from './compliance-soc2-checks.js'"), 'SOC2 checks should live in their framework owner');
    assert.ok(engine.includes("from './compliance-pci-checks.js'"), 'PCI checks should live in their framework owner');
    assert.ok(engine.includes("from './compliance-budr-azure-checks.js'"), 'Azure BUDR checks should live in their framework owner');
    assert.ok(engine.includes("from './compliance-fedramp-checks.js'"), 'FedRAMP/NIST/CMMC checks should live in their framework owner');

    assert.equal(engine.includes('function runCISAzureChecks('), false, 'CIS policy checks should not live in compliance-engine.js');
    assert.equal(engine.includes('function runCAFChecks('), false, 'CAF policy checks should not live in compliance-engine.js');
    assert.equal(engine.includes('function runSOC2Checks('), false, 'SOC2 policy checks should not live in compliance-engine.js');
    assert.equal(engine.includes('function runPCIChecks('), false, 'PCI policy checks should not live in compliance-engine.js');
    assert.equal(engine.includes('function runBUDRAzureChecks('), false, 'BUDR policy checks should not live in compliance-engine.js');
    assert.equal(engine.includes('function runFedRAMPChecks('), false, 'FedRAMP policy checks should not live in compliance-engine.js');
    assert.equal(engine.includes('function runRBACChecks('), false, 'legacy duplicate RBAC policy checker should not be kept as dead code');
  });

  it('keeps framework owners focused, bridge-free, and under reviewable size', () => {
    const owners = [
      ['compliance-cis-azure-checks.js', 'runCISAzureChecks', 400],
      ['compliance-caf-checks.js', 'runCAFChecks', 320],
      ['compliance-soc2-checks.js', 'runSOC2Checks', 160],
      ['compliance-pci-checks.js', 'runPCIChecks', 180],
      ['compliance-budr-azure-checks.js', 'runBUDRAzureChecks', 240],
      ['compliance-fedramp-checks.js', 'runFedRAMPChecks', 180],
    ];

    for (const [file, exportName, maxLines] of owners) {
      const content = readFileSync(join(MODULES_DIR, file), 'utf8');

      assert.ok(content.includes(`export function ${exportName}(`), `${file} should export ${exportName}`);
      assert.ok(content.includes('compliance-rule-primitives.js'), `${file} should use shared compliance rule primitives`);
      assert.ok(lineCount(content) <= maxLines, `${file} should stay under ${maxLines} lines`);
      assert.equal(content.includes('window.'), false, `${file} should not publish or read browser globals`);
      assert.equal(content.includes('globalThis'), false, `${file} should not use global fallback access`);
      assert.equal(content.includes('_rlCtx'), false, `${file} should not read render-context globals`);
    }
  });

  it('keeps Checkov mapping and Azure resource predicates in the shared primitive owner', () => {
    const primitives = readFileSync(join(MODULES_DIR, 'compliance-rule-primitives.js'), 'utf8');

    assert.ok(primitives.includes('export const CKV_MAP ='), 'Checkov ID mapping should have one owner');
    assert.ok(primitives.includes('export function _finding('), 'finding construction should have one owner');
    assert.ok(primitives.includes('export function _getRules('), 'NSG rule extraction should have one owner');
    assert.ok(primitives.includes('export function _subnetProps('), 'subnet property access should have one owner');
    assert.ok(lineCount(primitives) <= 220, 'compliance-rule-primitives.js should stay reviewable');
    assert.equal(primitives.includes('window.'), false, 'primitive owner should not use browser globals');
    assert.equal(primitives.includes('globalThis'), false, 'primitive owner should not use global fallback access');
  });
});

describe('Dashboard module structure (R1.7 structural check)', () => {
  it('does not keep the stale extracted dashboards.js duplicate', () => {
    assert.equal(
      existsSync(join(MODULES_DIR, 'dashboards.js')),
      false,
      'dashboard rendering should live in dashboard-shell.js, not stale dashboards.js'
    );
  });

  it('dashboard-shell.js owns unified dashboard rendering entry points', () => {
    const content = readFileSync(join(MODULES_DIR, 'dashboard-shell.js'), 'utf8');
    assert.ok(content.includes('function openUnifiedDash('), 'dashboard-shell.js should expose openUnifiedDash');
    assert.ok(content.includes('function closeUnifiedDash('), 'dashboard-shell.js should expose closeUnifiedDash');
    assert.ok(content.includes('function _renderUdashTabs('), 'dashboard-shell.js should render dashboard tabs');
    assert.ok(content.includes('function dashboardRuntimeContext('), 'dashboard-shell.js should read runtime data through the render-context adapter');
    assert.ok(content.includes('function dashboardNotify('), 'dashboard-shell.js should route user feedback through the notification adapter');
    assert.ok(content.includes('function dashboardDownload('), 'dashboard-shell.js should route exports through the download adapter');
    assert.ok(content.includes('function dashboardEsc('), 'dashboard-shell.js should own local dashboard escaping');
    assert.ok(content.includes('GovernanceClassification.ensure'), 'dashboard-shell.js should request classification rows through the classification owner');
    assert.ok(content.includes('GovernanceClassification.applyRules'), 'dashboard-shell.js should apply classification rule edits through the classification owner');
    assert.equal(content.includes('var _udashTab ='), false, 'dashboard-shell.js should not redeclare dashboard tab state');
    assert.equal(content.includes('var _udashAcctFilter ='), false, 'dashboard-shell.js should not redeclare dashboard account-filter state');
    assert.equal(content.includes('let _budrDashState'), false, 'dashboard-shell.js should not redeclare BUDR dashboard state');
    assert.equal(content.includes('function openBUDRDash('), false, 'BUDR dashboard rendering should live in budr-dashboard.js');
    assert.equal(content.includes('function _renderBUDRDash('), false, 'BUDR dashboard rendering should live in budr-dashboard.js');
    assert.equal(content.includes('_UDASH_TABS'), false, 'dashboard-shell.js should use an internal non-legacy tab registry name');
    assert.equal(content.includes('_rlCtx'), false, 'dashboard-shell.js should not read the legacy render context global directly');
    assert.equal(content.includes('_complianceFindings'), false, 'dashboard-shell.js should not read compliance findings globals directly');
    assert.equal(content.includes('_showToast'), false, 'dashboard-shell.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'dashboard-shell.js should not call the legacy download shim directly');
    assert.equal(content.includes('_escHtml'), false, 'dashboard-shell.js should not use the notes escape bridge');
    assert.equal(/_classificationData|_classificationOverrides|_classificationRules|_discoveredTags|_scoreClassification|_TIER_RPO_RTO|runClassificationEngine/.test(content), false, 'dashboard-shell.js should not reach into classification internals directly');
  });

  it('budr-dashboard.js owns BUDR dashboard rendering entry points', () => {
    const content = readFileSync(join(MODULES_DIR, 'budr-dashboard.js'), 'utf8');
    assert.ok(content.includes('function openBUDRDash('), 'budr-dashboard.js should expose openBUDRDash');
    assert.ok(content.includes('function _renderBUDRDash('), 'budr-dashboard.js should render the BUDR dashboard');
    assert.ok(content.includes('function budrEsc('), 'budr-dashboard.js should route markup escaping through a local owner');
    assert.ok(content.includes('function budrNotify('), 'budr-dashboard.js should route feedback through a local owner');
    assert.ok(content.includes('function budrSaveBlob('), 'budr-dashboard.js should route file saves through a local owner');
    assert.ok(content.includes('function budrDesktopExportXlsx('), 'budr-dashboard.js should route desktop XLSX export through a local owner');
    assert.ok(content.includes('DesktopAzureAdapter'), 'budr-dashboard.js should use the desktop adapter for Electron exports');
    assert.ok(content.includes("document.getElementById('budrBtn')"), 'budr-dashboard.js should wire the BUDR dock button');
    assert.equal(content.includes('_escHtml'), false, 'budr-dashboard.js should not use the legacy escape bridge');
    assert.equal(content.includes('_showToast'), false, 'budr-dashboard.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'budr-dashboard.js should not call the download bridge directly');
    assert.equal(content.includes('window.'), false, 'budr-dashboard.js should not call browser/Electron globals directly');
  });

  it('dashboard-state.js owns live dashboard state helpers, not rendering', () => {
    const content = readFileSync(join(MODULES_DIR, 'dashboard-state.js'), 'utf8');
    assert.ok(content.includes('var DashboardState ='), 'dashboard-state.js should expose the live state owner');
    assert.ok(content.includes('getUdashTab'), 'dashboard-state.js should expose tab state accessors');
    assert.ok(content.includes('setUdashAcctFilter'), 'dashboard-state.js should expose account-filter state accessors');
    assert.ok(content.includes('resetBudrDashState'), 'dashboard-state.js should expose BUDR dashboard state reset');
    assert.equal(content.includes('function openUnifiedDash('), false, 'dashboard-state.js should not own rendering entry points');
  });
});

describe('Project I/O module structure (R1.8 structural check)', () => {
  it('project-file-io.js resets runtime context through the render-context adapter', () => {
    const content = readFileSync(join(MODULES_DIR, 'project-file-io.js'), 'utf8');
    assert.ok(content.includes('function projectFileRenderState('), 'project-file-io.js should expose a local render-state adapter');
    assert.ok(content.includes('projectFileRenderState().rlCtx=null'), 'project-file-io.js should reset project render state through the adapter');
    assert.equal(content.includes('_rlCtx'), false, 'project-file-io.js should not write the legacy render context global directly');
  });

  it('folder-import.js uses notification and file-access adapters instead of direct browser bridges', () => {
    const content = readFileSync(join(MODULES_DIR, 'folder-import.js'), 'utf8');
    const fileAccess = readFileSync(join(MODULES_DIR, 'project-file-access.js'), 'utf8');
    assert.ok(content.includes('function importFolder('), 'folder-import.js should expose folder import');
    assert.ok(content.includes('AppNotifications.show'), 'folder-import.js should use the notification adapter');
    assert.ok(content.includes('AppProjectFiles.hasDirectoryPicker'), 'folder-import.js should query directory support through the file-access adapter');
    assert.ok(content.includes('AppProjectFiles.chooseDirectory'), 'folder-import.js should choose directories through the file-access adapter');
    assert.equal(content.includes('_showToast'), false, 'folder-import.js should not call the toast bridge directly');
    assert.equal(content.includes('window.showDirectoryPicker'), false, 'folder-import.js should not call browser directory APIs directly');
    assert.ok(fileAccess.includes('function chooseDirectory('), 'project-file-access.js should own browser directory picking');
    assert.ok(fileAccess.includes('AppDownloads.saveBlob'), 'project-file-access.js should route browser saves through the download adapter');
    assert.equal(fileAccess.includes('downloadBlob'), false, 'project-file-access.js should not call the legacy download shim directly');
  });
});

describe('Search/detail navigation adapter structure (R1.8 structural check)', () => {
  it('search, resource navigation, and map viewport use render-context adapters instead of direct global fallbacks', () => {
    const mapViewport = readFileSync(join(MODULES_DIR, 'map-viewport.js'), 'utf8');
    const navigation = readFileSync(join(MODULES_DIR, 'resource-navigation.js'), 'utf8');
    const searchPanel = readFileSync(join(MODULES_DIR, 'search-panel.js'), 'utf8');
    const complianceDashboard = readFileSync(join(MODULES_DIR, 'compliance-dashboard-runtime.js'), 'utf8');
    const dashboardShell = readFileSync(join(MODULES_DIR, 'dashboard-shell.js'), 'utf8');
    const governanceRuntime = readFileSync(join(MODULES_DIR, 'governance-inventory-runtime.js'), 'utf8');

    assert.ok(mapViewport.includes('AppRenderContext.createRenderContext'), 'map-viewport.js should use the render context adapter');
    assert.ok(navigation.includes('AppRenderContext.createRenderContext'), 'resource-navigation.js should use the render context adapter');
    assert.ok(searchPanel.includes('AppRenderContext.createRenderContext'), 'search-panel.js should use the render context adapter');
    assert.ok(complianceDashboard.includes('ResourceNavigation.zoomAndOpenDetail'), 'compliance dashboard should delegate jumps to ResourceNavigation');
    assert.ok(dashboardShell.includes('ResourceNavigation.zoomAndOpenDetail'), 'dashboard shell should delegate jumps to ResourceNavigation');
    assert.ok(governanceRuntime.includes('ResourceNavigation.zoomAndOpenDetail'), 'governance runtime should delegate jumps to ResourceNavigation');

    assert.equal(mapViewport.includes('_rlCtx'), false, 'map-viewport.js should not read the legacy render context global directly');
    assert.equal(mapViewport.includes('_mapG'), false, 'map-viewport.js should not read the legacy map group global directly');
    assert.equal(navigation.includes('_rlCtx'), false, 'resource-navigation.js should not read the legacy render context global directly');
    assert.equal(navigation.includes('_escHtml'), false, 'resource-navigation.js should use local escaping instead of the legacy escape bridge');
    assert.equal(navigation.includes('window.'), false, 'resource-navigation.js should not publish search/detail bridges through browser globals directly');
    assert.equal(navigation.includes('globalThis'), false, 'resource-navigation.js should not publish or resolve search/detail bridges through globalThis');
    assert.equal(navigation.includes('publishResourceNavigation'), false, 'resource-navigation.js should not keep a global publisher wrapper');
    assert.equal(searchPanel.includes('_rlCtx'), false, 'search-panel.js should not read the legacy render context global directly');
    assert.equal(searchPanel.includes('window.'), false, 'search-panel.js should not publish search bridges through browser globals directly');
    assert.equal(searchPanel.includes('globalThis'), false, 'search-panel.js should not publish or resolve search bridges through globalThis');
    assert.equal(searchPanel.includes('publishSearchPanel'), false, 'search-panel.js should not keep a global publisher wrapper');
    assert.equal(searchPanel.includes('function openSearch'), false, 'search-panel.js should not publish the legacy openSearch alias');
    assert.equal(searchPanel.includes('function closeSearch'), false, 'search-panel.js should not publish the legacy closeSearch alias');
    assert.equal(searchPanel.includes('function _invalidateSearchIndex'), false, 'search-panel.js should not publish the legacy search-index invalidation alias');
    assert.equal(navigation.includes('function _zoomToElement'), false, 'resource-navigation.js should not publish the legacy zoom alias');
    assert.equal(navigation.includes('function _zoomAndShowDetail'), false, 'resource-navigation.js should not publish the legacy detail-jump alias');
    assert.equal(navigation.includes('function _openResourceSpotlight'), false, 'resource-navigation.js should not publish the legacy spotlight-open alias');
    assert.equal(navigation.includes('function _closeSpotlight'), false, 'resource-navigation.js should not publish the legacy spotlight-close alias');
    assert.equal(complianceDashboard.includes('_zoomAndShowDetail'), false, 'compliance dashboard should not call the legacy detail-jump alias');
    assert.equal(dashboardShell.includes('_zoomAndShowDetail'), false, 'dashboard shell should not call the legacy detail-jump alias');
    assert.equal(governanceRuntime.includes('_zoomAndShowDetail'), false, 'governance runtime should not call the legacy detail-jump alias');
  });
});

describe('Topology renderer adapter structure (R1.8 structural check)', () => {
  it('topology-renderer.js publishes context, NSG lookup, gateway highlights, and errors through local owners', () => {
    const topology = readFileSync(join(MODULES_DIR, 'topology-renderer.js'), 'utf8');
    const geometry = readFileSync(join(MODULES_DIR, 'topology-grid-geometry.js'), 'utf8');
    const regionBands = readFileSync(join(MODULES_DIR, 'topology-grid-region-bands.js'), 'utf8');
    const resourceSections = readFileSync(join(MODULES_DIR, 'topology-grid-resource-sections.js'), 'utf8');
    const statusControls = readFileSync(join(MODULES_DIR, 'topology-status-controls.js'), 'utf8');
    const gridLayout = readFileSync(join(MODULES_DIR, 'topology-grid-layout.js'), 'utf8');
    const landingZoneResourceSections = readFileSync(join(MODULES_DIR, 'topology-landing-zone-resource-sections.js'), 'utf8');
    const landingZone = readFileSync(join(MODULES_DIR, 'topology-landing-zone.js'), 'utf8');
    const executiveOverview = readFileSync(join(MODULES_DIR, 'topology-executive-overview.js'), 'utf8');
    const renderContext = readFileSync(join(MODULES_DIR, 'render-context.js'), 'utf8');
    const mapViewport = readFileSync(join(MODULES_DIR, 'map-viewport.js'), 'utf8');
    const mapViewportCompatibility = readFileSync(join(MODULES_DIR, 'map-viewport-compatibility.js'), 'utf8');

    assert.ok(topology.includes('function topologyRuntimeContext('), 'topology renderer should have a named render-context adapter');
    assert.ok(topology.includes('AppRenderContext.createRenderContext'), 'topology renderer should use the shared render-context adapter');
    assert.ok(topology.includes('function topologyPublishRuntimeContext('), 'topology renderer should publish runtime context through a local owner');
    assert.ok(topology.includes('function topologyPublishSecurityGroups('), 'topology renderer should publish NSG lookup through a local owner');
    assert.ok(topology.includes('function topologyComplianceFindings('), 'topology renderer should read compliance rows through a local owner');
    assert.ok(topology.includes('function topologyNotify('), 'topology renderer should route render errors through notifications');
    assert.ok(topology.includes('function topologySetUnlockHandler('), 'topology renderer should own highlight unlock listener state locally');
    assert.ok(topology.includes('function topologySetGatewayHighlighter('), 'topology renderer should register gateway highlighting through MapViewport');
    assert.ok(topology.includes('function topologyOpenResourceSpotlight('), 'topology renderer should route resource spotlight through a local owner');
    assert.ok(topology.includes('ResourceNavigation.openSpotlight'), 'topology renderer should call the ResourceNavigation owner for spotlight cards');
    assert.ok(geometry.includes('function buildTopologyGridGeometry('), 'topology-grid-geometry.js should own standard grid layout geometry');
    assert.ok(geometry.includes('function buildSubLayouts('), 'topology-grid-geometry.js should own subnet layout placement');
    assert.ok(geometry.includes('gwP'), 'topology-grid-geometry.js should own gateway placement coordinates');
    assert.ok(regionBands.includes('function drawTopologyGridRegionBands('), 'topology-grid-region-bands.js should own standard grid region grouping and backplates');
    assert.ok(regionBands.includes('region-boundary'), 'topology-grid-region-bands.js should draw grid region boundaries');
    assert.ok(gridLayout.includes('function renderGridTopologyMap('), 'topology-grid-layout.js should own the standard grid topology layout mode');
    assert.ok(gridLayout.includes('buildTopologyGridGeometry({'), 'grid layout should delegate VNet/subnet/gateway geometry to its owner');
    assert.ok(gridLayout.includes('drawTopologyGridRegionBands({'), 'grid layout should delegate region bands to their owner');
    assert.ok(gridLayout.includes('drawTopologyGridResourceSections({'), 'grid layout should delegate resource sections to their owner');
    assert.ok(resourceSections.includes('function drawTopologyGridResourceSections('), 'topology-grid-resource-sections.js should own grid resource badges and sections');
    assert.ok(resourceSections.includes('Storage Accounts'), 'topology-grid-resource-sections.js should own storage account grid sections');
    assert.ok(resourceSections.includes('Front Door / CDN Profiles'), 'topology-grid-resource-sections.js should own Front Door/CDN grid sections');
    assert.ok(statusControls.includes('function renderTopologyStatusControls('), 'topology-status-controls.js should own shared topology status chips and footer controls');
    assert.ok(statusControls.includes('topologyPublishRuntimeContext'), 'topology status controls should publish runtime context through the topology owner');
    assert.ok(gridLayout.includes('renderTopologyStatusControls({'), 'grid layout should delegate status chips and footer controls to their owner');
    assert.ok(landingZoneResourceSections.includes('function drawLandingZoneResourceSections('), 'topology-landing-zone-resource-sections.js should own landing-zone endpoint, DNS, storage, and CDN sections');
    assert.ok(landingZoneResourceSections.includes('Azure DNS Private Zones'), 'landing-zone resource sections should draw DNS sections');
    assert.ok(landingZoneResourceSections.includes('Front Door / CDN Profiles'), 'landing-zone resource sections should draw CDN sections');
    assert.ok(landingZone.includes('drawLandingZoneResourceSections({'), 'landing-zone layout should delegate resource sections to their owner');
    assert.ok(landingZone.includes('renderTopologyStatusControls({'), 'landing-zone layout should delegate status chips and footer controls to their owner');
    assert.ok(gridLayout.includes('topologySetGatewayHighlighter'), 'grid layout should register gateway highlighting through the topology owner');
    assert.ok(landingZone.includes('function renderLandingZoneMap('), 'topology-landing-zone.js should own the landing-zone layout mode');
    assert.ok(landingZone.includes('topologyOpenResourceSpotlight'), 'landing-zone layout should route resource spotlights through the topology owner');
    assert.ok(executiveOverview.includes('function renderExecutiveOverview('), 'topology-executive-overview.js should own the executive topology layout mode');
    assert.equal(topology.includes('function renderGridTopologyMap('), false, 'topology-renderer.js should not reclaim standard grid topology rendering');
    assert.equal(topology.includes('function renderLandingZoneMap('), false, 'topology-renderer.js should not reclaim landing-zone layout rendering');
    assert.equal(topology.includes('function renderExecutiveOverview('), false, 'topology-renderer.js should not reclaim executive overview rendering');
    assert.ok(renderContext.includes('securityGroupsById'), 'render-context.js should own NSG lookup compatibility');
    assert.ok(mapViewport.includes('function setGatewayHighlighter('), 'map viewport should own the gateway highlighter callback');
    assert.equal(mapViewport.includes('window.MapViewport'), false, 'map viewport should not publish its browser global directly');
    assert.equal(mapViewport.includes('AppModules.MapViewport'), false, 'map viewport should not publish its AppModules compatibility hook directly');
    assert.ok(mapViewportCompatibility.includes('global.MapViewport = MapViewport'), 'map viewport compatibility owner should publish the stable browser global');
    assert.ok(mapViewportCompatibility.includes('global.AppModules.MapViewport = MapViewport'), 'map viewport compatibility owner should publish the AppModules hook');

    for (const [name, owner] of [
      ['topology-renderer.js', topology],
      ['topology-grid-geometry.js', geometry],
      ['topology-grid-region-bands.js', regionBands],
      ['topology-grid-resource-sections.js', resourceSections],
      ['topology-status-controls.js', statusControls],
      ['topology-grid-layout.js', gridLayout],
      ['topology-landing-zone-resource-sections.js', landingZoneResourceSections],
      ['topology-landing-zone.js', landingZone],
      ['topology-executive-overview.js', executiveOverview]
    ]) {
      assert.equal(owner.includes('_rlCtx'), false, `${name} should not write the legacy render context global directly`);
      assert.equal(owner.includes('_sgById'), false, `${name} should not write the legacy security-group cache directly`);
      assert.equal(owner.includes('_showToast'), false, `${name} should not call the toast bridge directly`);
      assert.equal(owner.includes('_openResourceSpotlight'), false, `${name} should not call the legacy resource spotlight alias`);
      assert.equal(owner.includes('_closeSpotlight'), false, `${name} should not call the legacy spotlight close alias`);
      assert.equal(owner.includes('window.'), false, `${name} should not publish highlight handlers on window`);
    }
    assert.equal(mapViewport.includes('_hlGwGlobal'), false, 'map viewport should not depend on the old gateway highlight window hook');
  });

  it('topology-renderer.js does not ship unconditional render performance logs', () => {
    const topology = readFileSync(join(MODULES_DIR, 'topology-renderer.js'), 'utf8');
    const geometry = readFileSync(join(MODULES_DIR, 'topology-grid-geometry.js'), 'utf8');
    const regionBands = readFileSync(join(MODULES_DIR, 'topology-grid-region-bands.js'), 'utf8');
    const resourceSections = readFileSync(join(MODULES_DIR, 'topology-grid-resource-sections.js'), 'utf8');
    const statusControls = readFileSync(join(MODULES_DIR, 'topology-status-controls.js'), 'utf8');
    const gridLayout = readFileSync(join(MODULES_DIR, 'topology-grid-layout.js'), 'utf8');
    const landingZoneResourceSections = readFileSync(join(MODULES_DIR, 'topology-landing-zone-resource-sections.js'), 'utf8');
    const landingZone = readFileSync(join(MODULES_DIR, 'topology-landing-zone.js'), 'utf8');
    const executiveOverview = readFileSync(join(MODULES_DIR, 'topology-executive-overview.js'), 'utf8');

    for (const [name, owner] of [
      ['topology-renderer.js', topology],
      ['topology-grid-geometry.js', geometry],
      ['topology-grid-region-bands.js', regionBands],
      ['topology-grid-resource-sections.js', resourceSections],
      ['topology-status-controls.js', statusControls],
      ['topology-grid-layout.js', gridLayout],
      ['topology-landing-zone-resource-sections.js', landingZoneResourceSections],
      ['topology-landing-zone.js', landingZone],
      ['topology-executive-overview.js', executiveOverview]
    ]) {
      assert.equal(owner.includes('[PERF]'), false, `${name} should not log debug timing in production`);
      assert.equal(owner.includes("console.log('[PERF]"), false, `${name} should not write render timing to console`);
    }
  });
});

describe('Design mode runtime adapter structure (R1.8 structural check)', () => {
  it('does not keep the stale design-mode.js duplicate outside the manifest owner', () => {
    assert.equal(
      existsSync(join(MODULES_DIR, 'design-mode.js')),
      false,
      'design mode UI and validation should live in design-mode-runtime.js, not a parallel ES sidecar'
    );
  });

  it('design-mode-runtime.js routes runtime state, downloads, notifications, and toolbar context through local owners', () => {
    const content = readFileSync(join(MODULES_DIR, 'design-mode-runtime.js'), 'utf8');

    assert.ok(content.includes('function designRuntimeData('), 'design mode should read app state through a local render-context adapter');
    assert.ok(content.includes('function designNotify('), 'design mode should route user feedback through the notification adapter');
    assert.ok(content.includes('function designDownload('), 'design mode should route exports through the download adapter');
    assert.ok(content.includes('function designToolbarButton('), 'design mode should bind toolbar context through event handlers');
    assert.ok(content.includes('event.stopPropagation()'), 'design toolbar clicks should not leak into global panel close handlers');
    assert.ok(content.includes('const _azureLocationZones='), 'design mode should use Azure location naming for design forms');

    assert.equal(content.includes('_rlCtx'), false, 'design-mode-runtime.js should not read the legacy render context global directly');
    assert.equal(content.includes('_showToast'), false, 'design-mode-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'design-mode-runtime.js should not call the download bridge directly');
    assert.equal(content.includes('window.'), false, 'design-mode-runtime.js should not write toolbar context onto window');
    assert.equal(content.includes('_dtCtx'), false, 'design-mode-runtime.js should not use transient global detail-toolbar context');
    assert.equal(content.includes('_regionAZs'), false, 'design-mode-runtime.js should not keep AWS region/AZ design lists');
    assert.equal(content.includes('us-east-1'), false, 'design-mode-runtime.js should default design location to an Azure location');
  });

  it('resource-list-panel.js builds design toolbar buttons without inline bridge strings', () => {
    const content = readFileSync(join(MODULES_DIR, 'resource-list-panel.js'), 'utf8');

    assert.ok(content.includes('function resourceListContext('), 'resource list should read app state through a local render-context adapter');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'resource list should use the shared render-context adapter');
    assert.ok(content.includes('function addResourceListDesignToolbar('), 'resource list design toolbar should have a named local owner');
    assert.ok(content.includes('function resourceListDesignButton('), 'resource list design buttons should use event handlers');

    assert.equal(content.includes('_rlCtx'), false, 'resource-list-panel.js should not read the legacy render context global directly');
    assert.equal(content.includes('onclick="showDesignForm'), false, 'resource-list-panel.js should not build design actions with inline onclick strings');
  });
});

describe('Multi-account runtime adapter structure (R1.8 structural check)', () => {
  it('multi-account-runtime.js routes context, notifications, and compliance data through local adapters', () => {
    const content = readFileSync(join(MODULES_DIR, 'multi-account-runtime.js'), 'utf8');

    assert.ok(content.includes('function multiAccountRuntimeContext('), 'multi-account runtime should have a named context adapter');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'multi-account runtime should use the shared render-context adapter');
    assert.ok(content.includes('function multiAccountNotify('), 'multi-account runtime should have a named notification adapter');
    assert.ok(content.includes('AppNotifications.show'), 'multi-account runtime should use the notification adapter');
    assert.ok(content.includes('function multiAccountComplianceRows('), 'multi-account runtime should read compliance rows through a local owner');
    assert.ok(content.includes('GovernanceClassification.reset()'), 'multi-account runtime should reset classification rows through the classification owner');

    assert.equal(content.includes('_rlCtx'), false, 'multi-account-runtime.js should not read or write the legacy render context global directly');
    assert.equal(content.includes('_showToast'), false, 'multi-account-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('_complianceFindings'), false, 'multi-account-runtime.js should not read or write compliance finding globals directly');
    assert.equal(content.includes('_classificationData'), false, 'multi-account-runtime.js should not reset classification state directly');
  });
});

describe('Session event wiring adapter structure (R1.8 structural check)', () => {
  it('session-event-wiring.js routes session context, downloads, notifications, and reset state through local owners', () => {
    const content = readFileSync(join(MODULES_DIR, 'session-event-wiring.js'), 'utf8');

    assert.ok(content.includes('function sessionRenderContext('), 'session wiring should have a named render-context adapter');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'session wiring should use the shared render-context adapter');
    assert.ok(content.includes('function sessionNotify('), 'session wiring should route user feedback through a local owner');
    assert.ok(content.includes('AppNotifications.show'), 'session wiring should use the notification adapter');
    assert.ok(content.includes('function sessionSaveBlob('), 'session wiring should route export-script downloads through a local owner');
    assert.ok(content.includes('AppDownloads.saveBlob'), 'session wiring should use the download adapter');
    assert.ok(content.includes('function clearLoadedSession('), 'session wiring should keep the clear/reset workflow in a named function');
    assert.ok(content.includes('GovernanceClassification.reset()'), 'session wiring should reset classification rows through the classification owner');

    assert.equal(content.includes('_rlCtx'), false, 'session-event-wiring.js should not read or write the legacy render context global directly');
    assert.equal(content.includes('_showToast'), false, 'session-event-wiring.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'session-event-wiring.js should not call the download bridge directly');
    assert.equal(content.includes('_complianceFindings'), false, 'session-event-wiring.js should not write compliance finding globals directly');
    assert.equal(content.includes('_classificationData'), false, 'session-event-wiring.js should not reset classification state directly');
    assert.equal(content.includes('window.'), false, 'session-event-wiring.js should not reach through window globals directly');
  });
});

describe('IaC runtime adapter structure (R1.8 structural check)', () => {
  it('iac-generator.js stays a pure lazy generator namespace without browser global publishes', () => {
    const content = readFileSync(join(MODULES_DIR, 'iac-generator.js'), 'utf8');
    const formatters = readFileSync(join(MODULES_DIR, 'iac-resource-formatters.js'), 'utf8');
    const terraform = readFileSync(join(MODULES_DIR, 'iac-terraform-generator.js'), 'utf8');
    const arm = readFileSync(join(MODULES_DIR, 'iac-arm-template-generator.js'), 'utf8');
    const bicep = readFileSync(join(MODULES_DIR, 'iac-bicep-generator.js'), 'utf8');
    const checkov = readFileSync(join(MODULES_DIR, 'iac-checkov-generator.js'), 'utf8');
    const azCli = readFileSync(join(MODULES_DIR, 'iac-azure-cli-generator.js'), 'utf8');
    const highlighting = readFileSync(join(MODULES_DIR, 'iac-syntax-highlighting.js'), 'utf8');
    const buildScript = readFileSync(join(PROJECT_ROOT, 'build.js'), 'utf8');

    assert.ok(content.includes('export { generateTerraform'), 'lazy IaC facade should re-export Terraform generation');
    assert.ok(content.includes('export { generateARM'), 'lazy IaC facade should re-export ARM generation');
    assert.ok(content.includes('export { generateBicep'), 'lazy IaC facade should re-export Bicep generation');
    assert.ok(content.includes('export { generateCheckov, generateCheckovArm }'), 'lazy IaC facade should re-export Checkov generation');
    assert.ok(content.includes('export { generateAzCli }'), 'lazy IaC facade should re-export Azure CLI generation');
    assert.ok(buildScript.includes("globalName: 'IacGeneratorModule'"), 'build should expose lazy generator exports as one namespace');
    assert.ok(content.split('\n').length < 80, 'iac-generator.js should stay a tiny lazy bundle facade');

    assert.ok(formatters.includes('export function safeName('), 'iac-resource-formatters.js should own IaC naming helpers');
    assert.ok(terraform.includes('export function generateTerraform('), 'iac-terraform-generator.js should own Terraform generation');
    assert.ok(arm.includes('export function generateARM('), 'iac-arm-template-generator.js should own ARM template generation');
    assert.ok(bicep.includes('export function generateBicep('), 'iac-bicep-generator.js should own Bicep generation');
    assert.ok(checkov.includes('export function generateCheckov('), 'iac-checkov-generator.js should own Checkov policy generation');
    assert.ok(checkov.includes('export function generateCheckovArm('), 'iac-checkov-generator.js should own Checkov ARM fixture generation');
    assert.ok(azCli.includes('export function generateAzCli('), 'iac-azure-cli-generator.js should own Azure CLI command generation');
    assert.ok(highlighting.includes('export function highlightHCL('), 'iac-syntax-highlighting.js should own IaC syntax highlighting');

    assert.equal(content.includes('WINDOW BRIDGE'), false, 'iac-generator.js should not keep a browser-global bridge section');
    assert.equal(content.includes('typeof window'), false, 'iac-generator.js should not branch on browser globals');
    assert.equal(content.includes('window.'), false, 'iac-generator.js should not publish individual generator functions to window');
    for (const [name, owner] of [
      ['iac-resource-formatters.js', formatters],
      ['iac-terraform-generator.js', terraform],
      ['iac-arm-template-generator.js', arm],
      ['iac-bicep-generator.js', bicep],
      ['iac-checkov-generator.js', checkov],
      ['iac-azure-cli-generator.js', azCli],
      ['iac-syntax-highlighting.js', highlighting]
    ]) {
      assert.ok(owner.split('\n').length < 700, `${name} should stay below the large-file threshold`);
      assert.equal(owner.includes('window.'), false, `${name} should not publish browser globals`);
      assert.equal(owner.includes('globalThis'), false, `${name} should not read global fallbacks`);
      assert.equal(owner.includes('_iacOutput'), false, `${name} should not own runtime output state`);
    }
  });

  it('iac-generator-runtime.js routes context, downloads, notifications, and lazy generators through local owners', () => {
    const content = readFileSync(join(MODULES_DIR, 'iac-generator-runtime.js'), 'utf8');

    assert.ok(content.includes('function iacRuntimeContext('), 'IaC runtime should have a named render-context adapter');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'IaC runtime should use the shared render-context adapter');
    assert.ok(content.includes('function iacComplianceFindings('), 'IaC runtime should read compliance rows through a local owner');
    assert.ok(content.includes('function iacNotify('), 'IaC runtime should route user feedback through a local owner');
    assert.ok(content.includes('AppNotifications'), 'IaC runtime should use the notification adapter');
    assert.ok(content.includes('function iacDownload('), 'IaC runtime should route file saves through a local owner');
    assert.ok(content.includes('AppDownloads'), 'IaC runtime should use the download adapter');
    assert.ok(content.includes('function iacEnsureGenerator('), 'IaC runtime should own lazy generator loading');
    assert.ok(content.includes('function iacResult('), 'IaC runtime should normalize lazy generator responses before rendering');
    assert.ok(content.includes('function iacGeneratorFunction('), 'IaC runtime should dispatch generation through a small lazy-generator selector');
    assert.ok(content.includes('function iacGeneratorUnavailable('), 'IaC runtime should show a clear failure state when the lazy bundle is missing');
    assert.ok(content.includes('function iacActiveDashboardTab('), 'IaC runtime should read dashboard shortcut state through a local helper');
    assert.ok(content.includes('function iacToggleDashboardTab('), 'IaC runtime should route dashboard shortcut toggles through a local helper');
    assert.ok(content.includes('DashboardState.getTab()'), 'IaC runtime should use DashboardState instead of the legacy tab global');
    assert.ok(content.includes('generator.generateTerraform'), 'IaC runtime should use the lazy generator namespace for Terraform output');
    assert.ok(content.includes('generator.generateARM'), 'IaC runtime should use the lazy generator namespace for ARM output');
    assert.ok(content.includes('generator.generateBicep'), 'IaC runtime should use the lazy generator namespace for Bicep output');
    assert.ok(content.includes('runGenerator(ctx'), 'IaC runtime should call the selected lazy generator instead of local fallback generators');
    assert.ok(content.includes('_iacOutput=result.code'), 'IaC runtime should keep copy/download state in sync with lazy output');
    assert.ok(content.split('\n').length < 500, 'iac-generator-runtime.js should remain a small modal/controller after generator code moved to the lazy bundle');

    assert.equal(content.includes('_rlCtx'), false, 'iac-generator-runtime.js should not read the legacy render context global directly');
    assert.equal(content.includes('_showToast'), false, 'iac-generator-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'iac-generator-runtime.js should not call the download bridge directly');
    assert.equal(content.includes('_complianceFindings'), false, 'iac-generator-runtime.js should not read compliance finding globals directly');
    assert.equal(content.includes('_udashTab'), false, 'iac-generator-runtime.js should not read dashboard tab state directly');
    assert.equal(content.includes('window.'), false, 'iac-generator-runtime.js should not call browser/Electron globals directly');
    assert.equal(content.includes('function generateTerraform('), false, 'iac-generator-runtime.js should not duplicate Terraform generation');
    assert.equal(content.includes('function generateArmTemplate('), false, 'iac-generator-runtime.js should not duplicate ARM generation');
    assert.equal(content.includes('function generateCheckovCfn('), false, 'iac-generator-runtime.js should not duplicate Checkov ARM generation');
    assert.equal(content.includes('function detectCircularSGs('), false, 'iac-generator-runtime.js should not keep generator-analysis helpers');
    assert.equal(content.includes('function _serializeCfnYaml('), false, 'iac-generator-runtime.js should not keep generator serializers');
  });
});

describe('Compliance dashboard runtime adapter structure (R1.8 structural check)', () => {
  it('does not keep the stale compliance-view.js bridge sidecar outside manifest owners', () => {
    const main = readFileSync(join(PROJECT_ROOT, 'src/main.js'), 'utf8');
    const reportSections = readFileSync(join(MODULES_DIR, 'report-render-functions.js'), 'utf8');

    assert.equal(
      existsSync(join(MODULES_DIR, 'compliance-view.js')),
      false,
      'compliance view helpers should live in manifest owners instead of a self-publishing ES sidecar'
    );
    assert.equal(main.includes("from './modules/compliance-view.js'"), false, 'main bundle should not import the stale compliance view sidecar');
    assert.ok(reportSections.includes('function _buildComplianceView('), 'report-render-functions.js should own compliance view construction');
    assert.ok(reportSections.includes('function _isMuted('), 'report-render-functions.js should own compliance mute state');
  });

  it('compliance-dashboard-runtime.js routes compliance rows, downloads, and escaping through local owners', () => {
    const content = readFileSync(join(MODULES_DIR, 'compliance-dashboard-runtime.js'), 'utf8');

    assert.ok(content.includes('function compDashboardRuntimeContext('), 'compliance dashboard should have a named render-context adapter');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'compliance dashboard should use the shared render-context adapter');
    assert.ok(content.includes('function compDashboardFindings('), 'compliance dashboard should read findings through a local owner');
    assert.ok(content.includes('function compDashboardEsc('), 'compliance dashboard should route markup escaping through a local owner');
    assert.ok(content.includes('AppHtml'), 'compliance dashboard should use the HTML adapter');
    assert.ok(content.includes('function compDashboardDownload('), 'compliance dashboard should route exports through a local owner');
    assert.ok(content.includes('AppDownloads'), 'compliance dashboard should use the download adapter');
    assert.ok(content.includes('function compDashboardOpenResourceDetail('), 'compliance dashboard should route map/detail jumps through a local owner');
    assert.ok(content.includes('function compDashboardActiveTab('), 'compliance dashboard should read dashboard tab state through a local owner');
    assert.ok(content.includes('DashboardState.getTab()'), 'compliance dashboard should use DashboardState instead of the legacy tab global');

    assert.equal(content.includes('_complianceFindings'), false, 'compliance-dashboard-runtime.js should not read compliance finding globals directly');
    assert.equal(content.includes('_udashTab'), false, 'compliance-dashboard-runtime.js should not read dashboard tab state directly');
    assert.equal(content.includes('_escHtml'), false, 'compliance-dashboard-runtime.js should not use the legacy escape bridge');
    assert.equal(content.includes('downloadBlob'), false, 'compliance-dashboard-runtime.js should not call the download bridge directly');
    assert.equal(content.includes('_showToast'), false, 'compliance-dashboard-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('window.'), false, 'compliance-dashboard-runtime.js should not call browser/Electron globals directly');
  });
});

describe('Firewall dashboard model structure (R1.8 structural check)', () => {
  it('does not keep the stale firewall-engine.js duplicate outside the manifest owners', () => {
    assert.equal(
      existsSync(join(MODULES_DIR, 'firewall-engine.js')),
      false,
      'firewall editing should live in firewall-editor-runtime.js with dashboard data in firewall-dashboard-model.js'
    );
  });

  it('does not keep the stale firewall-editor.js sidecar outside the manifest owners', () => {
    const main = readFileSync(join(PROJECT_ROOT, 'src/main.js'), 'utf8');

    assert.equal(
      existsSync(join(MODULES_DIR, 'firewall-editor.js')),
      false,
      'firewall editing should live in firewall-editor-runtime.js with dashboard data in firewall-dashboard-model.js'
    );
    assert.equal(main.includes("from './modules/firewall-editor.js'"), false, 'main bundle should not import the stale firewall editor sidecar');
    assert.equal(main.includes('import * as FirewallEditor'), false, 'main bundle should not publish a stale FirewallEditor namespace');
    assert.equal(main.includes('FirewallEditor,'), false, 'AppModules should not publish a stale FirewallEditor namespace');
  });

  it('firewall dashboard data shaping lives in a pure model and runtime uses adapters', () => {
    const model = readFileSync(join(MODULES_DIR, 'firewall-dashboard-model.js'), 'utf8');
    const changeSet = readFileSync(join(MODULES_DIR, 'firewall-change-set.js'), 'utf8');
    const runtime = readFileSync(join(MODULES_DIR, 'firewall-editor-runtime.js'), 'utf8');

    assert.ok(model.includes('var FirewallDashboardModel ='), 'firewall-dashboard-model.js should expose the dashboard model owner');
    assert.ok(model.includes('buildViewModel'), 'firewall-dashboard-model.js should build dashboard view models');
    assert.equal(model.includes('document.'), false, 'firewall-dashboard-model.js should not own DOM rendering');
    assert.equal(model.includes('window.'), false, 'firewall-dashboard-model.js should not write browser globals directly');
    assert.equal(model.includes('_rlCtx'), false, 'firewall-dashboard-model.js should not read legacy render context globals');
    assert.equal(model.includes('_showToast'), false, 'firewall-dashboard-model.js should not own notification delivery');
    assert.equal(model.includes('_escHtml'), false, 'firewall-dashboard-model.js should not depend on notes escaping');

    assert.ok(changeSet.includes('function firewallRuntimeData('), 'firewall-change-set.js should read app data through a local render-context adapter');
    assert.ok(changeSet.includes('function firewallRuntimeContext('), 'firewall-change-set.js should expose a local render-context owner');
    assert.ok(changeSet.includes('function firewallSecurityGroup('), 'firewall-change-set.js should resolve NSGs through a local owner');
    assert.ok(changeSet.includes('securityGroupsById'), 'firewall-change-set.js should use render-context NSG lookup compatibility');
    assert.ok(changeSet.includes('function firewallNotify('), 'firewall-change-set.js should route feedback through the notification adapter');
    assert.ok(changeSet.includes('function firewallEsc('), 'firewall-change-set.js should own local firewall escaping');
    assert.ok(changeSet.includes('function _fwGenerateCli('), 'firewall-change-set.js should own Azure CLI command generation');
    assert.ok(changeSet.includes('function _fwValidateNaclRule('), 'firewall-change-set.js should own NACL rule validation');
    assert.ok(changeSet.includes('function _fwValidateSgRule('), 'firewall-change-set.js should own NSG rule validation');
    assert.ok(changeSet.includes('function _fwValidateRoute('), 'firewall-change-set.js should own route validation');
    assert.ok(changeSet.includes('function _fwTakeSnapshot('), 'firewall-change-set.js should own edit snapshots');
    assert.ok(runtime.includes('function _fwRenderNaclInline('), 'firewall-editor-runtime.js should own NACL rendering');
    assert.ok(runtime.includes('function firewallRefreshDashboardIfOpen('), 'firewall-editor-runtime.js should refresh dashboard rendering through a named tab-state helper');
    assert.ok(runtime.includes('DashboardState.getTab()'), 'firewall-editor-runtime.js should use DashboardState instead of the legacy tab global');
    assert.ok(runtime.includes('FirewallDashboardModel.buildViewModel'), 'firewall-editor-runtime.js should delegate dashboard row/filter/group logic to the model');
    assert.equal(runtime.includes('function _fwGenerateCli('), false, 'firewall-editor-runtime.js should not own Azure CLI command generation');
    assert.equal(runtime.includes('function _fwValidateNaclRule('), false, 'firewall-editor-runtime.js should not own NACL validation');
    assert.equal(runtime.includes('function _fwTakeSnapshot('), false, 'firewall-editor-runtime.js should not own edit snapshots');
    assert.equal(runtime.includes('let _fwEdits='), false, 'firewall-editor-runtime.js should not own firewall edit state');
    assert.equal(changeSet.includes('_rlCtx'), false, 'firewall-change-set.js should not read the legacy render context global directly');
    assert.equal(changeSet.includes('_sgById'), false, 'firewall-change-set.js should not read the legacy security-group cache directly');
    assert.equal(changeSet.includes('_showToast'), false, 'firewall-change-set.js should not call the toast bridge directly');
    assert.equal(changeSet.includes('_escHtml'), false, 'firewall-change-set.js should not use the notes escape bridge');
    assert.equal(runtime.includes('_rlCtx'), false, 'firewall-editor-runtime.js should not read the legacy render context global directly');
    assert.equal(runtime.includes('_sgById'), false, 'firewall-editor-runtime.js should not read the legacy security-group cache directly');
    assert.equal(runtime.includes('_udashTab'), false, 'firewall-editor-runtime.js should not read dashboard tab state directly');
    assert.equal(runtime.includes('_showToast'), false, 'firewall-editor-runtime.js should not call the toast bridge directly');
    assert.equal(runtime.includes('_escHtml'), false, 'firewall-editor-runtime.js should not use the notes escape bridge');
  });
});

describe('Governance inventory model structure (R1.8 structural check)', () => {
  it('does not keep the stale governance.js sidecar outside the manifest owner', () => {
    const main = readFileSync(join(PROJECT_ROOT, 'src/main.js'), 'utf8');

    assert.equal(
      existsSync(join(MODULES_DIR, 'governance.js')),
      false,
      'governance ownership should live in governance-classification.js, governance-inventory-model.js, governance-inventory-runtime.js, and governance-iam-review.js'
    );
    assert.equal(main.includes("from './modules/governance.js'"), false, 'main bundle should not import the stale governance sidecar');
    assert.equal(main.includes('import * as Governance'), false, 'main bundle should not publish a stale Governance namespace');
    assert.equal(main.includes('Governance,'), false, 'AppModules should not publish a stale Governance namespace');
  });

  it('governance inventory data shaping lives in a pure model and runtime uses adapters', () => {
    const classification = readFileSync(join(MODULES_DIR, 'governance-classification.js'), 'utf8');
    const model = readFileSync(join(MODULES_DIR, 'governance-inventory-model.js'), 'utf8');
    const runtime = readFileSync(join(MODULES_DIR, 'governance-inventory-runtime.js'), 'utf8');
    const iamReview = readFileSync(join(MODULES_DIR, 'governance-iam-review.js'), 'utf8');

    assert.ok(classification.includes('var GovernanceClassification='), 'governance-classification.js should expose the classification owner');
    assert.ok(classification.includes('function runClassificationEngine('), 'governance-classification.js should own classification execution');
    assert.ok(classification.includes('function ensureClassificationData('), 'governance-classification.js should own classification lazy initialization');
    assert.ok(classification.includes('function resetClassificationData('), 'governance-classification.js should own classification reset state');
    assert.ok(classification.includes('function setClassificationOverride('), 'governance-classification.js should own manual tier override updates');
    assert.ok(classification.includes('function applyClassificationRules('), 'governance-classification.js should own rule application and reclassification');
    assert.ok(classification.includes('function _scoreClassification('), 'governance-classification.js should own tier scoring');
    assert.ok(classification.includes('function _discoverTagKeys('), 'governance-classification.js should own tag discovery');
    assert.ok(classification.includes('const _TIER_RPO_RTO='), 'governance-classification.js should own RPO/RTO tier metadata');
    assert.ok(lineCount(classification) <= 320, 'governance-classification.js should stay reviewable');
    assert.equal(classification.includes('window.'), false, 'governance-classification.js should not publish raw browser globals');
    assert.equal(classification.includes('globalThis'), false, 'governance-classification.js should not use global fallback access');
    assert.equal(classification.includes('_rlCtx'), false, 'governance-classification.js should not read render-context globals');

    assert.ok(model.includes('var GovernanceInventoryModel ='), 'governance-inventory-model.js should expose the inventory model owner');
    assert.ok(model.includes('function buildInventoryData('), 'governance-inventory-model.js should build inventory rows');
    assert.ok(model.includes('function filterInventory('), 'governance-inventory-model.js should filter inventory rows');
    assert.equal(model.includes('document.'), false, 'governance-inventory-model.js should not own DOM rendering');
    assert.equal(model.includes('window.'), false, 'governance-inventory-model.js should not write browser globals directly');
    assert.equal(model.includes('_rlCtx'), false, 'governance-inventory-model.js should not read legacy render context globals');
    assert.equal(model.includes('_complianceFindings'), false, 'governance-inventory-model.js should not read compliance finding globals');
    assert.equal(model.includes('_showToast'), false, 'governance-inventory-model.js should not own notification delivery');
    assert.equal(model.includes('downloadBlob'), false, 'governance-inventory-model.js should not own download delivery');
    assert.equal(model.includes('_escHtml'), false, 'governance-inventory-model.js should not depend on notes escaping');

    assert.ok(runtime.includes('function governanceRuntimeData('), 'governance-inventory-runtime.js should read app data through a local render-context adapter');
    assert.ok(runtime.includes('function governanceFindings('), 'governance-inventory-runtime.js should read compliance findings through a local adapter');
    assert.ok(runtime.includes('function governanceNotify('), 'governance-inventory-runtime.js should route feedback through the notification adapter');
    assert.ok(runtime.includes('function governanceDownload('), 'governance-inventory-runtime.js should route exports through the download adapter');
    assert.ok(runtime.includes('function governanceEsc('), 'governance-inventory-runtime.js should own local governance escaping');
    assert.ok(runtime.includes('function governanceOpenResourceDetail('), 'governance-inventory-runtime.js should route map/detail jumps through a local owner');
    assert.ok(runtime.includes('GovernanceInventoryModel.buildInventoryData'), 'governance-inventory-runtime.js should delegate inventory row building to the model');
    assert.ok(runtime.includes('GovernanceInventoryModel.filterInventory'), 'governance-inventory-runtime.js should delegate inventory filtering to the model');
    assert.ok(runtime.includes('GovernanceClassification.data'), 'governance-inventory-runtime.js should read classification rows through the classification owner');
    assert.ok(lineCount(runtime) <= 680, 'governance-inventory-runtime.js should stay focused on inventory rendering and governance adapters');
    assert.equal(runtime.includes('function runClassificationEngine('), false, 'classification execution should live in governance-classification.js');
    assert.equal(runtime.includes('function _scoreClassification('), false, 'classification scoring should live in governance-classification.js');
    assert.equal(runtime.includes('const _TIER_RPO_RTO='), false, 'classification tier metadata should live in governance-classification.js');
    assert.equal(runtime.includes('let _classificationData=[]'), false, 'classification state should live in governance-classification.js');
    assert.equal(runtime.includes('_classificationData'), false, 'governance-inventory-runtime.js should not read classification rows directly');
    assert.equal(runtime.includes('function prepareIAMReviewData('), false, 'IAM review preparation should live in governance-iam-review.js');
    assert.equal(runtime.includes('function openIAMPrincipalPanel('), false, 'IAM principal panels should live in governance-iam-review.js');
    assert.equal(runtime.includes('function canDo('), false, 'effective permission checks should live in governance-iam-review.js');
    assert.equal(runtime.includes('_iamReviewData'), false, 'IAM review state should live in governance-iam-review.js');
    assert.equal(runtime.includes('_rlCtx'), false, 'governance-inventory-runtime.js should not read the legacy render context global directly');
    assert.equal(runtime.includes('_complianceFindings'), false, 'governance-inventory-runtime.js should not read compliance findings globals directly');
    assert.equal(runtime.includes('_showToast'), false, 'governance-inventory-runtime.js should not call the toast bridge directly');
    assert.equal(runtime.includes('downloadBlob'), false, 'governance-inventory-runtime.js should not call the legacy download shim directly');
    assert.equal(runtime.includes('_escHtml'), false, 'governance-inventory-runtime.js should not use the notes escape bridge');

    assert.ok(iamReview.includes('var GovernanceIAMReview='), 'governance-iam-review.js should expose a named IAM review owner');
    assert.ok(iamReview.includes('function prepareIAMReviewData('), 'governance-iam-review.js should prepare dashboard/report IAM review rows');
    assert.ok(iamReview.includes('function summarizePermissions('), 'governance-iam-review.js should own effective permission summaries');
    assert.ok(iamReview.includes('function canDo('), 'governance-iam-review.js should own effective permission evaluation');
    assert.ok(iamReview.includes('function openIAMPrincipalPanel('), 'governance-iam-review.js should own IAM principal detail panels');
    assert.ok(lineCount(iamReview) <= 420, 'governance-iam-review.js should stay reviewable');
    assert.equal(iamReview.includes('window.'), false, 'governance-iam-review.js should not publish browser globals');
    assert.equal(iamReview.includes('globalThis'), false, 'governance-iam-review.js should not use global fallback access');
    assert.equal(iamReview.includes('_rlCtx'), false, 'governance-iam-review.js should not read render-context globals');
    assert.equal(iamReview.includes('_showToast'), false, 'governance-iam-review.js should not call the toast bridge directly');
    assert.equal(iamReview.includes('downloadBlob'), false, 'governance-iam-review.js should not call the legacy download shim directly');
    assert.equal(iamReview.includes('_escHtml'), false, 'governance-iam-review.js should not use the notes escape bridge');
  });
});

describe('Detail panel storage topology structure (R1.8 structural check)', () => {
  it('storage-topology.js owns storage topology and storage map-card helpers', () => {
    const content = readFileSync(join(MODULES_DIR, 'storage-topology.js'), 'utf8');
    assert.ok(content.includes('function _buildStorageTopology('), 'storage-topology.js should build storage-to-subnet links');
    assert.ok(content.includes('function _storageInfo('), 'storage-topology.js should classify storage access posture');
    assert.ok(content.includes('function _drawStorageAccountCard('), 'storage-topology.js should draw storage cards for topology rendering');
  });

  it('detail-panel.js keeps subnet/gateway panels and does not reclaim storage topology helpers', () => {
    const content = readFileSync(join(MODULES_DIR, 'detail-panel.js'), 'utf8');
    assert.ok(content.includes('function openSubnetPanel('), 'detail-panel.js should expose subnet detail panels');
    assert.ok(content.includes('function openGatewayPanel('), 'detail-panel.js should expose gateway detail panels');
    assert.ok(content.includes('function detailRuntimeContext('), 'detail-panel.js should read app state through the render-context adapter');
    assert.ok(content.includes('function detailSubnetLookup('), 'detail-panel.js should build subnet panel lookup data in one place');
    assert.ok(content.includes('function detailGatewayLookup('), 'detail-panel.js should build gateway panel lookup data in one place');
    assert.equal(content.includes('_rlCtx'), false, 'detail-panel.js should not read the legacy render context global directly');
    assert.equal(content.includes('_escHtml'), false, 'detail-panel.js should use local escaping instead of the legacy escape bridge');
    assert.equal(content.includes('function _buildStorageTopology('), false, 'storage topology should not live in detail-panel.js');
    assert.equal(content.includes('function _storageInfo('), false, 'storage access classification should not live in detail-panel.js');
    assert.equal(content.includes('function _drawStorageAccountCard('), false, 'storage map-card drawing should not live in detail-panel.js');
  });

  it('detail trace selection is owned locally instead of on window globals', () => {
    const detail = readFileSync(join(MODULES_DIR, 'detail-panel.js'), 'utf8');
    const session = readFileSync(join(MODULES_DIR, 'session-event-wiring.js'), 'utf8');
    assert.ok(detail.includes('var DetailTraceSelection='), 'detail-panel.js should own trace-from-detail state');
    assert.ok(detail.includes('DetailTraceSelection.set({type:\'subnet\''), 'subnet details should publish the selected trace source through the owner');
    assert.ok(detail.includes('DetailTraceSelection.clear()'), 'gateway details should clear stale trace source state');
    assert.ok(session.includes('DetailTraceSelection.get()'), 'session-event-wiring.js should read trace state through the owner');
    assert.equal(detail.includes('window._dpTraceCtx'), false, 'detail-panel.js should not write trace state onto window');
    assert.equal(session.includes('window._dpTraceCtx'), false, 'session-event-wiring.js should not read trace state from window');
  });
});

describe('Subnet resource tree structure (R1.8 structural check)', () => {
  it('subnet-resource-tree.js owns topology resource-tree entry points', () => {
    const content = readFileSync(join(MODULES_DIR, 'subnet-resource-tree.js'), 'utf8');
    assert.ok(content.includes('var SubnetResourceTree='), 'subnet-resource-tree.js should expose the owner object');
    assert.ok(content.includes('function buildResTree('), 'subnet-resource-tree.js should expose the legacy tree builder entry point');
    assert.ok(content.includes('function subMaxChildren('), 'subnet-resource-tree.js should expose the child-count entry point');
    assert.equal(content.includes('globalThis'), false, 'subnet-resource-tree.js should not publish its owner through globalThis');
  });

  it('detail-panel.js does not reclaim subnet resource-tree ownership', () => {
    const content = readFileSync(join(MODULES_DIR, 'detail-panel.js'), 'utf8');
    assert.equal(content.includes('function buildResTree('), false, 'subnet resource-tree construction should not live in detail-panel.js');
    assert.equal(content.includes('function subMaxChildren('), false, 'subnet child-count logic should not live in detail-panel.js');
  });
});

describe('Report module structure (R1.8 structural check)', () => {
  it('export-utilities-runtime.js routes file saves and user feedback through local owners', () => {
    const content = readFileSync(join(MODULES_DIR, 'export-utilities-runtime.js'), 'utf8');
    const exportUtils = readFileSync(join(MODULES_DIR, 'export-utils.js'), 'utf8');
    const exportUtilsCompatibility = readFileSync(join(MODULES_DIR, 'export-utils-compatibility.js'), 'utf8');
    const mapPng = readFileSync(join(MODULES_DIR, 'map-png-export.js'), 'utf8');
    const vsdx = readFileSync(join(MODULES_DIR, 'vsdx-network-export.js'), 'utf8');
    const lucidPackage = readFileSync(join(MODULES_DIR, 'lucid-export-package.js'), 'utf8');
    const lucidData = readFileSync(join(MODULES_DIR, 'lucid-network-export-data.js'), 'utf8');
    const lucidLandingZone = readFileSync(join(MODULES_DIR, 'lucid-landing-zone-export.js'), 'utf8');
    const lucidNetwork = readFileSync(join(MODULES_DIR, 'lucid-network-export.js'), 'utf8');

    assert.ok(content.includes('function exportUtilitiesNotify('), 'export utilities should have a named notification adapter');
    assert.ok(content.includes('AppNotifications.show'), 'export utilities should use the notification adapter');
    assert.ok(content.includes('function exportUtilitiesDownload('), 'export utilities should have a named download adapter');
    assert.ok(content.includes('AppDownloads.saveBlob'), 'export utilities should use the download adapter');
    assert.ok(content.includes("document.getElementById('layoutMode')"), 'export utilities should own export toolbar layout-mode wiring');
    assert.ok(content.includes('function updateDetailBtns('), 'export utilities should own map detail-level toolbar state');
    assert.equal(content.includes("document.getElementById('expPng')"), false, 'PNG export wiring should live in map-png-export.js');
    assert.equal(content.includes("document.getElementById('expVsdx')"), false, 'VSDX export wiring should live in vsdx-network-export.js');
    assert.equal(content.includes("document.getElementById('expLucidDl')"), false, 'Lucid download wiring should live in lucid-export-package.js');

    assert.ok(mapPng.includes("document.getElementById('expPng')"), 'map-png-export.js should own PNG export wiring');
    assert.ok(vsdx.includes("document.getElementById('expVsdx')"), 'vsdx-network-export.js should own VSDX export wiring');
    assert.equal(exportUtils.includes('export function downloadBlob('), false, 'export-utils.js should not keep a duplicate file-save implementation');
    assert.equal(exportUtils.includes('electronAPI.exportFile'), false, 'export-utils.js should not bypass the download adapter');
    assert.equal(exportUtils.includes("from './dom-helpers.js'"), false, 'export-utils.js should not import toast helpers for duplicate file-save feedback');
    assert.equal(exportUtils.includes('window.'), false, 'export-utils.js should not own browser compatibility globals');
    assert.equal(exportUtils.includes("Object.defineProperty(window, '_vsdx'"), false, 'export-utils.js should not publish VSDX browser globals directly');
    assert.ok(exportUtilsCompatibility.includes("import * as ExportUtils from './export-utils.js'"), 'export-utils compatibility owner should receive helper exports explicitly');
    assert.ok(exportUtilsCompatibility.includes("Object.defineProperty(root, '_vsdx'"), 'export-utils compatibility owner should publish the legacy VSDX surface');
    assert.ok(exportUtilsCompatibility.includes('root.resolveColor'), 'export-utils compatibility owner should publish resolveColor');
    assert.ok(exportUtilsCompatibility.includes('root._sanitizeName'), 'export-utils compatibility owner should publish sanitizeName');
    assert.ok(lucidPackage.includes('const AZURE_ICONS='), 'lucid-export-package.js should own Lucid icon package assets');
    assert.ok(lucidPackage.includes('async function buildLucidZip('), 'lucid-export-package.js should own Lucid ZIP assembly');
    assert.ok(lucidPackage.includes("document.getElementById('expLucidDl')"), 'lucid-export-package.js should own Lucid download wiring');
    assert.ok(lucidData.includes('var LucidNetworkExportData ='), 'lucid-network-export-data.js should own Lucid export data collection');
    assert.ok(lucidData.includes('function collect('), 'lucid-network-export-data.js should expose one collection entrypoint');
    assert.ok(lucidData.includes('function buildRelationshipIndexes('), 'lucid-network-export-data.js should own relationship indexes');
    assert.ok(lucidData.includes('function buildGatewayGroups('), 'lucid-network-export-data.js should own gateway grouping');
    assert.ok(lucidLandingZone.includes('function buildLandingZoneLayout('), 'lucid-landing-zone-export.js should own landing-zone Lucid layout');
    assert.ok(lucidNetwork.includes('LucidNetworkExportData.collect'), 'lucid-network-export.js should receive prepared export data');
    assert.ok(lucidNetwork.includes('function buildLucidExport('), 'lucid-network-export.js should own standard Lucid network layout');
    assert.equal(lucidNetwork.includes('safeParse(gv('), false, 'standard Lucid layout should receive prepared export data');
    assert.equal(lucidNetwork.includes('const gwSet2L=new Map'), false, 'standard Lucid layout should not own gateway grouping');
    assert.ok(lucidNetwork.split('\n').length < 1200, 'lucid-network-export.js should stay below threshold after data split');
    assert.equal(lucidData.includes('function buildLucidExport('), false, 'Lucid data owner should not own layout rendering');
    assert.equal(lucidData.includes('window.'), false, 'Lucid data owner should not use random window globals');

    assert.equal(content.includes('_showToast'), false, 'export-utilities-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'export-utilities-runtime.js should not call the download bridge directly');
    assert.equal(content.includes('_rlCtx'), false, 'export-utilities-runtime.js should not read the legacy render context global directly');
    assert.equal(content.includes('_complianceFindings'), false, 'export-utilities-runtime.js should not read compliance finding globals directly');
    for (const [name, owner] of [
      ['map-png-export.js', mapPng],
      ['vsdx-network-export.js', vsdx],
      ['lucid-export-package.js', lucidPackage],
      ['lucid-network-export-data.js', lucidData],
      ['lucid-landing-zone-export.js', lucidLandingZone],
      ['lucid-network-export.js', lucidNetwork]
    ]) {
      assert.equal(owner.includes('_showToast'), false, `${name} should not call the toast bridge directly`);
      assert.equal(owner.includes('downloadBlob'), false, `${name} should not call the download bridge directly`);
      assert.equal(owner.includes('_rlCtx'), false, `${name} should not read the legacy render context global directly`);
      assert.equal(owner.includes('_complianceFindings'), false, `${name} should not read compliance finding globals directly`);
    }
  });

  it('budr-report-registry.js routes module availability through render-context adapters', () => {
    const content = readFileSync(join(MODULES_DIR, 'budr-report-registry.js'), 'utf8');

    assert.ok(content.includes('const _RPT_MODULES='), 'BUDR report registry should own report module registration');
    assert.ok(content.includes('function reportRegistryRuntimeContext('), 'report registry should have a named render-context adapter');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'report registry should use the shared render-context adapter');
    assert.ok(content.includes('function reportRegistryContextData('), 'report registry should read runtime data through a local owner');
    assert.ok(content.includes('function reportRegistryComplianceRows('), 'report registry should read compliance rows through a local owner');
    assert.ok(content.includes('GovernanceClassification.ensure'), 'report registry should request classification rows through the classification owner');

    assert.equal(content.includes('_rlCtx'), false, 'budr-report-registry.js should not read the legacy render context global directly');
    assert.equal(content.includes('_complianceFindings'), false, 'budr-report-registry.js should not read compliance finding globals directly');
    assert.equal(content.includes('_showToast'), false, 'budr-report-registry.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'budr-report-registry.js should not call the download bridge directly');
    assert.equal(content.includes('window.'), false, 'budr-report-registry.js should not call browser/Electron globals directly');
    assert.equal(/_classificationData|runClassificationEngine/.test(content), false, 'budr-report-registry.js should not read or compute classification state directly');
  });

  it('report-import.js uses notification and render-context adapters instead of direct bridges', () => {
    const content = readFileSync(join(MODULES_DIR, 'report-import.js'), 'utf8');
    const renderContext = readFileSync(join(MODULES_DIR, 'render-context.js'), 'utf8');
    assert.ok(content.includes('function importReport('), 'report-import.js should expose report import');
    assert.ok(content.includes('AppNotifications.show'), 'report-import.js should use the notification adapter');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'report-import.js should use the render context adapter');
    assert.equal(content.includes('_showToast'), false, 'report-import.js should not call the toast bridge directly');
    assert.equal(content.includes('_complianceFindings'), false, 'report-import.js should not own compliance finding globals');
    assert.ok(renderContext.includes('set complianceFindings'), 'render-context.js should own compliance finding writes');
  });

  it('report-html-assets.js owns HTML report CSS, interaction script, toolbar, and SVG style serialization', () => {
    const content = readFileSync(join(MODULES_DIR, 'report-html-assets.js'), 'utf8');
    assert.ok(content.includes('function _rptCSS('), 'report-html-assets.js should build exported report CSS');
    assert.ok(content.includes('function _rptInteractiveCSS('), 'report-html-assets.js should build interactive report CSS');
    assert.ok(content.includes('function _rptInteractiveJS('), 'report-html-assets.js should build browser-side report interactions');
    assert.ok(content.includes('function _rptBuildToolbar('), 'report-html-assets.js should build reusable report table controls');
    assert.ok(content.includes('function _rptCollectStyles('), 'report-html-assets.js should serialize styles for diagram export');
    assert.equal(content.includes('window.'), false, 'report-html-assets.js should not hard-code exported report interactions to browser globals');
    assert.equal(content.includes('function _rptExecSummary('), false, 'report section renderers should stay in report-render-functions.js');
    assert.equal(content.includes('function _rptCompliance('), false, 'report section renderers should stay in report-render-functions.js');
  });

  it('report-render-functions.js owns report sections without reclaiming HTML asset scaffolding', () => {
    const content = readFileSync(join(MODULES_DIR, 'report-render-functions.js'), 'utf8');
    assert.ok(content.includes('function _rptExecSummary('), 'report-render-functions.js should render the executive summary');
    assert.ok(content.includes('function _rptCompliance('), 'report-render-functions.js should render compliance sections');
    assert.ok(content.includes('function _rptInventory('), 'report-render-functions.js should render inventory sections');
    assert.ok(content.includes('function reportSectionContext('), 'report-render-functions.js should read report context through a local owner');
    assert.ok(content.includes('function reportSectionComplianceRows('), 'report-render-functions.js should read compliance rows through a local owner');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'report-render-functions.js should use the shared render-context adapter');
    assert.ok(content.includes('GovernanceClassification.data'), 'report-render-functions.js should read classification rows through the classification owner');
    assert.equal(content.includes('function _rptCSS('), false, 'report CSS should live in report-html-assets.js');
    assert.equal(content.includes('function _rptInteractiveJS('), false, 'interactive report JS should live in report-html-assets.js');
    assert.equal(content.includes('function _rptBuildToolbar('), false, 'report table toolbar scaffolding should live in report-html-assets.js');
    assert.equal(content.includes('_rlCtx'), false, 'report-render-functions.js should not read the legacy render context global directly');
    assert.equal(content.includes('_complianceFindings'), false, 'report-render-functions.js should not read compliance finding globals directly');
    assert.equal(/_classificationData|_TIER_RPO_RTO/.test(content), false, 'report-render-functions.js should not reach into classification internals directly');
  });

  it('report-dashboard.js owns report dashboard, picker, preview, and metadata entry points', () => {
    const content = readFileSync(join(MODULES_DIR, 'report-dashboard.js'), 'utf8');
    assert.ok(content.includes('function openReportBuilder('), 'report-dashboard.js should expose the reports dashboard entry point');
    assert.ok(content.includes('function _renderReportsTab('), 'report-dashboard.js should render the reports tab');
    assert.ok(content.includes('function _renderRptPicker('), 'report-dashboard.js should render the report module picker');
    assert.ok(content.includes('function _renderRptPreview('), 'report-dashboard.js should render the report preview');
    assert.ok(content.includes('function _rptEnabledModules('), 'report-dashboard.js should own selected report module state');
    assert.ok(content.includes('function reportDashboardRuntimeContext('), 'report-dashboard.js should have a named render-context adapter');
    assert.ok(content.includes('function reportDashboardComplianceRows('), 'report-dashboard.js should read compliance rows through a local owner');
    assert.ok(content.includes('function reportDashboardNotify('), 'report-dashboard.js should route feedback through a local owner');
    assert.ok(content.includes('AppRenderContext.createRenderContext'), 'report-dashboard.js should use the shared render-context adapter');
    assert.ok(content.includes('AppNotifications.show'), 'report-dashboard.js should use the notification adapter');
    assert.equal(content.includes('_rlCtx'), false, 'report-dashboard.js should not read the legacy render context global directly');
    assert.equal(content.includes('_complianceFindings'), false, 'report-dashboard.js should not read compliance finding globals directly');
    assert.equal(content.includes('_showToast'), false, 'report-dashboard.js should not call the toast bridge directly');
    assert.equal(content.includes('downloadBlob'), false, 'report-dashboard.js should not call the download bridge directly');
    assert.equal(content.includes('window.'), false, 'report-dashboard.js should not call browser/Electron globals directly');
  });

  it('report-builder.js owns HTML and DOCX export generation without reclaiming dashboard UI or XLSX workbooks', () => {
    const content = readFileSync(join(MODULES_DIR, 'report-builder.js'), 'utf8');
    assert.ok(content.includes('async function _generateReport('), 'report-builder.js should generate HTML reports');
    assert.ok(content.includes('async function _generateDocx('), 'report-builder.js should generate DOCX reports');
    assert.ok(content.includes('GovernanceClassification.ensure'), 'report-builder.js should request classification rows through the classification owner');
    assert.equal(content.includes('async function _generateXlsx('), false, 'XLSX report generation should live in report-xlsx-export.js');
    assert.equal(content.includes('function _rptBuildXlsx'), false, 'XLSX workbook builders should live in report-xlsx-export.js');
    assert.equal(content.includes('function openReportBuilder('), false, 'report dashboard entry should not live in report-builder.js');
    assert.equal(content.includes('function _renderReportsTab('), false, 'report tab rendering should not live in report-builder.js');
    assert.equal(content.includes('function _renderRptPicker('), false, 'report picker rendering should not live in report-builder.js');
    assert.equal(content.includes('function _renderRptPreview('), false, 'report preview rendering should not live in report-builder.js');
    assert.equal(/_classificationData|_TIER_RPO_RTO|runClassificationEngine/.test(content), false, 'report-builder.js should not reach into classification internals directly');
  });

  it('report-xlsx-export.js owns XLSX export generation and does not reclaim dashboard or DOCX rendering', () => {
    const content = readFileSync(join(MODULES_DIR, 'report-xlsx-export.js'), 'utf8');
    assert.ok(content.includes('async function _generateXlsx('), 'report-xlsx-export.js should generate selected XLSX reports');
    assert.ok(content.includes('async function _exportFullXlsx('), 'report-xlsx-export.js should generate full assessment XLSX exports');
    assert.ok(content.includes('function _rptBuildXlsxSummary('), 'report-xlsx-export.js should build XLSX workbooks');
    assert.ok(content.includes('GovernanceClassification.ensure'), 'report-xlsx-export.js should request classification rows through the classification owner');
    assert.equal(content.includes('function openReportBuilder('), false, 'report dashboard entry should not live in report-xlsx-export.js');
    assert.equal(content.includes('function _renderReportsTab('), false, 'report tab rendering should not live in report-xlsx-export.js');
    assert.equal(content.includes('async function _generateDocx('), false, 'DOCX generation should stay in report-builder.js');
    assert.equal(/_classificationData|_TIER_RPO_RTO|runClassificationEngine/.test(content), false, 'report-xlsx-export.js should not reach into classification internals directly');
  });
});

describe('Timeline and notes module structure (R1.8 structural check)', () => {
  it('does not keep the stale notes.js duplicate outside the manifest owner', () => {
    assert.equal(
      existsSync(join(MODULES_DIR, 'notes.js')),
      false,
      'notes DOM rendering should live in timeline-notes-view.js, not stale notes.js'
    );
  });

  it('does not keep the stale timeline.js sidecar outside the manifest owner', () => {
    const main = readFileSync(join(PROJECT_ROOT, 'src/main.js'), 'utf8');
    const view = readFileSync(join(MODULES_DIR, 'timeline-notes-view.js'), 'utf8');

    assert.equal(
      existsSync(join(MODULES_DIR, 'timeline.js')),
      false,
      'timeline data and DOM behavior should not be split into an unused self-contained sidecar'
    );
    assert.equal(main.includes("from './modules/timeline.js'"), false, 'main bundle should not import the stale timeline sidecar');
    assert.ok(view.includes('function addAnnotation('), 'timeline-notes-view.js should own annotation writes');
    assert.ok(view.includes('function _renderTimeline('), 'timeline-notes-view.js should own snapshot timeline rendering');
  });

  it('timeline-notes-view.js owns the timeline and notes DOM entry points', () => {
    const content = readFileSync(join(MODULES_DIR, 'timeline-notes-view.js'), 'utf8');
    assert.ok(content.includes('function openTimeline('), 'timeline-notes-view.js should expose the timeline entry point');
    assert.ok(content.includes('function openNotesPanel('), 'timeline-notes-view.js should expose the notes panel entry point');
    assert.ok(content.includes('function _renderNotesPanel('), 'timeline-notes-view.js should render the notes panel');
    assert.ok(content.includes('function _renderNoteBadges('), 'timeline-notes-view.js should render map note badges');
    assert.ok(content.includes('function timelineRuntimeContext('), 'timeline-notes-view.js should read runtime data through the render-context adapter');
    assert.ok(content.includes('function timelineComplianceFindings('), 'timeline-notes-view.js should read compliance findings through a local adapter');
    assert.ok(content.includes('function timelineStorage('), 'timeline-notes-view.js should read browser storage through the storage adapter');
    assert.ok(content.includes('function timelineNotify('), 'timeline-notes-view.js should route feedback through the notification adapter');
    assert.ok(content.includes('function timelineZoomToResource('), 'timeline-notes-view.js should route note zoom through the map viewport adapter');
    assert.ok(content.includes('function timelineResourceSelector('), 'timeline-notes-view.js should build selector-safe map badge lookups locally');
    assert.ok(content.includes('DashboardState.setTab(null)'), 'timeline-notes-view.js should reset dashboard tab state through DashboardState');
    assert.equal(content.includes('_rlCtx'), false, 'timeline-notes-view.js should not read the legacy render context global directly');
    assert.equal(content.includes('_mapG'), false, 'timeline-notes-view.js should not read the legacy map group global directly');
    assert.equal(content.includes('_complianceFindings'), false, 'timeline-notes-view.js should not read compliance findings globals directly');
    assert.equal(content.includes('_udashTab'), false, 'timeline-notes-view.js should not write dashboard tab state directly');
    assert.equal(content.includes('_showToast'), false, 'timeline-notes-view.js should not call the toast bridge directly');
    assert.equal(content.includes('_escHtml'), false, 'timeline-notes-view.js should not use the notes escape bridge name');
    assert.equal(content.includes('_sgById'), false, 'timeline-notes-view.js should read NSGs from render context data');
    assert.equal(content.includes('window.'), false, 'timeline-notes-view.js should not call browser/Electron globals directly');
    assert.equal(content.includes('localStorage.'), false, 'timeline-notes-view.js should not call browser storage directly');
    assert.equal(content.includes('VPC: '), false, 'timeline-notes-view.js should use VNet labels in the note picker');
    assert.equal(content.includes('EC2: '), false, 'timeline-notes-view.js should use VM labels in the note picker');
    assert.equal(content.includes('RDS: '), false, 'timeline-notes-view.js should use SQL labels in the note picker');
    assert.equal(content.includes('Lambda: '), false, 'timeline-notes-view.js should use Function App labels in the note picker');
    assert.equal(content.includes('>SG: '), false, 'timeline-notes-view.js should use NSG labels in the note picker');
  });

  it('dom-helpers.js does not own dashboard panel or tab-state cleanup', () => {
    const content = readFileSync(join(MODULES_DIR, 'dom-helpers.js'), 'utf8');

    assert.equal(content.includes('closeAllDashboards'), false, 'dom-helpers.js should not keep an unused dashboard-closing helper');
    assert.equal(content.includes('setUdashTab'), false, 'dom-helpers.js should not reset dashboard tab state');
    assert.equal(content.includes('window._udashTab'), false, 'dom-helpers.js should not mutate dashboard tab globals directly');
    assert.equal(content.includes('Fallback until setUdashTab is wired'), false, 'dom-helpers.js should not retain stale dashboard-state fallback comments');
  });

  it('flow-tracing panel owns detail markup while runtime owns trace execution', () => {
    const content = readFileSync(join(MODULES_DIR, 'flow-tracing-runtime.js'), 'utf8');
    const panel = readFileSync(join(MODULES_DIR, 'flow-tracing-panel.js'), 'utf8');
    assert.ok(content.includes('function flowRuntimeContext('), 'flow tracing should read runtime state through a local context adapter');
    assert.ok(content.includes('function flowRuntimeData('), 'flow tracing should expose a local runtime-data helper');
    assert.ok(content.includes('function flowNotify('), 'flow tracing should route feedback through the notification adapter');
    assert.ok(content.includes('function flowSecurityGroup('), 'flow tracing should resolve NSGs from runtime data instead of the legacy SG cache');
    assert.ok(content.includes('FlowTracingPanel.renderSingle'), 'single-hop detail rendering should delegate to the panel owner');
    assert.ok(content.includes('FlowTracingPanel.renderMulti'), 'multi-hop detail rendering should delegate to the panel owner');
    assert.ok(content.split('\n').length < 1200, 'flow-tracing-runtime.js should stay below the oversized-file review threshold after panel split');
    assert.ok(panel.includes('var FlowTracingPanel ='), 'flow-tracing-panel.js should expose the named panel owner');
    assert.ok(panel.includes('function renderSingle('), 'flow-tracing-panel.js should own single-hop detail rendering');
    assert.ok(panel.includes('function renderMulti('), 'flow-tracing-panel.js should own multi-hop detail rendering');
    assert.ok(panel.includes('function hopTypeLabel('), 'flow-tracing-panel.js should own hop presentation labels');
    assert.ok(panel.includes('function esc('), 'flow-tracing-panel.js should route panel HTML escaping through a local adapter');
    assert.equal(content.includes('_rlCtx'), false, 'flow-tracing-runtime.js should not read the legacy render context global directly');
    assert.equal(content.includes('_sgById'), false, 'flow-tracing-runtime.js should not read the legacy security-group cache directly');
    assert.equal(content.includes('_showToast'), false, 'flow-tracing-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('_escHtml'), false, 'flow-tracing-runtime.js should not use the notes escape bridge name');
    assert.equal(content.includes('window.'), false, 'flow-tracing-runtime.js should not call browser/Electron globals directly');
    assert.equal(content.includes('function flowEsc('), false, 'flow-tracing-runtime.js should not keep panel-only escaping code');
    assert.equal(content.includes('function _hopTypeLabel'), false, 'flow-tracing-runtime.js should not keep panel-only hop labels');
    assert.equal(content.includes('Hop-by-Hop Trace'), false, 'flow-tracing-runtime.js should not keep detail panel copy');
    assert.equal(content.includes('Multi-Hop Traffic Trace'), false, 'flow-tracing-runtime.js should not keep detail panel copy');
    assert.equal(panel.includes('_flowPath'), false, 'flow-tracing-panel.js should receive explicit trace path state');
    assert.equal(panel.includes('_flowLegs'), false, 'flow-tracing-panel.js should receive explicit multi-hop leg state');
    assert.equal(panel.includes('_flowConfig'), false, 'flow-tracing-panel.js should receive explicit config state');
    assert.equal(panel.includes('window.'), false, 'flow-tracing-panel.js should not call browser/Electron globals directly');
  });

  it('flow-analysis-runtime.js uses adapters for context, notifications, security groups, viewport, and escaping', () => {
    const content = readFileSync(join(MODULES_DIR, 'flow-analysis-runtime.js'), 'utf8');
    const panel = readFileSync(join(MODULES_DIR, 'flow-analysis-panel.js'), 'utf8');
    const dashboard = readFileSync(join(MODULES_DIR, 'flow-analysis-dashboard.js'), 'utf8');
    assert.ok(content.includes('function flowAnalysisRuntimeContext('), 'flow analysis should read runtime state through a local context adapter');
    assert.ok(content.includes('function flowAnalysisRuntimeData('), 'flow analysis should expose a local runtime-data helper');
    assert.ok(content.includes('function flowAnalysisNotify('), 'flow analysis should route feedback through the notification adapter');
    assert.ok(content.includes('function flowAnalysisEsc('), 'flow analysis should route markup escaping through the HTML adapter');
    assert.ok(content.includes('function flowAnalysisSecurityGroup('), 'flow analysis should resolve NSGs from runtime data instead of the legacy SG cache');
    assert.ok(content.includes('function flowAnalysisViewportSize('), 'flow analysis should clamp context menus through a named viewport helper');
    assert.ok(content.includes('FlowAnalysisPanel.render'), 'flow analysis runtime should delegate side-panel rendering to FlowAnalysisPanel');
    assert.ok(content.includes('FlowAnalysisDashboard.open'), 'flow analysis runtime should delegate full dashboard rendering to FlowAnalysisDashboard');
    assert.ok(content.split('\n').length < 1200, 'flow-analysis-runtime.js should stay under the rough 1200-line feature-owner threshold');
    assert.ok(panel.includes('var FlowAnalysisPanel ='), 'flow-analysis-panel.js should own the side-panel surface');
    assert.ok(panel.includes('function render('), 'flow-analysis-panel.js should expose a render entry point');
    assert.ok(panel.includes('launchTraceFromButton'), 'flow-analysis-panel.js should receive trace launching as a callback');
    assert.ok(dashboard.includes('var FlowAnalysisDashboard ='), 'flow-analysis-dashboard.js should own the full dashboard surface');
    assert.ok(dashboard.includes('function buildRows('), 'flow-analysis-dashboard.js should own dashboard row flattening');
    assert.ok(dashboard.includes('function open('), 'flow-analysis-dashboard.js should expose an open entry point');
    assert.equal(content.includes('_rlCtx'), false, 'flow-analysis-runtime.js should not read the legacy render context global directly');
    assert.equal(content.includes('_sgById'), false, 'flow-analysis-runtime.js should not read the legacy security-group cache directly');
    assert.equal(content.includes('_showToast'), false, 'flow-analysis-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('_escHtml'), false, 'flow-analysis-runtime.js should not use the notes escape bridge name');
    assert.equal(content.includes('window.'), false, 'flow-analysis-runtime.js should not call browser/Electron globals directly');
    assert.equal(content.includes('function _openFlowAnalysisDashboard'), false, 'flow-analysis-runtime.js should not own full dashboard construction');
    assert.equal(content.includes('function _renderFaDash'), false, 'flow-analysis-runtime.js should not own dashboard table rendering');
    assert.equal(content.includes('Traffic Flow Analysis Dashboard'), false, 'flow-analysis-runtime.js should not carry dashboard markup');
    assert.equal(content.includes('_faDashRows'), false, 'flow-analysis-runtime.js should not own dashboard rows');
    assert.equal(content.includes('_faDashState'), false, 'flow-analysis-runtime.js should not own dashboard state');
    assert.equal(panel.includes('_flowAnalysisCache'), false, 'flow-analysis-panel.js should receive discovered data as input');
    assert.equal(panel.includes('_flowAnalysisMode'), false, 'flow-analysis-panel.js should receive mode as input');
    assert.equal(panel.includes('_launchTraceFromBtn'), false, 'flow-analysis-panel.js should not call runtime trace globals directly');
    assert.equal(panel.includes('window.'), false, 'flow-analysis-panel.js should not call browser/Electron globals directly');
    assert.equal(dashboard.includes('_flowAnalysisCache'), false, 'flow-analysis-dashboard.js should receive discovered data as input');
    assert.equal(dashboard.includes('_launchTraceFromBtn'), false, 'flow-analysis-dashboard.js should not call runtime trace globals directly');
    assert.equal(dashboard.includes('window.'), false, 'flow-analysis-dashboard.js should not call browser/Electron globals directly');
  });

  it('dependency-graph-runtime.js uses adapters and Azure-native runtime buckets', () => {
    const content = readFileSync(join(MODULES_DIR, 'dependency-graph-runtime.js'), 'utf8');
    assert.ok(content.includes('function dependencyRuntimeContext('), 'dependency graph should read runtime state through a local context adapter');
    assert.ok(content.includes('function dependencyMapGroup('), 'dependency graph should read map state through a local adapter');
    assert.ok(content.includes('function dependencyNotify('), 'dependency graph should route feedback through the notification adapter');
    assert.ok(content.includes('function dependencyEsc('), 'dependency graph should route markup escaping through the HTML adapter');
    assert.ok(content.includes("dependencyArray(ctx,'vnets','vpcs')"), 'dependency graph should prefer Azure-native VNet buckets with legacy fallback');
    assert.ok(content.includes("dependencyArray(ctx,'nsgs','sgs')"), 'dependency graph should prefer Azure-native NSG buckets with legacy fallback');
    assert.ok(content.includes("dependencyArray(ctx,'udrs','rts')"), 'dependency graph should prefer Azure-native UDR buckets with legacy fallback');
    assert.equal(content.includes('_rlCtx'), false, 'dependency-graph-runtime.js should not read the legacy render context global directly');
    assert.equal(content.includes('_sgById'), false, 'dependency-graph-runtime.js should not read the legacy security-group cache directly');
    assert.equal(content.includes('_showToast'), false, 'dependency-graph-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('_escHtml'), false, 'dependency-graph-runtime.js should not use the escape bridge name');
    assert.equal(content.includes('_mapG'), false, 'dependency-graph-runtime.js should not read the map group bridge directly');
    assert.equal(content.includes('window.'), false, 'dependency-graph-runtime.js should not call browser/Electron globals directly');
  });

  it('diff-mode-runtime.js uses adapters for context, map group, notifications, downloads, and escaping', () => {
    const content = readFileSync(join(MODULES_DIR, 'diff-mode-runtime.js'), 'utf8');
    const compare = readFileSync(join(MODULES_DIR, 'diff-snapshot-compare.js'), 'utf8');
    assert.ok(content.includes('function diffRuntimeContext('), 'diff mode should read runtime state through a local context adapter');
    assert.ok(content.includes('function diffRuntimeData('), 'diff mode should expose a local runtime-data helper');
    assert.ok(content.includes('function diffMapGroup('), 'diff mode should route map group access through a local adapter');
    assert.ok(content.includes('function diffNotify('), 'diff mode should route feedback through the notification adapter');
    assert.ok(content.includes('function diffDownload('), 'diff mode should route exports through the download adapter');
    assert.ok(content.includes('function diffEsc('), 'diff mode should route markup escaping through the HTML adapter');
    assert.ok(compare.includes('function diffComparableData('), 'diff snapshot comparison should translate snapshots into Azure-named comparison data');
    assert.ok(compare.includes('function computeDiff('), 'diff snapshot comparison should own the comparison engine');
    assert.ok(compare.includes('function _buildCtxFromTextareas('), 'diff snapshot comparison should own snapshot textarea parsing');
    assert.ok(content.includes('vnetFilter'), 'diff mode dashboard state should use Azure VNet naming');
    assert.equal(content.includes('function computeDiff('), false, 'diff-mode-runtime.js should not own snapshot comparison logic');
    assert.equal(content.includes('_rlCtx'), false, 'diff-mode-runtime.js should not read the legacy render context global directly');
    assert.equal(content.includes('_mapG'), false, 'diff-mode-runtime.js should not read the legacy map group global directly');
    assert.equal(content.includes('_showToast'), false, 'diff-mode-runtime.js should not call the toast bridge directly');
    assert.equal(content.includes('_escHtml'), false, 'diff-mode-runtime.js should not use the notes escape bridge name');
    assert.equal(content.includes('downloadBlob'), false, 'diff-mode-runtime.js should not call the download bridge directly');
    assert.equal(content.includes('window.'), false, 'diff-mode-runtime.js should not call browser/Electron globals directly');
    assert.equal(content.includes('vpcFilter'), false, 'diff-mode-runtime.js should not keep stale VPC filter state naming');
    assert.equal(compare.includes('window.'), false, 'diff-snapshot-compare.js should not call browser/Electron globals directly');
  });
});
