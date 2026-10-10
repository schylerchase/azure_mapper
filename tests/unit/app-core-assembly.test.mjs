import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { test, describe } from 'node:test';

const manifestPath = 'src/app-core.js';
const manifest = readFileSync(manifestPath, 'utf8');
const regionPattern = /^\/\/ @app-core-region:\s*(.+)$/gm;
const regions = Array.from(manifest.matchAll(regionPattern), match => match[1].trim());

describe('app-core source assembly manifest', () => {
  test('declares region files in runtime order', () => {
    assert.ok(regions.length >= 20, 'expected app-core to be split into ordered regions');
    assert.equal(regions[0], 'src/modules/app-shell.js');
    assert.equal(regions[1], 'src/modules/html-escape-adapter.js');
    assert.equal(regions[2], 'src/modules/notification-adapter.js');
    assert.equal(regions[3], 'src/modules/download-adapter.js');
    assert.equal(regions[4], 'src/modules/browser-storage-adapter.js');
    assert.equal(regions[5], 'src/modules/project-file-access.js');
    assert.equal(regions[6], 'src/modules/render-context.js');
    assert.equal(regions[7], 'src/modules/map-viewport.js');
    assert.ok(
      regions.indexOf('src/modules/dashboard-state.js') < regions.indexOf('src/modules/dashboard-shell.js'),
      'dashboard state owner should load before dashboard shell rendering'
    );
    assert.ok(
      regions.indexOf('src/modules/dashboard-shell.js') < regions.indexOf('src/modules/budr-dashboard.js'),
      'BUDR dashboard rendering should load after the general dashboard shell'
    );
    assert.ok(
      regions.indexOf('src/modules/firewall-dashboard-model.js') < regions.indexOf('src/modules/firewall-editor-runtime.js'),
      'firewall dashboard model should load before firewall editor rendering'
    );
    assert.ok(
      regions.indexOf('src/modules/firewall-dashboard-model.js') < regions.indexOf('src/modules/firewall-change-set.js'),
      'firewall dashboard model should load before firewall change-set logic'
    );
    assert.ok(
      regions.indexOf('src/modules/firewall-change-set.js') < regions.indexOf('src/modules/firewall-editor-runtime.js'),
      'firewall change-set state should load before firewall editor rendering'
    );
    assert.ok(
      regions.indexOf('src/modules/governance-classification.js') < regions.indexOf('src/modules/governance-inventory-runtime.js'),
      'governance classification owner should load before inventory runtime consumes classification rows'
    );
    assert.ok(
      regions.indexOf('src/modules/governance-inventory-model.js') < regions.indexOf('src/modules/governance-inventory-runtime.js'),
      'governance inventory model should load before governance inventory rendering'
    );
    assert.ok(
      regions.indexOf('src/modules/governance-inventory-runtime.js') < regions.indexOf('src/modules/governance-iam-review.js'),
      'governance runtime adapters should load before IAM review panels'
    );
    assert.ok(
      regions.indexOf('src/modules/governance-iam-review.js') < regions.indexOf('src/modules/resource-list-panel.js'),
      'IAM review panels should load before resource-list IAM principal links'
    );
    assert.ok(
      regions.indexOf('src/modules/flow-tracing-panel.js') < regions.indexOf('src/modules/flow-tracing-runtime.js'),
      'flow tracing detail panel owner should load before runtime mode control'
    );
    assert.ok(
      regions.indexOf('src/modules/flow-analysis-panel.js') < regions.indexOf('src/modules/flow-analysis-runtime.js'),
      'flow analysis detail panel owner should load before runtime mode control'
    );
    assert.ok(
      regions.indexOf('src/modules/flow-analysis-dashboard.js') < regions.indexOf('src/modules/flow-analysis-runtime.js'),
      'flow analysis dashboard owner should load before runtime dashboard button wiring'
    );
    assert.ok(
      regions.indexOf('src/modules/report-html-assets.js') < regions.indexOf('src/modules/report-render-functions.js'),
      'report HTML assets should load before report section renderers call table toolbar helpers'
    );
    assert.ok(
      regions.indexOf('src/modules/report-dashboard.js') < regions.indexOf('src/modules/report-builder.js'),
      'report dashboard UI should load before report export generation uses selected modules'
    );
    assert.ok(
      regions.indexOf('src/modules/report-builder.js') < regions.indexOf('src/modules/report-xlsx-export.js'),
      'XLSX export should load after shared report filename and section helpers'
    );
    assert.ok(
      regions.indexOf('src/modules/export-utilities-runtime.js') < regions.indexOf('src/modules/map-png-export.js'),
      'shared export adapters should load before PNG export wiring'
    );
    assert.ok(
      regions.indexOf('src/modules/export-utilities-runtime.js') < regions.indexOf('src/modules/vsdx-network-export.js'),
      'shared export adapters should load before VSDX export wiring'
    );
    assert.ok(
      regions.indexOf('src/modules/lucid-export-package.js') < regions.indexOf('src/modules/lucid-network-export.js'),
      'Lucid icon/package assets should load before Lucid network export generation'
    );
    assert.ok(
      regions.indexOf('src/modules/lucid-network-export-data.js') < regions.indexOf('src/modules/lucid-landing-zone-export.js'),
      'Lucid data/index owner should load before landing-zone Lucid layout'
    );
    assert.ok(
      regions.indexOf('src/modules/lucid-network-export-data.js') < regions.indexOf('src/modules/lucid-network-export.js'),
      'Lucid data/index owner should load before standard Lucid network export'
    );
    assert.ok(
      regions.indexOf('src/modules/lucid-landing-zone-export.js') < regions.indexOf('src/modules/lucid-network-export.js'),
      'Lucid landing-zone layout should load before Lucid network export dispatch'
    );
    assert.ok(
      regions.indexOf('src/modules/storage-topology.js') < regions.indexOf('src/modules/detail-panel.js'),
      'storage topology helpers should load before detail panels use storage posture data'
    );
    assert.ok(
      regions.indexOf('src/modules/storage-topology.js') < regions.indexOf('src/modules/topology-renderer.js'),
      'storage topology helpers should load before topology rendering draws storage cards'
    );
    assert.ok(
      regions.indexOf('src/modules/subnet-resource-tree.js') < regions.indexOf('src/modules/detail-panel.js'),
      'subnet resource trees should load before detail-panel consumers'
    );
    assert.ok(
      regions.indexOf('src/modules/subnet-resource-tree.js') < regions.indexOf('src/modules/topology-renderer.js'),
      'subnet resource trees should load before topology rendering'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-renderer.js') < regions.indexOf('src/modules/topology-landing-zone.js'),
      'topology adapter/orchestration should load before landing-zone topology layout'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-renderer.js') < regions.indexOf('src/modules/topology-grid-layout.js'),
      'topology adapter/orchestration should load before standard grid topology layout'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-renderer.js') < regions.indexOf('src/modules/topology-grid-geometry.js'),
      'topology adapter/orchestration should load before standard grid topology geometry'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-renderer.js') < regions.indexOf('src/modules/topology-grid-resource-sections.js'),
      'topology adapter/orchestration should load before grid resource sections'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-renderer.js') < regions.indexOf('src/modules/topology-status-controls.js'),
      'topology adapter/orchestration should load before topology status controls'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-grid-geometry.js') < regions.indexOf('src/modules/topology-grid-layout.js'),
      'standard grid topology geometry should load before grid layout uses it'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-grid-region-bands.js') < regions.indexOf('src/modules/topology-grid-layout.js'),
      'grid region bands should load before standard grid topology layout uses them'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-grid-resource-sections.js') < regions.indexOf('src/modules/topology-grid-layout.js'),
      'grid resource sections should load before standard grid topology layout uses them'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-status-controls.js') < regions.indexOf('src/modules/topology-grid-layout.js'),
      'topology status controls should load before standard grid topology layout uses them'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-grid-layout.js') < regions.indexOf('src/modules/topology-landing-zone.js'),
      'standard grid topology layout should load with the topology layout owners'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-landing-zone-resource-sections.js') < regions.indexOf('src/modules/topology-landing-zone.js'),
      'landing-zone resource sections should load before landing-zone layout uses them'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-status-controls.js') < regions.indexOf('src/modules/topology-landing-zone.js'),
      'topology status controls should load before landing-zone layout uses them'
    );
    assert.ok(
      regions.indexOf('src/modules/topology-renderer.js') < regions.indexOf('src/modules/topology-executive-overview.js'),
      'topology adapter/orchestration should load before executive topology layout'
    );
    assert.ok(
      regions.indexOf('src/modules/desktop-azure-adapter.js') < regions.indexOf('src/modules/project-file-io.js'),
      'desktop adapter should load before project file keyboard shortcuts read desktop availability'
    );
    assert.ok(
      regions.indexOf('src/modules/desktop-azure-adapter.js') < regions.indexOf('src/modules/folder-import.js'),
      'desktop adapter should load before folder import hides desktop-only controls'
    );
    assert.ok(
      regions.indexOf('src/modules/desktop-azure-adapter.js') < regions.indexOf('src/modules/electron-azure-actions.js'),
      'desktop adapter should load before Electron action wiring'
    );
    assert.equal(regions.at(-1), 'src/modules/iac-generator-runtime.js');
  });

  test('all declared region files exist', () => {
    for (const region of regions) {
      assert.ok(existsSync(region), `missing app-core region file: ${region}`);
    }
  });

  test('critical owners contain their expected entry points', () => {
    const topology = readFileSync('src/modules/topology-renderer.js', 'utf8');
    const html = readFileSync('src/modules/html-escape-adapter.js', 'utf8');
    const notifications = readFileSync('src/modules/notification-adapter.js', 'utf8');
    const downloads = readFileSync('src/modules/download-adapter.js', 'utf8');
    const browserStorage = readFileSync('src/modules/browser-storage-adapter.js', 'utf8');
    const projectFileAccess = readFileSync('src/modules/project-file-access.js', 'utf8');
    const mapViewport = readFileSync('src/modules/map-viewport.js', 'utf8');
    const mapViewportCompatibility = readFileSync('src/modules/map-viewport-compatibility.js', 'utf8');
    const resourceProfile = readFileSync('src/modules/resource-profile.js', 'utf8');
    const navigation = readFileSync('src/modules/resource-navigation.js', 'utf8');
    const searchIndex = readFileSync('src/modules/search-index.js', 'utf8');
    const storageTopology = readFileSync('src/modules/storage-topology.js', 'utf8');
    const subnetResourceTree = readFileSync('src/modules/subnet-resource-tree.js', 'utf8');
    const resourceList = readFileSync('src/modules/resource-list-panel.js', 'utf8');
    const topologyGridGeometry = readFileSync('src/modules/topology-grid-geometry.js', 'utf8');
    const topologyGridRegionBands = readFileSync('src/modules/topology-grid-region-bands.js', 'utf8');
    const topologyGridResourceSections = readFileSync('src/modules/topology-grid-resource-sections.js', 'utf8');
    const topologyStatusControls = readFileSync('src/modules/topology-status-controls.js', 'utf8');
    const topologyGrid = readFileSync('src/modules/topology-grid-layout.js', 'utf8');
    const topologyLandingZoneResourceSections = readFileSync('src/modules/topology-landing-zone-resource-sections.js', 'utf8');
    const topologyLandingZone = readFileSync('src/modules/topology-landing-zone.js', 'utf8');
    const topologyExecutive = readFileSync('src/modules/topology-executive-overview.js', 'utf8');
    const search = readFileSync('src/modules/search-panel.js', 'utf8');
    const projectFileIo = readFileSync('src/modules/project-file-io.js', 'utf8');
    const reportImport = readFileSync('src/modules/report-import.js', 'utf8');
    const folderImport = readFileSync('src/modules/folder-import.js', 'utf8');
    const desktopAzureAdapter = readFileSync('src/modules/desktop-azure-adapter.js', 'utf8');
    const timelineNotes = readFileSync('src/modules/timeline-notes-view.js', 'utf8');
    const firewallDashboardModel = readFileSync('src/modules/firewall-dashboard-model.js', 'utf8');
    const firewallChangeSet = readFileSync('src/modules/firewall-change-set.js', 'utf8');
    const governanceClassification = readFileSync('src/modules/governance-classification.js', 'utf8');
    const governanceInventoryModel = readFileSync('src/modules/governance-inventory-model.js', 'utf8');
    const governanceIamReview = readFileSync('src/modules/governance-iam-review.js', 'utf8');
    const flowTracingPanel = readFileSync('src/modules/flow-tracing-panel.js', 'utf8');
    const flowTracingRuntime = readFileSync('src/modules/flow-tracing-runtime.js', 'utf8');
    const flowAnalysisPanel = readFileSync('src/modules/flow-analysis-panel.js', 'utf8');
    const flowAnalysisDashboard = readFileSync('src/modules/flow-analysis-dashboard.js', 'utf8');
    const flowAnalysisRuntime = readFileSync('src/modules/flow-analysis-runtime.js', 'utf8');
    const dashboardState = readFileSync('src/modules/dashboard-state.js', 'utf8');
    const dashboard = readFileSync('src/modules/dashboard-shell.js', 'utf8');
    const budrDashboard = readFileSync('src/modules/budr-dashboard.js', 'utf8');
    const reportHtmlAssets = readFileSync('src/modules/report-html-assets.js', 'utf8');
    const reportRenderFunctions = readFileSync('src/modules/report-render-functions.js', 'utf8');
    const reportDashboard = readFileSync('src/modules/report-dashboard.js', 'utf8');
    const reports = readFileSync('src/modules/report-builder.js', 'utf8');
    const reportXlsx = readFileSync('src/modules/report-xlsx-export.js', 'utf8');
    const exportToolbar = readFileSync('src/modules/export-utilities-runtime.js', 'utf8');
    const mapPngExport = readFileSync('src/modules/map-png-export.js', 'utf8');
    const vsdxNetworkExport = readFileSync('src/modules/vsdx-network-export.js', 'utf8');
    const lucidExportPackage = readFileSync('src/modules/lucid-export-package.js', 'utf8');
    const lucidNetworkExportData = readFileSync('src/modules/lucid-network-export-data.js', 'utf8');
    const lucidLandingZoneExport = readFileSync('src/modules/lucid-landing-zone-export.js', 'utf8');
    const lucidNetworkExport = readFileSync('src/modules/lucid-network-export.js', 'utf8');

    assert.match(topology, /function renderMap\(/);
    assert.match(topology, /renderGridTopologyMap\(\{/);
    assert.doesNotMatch(topology, /function renderGridTopologyMap\(/);
    assert.doesNotMatch(topology, /function renderLandingZoneMap\(/);
    assert.doesNotMatch(topology, /function renderExecutiveOverview\(/);
    assert.match(topologyGridGeometry, /function buildTopologyGridGeometry\(/);
    assert.match(topologyGridGeometry, /function buildSubLayouts\(/);
    assert.match(topologyGridGeometry, /gwP/);
    assert.match(topologyGridGeometry, /return \{/);
    assert.match(topologyGridRegionBands, /function drawTopologyGridRegionBands\(/);
    assert.match(topologyGridRegionBands, /region-boundary/);
    assert.match(topologyGridResourceSections, /function drawTopologyGridResourceSections\(/);
    assert.match(topologyGridResourceSections, /Storage Accounts/);
    assert.match(topologyGridResourceSections, /Front Door \/ CDN Profiles/);
    assert.match(topologyGridResourceSections, /openResourceList\('Endpoints'\)/);
    assert.match(topologyStatusControls, /function renderTopologyStatusControls\(/);
    assert.match(topologyStatusControls, /topologyPublishRuntimeContext/);
    assert.match(topologyStatusControls, /statsBar/);
    assert.match(topologyLandingZoneResourceSections, /function drawLandingZoneResourceSections\(/);
    assert.match(topologyLandingZoneResourceSections, /Azure DNS Private Zones/);
    assert.match(topologyLandingZoneResourceSections, /Front Door \/ CDN Profiles/);
    assert.match(topologyGrid, /function renderGridTopologyMap\(/);
    assert.match(topologyGrid, /buildTopologyGridGeometry\(\{/);
    assert.match(topologyGrid, /drawTopologyGridRegionBands\(\{/);
    assert.match(topologyGrid, /drawTopologyGridResourceSections\(\{/);
    assert.match(topologyGrid, /renderTopologyStatusControls\(\{/);
    assert.doesNotMatch(topologyGrid, /function buildSubLayouts\(/);
    assert.doesNotMatch(topologyGrid, /function subHeight\(/);
    assert.doesNotMatch(topologyGrid, /region-boundary/);
    assert.doesNotMatch(topologyGrid, /topologyPublishRuntimeContext/);
    assert.doesNotMatch(topologyGrid, /Storage Accounts section/);
    assert.doesNotMatch(topologyGrid, /Front Door \/ CDN Profiles/);
    assert.doesNotMatch(topologyGrid, /function renderMap\(/);
    assert.match(topologyLandingZone, /function renderLandingZoneMap\(/);
    assert.match(topologyLandingZone, /topologyOpenResourceSpotlight/);
    assert.match(topologyLandingZone, /drawLandingZoneResourceSections\(\{/);
    assert.match(topologyLandingZone, /renderTopologyStatusControls\(\{/);
    assert.doesNotMatch(topologyLandingZone, /Azure DNS Private Zones/);
    assert.doesNotMatch(topologyLandingZone, /Front Door \/ CDN Profiles/);
    assert.match(topologyExecutive, /function renderExecutiveOverview\(/);
    assert.match(html, /var AppHtml = /);
    assert.match(html, /function createHtmlEscapeAdapter\(/);
    assert.match(html, /function _escHtml\(/);
    assert.match(notifications, /var AppNotifications = /);
    assert.match(notifications, /function _showToast\(/);
    assert.match(downloads, /var AppDownloads = /);
    assert.match(downloads, /function downloadBlob\(/);
    assert.match(browserStorage, /var AppBrowserStorage = /);
    assert.match(browserStorage, /function storageFor\(/);
    assert.match(browserStorage, /function createBrowserStorageAdapter\(/);
    assert.match(browserStorage, /function get\(/);
    assert.match(browserStorage, /function set\(/);
    assert.match(projectFileAccess, /var AppProjectFiles = /);
    assert.match(projectFileAccess, /function saveText\(/);
    assert.match(projectFileAccess, /function openText\(/);
    assert.match(projectFileAccess, /function chooseDirectory\(/);
    assert.match(mapViewport, /var MapViewport = /);
    assert.match(mapViewport, /function setMapRefs\(/);
    assert.match(mapViewport, /function zoomToResource\(/);
    assert.match(mapViewport, /function flashResource\(/);
    assert.match(mapViewportCompatibility, /global\.MapViewport = MapViewport/);
    assert.match(mapViewportCompatibility, /global\.AppModules\.MapViewport = MapViewport/);
    assert.match(resourceProfile, /var ResourceProfile = /);
    assert.match(resourceProfile, /function resolveResourceType\(/);
    assert.match(resourceProfile, /function buildResourceProfile\(/);
    assert.match(navigation, /var ResourceNavigation = /);
    assert.match(navigation, /openSearchResult/);
    assert.match(searchIndex, /var SearchIndex = /);
    assert.match(searchIndex, /function buildSearchIndex\(/);
    assert.match(searchIndex, /function findSearchMatches\(/);
    assert.match(storageTopology, /function _buildStorageTopology\(/);
    assert.match(storageTopology, /function _storageInfo\(/);
    assert.match(storageTopology, /function _drawStorageAccountCard\(/);
    assert.match(subnetResourceTree, /var SubnetResourceTree=/);
    assert.match(subnetResourceTree, /function buildResTree\(/);
    assert.match(subnetResourceTree, /function subMaxChildren\(/);
    assert.match(resourceList, /function openResourceList\(/);
    assert.match(search, /var SearchPanel = /);
    assert.match(search, /function open\(/);
    assert.match(projectFileIo, /function saveProject\(/);
    assert.match(reportImport, /function importReport\(/);
    assert.match(folderImport, /function importFolder\(/);
    assert.match(folderImport, /AppProjectFiles\.chooseDirectory/);
    assert.match(desktopAzureAdapter, /var DesktopAzureAdapter = /);
    assert.match(desktopAzureAdapter, /function createDesktopAzureAdapter\(/);
    assert.match(desktopAzureAdapter, /scanAzure/);
    assert.match(timelineNotes, /function openTimeline\(/);
    assert.match(timelineNotes, /function openNotesPanel\(/);
    assert.match(timelineNotes, /function _renderNotesPanel\(/);
    assert.match(timelineNotes, /function _renderNoteBadges\(/);
    assert.match(firewallDashboardModel, /var FirewallDashboardModel = /);
    assert.match(firewallDashboardModel, /buildViewModel/);
    assert.match(firewallChangeSet, /function firewallRuntimeContext\(/);
    assert.match(firewallChangeSet, /function _fwValidateNaclRule\(/);
    assert.match(firewallChangeSet, /function _fwGenerateCli\(/);
    assert.match(firewallChangeSet, /function _fwTakeSnapshot\(/);
    assert.match(governanceClassification, /var GovernanceClassification=/);
    assert.match(governanceClassification, /function runClassificationEngine\(/);
    assert.match(governanceClassification, /function ensureClassificationData\(/);
    assert.match(governanceClassification, /function resetClassificationData\(/);
    assert.match(governanceClassification, /function setClassificationOverride\(/);
    assert.match(governanceClassification, /function _scoreClassification\(/);
    assert.match(governanceClassification, /const _TIER_RPO_RTO=/);
    assert.match(governanceInventoryModel, /var GovernanceInventoryModel = /);
    assert.match(governanceInventoryModel, /function buildInventoryData\(/);
    assert.match(governanceInventoryModel, /function filterInventory\(/);
    assert.match(governanceIamReview, /var GovernanceIAMReview=/);
    assert.match(governanceIamReview, /function prepareIAMReviewData\(/);
    assert.match(governanceIamReview, /function openIAMPrincipalPanel\(/);
    assert.match(governanceIamReview, /function canDo\(/);
    assert.match(flowTracingPanel, /var FlowTracingPanel = /);
    assert.match(flowTracingPanel, /function renderSingle\(/);
    assert.match(flowTracingPanel, /function renderMulti\(/);
    assert.match(flowTracingRuntime, /FlowTracingPanel\.renderSingle/);
    assert.match(flowTracingRuntime, /FlowTracingPanel\.renderMulti/);
    assert.match(flowAnalysisPanel, /var FlowAnalysisPanel = /);
    assert.match(flowAnalysisPanel, /function render\(/);
    assert.match(flowAnalysisPanel, /launchTraceFromButton/);
    assert.match(flowAnalysisDashboard, /var FlowAnalysisDashboard = /);
    assert.match(flowAnalysisDashboard, /function buildRows\(/);
    assert.match(flowAnalysisDashboard, /function open\(/);
    assert.match(flowAnalysisRuntime, /FlowAnalysisPanel\.render/);
    assert.match(flowAnalysisRuntime, /FlowAnalysisDashboard\.open/);
    assert.match(dashboardState, /var DashboardState = /);
    assert.match(dashboardState, /function createDashboardState\(/);
    assert.match(dashboardState, /function _udashFilterByAccount\(/);
    assert.match(dashboard, /function openUnifiedDash\(/);
    assert.match(dashboard, /GovernanceClassification\.ensure/);
    assert.match(budrDashboard, /function openBUDRDash\(/);
    assert.match(budrDashboard, /function _renderBUDRDash\(/);
    assert.match(reportHtmlAssets, /function _rptCSS\(/);
    assert.match(reportHtmlAssets, /function _rptInteractiveJS\(/);
    assert.match(reportHtmlAssets, /function _rptBuildToolbar\(/);
    assert.match(reportHtmlAssets, /function _rptCollectStyles\(/);
    assert.doesNotMatch(reportRenderFunctions, /function _rptCSS\(/);
    assert.match(reportRenderFunctions, /function _rptExecSummary\(/);
    assert.match(reportRenderFunctions, /function _rptInventory\(/);
    assert.match(reportDashboard, /function openReportBuilder\(/);
    assert.match(reportDashboard, /function _renderReportsTab\(/);
    assert.match(reportDashboard, /function _renderRptPicker\(/);
    assert.match(reportDashboard, /function _renderRptPreview\(/);
    assert.match(reports, /async function _generateReport\(/);
    assert.match(reports, /async function _generateDocx\(/);
    assert.doesNotMatch(reports, /async function _generateXlsx\(/);
    assert.match(reportXlsx, /async function _generateXlsx\(/);
    assert.match(reportXlsx, /async function _exportFullXlsx\(/);
    assert.match(reportXlsx, /function _rptBuildXlsxSummary\(/);
    assert.match(exportToolbar, /function exportUtilitiesNotify\(/);
    assert.match(exportToolbar, /function updateDetailBtns\(/);
    assert.match(mapPngExport, /document\.getElementById\('expPng'\)/);
    assert.match(vsdxNetworkExport, /document\.getElementById\('expVsdx'\)/);
    assert.match(lucidExportPackage, /async function buildLucidZip\(/);
    assert.match(lucidExportPackage, /document\.getElementById\('expLucidDl'\)/);
    assert.match(lucidNetworkExportData, /var LucidNetworkExportData = /);
    assert.match(lucidNetworkExportData, /function collect\(/);
    assert.match(lucidNetworkExportData, /function buildRelationshipIndexes\(/);
    assert.match(lucidNetworkExportData, /function buildGatewayGroups\(/);
    assert.match(lucidLandingZoneExport, /function buildLandingZoneLayout\(/);
    assert.match(lucidNetworkExport, /LucidNetworkExportData\.collect/);
    assert.match(lucidNetworkExport, /function buildLucidExport\(/);
  });
});
