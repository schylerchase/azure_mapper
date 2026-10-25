import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import { _normalizeAzureResources } from '../../src/modules/normalization.js';
import { runBUDRChecks as runPublicBUDRChecks, budrAssessments } from '../../src/modules/budr-engine.js';

const require = createRequire(import.meta.url);
const Inventory = require('../../src/modules/governance-inventory-model.js');
const source = name => readFileSync(`src/modules/${name}`, 'utf8');
const base = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/results/providers/';
const resource = (type, name, properties = {}) => ({
  id: base + type + '/' + name, type, name, location: 'eastus',
  tags: { Environment: 'prod' }, properties
});

function registrySandbox() {
  const sandbox = vm.createContext({ structuredClone, gn: (r, id) => r.name || id });
  vm.runInContext(source('governance-classification.js') + '\n' + source('budr-report-registry.js'), sandbox);
  return sandbox;
}

function runners() {
  const sandbox = registrySandbox();
  return [
    ctx => {
      sandbox.GovernanceClassification.reset();
      const findings = sandbox.runBUDRChecks(ctx);
      return { findings, assessments: vm.runInContext('_budrAssessments', sandbox) };
    },
    ctx => ({ findings: runPublicBUDRChecks(ctx), assessments: budrAssessments })
  ];
}

function nativeContext() {
  const ctx = {
    functionApps: [resource('Microsoft.Web/sites', 'function', { siteConfig: { linuxFxVersion: 'NODE|20' } })],
    containerInstances: [resource('Microsoft.ContainerInstance/containerGroups', 'sidecar', {
      osType: 'Linux', containers: [{ name: 'app' }, { name: 'logging-sidecar' }]
    })],
    appGateways: [resource('Microsoft.Network/applicationGateways', 'gateway')],
    redisCaches: [resource('Microsoft.Cache/Redis', 'redis', {
      replicasPerMaster: 1, redisConfiguration: { 'rdb-backup-enabled': 'false', 'aof-backup-enabled': 'false' }
    })],
    synapseWorkspaces: [resource('Microsoft.Synapse/workspaces', 'synapse', {
      managedVirtualNetworkSettings: { preventDataExfiltration: true },
      workspaceRepositoryConfiguration: { type: 'WorkspaceGitHubConfiguration', repositoryName: 'repo' }
    })]
  };
  _normalizeAzureResources({
    lambdaFns: ctx.functionApps, ecsServices: ctx.containerInstances, albs: ctx.appGateways,
    ecacheClusters: ctx.redisCaches, redshiftClusters: ctx.synapseWorkspaces
  });
  return ctx;
}

describe('third rescan native inventory identity regressions', () => {
  it('joins native inventory to current classification, BUDR, and compliance through ARM IDs', () => {
    const ctx = nativeContext();
    const sandbox = registrySandbox();
    sandbox.runBUDRChecks(ctx);
    const resources = Object.values(ctx).filter(Array.isArray).flat();
    const rows = Inventory.buildInventoryData(ctx, {
      classificationData: sandbox.GovernanceClassification.data,
      budrAssessments: vm.runInContext('_budrAssessments', sandbox),
      complianceFindings: resources.map(r => ({ resource: r.name, resourceId: r.id, status: 'FAIL' }))
    });
    assert.equal(rows.length, 5);
    for (const r of resources) {
      const row = rows.find(item => item.id === r.id);
      assert.ok(row, `inventory must retain ${r.type} ARM ID`);
      assert.equal(row.name, r.name);
      assert.equal(row.classificationTier, 'critical');
      assert.notEqual(row.budrTier, null);
      assert.equal(row.complianceFail, 1);
    }
  });
});

describe('third rescan BUDR evidence regressions in dashboard and public engines', () => {
  it('reads explicit RDB/AOF string booleans without changing known replica protection', () => {
    for (const run of runners()) {
      for (const [rdb, aof, expected] of [
        ['false', 'false', false], ['true', 'false', true], ['false', 'true', true],
        [false, false, false], [' FALSE ', 'TRUE', true], ['false', undefined, 'Unknown']
      ]) {
        const ctx = { redisCaches: [resource('Microsoft.Cache/Redis', 'redis', {
          replicasPerMaster: 1,
          redisConfiguration: { 'rdb-backup-enabled': rdb, 'aof-backup-enabled': aof }
        })] };
        const { findings, assessments } = run(ctx);
        const assessment = assessments[0];
        assert.equal(assessment.signals.Persistence ?? assessment.signals.Snapshots, expected);
        assert.equal(assessment.profile.tier, 'protected');
        assert.equal(findings.some(f => f.control === 'BUDR-BAK-3'), false);
      }
    }
  });

  it('keeps uncollected Redis persistence unknown while retaining observed replicas', () => {
    for (const run of runners()) {
      for (const replicasPerMaster of [0, 1]) {
        const ctx = { redisCaches: [resource('Microsoft.Cache/Redis', 'redis', { replicasPerMaster })] };
        const { findings, assessments } = run(ctx);
        assert.equal(assessments[0].signals.Persistence ?? assessments[0].signals.Snapshots, 'Unknown');
        assert.equal(assessments[0].profile.tier, replicasPerMaster ? 'protected' : 'unknown');
        assert.equal(findings.some(f => f.control === 'BUDR-BAK-3' || f.control === 'BUDR-TIER-RPO'), false);
        assert.ok(ctx.assessmentGaps.redisPersistence);
      }
    }
  });

  it('does not promote one native ACI group when a sidecar is added', () => {
    for (const run of runners()) {
      for (const count of [1, 2]) {
        const ctx = { containerInstances: [resource('Microsoft.ContainerInstance/containerGroups', 'group', {
          osType: 'Linux', containers: Array.from({ length: count }, (_, i) => ({ name: i ? 'sidecar' : 'app' }))
        })] };
        const { findings, assessments } = run(ctx);
        assert.equal(assessments[0].profile.tier, 'unknown');
        assert.equal(assessments[0].profile.rto, 'Unknown');
        assert.equal(assessments[0].profile.rpo, 'Unknown');
        assert.equal(assessments[0].signals.IndependentGroups, 'Unknown');
        assert.equal(findings.some(f => f.control === 'BUDR-HA-3' || f.control === 'BUDR-TIER-RPO'), false);
        assert.ok(ctx.assessmentGaps.containerGroupRecovery);
      }
    }
  });

  it('does not infer Synapse data recovery from networking, a managed resource group, or Git integration', () => {
    for (const run of runners()) {
      const ctx = { synapseWorkspaces: [resource('Microsoft.Synapse/workspaces', 'workspace', {
        managedResourceGroupName: 'managed-rg',
        managedVirtualNetworkSettings: { preventDataExfiltration: true },
        workspaceRepositoryConfiguration: { type: 'WorkspaceGitHubConfiguration', repositoryName: 'repo' }
      })] };
      const { findings, assessments } = run(ctx);
      assert.equal(assessments[0].profile.tier, 'unknown');
      assert.equal(assessments[0].profile.rto, 'Unknown');
      assert.equal(assessments[0].profile.rpo, 'Unknown');
      assert.equal(assessments[0].compliance.status, 'unknown');
      assert.ok(ctx.assessmentGaps.synapseProtection);
      assert.equal(findings.some(f => f.control === 'BUDR-BAK-4' || f.control === 'BUDR-TIER-RPO'), false);
      for (const value of Object.values(assessments[0].signals)) assert.notEqual(value, true);
    }
  });
});

describe('third rescan generated report regressions', () => {
  it('exports corrected evidence and canonical inventory IDs in HTML and a serialized workbook', () => {
    const sandbox = registrySandbox();
    const ctx = nativeContext();
    sandbox.runBUDRChecks(ctx);
    Object.assign(sandbox, {
      Uint8Array, ArrayBuffer, TextEncoder, TextDecoder, Date, MUTE_KEY: 'mute',
      _SEV_ORDER: { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 },
      document: { getElementById: () => null }, esc: value => String(value ?? ''),
      _loadedContexts: [], _importedReportData: null, _rptState: { title: 'Evidence report' },
      AppRenderContext: { createRenderContext: () => ({ rlCtx: ctx, complianceFindings: [] }) },
      GovernanceInventoryModel: Inventory,
      _inventoryData: Inventory.buildInventoryData(ctx), _rptTagName: (r, id) => r.name || id
    });
    vm.runInContext(readFileSync('libs/xlsx.bundle.min.js', 'utf8'), sandbox);
    vm.runInContext(source('report-html-assets.js') + '\n' + source('report-render-functions.js') + '\n' + source('report-builder.js') + '\n' + source('report-xlsx-export.js'), sandbox);
    const html = sandbox._rptBUDR();
    assert.match(html, /Persistence:false/);
    assert.match(html, /IndependentGroups:Unknown/);
    assert.match(html, /Backup:Unknown, DR:Unknown/);
    const wb = sandbox.XLSX.utils.book_new();
    sandbox._rptBuildXlsxBUDR(wb);
    sandbox._rptBuildXlsxInventory(wb);
    const readback = sandbox.XLSX.read(sandbox.XLSX.write(wb, { type: 'array', bookType: 'xlsx' }), { type: 'array' });
    const budr = sandbox.XLSX.utils.sheet_to_json(readback.Sheets.BUDR);
    assert.equal(budr.filter(r => r['DR Tier'] === 'unknown').length, 2);
    assert.match(budr.find(r => r.Name === 'redis')['Backup Signals'], /Persistence: false/);
    const inventory = sandbox.XLSX.utils.sheet_to_json(readback.Sheets.Inventory);
    assert.ok(inventory.every(r => r.ID.startsWith(base)));
  });
});
