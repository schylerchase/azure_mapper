import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { runComplianceChecks, clearComplianceCache } from '../../src/modules/compliance-engine.js';
import { runBUDRChecks, budrAssessments } from '../../src/modules/budr-engine.js';
import { runBUDRAzureChecks } from '../../src/modules/compliance-budr-azure-checks.js';
import { runFedRAMPChecks } from '../../src/modules/compliance-fedramp-checks.js';
import { setCloudEnv, getCloudEnv } from '../../src/modules/cloud-env.js';

const source = name => readFileSync(`src/modules/${name}`, 'utf8');
const sheetSandbox = vm.createContext({ TextDecoder, TextEncoder, Uint8Array, ArrayBuffer });
vm.runInContext(readFileSync('libs/xlsx.bundle.min.js', 'utf8'), sheetSandbox);
const XLSX = sheetSandbox.XLSX;
const base = '/subscriptions/sub-A/resourceGroups/rg/providers/';

describe('assessment regressions from the browser rescan', () => {
  it('uses snapByVol from the renderer for VM protection and snapshot age', () => {
    const disk = base + 'Microsoft.Compute/disks/os';
    const ctx = {
      vms: [{ id: base + 'Microsoft.Compute/virtualMachines/vm', name: 'vm', properties: {
        storageProfile: { osDisk: { managedDisk: { id: disk } }, dataDisks: [] }
      } }],
      snapByVol: { [disk]: [{ properties: { timeCreated: new Date().toISOString() } }] }
    };
    const findings = runBUDRChecks(ctx);
    assert.equal(findings.some(f => f.control === 'BUDR-BAK-2'), false);
    assert.equal(budrAssessments[0].signals.Snapshots, true);
    assert.equal(budrAssessments[0].signals.SnapAgeDays, 0);
    assert.equal(budrAssessments[0].profile.tier, 'partial');
  });

  it('distinguishes missing SQL retention from an explicit zero in both active engines', () => {
    const registry = vm.createContext({ GovernanceClassification: { ensure: () => [] } });
    vm.runInContext(source('budr-report-registry.js'), registry);
    const runners = [
      ctx => ({ findings: runBUDRChecks(ctx), assessment: budrAssessments[0] }),
      ctx => ({ findings: registry.runBUDRChecks(ctx), assessment: vm.runInContext('_budrAssessments[0]', registry) })
    ];
    for (const run of runners) {
      for (const retention of [undefined, null, '', 0, 7]) {
        const ctx = { sqlServers: [{ id: base + 'Microsoft.Sql/servers/sql', name: 'sql', properties: {
          ...(retention === undefined ? {} : { backupRetentionDays: retention })
        } }] };
        const { findings, assessment } = run(ctx);
        const missing = retention === undefined || retention === null || retention === '';
        assert.equal(findings.some(f => f.control === 'BUDR-BAK-1'), retention === 0);
        assert.equal(assessment.profile.tier, missing ? 'unknown' : retention === 0 ? 'at_risk' : 'partial');
        if (missing) {
          assert.equal(assessment.profile.rpo, 'Unknown');
          assert.equal(assessment.signals.Backup, 'Unknown');
          assert.equal(assessment.compliance.status, 'unknown');
          assert.match(ctx.assessmentGaps.sqlBackupRetention, /not collected/);
        }
      }
    }
  });

  it('recognizes every geo-redundant storage SKU while retaining local-only findings', () => {
    for (const sku of ['Standard_GRS', 'Standard_RAGRS', 'Standard_GZRS', 'Standard_RAGZRS', 'Standard_LRS', 'Standard_ZRS']) {
      const findings = runBUDRAzureChecks({ storageAccounts: [{ name: 'storage', sku: { name: sku } }] });
      assert.equal(findings.some(f => f.id === 'BUDR-GEO'), /_(LRS|ZRS)$/.test(sku), sku);
    }
  });

  it('guards government absence findings but assesses explicitly collected empty evidence', () => {
    for (const evidence of [{}, { logAnalyticsWorkspaces: [], defenderPlans: [], collectionStatus: {
      logAnalyticsWorkspaces: 'failed', defenderPlans: 'failed'
    } }]) {
      const findings = runFedRAMPChecks(evidence, 'FEDRAMP_MOD');
      assert.equal(findings.some(f => f.id === 'FEDRAMP-AU2' || f.id === 'FEDRAMP-SI4'), false);
      assert.ok(evidence.assessmentGaps.logAnalyticsWorkspaces);
      assert.ok(evidence.assessmentGaps.defenderPlans);
    }
    const findings = runFedRAMPChecks({ logAnalyticsWorkspaces: [], defenderPlans: [] }, 'FEDRAMP_MOD');
    assert.ok(findings.some(f => f.id === 'FEDRAMP-AU2'));
    assert.ok(findings.some(f => f.id === 'FEDRAMP-SI4'));
  });

  it('recomputes the public compliance API when the same context changes cloud', () => {
    clearComplianceCache();
    const ctx = { nsgs: [{ properties: { securityRules: [{ properties: {
      direction: 'Inbound', access: 'Allow', protocol: '*', destinationPortRange: '*', sourceAddressPrefix: '*'
    } }] } }] };
    const commercial = runComplianceChecks(ctx, 'commercial');
    const gcc = runComplianceChecks(ctx, 'gcc');
    assert.equal(commercial.some(f => f.framework === 'FEDRAMP_MOD'), false);
    assert.ok(gcc.some(f => f.framework === 'FEDRAMP_MOD'));
  });

  it('restores assessment gaps on cache hits and changes the active wrapper cache with cloud', () => {
    let calls = 0;
    const cachedBudr = [{ id: 'sql' }];
    const sandbox = vm.createContext({
      document: { querySelectorAll: () => [{ id: 'in_nsgs', value: '[]' }] },
      AppModules: { getCloudEnv },
      GovernanceClassification: { reset() {} },
      gv: () => '', safeParse: () => null,
      _budrFindings: [], _budrAssessments: cachedBudr,
      appShellSetComplianceFindings() {},
      runComplianceChecks(ctx) { calls++; ctx.assessmentGaps = { defenderPlans: 'Not collected' }; return [{ framework: getCloudEnv() }]; }
    });
    const shell = source('app-shell.js');
    vm.runInContext(shell.slice(shell.indexOf("let _complianceDataFP="), shell.indexOf('// #endregion INITIALIZATION & GLOBALS')), sandbox);
    setCloudEnv('commercial');
    sandbox._runComplianceWithCache({});
    const freshCtx = {};
    sandbox._runComplianceWithCache(freshCtx);
    assert.equal(calls, 1);
    assert.equal(freshCtx.assessmentGaps.defenderPlans, 'Not collected');
    setCloudEnv('gcc');
    assert.equal(sandbox._runComplianceWithCache({})[0].framework, 'gcc');
    assert.equal(calls, 2);
    setCloudEnv('commercial');
  });
});

describe('account-filtered report IAM exports', () => {
  it('scopes HTML, DOCX, workbook rows, and embedded/importable data', () => {
    let account = 'sub-A';
    const principal = (sub, name, tagged = true) => ({ name, type: 'User', provider: 'azure',
      ...(tagged ? { _subscriptionId: sub } : {}), roleName: 'Owner', scope: '/subscriptions/' + sub,
      isAdmin: true, findings: [], crossAccounts: [], policies: 1, hasMFA: null, hasConsole: null,
      created: null, lastUsed: null
    });
    const sandbox = vm.createContext({
      XLSX, Date, MUTE_KEY: 'mute',
      document: { getElementById: () => ({ get value() { return account; } }) },
      esc: value => String(value ?? ''),
      _importedReportData: {}, _iamReviewData: [principal('sub-A', 'owner-A', false), principal('sub-B', 'owner-B')],
      _loadedContexts: [{ accountId: 'sub-A', accountLabel: 'A' }, { accountId: 'sub-B', accountLabel: 'B' }],
      _budrAssessments: [], _budrFindings: [], _inventoryData: [], _appRegistry: [],
      _rptState: { title: 'Scoped report' }
    });
    vm.runInContext(source('report-render-functions.js') + '\n' + source('report-builder.js') + '\n' + source('report-xlsx-export.js'), sandbox);
    for (account of ['sub-A', 'sub-B', 'all']) {
      const wanted = account === 'all' ? ['owner-A', 'owner-B'] : [account === 'sub-A' ? 'owner-A' : 'owner-B'];
      for (const text of [sandbox._rptIAMReview(), sandbox._docxIAMReview(false), sandbox._docxIAMReview(true)]) {
        for (const name of ['owner-A', 'owner-B']) assert.equal(text.includes(name), wanted.includes(name));
      }
      const embedded = sandbox._rptEmbedDataBlob(['iam-review']);
      const blob = JSON.parse(embedded.match(/\n(\{.*\})\n/)[1]);
      assert.deepEqual(blob.iamReviewData.map(p => p.name), wanted);
      assert.equal(blob.contexts.length, account === 'all' ? 2 : 1);
      const wb = XLSX.utils.book_new();
      sandbox._rptBuildXlsxIAMReview(wb);
      const exported = XLSX.read(XLSX.write(wb, { type: 'array', bookType: 'xlsx' }), { type: 'array' });
      assert.deepEqual(Array.from(XLSX.utils.sheet_to_json(exported.Sheets['IAM Review']), r => r.Name), wanted);
    }
  });
});
