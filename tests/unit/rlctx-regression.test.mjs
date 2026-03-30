import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const MODULES_DIR = join(import.meta.dirname, '../../src/modules');

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

  it('correct Azure-named _rlCtx keys exist in codebase', () => {
    const expectedKeys = [
      'vnets', 'subnets', 'nsgs', 'nics', 'natGateways',
      'privateEndpoints', 'vms', 'appGateways', 'firewalls',
      'sqlServers', 'redisCaches'
    ];
    // Read app-core.js to verify these keys are used
    const appCore = readFileSync(join(MODULES_DIR, '../app-core.js'), 'utf8');
    for (const key of expectedKeys) {
      assert.ok(
        appCore.includes(`_rlCtx.${key}`),
        `Expected _rlCtx.${key} to be used in app-core.js`
      );
    }
  });
});

describe('Dashboard module structure (R1.7 structural check)', () => {
  it('dashboards.js exists and contains rendering functions', () => {
    const content = readFileSync(join(MODULES_DIR, 'dashboards.js'), 'utf8');
    assert.ok(content.length > 100, 'dashboards.js should have substantial content');
    assert.ok(
      content.includes('function') || content.includes('=>'),
      'dashboards.js should contain function definitions'
    );
  });

  it('unified-dashboard.js exists and contains rendering functions', () => {
    const content = readFileSync(join(MODULES_DIR, 'unified-dashboard.js'), 'utf8');
    assert.ok(content.length > 100, 'unified-dashboard.js should have substantial content');
    assert.ok(
      content.includes('function') || content.includes('=>'),
      'unified-dashboard.js should contain function definitions'
    );
  });
});
