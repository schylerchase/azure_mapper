# Phase 2: Automated Test Suite - Research

**Researched:** 2026-03-30
**Domain:** Node.js test infrastructure, app-core.js normalization pipeline, _rlCtx data model
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None — auto-generated infrastructure phase. All implementation choices at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure/testing phase. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

### Deferred Ideas (OUT OF SCOPE)
None — infrastructure phase.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| R1.1 | Unit tests for normalization layer (_normalizeAzureResources) | Function is in app-core.js (not exported); must be extracted to a module or tested inline via a wrapper file |
| R1.2 | Unit tests for ext() function with flat arrays, wrapped objects, and edge cases | ext() is exported from src/modules/utils.js; already partially tested in utils.test.mjs — needs flat-array and wrapped edge case coverage |
| R1.3 | Unit tests for tag normalization (Azure object -> AWS array format) | _normTags is a nested function inside _normalizeAzureResources; same extraction challenge as R1.1 |
| R1.4 | Unit tests for _friendlyFolderLabel extraction | _friendlyFolderLabel is in app-core.js (not exported); must be extracted |
| R1.5 | Unit tests for matchFile with flat Azure CLI exports | matchFile is in app-core.js (not exported); must be extracted |
| R1.6 | Integration test: load real Azure export folder, verify _rlCtx keys populated | Real export folders exist at repo root; use `_buildRlCtxFromData` or equivalent to drive the test |
| R1.7 | Integration test: verify all dashboard tabs render without errors | DOM-heavy; must use Playwright or headless Electron — cannot unit test without a browser |
| R1.8 | Regression test: verify no _rlCtx key mismatches (programmatic check) | `_rlCtx` creation keys are well-documented; static analysis or a runtime key-audit test is feasible |
</phase_requirements>

---

## Summary

The project already has a functioning two-runner test infrastructure: `node:test` for `.mjs` unit tests under `tests/unit/` and Jest for `routing.test.js` and `main-utils.test.js`. All 232 unit tests and 95 Jest tests pass. No new test runner is needed.

The central challenge of this phase is that `_normalizeAzureResources`, `matchFile`, and `_friendlyFolderLabel` are private functions inside `src/app-core.js` — an esbuild IIFE entry point that is not importable as a module. These three functions must be extracted into a new testable module (e.g., `src/modules/normalization.js`) before unit tests can be written for them. This is the only code change required and is a pure refactor with no behavioral change.

The `_rlCtx` regression test (R1.8) is feasible as a static string-search audit: scan all `src/modules/*.js` files for patterns `_rlCtx\.(vpcs|sgs|nacls|enis|igws|nats|vpces|instances|albs|rdsInstances|ecsServices|lambdaFns|ecacheClusters|redshiftClusters)` (the old AWS-internal variable names) and assert zero matches. This is the programmatic version of the fix made in commit `64d6914`.

**Primary recommendation:** Extract the three untestable functions into `src/modules/normalization.js`, write `node:test` `.mjs` tests following the existing pattern, and add a regression test that programmatically scans for stale `_rlCtx` key names.

---

## Project Constraints (from CLAUDE.md)

| Directive | Applies to This Phase |
|-----------|----------------------|
| Functions < 30 lines | New helper functions in normalization.js must stay under 30 lines each |
| Files < 300 lines | normalization.js will be long (the normalization function is ~50 lines); acceptable since it's a pure extraction |
| Nesting max 3 levels | Review normalization.js extraction for deep nesting |
| Never commit secrets | No secrets risk in test infrastructure |
| Handle errors at boundaries | Test helpers should not swallow assertion errors |
| Git: show summary and wait for yes before committing | Planner must include commit-approval step |

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| node:test | built-in (Node 22.17.1) | Unit/integration test runner | Already used in tests/unit/*.test.mjs; zero deps |
| node:assert/strict | built-in | Assertions | Already used throughout existing unit tests |
| Jest | 29.7.0 (installed) | Legacy test runner for routing.test.js, main-utils.test.js | Already in package.json; do NOT expand its scope |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| fs (node:fs) | built-in | Read real export folder JSON in integration test | R1.6 integration test only |
| path (node:path) | built-in | Resolve export folder paths | R1.6 integration test only |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| node:test | vitest | vitest 4.1.2 IS installed globally (npx vitest works), but the project convention is node:test for unit tests; mixing runners adds complexity with no benefit |
| node:test | Jest | Jest is already present but configured only for routing/main-utils; expanding Jest scope would require ESM config work due to the MODULE_TYPELESS_PACKAGE_JSON warnings |

**Installation:** No new packages required. All test dependencies are already present.

---

## Architecture Patterns

### Recommended Project Structure
```
src/modules/normalization.js     # NEW: extracted functions from app-core.js
tests/unit/
├── normalization.test.mjs       # R1.1, R1.2, R1.3, R1.4, R1.5
├── integration.test.mjs         # R1.6 (load real export folder, verify _rlCtx)
└── rlctx-regression.test.mjs    # R1.8 (static key audit)
```
R1.7 (dashboard tab rendering) requires Playwright — it belongs in `tests/` alongside existing Playwright specs.

### Pattern 1: node:test .mjs Unit Test File
**What:** Each test file uses `import { describe, it } from 'node:test'` + `import assert from 'node:assert/strict'`
**When to use:** All new unit and integration tests
**Example:**
```javascript
// Source: tests/unit/utils.test.mjs (existing pattern)
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { myFunction } from '../../src/modules/normalization.js';

describe('myFunction', () => {
  it('handles the happy path', () => {
    assert.deepEqual(myFunction(input), expected);
  });
});
```

### Pattern 2: DOM-guard for Modules with Event Listeners
**What:** Modules with top-level `document.addEventListener` calls guard them with `if (typeof document !== 'undefined')`
**When to use:** When extracting code from app-core.js that has DOM side effects
**Example:**
```javascript
// Source: src/modules/diff-engine.js (existing pattern)
if (typeof document !== 'undefined') {
  document.getElementById('compareBtn').addEventListener('click', handler);
}
```
normalization.js will have no DOM references, so this guard is not needed there.

### Pattern 3: Module Export Block at End of File
**What:** Pure functions are collected into a single `export {}` block at end of file
**When to use:** When extracting functions that are currently not exported
**Example:**
```javascript
// Source: src/modules/diff-engine.js line 2143
export {
  _normalizeAzureResources, _friendlyFolderLabel, matchFile, _normTags
};
```

### Pattern 4: Integration Test Using Real File Data
**What:** Load real Azure export folder JSON with `fs.readFileSync`, pass into the pipeline function
**When to use:** R1.6 integration test
**Example:**
```javascript
// Source: derived from _buildRlCtxFromData calling pattern
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const exportDir = join(import.meta.dirname, '../../azure-export-00b800a2-140e-4a89-94f9-ed6aab746a51-20260330-105511');
const vnetsJson = readFileSync(join(exportDir, 'vnets.json'), 'utf8');
```

### Pattern 5: Static Regression Test (R1.8)
**What:** Use `fs.readdirSync` + `fs.readFileSync` to scan module source files for forbidden key patterns
**When to use:** R1.8 _rlCtx key mismatch regression
**Example:**
```javascript
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const STALE_KEYS = ['_rlCtx.vpcs', '_rlCtx.sgs', '_rlCtx.nacls', '_rlCtx.enis',
  '_rlCtx.igws', '_rlCtx.nats[^G]', '_rlCtx.vpces', '_rlCtx.instances',
  '_rlCtx.albs', '_rlCtx.rdsInstances', '_rlCtx.ecsServices',
  '_rlCtx.lambdaFns', '_rlCtx.ecacheClusters', '_rlCtx.redshiftClusters'];
```

### Anti-Patterns to Avoid
- **Expanding Jest scope:** The MODULE_TYPELESS_PACKAGE_JSON warning fires for all `src/modules/*.js` imports under Jest due to missing `"type": "module"`. Adding `"type": "module"` to package.json would break the CommonJS test files (`routing.test.js`, `main-utils.test.js`). Do not change `"type"` in package.json.
- **Importing app-core.js directly:** It has no exports, is an IIFE entry point, and requires `document`, `window`, and bundled globals to be present. It is not importable in node:test.
- **Testing _normalizeAzureResources without extracting it:** The function must be moved to a module. Do not attempt to test it in-place.
- **Using vitest for new tests:** Already works globally but adds a new runner when node:test already serves the purpose.

---

## Critical Finding: Functions That Must Be Extracted

The following functions in `src/app-core.js` are needed for R1.1–R1.5 but are NOT exported:

| Function | Line in app-core.js | Description |
|----------|-------------------|-------------|
| `_normalizeAzureResources(d)` | 8785 | Azure property mapping + tag normalization |
| `_normTags(r)` (nested) | 8787 | Tag format conversion: Azure object → [{Key,Value}] array |
| `matchFile(fname, content)` | 22932 | Maps filename/content to textarea input ID |
| `_friendlyFolderLabel(folderName)` | 11304 | Strips azure-export prefix + timestamp from folder name |

**Extraction plan:**
1. Create `src/modules/normalization.js`
2. Move the four functions verbatim
3. Export them from `normalization.js`
4. Import them back in `app-core.js` with `import { _normalizeAzureResources, matchFile, _friendlyFolderLabel } from './modules/normalization.js'`
5. Verify build still works (`npm run bundle`)

`_normTags` is a nested function inside `_normalizeAzureResources`. When extracted, it should become a module-level function in `normalization.js` and be called from `_normalizeAzureResources` directly.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| DOM mocking for R1.7 | Custom DOM shim | Playwright (already in package.json) | R1.7 requires real browser rendering; Playwright is already configured |
| File glob for integration test | Custom directory walker | `fs.readdirSync` | Simple case; one folder, one level deep |
| Test reporter | Custom TAP parser | node:test built-in TAP output | Already works with existing npm scripts |

**Key insight:** The project already has the right infrastructure — the gap is purely the missing module extraction.

---

## _rlCtx Object Structure (Authoritative)

The `_rlCtx` object is created at line 10822 of `src/app-core.js` and has these 49 keys:

**Azure-named (public) keys — use these when accessing _rlCtx:**
```
vnets, subnets, pubSubs, udrs, nsgs, subnetNsgs, nics, firewalls, natGateways,
privateEndpoints, vms, appGateways, tgs, peerings, vpns, volumes, snapshots,
s3bk, zones, wafAcls, wafByAlb, tgByAlb, cfByAlb, sqlServers, containerInstances,
functionApps, redisCaches, synapseWorkspaces, cfDistributions, instBySub, albBySub,
eniBySub, rdsBySub, ecsBySub, lambdaBySub, subRT, subNacl, nsgByVnet, volByInst,
snapByVol, ecacheByVpc, redshiftByVpc, vhubs, recsByZone, _multiTenant, _accounts,
_regions, _multiRegion, iamRoleResources
```

**IMPORTANT:** `_buildRlCtxFromData()` returns an object with OLD internal variable names (`vpcs`, `rts`, `sgs`, `nacls`, `enis`, `igws`, `nats`, `vpces`, `instances`, `albs`, `rdsInstances`, `ecsServices`, `lambdaFns`, `ecacheClusters`, `redshiftClusters`) — not the Azure-named keys. The R1.6 integration test should call `_buildRlCtxFromData` and check the keys it returns, or test via the extracted normalization pipeline directly.

**Regression keys to detect (R1.8):** Any module file that accesses `_rlCtx.vpcs`, `_rlCtx.sgs`, `_rlCtx.nacls`, `_rlCtx.enis`, `_rlCtx.igws`, `_rlCtx.nats` (but not `_rlCtx.natGateways`), `_rlCtx.vpces`, `_rlCtx.instances`, `_rlCtx.albs`, `_rlCtx.rdsInstances`, `_rlCtx.ecsServices`, `_rlCtx.lambdaFns`, `_rlCtx.ecacheClusters`, `_rlCtx.redshiftClusters` is using stale AWS-internal names. Fixed in commit `64d6914`.

---

## Test Data Available

| File | Format | Content |
|------|--------|---------|
| `_test_vnets.json` | Flat array (az CLI) | 4 VNets with subnets, tags, NSG refs |
| `_test_subnets.json` | Flat array | Subnets with addressPrefix, NSG refs |
| `_test_nsgs.json` | Flat array | NSGs with securityRules (large file) |
| `_test_nics.json` | Flat array | NICs with ipConfigurations, subnet refs |
| `_test_pubips.json` | Flat array | Public IPs with dnsSettings |
| `azure-export-00b800a2-.../` | Export folder | Real multi-VNet export; vnets.json has 4 VNets |
| `azure-export-3bfa3ead-.../` | Export folder | Second real export for multi-subscription testing |

Export folder file-to-input mapping (from `matchFile` patterns):
- `vnets.json` → `in_vnets`
- `subnets.json` → `in_subnets`
- `nsgs.json` → `in_nsgs`
- `nics.json` → `in_nics`
- `public-ips.json` → `in_pubips`
- `route-tables.json` → `in_udrs`
- `bastions.json` → `in_bastions`
- `app-gateways.json` → `in_albs`

---

## Common Pitfalls

### Pitfall 1: MODULE_TYPELESS_PACKAGE_JSON Warning
**What goes wrong:** All `node --test tests/unit/*.test.mjs` runs print a warning about package.json missing `"type": "module"`, causing performance overhead.
**Why it happens:** package.json has no `"type"` field, so Node.js re-parses each `.js` module as ES module after finding `import` syntax.
**How to avoid:** Add `"type": "module"` to package.json to suppress the warning — BUT this will break `routing.test.js` and `main-utils.test.js` which use `require()`. Instead, rename those two test files to `.cjs` and add `"type": "module"` to package.json. This is optional cleanup; the current warning does not fail tests.
**Warning signs:** The warning appears every run but does not cause failures.

### Pitfall 2: app-core.js is Not Importable
**What goes wrong:** Attempting `import ... from '../../src/app-core.js'` in a test will fail because app-core.js accesses `window`, `document`, `_prefs`, and other browser globals at module evaluation time.
**Why it happens:** app-core.js is an esbuild IIFE entry point, not a module. It is bundled, not imported.
**How to avoid:** Only import from `src/modules/*.js`. Extract needed functions before testing.

### Pitfall 3: _normTags is a Nested Function
**What goes wrong:** `_normTags` is defined inside `_normalizeAzureResources`, not at module level. It cannot be individually exported.
**Why it happens:** Original code kept related helpers local.
**How to avoid:** When extracting, promote `_normTags` to module-level function in `normalization.js`. It is a pure function with no closure dependencies.

### Pitfall 4: matchFile References fileMap (Large Top-Level Array)
**What goes wrong:** `matchFile` depends on `fileMap`, a 50+ entry array defined at lines 22870-22930 of app-core.js. Extracting `matchFile` requires extracting `fileMap` too.
**Why it happens:** Both are in app-core.js.
**How to avoid:** Extract both `fileMap` and `matchFile` together into `normalization.js`.

### Pitfall 5: R1.7 Cannot Be Unit Tested
**What goes wrong:** "Verify all dashboard tabs render without errors" requires DOM, SVG, and D3 rendering — none of which work in node:test.
**Why it happens:** All dashboard functions call `document.getElementById`, build SVG, and rely on the full initialized app state.
**How to avoid:** Implement R1.7 as a Playwright test. The Playwright infrastructure is already configured (`playwright.config.js`, `tests/*.spec.js`). Add a new `tests/dashboard-tabs.spec.js`.

### Pitfall 6: Integration Test For R1.6 Cannot Use _buildRlCtxFromData Directly
**What goes wrong:** `_buildRlCtxFromData` is inside app-core.js and not exported.
**Why it happens:** It uses dozens of variables from app-core.js scope.
**How to avoid:** The integration test for R1.6 should instead: (1) load the export folder JSON files as strings, (2) call `ext()` + `_normalizeAzureResources()` directly (after extraction), and verify that the normalized output has `VpcId` set on VNets, `CidrBlock` set on subnets, `Tags` array populated, etc. This tests the normalization pipeline without needing the full rendering context.

---

## Code Examples

### ext() Flat Array Fallback (Already Tested Partially)
```javascript
// Source: src/modules/utils.js lines 57-71
// The flat-array fallback fires when no keys match but the array contains
// Azure resource objects (has .id, .name, or .type):
ext([{id: '/subs/x/...', name: 'hub-vnet', type: 'Microsoft.Network/virtualNetworks'}], ['value'])
// → returns the array as-is (flat az CLI output path)
```

### _normTags Behavior
```javascript
// Source: src/app-core.js lines 8787-8791
// Input: Azure tags object { Environment: "prod", Owner: "team-a" }
// Output after _normTags: resource.Tags = [{ Key: "Environment", Value: "prod" }, { Key: "Owner", Value: "team-a" }]
// Edge case: no tags + has name → Tags = [{ Key: "Name", Value: resource.name }]
```

### matchFile Exact-Match Path
```javascript
// Source: src/app-core.js lines 22932-22968
matchFile('vnets.json', '[{"addressSpace":...}]')  // → 'in_vnets'
matchFile('subnets.json', '[{"addressPrefix":...}]')  // → 'in_subnets'
matchFile('nsgs.json', '[{"securityRules":...}]')  // → 'in_nsgs'
matchFile('UNKNOWN_FILE.json', '[{"securityRules":...}]')  // → 'in_nsgs' (content fallback)
```

### _friendlyFolderLabel Patterns
```javascript
// Source: src/app-core.js lines 11304-11316
_friendlyFolderLabel('azure-export-lmat-PROD-20260330-075242')  // → 'lmat-PROD'
_friendlyFolderLabel('azure-export-00b800a2-140e-4a89-94f9-ed6aab746a51-20260330-105511')  // → '00b800a2-140e...' (truncated GUID)
_friendlyFolderLabel('some-other-folder')  // → 'some-other-folder' (passthrough, under 30 chars)
_friendlyFolderLabel(null)  // → null
```

### R1.8 Regression Check Pattern
```javascript
// Scan src/modules/*.js for stale _rlCtx key accesses
const STALE_PATTERNS = [
  /_rlCtx\.vpcs\b/,
  /_rlCtx\.sgs\b/,
  /_rlCtx\.nacls\b/,
  /_rlCtx\.enis\b/,
  /_rlCtx\.igws\b/,
  /_rlCtx\.nats[^G]/,  // exclude natGateways
  /_rlCtx\.vpces\b/,
  /_rlCtx\.instances\b/,
  /_rlCtx\.albs\b/,
  /_rlCtx\.rdsInstances\b/,
  /_rlCtx\.ecsServices\b/,
  /_rlCtx\.lambdaFns\b/,
  /_rlCtx\.ecacheClusters\b/,
  /_rlCtx\.redshiftClusters\b/,
];
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Jest for all tests | node:test for module-level unit tests, Jest only for CJS files | Already in place | node:test has zero config; Jest needs transform config for ESM |
| Manual _rlCtx key audit | Programmatic regression test | Being added in this phase | Prevents recurrence of commit 64d6914 class of bugs |

**Deprecated/outdated:**
- Expanding Jest to cover ESM modules: Jest 29 supports ESM but requires `"transform": {}` (already in package.json!) plus `"type": "module"`. The current Jest config explicitly sets `"transform": {}` to disable transforms. This works for CJS but not for ESM imports.

---

## Open Questions

1. **Should normalization.js also extract `_buildRlCtxFromData`?**
   - What we know: The function is 130+ lines and depends on ~15 other app-core.js-scoped functions (`_isIgwRoute`, `detectAccountId`, `detectRegion`, `parseIAMData`).
   - What's unclear: Whether extracting the full pipeline is feasible without creating a large dependency chain.
   - Recommendation: Do NOT extract `_buildRlCtxFromData` in this phase. Test the normalization layer only (R1.1–R1.5). The integration test (R1.6) verifies key population by calling `_normalizeAzureResources` directly with fixture data.

2. **R1.7: Which dashboard tabs need to be verified?**
   - What we know: `tests/dashboard.spec.js` exists and covers some dashboard functionality.
   - What's unclear: Whether the existing Playwright spec covers all dock button tabs.
   - Recommendation: Review `tests/dashboard.spec.js` before writing the new R1.7 spec to avoid duplication.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| node:test | Unit tests | Yes | Node 22.17.1 (built-in) | — |
| node:assert | Unit tests | Yes | Node 22.17.1 (built-in) | — |
| jest | Jest test suite | Yes | 29.7.0 | — |
| Playwright | R1.7 | Yes | @playwright/test ^1.58.2 installed | — |
| esbuild | Build verification | Yes | ^0.27.3 installed | — |

No missing dependencies.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | node:test (Node.js 22.17.1 built-in) + Jest 29.7.0 |
| Config file | package.json ("jest" section; node:test is zero-config) |
| Quick run command | `node --test tests/unit/*.test.mjs` |
| Full suite command | `npm run test:all` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R1.1 | _normalizeAzureResources maps Azure properties to internal format | unit | `node --test tests/unit/normalization.test.mjs` | No — Wave 0 |
| R1.2 | ext() flat array fallback, wrapped object, edge cases | unit | `node --test tests/unit/normalization.test.mjs` | No — Wave 0 (extend utils.test.mjs or add to normalization.test.mjs) |
| R1.3 | Tag normalization Azure object → [{Key,Value}] array | unit | `node --test tests/unit/normalization.test.mjs` | No — Wave 0 |
| R1.4 | _friendlyFolderLabel extracts label from folder name | unit | `node --test tests/unit/normalization.test.mjs` | No — Wave 0 |
| R1.5 | matchFile maps filenames to input IDs (flat Azure CLI exports) | unit | `node --test tests/unit/normalization.test.mjs` | No — Wave 0 |
| R1.6 | Load real export folder JSON, verify normalized VNets/subnets populated | integration | `node --test tests/unit/integration.test.mjs` | No — Wave 0 |
| R1.7 | All dashboard tabs render without errors | e2e | `npx playwright test tests/dashboard-tabs.spec.js` | No — Wave 0 |
| R1.8 | Zero _rlCtx key mismatches in src/modules/*.js | regression (static) | `node --test tests/unit/rlctx-regression.test.mjs` | No — Wave 0 |

### Sampling Rate
- **Per task commit:** `node --test tests/unit/*.test.mjs`
- **Per wave merge:** `npm run test:all`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `src/modules/normalization.js` — extract _normalizeAzureResources, _normTags, matchFile, fileMap, _friendlyFolderLabel
- [ ] `tests/unit/normalization.test.mjs` — covers R1.1, R1.3, R1.4, R1.5 (R1.2 may extend utils.test.mjs)
- [ ] `tests/unit/integration.test.mjs` — covers R1.6
- [ ] `tests/unit/rlctx-regression.test.mjs` — covers R1.8
- [ ] `tests/dashboard-tabs.spec.js` — covers R1.7 (Playwright)

---

## Sources

### Primary (HIGH confidence)
- Direct code inspection: `src/app-core.js` lines 8785-8832, 11304-11316, 22932-23003, 10822 — normalization, folderLabel, matchFile, _rlCtx creation
- Direct code inspection: `src/modules/utils.js` — ext() function implementation
- Direct code inspection: `tests/unit/*.test.mjs` — existing test patterns
- Direct code inspection: `package.json` — installed deps, scripts, jest config
- Runtime verification: `node --test tests/unit/*.test.mjs` — 232 tests pass, 0 fail
- Runtime verification: `npm run test:jest` — 95 tests pass
- Runtime verification: `node --version` — v22.17.1 confirmed

### Secondary (MEDIUM confidence)
- Commit `64d6914` message — documents exact _rlCtx key mismatch problem and which files were affected (authoritative: git history)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — verified by runtime (`node --test` works, jest works, vitest available)
- Architecture: HIGH — all function locations verified by grep + line reads
- Pitfalls: HIGH — pitfall 1-4 verified by direct code inspection; pitfall 5-6 verified by runtime import attempt knowledge
- _rlCtx keys: HIGH — extracted programmatically from line 10822

**Research date:** 2026-03-30
**Valid until:** 2026-04-30 (stable codebase; functions change rarely)
