---
phase: 04-performance-optimization
verified: 2026-03-30T00:00:00Z
status: gaps_found
score: 5/8 must-haves verified
gaps:
  - truth: "Demo button still works (loads demo-data lazily on click)"
    status: failed
    reason: "app-core.js click handler calls generateDemo() as a bare identifier with no lazy-load guard. window._loadDemoData() is defined in main.js but never called from app-core.js. At click time, generateDemo is not on window, so the call throws ReferenceError."
    artifacts:
      - path: "src/app-core.js"
        issue: "Lines 23093, 27422, 27468, 27501, 27886, 28068, 28126 call generateDemo() synchronously. None call window._loadDemoData() first."
      - path: "src/main.js"
        issue: "window._loadDemoData defined at line 188 but never called from app-core.js"
    missing:
      - "Each generateDemo() call site in app-core.js must be wrapped: await window._loadDemoData() before first use, then call window.generateDemo()"
      - "The loadDemo click handler at line 23090 must be made async and await _loadDemoData before calling generateDemo()"
      - "window.generateDemoSnapshots, window.generateDemoBaseline, and related functions at lines 27421, 27467, 27500, 27885, 28067 must await _loadDemoData"

  - truth: "IaC generator modal still works (loads iac-generator lazily on click)"
    status: failed
    reason: "app-core.js IaC modal handler at line 27251 checks window.AppModules.IacGenerator but never calls window._loadIacGenerator(). window.AppModules.IacGenerator is not populated at startup (removed from AppModules in main.js line 172). Modal will silently produce no output."
    artifacts:
      - path: "src/app-core.js"
        issue: "Line 27251 checks window.AppModules.IacGenerator but it is null at startup; no _loadIacGenerator() call precedes it"
      - path: "src/main.js"
        issue: "window._loadIacGenerator defined at line 207 but never called from app-core.js"
    missing:
      - "IaC modal handler at line 27251 must call await window._loadIacGenerator() before accessing window.AppModules.IacGenerator"
      - "Handler function must be made async to support await"

  - truth: "Compliance checks run asynchronously via requestIdleCallback, not blocking render"
    status: failed
    reason: "04-02 Task 2 was explicitly deferred. The _deferComplianceUpdate function was never implemented. All three compliance call sites in app-core.js remain synchronous: lines 10779, 8443-area (landing zone stats bar), and 8751-area (header grid badge) all call _runComplianceWithCache() directly on the synchronous render path."
    artifacts:
      - path: "src/app-core.js"
        issue: "Line 10779: try{const findings=_runComplianceWithCache(_rlCtx);... — still synchronous. No _deferComplianceUpdate function exists. No requestIdleCallback wrapping compliance calls."
    missing:
      - "Implement _deferComplianceUpdate(ctx, sb2) function near line 340 in app-core.js"
      - "Replace synchronous compliance calls at lines 10779 and landing-zone stats bar with _deferComplianceUpdate(_rlCtx, sb2)"
      - "Cache-hit path may remain synchronous; cache-miss path must use requestIdleCallback with 2000ms timeout fallback"
---

# Phase 4: Performance Optimization Verification Report

**Phase Goal:** Reduce bundle size and improve render speed
**Verified:** 2026-03-30
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Production build reports per-module sizes via esbuild metafile | VERIFIED | dist/meta.json exists (8KB), 25 input modules tracked, written by build.js metafile:isProd config |
| 2 | demo-data.js and iac-generator.js are NOT in the initial app.bundle.js payload | VERIFIED | meta.json inputs list has 0 entries matching "demo-data" or "iac-generator"; both confirmed absent |
| 3 | Demo button still works (loads demo-data lazily on click) | FAILED | window._loadDemoData defined in main.js but never called from app-core.js; 7 direct generateDemo() calls remain in app-core.js with no lazy-load guard |
| 4 | IaC generator modal still works (loads iac-generator lazily on click) | FAILED | window._loadIacGenerator defined in main.js but never called from app-core.js; modal handler at line 27251 checks AppModules.IacGenerator which is null at startup |
| 5 | Render timing is logged for topologies with 10+ VNets | VERIFIED (deferred compliance) | 5 PERF log points in _renderMapInner cover parse, index build, layout calc, SVG draw, TOTAL — logs unconditionally for all renders, which is a superset of the 10+ VNet requirement |
| 6 | CIS Azure NSG checks run in a single nsgs.forEach loop instead of 5 separate loops | VERIFIED | compliance-engine.js line 223-229: single consolidated pass with comment "Single pass: CIS-9 (RDP), CIS-10 (SSH), CIS-12 (all inbound), CIS-DB (database ports), CIS-UDP (all UDP)" |
| 7 | Compliance engine produces identical findings before and after consolidation | VERIFIED | 273 unit tests pass (29 in compliance-engine.test.mjs, 0 failures) |
| 8 | Compliance checks run asynchronously via requestIdleCallback, not blocking render | FAILED | 04-02 Task 2 explicitly deferred; no _deferComplianceUpdate function; compliance calls at lines 10779, 8443, 8751 remain synchronous on the render path |

**Score:** 5/8 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dist/meta.json` | Bundle composition metadata | VERIFIED | 8KB file, 25 modules, written on production builds |
| `dist/demo-data.bundle.js` | Separate lazy bundle for demo data | VERIFIED | 89KB file exists |
| `dist/iac-generator.bundle.js` | Separate lazy bundle for IaC generator | VERIFIED | 108KB file exists |
| `build.js` | Metafile-enabled build with size reporting | VERIFIED | metafile:isProd, separate esbuild.build() for demo-data and iac-generator |
| `src/main.js` | Lazy loader functions on window | VERIFIED (partial) | window._loadDemoData (line 188) and window._loadIacGenerator (line 207) defined; but not wired to call sites |
| `src/modules/compliance-engine.js` | Consolidated single-pass NSG checks | VERIFIED | Single pass comment + single nsgs.forEach for CIS checks at line 229 |
| `src/app-core.js` | Lazy-load guards at generateDemo call sites | FAILED | 7 call sites use bare generateDemo() with no _loadDemoData guard |
| `src/app-core.js` | Deferred compliance via requestIdleCallback | FAILED | _deferComplianceUpdate not implemented; compliance call at line 10779 still synchronous |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| src/main.js | src/modules/demo-data.js | dynamic script injection in window._loadDemoData | VERIFIED | Loader defined at main.js line 188; injects dist/demo-data.bundle.js script tag |
| src/main.js | src/modules/iac-generator.js | dynamic script injection in window._loadIacGenerator | VERIFIED | Loader defined at main.js line 207; injects dist/iac-generator.bundle.js script tag |
| src/app-core.js | window._loadDemoData | async call before generateDemo() | FAILED | No call to window._loadDemoData in app-core.js; app-core.js calls generateDemo() directly at 7 sites |
| src/app-core.js | window._loadIacGenerator | async call before IacGenerator use | FAILED | No call to window._loadIacGenerator in app-core.js; IaC handler checks AppModules.IacGenerator which is null |
| src/app-core.js | compliance-engine.js | _runComplianceWithCache inside requestIdleCallback | FAILED | requestIdleCallback not used for compliance calls; calls are synchronous at lines 10779, 8443, 8751 |
| src/app-core.js | addComplianceChip | Called after idle callback fires | FAILED | No idle callback wrapping; addComplianceChip called synchronously from _runComplianceWithCache result |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| dist/demo-data.bundle.js | DemoDataModule.generateDemo | src/modules/demo-data.js (separate IIFE bundle) | Yes — returns full Azure topology fixture | HOLLOW_PROP — bundle exists and is real, but call site in app-core.js cannot reach it (no _loadDemoData call) |
| dist/iac-generator.bundle.js | IacGeneratorModule | src/modules/iac-generator.js (separate IIFE bundle) | Yes — real IaC generation | HOLLOW_PROP — bundle exists, AppModules.IacGenerator is null at startup, no _loadIacGenerator call |
| src/app-core.js compliance | findings array | _runComplianceWithCache -> compliance-engine.js | Yes — real DB traversal | FLOWING but synchronous (blocks render path) |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| dist/meta.json exists and has module data | test -f dist/meta.json && python3 -c "import json; d=json.load(open('dist/meta.json')); print(len(d.get('inputs',{})), 'inputs')" | 25 inputs | PASS |
| demo-data not in main bundle | python3 check meta.json inputs for demo-data | 0 matches | PASS |
| iac-generator not in main bundle | python3 check meta.json inputs for iac-generator | 0 matches | PASS |
| 273 unit tests pass | node --test tests/unit/*.test.mjs | 273 pass, 0 fail | PASS |
| Compliance single-pass present | grep -c "Single pass" compliance-engine.js | 1 match | PASS |
| app-core.js calls _loadDemoData | grep -c "_loadDemoData" src/app-core.js | 0 matches | FAIL |
| app-core.js calls _loadIacGenerator | grep -c "_loadIacGenerator" src/app-core.js | 0 matches | FAIL |
| compliance deferred to requestIdleCallback | grep compliance + requestIdleCallback check in app-core.js | no match | FAIL |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|---------|
| R3.1 | 04-01 | Bundle size audit — dist/meta.json with module sizes | SATISFIED | meta.json exists; build.js writes it on production builds; 25 modules tracked |
| R3.2 | 04-01, 04-02 | Profile render time — timing instrumentation | SATISFIED (deferred path) | 5 PERF log points in _renderMapInner cover full render pipeline unconditionally. Deferred compliance timing from 04-02 Task 2 was not implemented but the render profiling requirement is met. |
| R3.3 | 04-01 | Lazy load dashboard tabs — demo-data.js and iac-generator.js extracted to separate bundles | PARTIAL | Bundles extracted and exist (SATISFIED). Lazy loaders defined on window (SATISFIED). Call sites in app-core.js NOT updated to use lazy loaders (FAILED). The lazy loading infrastructure exists but is not actually invoked. |
| R3.4 | 04-02 | Compliance engine optimization — NSG passes consolidated from 5 to 1 | SATISFIED | compliance-engine.js line 223-229 has single consolidated nsgs.forEach for all CIS checks. 273 unit tests pass proving identical findings. The requestIdleCallback deferral (also in R3.4 plan) was not implemented but is not listed as the primary R3.4 requirement. |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| src/app-core.js | 23093 | `generateDemo()` bare call — function not on window at click time | BLOCKER | Demo button throws ReferenceError on first click |
| src/app-core.js | 27422, 27468, 27501, 27886, 28068, 28126 | 6 more `generateDemo()` calls without _loadDemoData guard | BLOCKER | All demo-related functions (generateDemoSnapshots, generateDemoBaseline) throw ReferenceError |
| src/app-core.js | 27251 | `window.AppModules.IacGenerator` checked but is null at startup | BLOCKER | IaC modal silently produces no output; condition `window.AppModules&&window.AppModules.IacGenerator` fails, falls to else branch |
| src/app-core.js | 10779 | `_runComplianceWithCache` called synchronously on render path | WARNING | Compliance blocks the render thread; no requestIdleCallback deferral implemented |

### Human Verification Required

None — all items were deterministically verified or falsified via code inspection and unit tests.

The following require browser testing to confirm actual runtime behavior of the failures found above:

#### 1. Demo Button Runtime Failure

**Test:** Open index.html in browser, click "Load Demo" button
**Expected:** ReferenceError: generateDemo is not defined (or similar) in browser console
**Why human:** Can only confirm the actual error message and user-visible behavior (spinner stuck, no map rendered, etc.) in a running browser

#### 2. IaC Modal Runtime Behavior

**Test:** Load a topology, open IaC Generator modal, select Bicep output
**Expected:** No output generated (silent failure — condition check fails, falls through)
**Why human:** Silent failures require browser observation to confirm exact behavior

### Gaps Summary

Three gaps block the R3.3 lazy-loading goal:

**Root cause: 04-01 Task 2 was never executed.** The SUMMARY states "Task deferred — executor completed Task 1 only due to approval gate." The lazy-load infrastructure (bundles + window loaders) was built, but the call sites in `app-core.js` that actually trigger demo and IaC functionality were not updated to use the loaders.

This means the app is in a broken state for demo and IaC functionality: `generateDemo` was removed from the eager bundle (correct) but the 7 call sites in `app-core.js` still call it as if it were eagerly loaded. At runtime, calling `generateDemo()` will throw `ReferenceError` because the function is not on `window` until `_loadDemoData()` is explicitly invoked.

**Compliance deferral** (one gap from 04-02 Task 2) is a separate lower-priority gap — it's a performance improvement that was deferred, not a regression. The compliance engine still works synchronously.

**What passes:** Bundle extraction (R3.1 fully satisfied), single-pass NSG consolidation (R3.4 fully satisfied), 273 unit tests green, render timing instrumentation present (R3.2 partially satisfied), separate bundles exist with correct globalName exports.

---

_Verified: 2026-03-30_
_Verifier: Claude (gsd-verifier)_
