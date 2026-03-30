# Phase 4: Performance Optimization - Research

**Researched:** 2026-03-30
**Domain:** Browser application performance — bundle analysis, lazy loading, rendering pipelines, compliance engine
**Confidence:** HIGH (all findings derived from direct codebase inspection)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None — all implementation choices are at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure/performance phase. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

### Deferred Ideas (OUT OF SCOPE)
None — infrastructure phase.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| R3.1 | Bundle size audit (current: 553KB app.bundle.js + 1578KB app-core.js) | Verified via esbuild metafile; prod sizes are 362KB + 1173KB; top module contributors identified |
| R3.2 | Profile render time for large topologies (50+ VNets) | Rendering pipeline documented; 7 separate vL.forEach passes identified; compliance runs synchronously on render |
| R3.3 | Lazy load dashboard tabs (only parse data when tab first opened) | _UDASH_TABS structure and prereq() mechanism documented; tabs already gate on data availability |
| R3.4 | Optimize compliance engine for large resource sets | 8 NSG passes, 29 total resource-iteration passes identified; multi-pass consolidation strategy documented |
</phase_requirements>

---

## Summary

The application consists of two JavaScript bundles loaded at startup: `dist/app.bundle.js` (362KB minified — ES modules via esbuild IIFE) and `dist/app-core.js` (1173KB minified — a monolithic plain script that cannot be tree-shaken by esbuild). The initial load payload is therefore 1535KB of JS before gzip, which Vercel compresses to roughly 500KB. The two largest contributors to `app.bundle.js` are `demo-data.js` (16.9%) and `iac-generator.js` (15.4%) — both loaded eagerly even though they are only used in specific user-triggered flows.

The dashboard tab system (`_UDASH_TABS`) already has a `prereq()` gate that prevents rendering until data is present, but it does not defer *data processing*. Compliance checks, BUDR assessments, classification, and inventory builds all run at map-render time in `app-core.js`, adding synchronous work to every "Render Map" click. For 50+ VNets this compounds with 7 sequential D3 rendering passes over the VNet layout array (`vL`).

The compliance engine (`compliance-engine.js`) runs 29 separate resource iteration passes across 7 framework functions. NSGs alone are iterated 8 times. A single consolidated pass with per-rule dispatch would cut this to 1 pass per resource type and is the primary compliance engine optimization.

**Primary recommendation:** Move compliance/BUDR/classification from synchronous render-path to a deferred `requestIdleCallback` background task that updates the badge counter when done. Bundle savings are secondary — trim `demo-data.js` and `iac-generator.js` from the eager bundle first, but the larger wins are in execution time, not parse time.

---

## Standard Stack

### Core (already in use — no changes needed)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| esbuild | 0.27.3 | Bundler | Already in use; minifies app.bundle.js; does NOT process app-core.js as ESM |
| D3 (custom) | 3.x modules | SVG visualization | Custom 5-module build already: selection, zoom, shape, transition, ease — 52KB vs 280KB full |
| XLSX / SheetJS | bundled | Excel export | Already lazy-loaded via dynamic `<script>` injection; 416KB never in initial parse |
| Playwright | 1.58.2 | E2E testing | Already in use for other phases |

### Tooling for this phase
| Tool | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| esbuild metafile | built-in | Bundle composition analysis | Run `esbuild.build({metafile:true})` + `analyzeMetafileSync` to measure module weights before/after |
| `requestIdleCallback` | browser native | Deferred background processing | Schedule compliance/classification after render frame completes |
| `performance.now()` | browser native | Render timing instrumentation | Wrap `_renderMapInner()` calls to measure large-VNet render time |

**No new dependencies required for this phase.**

---

## Architecture Patterns

### Current Bundle Architecture

```
index.html loads (in order):
  1. libs/d3.custom.min.js     — 52KB, global d3 object
  2. libs/jszip.min.js         — 97KB, global JSZip object
  3. dist/app.bundle.js        — 362KB minified (ES module bundle)
  4. [inline HTML / DOM]
  5. dist/app-core.js          — 1173KB minified (plain script, global scope)
  6. /_vercel/insights/script.js  — deferred
  7. /_vercel/speed-insights/script.js — deferred

  libs/xlsx.bundle.min.js (416KB) — lazy loaded by _loadSheetJS() only when XLSX export is triggered
```

### What app.bundle.js contains (esbuild metafile, prod build)
| Module | Minified Size | % of Bundle | Lazy Load Candidate? |
|--------|--------------|-------------|---------------------|
| demo-data.js | 61KB | 16.9% | YES — only used on demo click |
| iac-generator.js | 56KB | 15.4% | YES — only used in IaC modal |
| compliance-engine.js | 36KB | 10.0% | No — runs at render time |
| design-mode.js | 31KB | 8.7% | Partial — enterDesignMode() on demand |
| governance.js | 27KB | 7.5% | YES — only used in Classification/AppSummary tabs |
| flow-tracing.js | 24KB | 6.7% | YES — only used in flow tracing mode |
| budr-engine.js | 19KB | 5.3% | No — runs at render time |
| compliance-view.js | 17KB | 4.8% | YES — only used in Compliance tab |
| normalization.js | 16KB | 4.4% | No — used in critical path |
| **Total bundle** | **362KB** | | |

### What app-core.js contains (plain script, not tree-shakeable)
| Region | Lines | Key Content |
|--------|-------|-------------|
| TOPOLOGY RENDERER | 3746 | renderMap, _renderMapInner — the main D3 rendering pipeline |
| IAC GENERATOR | 2757 | Terraform/ARM/Bicep generation — could be deferred |
| EXPORT UTILITIES | 2753 | VSDX, draw.io export — could be deferred |
| REPORTS & XLSX | 2346 | Report generation — already partially deferred |
| REPORT BUILDER | 1603 | Tab-level rendering — already gated on tab open |
| FIREWALL EDITOR | 1600 | NSG rule CRUD — deferred by tab open |
| FLOW ANALYSIS | 1488 | Traffic flow discovery — deferred by mode toggle |
| UNIFIED DASHBOARD | 1385 | Tab orchestration — required at startup for event binding |
| GOVERNANCE & INVENTORY | 1350 | Classification engine — runs on tab open |

### Dashboard Tab System (_UDASH_TABS)

Tabs are defined in `app-core.js` at line 18869. Each tab has:
- `prereq()`: guard function — returns false if data not ready, shows toast
- `render()`: synchronous DOM-building function called immediately on tab click

Current tab list and their render functions:
```
classification -> _renderClassificationTab()   [triggers runClassificationEngine if not cached]
appsummary     -> _renderAppSummaryTab()
iam            -> _renderIAMTab()
compliance     -> _renderCompDash()            [reads _complianceFindings]
firewall       -> _renderFirewallTab()
budr           -> _renderBUDRDash()            [calls runBUDRChecks if not cached]
inventory      -> _renderInventoryTab()        [calls _buildInventoryData if not cached]
reports        -> _renderReportsTab()
```

The tabs already GATE rendering on data availability. The optimization target is deferring the **data computation** (compliance checks, classification, BUDR) off the render critical path.

### Compliance Engine Execution Flow (current state)

```
User clicks "Render Map"
  -> _renderMapInner() (synchronous, in requestAnimationFrame)
     -> builds _rlCtx (new object each render)
     -> _runComplianceWithCache(_rlCtx) ← SYNCHRONOUS on render path
        -> checks _dataFingerprint() (field count hash)
        -> cache HIT: return cached findings (fast)
        -> cache MISS: runComplianceChecks(ctx) ← full check, potentially slow
           -> runCISAzureChecks  (9 resource iterations)
           -> runCAFChecks       (N iterations)
           -> runSOC2Checks      (N iterations)
           -> runPCIChecks       (N iterations)
           -> runBUDRAzureChecks (N iterations)
           -> runFedRAMPChecks*4 (N iterations each)
           -> runBUDRChecks      (external engine)
           -> analyzeRoleAssignments (if RBAC data present)
     -> updates compliance badge in stats bar
```

**Hot path problem:** The compliance engine runs synchronously on every first render (cache miss). The fingerprint cache (`_complianceDataFP`) only helps on *repeated renders of the same data* (e.g. zoom/pan triggers re-render — but actually zoom/pan does NOT call `renderMap`, only the Render Map button does). So in practice the cache is only valuable if the user clicks Render Map multiple times without changing data.

### Multi-Pass Problem in Compliance Engine

`runCISAzureChecks` iterates over NSGs 5 times (one pass per check: CIS-9, CIS-10, CIS-12, CIS-13, CIS-36). With 100 NSGs × 20 rules each = 2000 rule objects traversed 5 times = 10,000 iterations for CIS alone. The same NSG list is iterated again in `runSOC2Checks`, `runPCIChecks`, `runFedRAMPChecks` × 4 = a total of **8 separate passes over the NSG array** across the full compliance run.

Consolidating to a single NSG pass with a multi-check dispatch would reduce this to O(NSG × rules) regardless of framework count.

### Topology Renderer: Large VNet Performance

`_renderMapInner()` makes 7 sequential passes over the VNet layout array (`vL`):

1. `vL.forEach` — gateway positioning (line 630)
2. `vL.forEach` — region map building (line 1489)
3. `vL.forEach` — VNet group + rect rendering (line 1574)
4. `vL.forEach` — subnet node rendering (line 1608)
5. `vL.forEach` — private endpoint badges (line 1860)
6. `vL.forEach` — private DNS zone labels (line 2014)
7. `vL.forEach` (inner) — DNS zone to VNet lookup (line 2059)

Each pass touches every VNet. For 50 VNets with 5 subnets each, pass 4 alone creates 250 D3 SVG groups. The renderer does NOT use D3's data-join pattern (`selection.data().join()`) which would enable incremental DOM updates. Instead it calls `svg.selectAll('*').remove()` at the start and rebuilds the entire SVG from scratch on every render.

The `_detailLevel` variable (0 = collapsed, 1 = normal, 2 = expanded) already gates resource icon rendering, which is a significant optimization for large topologies at zoom-out.

### Parse Cache (_cachedParse)

Located in `app-core.js` at line 8787. Uses a simple djb2 hash of textarea values. This prevents re-parsing JSON when the textarea hasn't changed (e.g. switching detail levels). This is already a useful optimization and should not be changed.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Bundle composition analysis | Custom build analyzer | esbuild `metafile: true` + `analyzeMetafileSync` | Already available in esbuild 0.27.3 |
| Deferred background processing | Web Workers | `requestIdleCallback` | Workers require message passing overhead; compliance engine reads globals; `requestIdleCallback` is sufficient for the scale |
| CSS minification | Custom minifier | esbuild CSS transform | esbuild 0.27.3 supports CSS bundling/minification via `--bundle` on CSS entry points |
| Lazy module loading | Custom dynamic import system | Native `import()` | ES dynamic import is the standard; note that app-core.js is a plain script not an ES module, so dynamic import only works from the bundle side |

**Key insight:** app-core.js is a 28,710-line plain script that runs in global scope. It cannot use `import()` statements. Bundle-side lazy loading (from main.js) is feasible for modules that only expose data through `window.AppModules`. App-core.js deferred execution requires timing tricks (`setTimeout`, `requestIdleCallback`) not module splitting.

---

## Common Pitfalls

### Pitfall 1: Tree-Shaking app-core.js
**What goes wrong:** Treating app-core.js as a bundle-size reduction target via esbuild tree-shaking.
**Why it happens:** app-core.js is a plain script (no `import`/`export`), processed by `esbuild.transform()` (minify only), not `esbuild.build()` (bundle). esbuild cannot tree-shake it.
**How to avoid:** Dead code removal in app-core.js requires manual identification and deletion. Focus bundle tree-shaking on `app.bundle.js` only (via main.js entry point).
**Warning signs:** Expecting large size reductions from build config changes alone without code deletions.

### Pitfall 2: Lazy Loading Modules That Touch window.AppModules
**What goes wrong:** Moving a module to dynamic `import()` in main.js but app-core.js references its exports synchronously at startup via `window.AppModules`.
**Why it happens:** `main.js` does `Object.assign(window, window.AppModules)` at module evaluation time. If a module is lazily loaded, the globals it contributes are not on `window` when app-core.js event handlers try to call them.
**How to avoid:** Only lazy-load modules whose functions are called from explicit user actions (button clicks, tab opens) — not modules whose exports are referenced during DOM initialization. Safe candidates: `demo-data.js`, `iac-generator.js`, `governance.js`, `compliance-view.js`, `flow-tracing.js`.
**Warning signs:** `TypeError: AppModules.X is not a function` or `X is not defined` errors in app-core.js after making a module lazy.

### Pitfall 3: Deferring Compliance Off the Stats Bar
**What goes wrong:** Moving compliance to `requestIdleCallback` breaks the stats bar compliance badge which renders synchronously with the map.
**Why it happens:** `_runComplianceWithCache` is called inside `_renderMapInner` to populate the compliance chip in the stats bar. If deferred, the badge renders empty initially.
**How to avoid:** The badge counter update must be the callback for the deferred compliance run. Show a loading spinner or empty state, update when idle callback fires. This is a UI state change, not a correctness problem.
**Warning signs:** Stats bar shows "0 findings" permanently when the user has NSG violations.

### Pitfall 4: Breaking the Fingerprint Cache Invalidation
**What goes wrong:** Changing how `_dataFingerprint()` works breaks cache invalidation, causing stale compliance results after new data is loaded.
**Why it happens:** The fingerprint is computed as `el.id + ':' + el.value.length` for all `.ji` input elements. This is a coarse hash — it only detects length changes, not content changes. If two different data sets have the same total character count, the cache will NOT invalidate.
**How to avoid:** Don't change the fingerprint logic without also understanding that this is an intentional performance trade-off. For this phase, keep the existing fingerprint approach.
**Warning signs:** Old compliance findings persist after pasting new JSON data of similar length.

### Pitfall 5: SVG Re-render Not Incremental
**What goes wrong:** Assuming D3 data-join will make re-renders faster.
**Why it happens:** `_renderMapInner()` always calls `svg.selectAll('*').remove()` at line 69 and rebuilds from scratch. There is no incremental update path.
**How to avoid:** For Phase 4, don't attempt to convert to incremental D3 data-joins — this is a major refactor. Instead focus on (1) reducing work before the SVG rebuild, and (2) throttling render triggers. The setTimeout(50ms) debounce is already in place in `renderMap()`.
**Warning signs:** Attempting to "update only changed VNets" — this would require a complete rewrite of the renderer's state model.

---

## Code Examples

### Bundle Analysis with esbuild Metafile
```javascript
// Source: esbuild docs (verified against 0.27.3 in project)
// Add to build.js temporarily for analysis
const result = await esbuild.build({
  entryPoints: ['src/main.js'],
  bundle: true,
  outfile: 'dist/app.bundle.js',
  format: 'iife',
  metafile: true,
  // ... other config
});
const text = esbuild.analyzeMetafileSync(result.metafile, { verbose: false });
console.log(text);
// Also write metafile for external tools
fs.writeFileSync('dist/meta.json', JSON.stringify(result.metafile));
```

### Lazy Loading a Module (demo-data.js pattern)
```javascript
// In main.js — replace static import with dynamic import factory
// BEFORE:
// import { generateDemo } from './modules/demo-data.js';
// window.AppModules = { generateDemo, ... };

// AFTER — expose a lazy loader instead of the function directly:
// In app-core.js event handler (generateDemo call site):
async function _loadDemoData() {
  if (!window.generateDemo) {
    const mod = await import('./src/modules/demo-data.js');
    window.generateDemo = mod.generateDemo;
  }
  return window.generateDemo;
}
// NOTE: app-core.js is a plain script, cannot use import() directly.
// The dynamic import must live in app.bundle.js and be exposed via window.
// Pattern: expose an async loader function on window from main.js,
// call it from app-core.js event handlers.
```

### Deferred Compliance with requestIdleCallback
```javascript
// In app-core.js, replace synchronous compliance call in _renderMapInner:
// BEFORE (line 8443):
// try{const findings=_runComplianceWithCache(_rlCtx);if(findings.length)addComplianceChip(sb2,findings);}

// AFTER:
function _deferredComplianceUpdate(ctx, statsBar) {
  const run = () => {
    try {
      const findings = _runComplianceWithCache(ctx);
      _complianceFindings = findings;
      window._complianceFindings = findings;
      if (findings.length) addComplianceChip(statsBar, findings);
      _addBUDRChip(statsBar);
    } catch(e) { console.warn('Compliance check error:', e); }
  };
  if (typeof requestIdleCallback === 'function') {
    requestIdleCallback(run, { timeout: 2000 });
  } else {
    setTimeout(run, 100); // Safari fallback
  }
}
```

### Consolidated NSG Pass in Compliance Engine
```javascript
// Replace 5 separate nsgs.forEach loops in runCISAzureChecks with one:
function runCISAzureChecks(data) {
  const f = [];
  const nsgs = data.nsgs || [];
  // Single pass — dispatch per-rule checks inside one loop
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction !== 'Inbound' || rp.access !== 'Allow') return;
      const openSrc = _hasOpenSourcePrefixes(rule);
      if (!openSrc) return;
      // CIS-9: RDP
      if (_coversPort(rule, 3389)) f.push(_finding({ id: 'CIS-9', ... }));
      // CIS-10: SSH
      if (_coversPort(rule, 22)) f.push(_finding({ id: 'CIS-10', ... }));
      // CIS-12: all inbound
      if (_isAllProtocols(rule) && _isAllPorts(rule)) f.push(_finding({ id: 'CIS-12', ... }));
      // CIS-13: broad port ranges
      if (_coversPort(rule, 80) || _coversPort(rule, 443)) { /* ... */ }
    });
  });
  // ... non-NSG checks remain separate
  return f;
}
```

### Topology Render Timing Instrumentation
```javascript
// Wrap _renderMapInner in app-core.js to measure render time:
function _renderMapInner() {
  const t0 = performance.now();
  // ... existing body ...
  const t1 = performance.now();
  if (vnets.length >= 10) {
    console.info(`Render: ${vnets.length} VNets, ${subnets.length} subnets — ${(t1-t0).toFixed(0)}ms`);
  }
}
```

---

## State of the Art

| Old Approach | Current Approach | Recommended For Phase 4 |
|--------------|------------------|------------------------|
| Full d3.min.js (280KB) | Custom 5-module build (52KB) | Already done — no action |
| Eager XLSX load | Lazy `_loadSheetJS()` dynamic script | Already done — no action |
| All compliance on render path | Fingerprint-cached compliance | Defer to requestIdleCallback for first-render perf |
| 5 NSG passes in CIS alone | 8 total NSG passes across all frameworks | Consolidate to 1 NSG pass |
| No bundle composition analysis | No metafile in build | Add metafile to prod build for ongoing monitoring |
| CSS unminified in prod | CSS loaded as-is (180KB) | Add esbuild CSS minification step |

---

## Open Questions

1. **How much time does compliance add to render for large datasets?**
   - What we know: The fingerprint cache means only the FIRST render after new data loads is expensive. Subsequent re-renders hit the cache.
   - What's unclear: Actual millisecond cost on real 50+ VNet datasets. The code path is synchronous but the checks are not deeply nested.
   - Recommendation: Add `performance.now()` instrumentation as Wave 1 task to measure before optimizing.

2. **Are `demo-data.js` and `iac-generator.js` safe to lazy load?**
   - What we know: `generateDemo` is called from a button click handler (`document.getElementById('demoBtn').addEventListener`). `IacGenerator` functions are called from a modal trigger. Neither is called during DOM initialization.
   - What's unclear: Whether app-core.js references these via `window.IacGenerator.*` or direct function calls. Direct inspection of call sites needed during planning.
   - Recommendation: Grep for `IacGenerator\.\|generateDemo` in app-core.js to confirm all call sites are user-triggered. If yes, safe to lazy-load.

3. **Is CSS minification worthwhile (180KB -> ~18KB gzip)?**
   - What we know: The CSS is already gzip-compressed by Vercel's CDN. 180KB CSS gzips to ~18KB. The raw parse cost of 1844 lines of CSS is negligible in modern browsers.
   - What's unclear: Whether there is significant dead CSS (styles for removed UI elements).
   - Recommendation: LOW priority for Phase 4. Minification would save ~2KB gzip. Focus on JS execution time instead.

4. **Is vercel.json missing Cache-Control headers for static assets?**
   - What we know: The current `vercel.json` sets security headers globally but no `Cache-Control` for `dist/` or `libs/` paths. Vercel defaults to `public, max-age=0, must-revalidate` for non-immutable assets. The index.html has content-hash query strings (`app.bundle.js?v=3b883ed4`) enabling safe long-term caching.
   - What's unclear: Whether Vercel's default CDN behavior already applies edge caching to static assets, making explicit `Cache-Control` headers redundant.
   - Recommendation: Add `Cache-Control: public, max-age=31536000, immutable` for `/dist/*` and `/libs/*` paths in vercel.json (R4.5 requirement belongs here).

---

## Environment Availability

Step 2.6: SKIPPED — this phase is pure code/config changes with no external service dependencies. All tools (esbuild, node, browser APIs) are already available and in use.

---

## Validation Architecture

nyquist_validation is not explicitly set to false in .planning/config.json — treating as enabled.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Playwright 1.58.2 (E2E) + node:test (unit) |
| Config file | `playwright.config.js` |
| Quick run command | `npx playwright test tests/smoke.spec.js` |
| Full suite command | `npx playwright test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R3.1 | Bundle size audit — prod build reports sizes | smoke/build | `node build.js --production 2>&1 \| grep -E 'kb\|KB'` | N/A (build output) |
| R3.2 | Large topology render completes without timeout | perf/smoke | `npx playwright test tests/smoke.spec.js --timeout=10000` | Partial (smoke exists) |
| R3.3 | Compliance tab renders correctly after lazy defer | e2e | `npx playwright test tests/dashboard-buttons.spec.js` | ✅ exists |
| R3.4 | Compliance engine produces same findings before/after consolidation | unit | `node --test tests/unit/compliance-engine.test.mjs` | ✅ exists |

### Sampling Rate
- **Per task commit:** `npx playwright test tests/smoke.spec.js && node --test tests/unit/compliance-engine.test.mjs`
- **Per wave merge:** `npx playwright test`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/unit/bundle-size.test.mjs` — validates prod bundle sizes don't regress (covers R3.1); run `node build.js --production` and assert sizes
- [ ] Performance fixture: a large synthetic topology with 50+ VNets for R3.2 profiling (or use existing Playwright fixture loading approach with larger data)

---

## Sources

### Primary (HIGH confidence)
- Direct codebase inspection: `src/app-core.js`, `src/main.js`, `src/modules/compliance-engine.js`, `src/modules/topology-renderer.js`, `build.js`, `index.html`, `package.json`, `vercel.json`
- esbuild metafile analysis (ran `esbuild.build({metafile:true})` against the actual project): verified module sizes at prod build time
- Production build output (`node build.js --production`): verified actual minified sizes (362KB bundle, 1173KB app-core)

### Secondary (MEDIUM confidence)
- esbuild 0.27.3 documentation: metafile/analyzeMetafileSync API confirmed via direct execution
- MDN: `requestIdleCallback` availability (browser-native, no polyfill needed for Vercel/Chrome target; Safari needs setTimeout fallback)

### Tertiary (LOW confidence)
- Gzip compression estimates (70% reduction) — standard rule of thumb, not measured for these specific files

---

## Metadata

**Confidence breakdown:**
- Bundle composition: HIGH — measured via esbuild metafile on actual prod build
- Compliance engine hot paths: HIGH — counted iteration passes from source code directly
- Topology renderer passes: HIGH — enumerated all vL.forEach call sites with line numbers
- Lazy load safety analysis: MEDIUM — call site grep suggests safety; planner should verify specific call sites for demo-data and iac-generator during task planning
- requestIdleCallback deferral pattern: HIGH — well-established browser API; Safari fallback documented

**Research date:** 2026-03-30
**Valid until:** 2026-04-30 (codebase is local; no third-party API changes to track)
