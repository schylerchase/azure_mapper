---
phase: 01-fix-known-issues
verified: 2026-03-30T21:00:00Z
status: passed
score: 9/9 must-haves verified
re_verification: false
gaps: []
human_verification:
  - test: "Open demo mode in Chrome and confirm account labels show 'Production (a1b2c3d4)' and 'Security-Ops (c9d8e7f6)' in the sidebar"
    expected: "Azure subscription format labels appear — no 'prod-account (111122223333)' anywhere"
    why_human: "Visual UI rendering cannot be verified programmatically"
  - test: "Click 'Import Folder' button in Chrome, select a folder, dismiss the file chooser without choosing files, then immediately click Import Folder again"
    expected: "A fresh file chooser opens without the 'stale file chooser' error"
    why_human: "Browser file dialog lifecycle cannot be verified by grep"
  - test: "Adjust --txt-scale CSS variable (via DevTools) and confirm sidebar text in detail panel, dashboards, diff engine, firewall, search, and notes all scale correctly"
    expected: "All sidebar text grows/shrinks proportionally; no text remains fixed at its original px size"
    why_human: "CSS variable cascade effect requires visual rendering"
  - test: "Create a topology with two side-by-side gateways (e.g., VPN Gateway + ExpressRoute Gateway in the same VNet) and inspect their labels"
    expected: "Labels shift horizontally and do not overlap each other"
    why_human: "Collision resolution outcome depends on rendered SVG positions"
---

# Phase 01: Fix Known Issues Verification Report

**Phase Goal:** Resolve remaining bugs from M1 migration
**Verified:** 2026-03-30T21:00:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Chrome file upload via Import Folder button works without stale dialogs | VERIFIED | `inp.remove()` present at lines 11582, 11626 (_folderFallback) and 20269, 20274, 20280 (govRulesImport) in src/app-core.js |
| 2 | Ephemeral file input elements are cleaned up after use | VERIFIED | cancel listeners at lines 11629 and 20284; change path also calls `inp.remove()` at both handler sites |
| 3 | Demo data shows Azure subscription labels instead of AWS account IDs | VERIFIED | Lines 23377-23378 in src/app-core.js: `'Production (a1b2c3d4)'` and `'Security-Ops (c9d8e7f6)'`; no occurrences of `111122223333`, `444455556666`, or `prod-account` remain |
| 4 | Sidebar text sizes respect CSS --txt-scale and --dp-txt-scale variables | VERIFIED | Zero hardcoded inline `font-size:Npx` remain in all 6 sidebar modules; 102 `font-size:calc()` expressions confirmed across detail-panel.js (9), dashboards.js (23), diff-engine.js (32), firewall-engine.js (25), search.js (7), notes.js (6) |
| 5 | No hardcoded inline font-size px values remain in sidebar module HTML strings | VERIFIED | `grep -cn "style=.*font-size:[0-9]+px[^*]"` returns 0 for all 6 modules |
| 6 | Gateway labels can shift horizontally when side-by-side gateways overlap | VERIFIED | Two-pass collision block at topology-renderer.js lines 1781-1788: shift-y (pass 1) then shift-x (pass 2); `strategy:'shift-x'` confirmed at line 1786 |
| 7 | Collision engine resolves gateway label overlaps using shift-x when shift-y alone is insufficient | VERIFIED | `_resolveCollisions` has `strategy === 'shift-x'` branch at line 28; cross-type sweep at lines 2432-2441 handles `overlapX` with min-displacement axis selection |

**Score:** 7/7 truths verified (plan 01-01: 3/3, plan 01-02: 4/4)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/app-core.js` | Fixed file upload with cleanup and Azure demo labels | VERIFIED | 7 `inp.remove()` calls (4 change paths, 2 cancel listeners, 1 early-exit); Azure labels at lines 23377-23378 |
| `src/modules/detail-panel.js` | Detail panel with scalable font sizes | VERIFIED | 9 `font-size:calc()` occurrences; 0 remaining hardcoded px inline |
| `src/modules/dashboards.js` | Dashboard tabs with scalable font sizes | VERIFIED | 23 `font-size:calc()` occurrences; 0 remaining hardcoded px inline |
| `src/modules/diff-engine.js` | Diff engine UI with scalable font sizes | VERIFIED | 32 `font-size:calc()` occurrences; 0 remaining hardcoded px inline |
| `src/modules/firewall-engine.js` | Firewall editor with scalable font sizes | VERIFIED | 25 `font-size:calc()` occurrences; 0 remaining hardcoded px inline |
| `src/modules/search.js` | Search overlay with scalable font sizes | VERIFIED | 7 `font-size:calc()` occurrences; 0 remaining hardcoded px inline |
| `src/modules/notes.js` | Notes panel with scalable font sizes | VERIFIED | 6 `font-size:calc()` occurrences; 0 remaining hardcoded px inline |
| `src/modules/topology-renderer.js` | Collision engine with horizontal shift for gateway labels | VERIFIED | `shift-x` strategy at line 1786; `overlapX` at lines 29-30 (inside `_resolveCollisions`) and 2434-2439 (cross-type sweep) |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/app-core.js` | `addAccountContext` calls | Azure subscription labels | VERIFIED | Lines 23377-23378 pass `'Production (a1b2c3d4)'` and `'Security-Ops (c9d8e7f6)'` as both `accountLabel` and display-name arguments |
| `src/modules/topology-renderer.js` | `_resolveCollisions function` | `strategy:'shift-x'` parameter | VERIFIED | Line 1786 calls `_resolveCollisions(gwLabelRecs,{strategy:'shift-x',padding:4,maxIter:4})`; function branch at line 28 handles it |
| `src/styles/main.css` | sidebar modules | `var(--txt-scale)` CSS variable | VERIFIED (programmatic) | 102 calc() expressions across 6 modules reference `var(--txt-scale,1)`; detail panel elements additionally include `var(--dp-txt-scale,1)` |

### Data-Flow Trace (Level 4)

Not applicable — this phase modifies UI rendering logic and DOM cleanup handlers, not data pipeline components. No components were added that render dynamic data from a new source.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `inp.remove()` present in both handler sites | `grep -n "inp.remove()" src/app-core.js` | 7 matches at lines 11582, 11626, 11629, 20269, 20274, 20280, 20284 | PASS |
| AWS-style account IDs absent | `grep "111122223333\|444455556666\|prod-account" src/app-core.js` | 0 matches | PASS |
| Azure subscription labels present | `grep "Production (a1b2c3d4)\|Security-Ops (c9d8e7f6)" src/app-core.js` | 2 matches each | PASS |
| No hardcoded inline font-size px in sidebar modules | `grep -cn "style=.*font-size:[0-9]+px[^*]"` across 6 modules | All 0 | PASS |
| shift-x strategy wired in gateway collision block | `grep "strategy:'shift-x'" src/modules/topology-renderer.js` | Match at line 1786 | PASS |
| overlapX handled in cross-type sweep | `grep "overlapX" src/modules/topology-renderer.js` | Matches at lines 29, 30, 2434, 2436, 2438, 2439 | PASS |
| Commits exist in git history | `git log --oneline \| grep 14dd0e5\|337b2ab\|255ca80\|c7156da` | All 4 commits confirmed | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| R5.1 | 01-01-PLAN.md | Chrome file upload not working (stale file chooser dialogs blocking page) | SATISFIED | `inp.remove()` + cancel listeners in both ephemeral input handlers; verified at 7 call sites |
| R5.2 | 01-01-PLAN.md | Demo data still shows AWS-style account labels | SATISFIED | No AWS IDs remain; Azure labels confirmed at lines 23377-23378 |
| R5.3 | 01-02-PLAN.md | Sidebar text sizes still small in some areas (inline styles override CSS) | SATISFIED | 0 hardcoded px remain in 6 target modules; 102 calc() expressions with --txt-scale |
| R5.4 | 01-02-PLAN.md | Collision engine needs horizontal shift support for side-by-side gateways | SATISFIED | Two-pass gateway collision and updated cross-type sweep with min-displacement axis selection |

No orphaned requirements — all four R5.x requirements from ROADMAP.md Phase 1 are claimed and satisfied.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/modules/detail-panel.js` | 471, 478, 510 | `font-size:calc(11px * var(--dp-txt-scale,1))` — missing `--txt-scale` multiplier on parent container divs | Info | Pre-existing condition; these lines already used `calc()` before this phase and were not targeted by the plan (plan targeted hardcoded `Npx` only). Text at these sizes does not respond to global text scale, but does respond to detail-panel-specific scale. Not introduced by this phase. |

No blockers or warnings introduced by this phase.

### Human Verification Required

#### 1. Demo Mode Account Labels (Visual)

**Test:** Load the app, click "Load Demo", open the left sidebar or any multi-subscription view
**Expected:** Account labels read "Production (a1b2c3d4)" and "Security-Ops (c9d8e7f6)" — no numeric AWS IDs visible anywhere
**Why human:** Label display in rendered UI must be visually confirmed

#### 2. Chrome File Upload (Browser Behavior)

**Test:** In Chrome, click Import Folder, open DevTools Elements panel, dismiss the file chooser without selecting files, observe the DOM
**Expected:** The ephemeral `<input type="file">` element disappears from DOM after dismissal; clicking Import Folder again opens a fresh chooser with no "stale file chooser" error
**Why human:** Browser file dialog lifecycle and DOM cleanup cannot be verified by static analysis

#### 3. CSS Text Scaling (Visual Rendering)

**Test:** Open DevTools, select `:root`, set `--txt-scale: 1.5`, inspect sidebar panels (detail panel, dashboards, diff view, firewall, search, notes)
**Expected:** All text in those panels scales up proportionally; no text remains fixed at its original size
**Why human:** CSS variable cascade and computed styles require a live browser

#### 4. Side-by-Side Gateway Label Collision (Visual Rendering)

**Test:** Create or load a topology with two gateways positioned at approximately the same Y coordinate in the same VNet (e.g., VPN Gateway and Application Gateway)
**Expected:** Labels shift horizontally away from each other, not only vertically — no overlap
**Why human:** SVG collision resolution outcome depends on actual rendered layout geometry

### Gaps Summary

No gaps found. All phase-01 goal requirements are met:

- **R5.1 (Chrome upload):** Ephemeral inputs are cleaned up on both change and cancel in `_folderFallback` and `govRulesImport`. Seven `inp.remove()` call sites confirmed. Commits 14dd0e5 verified.
- **R5.2 (Demo labels):** AWS IDs fully removed; Azure subscription format labels confirmed at both `addAccountContext` call sites. Commit 337b2ab verified.
- **R5.3 (Font scaling):** Zero hardcoded inline `font-size:Npx` remain across all 6 target sidebar modules. 102 `calc()` expressions with `--txt-scale` confirmed. Commit 255ca80 verified.
- **R5.4 (Gateway collision):** Two-pass collision (shift-y then shift-x) implemented for gateway labels; cross-type sweep extended with min-displacement axis logic. Commit c7156da verified.

One pre-existing info-level finding noted: three parent divs in `detail-panel.js` (lines 471, 478, 510) use `calc(11px * var(--dp-txt-scale,1))` without the global `--txt-scale` multiplier. This predates this phase and was explicitly out of scope per the plan's task description.

---

_Verified: 2026-03-30T21:00:00Z_
_Verifier: Claude (gsd-verifier)_
