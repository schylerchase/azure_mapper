# Feature Batch Design: AWS Mapper Parity

**Date:** 2026-02-17
**Scope:** 6 features to close the gap with AWS Mapper

## Features (priority order)

### 1. Resource List Panel
**What:** Clickable resource inventory panel showing all VNets, Subnets, NSGs, VMs, etc. with counts, click to zoom/navigate on map.
**Pattern:** Reuse existing `openDetailPanel()`. Switch statement by resource type. Each row has name + "Go to" button that calls `zoomToNode()`.
**Data:** Read from `_lk` global — already has all resources indexed.
**Keyboard:** `Shift+R` to open.
**Location:** New function `openResourceList(type)` after blast radius section (~line 4232).

### 2. Notes/Annotations
**What:** Pin notes to any resource. Categories: info, warning, todo, critical. CRUD with localStorage persistence. Badge count on map nodes.
**Storage:** `localStorage` key `azureNetMap_annotations` → `{resourceId: [{text, category, created, updated}]}`
**UI:** Notes panel (reuse detail panel), note form overlay, SVG badges on subnet/VNet nodes.
**Keyboard:** `n` to toggle notes panel.
**Location:** New section after snapshots (~line 4609).

### 3. History Timeline
**What:** Extend existing snapshots into a visual timeline bar at bottom of screen. Dots represent snapshots. Click to view, right-click to compare. History banner when viewing past state.
**Pattern:** Port from AWS Mapper (lines 9216-9335). Fixed-position bar, horizontal dot track, view/restore/return flow.
**Extends:** Existing `saveSnapshot()` / `loadSnapshotData()` at line 4565.
**Keyboard:** `h` to toggle timeline.
**Location:** Extend existing snapshot section.

### 4. File Import Auto-Detection
**What:** Enhance existing file upload (line 972) with content-based auto-detection. When filename doesn't match `FILE_TO_INPUT_MAP`, inspect JSON content for Azure API response patterns.
**Pattern:** New `matchFileContent(content)` function. Check for keys like `"virtualNetworks"`, `"networkSecurityGroups"`, `"networkInterfaces"`, etc.
**Extends:** Existing file input handler at line 972.
**Location:** Insert before existing handler (~line 970).

### 5. Compliance Excel/HTML Export
**What:** Add Excel (.xls via HTML SpreadsheetML) and HTML report exports alongside existing CSV.
**Excel:** 3 worksheets — Executive Summary, Findings Detail, By Framework. Color-coded severity.
**HTML:** Standalone report with score gauge, framework cards, findings table. Print-optimized.
**Extends:** Existing `exportComplianceCsv()` at line 4137.
**Location:** Add functions after CSV export.

### 6. Dependency Graph Visualization
**What:** Add SVG overlay for existing `calculateBlastRadius()` (line 4156). Highlight affected resources on map with colored glows. Dim non-affected resources.
**Pattern:** Add CSS classes `.blast-glow-hard`, `.blast-glow-soft`. Apply via D3 selection. Clear on click or Escape.
**Extends:** Existing `openBlastRadiusPanel()` at line 4206.
**Location:** Extend blast radius section with `applyBlastRadiusOverlay()`.

## Architecture Notes

- All features are additive — no existing code needs to change (except minor extensions to file import handler and compliance dashboard)
- All use existing patterns: `openDetailPanel()`, `_lk` global, localStorage, `resolveCssVars()`
- Single-file architecture maintained — each feature is a contiguous section
- Total estimated addition: ~800-1200 lines

## Implementation Batches (for parallel agents)

**Batch A (independent features):**
1. Resource List Panel
2. Notes/Annotations
3. File Import Auto-Detection

**Batch B (extensions of existing features):**
4. History Timeline (extends snapshots)
5. Compliance Excel/HTML Export (extends compliance)
6. Dependency Graph Visualization (extends blast radius)

All 6 can run in parallel since they touch different sections of the file.
