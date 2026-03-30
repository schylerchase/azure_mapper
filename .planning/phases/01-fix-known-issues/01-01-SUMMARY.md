---
phase: 01-fix-known-issues
plan: 01
subsystem: ui
tags: [file-upload, chrome, dom-cleanup, demo-data, azure-subscriptions]

# Dependency graph
requires: []
provides:
  - Ephemeral file input DOM cleanup in _folderFallback and govRulesImport handlers
  - Azure-native subscription labels in demo mode (Production/Security-Ops with short GUIDs)
affects: [demo-data, browser-import, governance-import]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Ephemeral input cleanup: create input, add change+cancel listeners that call inp.remove(), then click"

key-files:
  created: []
  modified:
    - src/app-core.js

key-decisions:
  - "Added inp.remove() in both change and cancel paths to cover user-confirms and user-cancels scenarios"
  - "Placed inp.remove() inside Promise.all().then() callback so removal happens after all file reads complete"
  - "Azure label format: 'Display Name (first-8-guid-chars)' matching Azure Portal convention"

patterns-established:
  - "Ephemeral input pattern: always clean up DOM-created inputs on both change and cancel events"

requirements-completed:
  - R5.1
  - R5.2

# Metrics
duration: 2min
completed: 2026-03-30
---

# Phase 01 Plan 01: Fix Chrome File Upload and Demo Labels Summary

**Ephemeral file input DOM cleanup via inp.remove() on change/cancel, plus Azure subscription label format in demo mode**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-30T20:25:00Z
- **Completed:** 2026-03-30T20:26:52Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- Fixed Chrome stale file chooser bug by removing ephemeral `<input>` elements from DOM after use in both `_folderFallback` (folder import) and `govRulesImport` (governance rules import)
- Added cancel event listeners so inputs are also cleaned up when user dismisses the file dialog
- Replaced AWS-style demo account labels (`prod-account (111122223333)`) with Azure subscription format (`Production (a1b2c3d4)`, `Security-Ops (c9d8e7f6)`)

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix Chrome file upload stale file chooser** - `14dd0e5` (fix)
2. **Task 2: Update demo data to Azure-native subscription labels** - `337b2ab` (fix)

**Plan metadata:** _(docs commit follows)_

## Files Created/Modified
- `src/app-core.js` - Added inp.remove() cleanup in _folderFallback and govRulesImport; updated demo addAccountContext labels to Azure format

## Decisions Made
- Added `inp.remove()` inside `Promise.all().then()` callback rather than before it, ensuring removal only happens after all file reads complete (avoids accessing inp.files after removal)
- Used `inp.addEventListener('cancel', ()=>inp.remove())` which is the native browser cancel event for file inputs (Chrome 113+)
- Azure label format `Name (short-guid)` follows Azure Portal convention, matching the first 8 chars of the subscription GUID from demo-data.js

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Chrome file upload now creates and destroys ephemeral inputs cleanly
- Demo mode displays Azure-native subscription names throughout
- Ready for Plan 02 tasks in phase 01-fix-known-issues

---
*Phase: 01-fix-known-issues*
*Completed: 2026-03-30*
