---
plan: 02-01
phase: 02-automated-test-suite
status: complete
started: 2026-03-30
completed: 2026-03-30
tasks_completed: 2
tasks_total: 2
---

## Summary

Extracted 5 private functions from the `src/app-core.js` IIFE into a new `src/modules/normalization.js` module, making them importable for unit testing.

## Tasks Completed

### Task 1: Create src/modules/normalization.js
- Extracted: `_normalizeAzureResources`, `ext`, `matchFile`, `fileMap`, `_friendlyFolderLabel`
- Module uses standard ESM exports
- All functions preserve original signatures and behavior

### Task 2: Wire module into bundle and remove inline definitions
- Updated `src/main.js` to import normalization.js and expose functions via `window.AppModules`
- Removed inline definitions from `src/app-core.js`, replaced with references to `window.AppModules`
- Bundle rebuilt and verified: 232 existing tests still pass

## Key Files

### Created
- `src/modules/normalization.js` — Testable normalization functions

### Modified
- `src/app-core.js` — Removed inline function definitions
- `src/main.js` — Added normalization.js import and window.AppModules exposure

## Self-Check: PASSED
- normalization.js exists with all 5 function exports
- app-core.js no longer contains inline `_normalizeAzureResources` definition
- Bundle builds successfully
- 232 existing unit tests pass (0 failures)
