# M2: Production Readiness - Roadmap

## Phase 1: Fix Known Issues
**Goal:** Resolve remaining bugs from M1 migration
- Fix Chrome file upload (stale file chooser prevention)
- Update demo data to Azure-native format
- Fix inline font sizes that override CSS globals
- Improve collision engine horizontal shift

**Requirements:** R5.1, R5.2, R5.3, R5.4
**Estimate:** 1 session
**Plans:** 2/2 plans complete

Plans:
- [x] 01-01-PLAN.md -- Fix Chrome file upload + Azure demo labels
- [x] 01-02-PLAN.md -- Fix inline font sizes + collision engine horizontal shift

## Phase 2: Automated Test Suite
**Goal:** Unit + integration tests for core normalization and data pipeline
- Set up test runner (vitest or node:test)
- Unit tests for normalization, ext(), tags, matchFile, folder labels
- Integration test: load export folder -> verify rlCtx
- Regression test: programmatic _rlCtx key mismatch detection
- Add test script to package.json

**Requirements:** R1.1-R1.8
**Estimate:** 1-2 sessions
**Plans:** 2 plans

Plans:
- [ ] 02-01-PLAN.md -- Extract normalization functions from app-core.js into testable module
- [ ] 02-02-PLAN.md -- Write unit, integration, and regression tests for all R1.x requirements

## Phase 3: E2E Browser Tests
**Goal:** Playwright tests for critical user flows
- Upload JSON -> map renders
- Each dock button opens its dashboard
- Demo data renders clean
- Multi-subscription import

**Requirements:** R2.1-R2.4
**Estimate:** 1 session
**Plans:** 1/2 plans executed

Plans:
- [x] 03-01-PLAN.md -- Test fixtures + upload flow spec (R2.1, R2.3)
- [ ] 03-02-PLAN.md -- Dashboard dock buttons + multi-subscription import spec (R2.2, R2.4)

## Phase 4: Performance Optimization
**Goal:** Reduce bundle size and improve render speed
- Bundle analysis and dead code removal
- Lazy load dashboard tabs
- Profile and optimize large topology rendering
- Compliance engine optimization

**Requirements:** R3.1-R3.4
**Estimate:** 1-2 sessions
**Plans:** 2 plans

Plans:
- [ ] 04-01-PLAN.md -- Bundle audit, lazy-load demo-data + iac-generator, render timing instrumentation
- [ ] 04-02-PLAN.md -- Consolidate compliance engine NSG multi-pass + defer compliance to requestIdleCallback

## Phase 5: Release Preparation
**Goal:** Version bump to 2.0.0, changelog, packaging, and deployment
- Version bump and changelog generation
- Electron packaging (macOS + Windows)
- Auto-update configuration
- Vercel deployment optimization
- Final QA pass

**Requirements:** R4.1-R4.6
**Estimate:** 1 session
**Plans:** 2 plans

Plans:
- [ ] 05-01-PLAN.md -- Version bump to 2.0.0, CHANGELOG.md generation, Vercel lazy bundle fix + cache headers
- [ ] 05-02-PLAN.md -- Electron packaging with lazy bundles, auto-update verification, R4.6 demo data validation
