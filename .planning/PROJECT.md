# Azure Network Mapper

## Overview
Azure Network Topology Visualizer: an Electron + web app that imports Azure CLI JSON exports and renders interactive network topology maps with compliance, BUDR, flow analysis, governance, and reporting dashboards.

## Tech Stack
- Electron (desktop) + static HTML/JS (web)
- D3.js for SVG topology rendering
- esbuild for bundling (src/modules -> dist/)
- Python HTTP server for local web development
- PowerShell/Bash export scripts for Azure CLI data collection
- Vercel for web deployment

## Milestone History

### M1: AWS-to-Azure Migration (completed 2026-03-30)
Refactored from AWS VPC Mapper to Azure Network Mapper:
- PS1 export script with parallel az CLI execution
- Azure property normalization (20+ resource types)
- Tag format conversion (Azure object -> AWS array)
- AWS networking model replaced with Azure (Public IP + NSG, no IGW/NACL)
- 68 _rlCtx key mismatches fixed
- 60+ AWS terminology renames
- All dashboard tabs working (Compliance, BUDR, Inventory, Classification, Reports)
- Multi-subscription import with account labeling
- Label collision detection
- Browser folder import fallback

### M2: Production Readiness (completed 2026-03-31)
Testing, performance, release preparation:
- 271 unit tests (node:test), 19 E2E specs (Playwright)
- Normalization functions extracted to testable module
- Bundle 362KB->246KB via lazy-loading demo-data + iac-generator
- NSG compliance engine consolidated (5 passes -> 1)
- Electron v2.0.0 DMG+ZIP packaging with auto-update
- Vercel deployment with cache headers for JS bundles

### M3: Modularization & UX (planned)
Focus: Split 27K-line app-core.js monolith, dashboard navigation improvements.
- Extract topology renderer, IaC generators, dashboard builders, event handlers
- Add back-button/breadcrumb navigation to dashboard overlays
- Add IaC Export to dock bar (currently only on landing page)
- requestIdleCallback compliance deferral (deferred from M2)
