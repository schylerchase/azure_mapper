# Changelog

All notable changes to Azure Network Mapper are documented here.

## [2.0.0] - 2026-03-31

### Added

- Lazy-load demo-data and IaC generator as separate bundles, reducing initial load time
- Multi-subscription upload flow E2E tests and test fixtures
- Dashboard and multi-subscription import E2E test specs
- Normalization module extracted to `src/modules/normalization.js` for testability
- Integration, regression, and structural unit tests covering normalization and extension edge cases
- Lazy loader wiring to all `generateDemo` and `IacGenerator` call sites

### Fixed

- Horizontal shift added to gateway label collision resolution (two-axis collision)
- Hardcoded inline font sizes replaced with CSS scale variables (`calc()`)
- Demo account labels updated to Azure subscription format (Display Name + short GUID)
- Ephemeral file inputs removed from DOM after use (stale dialog bug)
- 68 `_rlCtx` property key mismatches fixed across 3 modules
- Exec summary using wrong `rlCtx` keys (`vpcs` vs `vnets`, etc.)
- Folder name now passed from browser import paths for correct short labels
- Stripe label font scales to fit VNet height instead of extending beyond box
- Cross-type label collision detection for gateways and peerings
- Subscription label auto-derived for browser multi-folder import
- Fallback to file input when `showDirectoryPicker` API is unavailable
- All remaining label truncation removed; containers expand to fit content
- Missing normalization call added in textarea render path
- Properties self-reference added to nested arrays for connection normalization

### Changed

- Compliance engine consolidated from CIS NSG multi-pass to single-pass dispatch
- Main bundle reduced from 362KB to 246KB via code splitting
- Emojis removed from UI; font sizes increased for readability

## [1.2.0]

### Added

- Private Link (Private Endpoint) topology visualization with DNS resolution, compliance checks, and flow tracing
- Full port of 12 features from aws_mapper with code review and bug fixes

### Fixed

- Vulnerable transitive dev dependencies overridden (tar, minimatch)
- Demo data loading and VNet label display issues
- 4 CodeQL security alerts resolved
- Data correctness, security, and performance issues across 21 files

### Changed

- Rewritten with aws_mapper modular architecture for full Azure feature parity
- README rewritten with comprehensive feature documentation

## [1.1.4]

### Added

- Stat chip filters, flow tracer, keyboard help panel
- Persistent update banner UI for Electron auto-updater
- GitHub release publishing and auto-update support (electron-updater)
- Testable flow-tracing module with 95 unit tests
- Demo data expanded to showcase all supported features
- Mobile-friendly UI aligned to aws_mapper design

### Fixed

- CI/CD: publish-release job runs after all platform builds complete (no more draft releases)
- CI/CD: auto-tag workflow merged into release workflow to fix GITHUB_TOKEN limitation
- CI/CD workflow added and builds fixed for push events
- Peering line geometry, label collision, and GW icon positioning
- Electron and electron-builder bumped to resolve security vulnerabilities
- Gate mobile-only code behind `!_isElectron`; harden executive mode

### Changed

- Peering lines redesigned to use VNet boundary ports with individual subnet routing
- README and routing design docs rewritten

## [1.0.0]

Initial release. Azure network topology mapper with full security hardening, Electron desktop packaging, Vercel static web deployment, and electron-builder configuration.
