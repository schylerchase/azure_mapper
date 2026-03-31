# Phase 5: Release Preparation - Research

**Researched:** 2026-03-30
**Domain:** Electron packaging, changelog generation, Vercel deployment, version management
**Confidence:** HIGH

## Summary

This phase prepares Azure Network Mapper for public distribution. The project is already in an advanced release-ready state: electron-builder is fully configured, GitHub Actions workflows for CI and multi-platform release are in place, electron-updater is wired in main.js, and Vercel deployment via `build:web` is functional. The primary work is straightforward coordination tasks — not infrastructure setup.

The current version is `1.2.0` (package.json), but the About dialog in main.js still hardcodes `v1.0.0`. There are no existing CHANGELOG.md or git tags other than `v1.0.0`, `v1.1.4`, and `v1.2.0`. Ninety-two commits exist since the beginning with a conventional commit prefix pattern (`feat`, `fix`, `refactor`, `chore`, `docs`). R4.6 (remove AWS account IDs from demo data) appears already resolved from Phase 01 work — no AWS-style strings were found in demo-data.js.

**Primary recommendation:** The release trigger is a version bump in package.json. Pushing `1.3.0` to main auto-creates a GitHub tag and fires the full multi-platform build matrix. The only manual steps are: write CHANGELOG.md, fix the hardcoded version string in the About dialog, add lazy bundles to the Vercel public/ assembly, and verify Vercel cache headers are optimal.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
All implementation choices are at Claude's discretion — pure infrastructure/release phase.

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure/release phase. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

### Deferred Ideas (OUT OF SCOPE)
None — infrastructure phase.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| R4.1 | Bump version number in index.html and package.json | Current version: 1.2.0 in package.json. index.html has no version display string; About dialog in main.js hardcodes "v1.0.0" — both need updating to next version |
| R4.2 | Generate CHANGELOG.md from git history | No CHANGELOG.md exists. 92 commits total, 3 tags (v1.0.0, v1.1.4, v1.2.0). Conventional commits used throughout. Manual grouping by tag range is most accurate |
| R4.3 | Electron packaging (macOS, Windows) with electron-builder | electron-builder 26.7.0 installed (26.8.1 available). Build config in package.json. `npm run build:mac` and `npm run build:win` scripts exist. GitHub Actions release.yml handles multi-platform builds |
| R4.4 | Auto-update configuration for Electron builds | electron-updater 6.7.3 is already wired in main.js (checkForUpdates function). GitHub publish config present in package.json build section |
| R4.5 | Vercel deployment with proper cache headers | vercel.json exists with security headers. build:web script assembles public/. Missing: lazy bundles (demo-data.bundle.js, iac-generator.bundle.js) not copied in build-web.js |
| R4.6 | Update demo data to use Azure-native format (remove AWS account IDs) | Resolved in Phase 01 — demo-data.js uses Azure subscription UUIDs and tenant IDs only. No AWS-style numeric account IDs found |
</phase_requirements>

## Standard Stack

### Core
| Library | Version (installed) | Version (latest) | Purpose | Why Standard |
|---------|---------------------|------------------|---------|--------------|
| electron-builder | 26.7.0 | 26.8.1 | Cross-platform packaging | Already configured, GitHub publish provider set |
| electron-updater | 6.7.3 | 6.8.3 | Auto-update at runtime | Already wired in main.js, GitHub releases as update feed |
| esbuild | 0.27.3 | — | Bundle production assets before packaging | Already used via build.js |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| git log (manual) | — | CHANGELOG generation | No changelog tool is installed; manual grouping from `git log --format=...` by tag range |
| GitHub Actions | — | Multi-platform Electron builds | Windows and Linux require GitHub Actions runners; macOS local build only supplements |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Manual CHANGELOG | auto-changelog / conventional-changelog-cli | Tools add a dev dependency and require setup; git history is clean conventional commits so manual grouping is fast and produces better prose |
| Local electron-builder build | CI-only builds | macOS arm64 works locally (dist/mac-arm64 already exists); Windows requires Windows runner or cross-compile via GitHub Actions |

**Installation:** No new dependencies required. All tooling already installed.

## Architecture Patterns

### Release Trigger Flow
```
1. Write CHANGELOG.md
2. Bump version in package.json (e.g. 1.2.0 -> 1.3.0)
3. Fix About dialog version string in main.js
4. Rebuild production bundles (npm run bundle:prod)
5. Update public/ via build-web.js (add lazy bundle copies)
6. git push to main
7. GitHub Actions: check-version detects no tag for v1.3.0 -> creates tag
8. Parallel jobs: build-linux, build-windows, build-mac
9. publish-release: removes draft from GitHub release
10. Vercel: auto-deploys on push to main (via Vercel GitHub integration)
```

### Pattern 1: Version Synchronization
**What:** Version lives in package.json (single source of truth). Two secondary locations need manual sync: the About dialog message in main.js and any visible version display in index.html.
**When to use:** Every release.

Current state:
- `package.json`: `"version": "1.2.0"` — source of truth
- `main.js` line 102: `message: 'Azure Network Mapper v1.0.0'` — STALE, must update
- `index.html`: no version string found in HTML — no update needed

### Pattern 2: GitHub Release Auto-Trigger
**What:** release.yml fires when package.json changes on main branch. It reads the version, checks whether a git tag already exists for it, creates the tag if not, then kicks off the build matrix.
**When to use:** Simply bumping the version in package.json and pushing to main is sufficient.

Key: the workflow uses `--publish always` which pushes built artifacts to the GitHub release as assets. electron-updater then fetches `latest.yml` / `latest-mac.yml` from GitHub releases to check for updates.

### Pattern 3: Vercel Static Web Deployment
**What:** `npm run build:web` runs `build.js --production` then `build-web.js` to assemble `public/`. Vercel reads `vercel.json` which sets `"outputDirectory": "public"` and `"buildCommand": "npm run build:web"`.
**When to use:** Vercel auto-deploys on every push. No manual deploy step needed.

**Gap found:** `build-web.js` copies `dist/app.bundle.js` and `dist/app-core.js` but does NOT copy `dist/demo-data.bundle.js` or `dist/iac-generator.bundle.js`. The lazy-loader feature (Phase 4) will silently fail in the web version unless these are added.

### Pattern 4: Cache Headers
Current vercel.json applies the same security headers to all routes (`/(.*)`). For Vercel, cache optimization requires a second header block targeting hashed bundle files.

Recommended addition to vercel.json:
```json
{
  "source": "/dist/(.*)\\.js",
  "headers": [
    { "key": "Cache-Control", "value": "public, max-age=31536000, immutable" }
  ]
}
```

The `immutable` directive is correct here because `build.js --production` already injects MD5 content hashes into `index.html` script tags (`app.bundle.js?v=682b29b6`). The hash changes on every build, so old clients will never serve a stale bundle.

### Anti-Patterns to Avoid
- **Do not use `electron-builder --publish always` locally:** This pushes to GitHub releases from a dev machine and can create duplicate/incomplete releases. Use `--publish never` locally and let GitHub Actions handle publishing.
- **Do not forget `--prebuilt` flag if building locally first:** `npm run build:mac` already chains `npm run bundle:prod && electron-builder` correctly. Do not run them separately and then try to reuse output.
- **Do not skip macOS code signing for unsigned builds:** `"identity": null` is already set in package.json which forces an unsigned build. This is correct for open-source distribution without an Apple Developer account. Gatekeeper will warn users; this is expected.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Auto-update feed | Custom update server | electron-updater + GitHub Releases | Handles delta updates, rollback, staged rollouts, platform-specific channels. Already wired. |
| Cross-platform build matrix | Local builds for each OS | GitHub Actions release.yml | Windows NSIS installer requires Windows runner. macOS notarization requires macOS runner. |
| Cache-busting | Manual filename versioning | esbuild MD5 hash injection (already in build.js) | build.js already rewrites `?v=HASH` in index.html on every production build. |

## Common Pitfalls

### Pitfall 1: Version drift across files
**What goes wrong:** package.json says 1.3.0 but main.js About dialog still says v1.0.0. Users see wrong version in-app.
**Why it happens:** No automated sync between package.json and string literals in main.js.
**How to avoid:** Treat main.js line 102 as a checklist item in the version bump task. Could also use `require('./package.json').version` at runtime but that adds a file read — manual sync is simpler.
**Warning signs:** `git grep "v1\."` after the version bump shows mismatches.

### Pitfall 2: Lazy bundles missing from Vercel deployment
**What goes wrong:** Demo data and IaC generator buttons fail silently in the browser version. No 404 in the console unless DevTools are open.
**Why it happens:** `build-web.js` copies only `app.bundle.js` and `app-core.js`. The lazy bundles added in Phase 4 (`demo-data.bundle.js`, `iac-generator.bundle.js`) are not in the copy list.
**How to avoid:** Add explicit `fs.copyFileSync` calls for both lazy bundles in build-web.js.
**Warning signs:** `public/dist/` after `npm run build:web` lists only 2 JS files instead of 4.

### Pitfall 3: GitHub release stays in draft state
**What goes wrong:** Build artifacts are attached to a draft release. electron-updater won't serve updates from draft releases. Users can't download from the Releases page.
**Why it happens:** electron-builder with `--publish always` creates a draft release by default and attaches artifacts. The `publish-release` job in release.yml calls `gh release edit ... --draft=false` but it depends on all three build jobs succeeding.
**How to avoid:** Ensure all three platform builds pass before merging. If a build fails, the release stays in draft — delete the draft and retry after fixing.
**Warning signs:** GitHub Releases page shows "Draft" label. `gh release list` shows `Draft` status.

### Pitfall 4: macOS Gatekeeper blocking unsigned .app
**What goes wrong:** macOS users see "Azure Network Mapper is damaged and can't be opened."
**Why it happens:** `"identity": null` in electron-builder config skips code signing. Apple Gatekeeper quarantines unsigned .app files downloaded from the internet.
**How to avoid:** Document in README that users must run `xattr -cr /Applications/Azure\ Network\ Mapper.app` or right-click Open to bypass Gatekeeper. This is a known tradeoff for unsigned open-source apps.
**Warning signs:** User reports "damaged" or "can't be opened" error on macOS.

### Pitfall 5: electron-builder version mismatch
**What goes wrong:** Local version is 26.7.0, latest is 26.8.1. GitHub Actions installs from npm ci which uses package-lock.json, so CI and local are in sync. Minor patch — no action needed, but note if builds fail with cryptic errors.
**Why it happens:** Installed version lags behind latest.
**How to avoid:** Run `npm update electron-builder` before the release if CI failures occur.

## Code Examples

### Fix About dialog to use package.json version
```javascript
// main.js — replace hardcoded string at line 102
// Source: project convention (package.json as single source of truth)
const { version } = require('./package.json');
// ...in buildMenu(), About click handler:
message: `Azure Network Mapper v${version}`,
```

### Add lazy bundles to build-web.js
```javascript
// build-web.js — add after existing dist copies
// Source: project pattern (build-web.js lines 29-32)
fs.copyFileSync('dist/demo-data.bundle.js', path.join(OUT, 'dist/demo-data.bundle.js'));
fs.copyFileSync('dist/iac-generator.bundle.js', path.join(OUT, 'dist/iac-generator.bundle.js'));
```

### Add immutable cache headers to vercel.json
```json
{
  "source": "/dist/(.*)\\.js",
  "headers": [
    { "key": "Cache-Control", "value": "public, max-age=31536000, immutable" }
  ]
}
```
Place this as the FIRST entry in the `headers` array (more specific routes must precede the catch-all `/(.*)`).

### CHANGELOG.md git log commands
```bash
# Get commits between tags for CHANGELOG sections
git log v1.1.4..v1.2.0 --format="%s" --no-merges
git log v1.0.0..v1.1.4 --format="%s" --no-merges
git log v1.2.0..HEAD --format="%s" --no-merges
```

### Trigger release via version bump
```bash
# After updating all version strings and rebuilding
npm version minor  # bumps 1.2.0 -> 1.3.0 and creates git tag
# OR manually:
# edit package.json version field, then:
git add package.json CHANGELOG.md main.js build-web.js
git commit -m "chore(release): bump to v1.3.0"
git push origin main
# GitHub Actions detects no tag for v1.3.0, creates it, fires build matrix
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single monolithic bundle | Split bundles (app.bundle.js + lazy demo/iac) | Phase 4 | Lazy bundles must be copied to public/ |
| Full D3 library | Custom D3 bundle (5 modules) | Phase 4 | libs/d3.custom.min.js is already in electron-builder files list |

**Deprecated/outdated:**
- `main.js` About dialog version `v1.0.0`: Hardcoded, stale since initial commit. Replace with `require('./package.json').version`.

## Open Questions

1. **Target version number for this release**
   - What we know: Current is 1.2.0. This milestone adds testing, performance, and release prep across 5 phases — a substantial feature set.
   - What's unclear: Whether to go to 1.3.0 (minor) or 2.0.0 (major) given the scope.
   - Recommendation: Use `2.0.0` — this milestone (`M2: Production Readiness`) is named `v1.0` in STATE.md's milestone field, but the work constitutes a full production-readiness milestone. Either choice works; `2.0.0` signals production stability to users.

2. **R4.6 status verification**
   - What we know: Phase 01 fixed demo labels to Azure subscription format. No AWS-style numeric IDs found in demo-data.js.
   - What's unclear: Whether any path through app-core.js still surfaces AWS-style labels (e.g., 12-digit `accountId`).
   - Recommendation: Quick smoke test — load demo in browser, check account pill labels for numeric strings. If clean, mark R4.6 done.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Node.js | build scripts | Yes | v22.17.1 | — |
| electron-builder | R4.3 local build | Yes | 26.7.0 (latest 26.8.1) | GitHub Actions builds |
| GitHub Actions | R4.3 Windows/Linux builds | Yes (workflows exist) | — | — |
| Vercel CLI | R4.5 manual deploy | Not checked (auto-deploy via GitHub) | — | Push to main triggers auto-deploy |
| git | CHANGELOG generation | Yes | system | — |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None — all required tooling is available.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Playwright (E2E) + Jest + Node test runner (unit) |
| Config file | `playwright.config.js` (E2E), `jest` config in `package.json` |
| Quick run command | `npm run test:unit` |
| Full suite command | `npm run test:all` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R4.1 | Version in package.json matches About dialog | Manual smoke | Check main.js string matches package.json | N/A |
| R4.2 | CHANGELOG.md exists and covers all tags | Manual review | Verify file exists and contains v1.0.0, v1.1.4, v1.2.0, next version sections | N/A |
| R4.3 | Electron build produces DMG/ZIP (mac), NSIS/portable (win) | Manual/CI | `npm run build:mac` locally; CI matrix for win/linux | CI (release.yml) |
| R4.4 | Auto-updater fires checkForUpdates after 5s delay | Manual/smoke | Launch packaged app, check update check fires without crash | N/A |
| R4.5 | Vercel public/ includes all 4 JS bundles | Automated | `ls public/dist/*.js \| wc -l` == 4 after `npm run build:web` | N/A |
| R4.6 | Demo data shows Azure subscription labels, not numeric IDs | E2E smoke | Existing smoke.spec.js or visual.spec.js covers demo render | tests/smoke.spec.js |

### Sampling Rate
- **Per task commit:** `npm run test:unit`
- **Per wave merge:** `npm run test:all`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
None — existing test infrastructure covers all phase requirements. Release tasks are primarily file edits and build verification, not new code paths requiring new tests.

## Sources

### Primary (HIGH confidence)
- Direct file reads: `package.json`, `main.js`, `build.js`, `build-web.js`, `vercel.json`, `.github/workflows/release.yml`, `.github/workflows/ci.yml`
- Verified versions via `npm view`: electron-builder 26.8.1, electron-updater 6.8.3
- Git tag list: v1.0.0, v1.1.4, v1.2.0 confirmed by `git tag --list`
- Commit count: 92 total, 20 since v1.2.0 tag

### Secondary (MEDIUM confidence)
- Vercel cache header best practice: `immutable` directive appropriate when content-hash query strings are in use (confirmed by build.js MD5 hash injection pattern)
- macOS Gatekeeper behavior for `"identity": null` builds: well-documented Electron community pattern

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all tooling verified in package.json and node_modules
- Architecture: HIGH — release.yml and build scripts read directly
- Pitfalls: HIGH for items with direct code evidence; MEDIUM for macOS Gatekeeper behavior

**Research date:** 2026-03-30
**Valid until:** 2026-04-30 (stable tooling, 30-day window)
