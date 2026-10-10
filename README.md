<p align="center">
  <img src="logo.png" alt="Azure Mapper" width="300">
</p>

<h1 align="center">Azure Network Mapper</h1>

<p align="center">
  Interactive topology visualization, compliance auditing, and infrastructure reporting for Azure environments.
</p>

<p align="center">
  <a href="https://schylerchase.github.io/azure_mapper/">Live Demo</a> &middot;
  <a href="https://github.com/schylerchase/azure_mapper/releases/latest">Download Desktop App</a> &middot;
  <a href="#quick-start">Quick Start</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux%20%7C%20Browser-lightgrey" alt="Platform">
</p>

---

## What It Does

Paste Azure CLI JSON exports (or scan directly from the desktop app) and get an interactive network map with compliance scoring, traffic flow tracing, governance rules, and exportable reports. Zero backend, zero dependencies for the browser version.

> **Looking for AWS?** See [AWS Network Mapper](https://github.com/schylerchase/aws_mapper) for the AWS equivalent.

---

## Features

### Visualization
- D3.js SVG canvas with VNets, public/private subnets, NSGs, peerings, firewalls, and 30+ resource types
- Three layout modes: **Grid** (columns), **Landing Zone** (hub-spoke), **Executive Overview**
- Traffic flow tracing with NSG rule evaluation and flow analysis dashboard
- Blast radius analysis for any resource
- Detail level cycling (collapsed / default / expanded) with keyboard shortcuts
- **Design Mode**: build infrastructure from scratch with a drag-and-drop palette

### Compliance Engine
28 controls across 4 frameworks, evaluated against every applicable resource:

| Framework | Controls | Coverage |
|-----------|----------|----------|
| CIS Azure 3.0 | 8 | NSG rules, storage encryption, disk encryption, Bastion |
| Azure Architecture | 15 | Best practices, HA, private endpoints, network segmentation |
| SOC 2 | 2 | TLS enforcement, outbound access controls |
| PCI DSS | 3 | Network segmentation, admin credentials, HTTPS listeners |

Full compliance dashboard with severity filtering, framework breakdowns, and remediation guidance.

### Governance Rules Engine
- Automatic resource classification with tiered governance (Critical / High / Standard / Low)
- Pattern-based rule matching with pre-compiled RegExp for performance
- Governance dashboard with per-tier breakdown and CSV/JSON export

### NSG / Firewall Dashboard
- Unified view of all NSGs and their security rules
- Search, filter by direction/access, sort by name or open ingress count
- Summary cards: total NSGs, total rules, allow rules, open ingress
- Export as CSV, JSON, or Azure CLI commands

### Report Builder
Modular report generator with drag-to-reorder sections, live preview, and standalone HTML export:
- Executive Summary
- Compliance Report
- Resource Governance
- Resource Inventory
- NSG Rule Summary
- Architecture Notes

### Flow Analysis
- Traffic flow tracing between any source/destination with NSG rule evaluation
- Flow exposure dashboard ranking subnets by exposure level
- One-click trace launch from context menu or flow entries

### Export Formats

| Format | Description |
|--------|-------------|
| PNG | Map screenshot |
| SVG | Vector format |
| Terraform HCL | Azure provider with `azurerm` resources |
| ARM Template | Native Azure JSON deployment template |
| Bicep | Azure DSL format |
| HTML Report | Standalone assessment report |
| CSV / XLSX | Compliance findings and NSG rules |
| .azmap | Full project save/restore |

### Other Capabilities
- Snapshot timeline: capture, browse, and compare historical infrastructure states
- Diff/change detection between snapshots
- Annotations: pin searchable notes to any resource
- Resource search with fuzzy matching
- Context menus with resource-specific actions
- Auto-save to browser every 30 seconds

---

## Quick Start

### Browser (no install)

1. Open the [live demo](https://schylerchase.github.io/azure_mapper/) or `index.html` locally
2. Click **Load Demo** or paste Azure CLI JSON into the input fields
3. Click **Render Map**

### Desktop App (Electron)

Download from [Releases](https://github.com/schylerchase/azure_mapper/releases/latest). Available for macOS (.dmg), Windows (.exe), and Linux (.AppImage).

The desktop app adds:
- **Scan Azure** button -- runs Azure CLI commands automatically
- Native file save/open/export dialogs
- **Import Folder** for bulk JSON loading
- XLSX compliance export
- Auto-update via GitHub Releases

### Export Azure Data

A Bash export script is included for extracting data from your Azure subscriptions:

```bash
./export-azure-data.sh -s my-subscription
./export-azure-data.sh -s my-subscription -g my-resource-group
./export-azure-data.sh -s my-subscription -l eastus
```

The script runs 30+ `az` CLI commands and outputs JSON files ready for import.

---

## Supported Azure Resources

| Category | Resources |
|----------|-----------|
| Network | VNets, Subnets, Route Tables, NSGs, NICs, ASGs |
| Gateways | NAT Gateways, Private Endpoints, Azure Bastion |
| Compute | Virtual Machines, Function Apps, Container Instances, AKS |
| Database | SQL Servers, SQL Databases, Redis Caches, Synapse |
| Load Balancing | Application Gateways, Load Balancers, Front Door |
| Connectivity | VNet Peerings, VPN Connections, Virtual WANs, Virtual Hubs |
| Storage | Storage Accounts, Managed Disks, Snapshots |
| DNS | DNS Zones (Public), DNS Zones (Private), DNS Record Sets |
| Security | WAF Policies, Azure Firewalls, Network Watchers |
| Identity | Role Assignments, Role Definitions, Service Principals |
| Management | Resource Groups |

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Search resources |
| `?` | Help overlay |
| `D` | Generate demo data |
| `R` | Render map |
| `F` | Zoom to fit |
| `N` | Notes / Annotations |
| `H` | Snapshot timeline |
| `[` / `]` | Cycle detail level |
| `+` / `-` | Zoom in / out |
| `Shift+B` | Report Builder |
| `Shift+C` | Compliance Dashboard |
| `Shift+D` | Design Mode |
| `Shift+E` | Flow Exposure Dashboard |
| `Shift+F` | NSG / Firewall Dashboard |
| `Shift+G` | Governance Dashboard |
| `Shift+R` | Resource List |
| `Shift+T` | Traffic Flow Tracer |
| `Ctrl+S` | Save project |

---

## Build

```bash
npm run build:mac    # macOS (dmg + zip)
npm run build:win    # Windows (nsis + portable)
npm run build:linux  # Linux (AppImage + deb)
npm run build:all    # all platforms
```

## Test

```bash
npm test
```

---

## Source Layout

`src/app-core.js` is an assembly manifest. It declares ordered
`// @app-core-region` entries, and `build.js` expands those feature-owned source
regions into `dist/app-core.js` for the browser and Electron runtime.

Primary runtime owners:

| Area | Owner |
|------|-------|
| App shell and boot wiring | `src/modules/app-shell.js` |
| Shared HTML escaping and legacy escape shim | `src/modules/html-escape-adapter.js` |
| Notifications and legacy toast shim | `src/modules/notification-adapter.js` |
| Browser/Electron downloads and legacy download shim | `src/modules/download-adapter.js` |
| Browser local/session storage access | `src/modules/browser-storage-adapter.js` |
| Project file, folder picker, and save dialog access | `src/modules/project-file-access.js` |
| Explicit render/map/compliance compatibility bridge | `src/modules/render-context.js` |
| App bundle compatibility publishing and lazy bundle loaders | `src/modules/app-compatibility-publisher.js` |
| Compliance dispatch, cache, and compatibility publish point | `src/modules/compliance-engine.js` |
| Compliance rule predicates, resource access, and Checkov mapping | `src/modules/compliance-rule-primitives.js` |
| CIS Azure policy checks | `src/modules/compliance-cis-azure-checks.js` |
| Cloud Adoption Framework policy checks | `src/modules/compliance-caf-checks.js` |
| SOC 2 policy checks | `src/modules/compliance-soc2-checks.js` |
| PCI DSS policy checks | `src/modules/compliance-pci-checks.js` |
| Azure backup, uptime, and disaster recovery policy checks | `src/modules/compliance-budr-azure-checks.js` |
| FedRAMP, NIST 800-171, and CMMC policy checks | `src/modules/compliance-fedramp-checks.js` |
| Map viewport focus, zoom, and highlight controls | `src/modules/map-viewport.js` |
| Stable map viewport browser/AppModules publish point | `src/modules/map-viewport-compatibility.js` |
| Storage account topology, access posture, and map cards | `src/modules/storage-topology.js` |
| Subnet service inventory trees for topology and flow tracing | `src/modules/subnet-resource-tree.js` |
| Traffic flow tracing detail panel | `src/modules/flow-tracing-panel.js` |
| Traffic flow tracing trace engine, mode control, and flow overlay UI | `src/modules/flow-tracing-runtime.js` |
| Traffic flow analysis detail panel | `src/modules/flow-analysis-panel.js` |
| Traffic flow analysis full dashboard | `src/modules/flow-analysis-dashboard.js` |
| Traffic flow analysis discovery, overlays, and mode control | `src/modules/flow-analysis-runtime.js` |
| Topology render orchestration and runtime data preparation | `src/modules/topology-renderer.js` |
| Standard grid VNet/subnet/gateway geometry | `src/modules/topology-grid-geometry.js` |
| Standard grid region grouping and backplates | `src/modules/topology-grid-region-bands.js` |
| Standard grid resource badges and DNS/storage/CDN sections | `src/modules/topology-grid-resource-sections.js` |
| Shared topology status chips and footer controls | `src/modules/topology-status-controls.js` |
| Standard grid topology layout | `src/modules/topology-grid-layout.js` |
| Landing-zone resource badges and DNS/storage/CDN sections | `src/modules/topology-landing-zone-resource-sections.js` |
| Landing-zone topology layout | `src/modules/topology-landing-zone.js` |
| Executive overview topology layout | `src/modules/topology-executive-overview.js` |
| Pure resource profile/type resolution | `src/modules/resource-profile.js` |
| Search/detail navigation and spotlight | `src/modules/resource-navigation.js` |
| Pure search index construction and matching | `src/modules/search-index.js` |
| Search overlay and search index | `src/modules/search-panel.js` |
| Subnet and gateway detail panels with runtime context lookup helpers | `src/modules/detail-panel.js` |
| Clickable resource list drawer | `src/modules/resource-list-panel.js` |
| Project save/load | `src/modules/project-file-io.js` |
| Report import | `src/modules/report-import.js` |
| Folder import workflow | `src/modules/folder-import.js` |
| Desktop Azure scan/menu/update API adapter and desktop availability flag | `src/modules/desktop-azure-adapter.js` |
| Electron scan/menu hooks | `src/modules/electron-azure-actions.js` |
| Timeline snapshots, notes, note badges, and compliance badge overlays | `src/modules/timeline-notes-view.js` |
| Firewall dashboard row, filter, sort, and group model | `src/modules/firewall-dashboard-model.js` |
| Firewall edit state, validation, snapshots, and Azure CLI command generation | `src/modules/firewall-change-set.js` |
| Firewall inline/full-panel rendering and rule edit UI | `src/modules/firewall-editor-runtime.js` |
| Governance inventory row, filter, and enrichment model | `src/modules/governance-inventory-model.js` |
| Governance classification rules, scoring, tier metadata, and owner API | `src/modules/governance-classification.js` |
| Governance inventory dashboard runtime | `src/modules/governance-inventory-runtime.js` |
| IAM review preparation, effective permissions, and principal detail panels | `src/modules/governance-iam-review.js` |
| Unified dashboard shell | `src/modules/dashboard-shell.js` |
| Unified dashboard state and account filter helpers | `src/modules/dashboard-state.js` |
| BUDR dashboard rendering and exports | `src/modules/budr-dashboard.js` |
| Dependency graph overlay and blast-radius map highlighting | `src/modules/dependency-graph-runtime.js` |
| Pure diff comparison engine | `src/modules/diff-engine.js` |
| Diff mode browser snapshot comparison | `src/modules/diff-snapshot-compare.js` |
| Diff mode browser wiring, compare dashboard, and exports | `src/modules/diff-mode-runtime.js` |
| Report dashboard, picker, preview, and metadata controls | `src/modules/report-dashboard.js` |
| Report HTML shell CSS, table controls, and SVG style serialization | `src/modules/report-html-assets.js` |
| Report section rendering | `src/modules/report-render-functions.js` |
| Report HTML, CSV, and DOCX export assembly | `src/modules/report-builder.js` |
| Report XLSX workbook generation and SheetJS export flow | `src/modules/report-xlsx-export.js` |
| Export toolbar adapters, layout mode, and detail-level controls | `src/modules/export-utilities-runtime.js` |
| Legacy VSDX helper browser surface | `src/modules/export-utils-compatibility.js` |
| Map PNG export | `src/modules/map-png-export.js` |
| VSDX network diagram export | `src/modules/vsdx-network-export.js` |
| Lucid icon package and `.lucid` ZIP download | `src/modules/lucid-export-package.js` |
| Lucid export data collection and relationship indexes | `src/modules/lucid-network-export-data.js` |
| Lucid landing-zone layout export | `src/modules/lucid-landing-zone-export.js` |
| Lucid standard network layout export | `src/modules/lucid-network-export.js` |
| IaC modal controller and lazy generator dispatch | `src/modules/iac-generator-runtime.js` |
| IaC lazy bundle facade | `src/modules/iac-generator.js` built as `dist/iac-generator.bundle.js` |
| IaC resource naming and formatting | `src/modules/iac-resource-formatters.js` |
| Terraform `azurerm` generation | `src/modules/iac-terraform-generator.js` |
| ARM template generation | `src/modules/iac-arm-template-generator.js` |
| Bicep generation | `src/modules/iac-bicep-generator.js` |
| Checkov policy and ARM fixture generation | `src/modules/iac-checkov-generator.js` |
| Azure CLI command generation | `src/modules/iac-azure-cli-generator.js` |
| IaC syntax highlighting | `src/modules/iac-syntax-highlighting.js` |

Runtime feature owners should stay free of direct `window.*`, `_rlCtx`, map
group, toast, download, and escape bridge access. Compatibility belongs in the
named adapter owners above, or in deliberately quarantined sidecars until those
are retired.

---

## See Also

- **[AWS Network Mapper](https://github.com/schylerchase/aws_mapper)** -- the AWS equivalent with VPCs, security groups, transit gateways, and 25+ AWS resource types

---

## License

MIT
