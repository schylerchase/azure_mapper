// Main entry point for Azure Network Mapper
// Imports all modules and initializes the application
// This file is bundled by esbuild into dist/app.bundle.js

// Core utilities
import { SEV_ORDER, FW_LABELS, EOL_RUNTIMES, EFFORT_LABELS, EFFORT_TIME, PRIORITY_META, TIER_META, PRIORITY_ORDER, PRIORITY_KEYS, MUTE_KEY, NOTES_KEY, SNAP_KEY, SAVE_KEY, MAX_SNAPSHOTS, SAVE_INTERVAL, NOTE_CATEGORIES } from './modules/constants.js';
import { safeParse, ext, esc, gn, sid, clsGw, isShared, gcv, gch, gv, parseResourceId, getTenantFromResource } from './modules/utils.js';
import { showToast, toggleClass, setVisible, getEl, qs, qsa } from './modules/dom-helpers.js';
import { _prefs, loadPrefs, savePrefs } from './modules/prefs.js';
import { publishLegacyAppModules, ensureLegacyComplianceFindings, installLazyBundleLoaders } from './modules/app-compatibility-publisher.js';

// Cloud environment management
import { CLOUDS, getCloudEnv, setCloudEnv, getCloudConfig, getComplianceFrameworks, isServiceAvailable, getPortalUrl, detectCloudFromEndpoint } from './modules/cloud-env.js';

// Feature engines
// Note: demo-data and iac-generator are lazy-loaded by app-compatibility-publisher.js.
import { ipToInt, intToIp, parseCIDR, cidrToString, splitCIDR, cidrContains, cidrOverlap, ipInCIDR } from './modules/cidr-engine.js';
import { runComplianceChecks, invalidateComplianceCache } from './modules/compliance-engine.js';

// Network rules (Azure NSG + UDR evaluation)
import { evaluateNsgRules, evaluateNsgPath, evaluateRoute, protocolMatch, portMatch, addressMatch, classifySubnet, hasExplicitOutbound } from './modules/network-rules.js';

// Shared state (cross-cutting globals used by 5+ regions)
import * as State from './modules/state.js';

// Safe DOM builders (used by extracted modules, available to inline code during transition)
import { buildEl, buildOption, buildSelect, buildButton, setText, replaceChildren, safeHtml } from './modules/dom-builders.js';

// BUDR engine (backup, uptime, disaster recovery assessment)
import {
  _BUDR_STRATEGY, _BUDR_STRATEGY_ORDER, _BUDR_STRATEGY_LEGEND,
  _BUDR_RTO_RPO, _BUDR_EST_MINUTES, _TIER_TARGETS,
  runBUDRChecks, _budrTierCompliance, _fmtMin,
  _enrichBudrWithClassification, _reapplyBUDROverrides,
  _getBUDRTierCounts, _getBudrComplianceCounts,
  budrFindings, budrAssessments, budrOverrides,
  setBudrFindings, setBudrAssessments, setBudrOverrides,
  _budrFindings, _budrAssessments, _budrOverrides
} from './modules/budr-engine.js';

// Dependency graph (pure logic — DOM display functions remain inline)
import {
  buildDependencyGraph, getBlastRadius, getResType, getResName,
  clearBlastRadius, resetDepGraph, isBlastActive,
  depGraph, blastActive
} from './modules/dep-graph.js';

// RBAC engine (Azure role assignment analysis and compliance checks)
import {
  analyzeRoleAssignments, findOverPrivileged, findOrphanedAssignments,
  countOwnersPerScope, findGuestPrivileges, findServicePrincipalRisks,
  classifyPermission, getScopeLevel,
  parseRBACData, getRBACForScope
} from './modules/iam-engine.js';

// Flow tracing (trace engine, network position — DOM/SVG rendering remains inline)
import * as FlowTracing from './modules/flow-tracing.js';

// Flow analysis (traffic flow discovery — dashboard rendering remains inline)
import * as FlowAnalysis from './modules/flow-analysis.js';

// Multi-tenant (context building, merging, Lighthouse — DOM panels remain inline)
import * as MultiTenant from './modules/multi-tenant.js';

// Phase 5: Core
// Export utilities (VSDX layout and XML builders; DOM export handlers remain inline)
import * as ExportUtils from './modules/export-utils.js';
import './modules/export-utils-compatibility.js';

// IaC generator: lazy-loaded by app-compatibility-publisher.js — not in initial bundle

// Normalization utilities (extracted from app-core.js for unit testability)
import { _normalizeAzureResources, _normTags, matchFile, fileMap, _friendlyFolderLabel } from './modules/normalization.js';

// NOTE: diff-engine.js and report-builder.js are NOT imported here.
// They have top-level DOM event listeners and are loaded via separate <script type="module"> tags
// in index.html (after DOM is ready).

const appModules = {
  // Constants (clean + underscore-prefixed aliases for inline code)
  SEV_ORDER, FW_LABELS, EOL_RUNTIMES, EFFORT_LABELS, EFFORT_TIME,
  PRIORITY_META, TIER_META, PRIORITY_ORDER, PRIORITY_KEYS,
  MUTE_KEY, NOTES_KEY, SNAP_KEY, SAVE_KEY, MAX_SNAPSHOTS, SAVE_INTERVAL, NOTE_CATEGORIES,
  _SEV_ORDER: SEV_ORDER,
  _FW_LABELS: FW_LABELS,

  // Utils
  safeParse, ext, esc, gn, sid, clsGw, isShared, gcv, gch, gv,
  parseResourceId, getTenantFromResource,

  // Cloud environment
  CLOUDS, getCloudEnv, setCloudEnv, getCloudConfig, getComplianceFrameworks,
  isServiceAvailable, getPortalUrl, detectCloudFromEndpoint,

  // DOM helpers
  showToast, toggleClass, setVisible, getEl, qs, qsa,

  // Prefs
  _prefs, loadPrefs, savePrefs,

  // CIDR engine
  ipToInt, intToIp, parseCIDR, cidrToString, splitCIDR, cidrContains, cidrOverlap, ipInCIDR,

  // Compliance
  runComplianceChecks, invalidateComplianceCache,

  // Network rules (Azure NSG + UDR)
  evaluateNsgRules, evaluateNsgPath, evaluateRoute, hasExplicitOutbound,
  protocolMatch, portMatch, addressMatch, classifySubnet,

  // Shared state
  State,

  // DOM builders
  buildEl, buildOption, buildSelect, buildButton, setText, replaceChildren, safeHtml,

  // BUDR engine
  _BUDR_STRATEGY, _BUDR_STRATEGY_ORDER, _BUDR_STRATEGY_LEGEND,
  _BUDR_RTO_RPO, _BUDR_EST_MINUTES, _TIER_TARGETS,
  runBUDRChecks, _budrTierCompliance, _fmtMin,
  _enrichBudrWithClassification, _reapplyBUDROverrides,
  _getBUDRTierCounts, _getBudrComplianceCounts,
  _budrFindings, _budrAssessments, _budrOverrides,
  setBudrFindings, setBudrAssessments, setBudrOverrides,

  // Dependency graph
  buildDependencyGraph, getBlastRadius, getResType, getResName,
  clearBlastRadius, resetDepGraph, isBlastActive,

  // RBAC engine (Azure role-based access control)
  analyzeRoleAssignments, findOverPrivileged, findOrphanedAssignments,
  countOwnersPerScope, findGuestPrivileges, findServicePrincipalRisks,
  classifyPermission, getScopeLevel,
  parseRBACData, getRBACForScope,

  // Phase 3: Feature Engines
  FlowTracing,
  FlowAnalysis,
  MultiTenant,

  // Phase 5: Core
  ExportUtils,
  // IacGenerator: lazy-loaded by app-compatibility-publisher.js — not in AppModules at startup

  // Note: diff-engine and report-builder loaded via separate script tags (DOM-dependent)

  // Normalization (used by app-core.js inline code via window globals)
  _normalizeAzureResources, _normTags, matchFile, fileMap, _friendlyFolderLabel,
};

publishLegacyAppModules(appModules);
ensureLegacyComplianceFindings();
installLazyBundleLoaders();

console.log('Azure Network Mapper modules loaded');
