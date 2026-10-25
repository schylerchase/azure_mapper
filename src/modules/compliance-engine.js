// Compliance checks engine for Azure Network Mapper
// Public API and framework dispatch only. Domain checks live in framework owners.

import { getCloudEnv, getComplianceFrameworks } from './cloud-env.js';
import { runBUDRChecks } from './budr-engine.js';
import { analyzeRoleAssignments, getRbacData } from './iam-engine.js';
import { CKV_MAP } from './compliance-rule-primitives.js';
import { runCISAzureChecks } from './compliance-cis-azure-checks.js';
import { runCAFChecks } from './compliance-caf-checks.js';
import { runSOC2Checks } from './compliance-soc2-checks.js';
import { runPCIChecks } from './compliance-pci-checks.js';
import { runBUDRAzureChecks } from './compliance-budr-azure-checks.js';
import { runFedRAMPChecks } from './compliance-fedramp-checks.js';

let _complianceFindings = [];
let _complianceCacheData = null;
let _complianceCacheCloud = null;

export function getComplianceFindings() {
  return _complianceFindings;
}

export function clearComplianceCache() {
  _complianceCacheData = null;
  _complianceCacheCloud = null;
  _complianceFindings = [];
}

export function invalidateComplianceCache() {
  clearComplianceCache();
}

function runFrameworkChecks(data, frameworks) {
  const findings = [];

  if (frameworks.includes('CIS')) {
    findings.push(...runCISAzureChecks(data));
  }
  if (frameworks.includes('CAF')) {
    findings.push(...runCAFChecks(data));
  }
  if (frameworks.includes('SOC2')) {
    findings.push(...runSOC2Checks(data));
  }
  if (frameworks.includes('PCI')) {
    findings.push(...runPCIChecks(data));
  }
  if (frameworks.includes('BUDR')) {
    findings.push(...runBUDRAzureChecks(data));
  }

  const governmentFrameworks = [
    'FEDRAMP_MOD',
    'FEDRAMP_HIGH',
    'NIST_800_171',
    'CMMC'
  ];
  for (const framework of governmentFrameworks) {
    if (frameworks.includes(framework)) {
      findings.push(...runFedRAMPChecks(data, framework));
    }
  }

  return findings;
}

function appendBudrEngineFindings(data, findings) {
  try {
    const budrFindings = runBUDRChecks(data);
    if (budrFindings && budrFindings.length > 0) {
      findings.push(...budrFindings);
    }
  } catch (e) {
    console.warn('BUDR engine checks failed:', e);
  }
}

function appendIamFindings(data, findings) {
  try {
    const rbacData = Object.prototype.hasOwnProperty.call(data, 'rbac') ? data.rbac : getRbacData();
    if (!rbacData) return;

    const assignments = rbacData.roleAssignments || rbacData;
    const definitions = rbacData.roleDefinitions || [];
    if (Array.isArray(assignments) && assignments.length) {
      findings.push(...analyzeRoleAssignments(assignments, definitions));
    }
  } catch (e) {
    console.warn('IAM compliance checks failed:', e);
  }
}

function normalizeFindingMetadata(finding) {
  if (!finding.checkovId && CKV_MAP[finding.id]) {
    finding.checkovId = CKV_MAP[finding.id];
  }
  if (!finding.control) finding.control = finding.id;
  if (!finding.resourceName) finding.resourceName = finding.resource;
}

function publishComplianceFindings(findings) {
  _complianceFindings = findings;
  if (typeof window !== 'undefined') {
    window._complianceFindings = _complianceFindings;
  }
  return _complianceFindings;
}

/**
 * Run all compliance checks against the provided Azure data.
 * @param {Object} data - Parsed Azure resource data context
 * @param {string} [cloudEnv] - Cloud environment override (defaults to current)
 * @returns {Array} Array of compliance findings
 */
export function runComplianceChecks(data, cloudEnv) {
  const env = cloudEnv || getCloudEnv();
  if (_complianceCacheData === data && _complianceCacheCloud === env && _complianceFindings.length > 0) {
    return _complianceFindings;
  }

  _complianceCacheData = data;
  _complianceCacheCloud = env;
  data.assessmentGaps={};
  const frameworks = getComplianceFrameworks(env);
  const findings = runFrameworkChecks(data, frameworks);

  appendBudrEngineFindings(data, findings);
  appendIamFindings(data, findings);
  findings.forEach(normalizeFindingMetadata);

  return publishComplianceFindings(findings);
}
