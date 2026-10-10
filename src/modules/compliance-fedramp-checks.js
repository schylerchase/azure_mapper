// FedRAMP, NIST 800-171, and CMMC compliance checks.

import { _getRules, _ruleProps, _hasOpenSourcePrefixes, _isAllPorts, _isAllProtocols, _finding, _hasAssessmentEvidence } from './compliance-rule-primitives.js';

export function runFedRAMPChecks(data, framework) {
  const f = [];
  const roleAssignments = data.roleAssignments || [];
  const logAnalytics = data.logAnalyticsWorkspaces || [];
  const nsgs = data.nsgs || [];
  const nsgFlowLogs = data.nsgFlowLogs || [];
  const storageAccounts = data.storageAccounts || [];
  const keyVaults = data.keyVaults || [];
  const vms = data.vms || [];
  const mfaConfig = data.mfaConfig || {};
  const conditionalAccessPolicies = data.conditionalAccessPolicies || [];
  const managedDisks = data.managedDisks || [];
  const firewalls = data.firewalls || [];
  const defenderPlans = data.defenderPlans || [];

  // AC-2: Account management controls
  const roleCount = roleAssignments.length;
  if (roleCount > 100) {
    f.push(_finding({
      id: 'FEDRAMP-AC2', framework, severity: 'MEDIUM',
      title: 'AC-2: Large number of role assignments',
      message: `${roleCount} role assignments found: review for inactive or excessive access`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/roleAssignments',
      remediation: 'Conduct quarterly access reviews; remove stale assignments; use PIM for JIT access',
    }));
  }

  // AC-6: Least privilege
  const ownerAssignments = roleAssignments.filter(ra => {
    const props = ra.properties || ra;
    const roleId = (props.roleDefinitionId || '').toLowerCase();
    return roleId.includes('owner') || roleId.endsWith('/8e3af657-a8ff-443c-a75c-2fe8c4bcb635');
  });
  if (ownerAssignments.length > 5) {
    f.push(_finding({
      id: 'FEDRAMP-AC6', framework, severity: 'HIGH',
      title: 'AC-6: Excessive Owner role assignments',
      message: `${ownerAssignments.length} Owner role assignments: violates least privilege principle`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/roleAssignments',
      remediation: 'Reduce Owner assignments; use Contributor or custom roles with scoped permissions',
    }));
  }

  // AU-2: Audit events: verify logging infrastructure
  if (_hasAssessmentEvidence(data, 'logAnalyticsWorkspaces') && logAnalytics.length === 0) {
    f.push(_finding({
      id: 'FEDRAMP-AU2', framework, severity: 'CRITICAL',
      title: 'AU-2: No audit logging infrastructure',
      message: 'No Log Analytics workspace found: audit event collection requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.OperationalInsights/workspaces',
      remediation: 'Deploy Log Analytics workspace; enable Azure Activity Log and resource diagnostic settings',
    }));
  }

  // CM-7: Least functionality: check for overly permissive NSG rules
  let openRuleCount = 0;
  nsgs.forEach(nsg => {
    const rules = _getRules(nsg);
    rules.forEach(rule => {
      const rp = _ruleProps(rule);
      if (rp.direction === 'Inbound' && rp.access === 'Allow' &&
          _isAllProtocols(rule) && _isAllPorts(rule) && _hasOpenSourcePrefixes(rule)) {
        openRuleCount++;
      }
    });
  });
  if (openRuleCount > 0) {
    f.push(_finding({
      id: 'FEDRAMP-CM7', framework, severity: 'HIGH',
      title: 'CM-7: Overly permissive network rules',
      message: `${openRuleCount} NSG rule(s) allow all inbound traffic: least functionality violated`,
      resource: 'NSGs', resourceId: '', resourceType: 'Microsoft.Network/networkSecurityGroups',
      remediation: 'Remove or restrict all "allow any" inbound rules to specific required ports and sources',
    }));
  }

  // IA-2: Multi-factor authentication
  const hasMfaPolicy = conditionalAccessPolicies.some(p => {
    const props = p.properties || p;
    const gc = props.grantControls || {};
    return (gc.builtInControls || []).includes('mfa');
  });
  if (!hasMfaPolicy && conditionalAccessPolicies.length > 0) {
    f.push(_finding({
      id: 'FEDRAMP-IA2', framework, severity: 'CRITICAL',
      title: 'IA-2: No MFA conditional access policy',
      message: 'No conditional access policy enforcing MFA found: identification/authentication gap',
      resource: 'Azure AD', resourceId: '', resourceType: 'Microsoft.Authorization/conditionalAccessPolicies',
      remediation: 'Create conditional access policy requiring MFA for all users on sensitive operations',
    }));
  }

  // SC-7: Boundary protection: firewall presence
  if (firewalls.length === 0 && nsgs.length > 0) {
    f.push(_finding({
      id: 'FEDRAMP-SC7', framework, severity: 'HIGH',
      title: 'SC-7: No centralized boundary protection',
      message: 'No Azure Firewall deployed: boundary protection relies only on NSGs',
      resource: 'Network', resourceId: '', resourceType: 'Microsoft.Network/azureFirewalls',
      remediation: 'Deploy Azure Firewall for centralized boundary protection and traffic inspection',
    }));
  }

  // SC-28: Protection of data at rest
  const unencryptedDisks = managedDisks.filter(d => {
    const props = d.properties || d;
    const enc = props.encryption || {};
    return !enc.type && !enc.diskEncryptionSetId;
  });
  if (unencryptedDisks.length > 0) {
    f.push(_finding({
      id: 'FEDRAMP-SC28', framework, severity: 'HIGH',
      title: 'SC-28: Unprotected data at rest',
      message: `${unencryptedDisks.length} managed disk(s) without explicit encryption: data at rest protection gap`,
      resource: 'Multiple', resourceId: '', resourceType: 'Microsoft.Compute/disks',
      remediation: 'Enable encryption with customer-managed keys for all managed disks',
    }));
  }

  // SI-4: Information system monitoring
  if (_hasAssessmentEvidence(data, 'defenderPlans') && defenderPlans.length === 0) {
    f.push(_finding({
      id: 'FEDRAMP-SI4', framework, severity: 'HIGH',
      title: 'SI-4: No system monitoring',
      message: 'No Microsoft Defender for Cloud plans enabled: continuous monitoring requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Security/pricings',
      remediation: 'Enable Microsoft Defender for Cloud on all resource types for continuous monitoring',
    }));
  }

  return f;
}
