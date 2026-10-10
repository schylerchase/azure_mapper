// SOC 2 compliance checks.

import { _rn, _finding, _hasAssessmentEvidence } from './compliance-rule-primitives.js';

export function runSOC2Checks(data) {
  const f = [];
  const storageAccts = data.storageAccounts || [];
  const managedDisks = data.managedDisks || [];
  const nsgs = data.nsgs || [];
  const monitorConfig = data.monitorConfig || {};
  const keyVaults = data.keyVaults || [];
  const diagnosticSettings = data.diagnosticSettings || [];

  // SOC2-TLS: TLS 1.2 minimum on storage accounts
  storageAccts.forEach(sa => {
    const props = sa.properties || sa;
    const minTls = props.minimumTlsVersion || '';
    if (!minTls || (minTls !== 'TLS1_2' && minTls !== 'TLS1_3')) {
      f.push(_finding({
        id: 'SOC2-TLS', framework: 'SOC2', severity: 'HIGH',
        title: 'Storage account TLS < 1.2',
        message: `Storage account "${_rn(sa)}" does not enforce TLS 1.2 minimum: data in transit at risk`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Set minimumTlsVersion to TLS1_2 on all storage accounts',
      }));
    }
  });

  // SOC2-DISK: Encryption at rest for managed disks
  managedDisks.forEach(disk => {
    const props = disk.properties || disk;
    const encryption = props.encryption || {};
    const encType = encryption.type || props.encryptionSettingsCollection?.enabled;
    if (!encType && !props.encryptionSettingsCollection) {
      f.push(_finding({
        id: 'SOC2-DISK', framework: 'SOC2', severity: 'HIGH',
        title: 'Managed disk without encryption',
        message: `Managed disk "${_rn(disk)}" may not have encryption at rest configured`,
        resource: _rn(disk), resourceId: disk.id || '', resourceType: 'Microsoft.Compute/disks',
        remediation: 'Enable server-side encryption with platform-managed or customer-managed keys',
      }));
    }
  });

  // SOC2-FLOWLOG: NSG flow logs not enabled
  const nsgFlowLogs = data.nsgFlowLogs || [];
  const nsgWithFlowLog = new Set(
    nsgFlowLogs.map(fl => {
      const props = fl.properties || fl;
      return (props.targetResourceId || '').toLowerCase();
    })
  );
  if(_hasAssessmentEvidence(data,'nsgFlowLogs'))nsgs.forEach(nsg => {
    const nsgId = (nsg.id || '').toLowerCase();
    if (nsgId && !nsgWithFlowLog.has(nsgId)) {
      f.push(_finding({
        id: 'SOC2-FLOWLOG', framework: 'SOC2', severity: 'HIGH',
        title: 'NSG flow logs not enabled',
        message: `NSG "${_rn(nsg)}" does not have flow logs enabled: insufficient audit trail`,
        resource: _rn(nsg), resourceId: nsg.id || '', resourceType: 'Microsoft.Network/networkSecurityGroups',
        remediation: 'Enable NSG flow logs (v2) and send to Log Analytics for retention and analysis',
      }));
    }
  });

  // SOC2-MONITOR: No Azure Monitor configured
  const logAnalytics = data.logAnalyticsWorkspaces || [];
  const workspaceEvidence=_hasAssessmentEvidence(data,'logAnalyticsWorkspaces');
  const diagnosticEvidence=_hasAssessmentEvidence(data,'diagnosticSettings');
  if (logAnalytics.length === 0 && diagnosticSettings.length === 0 &&
      workspaceEvidence && diagnosticEvidence) {
    f.push(_finding({
      id: 'SOC2-MONITOR', framework: 'SOC2', severity: 'HIGH',
      title: 'No Azure Monitor / Log Analytics configured',
      message: 'No Log Analytics workspaces or diagnostic settings found: insufficient monitoring',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.OperationalInsights/workspaces',
      remediation: 'Deploy Log Analytics workspace and enable diagnostic settings on all resources',
    }));
  }

  // SOC2-KV-RBAC: Key Vault not using RBAC
  keyVaults.forEach(kv => {
    const props = kv.properties || kv;
    const rbac = props.enableRbacAuthorization;
    if (rbac !== true) {
      f.push(_finding({
        id: 'SOC2-KV-RBAC', framework: 'SOC2', severity: 'MEDIUM',
        title: 'Key Vault not using RBAC authorization',
        message: `Key Vault "${_rn(kv)}" uses access policies instead of RBAC: less auditable`,
        resource: _rn(kv), resourceId: kv.id || '', resourceType: 'Microsoft.KeyVault/vaults',
        remediation: 'Enable RBAC authorization mode for centralized access management and audit logging',
      }));
    }
  });

  // SOC2-SA-ENC: Storage account without infrastructure encryption
  storageAccts.forEach(sa => {
    const props = sa.properties || sa;
    const enc = props.encryption || {};
    if (!enc.requireInfrastructureEncryption && !enc.services) {
      f.push(_finding({
        id: 'SOC2-SA-ENC', framework: 'SOC2', severity: 'MEDIUM',
        title: 'Storage account without explicit encryption settings',
        message: `Storage account "${_rn(sa)}" has no explicit encryption configuration`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Enable infrastructure encryption and customer-managed keys for enhanced protection',
      }));
    }
  });

  return f;
}
