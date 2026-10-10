// PCI DSS compliance checks.

import { _rn, _finding, _subnetProps, _hasAssessmentEvidence } from './compliance-rule-primitives.js';

export function runPCIChecks(data) {
  const f = [];
  const nsgs = data.nsgs || [];
  const sqlServers = data.sqlServers || [];
  const sqlDatabases = data.sqlDatabases || [];
  const managedDisks = data.managedDisks || [];
  const appGateways = data.appGateways || [];
  const storageAccounts = data.storageAccounts || [];
  const securityCenter = data.securityCenter || {};
  const nsgFlowLogs = data.nsgFlowLogs || [];
  const logAnalytics = data.logAnalyticsWorkspaces || [];

  // PCI-SEG: Network segmentation (PCI subnet isolated)
  const subnets = data.subnets || [];
  const pciSubnets = subnets.filter(s => {
    const name = (s.name || '').toLowerCase();
    return name.includes('pci') || name.includes('payment') || name.includes('cardholder');
  });
  pciSubnets.forEach(sub => {
    const sp = _subnetProps(sub);
    const nsgRef = sp.networkSecurityGroup;
    if (!nsgRef || !nsgRef.id) {
      f.push(_finding({
        id: 'PCI-SEG', framework: 'PCI', severity: 'CRITICAL',
        title: 'PCI subnet without NSG',
        message: `PCI-scoped subnet "${sub.name || sid(sub.id)}" has no NSG: network segmentation violation`,
        resource: sub.name || sid(sub.id), resourceId: sub.id || '', resourceType: 'Microsoft.Network/virtualNetworks/subnets',
        remediation: 'Apply strict NSG rules isolating cardholder data environment from other subnets',
      }));
    }
  });

  // PCI-SQL: SQL databases publicly accessible
  sqlServers.forEach(srv => {
    const props = srv.properties || srv;
    const pubAccess = props.publicNetworkAccess || '';
    if (pubAccess.toLowerCase() === 'enabled') {
      f.push(_finding({
        id: 'PCI-SQL', framework: 'PCI', severity: 'CRITICAL',
        title: 'SQL server publicly accessible',
        message: `SQL server "${_rn(srv)}" has public network access enabled: CDE exposure`,
        resource: _rn(srv), resourceId: srv.id || '', resourceType: 'Microsoft.Sql/servers',
        remediation: 'Disable public access; use private endpoints for database connectivity',
      }));
    }
  });

  // PCI-ENCRYPT: Unencrypted data at rest
  managedDisks.forEach(disk => {
    const props = disk.properties || disk;
    const enc = props.encryption || {};
    if (enc.type === 'EncryptionAtRestWithPlatformKey' || !enc.type) {
      // Platform-managed keys are minimum: but CMK is preferred for PCI
      if (!enc.diskEncryptionSetId) {
        f.push(_finding({
          id: 'PCI-ENCRYPT', framework: 'PCI', severity: 'HIGH',
          title: 'Disk without customer-managed encryption',
          message: `Managed disk "${_rn(disk)}" uses platform-managed keys: CMK required for PCI`,
          resource: _rn(disk), resourceId: disk.id || '', resourceType: 'Microsoft.Compute/disks',
          remediation: 'Enable encryption with customer-managed keys via Disk Encryption Set',
        }));
      }
    }
  });

  // PCI-WAF: App Gateway without WAF SKU
  appGateways.forEach(ag => {
    const props = ag.properties || ag;
    const sku = props.sku || {};
    const tier = (sku.tier || sku.name || '').toLowerCase();
    if (!tier.includes('waf')) {
      f.push(_finding({
        id: 'PCI-WAF', framework: 'PCI', severity: 'HIGH',
        title: 'Application Gateway without WAF',
        message: `Application Gateway "${_rn(ag)}" uses "${sku.tier || sku.name || 'Standard'}" tier: WAF required for PCI`,
        resource: _rn(ag), resourceId: ag.id || '', resourceType: 'Microsoft.Network/applicationGateways',
        remediation: 'Upgrade to WAF_v2 SKU and enable OWASP rule sets for web application protection',
        checkovId: 'CKV_AZURE_120',
      }));
    }
  });

  // PCI-IDS: Missing intrusion detection (no Azure Defender / Microsoft Defender)
  const defenderPlans = data.defenderPlans || [];
  if (defenderPlans.length === 0 && _hasAssessmentEvidence(data,'defenderPlans')) {
    f.push(_finding({
      id: 'PCI-IDS', framework: 'PCI', severity: 'HIGH',
      title: 'No Microsoft Defender plans enabled',
      message: 'No Microsoft Defender for Cloud plans found: intrusion detection requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Security/pricings',
      remediation: 'Enable Microsoft Defender for Cloud on all resource types (servers, SQL, storage, etc.)',
    }));
  }

  // PCI-STORAGE: Cardholder data in unencrypted storage
  storageAccounts.forEach(sa => {
    const props = sa.properties || sa;
    const enc = props.encryption || {};
    if (!enc.keySource && !enc.services) {
      f.push(_finding({
        id: 'PCI-STORAGE', framework: 'PCI', severity: 'CRITICAL',
        title: 'Storage account without encryption configuration',
        message: `Storage account "${_rn(sa)}" has no explicit encryption: data at rest violation`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Enable encryption with customer-managed keys for cardholder data storage',
      }));
    }
  });

  // PCI-REVIEW: Missing access reviews (no PIM or access reviews configured)
  const accessReviews = data.accessReviews || [];
  if (accessReviews.length === 0 && _hasAssessmentEvidence(data,'accessReviews')) {
    f.push(_finding({
      id: 'PCI-REVIEW', framework: 'PCI', severity: 'MEDIUM',
      title: 'No access reviews configured',
      message: 'No Azure AD access reviews found: periodic access review required for PCI',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.Authorization/accessReviewScheduleDefinitions',
      remediation: 'Configure quarterly access reviews for privileged roles via Azure AD PIM',
    }));
  }

  // PCI-LOG: Insufficient logging
  const workspaceEvidence=_hasAssessmentEvidence(data,'logAnalyticsWorkspaces');
  const flowLogEvidence=_hasAssessmentEvidence(data,'nsgFlowLogs');
  if (logAnalytics.length === 0 && nsgFlowLogs.length === 0 &&
      workspaceEvidence && flowLogEvidence) {
    f.push(_finding({
      id: 'PCI-LOG', framework: 'PCI', severity: 'HIGH',
      title: 'Insufficient logging for PCI compliance',
      message: 'No Log Analytics workspace or NSG flow logs: audit trail requirement unmet',
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.OperationalInsights/workspaces',
      remediation: 'Deploy Log Analytics and enable diagnostic settings with 1-year retention',
    }));
  }

  return f;
}
