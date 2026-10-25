// Shared Azure compliance rule primitives.
// Keep policy checks in framework modules; this file owns common resource access.

import { sid } from './utils.js';

// Evidence from an omitted or failed collector cannot establish an absent control.
export function _hasAssessmentEvidence(data, key) {
  const known=Array.isArray(data[key])&&data.collectionStatus?.[key]!=='failed';
  if(!known){
    if(!data.assessmentGaps)data.assessmentGaps={};
    data.assessmentGaps[key]='Not collected or collection failed';
  }
  return known;
}

export const CKV_MAP = {
  'CIS-9':     'CKV_AZURE_9',    // NSG allows RDP from 0.0.0.0/0
  'CIS-10':    'CKV_AZURE_10',   // NSG allows SSH from 0.0.0.0/0
  'CIS-12':    'CKV_AZURE_12',   // NSG allows all inbound
  'CIS-34':    'CKV_AZURE_34',   // Storage public blob access
  'CIS-44':    'CKV_AZURE_44',   // Storage min TLS < 1.2
  'CIS-SQL-1': 'CKV_AZURE_28',   // SQL server publicly accessible
  'CIS-REDIS': 'CKV_AZURE_88',   // Redis not using TLS
  'CIS-AKS':   'CKV_AZURE_5',    // AKS RBAC not enabled
  'CIS-DDOS':  'CKV_AZURE_57',   // VNet without DDoS protection
  'CAF-NSG':   'CKV_AZURE_160',  // Subnet without NSG
  'CAF-UDR':   'CKV_AZURE_161',  // Subnet without route table
  'SOC2-TLS':  'CKV_AZURE_44',   // TLS 1.2 minimum on storage
  'SOC2-DISK': 'CKV_AZURE_93',   // Managed disk encryption
  'PCI-WAF':   'CKV_AZURE_120',  // App GW without WAF
  'PE-PENDING': 'CKV_AZURE_PE_1', // PE connection pending
  'PE-NO-DNS':  'CKV_AZURE_PE_2', // No matching private DNS zone
  'PE-DNS-UNLINKED': 'CKV_AZURE_PE_3', // DNS zone not linked to VNet
  'PE-NSG-POLICY':   'CKV_AZURE_PE_4', // Subnet NSG policies disabled
  'PE-ORPHAN':       'CKV_AZURE_PE_5', // PE connection failed/disconnected
};

// ============================================================================
// Helpers: Azure NSG rule evaluation
// ============================================================================

/**
 * Extract security rules from an NSG resource object.
 * Azure NSGs carry rules under properties.securityRules or securityRules.
 */
export function _getRules(nsg) {
  if (!nsg) return [];
  const props = nsg.properties || nsg;
  return props.securityRules || props.SecurityRules || [];
}

/**
 * Get the properties of an NSG rule (handles nested .properties pattern).
 */
export function _ruleProps(rule) {
  return rule.properties || rule;
}

/**
 * Check if a source address prefix matches "any" (0.0.0.0/0 or * or Internet).
 */
export function _isOpenSource(prefix) {
  if (!prefix) return false;
  const p = String(prefix).trim();
  return p === '*' || p === '0.0.0.0/0' || p === 'Internet' || p === 'Any' || p === '::/0';
}

/**
 * Check if any source address prefix in prefixes array is open.
 */
export function _hasOpenSourcePrefixes(rule) {
  const rp = _ruleProps(rule);
  if (_isOpenSource(rp.sourceAddressPrefix)) return true;
  const prefixes = rp.sourceAddressPrefixes || [];
  return prefixes.some(p => _isOpenSource(p));
}

/**
 * Check if a rule covers a specific port number.
 */
export function _coversPort(rule, port) {
  const rp = _ruleProps(rule);
  const ranges = _collectPortRanges(rp);
  return ranges.some(range => _portInRange(range, port));
}

/**
 * Collect all destination port ranges from a rule.
 */
export function _collectPortRanges(rp) {
  const ranges = [];
  if (rp.destinationPortRange) ranges.push(rp.destinationPortRange);
  if (rp.destinationPortRanges) ranges.push(...rp.destinationPortRanges);
  return ranges;
}

/**
 * Check if a port falls within a port range string ("80", "80-443", "*").
 */
export function _portInRange(range, port) {
  if (!range) return false;
  const r = String(range).trim();
  if (r === '*') return true;
  if (r.includes('-')) {
    const [lo, hi] = r.split('-').map(Number);
    return port >= lo && port <= hi;
  }
  return Number(r) === port;
}

/**
 * Check if a rule allows all ports (destinationPortRange = '*').
 */
export function _isAllPorts(rule) {
  const rp = _ruleProps(rule);
  return rp.destinationPortRange === '*' ||
    (rp.destinationPortRanges || []).includes('*');
}

/**
 * Check if a rule uses UDP protocol.
 */
export function _isUdp(rule) {
  const rp = _ruleProps(rule);
  const proto = (rp.protocol || '').toLowerCase();
  return proto === 'udp' || proto === '*';
}

/**
 * Check if a rule allows all protocols.
 */
export function _isAllProtocols(rule) {
  const rp = _ruleProps(rule);
  return (rp.protocol || '').trim() === '*';
}

/**
 * Get the resource name for display. Azure resources use .name or last ID segment.
 */
export function _rn(resource, fallback) {
  if (!resource) return fallback || '';
  return resource.name || sid(resource.id) || fallback || '';
}

/**
 * Get Azure resource type from the resource object.
 */
export function _rtype(resource) {
  return resource?.type || '';
}

/**
 * Build a finding object in the standard format.
 */
export function _finding(opts) {
  return {
    id: opts.id || '',
    framework: opts.framework || '',
    severity: opts.severity || 'MEDIUM',
    title: opts.title || '',
    message: opts.message || '',
    resource: opts.resource || '',
    resourceId: opts.resourceId || '',
    resourceType: opts.resourceType || '',
    remediation: opts.remediation || '',
    checkovId: CKV_MAP[opts.id] || opts.checkovId || '',
    control: opts.id || '',
    resourceName: opts.resource || '',
  };
}

/**
 * Get tags object from an Azure resource.
 */
export function _getTags(resource) {
  if (!resource) return {};
  return resource.tags || resource.Tags || (resource.properties || {}).tags || {};
}

/**
 * Check if resource has any user-defined tags.
 */
export function _hasTags(resource) {
  const tags = _getTags(resource);
  return Object.keys(tags).length > 0;
}

/**
 * Extract subnets from a VNet resource.
 */
export function _getVnetSubnets(vnet) {
  if (!vnet) return [];
  const props = vnet.properties || vnet;
  return props.subnets || [];
}

/**
 * Get subnet properties.
 */
export function _subnetProps(subnet) {
  return subnet.properties || subnet;
}
