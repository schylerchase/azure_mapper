// Utility functions used across the application
// Azure Network Mapper — rewritten from AWS equivalents

// Maximum input size for safeParse (50 MB) — prevents browser freeze
// on oversized paste. Typical multi-subscription Azure exports are 5-15 MB.
const MAX_PARSE_BYTES = 50 * 1024 * 1024;

/**
 * Safe JSON parse with fallback for malformed JSON.
 * Attempts to extract valid JSON objects from text.
 * Rejects input exceeding MAX_PARSE_BYTES to prevent DoS.
 * @param {string} t - Text to parse
 * @returns {Object|Object[]|null} Parsed JSON or null
 */
export function safeParse(t) {
  if (!t || !t.trim()) return null;
  if (t.length > MAX_PARSE_BYTES) {
    console.warn(`safeParse: input exceeds ${MAX_PARSE_BYTES / 1024 / 1024} MB limit (${(t.length / 1024 / 1024).toFixed(1)} MB) — rejected`);
    return null;
  }
  try {
    return JSON.parse(t.trim());
  } catch (e) {
    const b = [];
    let d = 0, s = -1;
    for (let i = 0; i < t.length; i++) {
      if (t[i] === '{') {
        if (d === 0) s = i;
        d++;
      }
      if (t[i] === '}') {
        d--;
        if (d === 0 && s >= 0) {
          b.push(t.substring(s, i + 1));
          s = -1;
        }
      }
    }
    return b.length
      ? b.map(x => {
          try {
            return JSON.parse(x);
          } catch (e2) {
            return null;
          }
        }).filter(Boolean)
      : null;
  }
}

/**
 * Extract nested properties from resource(s).
 * @param {Object|Object[]} r - Resource or array of resources
 * @param {string[]} keys - Property keys to extract
 * @returns {Array} Flattened array of extracted values
 */
export function ext(r, keys) {
  if (!r) return [];
  const a = Array.isArray(r) ? r : [r];
  let res = [];
  for (const i of a) {
    for (const k of keys) {
      if (i[k]) res = res.concat(i[k]);
    }
  }
  return res;
}

/**
 * HTML escape a value.
 * @param {*} s - Value to escape
 * @returns {string} Escaped string
 */
export function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Get display name from an Azure resource.
 * Azure resources carry a top-level `name` property. Falls back to the
 * last segment of the ARM resource ID when name is absent.
 * @param {Object} resource - Azure ARM resource object
 * @returns {string} Escaped display name
 */
export function gn(resource) {
  const name = resource.name || resource.id?.split('/').pop() || '';
  return esc(name);
}

/**
 * Shorten an Azure resource ID to just the resource name (last path segment).
 * Example:
 *   /subscriptions/abc/resourceGroups/prod/providers/Microsoft.Network/virtualNetworks/hub-vnet
 *   → hub-vnet
 * @param {string} id - Full ARM resource ID
 * @returns {string} Resource name segment
 */
export function sid(id) {
  if (!id) return '';
  const segments = id.split('/').filter(Boolean);
  return segments[segments.length - 1] || '';
}

/**
 * Classify an Azure gateway / network resource type into a short display token.
 * Matches on the ARM resource type string (case-insensitive).
 * @param {string} type - ARM resource type (e.g. 'Microsoft.Network/azureFirewalls')
 * @returns {string} Short token: 'fw' | 'bastion' | 'nat' | 'vpn' | 'appgw' | 'pe' | 'GW'
 */
export function clsGw(type) {
  if (!type) return 'GW';
  const t = type.toLowerCase();
  if (t === 'microsoft.network/azurefirewalls')                          return 'fw';
  if (t === 'microsoft.network/bastionhosts')                            return 'bastion';
  if (t === 'microsoft.network/natgateways')                             return 'nat';
  if (t === 'microsoft.network/virtualnetworkgateways')                  return 'vpn';
  if (t === 'microsoft.network/applicationgateways')                     return 'appgw';
  if (t === 'microsoft.network/privatelinkservices')                     return 'pe';
  return 'GW';
}

/**
 * Check whether a resource type is shared across Virtual Networks
 * (analogous to Transit Gateway / VPC Peering in AWS).
 * Azure Firewall, Bastion, VPN Gateway, and NAT Gateway are all
 * hub-level resources that multiple VNets can reference.
 * @param {string} t - Short type token (output of clsGw) or ARM type string
 * @returns {boolean} True if shared
 */
export function isShared(t) {
  if (!t) return false;
  const lower = t.toLowerCase();
  return (
    lower === 'fw'       ||
    lower === 'bastion'  ||
    lower === 'vpn'      ||
    lower === 'nat'      ||
    lower === 'microsoft.network/azurefirewalls'           ||
    lower === 'microsoft.network/bastionhosts'             ||
    lower === 'microsoft.network/virtualnetworkgateways'   ||
    lower === 'microsoft.network/natgateways'
  );
}

/**
 * Get CSS color variable for an Azure resource type token.
 * @param {string} t - Short type token (fw | bastion | nat | vpn | appgw | pe | vwan | peer)
 * @returns {string} CSS variable reference
 */
export function gcv(t) {
  return {
    fw:      'var(--fw-color)',
    bastion: 'var(--bastion-color)',
    nat:     'var(--nat-color)',
    vpn:     'var(--vpn-color)',
    appgw:   'var(--appgw-color)',
    pe:      'var(--pe-color)',
    vwan:    'var(--vwan-color)',
    peer:    'var(--peer-color)'
  }[t] || 'var(--text-muted)';
}

/**
 * Get hex color for an Azure resource type token.
 * @param {string} t - Short type token
 * @returns {string} Hex color string
 */
export function gch(t) {
  return {
    fw:      '#ef4444',
    bastion: '#10b981',
    nat:     '#f59e0b',
    vpn:     '#3b82f6',
    appgw:   '#8b5cf6',
    pe:      '#a78bfa',
    vwan:    '#ec4899',
    peer:    '#fb923c'
  }[t] || '#4a5e80';
}

/**
 * Get value from an input element by ID.
 * @param {string} id - DOM element ID
 * @returns {string} Input value or empty string
 */
export function gv(id) {
  return (document.getElementById(id) || {}).value || '';
}

/**
 * Parse an Azure ARM resource ID into its component parts.
 * ARM IDs follow the pattern:
 *   /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
 * Nested resource types (e.g. subnets) produce additional segments that are
 * captured in `subType` and `subName`.
 *
 * @param {string} id - Full ARM resource ID
 * @returns {{
 *   subscriptionId: string,
 *   resourceGroup: string,
 *   provider: string,
 *   resourceType: string,
 *   name: string,
 *   subType: string,
 *   subName: string,
 *   raw: string
 * }}
 */
export function parseResourceId(id) {
  const empty = {
    subscriptionId: '',
    resourceGroup:  '',
    provider:       '',
    resourceType:   '',
    name:           '',
    subType:        '',
    subName:        '',
    raw:            id || ''
  };

  if (!id) return empty;

  // Normalize: remove leading slash, split on '/'
  const parts = id.replace(/^\//, '').split('/');

  // Minimum valid ARM path:
  // subscriptions / {sub} / resourceGroups / {rg} / providers / {ns} / {type} / {name}
  // indices:   0        1         2              3       4         5       6       7
  if (parts.length < 8 || parts[0].toLowerCase() !== 'subscriptions') return empty;

  return {
    subscriptionId: parts[1] || '',
    resourceGroup:  parts[3] || '',
    provider:       parts[5] || '',
    resourceType:   parts[6] || '',
    name:           parts[7] || '',
    subType:        parts[8] || '',
    subName:        parts[9] || '',
    raw:            id
  };
}

/**
 * Extract the tenant context from an Azure resource object.
 * Azure resources returned by ARM APIs do not embed the tenant ID directly;
 * it is typically carried in the session context. This helper checks common
 * locations where tenant information may have been attached during ingestion.
 *
 * @param {Object} resource - Azure ARM resource object
 * @returns {string} Tenant ID or empty string if not determinable
 */
export function getTenantFromResource(resource) {
  if (!resource) return '';

  // Ingestion layer may attach tenantId directly
  if (resource.tenantId) return resource.tenantId;

  // Some ARM responses include it under extendedProperties or identity
  if (resource.identity?.tenantId) return resource.identity.tenantId;
  if (resource.extendedProperties?.tenantId) return resource.extendedProperties.tenantId;

  // Fall back to subscriptionId-keyed lookup that the ingestion session provides
  // (populated by state.tenantId after login)
  return '';
}
