// Azure network rule evaluation functions
// Handles NSG (Network Security Group) evaluation, UDR (User Defined Route) evaluation,
// and subnet classification for Azure networking model.
// Zero DOM dependency -- suitable for unit testing.

import { ipInCIDR, parseCIDR } from './cidr-engine.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_INBOUND_RULES = [
  {
    name: 'AllowVNetInBound',
    priority: 65000,
    direction: 'Inbound',
    access: 'Allow',
    protocol: '*',
    sourceAddressPrefix: 'VirtualNetwork',
    sourcePortRange: '*',
    destinationAddressPrefix: 'VirtualNetwork',
    destinationPortRange: '*',
  },
  {
    name: 'AllowAzureLoadBalancerInBound',
    priority: 65001,
    direction: 'Inbound',
    access: 'Allow',
    protocol: '*',
    sourceAddressPrefix: 'AzureLoadBalancer',
    sourcePortRange: '*',
    destinationAddressPrefix: '*',
    destinationPortRange: '*',
  },
  {
    name: 'DenyAllInBound',
    priority: 65500,
    direction: 'Inbound',
    access: 'Deny',
    protocol: '*',
    sourceAddressPrefix: '*',
    sourcePortRange: '*',
    destinationAddressPrefix: '*',
    destinationPortRange: '*',
  },
];

const DEFAULT_OUTBOUND_RULES = [
  {
    name: 'AllowVNetOutBound',
    priority: 65000,
    direction: 'Outbound',
    access: 'Allow',
    protocol: '*',
    sourceAddressPrefix: 'VirtualNetwork',
    sourcePortRange: '*',
    destinationAddressPrefix: 'VirtualNetwork',
    destinationPortRange: '*',
  },
  {
    name: 'AllowInternetOutBound',
    priority: 65001,
    direction: 'Outbound',
    access: 'Allow',
    protocol: '*',
    sourceAddressPrefix: '*',
    sourcePortRange: '*',
    destinationAddressPrefix: 'Internet',
    destinationPortRange: '*',
  },
  {
    name: 'DenyAllOutBound',
    priority: 65500,
    direction: 'Outbound',
    access: 'Deny',
    protocol: '*',
    sourceAddressPrefix: '*',
    sourcePortRange: '*',
    destinationAddressPrefix: '*',
    destinationPortRange: '*',
  },
];

// RFC 1918 private ranges used for VirtualNetwork service tag fallback
const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

// ---------------------------------------------------------------------------
// Protocol matching
// ---------------------------------------------------------------------------

/**
 * Match a rule's protocol field against a query protocol.
 * Azure NSG protocols: *, Tcp, Udp, Icmp, Ah, Esp (case-insensitive).
 * Wildcard '*' matches everything.
 */
export function protocolMatch(ruleProtocol, queryProtocol) {
  if (!ruleProtocol || !queryProtocol) return false;
  const rp = String(ruleProtocol).toLowerCase();
  const qp = String(queryProtocol).toLowerCase();
  if (rp === '*' || qp === '*') return true;
  return rp === qp;
}

// ---------------------------------------------------------------------------
// Port matching
// ---------------------------------------------------------------------------

/**
 * Parse a single port token into a {low, high} range.
 * Accepts: '*', '80', '80-443'.
 */
function parsePortToken(token) {
  const t = token.trim();
  if (t === '*') return { low: 0, high: 65535 };
  if (t.includes('-')) {
    const [lo, hi] = t.split('-').map(Number);
    return { low: lo, high: hi };
  }
  const n = Number(t);
  return { low: n, high: n };
}

/**
 * Match a rule's port range specification against a query port.
 * Handles: '*' (all ports), '80', '80-443', '22,80,443', '80,100-200'.
 * Azure allows comma-separated values in sourcePortRanges / destinationPortRanges.
 */
export function portMatch(rulePortRange, queryPort) {
  if (rulePortRange === undefined || rulePortRange === null) return true;
  const rule = String(rulePortRange).trim();
  if (rule === '*' || rule === '') return true;

  const port = Number(queryPort);
  if (isNaN(port)) return false;

  const segments = rule.split(',');
  for (const seg of segments) {
    const { low, high } = parsePortToken(seg);
    if (port >= low && port <= high) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Address / service tag matching
// ---------------------------------------------------------------------------

/**
 * Determine if an IP address belongs to RFC 1918 private space.
 */
function isPrivateIp(ip) {
  for (const range of PRIVATE_RANGES) {
    if (ipInCIDR(ip, range)) return true;
  }
  return false;
}

/**
 * Match a rule's address prefix (or service tag) against a query address.
 *
 * Service tags handled:
 *   '*'                  - matches any address
 *   'VirtualNetwork'     - matches VNet prefixes (if provided) or RFC 1918
 *   'AzureLoadBalancer'  - matches 168.63.129.16
 *   'Internet'           - matches anything NOT in VNet prefixes / RFC 1918
 *   CIDR notation        - standard prefix match
 *   Bare IP              - exact match
 *
 * @param {string}   ruleAddress   - The rule's source or destination address prefix
 * @param {string}   queryAddress  - The IP being tested (bare IP, no CIDR)
 * @param {string[]} vnetPrefixes  - Address prefixes of the VNet (optional)
 */
export function addressMatch(ruleAddress, queryAddress, vnetPrefixes) {
  if (!ruleAddress || !queryAddress) return false;
  const addr = ruleAddress.trim();
  const ip = queryAddress.trim();

  if (addr === '*') return true;

  if (addr === 'VirtualNetwork') {
    if (Array.isArray(vnetPrefixes) && vnetPrefixes.length > 0) {
      for (const prefix of vnetPrefixes) {
        if (ipInCIDR(ip, prefix)) return true;
      }
      return false;
    }
    return isPrivateIp(ip);
  }

  if (addr === 'AzureLoadBalancer') {
    return ip === '168.63.129.16';
  }

  if (addr === 'Internet') {
    if (Array.isArray(vnetPrefixes) && vnetPrefixes.length > 0) {
      for (const prefix of vnetPrefixes) {
        if (ipInCIDR(ip, prefix)) return false;
      }
      return true;
    }
    return !isPrivateIp(ip);
  }

  // CIDR match
  if (addr.includes('/')) {
    return ipInCIDR(ip, addr);
  }

  // Exact IP match
  return addr === ip;
}

// ---------------------------------------------------------------------------
// Single-rule matching helper
// ---------------------------------------------------------------------------

/**
 * Collect all address prefixes from a rule.
 * Azure NSG rules can have:
 *   - sourceAddressPrefix / destinationAddressPrefix (single string)
 *   - sourceAddressPrefixes / destinationAddressPrefixes (array of strings)
 */
function collectAddresses(rule, fieldSingle, fieldArray) {
  const addrs = [];
  if (rule[fieldSingle]) addrs.push(rule[fieldSingle]);
  if (Array.isArray(rule[fieldArray])) {
    for (const a of rule[fieldArray]) addrs.push(a);
  }
  return addrs;
}

/**
 * Collect all port ranges from a rule.
 * Azure NSG rules can have:
 *   - sourcePortRange / destinationPortRange (single string)
 *   - sourcePortRanges / destinationPortRanges (array of strings)
 */
function collectPorts(rule, fieldSingle, fieldArray) {
  const ports = [];
  if (rule[fieldSingle] !== undefined && rule[fieldSingle] !== null) {
    ports.push(String(rule[fieldSingle]));
  }
  if (Array.isArray(rule[fieldArray])) {
    for (const p of rule[fieldArray]) ports.push(String(p));
  }
  return ports.length > 0 ? ports : ['*'];
}

/**
 * Test whether a single NSG rule matches the given traffic parameters.
 */
function ruleMatches(rule, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, vnetPrefixes) {
  // Direction filter
  const ruleDir = (rule.direction || '').toLowerCase();
  if (ruleDir !== direction.toLowerCase()) return false;

  // Protocol
  if (!protocolMatch(rule.protocol, protocol)) return false;

  // Source addresses
  const srcAddrs = collectAddresses(rule, 'sourceAddressPrefix', 'sourceAddressPrefixes');
  if (srcAddrs.length > 0) {
    let srcMatch = false;
    for (const sa of srcAddrs) {
      if (addressMatch(sa, srcAddr, vnetPrefixes)) { srcMatch = true; break; }
    }
    if (!srcMatch) return false;
  }

  // Destination addresses
  const dstAddrs = collectAddresses(rule, 'destinationAddressPrefix', 'destinationAddressPrefixes');
  if (dstAddrs.length > 0) {
    let dstMatch = false;
    for (const da of dstAddrs) {
      if (addressMatch(da, dstAddr, vnetPrefixes)) { dstMatch = true; break; }
    }
    if (!dstMatch) return false;
  }

  // Source ports
  const srcPorts = collectPorts(rule, 'sourcePortRange', 'sourcePortRanges');
  let srcPortMatch = false;
  for (const sp of srcPorts) {
    if (portMatch(sp, srcPort)) { srcPortMatch = true; break; }
  }
  if (!srcPortMatch) return false;

  // Destination ports
  const dstPorts = collectPorts(rule, 'destinationPortRange', 'destinationPortRanges');
  let dstPortMatch = false;
  for (const dp of dstPorts) {
    if (portMatch(dp, dstPort)) { dstPortMatch = true; break; }
  }
  if (!dstPortMatch) return false;

  return true;
}

// ---------------------------------------------------------------------------
// NSG evaluation
// ---------------------------------------------------------------------------

// Cache merged+sorted rules per NSG per direction to avoid re-sorting on every call.
// WeakMap keyed by NSG object -- auto-invalidates when NSG data is replaced on reload.
const _nsgRuleCache = new WeakMap();

function _getCachedRules(nsg, direction) {
  const dirKey = direction.toLowerCase() === 'inbound' ? 'in' : 'out';
  let cached = _nsgRuleCache.get(nsg);
  if (cached && cached[dirKey]) return cached[dirKey];
  const customRules = (nsg && nsg.securityRules) || [];
  const defaults = dirKey === 'in' ? DEFAULT_INBOUND_RULES : DEFAULT_OUTBOUND_RULES;
  const allRules = [...customRules, ...defaults];
  allRules.sort((a, b) => a.priority - b.priority);
  if (!cached) { cached = {}; _nsgRuleCache.set(nsg, cached); }
  cached[dirKey] = allRules;
  return allRules;
}

/**
 * Evaluate an NSG's rules for a given traffic flow in priority order.
 *
 * Azure evaluates rules lowest-priority-number first (100 before 200).
 * Custom rules range 100-4096; default rules are 65000-65500.
 * First matching rule wins (either Allow or Deny).
 *
 * @param {object}   nsg          - NSG object with securityRules array
 * @param {string}   direction    - 'Inbound' or 'Outbound'
 * @param {string}   protocol     - 'Tcp', 'Udp', 'Icmp', '*', etc.
 * @param {string}   srcAddr      - Source IP address
 * @param {number|string} srcPort - Source port number
 * @param {string}   dstAddr      - Destination IP address
 * @param {number|string} dstPort - Destination port number
 * @param {object}   [opts]       - Optional: { vnetPrefixes: string[] }
 * @returns {{ action: string, rule: object, priority: number }}
 */
export function evaluateNsgRules(nsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts) {
  const vnetPrefixes = (opts && opts.vnetPrefixes) || [];

  // Use cached merged+sorted rules (avoids re-sorting on every call)
  const allRules = _getCachedRules(nsg, direction);

  for (const rule of allRules) {
    if (ruleMatches(rule, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, vnetPrefixes)) {
      return {
        action: rule.access,
        rule,
        priority: rule.priority,
      };
    }
  }

  // Should never reach here because DenyAll defaults exist, but safety net
  const fallback = direction.toLowerCase() === 'inbound'
    ? DEFAULT_INBOUND_RULES[2]
    : DEFAULT_OUTBOUND_RULES[2];
  return { action: 'Deny', rule: fallback, priority: 65500 };
}

// ---------------------------------------------------------------------------
// NSG path evaluation (NIC + Subnet)
// ---------------------------------------------------------------------------

/**
 * Evaluate traffic through both NIC-level and subnet-level NSGs.
 *
 * Azure applies NSGs at two levels:
 *   - Inbound:  subnet NSG evaluated first, then NIC NSG. Both must allow.
 *   - Outbound: NIC NSG evaluated first, then subnet NSG. Both must allow.
 *
 * If either level has no NSG, that level is treated as Allow.
 *
 * @param {object|null} nicNsg      - NSG attached to the NIC (or null)
 * @param {object|null} subnetNsg   - NSG attached to the subnet (or null)
 * @param {string}      direction   - 'Inbound' or 'Outbound'
 * @param {string}      protocol    - Protocol string
 * @param {string}      srcAddr     - Source IP
 * @param {number|string} srcPort   - Source port
 * @param {string}      dstAddr     - Destination IP
 * @param {number|string} dstPort   - Destination port
 * @param {object}      [opts]      - Optional: { vnetPrefixes: string[] }
 * @returns {{ allowed: boolean, nicResult: object|null, subnetResult: object|null }}
 */
export function evaluateNsgPath(nicNsg, subnetNsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts) {
  const noNsgResult = { action: 'Allow', rule: { name: 'NoNsgAttached' }, priority: 0 };

  const nicResult = nicNsg
    ? evaluateNsgRules(nicNsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts)
    : noNsgResult;

  const subnetResult = subnetNsg
    ? evaluateNsgRules(subnetNsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts)
    : noNsgResult;

  const isInbound = direction.toLowerCase() === 'inbound';

  if (isInbound) {
    // Inbound: subnet first, then NIC. Both must Allow.
    const allowed = subnetResult.action === 'Allow' && nicResult.action === 'Allow';
    return { allowed, subnetResult, nicResult };
  }

  // Outbound: NIC first, then subnet. Both must Allow.
  const allowed = nicResult.action === 'Allow' && subnetResult.action === 'Allow';
  return { allowed, nicResult, subnetResult };
}

// ---------------------------------------------------------------------------
// Route evaluation (UDR + system routes)
// ---------------------------------------------------------------------------

/**
 * Build the default Azure system routes for a VNet.
 * Azure automatically creates:
 *   - A route for each VNet address prefix -> VNetLocal
 *   - 0.0.0.0/0 -> Internet
 *   - RFC 1918 + 100.64.0.0/10 -> None (when not part of VNet)
 *
 * @param {string[]} vnetPrefixes - VNet address space prefixes
 * @returns {object[]} Array of system route objects
 */
function buildSystemRoutes(vnetPrefixes) {
  const routes = [];

  // VNet address space routes
  if (Array.isArray(vnetPrefixes)) {
    for (const prefix of vnetPrefixes) {
      routes.push({
        name: 'System-VNetLocal-' + prefix,
        addressPrefix: prefix,
        nextHopType: 'VNetLocal',
        nextHopIpAddress: null,
        isSystem: true,
      });
    }
  }

  // Default route to Internet
  routes.push({
    name: 'System-DefaultToInternet',
    addressPrefix: '0.0.0.0/0',
    nextHopType: 'Internet',
    nextHopIpAddress: null,
    isSystem: true,
  });

  // RFC 1918 & CGNAT null routes (Azure drops these by default unless VNet includes them)
  const nullPrefixes = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];
  for (const np of nullPrefixes) {
    // Only add the null route if it is NOT covered by a VNet prefix
    let coveredByVnet = false;
    if (Array.isArray(vnetPrefixes)) {
      for (const vp of vnetPrefixes) {
        const vpParsed = parseCIDR(vp);
        const npParsed = parseCIDR(np);
        if (vpParsed && npParsed) {
          // If the null prefix overlaps with vnet prefix, skip it
          // The vnet-local route with the more specific prefix will win
          if (ipInCIDR(intToIpSafe(npParsed.network), vp) ||
              ipInCIDR(intToIpSafe(vpParsed.network), np)) {
            coveredByVnet = true;
            break;
          }
        }
      }
    }
    if (!coveredByVnet) {
      routes.push({
        name: 'System-Null-' + np.replace(/[/.]/g, '_'),
        addressPrefix: np,
        nextHopType: 'None',
        nextHopIpAddress: null,
        isSystem: true,
      });
    }
  }

  return routes;
}

/**
 * Convert an integer back to IP string (local helper to avoid circular import).
 */
function intToIpSafe(n) {
  n = n >>> 0;
  return `${(n >>> 24) & 0xFF}.${(n >>> 16) & 0xFF}.${(n >>> 8) & 0xFF}.${n & 0xFF}`;
}

/**
 * Evaluate the effective route for a destination IP.
 *
 * Azure route selection: UDR routes override system routes.
 * Among matching routes, longest prefix match wins.
 * Among equal-length prefixes: UDR > VNet peering > system route.
 *
 * @param {object}   routeTable    - Route table with `routes` array and optional `vnetPrefixes`
 * @param {string}   destinationIp - Destination IP address (bare IP, no CIDR)
 * @returns {{ nextHopType: string, nextHopIpAddress: string|null, route: object }}
 */
export function evaluateRoute(routeTable, destinationIp) {
  if (!destinationIp) {
    return { nextHopType: 'None', nextHopIpAddress: null, route: null };
  }

  const ip = destinationIp.trim();
  const vnetPrefixes = (routeTable && routeTable.vnetPrefixes) || [];
  const udrRoutes = (routeTable && routeTable.routes) || [];
  const systemRoutes = buildSystemRoutes(vnetPrefixes);

  // Tag UDR routes as non-system for priority
  const taggedUdr = udrRoutes.map(r => ({ ...r, isSystem: false }));

  const allRoutes = [...taggedUdr, ...systemRoutes];

  let bestMatch = null;
  let bestPrefix = -1;
  let bestIsSystem = true;

  for (const route of allRoutes) {
    const prefix = route.addressPrefix;
    if (!prefix) continue;

    // Check if destination IP falls within this route's prefix
    let matches = false;
    if (prefix === '0.0.0.0/0') {
      matches = true;
    } else if (prefix.includes('/')) {
      matches = ipInCIDR(ip, prefix);
    } else {
      // Bare IP prefix (exact match)
      matches = (ip === prefix);
    }

    if (!matches) continue;

    const prefixLen = prefix.includes('/')
      ? parseInt(prefix.split('/')[1], 10)
      : 32;

    // Longest prefix wins; UDR beats system at same length
    if (prefixLen > bestPrefix ||
        (prefixLen === bestPrefix && !route.isSystem && bestIsSystem)) {
      bestPrefix = prefixLen;
      bestMatch = route;
      bestIsSystem = !!route.isSystem;
    }
  }

  if (!bestMatch) {
    return { nextHopType: 'None', nextHopIpAddress: null, route: null };
  }

  return {
    nextHopType: bestMatch.nextHopType || 'None',
    nextHopIpAddress: bestMatch.nextHopIpAddress || null,
    route: bestMatch,
  };
}

// ---------------------------------------------------------------------------
// Subnet classification
// ---------------------------------------------------------------------------

/**
 * Classify a subnet as public or private based on effective routing.
 *
 * An Azure subnet is considered "public" if traffic to 0.0.0.0/0 routes to
 * Internet (which is the default system route behavior). It is "private" if
 * a UDR overrides the default route with nextHopType None or VirtualAppliance,
 * or if there is no route to Internet at all.
 *
 * @param {object} subnet     - Subnet object (unused directly, but passed for context)
 * @param {object} routeTable - Route table associated with the subnet
 * @returns {{ classification: string, reason: string }}
 */
export function classifySubnet(subnet, routeTable) {
  // Test what happens to traffic destined for a public IP (e.g., 8.8.8.8)
  const result = evaluateRoute(routeTable || {}, '8.8.8.8');

  if (result.nextHopType === 'Internet') {
    const isDefault = result.route && result.route.isSystem;
    return {
      classification: 'public',
      reason: isDefault
        ? 'Default system route sends 0.0.0.0/0 to Internet'
        : 'UDR explicitly routes 0.0.0.0/0 to Internet',
    };
  }

  if (result.nextHopType === 'VirtualAppliance') {
    return {
      classification: 'private',
      reason: 'UDR routes 0.0.0.0/0 through VirtualAppliance (' +
        (result.nextHopIpAddress || 'NVA') + ')',
    };
  }

  if (result.nextHopType === 'VirtualNetworkGateway') {
    return {
      classification: 'private',
      reason: 'UDR routes 0.0.0.0/0 through VirtualNetworkGateway (forced tunneling)',
    };
  }

  if (result.nextHopType === 'None') {
    return {
      classification: 'private',
      reason: 'UDR drops traffic to 0.0.0.0/0 (nextHopType: None)',
    };
  }

  if (result.nextHopType === 'VNetLocal') {
    return {
      classification: 'private',
      reason: 'Traffic routes to VNetLocal, no Internet egress',
    };
  }

  return {
    classification: 'private',
    reason: 'No route to Internet found (nextHopType: ' + result.nextHopType + ')',
  };
}
