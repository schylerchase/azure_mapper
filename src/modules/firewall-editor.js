// Firewall Editor — pure logic (state, validation, CRUD, CLI generation)
// Azure NSG / UDR model — priority-based rules, service tags, ARM resource IDs
// DOM rendering and form creation remain inline in index.html.

// ── State ──────────────────────────────────────────────────────────────
let _fwEdits = [];
let _fwSnapshot = null;
let _fwFpType = null;
let _fwFpResId = null;
let _fwFpSub = null;
let _fwFpVnetId = null;
let _fwFpLk = null;
let _fwFpDir = 'inbound';

// ── State accessors ────────────────────────────────────────────────────

export function getFwEdits() { return _fwEdits; }
export function setFwEdits(v) { _fwEdits = v; }

export function getFwSnapshot() { return _fwSnapshot; }
export function setFwSnapshot(v) { _fwSnapshot = v; }

export function getFwFpType() { return _fwFpType; }
export function setFwFpType(v) { _fwFpType = v; }

export function getFwFpResId() { return _fwFpResId; }
export function setFwFpResId(v) { _fwFpResId = v; }

export function getFwFpSub() { return _fwFpSub; }
export function setFwFpSub(v) { _fwFpSub = v; }

export function getFwFpVnetId() { return _fwFpVnetId; }
export function setFwFpVnetId(v) { _fwFpVnetId = v; }

export function getFwFpLk() { return _fwFpLk; }
export function setFwFpLk(v) { _fwFpLk = v; }

export function getFwFpDir() { return _fwFpDir; }
export function setFwFpDir(v) { _fwFpDir = v; }

// ── Protocol label helper ──────────────────────────────────────────────

/**
 * Human-readable label for an Azure NSG protocol value.
 * Azure uses string names: Tcp, Udp, Icmp, Esp, Ah, * (any).
 * @param {string} proto
 * @returns {string}
 */
export function fwProtoLabel(proto) {
  if (!proto) return 'Any';
  const p = String(proto).toLowerCase();
  if (p === '*') return 'Any';
  if (p === 'tcp') return 'TCP';
  if (p === 'udp') return 'UDP';
  if (p === 'icmp') return 'ICMP';
  if (p === 'esp') return 'ESP';
  if (p === 'ah') return 'AH';
  return proto;
}

// ── Rule equality ──────────────────────────────────────────────────────

/**
 * Compare two NSG security rule objects for logical equality.
 * Matches on name, priority, direction, access, protocol, and address/port prefixes.
 * @param {Object} a
 * @param {Object} b
 * @returns {boolean}
 */
export function fwRuleMatch(a, b) {
  if (!a || !b) return false;
  if (a.name !== b.name) return false;
  if (a.priority !== b.priority) return false;
  if ((a.direction || '').toLowerCase() !== (b.direction || '').toLowerCase()) return false;
  if ((a.access || '').toLowerCase() !== (b.access || '').toLowerCase()) return false;
  if ((a.protocol || '').toLowerCase() !== (b.protocol || '').toLowerCase()) return false;
  if ((a.sourceAddressPrefix || '') !== (b.sourceAddressPrefix || '')) return false;
  if ((a.destinationAddressPrefix || '') !== (b.destinationAddressPrefix || '')) return false;
  if ((a.destinationPortRange || '') !== (b.destinationPortRange || '')) return false;
  return true;
}

// ── Edit count ─────────────────────────────────────────────────────────

/**
 * Count edits targeting a specific resource.
 * @param {string} resourceId
 * @returns {number}
 */
export function fwEditCount(resourceId) {
  return _fwEdits.filter(e => e.resourceId === resourceId).length;
}

// ── Validation ─────────────────────────────────────────────────────────

/**
 * Validate a CIDR string (IPv4 only).
 * @param {string} cidr
 * @returns {boolean}
 */
export function fwValidateCidr(cidr) {
  if (!cidr || typeof cidr !== 'string') return false;
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) return false;
  const parts = cidr.split('/');
  const octets = parts[0].split('.');
  for (let i = 0; i < 4; i++) {
    if (parseInt(octets[i], 10) > 255) return false;
  }
  if (parseInt(parts[1], 10) > 32) return false;
  return true;
}

/**
 * Validate an Azure address prefix (CIDR, bare IP, service tag, or wildcard).
 * Service tags: *, VirtualNetwork, AzureLoadBalancer, Internet.
 * Also accepts custom service tag names (alphanumeric with dots).
 * @param {string} prefix
 * @returns {boolean}
 */
export function fwValidateAddressPrefix(prefix) {
  if (!prefix || typeof prefix !== 'string') return false;
  const val = prefix.trim();
  const serviceTags = ['*', 'VirtualNetwork', 'AzureLoadBalancer', 'Internet'];
  if (serviceTags.includes(val)) return true;
  if (fwValidateCidr(val)) return true;
  // Bare IP address (no prefix length)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) {
    const octets = val.split('.');
    for (let i = 0; i < 4; i++) {
      if (parseInt(octets[i], 10) > 255) return false;
    }
    return true;
  }
  // Custom service tag name (e.g., Storage.WestUS, Sql, AppService)
  if (/^[A-Za-z][A-Za-z0-9.]*$/.test(val)) return true;
  return false;
}

/**
 * Validate an NSG security rule object.
 * @param {Object} rule - Rule with name, priority, direction, access, protocol,
 *   sourceAddressPrefix, destinationAddressPrefix, destinationPortRange
 * @param {Object[]} [existingRules] - Current rules (for duplicate priority check)
 * @param {string} [editingName] - Name of rule being edited (excluded from dup check)
 * @returns {string[]} Array of error messages (empty = valid)
 */
export function fwValidateNsgRule(rule, existingRules, editingName) {
  const errs = [];

  // Rule name
  if (!rule.name || typeof rule.name !== 'string' || !rule.name.trim()) {
    errs.push('Rule name is required');
  } else if (!/^[A-Za-z0-9_.-]+$/.test(rule.name.trim())) {
    errs.push('Rule name must contain only alphanumerics, underscores, periods, hyphens');
  }

  // Priority (100-4096 for custom rules)
  const priority = parseInt(rule.priority, 10);
  if (isNaN(priority) || priority < 100 || priority > 4096) {
    errs.push('Priority must be 100-4096');
  }
  if (existingRules && !isNaN(priority)) {
    const dup = existingRules.some(r =>
      r.priority === priority &&
      (r.direction || '').toLowerCase() === (rule.direction || '').toLowerCase() &&
      r.name !== editingName
    );
    if (dup) errs.push('Duplicate priority ' + priority + ' in ' + rule.direction + ' direction');
  }

  // Direction
  const dir = (rule.direction || '').toLowerCase();
  if (dir !== 'inbound' && dir !== 'outbound') {
    errs.push('Direction must be Inbound or Outbound');
  }

  // Access
  const access = (rule.access || '').toLowerCase();
  if (access !== 'allow' && access !== 'deny') {
    errs.push('Access must be Allow or Deny');
  }

  // Protocol
  const proto = (rule.protocol || '').toLowerCase();
  const validProtos = ['tcp', 'udp', 'icmp', 'esp', 'ah', '*'];
  if (!validProtos.includes(proto)) errs.push('Invalid protocol: ' + rule.protocol);

  // Destination port range (required for TCP/UDP)
  if (proto === 'tcp' || proto === 'udp') {
    if (!rule.destinationPortRange && !rule.destinationPortRanges) {
      errs.push('Destination port range required for TCP/UDP');
    } else {
      const portStr = rule.destinationPortRange || '';
      if (portStr && portStr !== '*') {
        const segments = portStr.split(',');
        for (const seg of segments) {
          const s = seg.trim();
          if (s.includes('-')) {
            const [lo, hi] = s.split('-').map(Number);
            if (isNaN(lo) || isNaN(hi) || lo < 0 || lo > 65535 || hi < 0 || hi > 65535 || lo > hi) {
              errs.push('Invalid port range: ' + s);
            }
          } else {
            const n = Number(s);
            if (isNaN(n) || n < 0 || n > 65535) errs.push('Invalid port: ' + s);
          }
        }
      }
    }
  }

  // Source address prefix
  if (!fwValidateAddressPrefix(rule.sourceAddressPrefix || '')) {
    if (!(rule.sourceAddressPrefixes && rule.sourceAddressPrefixes.length)) {
      errs.push('Invalid source address prefix');
    }
  }

  // Destination address prefix
  if (!fwValidateAddressPrefix(rule.destinationAddressPrefix || '')) {
    if (!(rule.destinationAddressPrefixes && rule.destinationAddressPrefixes.length)) {
      errs.push('Invalid destination address prefix');
    }
  }

  return errs;
}

/**
 * Validate a UDR route object.
 * @param {Object} route - Route with name, addressPrefix, nextHopType, nextHopIpAddress
 * @param {Object[]} [existingRoutes] - Current routes (for duplicate check)
 * @param {string} [editingName] - Name of route being edited (excluded from dup check)
 * @returns {string[]} Array of error messages (empty = valid)
 */
export function fwValidateRoute(route, existingRoutes, editingName) {
  const errs = [];

  if (!route.name || typeof route.name !== 'string' || !route.name.trim()) {
    errs.push('Route name is required');
  }

  if (!fwValidateCidr(route.addressPrefix)) errs.push('Invalid address prefix (CIDR)');

  if (existingRoutes) {
    const dup = existingRoutes.some(r =>
      r.addressPrefix === route.addressPrefix && r.name !== editingName
    );
    if (dup) errs.push('Duplicate address prefix: ' + route.addressPrefix);
  }

  const validHops = ['VirtualNetworkGateway', 'VNetLocal', 'Internet', 'VirtualAppliance', 'None'];
  if (!validHops.includes(route.nextHopType)) {
    errs.push('Invalid next hop type. Must be: ' + validHops.join(', '));
  }

  if (route.nextHopType === 'VirtualAppliance') {
    if (!route.nextHopIpAddress || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(route.nextHopIpAddress)) {
      errs.push('VirtualAppliance requires a valid next hop IP address');
    }
  }

  return errs;
}

// ── Shadow detection ───────────────────────────────────────────────────

/**
 * Detect NSG rules that are shadowed by earlier (lower-priority-number) rules.
 * In Azure NSGs, rules are evaluated lowest priority number first; first match wins.
 * @param {Object} nsg - NSG object with securityRules array
 * @param {string} direction - 'inbound' or 'outbound'
 * @returns {string[]} Human-readable warning messages
 */
export function fwCheckNsgShadow(nsg, direction) {
  if (!nsg || !nsg.securityRules) return [];
  const dir = (direction || '').toLowerCase();
  const rules = (nsg.securityRules || [])
    .filter(r => (r.direction || '').toLowerCase() === dir)
    .sort((a, b) => a.priority - b.priority);
  const warnings = [];
  for (let i = 1; i < rules.length; i++) {
    for (let j = 0; j < i; j++) {
      const hi = rules[i];
      const lo = rules[j];
      const sameSrc = (hi.sourceAddressPrefix || '') === (lo.sourceAddressPrefix || '') || lo.sourceAddressPrefix === '*';
      const sameDst = (hi.destinationAddressPrefix || '') === (lo.destinationAddressPrefix || '') || lo.destinationAddressPrefix === '*';
      const sameProto = (hi.protocol || '') === (lo.protocol || '') || lo.protocol === '*';
      const samePort = (hi.destinationPortRange || '') === (lo.destinationPortRange || '') || lo.destinationPortRange === '*';
      if (sameSrc && sameDst && sameProto && samePort && (hi.access || '').toLowerCase() !== (lo.access || '').toLowerCase()) {
        warnings.push(
          'Rule "' + hi.name + '" (priority ' + hi.priority + ', ' + hi.access +
          ') is shadowed by "' + lo.name + '" (priority ' + lo.priority + ', ' + lo.access +
          ') \u2014 same scope, evaluated first'
        );
      }
    }
  }
  return warnings;
}

// ── ARM resource group extraction ──────────────────────────────────────

/**
 * Extract the resource group name from an ARM resource ID.
 * @param {string} armId - Full ARM resource ID path
 * @returns {string} Resource group name, or '{resource-group}' placeholder
 */
export function extractResourceGroup(armId) {
  if (!armId || typeof armId !== 'string') return '{resource-group}';
  const match = armId.match(/\/resourceGroups\/([^/]+)/i);
  return match ? match[1] : '{resource-group}';
}

// ── CLI generation ─────────────────────────────────────────────────────

/**
 * Build Azure CLI commands for a list of edits.
 * @param {Object[]} [edits] - Edit objects; defaults to internal _fwEdits
 * @returns {string[]} Array of CLI command strings
 */
export function fwGenerateCli(edits) {
  const list = edits || _fwEdits;
  const cmds = [];
  list.forEach(edit => {
    if (edit.type === 'nsg') fwGenNsgCli(edit, cmds);
    else if (edit.type === 'udr') fwGenUdrCli(edit, cmds);
  });
  return cmds;
}

/**
 * Append NSG CLI command(s) for a single edit.
 * @param {Object} edit
 * @param {string[]} cmds - Accumulator array
 */
export function fwGenNsgCli(edit, cmds) {
  const nsgName = edit.nsgName || edit.resourceId;
  const rg = edit.resourceGroup || '{resource-group}';
  if (edit.action === 'add' || edit.action === 'modify') {
    cmds.push(_fwNsgRuleCmd('create', rg, nsgName, edit.rule));
  } else if (edit.action === 'delete') {
    cmds.push(
      'az network nsg rule delete' +
      ' --resource-group ' + rg +
      ' --nsg-name ' + nsgName +
      ' --name ' + edit.rule.name
    );
  }
}

function _fwNsgRuleCmd(verb, rg, nsgName, rule) {
  let cmd = 'az network nsg rule ' + verb +
    ' --resource-group ' + rg +
    ' --nsg-name ' + nsgName +
    ' --name ' + rule.name +
    ' --priority ' + rule.priority +
    ' --direction ' + rule.direction +
    ' --access ' + rule.access +
    ' --protocol ' + rule.protocol;
  if (rule.sourcePortRange) cmd += ' --source-port-ranges ' + rule.sourcePortRange;
  else cmd += ' --source-port-ranges "*"';
  if (rule.destinationPortRange) cmd += ' --destination-port-ranges ' + rule.destinationPortRange;
  else cmd += ' --destination-port-ranges "*"';
  if (rule.sourceAddressPrefix) cmd += ' --source-address-prefixes ' + rule.sourceAddressPrefix;
  else cmd += ' --source-address-prefixes "*"';
  if (rule.destinationAddressPrefix) cmd += ' --destination-address-prefixes ' + rule.destinationAddressPrefix;
  else cmd += ' --destination-address-prefixes "*"';
  return cmd;
}

/**
 * Append UDR CLI command(s) for a single edit.
 * @param {Object} edit
 * @param {string[]} cmds - Accumulator array
 */
export function fwGenUdrCli(edit, cmds) {
  const rtName = edit.routeTableName || edit.resourceId;
  const rg = edit.resourceGroup || '{resource-group}';
  if (edit.action === 'add' || edit.action === 'modify') {
    cmds.push(_fwUdrRouteCmd('create', rg, rtName, edit.rule));
  } else if (edit.action === 'delete') {
    cmds.push(
      'az network route-table route delete' +
      ' --resource-group ' + rg +
      ' --route-table-name ' + rtName +
      ' --name ' + edit.rule.name
    );
  }
}

function _fwUdrRouteCmd(verb, rg, rtName, route) {
  let cmd = 'az network route-table route ' + verb +
    ' --resource-group ' + rg +
    ' --route-table-name ' + rtName +
    ' --name ' + route.name +
    ' --address-prefix ' + route.addressPrefix +
    ' --next-hop-type ' + route.nextHopType;
  if (route.nextHopType === 'VirtualAppliance' && route.nextHopIpAddress) {
    cmd += ' --next-hop-ip-address ' + route.nextHopIpAddress;
  }
  return cmd;
}

// ── Snapshot / reset ───────────────────────────────────────────────────

/**
 * Take a deep-copy snapshot of nsgs/udrs from the given context.
 * No-op if a snapshot already exists.
 * @param {Object} ctx - The _rlCtx context object
 */
export function fwTakeSnapshot(ctx) {
  if (_fwSnapshot) return;
  if (!ctx) return;
  _fwSnapshot = {
    nsgs: JSON.parse(JSON.stringify(ctx.nsgs || [])),
    udrs: JSON.parse(JSON.stringify(ctx.udrs || []))
  };
}

/**
 * Restore nsgs/udrs from the snapshot, clear edits, and rebuild lookups.
 * Preserves the original array references in ctx.
 * @param {Object} ctx - The _rlCtx context object
 */
export function fwResetAll(ctx) {
  if (!_fwSnapshot || !ctx) return;
  ctx.nsgs.length = 0;
  _fwSnapshot.nsgs.forEach(n => ctx.nsgs.push(JSON.parse(JSON.stringify(n))));
  ctx.udrs.length = 0;
  _fwSnapshot.udrs.forEach(r => ctx.udrs.push(JSON.parse(JSON.stringify(r))));
  fwRebuildLookups(ctx);
  _fwEdits = [];
  _fwSnapshot = null;
}

// ── Lookup rebuilding ──────────────────────────────────────────────────

/**
 * Rebuild derived lookup maps (subnetNsgs, subRT, nsgByVnet) on ctx.
 * @param {Object} ctx - The _rlCtx context object
 */
export function fwRebuildLookups(ctx) {
  if (!ctx) return;

  // subnetNsgs: SubnetId -> NSG
  const subnetNsgs = {};
  (ctx.nsgs || []).forEach(nsg => {
    (nsg.subnets || []).forEach(subRef => {
      const subId = typeof subRef === 'string' ? subRef : (subRef.id || subRef.SubnetId);
      if (subId) subnetNsgs[subId] = nsg;
    });
  });
  ctx.subnetNsgs = subnetNsgs;

  // subRT: SubnetId -> UDR route table
  const subRT = {};
  (ctx.udrs || []).forEach(rt => {
    (rt.subnets || []).forEach(subRef => {
      const subId = typeof subRef === 'string' ? subRef : (subRef.id || subRef.SubnetId);
      if (subId) subRT[subId] = rt;
    });
  });
  ctx.subRT = subRT;

  // nsgByVnet: VnetId -> NSG[]
  const nsgByVnet = {};
  (ctx.nsgs || []).forEach(nsg => {
    const vnetId = nsg.vnetId || '';
    (nsgByVnet[vnetId] = nsgByVnet[vnetId] || []).push(nsg);
  });
  ctx.nsgByVnet = nsgByVnet;
}

// ── Rule CRUD ──────────────────────────────────────────────────────────

/**
 * Remove a rule from context arrays based on an edit descriptor.
 * @param {Object} edit - Edit object with type, resourceId, direction, rule
 * @param {Object} ctx - The _rlCtx context object
 */
export function fwRemoveRule(edit, ctx) {
  if (edit.type === 'nsg') {
    const nsg = (ctx.nsgs || []).find(n => n.id === edit.resourceId || n.name === edit.resourceId);
    if (!nsg) return;
    const idx = (nsg.securityRules || []).findIndex(r =>
      r.name === edit.rule.name && r.priority === edit.rule.priority
    );
    if (idx >= 0) nsg.securityRules.splice(idx, 1);
  } else if (edit.type === 'udr') {
    const rt = (ctx.udrs || []).find(r => r.id === edit.resourceId || r.name === edit.resourceId);
    if (!rt || !rt.routes) return;
    const idx = rt.routes.findIndex(r => r.addressPrefix === edit.rule.addressPrefix);
    if (idx >= 0) rt.routes.splice(idx, 1);
  }
}

/**
 * Restore a previously deleted rule via its originalRule field.
 * @param {Object} edit - Edit object (must have originalRule)
 * @param {Object} ctx - The _rlCtx context object
 */
export function fwRestoreRule(edit, ctx) {
  if (edit.originalRule) {
    fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule, ctx);
  }
}

/**
 * Upsert a rule into the appropriate context array.
 * @param {string} type - 'nsg' or 'udr'
 * @param {string} resourceId - The ARM resource ID or name
 * @param {string} direction - 'inbound' or 'outbound' (NSG only)
 * @param {Object} ruleData - The rule to apply
 * @param {Object} ctx - The _rlCtx context object
 */
export function fwApplyRule(type, resourceId, direction, ruleData, ctx) {
  if (type === 'nsg') {
    const nsg = (ctx.nsgs || []).find(n => n.id === resourceId || n.name === resourceId);
    if (!nsg) return;
    if (!nsg.securityRules) nsg.securityRules = [];
    const idx = nsg.securityRules.findIndex(r =>
      r.name === ruleData.name && r.priority === ruleData.priority
    );
    const entry = Object.assign({}, ruleData);
    if (idx >= 0) nsg.securityRules[idx] = entry;
    else nsg.securityRules.push(entry);
  } else if (type === 'udr') {
    const rt = (ctx.udrs || []).find(r => r.id === resourceId || r.name === resourceId);
    if (!rt) return;
    if (!rt.routes) rt.routes = [];
    const idx = rt.routes.findIndex(r => r.addressPrefix === ruleData.addressPrefix);
    if (idx >= 0) rt.routes[idx] = Object.assign({}, ruleData);
    else rt.routes.push(Object.assign({}, ruleData));
  }
}

// ── Undo ───────────────────────────────────────────────────────────────

/**
 * Undo the most recent edit, reversing its effect on ctx arrays.
 * @param {Object} ctx - The _rlCtx context object
 * @returns {Object|null} The undone edit, or null if nothing to undo
 */
export function fwUndo(ctx) {
  if (!_fwEdits.length) return null;
  const edit = _fwEdits.pop();
  if (edit.action === 'add') fwRemoveRule(edit, ctx);
  else if (edit.action === 'delete') fwRestoreRule(edit, ctx);
  else if (edit.action === 'modify') {
    fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule, ctx);
  }
  fwRebuildLookups(ctx);
  return edit;
}
