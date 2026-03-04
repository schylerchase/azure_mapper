// Azure RBAC analysis and role assignment assessment engine
// Analyzes role assignments, role definitions, and access patterns
// Azure RBAC model: role definitions + role assignments at scopes

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------
let _rbacData = null;
let _showRBAC = false;

export function setRbacData(v) { _rbacData = v; }
export function setShowRBAC(v) { _showRBAC = v; }
export function getRbacData() { return _rbacData; }
export function getShowRBAC() { return _showRBAC; }

// ---------------------------------------------------------------------------
// Built-in role IDs (well-known Azure built-in roles)
// ---------------------------------------------------------------------------
const BUILTIN_ROLES = {
  'acdd72a7-3385-48ef-bd42-f606fba81ae7': 'Reader',
  'b24988ac-6180-42a0-ab88-20f7382dd24c': 'Contributor',
  '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': 'Owner',
  '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': 'User Access Administrator',
  'f58310d9-a9f6-439a-9e8d-f62e7b41a168': 'Role Based Access Control Administrator',
  'fb1c8493-542b-48eb-b624-b4c8fea62acd': 'Security Admin',
  '39bc4728-0917-49c7-9d2c-d95423bc2eb4': 'Security Reader',
  '4a9ae827-6dc8-4573-8ac7-8239d42aa03f': 'Tag Contributor',
  '9980e02c-c2be-4d73-94e8-173b1dc7cf3c': 'Virtual Machine Contributor',
  'de139f84-1756-47ae-9be6-808fbbe84772': 'Website Contributor',
  'b7e6dc6d-f1e8-4753-8033-0f276bb0955b': 'Storage Blob Data Owner',
};

const HIGH_PRIVILEGE_ROLES = ['Owner', 'User Access Administrator', 'Role Based Access Control Administrator'];
const WRITE_DELETE_ROLE_NAMES = ['Contributor', 'Owner', 'User Access Administrator', 'Role Based Access Control Administrator'];

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

/**
 * Determine the scope level from an Azure scope string.
 * @param {string} scope - Azure scope string
 * @returns {'managementGroup'|'subscription'|'resourceGroup'|'resource'} Scope level
 */
export function getScopeLevel(scope) {
  if (!scope) return 'resource';
  const lower = scope.toLowerCase();
  if (lower.startsWith('/providers/microsoft.management/managementgroups/')) return 'managementGroup';
  // /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
  const parts = lower.replace(/^\//, '').split('/');
  if (parts[0] === 'subscriptions' && parts.length === 2) return 'subscription';
  if (parts[0] === 'subscriptions' && parts[2] === 'resourcegroups' && parts.length === 4) return 'resourceGroup';
  if (parts[0] === 'subscriptions' && parts.length > 4) return 'resource';
  return 'resource';
}

/**
 * Extract subscription ID from a scope string.
 * @param {string} scope
 * @returns {string} Subscription ID or empty string
 */
function _subFromScope(scope) {
  if (!scope) return '';
  const m = scope.match(/\/subscriptions\/([^/]+)/i);
  return m ? m[1] : '';
}

// ---------------------------------------------------------------------------
// Permission classification
// ---------------------------------------------------------------------------

/**
 * Classify an Azure RBAC action string into a permission category.
 * @param {string} action - Azure action string (e.g. "Microsoft.Compute/virtualMachines/read")
 * @returns {'admin'|'delete'|'write'|'read'} Permission category
 */
export function classifyPermission(action) {
  if (!action) return 'read';
  const lower = action.toLowerCase();
  if (lower === '*') return 'admin';
  if (lower.endsWith('/*')) return 'admin';
  if (lower.endsWith('/delete') || lower.includes('/delete/')) return 'delete';
  if (lower.endsWith('/write') || lower.includes('/write/') ||
      lower.endsWith('/action') || lower.includes('/action/') ||
      lower.endsWith('/start/action') || lower.endsWith('/restart/action') ||
      lower.endsWith('/deallocate/action')) return 'write';
  if (lower.endsWith('/read') || lower.includes('/read/') ||
      lower.endsWith('/listkeys/action') || lower.endsWith('/list/action')) return 'read';
  // If no clear suffix, default to write (actions without /read are typically mutations)
  return 'write';
}

// ---------------------------------------------------------------------------
// Role definition helpers
// ---------------------------------------------------------------------------

/**
 * Check if a role definition has wildcard (admin-level) permissions.
 * @param {Object} definition - Azure role definition
 * @returns {boolean}
 */
function _isWildcardRole(definition) {
  if (!definition) return false;
  const perms = definition.properties?.permissions || definition.permissions || [];
  return perms.some(p => {
    const actions = p.actions || [];
    return actions.includes('*');
  });
}

/**
 * Resolve a role definition ID to its name.
 * @param {string} roleDefId - Full role definition ID
 * @param {Object[]} definitions - Array of role definitions
 * @returns {string} Role name
 */
function _resolveRoleName(roleDefId, definitions) {
  if (!roleDefId) return 'Unknown';
  // Extract GUID from the end of the role definition ID
  const parts = roleDefId.split('/');
  const guid = parts[parts.length - 1] || '';
  // Check built-in map first
  if (BUILTIN_ROLES[guid]) return BUILTIN_ROLES[guid];
  // Search definitions array
  const def = (definitions || []).find(d =>
    d.id === roleDefId || d.name === guid || d.properties?.roleName === guid
  );
  if (def) return def.properties?.roleName || def.name || 'Unknown';
  return guid.length > 12 ? guid.substring(0, 8) + '...' : guid;
}

/**
 * Find the full role definition object for a role definition ID.
 * @param {string} roleDefId
 * @param {Object[]} definitions
 * @returns {Object|null}
 */
function _findDefinition(roleDefId, definitions) {
  if (!roleDefId || !definitions) return null;
  const parts = roleDefId.split('/');
  const guid = parts[parts.length - 1] || '';
  return definitions.find(d =>
    d.id === roleDefId || d.name === guid
  ) || null;
}

// ---------------------------------------------------------------------------
// Main analysis function
// ---------------------------------------------------------------------------

/**
 * Analyze Azure RBAC role assignments and produce security findings.
 * @param {Object[]} assignments - Array of role assignment objects
 * @param {Object[]} definitions - Array of role definition objects
 * @returns {Object[]} Array of finding objects
 */
export function analyzeRoleAssignments(assignments, definitions) {
  const findings = [];
  if (!assignments || !assignments.length) return findings;

  // Pre-index definitions by ID for fast lookup
  const defById = new Map();
  (definitions || []).forEach(d => {
    if (d.id) defById.set(d.id, d);
    if (d.name) defById.set(d.name, d);
  });

  const overPrivileged = findOverPrivileged(assignments, definitions);
  overPrivileged.forEach(f => findings.push(f));

  const orphaned = findOrphanedAssignments(assignments);
  orphaned.forEach(f => findings.push(f));

  const ownerCounts = countOwnersPerScope(assignments);
  ownerCounts.forEach(f => findings.push(f));

  const guestRisks = findGuestPrivileges(assignments, definitions);
  guestRisks.forEach(f => findings.push(f));

  const spRisks = findServicePrincipalRisks(assignments, definitions);
  spRisks.forEach(f => findings.push(f));

  // RBAC-6: Classic administrators (co-admins)
  assignments.forEach(a => {
    const props = a.properties || a;
    const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
    if (roleName === 'CoAdministrator' || roleName === 'ServiceAdministrator') {
      findings.push({
        severity: 'HIGH',
        control: 'RBAC-6',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: props.principalDisplayName || props.principalId || '',
        message: 'Classic administrator role "' + roleName + '" still in use',
        remediation: 'Migrate to Azure RBAC roles and remove classic administrator assignments'
      });
    }
  });

  // RBAC-7: Role assignments at management group scope
  assignments.forEach(a => {
    const props = a.properties || a;
    const scope = props.scope || a.scope || '';
    if (getScopeLevel(scope) === 'managementGroup') {
      const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
      if (HIGH_PRIVILEGE_ROLES.includes(roleName)) {
        findings.push({
          severity: 'HIGH',
          control: 'RBAC-7',
          framework: 'RBAC',
          resource: props.principalId || '',
          resourceName: props.principalDisplayName || props.principalId || '',
          message: roleName + ' assigned at management group scope — broad blast radius',
          remediation: 'Assign roles at the most restrictive scope needed (subscription or resource group)'
        });
      }
    }
  });

  // RBAC-8: Custom role definitions with wildcard actions
  (definitions || []).forEach(def => {
    const roleType = def.properties?.type || '';
    if (roleType === 'CustomRole' || roleType === 'customRole') {
      if (_isWildcardRole(def)) {
        findings.push({
          severity: 'HIGH',
          control: 'RBAC-8',
          framework: 'RBAC',
          resource: def.id || '',
          resourceName: def.properties?.roleName || def.name || '',
          message: 'Custom role "' + (def.properties?.roleName || '') + '" has wildcard (*) actions',
          remediation: 'Scope custom role actions to specific resource provider operations'
        });
      }
    }
  });

  // RBAC-9: Excessive role assignments per principal (>10 direct assignments)
  const assignmentsByPrincipal = {};
  assignments.forEach(a => {
    const pid = (a.properties || a).principalId || '';
    if (pid) {
      if (!assignmentsByPrincipal[pid]) assignmentsByPrincipal[pid] = [];
      assignmentsByPrincipal[pid].push(a);
    }
  });
  Object.entries(assignmentsByPrincipal).forEach(([pid, aList]) => {
    if (aList.length > 10) {
      const firstProps = aList[0].properties || aList[0];
      findings.push({
        severity: 'LOW',
        control: 'RBAC-9',
        framework: 'RBAC',
        resource: pid,
        resourceName: firstProps.principalDisplayName || pid,
        message: 'Principal has ' + aList.length + ' direct role assignments — consider using groups',
        remediation: 'Use Azure AD groups to consolidate role assignments'
      });
    }
  });

  return findings;
}

/**
 * Find over-privileged role assignments (wildcard actions or Owner at subscription scope).
 * @param {Object[]} assignments
 * @param {Object[]} definitions
 * @returns {Object[]} Array of findings
 */
export function findOverPrivileged(assignments, definitions) {
  const findings = [];
  (assignments || []).forEach(a => {
    const props = a.properties || a;
    const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
    const scope = props.scope || a.scope || '';
    const scopeLevel = getScopeLevel(scope);
    const principalName = props.principalDisplayName || props.principalId || '';

    // Owner at subscription or management group scope
    if (roleName === 'Owner' && (scopeLevel === 'subscription' || scopeLevel === 'managementGroup')) {
      findings.push({
        severity: 'CRITICAL',
        control: 'RBAC-1',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: principalName,
        message: 'Owner role at ' + scopeLevel + ' scope for "' + principalName + '"',
        remediation: 'Apply least-privilege: use Contributor or more specific roles; restrict Owner to break-glass accounts only'
      });
    }

    // User Access Administrator at subscription scope
    if (roleName === 'User Access Administrator' && scopeLevel === 'subscription') {
      findings.push({
        severity: 'HIGH',
        control: 'RBAC-1',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: principalName,
        message: 'User Access Administrator at subscription scope for "' + principalName + '"',
        remediation: 'Restrict to resource group scope or use Conditional Access for just-in-time access'
      });
    }

    // Custom roles with wildcard
    const def = _findDefinition(props.roleDefinitionId, definitions);
    if (def && _isWildcardRole(def) && roleName !== 'Owner' && roleName !== 'Contributor') {
      findings.push({
        severity: 'HIGH',
        control: 'RBAC-1',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: principalName,
        message: 'Role "' + roleName + '" has wildcard (*) actions assigned to "' + principalName + '"',
        remediation: 'Replace with a scoped role definition that lists specific actions'
      });
    }
  });
  return findings;
}

/**
 * Find orphaned role assignments (where the principal no longer exists).
 * Azure marks these with principalType: 'Unknown' or empty principalType.
 * @param {Object[]} assignments
 * @returns {Object[]} Array of findings
 */
export function findOrphanedAssignments(assignments) {
  const findings = [];
  (assignments || []).forEach(a => {
    const props = a.properties || a;
    const principalType = props.principalType || '';
    if (principalType === 'Unknown' || principalType === '') {
      findings.push({
        severity: 'MEDIUM',
        control: 'RBAC-2',
        framework: 'RBAC',
        resource: props.principalId || a.id || '',
        resourceName: props.principalId || 'Unknown Principal',
        message: 'Orphaned role assignment — principal no longer exists in Azure AD',
        remediation: 'Remove the orphaned assignment: az role assignment delete --ids ' + (a.id || '$ASSIGNMENT_ID')
      });
    }
  });
  return findings;
}

/**
 * Count Owner role assignments per scope and flag excessive counts.
 * Best practice: max 3 Owners per subscription.
 * @param {Object[]} assignments
 * @returns {Object[]} Array of findings
 */
export function countOwnersPerScope(assignments) {
  const findings = [];
  const ownersByScope = {};
  (assignments || []).forEach(a => {
    const props = a.properties || a;
    const roleDefId = props.roleDefinitionId || '';
    const guid = roleDefId.split('/').pop();
    // Owner GUID
    if (guid === '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' || BUILTIN_ROLES[guid] === 'Owner') {
      const scope = props.scope || a.scope || '';
      if (!ownersByScope[scope]) ownersByScope[scope] = [];
      ownersByScope[scope].push(props.principalId || '');
    }
  });
  Object.entries(ownersByScope).forEach(([scope, owners]) => {
    if (owners.length > 3) {
      const scopeLevel = getScopeLevel(scope);
      findings.push({
        severity: 'MEDIUM',
        control: 'RBAC-3',
        framework: 'RBAC',
        resource: scope,
        resourceName: scope.split('/').pop() || scope,
        message: owners.length + ' Owner assignments at ' + scopeLevel + ' scope (recommended max: 3)',
        remediation: 'Reduce Owner count; use Contributor for day-to-day operations'
      });
    }
  });
  return findings;
}

/**
 * Find guest users with write/delete permissions.
 * @param {Object[]} assignments
 * @param {Object[]} definitions
 * @returns {Object[]} Array of findings
 */
export function findGuestPrivileges(assignments, definitions) {
  const findings = [];
  (assignments || []).forEach(a => {
    const props = a.properties || a;
    if (props.principalType !== 'Guest' && props.principalType !== 'ForeignGroup') return;
    const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
    const principalName = props.principalDisplayName || props.principalId || '';

    // Check if the role grants write/delete
    if (WRITE_DELETE_ROLE_NAMES.includes(roleName)) {
      findings.push({
        severity: 'HIGH',
        control: 'RBAC-4',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: principalName,
        message: 'Guest user "' + principalName + '" has "' + roleName + '" role',
        remediation: 'Restrict guest users to Reader role or remove access; use Conditional Access policies for guest accounts'
      });
      return;
    }

    // Check custom role for write/delete actions
    const def = _findDefinition(props.roleDefinitionId, definitions);
    if (def) {
      const perms = def.properties?.permissions || def.permissions || [];
      const hasWrite = perms.some(p =>
        (p.actions || []).some(a => classifyPermission(a) === 'write' || classifyPermission(a) === 'delete' || classifyPermission(a) === 'admin')
      );
      if (hasWrite) {
        findings.push({
          severity: 'MEDIUM',
          control: 'RBAC-4',
          framework: 'RBAC',
          resource: props.principalId || '',
          resourceName: principalName,
          message: 'Guest user "' + principalName + '" has custom role "' + roleName + '" with write/delete permissions',
          remediation: 'Review guest user access and restrict to read-only roles'
        });
      }
    }
  });
  return findings;
}

/**
 * Find risky service principal role assignments.
 * Flags service principals with Owner or Contributor at subscription scope.
 * @param {Object[]} assignments
 * @param {Object[]} definitions
 * @returns {Object[]} Array of findings
 */
export function findServicePrincipalRisks(assignments, definitions) {
  const findings = [];
  (assignments || []).forEach(a => {
    const props = a.properties || a;
    if (props.principalType !== 'ServicePrincipal') return;
    const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
    const scope = props.scope || a.scope || '';
    const scopeLevel = getScopeLevel(scope);
    const principalName = props.principalDisplayName || props.principalId || '';

    if (roleName === 'Owner' && (scopeLevel === 'subscription' || scopeLevel === 'managementGroup')) {
      findings.push({
        severity: 'CRITICAL',
        control: 'RBAC-5',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: principalName,
        message: 'Service principal "' + principalName + '" has Owner at ' + scopeLevel + ' scope',
        remediation: 'Use Contributor or a custom role with specific permissions; implement credential rotation and monitoring'
      });
    } else if (roleName === 'Contributor' && scopeLevel === 'subscription') {
      findings.push({
        severity: 'HIGH',
        control: 'RBAC-5',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: principalName,
        message: 'Service principal "' + principalName + '" has Contributor at subscription scope',
        remediation: 'Scope to resource group level; use specific roles matching the workload needs'
      });
    }

    // Check for wildcard custom roles on service principals
    const def = _findDefinition(props.roleDefinitionId, definitions);
    if (def && _isWildcardRole(def) && roleName !== 'Owner' && roleName !== 'Contributor') {
      findings.push({
        severity: 'HIGH',
        control: 'RBAC-5',
        framework: 'RBAC',
        resource: props.principalId || '',
        resourceName: principalName,
        message: 'Service principal "' + principalName + '" has custom wildcard role "' + roleName + '"',
        remediation: 'Replace with scoped permissions; service principals should have minimal required access'
      });
    }
  });
  return findings;
}

/**
 * Parse RBAC data from Azure API responses into a normalized format.
 * @param {Object} raw - Raw RBAC data containing roleAssignments and roleDefinitions
 * @returns {Object|null} Normalized RBAC data
 */
function parseRBACData(raw) {
  if (!raw) return null;
  const data = {
    roleAssignments: [],
    roleDefinitions: [],
    customRoles: []
  };

  if (raw.roleAssignments) data.roleAssignments = Array.isArray(raw.roleAssignments) ? raw.roleAssignments : (raw.roleAssignments.value || []);
  if (raw.value && !raw.roleAssignments) data.roleAssignments = raw.value;
  if (raw.roleDefinitions) data.roleDefinitions = Array.isArray(raw.roleDefinitions) ? raw.roleDefinitions : (raw.roleDefinitions.value || []);

  // Separate custom roles
  data.customRoles = data.roleDefinitions.filter(d => {
    const roleType = d.properties?.type || '';
    return roleType === 'CustomRole' || roleType === 'customRole';
  });

  // Run analysis
  data.findings = analyzeRoleAssignments(data.roleAssignments, data.roleDefinitions);

  return data;
}

/**
 * Get RBAC findings relevant to a specific VNet or scope.
 * @param {Object} rbacData - Parsed RBAC data
 * @param {string} scope - Azure scope string (VNet ID, subscription ID, etc.)
 * @returns {Object[]} Relevant findings
 */
function getRBACForScope(rbacData, scope) {
  if (!rbacData || !scope) return [];
  const scopeLower = scope.toLowerCase();
  return (rbacData.findings || []).filter(f => {
    if (!f.resource) return false;
    // Check if the finding's resource is at or above the requested scope
    return f.resource.toLowerCase().includes(scopeLower) ||
           scopeLower.includes(f.resource.toLowerCase());
  });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
export {
  parseRBACData, getRBACForScope,
  _rbacData, _showRBAC
};
