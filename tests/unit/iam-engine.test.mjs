import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  getScopeLevel, classifyPermission,
  analyzeRoleAssignments, findOverPrivileged,
  findOrphanedAssignments, countOwnersPerScope
} from '../../src/modules/iam-engine.js';

// ---------------------------------------------------------------------------
// Helpers to build test fixtures
// ---------------------------------------------------------------------------

const SUB_SCOPE = '/subscriptions/sub-abc';
const RG_SCOPE  = '/subscriptions/sub-abc/resourceGroups/prod-rg';
const MG_SCOPE  = '/providers/Microsoft.Management/managementGroups/root-mg';

// Well-known role definition IDs (GUIDs from BUILTIN_ROLES map in iam-engine.js)
const OWNER_ROLE_DEF_ID      = '/subscriptions/sub-abc/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635';
const CONTRIBUTOR_ROLE_DEF_ID = '/subscriptions/sub-abc/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c';
const READER_ROLE_DEF_ID      = '/subscriptions/sub-abc/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7';

function makeAssignment(principalId, roleDefId, scope, principalType = 'User') {
  return {
    id: `/subscriptions/sub-abc/providers/Microsoft.Authorization/roleAssignments/${principalId}-assign`,
    properties: {
      principalId,
      principalType,
      principalDisplayName: principalId,
      roleDefinitionId: roleDefId,
      scope
    }
  };
}

// ---------------------------------------------------------------------------
// getScopeLevel
// ---------------------------------------------------------------------------

describe('getScopeLevel', () => {
  it('detects subscription scope', () => {
    assert.equal(getScopeLevel('/subscriptions/sub-abc'), 'subscription');
  });
  it('detects resourceGroup scope', () => {
    assert.equal(getScopeLevel('/subscriptions/sub-abc/resourceGroups/prod-rg'), 'resourceGroup');
  });
  it('detects managementGroup scope', () => {
    assert.equal(getScopeLevel('/providers/Microsoft.Management/managementGroups/root-mg'), 'managementGroup');
  });
  it('detects resource scope for deeper paths', () => {
    assert.equal(getScopeLevel('/subscriptions/sub-abc/resourceGroups/prod-rg/providers/Microsoft.Network/virtualNetworks/hub-vnet'), 'resource');
  });
  it('defaults to resource for null', () => {
    assert.equal(getScopeLevel(null), 'resource');
  });
});

// ---------------------------------------------------------------------------
// classifyPermission
// ---------------------------------------------------------------------------

describe('classifyPermission', () => {
  it('* is admin', () => assert.equal(classifyPermission('*'), 'admin'));
  it('Microsoft.Compute/* is admin', () => assert.equal(classifyPermission('Microsoft.Compute/*'), 'admin'));
  it('Microsoft.Network/virtualNetworks/delete is delete', () => {
    assert.equal(classifyPermission('Microsoft.Network/virtualNetworks/delete'), 'delete');
  });
  it('Microsoft.Compute/virtualMachines/write is write', () => {
    assert.equal(classifyPermission('Microsoft.Compute/virtualMachines/write'), 'write');
  });
  it('Microsoft.Compute/virtualMachines/start/action is write', () => {
    assert.equal(classifyPermission('Microsoft.Compute/virtualMachines/start/action'), 'write');
  });
  it('Microsoft.Compute/virtualMachines/read is read', () => {
    assert.equal(classifyPermission('Microsoft.Compute/virtualMachines/read'), 'read');
  });
  it('null returns read', () => assert.equal(classifyPermission(null), 'read'));
});

// ---------------------------------------------------------------------------
// findOrphanedAssignments
// ---------------------------------------------------------------------------

describe('findOrphanedAssignments', () => {
  it('returns empty for empty assignments', () => {
    assert.deepEqual(findOrphanedAssignments([]), []);
  });
  it('returns empty for null', () => {
    assert.deepEqual(findOrphanedAssignments(null), []);
  });
  it('flags assignment with principalType Unknown', () => {
    const assignments = [makeAssignment('orphan-pid', READER_ROLE_DEF_ID, RG_SCOPE, 'Unknown')];
    const findings = findOrphanedAssignments(assignments);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].control, 'RBAC-2');
    assert.equal(findings[0].severity, 'MEDIUM');
  });
  it('flags assignment with empty principalType', () => {
    const a = makeAssignment('empty-type-pid', READER_ROLE_DEF_ID, RG_SCOPE, '');
    const findings = findOrphanedAssignments([a]);
    assert.equal(findings.length, 1);
  });
  it('does not flag valid User assignments', () => {
    const assignments = [makeAssignment('valid-user', READER_ROLE_DEF_ID, RG_SCOPE, 'User')];
    const findings = findOrphanedAssignments(assignments);
    assert.equal(findings.length, 0);
  });
});

// ---------------------------------------------------------------------------
// findOverPrivileged
// ---------------------------------------------------------------------------

describe('findOverPrivileged', () => {
  it('returns empty for empty assignments', () => {
    assert.deepEqual(findOverPrivileged([], []), []);
  });
  it('flags Owner at subscription scope as CRITICAL RBAC-1', () => {
    const assignments = [makeAssignment('user-1', OWNER_ROLE_DEF_ID, SUB_SCOPE)];
    const findings = findOverPrivileged(assignments, []);
    assert.ok(findings.some(f => f.control === 'RBAC-1' && f.severity === 'CRITICAL'));
  });
  it('flags Owner at management group scope as CRITICAL RBAC-1', () => {
    const assignments = [makeAssignment('user-1', OWNER_ROLE_DEF_ID, MG_SCOPE)];
    const findings = findOverPrivileged(assignments, []);
    assert.ok(findings.some(f => f.control === 'RBAC-1' && f.severity === 'CRITICAL'));
  });
  it('does not flag Owner at resourceGroup scope', () => {
    const assignments = [makeAssignment('user-2', OWNER_ROLE_DEF_ID, RG_SCOPE)];
    const findings = findOverPrivileged(assignments, []);
    // Owner at RG scope is not flagged by findOverPrivileged
    assert.ok(!findings.some(f => f.control === 'RBAC-1' && f.severity === 'CRITICAL'));
  });
  it('flags custom wildcard role', () => {
    const customRoleDefId = '/subscriptions/sub-abc/providers/Microsoft.Authorization/roleDefinitions/custom-guid-001';
    const customDef = {
      id: customRoleDefId,
      name: 'custom-guid-001',
      properties: {
        roleName: 'SuperCustomRole',
        type: 'CustomRole',
        permissions: [{ actions: ['*'], notActions: [] }]
      }
    };
    const assignments = [makeAssignment('user-3', customRoleDefId, RG_SCOPE)];
    const findings = findOverPrivileged(assignments, [customDef]);
    assert.ok(findings.some(f => f.control === 'RBAC-1'));
  });
});

// ---------------------------------------------------------------------------
// countOwnersPerScope
// ---------------------------------------------------------------------------

describe('countOwnersPerScope', () => {
  it('returns empty when fewer than 4 owners at any scope', () => {
    const assignments = [
      makeAssignment('u1', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u2', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u3', OWNER_ROLE_DEF_ID, SUB_SCOPE)
    ];
    assert.deepEqual(countOwnersPerScope(assignments), []);
  });
  it('flags scope with more than 3 owners as RBAC-3', () => {
    const assignments = [
      makeAssignment('u1', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u2', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u3', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u4', OWNER_ROLE_DEF_ID, SUB_SCOPE)
    ];
    const findings = countOwnersPerScope(assignments);
    assert.ok(findings.some(f => f.control === 'RBAC-3'));
    assert.ok(findings.some(f => f.severity === 'MEDIUM'));
  });
  it('counts owners per scope independently', () => {
    // 2 owners at sub, 2 owners at rg — neither exceeds 3
    const assignments = [
      makeAssignment('u1', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u2', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u3', OWNER_ROLE_DEF_ID, RG_SCOPE),
      makeAssignment('u4', OWNER_ROLE_DEF_ID, RG_SCOPE)
    ];
    assert.deepEqual(countOwnersPerScope(assignments), []);
  });
});

// ---------------------------------------------------------------------------
// analyzeRoleAssignments
// ---------------------------------------------------------------------------

describe('analyzeRoleAssignments', () => {
  it('returns empty for empty assignments', () => {
    assert.deepEqual(analyzeRoleAssignments([], []), []);
  });
  it('returns empty for null assignments', () => {
    assert.deepEqual(analyzeRoleAssignments(null, []), []);
  });
  it('produces RBAC-1 finding for Owner at subscription scope', () => {
    const assignments = [makeAssignment('user-1', OWNER_ROLE_DEF_ID, SUB_SCOPE)];
    const findings = analyzeRoleAssignments(assignments, []);
    assert.ok(findings.some(f => f.control === 'RBAC-1'));
  });
  it('produces RBAC-2 finding for orphaned assignment', () => {
    const assignments = [makeAssignment('ghost-pid', READER_ROLE_DEF_ID, RG_SCOPE, 'Unknown')];
    const findings = analyzeRoleAssignments(assignments, []);
    assert.ok(findings.some(f => f.control === 'RBAC-2'));
  });
  it('produces RBAC-3 finding for >3 owners at same scope', () => {
    const assignments = [
      makeAssignment('u1', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u2', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u3', OWNER_ROLE_DEF_ID, SUB_SCOPE),
      makeAssignment('u4', OWNER_ROLE_DEF_ID, SUB_SCOPE)
    ];
    const findings = analyzeRoleAssignments(assignments, []);
    assert.ok(findings.some(f => f.control === 'RBAC-3'));
  });
  it('produces RBAC-8 finding for custom role with wildcard', () => {
    const customRoleDefId = '/subscriptions/sub-abc/providers/Microsoft.Authorization/roleDefinitions/custom-guid-002';
    const customDef = {
      id: customRoleDefId,
      name: 'custom-guid-002',
      properties: {
        roleName: 'WildcardCustomRole',
        type: 'CustomRole',
        permissions: [{ actions: ['*'], notActions: [] }]
      }
    };
    // analyzeRoleAssignments early-returns for empty assignments; provide one Reader
    // assignment at RG scope so the function runs to completion and checks definitions
    const assignments = [makeAssignment('some-user', READER_ROLE_DEF_ID, RG_SCOPE)];
    const findings = analyzeRoleAssignments(assignments, [customDef]);
    assert.ok(findings.some(f => f.control === 'RBAC-8'));
  });
  it('all findings include severity, control, framework, resource fields', () => {
    const assignments = [makeAssignment('user-1', OWNER_ROLE_DEF_ID, SUB_SCOPE)];
    const findings = analyzeRoleAssignments(assignments, []);
    for (const f of findings) {
      assert.ok(f.severity, `Missing severity on finding ${f.control}`);
      assert.ok(f.control, 'Missing control');
      assert.ok(f.framework, 'Missing framework');
      assert.ok('resource' in f, 'Missing resource field');
    }
  });
});
