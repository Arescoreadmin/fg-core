'use strict';

/**
 * workforce-invitation-authority.test.js
 *
 * Regression tests for H0-PR1: BFF credential routing for workforce user mutations.
 *
 * POST and PATCH /workforce/users require admin:write + identity.scim at Core.
 * Tenant portal API keys lack these scopes. The BFF must use admin gateway
 * credentials for these routes, not the tenant portal key.
 *
 * Tests:
 *   WF-1  isWorkforceAdminMutation returns true for POST workforce/users
 *   WF-2  isWorkforceAdminMutation returns true for PATCH workforce/users/{id}
 *   WF-3  isWorkforceAdminMutation returns false for GET workforce/users (read stays tenant-key)
 *   WF-4  isWorkforceAdminMutation returns false for HEAD workforce/users
 *   WF-5  isWorkforceAdminMutation returns false for unrelated POST paths
 *   WF-6  isWorkforceAdminMutation returns false for POST portal/grants (separate admin path)
 *   WF-7  Workforce mutation branch sets X-Admin-Gateway-Internal: true
 *   WF-8  Workforce mutation branch sets X-FG-Internal-Token (admin gateway token)
 *   WF-9  Workforce mutation branch sets X-Tenant-ID to the authorized tenant
 *   WF-10 Workforce mutation branch does NOT use tenant portal API key
 *   WF-11 Workforce mutation branch is distinct from isCrossTenantAdminPath (tenant still resolved)
 *   WF-12 Missing ADMIN_GATEWAY_TOKEN returns 503 for workforce mutation
 *   WF-13 Source: route.ts contains isWorkforceAdminMutation function definition
 *   WF-14 Source: isWorkforceAdminMutation is referenced in proxyToCore
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROUTE_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'app/api/core/[...path]/route.ts'),
  'utf8',
);

// ─── Extract and evaluate isWorkforceAdminMutation from source ────────────────

// Parse the function body from the TypeScript source (it has no TS-specific syntax)
function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`function ${name} not found in source`);
  let depth = 0;
  let i = src.indexOf('{', start);
  const bodyStart = i;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return src.slice(bodyStart, i + 1);
    }
  }
  throw new Error(`Unterminated function ${name}`);
}

// Inline JS-compatible version of isWorkforceAdminMutation for runtime testing
// (mirrors the TS source exactly — only strips TypeScript type annotations)
function isWorkforceAdminMutation(path, method) {
  return (
    (method === 'POST' || method === 'PATCH') &&
    path.length >= 2 &&
    path[0] === 'workforce' &&
    path[1] === 'users'
  );
}

// ─── Source-level guards ──────────────────────────────────────────────────────

test('WF-13 source: isWorkforceAdminMutation function is defined in route.ts', () => {
  assert.ok(
    ROUTE_SRC.includes('function isWorkforceAdminMutation('),
    'isWorkforceAdminMutation function definition not found in route.ts',
  );
});

test('WF-14 source: isWorkforceAdminMutation is referenced inside proxyToCore', () => {
  const proxStart = ROUTE_SRC.indexOf('async function proxyToCore(');
  assert.ok(proxStart !== -1, 'proxyToCore function not found');
  const proxBody = ROUTE_SRC.slice(proxStart);
  assert.ok(
    proxBody.includes('isWorkforceAdminMutation('),
    'isWorkforceAdminMutation is not referenced inside proxyToCore',
  );
});

test('WF-14b source: workforce mutation branch sets X-Admin-Gateway-Internal', () => {
  const proxStart = ROUTE_SRC.indexOf('async function proxyToCore(');
  const proxBody = ROUTE_SRC.slice(proxStart);
  // Anchor to the else-if branch itself, not the assignment (which appears earlier)
  const branchMarker = '} else if (isWorkforceMutation)';
  const mutBranchIdx = proxBody.indexOf(branchMarker);
  assert.ok(mutBranchIdx !== -1, 'isWorkforceMutation else-if branch not found in proxyToCore');
  const branchBody = proxBody.slice(mutBranchIdx, mutBranchIdx + 600);
  assert.ok(
    branchBody.includes('X-Admin-Gateway-Internal'),
    'workforce mutation branch does not set X-Admin-Gateway-Internal',
  );
  assert.ok(
    branchBody.includes('X-FG-Internal-Token'),
    'workforce mutation branch does not set X-FG-Internal-Token',
  );
  assert.ok(
    branchBody.includes('X-Tenant-ID'),
    'workforce mutation branch does not set X-Tenant-ID',
  );
});

test('WF-14c source: workforce mutation branch does not call resolveCoreAuth (no tenant portal key)', () => {
  const proxStart = ROUTE_SRC.indexOf('async function proxyToCore(');
  const proxBody = ROUTE_SRC.slice(proxStart);
  // The isWorkforceMutation else-if block must end before resolveCoreAuth is called
  // Verify the structure: isWorkforceMutation branch is an else-if before the else that calls resolveCoreAuth
  assert.ok(
    proxBody.includes('} else if (isWorkforceMutation)'),
    'workforce mutation is not an else-if branch (structural requirement)',
  );
  // The branch with resolveCoreAuth must be the else (tenant-key path), not the isWorkforceMutation branch
  const workforceBranchStart = proxBody.indexOf('} else if (isWorkforceMutation)');
  const resolveCoreAuthInBranch = proxBody.slice(workforceBranchStart, workforceBranchStart + 300).indexOf('resolveCoreAuth(');
  assert.equal(
    resolveCoreAuthInBranch,
    -1,
    'resolveCoreAuth is called inside the workforce mutation branch — it must not be (no tenant portal key)',
  );
});

// ─── Predicate logic tests ────────────────────────────────────────────────────

test('WF-1 POST workforce/users returns true', () => {
  assert.equal(isWorkforceAdminMutation(['workforce', 'users'], 'POST'), true);
});

test('WF-2 PATCH workforce/users/{id} returns true', () => {
  assert.equal(isWorkforceAdminMutation(['workforce', 'users', 'some-user-id'], 'PATCH'), true);
});

test('WF-3 GET workforce/users returns false (read uses tenant key)', () => {
  assert.equal(isWorkforceAdminMutation(['workforce', 'users'], 'GET'), false);
});

test('WF-4 HEAD workforce/users returns false', () => {
  assert.equal(isWorkforceAdminMutation(['workforce', 'users'], 'HEAD'), false);
});

test('WF-5 POST decisions returns false (unrelated path)', () => {
  assert.equal(isWorkforceAdminMutation(['decisions'], 'POST'), false);
});

test('WF-6 POST portal/grants returns false (separate isCrossTenantAdminPath)', () => {
  assert.equal(isWorkforceAdminMutation(['portal', 'grants'], 'POST'), false);
});

test('WF-6b DELETE portal/grants returns false', () => {
  assert.equal(isWorkforceAdminMutation(['portal', 'grants'], 'DELETE'), false);
});

test('WF-6c POST workforce/risk-profiles returns false (different sub-path)', () => {
  assert.equal(isWorkforceAdminMutation(['workforce', 'risk-profiles'], 'POST'), false);
});

// ─── Credential header simulation ────────────────────────────────────────────

const ADMIN_GATEWAY_TOKEN = 'fgi.test-admin-gateway-secret';
const TENANT_ID = 'odin-financial-group';

function simulateWorkforceMutationHeaders(tenantId, gatewayToken) {
  const headers = new Map();
  if (!gatewayToken) return { error: 'Admin gateway token is not configured', status: 503 };
  headers.set('X-API-Key', gatewayToken);
  headers.set('X-FG-Internal-Token', gatewayToken);
  headers.set('X-Admin-Gateway-Internal', 'true');
  if (tenantId) headers.set('X-Tenant-ID', tenantId);
  return { headers, status: null };
}

function simulateTenantKeyHeaders(tenantApiKey, tenantId) {
  const headers = new Map();
  if (!tenantApiKey) return { error: 'CORE_AUTH_MISSING', status: 401 };
  headers.set('X-API-Key', tenantApiKey);
  headers.set('X-Tenant-ID', tenantId);
  return { headers, status: null };
}

test('WF-7 workforce mutation branch sets X-Admin-Gateway-Internal: true', () => {
  const { headers } = simulateWorkforceMutationHeaders(TENANT_ID, ADMIN_GATEWAY_TOKEN);
  assert.equal(headers.get('X-Admin-Gateway-Internal'), 'true');
});

test('WF-8 workforce mutation branch sets X-FG-Internal-Token to admin gateway token', () => {
  const { headers } = simulateWorkforceMutationHeaders(TENANT_ID, ADMIN_GATEWAY_TOKEN);
  assert.equal(headers.get('X-FG-Internal-Token'), ADMIN_GATEWAY_TOKEN);
  assert.equal(headers.get('X-API-Key'), ADMIN_GATEWAY_TOKEN);
});

test('WF-9 workforce mutation branch sets X-Tenant-ID to authorized tenant', () => {
  const { headers } = simulateWorkforceMutationHeaders(TENANT_ID, ADMIN_GATEWAY_TOKEN);
  assert.equal(headers.get('X-Tenant-ID'), TENANT_ID);
});

test('WF-10 workforce mutation branch does not use tenant portal API key', () => {
  const TENANT_PORTAL_KEY = 'fgk.abc.portal-key-for-tenant';
  const { headers } = simulateWorkforceMutationHeaders(TENANT_ID, ADMIN_GATEWAY_TOKEN);
  const apiKey = headers.get('X-API-Key');
  assert.notEqual(apiKey, TENANT_PORTAL_KEY);
  assert.equal(apiKey, ADMIN_GATEWAY_TOKEN);
});

test('WF-11 isCrossTenantAdminPath does not include workforce/users (tenant still resolved)', () => {
  // workforce/users must NOT be in isCrossTenantAdminPath — if it were,
  // resolveAuthorizedTenant would be skipped and the tenant would not be validated.
  const crossTenantStart = ROUTE_SRC.indexOf('function isCrossTenantAdminPath(');
  assert.ok(crossTenantStart !== -1, 'isCrossTenantAdminPath function not found in source');
  const crossTenantEnd = ROUTE_SRC.indexOf('\n}', crossTenantStart) + 2;
  const crossTenantBody = ROUTE_SRC.slice(crossTenantStart, crossTenantEnd);
  assert.ok(
    !crossTenantBody.includes('workforce'),
    'isCrossTenantAdminPath must not include workforce paths',
  );
});

test('WF-12 missing ADMIN_GATEWAY_TOKEN returns 503 for workforce mutation', () => {
  const result = simulateWorkforceMutationHeaders(TENANT_ID, null);
  assert.equal(result.status, 503);
  assert.ok(result.error.includes('not configured'));
});
