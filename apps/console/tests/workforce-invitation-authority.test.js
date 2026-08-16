'use strict';
// @version 2

/**
 * Tenant-admin Core authority regression tests.
 *
 * Workforce users, Portal Grants, Engagement lookup, and Identity Governance
 * must share one Console BFF -> Core authority path: admin gateway identity plus
 * explicit, session-authorized X-Tenant-ID. No tab may construct its own auth
 * headers or skip tenant resolution in the shared proxy.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROUTE_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'app/api/core/[...path]/route.ts'),
  'utf8',
);
const IDENTITY_API_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'lib/identityApi.ts'),
  'utf8',
);

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

function isTenantAdminCorePath(pathParts) {
  const joined = pathParts.join('/');
  return (
    joined.startsWith('workforce/users') ||
    joined === 'portal/grants' ||
    joined.startsWith('portal/grants/') ||
    joined.startsWith('admin/identity/tenants/') ||
    joined === 'admin/identity/invitations' ||
    joined.startsWith('admin/identity/invitations/')
  );
}

test('tenant-admin Core helper is the only special auth predicate', () => {
  assert.match(ROUTE_SRC, /function isTenantAdminCorePath\(/);
  assert.doesNotMatch(ROUTE_SRC, /function isCrossTenantAdminPath\(/);
  assert.doesNotMatch(ROUTE_SRC, /function isWorkforceAdminPath\(/);
});

test('tenant-admin helper covers every affected Console surface', () => {
  assert.equal(isTenantAdminCorePath(['workforce', 'users']), true, 'Console Users list/invite');
  assert.equal(isTenantAdminCorePath(['workforce', 'users', 'user-1']), true, 'Console User update');
  assert.equal(isTenantAdminCorePath(['portal', 'grants']), true, 'Portal Grants list/create');
  assert.equal(isTenantAdminCorePath(['portal', 'grants', 'grant-1']), true, 'Portal Grant revoke');
  assert.equal(isTenantAdminCorePath(['admin', 'identity', 'tenants', 'odin-financial-group', 'engagements']), true, 'Portal engagement lookup');
  assert.equal(isTenantAdminCorePath(['admin', 'identity', 'tenants', 'odin-financial-group', 'governance-actions']), true, 'Identity Governance tenant operation');
  assert.equal(isTenantAdminCorePath(['admin', 'identity', 'invitations', 'inv-1', 'revoke']), true, 'Identity invitation operation');
  assert.equal(isTenantAdminCorePath(['decisions']), false, 'unrelated tenant key path');
});

test('tenant-admin helper source includes all protected prefixes', () => {
  const helper = extractFunction(ROUTE_SRC, 'isTenantAdminCorePath');
  for (const expected of [
    'workforce/users',
    'portal/grants',
    'admin/identity/tenants',
    'admin/identity/invitations',
  ]) {
    assert.match(helper, new RegExp(expected.replaceAll('/', '\\/')));
  }
});

test('workforce dashboard internal fallback is scoped to workforce user routes', () => {
  const helper = extractFunction(ROUTE_SRC, 'isOperatorDefaultTenantAdminCorePath');
  assert.match(helper, /workforce\/users/);
  assert.doesNotMatch(helper, /portal\/grants/);
  assert.doesNotMatch(helper, /admin\/identity/);

  const resolverStart = ROUTE_SRC.indexOf('function resolveAuthorizedTenant(');
  const resolverEnd = ROUTE_SRC.indexOf('const tenantId = raw.trim();', resolverStart);
  const rawNullBranch = ROUTE_SRC.slice(resolverStart, resolverEnd);
  assert.match(rawNullBranch, /isOperatorDefaultTenantAdminCorePath\(path\)/);
  assert.match(rawNullBranch, /claims\.experienceClass === 'internal_console'/);
  assert.doesNotMatch(rawNullBranch, /claims\.experienceClass === 'legacy_internal'/);
  assert.match(rawNullBranch, /return resolveConfiguredOperatorTenant\(requestId\)/);
  assert.ok(
    rawNullBranch.indexOf('return resolveConfiguredOperatorTenant(requestId)') <
      rawNullBranch.indexOf("return jsonError('tenant_id is required for tenant-admin Core routes'"),
  );
});

test('tenant resolution runs before every tenant-admin proxy call', () => {
  const handleStart = ROUTE_SRC.indexOf('async function handle');
  const handleEnd = ROUTE_SRC.indexOf('\nexport async function', handleStart);
  const handleBody = ROUTE_SRC.slice(handleStart, handleEnd);

  assert.ok(handleBody.includes('resolveAuthorizedTenant(request, path, session, requestId)'));
  assert.ok(handleBody.indexOf('resolveAuthorizedTenant(request, path, session, requestId)') < handleBody.indexOf('proxyToCore(request, path, requestId, tenantId)'));
  assert.doesNotMatch(handleBody, /isAdminPath/);
  assert.doesNotMatch(handleBody, /return proxyToCore\(request, path, requestId, ''\)/);
});

test('tenant-admin branch uses admin gateway authority with explicit tenant binding', () => {
  const proxyStart = ROUTE_SRC.indexOf('async function proxyToCore');
  const proxyEnd = ROUTE_SRC.indexOf('\nasync function getAlignmentArtifact', proxyStart);
  const proxyBody = ROUTE_SRC.slice(proxyStart, proxyEnd);
  const branchStart = proxyBody.indexOf('if (isTenantAdminPath)');
  const elseStart = proxyBody.indexOf('} else {', branchStart);
  const branch = proxyBody.slice(branchStart, elseStart);

  assert.match(branch, /ADMIN_GATEWAY_TOKEN/);
  assert.match(branch, /headers\.set\('X-API-Key', ADMIN_GATEWAY_TOKEN\)/);
  assert.match(branch, /headers\.set\('X-FG-Internal-Token', ADMIN_GATEWAY_TOKEN\)/);
  assert.match(branch, /headers\.set\('X-Admin-Gateway-Internal', 'true'\)/);
  assert.match(branch, /headers\.set\('X-Tenant-ID', tenantId\)/);
  assert.doesNotMatch(branch, /resolveCoreAuth\(/);
});

test('tenant-admin denials are normalized and diagnostically logged', () => {
  assert.match(ROUTE_SRC, /normalized_error=CORE_AUTH_REJECTED/);
  assert.match(ROUTE_SRC, /normalized_error=CORE_ACCESS_DENIED/);
  assert.match(ROUTE_SRC, /authority=\$\{isTenantAdminPath \? 'admin_gateway' : 'tenant_credential'\}/);
  assert.match(ROUTE_SRC, /surface=\$\{path\.join\('\/'\)\}/);
});

test('identity client appends tenant context, including invitation-id operations', () => {
  assert.match(IDENTITY_API_SRC, /function withTenantContext\(/);
  assert.match(IDENTITY_API_SRC, /function tenantPath\(/);
  assert.match(IDENTITY_API_SRC, /params\.set\('tenant_id', tenantId\)/);
  assert.match(IDENTITY_API_SRC, /revokeInvitation\(tenantId: string, invitationId: string\)/);
  assert.match(IDENTITY_API_SRC, /resendInvitation\(tenantId: string, invitationId: string\)/);
  assert.match(IDENTITY_API_SRC, /approveInvitation\(\n  tenantId: string,/);
  assert.match(IDENTITY_API_SRC, /rejectApproval\(\n  tenantId: string,/);
});
