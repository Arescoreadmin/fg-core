'use strict';

/**
 * tenant-resolution.test.js
 *
 * Tests for authorized tenant resolution and workforce route reclassification.
 *
 * Static source assertions verify structural invariants in route.ts.
 * Unit tests exercise an inline mirror of resolveAuthorizedTenant to verify
 * the authorization matrix without a build step or live session.
 *
 * Test IDs:
 *   1. authorized_internal_operator_resolves_any_tenant
 *   2. authorized_client_resolves_own_tenant
 *   3. unauthorized_client_cannot_access_other_tenant
 *   4. missing_tenant_id_uses_operator_fallback
 *   5. malformed_tenant_id_returns_422
 *   6. empty_tenant_id_returns_422
 *   7. workforce_route_uses_tenant_scoped_resolution
 *   8. cross_tenant_admin_routes_continue_using_gateway_authority
 *   9. tenant_resolution_runs_before_proxy_call
 *  10. rate_limit_key_uses_resolved_tenant_not_env_constant
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ─── Inline mirror of resolveAuthorizedTenant ─────────────────────────────────
// Mirrors the logic in app/api/core/[...path]/route.ts so unit tests don't
// require a build step. Must be kept in sync with the TypeScript source.

const TENANT_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;

function fakeJsonError(message, status) {
  return { __error: true, status, message };
}

function resolveAuthorizedTenant(rawTenantIdParam, claims, requestId = 'test') {
  // rawTenantIdParam: value from url.searchParams.get('tenant_id') — null if absent
  if (rawTenantIdParam === null) {
    return { tenantId: 'operator-default' };
  }

  const tenantId = rawTenantIdParam.trim();
  if (!TENANT_ID_RE.test(tenantId)) {
    return fakeJsonError(
      'tenant_id is malformed — must be 1–128 characters: letters, numbers, hyphens, underscores',
      422,
    );
  }

  if (claims.experienceClass === 'internal_console' || claims.experienceClass === 'legacy_internal') {
    return { tenantId };
  }

  if (claims.experienceClass === 'console_enabled_client' && claims.tenantId === tenantId) {
    return { tenantId };
  }

  return fakeJsonError('Forbidden: not authorized to act on behalf of this tenant', 403);
}

function internalClaims() {
  return { experienceClass: 'internal_console', tenantId: null };
}

function legacyClaims() {
  return { experienceClass: 'legacy_internal', tenantId: null };
}

function clientClaims(tenantId) {
  return { experienceClass: 'console_enabled_client', tenantId };
}

function portalOnlyClaims() {
  return { experienceClass: 'portal_only', tenantId: 'acme' };
}

// ─── Test 1: authorized_internal_operator_resolves_any_tenant ─────────────────

test('authorized_internal_operator_resolves_any_tenant', () => {
  const result = resolveAuthorizedTenant('acme-corp', internalClaims());
  assert.ok(!result.__error, 'should not be an error');
  assert.equal(result.tenantId, 'acme-corp');

  // Also works for a different tenant
  const result2 = resolveAuthorizedTenant('other-client', internalClaims());
  assert.equal(result2.tenantId, 'other-client');

  // legacy_internal also gets full access
  const result3 = resolveAuthorizedTenant('any-tenant', legacyClaims());
  assert.equal(result3.tenantId, 'any-tenant');
});

// ─── Test 2: authorized_client_resolves_own_tenant ───────────────────────────

test('authorized_client_resolves_own_tenant', () => {
  const result = resolveAuthorizedTenant('acme-corp', clientClaims('acme-corp'));
  assert.ok(!result.__error, 'client accessing own tenant must succeed');
  assert.equal(result.tenantId, 'acme-corp');
});

// ─── Test 3: unauthorized_client_cannot_access_other_tenant ──────────────────

test('unauthorized_client_cannot_access_other_tenant', () => {
  // Client's session has tenantId = 'acme-corp'; requests 'rival-corp'
  const result = resolveAuthorizedTenant('rival-corp', clientClaims('acme-corp'));
  assert.ok(result.__error, 'cross-tenant client access must be denied');
  assert.equal(result.status, 403);

  // portal_only role must also be denied
  const result2 = resolveAuthorizedTenant('acme', portalOnlyClaims());
  assert.ok(result2.__error);
  assert.equal(result2.status, 403);
});

// ─── Test 4: missing_tenant_id_uses_operator_fallback ────────────────────────

test('missing_tenant_id_uses_operator_fallback', () => {
  // null means the URL param was absent
  const result = resolveAuthorizedTenant(null, internalClaims());
  assert.ok(!result.__error, 'missing tenant_id must not error');
  assert.equal(result.tenantId, 'operator-default');

  // Same behavior for client users — no param means use default
  const result2 = resolveAuthorizedTenant(null, clientClaims('acme-corp'));
  assert.ok(!result2.__error);
  assert.equal(result2.tenantId, 'operator-default');
});

// ─── Test 5: malformed_tenant_id_returns_422 ─────────────────────────────────

test('malformed_tenant_id_returns_422', () => {
  const badIds = [
    'has spaces',
    'has!bang',
    'has@at',
    'a'.repeat(129),  // 129 chars — too long
    'has/slash',
    'has.dot',
  ];
  for (const bad of badIds) {
    const result = resolveAuthorizedTenant(bad, internalClaims());
    assert.ok(result.__error, `"${bad}" must be rejected`);
    assert.equal(result.status, 422, `"${bad}" must return 422`);
  }
});

// ─── Test 6: empty_tenant_id_returns_422 ─────────────────────────────────────

test('empty_tenant_id_returns_422', () => {
  // Empty string (param present but empty) must be rejected — not treated as fallback
  const result = resolveAuthorizedTenant('', internalClaims());
  assert.ok(result.__error);
  assert.equal(result.status, 422);

  // Whitespace-only is trimmed to empty → also rejected
  const result2 = resolveAuthorizedTenant('   ', internalClaims());
  assert.ok(result2.__error);
  assert.equal(result2.status, 422);
});

// ─── Test 7: workforce_route_uses_tenant_scoped_resolution ───────────────────

test('workforce_route_uses_tenant_scoped_resolution', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');

  // workforce/users must NOT appear in isCrossTenantAdminPath
  const adminFn = routeSrc.match(/function isCrossTenantAdminPath[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(adminFn, 'isCrossTenantAdminPath must exist');
  assert.doesNotMatch(adminFn, /workforce/, 'workforce/users must not be in isCrossTenantAdminPath');

  // workforce/users must remain in PROXY_RULES (still proxied, just not as admin)
  assert.match(routeSrc, /prefix: 'workforce\/users'/, 'workforce/users must stay in PROXY_RULES');
});

// ─── Test 8: cross_tenant_admin_routes_continue_using_gateway_authority ──────

test('cross_tenant_admin_routes_continue_using_gateway_authority', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');

  const adminFn = routeSrc.match(/function isCrossTenantAdminPath[\s\S]*?\n\}/)?.[0] ?? '';

  // These routes must still use gateway authority
  assert.match(adminFn, /admin\/identity\/tenants/);
  assert.match(adminFn, /admin\/identity\/invitations/);
  assert.match(adminFn, /portal\/grants/);

  // The proxy branch for admin paths must set X-Admin-Gateway-Internal
  assert.match(routeSrc, /X-Admin-Gateway-Internal/);
  assert.match(routeSrc, /ADMIN_GATEWAY_TOKEN/);
});

// ─── Test 9: tenant_resolution_runs_before_proxy_call ────────────────────────

test('tenant_resolution_runs_before_proxy_call', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');

  // resolveAuthorizedTenant must be called before proxyToCore in handle()
  const handleFn = routeSrc.match(/async function handle[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(handleFn, 'handle() must exist');

  const resolvePos = handleFn.indexOf('resolveAuthorizedTenant');
  const proxyPos = handleFn.indexOf('proxyToCore');
  assert.ok(resolvePos > -1, 'resolveAuthorizedTenant must be called in handle()');
  assert.ok(proxyPos > -1, 'proxyToCore must be called in handle()');
  assert.ok(resolvePos < proxyPos, 'resolveAuthorizedTenant must precede proxyToCore');

  // Error path must short-circuit
  assert.match(handleFn, /instanceof NextResponse/);
});

// ─── Test 10: rate_limit_key_uses_resolved_tenant_not_env_constant ───────────

test('rate_limit_key_uses_resolved_tenant_not_env_constant', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');

  // buildRateLimitKey must accept tenantId as a parameter (not read CORE_TENANT_ID internally)
  const keyFn = routeSrc.match(/function buildRateLimitKey[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(keyFn, 'buildRateLimitKey must exist');

  // Must take tenantId as a param — not call resolveTenant or read process.env.CORE_TENANT_ID
  assert.doesNotMatch(keyFn, /CORE_TENANT_ID/, 'must not read env constant inside key builder');
  assert.doesNotMatch(keyFn, /resolveTenant/, 'must not call resolveTenant inside key builder');

  // tenantId param must appear in the key string
  assert.match(keyFn, /tenantId/);
});
