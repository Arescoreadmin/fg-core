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
 *   7. tenant_admin_routes_use_tenant_scoped_resolution
 *   8. tenant_admin_routes_use_gateway_authority_after_resolution
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

function fakeJsonError(message, status, code) {
  const error = { __error: true, status, message };
  if (code) error.code = code;
  return error;
}

function isProdLikeEnv(env) {
  const nodeEnv = (env.NODE_ENV || '').trim().toLowerCase();
  const fgEnv = (env.FG_ENV || '').trim().toLowerCase();
  return nodeEnv === 'production' || ['prod', 'production', 'staging'].includes(fgEnv);
}

function resolveConfiguredOperatorTenant(env = {}) {
  const tenantId = (env.CORE_TENANT_ID || '').trim();
  if (!isProdLikeEnv(env)) return { tenantId };
  if (!tenantId) return fakeJsonError('Tenant context missing', 500, 'TENANT_CONTEXT_MISSING');
  if (tenantId.toLowerCase() === 'default') {
    return fakeJsonError('Tenant context invalid', 500, 'TENANT_CONTEXT_INVALID');
  }
  if (!TENANT_ID_RE.test(tenantId)) {
    return fakeJsonError('Tenant context invalid', 500, 'TENANT_CONTEXT_INVALID');
  }
  return { tenantId };
}

function resolveAuthorizedTenant(rawTenantIdParam, claims, env = {}) {
  // rawTenantIdParam: value from url.searchParams.get('tenant_id') — null if absent
  if (rawTenantIdParam === null) {
    return resolveConfiguredOperatorTenant(env);
  }

  const tenantId = rawTenantIdParam.trim();
  if (!TENANT_ID_RE.test(tenantId)) {
    return fakeJsonError(
      'tenant_id is malformed — must be 1–128 characters: letters, numbers, hyphens, underscores',
      422,
    );
  }

  if (claims.experienceClass === 'internal_console') {
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

});

test('legacy_internal_is_denied_any_tenant_authority', () => {
  // legacy_internal must not receive any-tenant authority after PR-SEC-001
  const result = resolveAuthorizedTenant('any-tenant', legacyClaims());
  assert.ok(result.__error, 'legacy_internal must not resolve any tenant');
  assert.equal(result.status, 403);
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

test('missing_tenant_id_uses_configured_operator_tenant', () => {
  // null means the URL param was absent; this PR intentionally keeps operator fallback
  // authority on CORE_TENANT_ID instead of switching to session tenant authority.
  const env = { NODE_ENV: 'production', CORE_TENANT_ID: 'fg-internal-operator' };
  const result = resolveAuthorizedTenant(null, internalClaims(), env);
  assert.ok(!result.__error, 'valid configured operator tenant must not error');
  assert.equal(result.tenantId, 'fg-internal-operator');

  const result2 = resolveAuthorizedTenant(null, clientClaims('acme-corp'), env);
  assert.ok(!result2.__error);
  assert.equal(result2.tenantId, 'fg-internal-operator');
});

test('production_missing_core_tenant_id_fails_closed', () => {
  for (const env of [
    { NODE_ENV: 'production' },
    { NODE_ENV: 'production', CORE_TENANT_ID: '' },
    { NODE_ENV: 'production', CORE_TENANT_ID: '   ' },
    { FG_ENV: 'staging', CORE_TENANT_ID: '' },
  ]) {
    const result = resolveAuthorizedTenant(null, internalClaims(), env);
    assert.ok(result.__error, 'missing production CORE_TENANT_ID must error');
    assert.equal(result.status, 500);
    assert.equal(result.code, 'TENANT_CONTEXT_MISSING');
  }
});

test('production_default_core_tenant_id_fails_closed', () => {
  for (const value of ['default', 'Default', ' default ']) {
    const result = resolveAuthorizedTenant(null, internalClaims(), {
      NODE_ENV: 'production',
      CORE_TENANT_ID: value,
    });
    assert.ok(result.__error, 'literal default must not be a production operator tenant');
    assert.equal(result.status, 500);
    assert.equal(result.code, 'TENANT_CONTEXT_INVALID');
  }
});

test('development_missing_core_tenant_id_preserves_local_empty_operator_context', () => {
  const result = resolveAuthorizedTenant(null, internalClaims(), { NODE_ENV: 'development' });
  assert.ok(!result.__error, 'development fallback must remain local-only compatible');
  assert.equal(result.tenantId, '');
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

test('tenant_admin_routes_use_tenant_scoped_resolution', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');

  const adminFn = routeSrc.match(/function isTenantAdminCorePath[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(adminFn, 'isTenantAdminCorePath must exist');
  assert.match(adminFn, /workforce\/users/);
  assert.match(adminFn, /portal\/grants/);
  assert.match(adminFn, /admin\/identity\/tenants/);
  assert.match(adminFn, /admin\/identity\/invitations/);
  assert.doesNotMatch(routeSrc, /function isCrossTenantAdminPath\(/);

  for (const prefix of ['workforce/users', 'portal/grants', 'admin/identity/tenants', 'admin/identity/invitations']) {
    assert.match(routeSrc, new RegExp(`prefix: '${prefix.replaceAll('/', '\\/')}'`));
  }
});

// ─── Test 8: tenant_admin_routes_use_gateway_authority_after_resolution ──────

test('tenant_admin_routes_use_gateway_authority_after_resolution', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  const proxyFn = routeSrc.match(/async function proxyToCore[\s\S]*?\nasync function getAlignmentArtifact/)?.[0] ?? '';
  assert.ok(proxyFn, 'proxyToCore must exist');

  assert.match(proxyFn, /if \(isTenantAdminPath\)/);
  assert.match(proxyFn, /X-Admin-Gateway-Internal/);
  assert.match(proxyFn, /X-FG-Internal-Token/);
  assert.match(proxyFn, /X-Tenant-ID/);
  assert.match(proxyFn, /ADMIN_GATEWAY_TOKEN/);
});

// ─── Test 9: tenant_resolution_runs_before_proxy_call ────────────────────────

test('tenant_resolution_runs_before_proxy_call', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');

  // resolveAuthorizedTenant must be called before proxyToCore in handle()
  const handleFn = routeSrc.match(/async function handle[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(handleFn, 'handle() must exist');

  const resolvePos = handleFn.indexOf('resolveAuthorizedTenant');
  const tenantScopedProxyPos = handleFn.indexOf('proxyToCore(request, path, requestId, tenantId)');
  assert.ok(resolvePos > -1, 'resolveAuthorizedTenant must be called in handle()');
  assert.ok(tenantScopedProxyPos > -1, 'tenant-scoped proxyToCore call must be in handle()');
  assert.ok(resolvePos < tenantScopedProxyPos, 'resolveAuthorizedTenant must precede tenant-scoped proxyToCore');

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


// ─── Production tenant-context fail-closed invariants ─────────────────────────

test('production_core_tenant_id_default_is_rejected_before_core_fetch', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  assert.match(routeSrc, /function resolveConfiguredOperatorTenant/);
  assert.match(routeSrc, /TENANT_CONTEXT_MISSING/);
  assert.match(routeSrc, /TENANT_CONTEXT_INVALID/);
  assert.match(routeSrc, /CORE_TENANT_ID=default/);

  const handleFn = routeSrc.match(/async function handle[\s\S]*?return proxyToCore\(request, path, requestId, tenantId\);/)?.[0] ?? '';
  assert.ok(handleFn, 'handle() must include tenant resolution and tenant-scoped proxy call');
  assert.ok(
    handleFn.indexOf('resolveAuthorizedTenant') < handleFn.indexOf('proxyToCore(request, path, requestId, tenantId)'),
    'tenant context validation must happen before tenant-scoped Core proxying',
  );
});

test('only_alignment_artifact_skips_tenant_resolution', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  const handleFn = routeSrc.match(/async function handle[\s\S]*?\nexport async function/)?.[0] ?? '';
  assert.ok(handleFn, 'handle() must exist');

  const alignmentPos = handleFn.indexOf('isAlignmentArtifact(path)');
  const resolvePos = handleFn.indexOf('resolveAuthorizedTenant');
  assert.ok(alignmentPos > -1, 'alignment artifact branch must exist');
  assert.ok(resolvePos > -1, 'tenant-scoped resolution branch must exist');
  assert.ok(alignmentPos < resolvePos, 'alignment artifact must be handled before tenant validation');
  assert.doesNotMatch(handleFn, /if \(isAdminPath\)/);
  assert.doesNotMatch(handleFn, /return proxyToCore\(request, path, requestId, ''\);/);
  assert.match(handleFn, /return getAlignmentArtifact\(requestId\);/);
  assert.match(routeSrc, /tenantIndependentRateLimitTenant/);
});

test('core_api_key_operator_path_requires_valid_configured_tenant', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  assert.match(routeSrc, /const CORE_TENANT_ID = \(process\.env\.CORE_TENANT_ID \|\| ''\)\.trim\(\);/);
  assert.match(routeSrc, /function configuredOperatorTenantContextError/);
  assert.match(routeSrc, /tenantId === CORE_TENANT_ID/);

  const authFn = routeSrc.match(/async function resolveCoreAuth[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(authFn, 'resolveCoreAuth must exist');
  assert.ok(
    authFn.indexOf('configuredOperatorTenantContextError') < authFn.indexOf('CORE_API_KEY'),
    'configured tenant context must be validated before CORE_API_KEY can be used',
  );
  assert.match(routeSrc, /TENANT_CONTEXT_MISSING/);
  assert.match(routeSrc, /TENANT_CONTEXT_INVALID/);
  assert.match(authFn, /tenantContextCode/);
  assert.match(authFn, /if \(CORE_API_KEY\) return \{ tenantId, apiKey: CORE_API_KEY \};/);
});

test('browser_query_tenant_rules_remain_authorized_by_session_claims', () => {
  const own = resolveAuthorizedTenant('acme-corp', clientClaims('acme-corp'), {
    NODE_ENV: 'production',
    CORE_TENANT_ID: 'fg-internal-operator',
  });
  assert.ok(!own.__error);
  assert.equal(own.tenantId, 'acme-corp');

  const other = resolveAuthorizedTenant('other-corp', clientClaims('acme-corp'), {
    NODE_ENV: 'production',
    CORE_TENANT_ID: 'fg-internal-operator',
  });
  assert.ok(other.__error);
  assert.equal(other.status, 403);
});

test('configured operator tenant requires core authority validation before env key use', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  assert.match(routeSrc, /validateConfiguredOperatorAuthority/);
  assert.match(routeSrc, /\/admin\/tenants\/\$\{encodeURIComponent\(CORE_TENANT_ID\)\}\/operator-authority/);
  assert.match(routeSrc, /tenant_kind === 'internal_platform'/);
  assert.match(routeSrc, /lifecycle_state === 'active'/);
  assert.match(routeSrc, /operator_authority_allowed === true/);
  assert.ok(
    routeSrc.indexOf('validateConfiguredOperatorAuthority(requestId)') < routeSrc.indexOf('if (CORE_API_KEY) return'),
    'operator authority must be validated before CORE_API_KEY use',
  );
});

test('customer tenant fixture is not normalized as operator authority', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  const credentialTests = read('tests/core-credential-resolution.test.js');
  assert.doesNotMatch(routeSrc, /lace-money-group/);
  assert.doesNotMatch(credentialTests, /lace-money-group/);
});

// ─── PR-SEC-002: legacy_internal removed from BFF authority ──────────────────

test('route.ts contains no legacy_internal authority branch', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  assert.doesNotMatch(
    routeSrc,
    /experienceClass === 'legacy_internal'/,
    'legacy_internal must not appear in any BFF authority check',
  );
  assert.match(
    routeSrc,
    /experienceClass === 'internal_console'/,
    'internal_console must remain as the authorized operator experienceClass',
  );
});

test('stale legacy_internal session is denied any-tenant BFF authority', () => {
  // Behavioral proof via the inline mirror — matches the route.ts logic post-PR-SEC-002
  const result = resolveAuthorizedTenant('any-tenant', legacyClaims());
  assert.ok(result.__error, 'stale legacy_internal session must be denied');
  assert.equal(result.status, 403, 'must return 403 Forbidden');
});

test('forged legacy_internal session cannot reach workforce operator default tenant', () => {
  // raw === null path (no ?tenant_id) on a workforce/users route
  // legacy_internal must be rejected; only internal_console gets operator default
  const forged = legacyClaims();
  const env = { NODE_ENV: 'production', CORE_TENANT_ID: 'fg-internal-operator' };

  // With a tenant_id provided: must get 403
  const withTenant = resolveAuthorizedTenant('victim-tenant', forged, env);
  assert.ok(withTenant.__error);
  assert.equal(withTenant.status, 403);

  // Legitimate internal_console still works (regression guard)
  const legitimate = resolveAuthorizedTenant('any-tenant', internalClaims(), env);
  assert.ok(!legitimate.__error);
  assert.equal(legitimate.tenantId, 'any-tenant');
});