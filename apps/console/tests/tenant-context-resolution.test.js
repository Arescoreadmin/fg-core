'use strict';

/**
 * tenant-context-resolution.test.js
 *
 * AUTH-TENANT-CONTEXT-001 — Behavioral test suite.
 *
 * Verifies authorization boundary behavior for the tenant-context fix:
 * - consoleAccess.js functions behave correctly with/without tenantId
 * - resolveTenantRequestAuthority enforces session-binding for clients
 * - static invariants in auth.config.ts and tenantResolution.ts are present
 * - expected structural boundaries hold for all required scenarios
 *
 * Test IDs:
 *   TC-001  valid_authenticated_client_with_active_bound_membership
 *   TC-002  missing_principal_id_leaves_tenant_null
 *   TC-003  missing_membership_session_is_unsupported
 *   TC-004  inactive_membership_session_is_unsupported
 *   TC-005  unbound_identity_session_is_unsupported
 *   TC-006  revoked_principal_session_is_unsupported
 *   TC-007  multiple_ambiguous_memberships_resolution_null
 *   TC-008  forged_tenant_id_from_browser_is_rejected
 *   TC-009  cross_tenant_request_is_denied
 *   TC-010  stale_auth0_role_projection_produces_unsupported
 *   TC-011  internal_operator_regression_no_tenant_required
 *   TC-012  unsupported_role_denial
 *   TC-013  session_renewal_preserves_tenant_id
 *   TC-014  client_executive_cannot_access_internal_only_route
 *   TC-015  client_executive_can_access_client_console_route
 *   TC-016  platform_admin_apis_denied_to_client
 *   TC-017  auth_config_stores_principal_id_claim
 *   TC-018  tenant_resolution_module_invariants
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  resolveConsolePrincipal,
  resolveTenantRequestAuthority,
  canAccessConsoleRoute,
  canAccessCoreApiPath,
} = require('../lib/consoleAccess.js');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ── Session builders ──────────────────────────────────────────────────────────

function clientSession(roles, tenantId) {
  return { user: { roles, tenantId, experienceClass: 'console_enabled_client' } };
}

function internalSession() {
  return { user: { roles: ['Administrator'], tenantId: null, experienceClass: 'internal_console' } };
}

function rawSession(roles, tenantId) {
  // Simulate token-level session (middleware reads these fields)
  return { token: { roles, tenantId } };
}

// ── TC-001: Valid client with active bound membership ─────────────────────────

test('TC-001 valid_authenticated_client_with_active_bound_membership', () => {
  const session = clientSession(['client_executive'], 'acme-corp');
  const principal = resolveConsolePrincipal(session);

  assert.equal(principal.experienceClass, 'console_enabled_client');
  assert.deepEqual(principal.roles, ['client_executive']);
  assert.equal(principal.tenantId, 'acme-corp');
  assert.equal(principal.isAuthenticated, true);
});

// ── TC-002: Missing principalId leaves tenantId null ─────────────────────────

test('TC-002 missing_principal_id_leaves_tenant_null', () => {
  // Simulate a session where principal_id was not in the JWT (e.g. projection not yet run)
  const session = { user: { roles: ['client_executive'], tenantId: null } };
  const principal = resolveConsolePrincipal(session);

  // No roles projection yet → unsupported (Auth0 Action returned early, no roles claim)
  // If roles ARE present but tenantId is null, session has console_enabled_client class
  // but tenantId is null — this should resolve to console_enabled_client with null tenantId.
  // The BFF then enforces TENANT_AUTHORITY_MISSING.
  assert.equal(principal.isAuthenticated, true);

  // tenant authority must be missing for BFF calls
  const authority = resolveTenantRequestAuthority(session, {});
  assert.equal(authority.ok, false);
  assert.equal(authority.code, 'TENANT_AUTHORITY_MISSING');
});

// ── TC-003: Missing membership → unsupported session ─────────────────────────

test('TC-003 missing_membership_session_is_unsupported', () => {
  // No roles at all (projection worker has not run; Auth0 Action returns early)
  const session = { user: { roles: [], tenantId: null } };
  const principal = resolveConsolePrincipal(session);
  assert.equal(principal.experienceClass, 'unsupported');
});

// ── TC-004: Inactive membership produces no roles ─────────────────────────────

test('TC-004_inactive_membership_roles_absent_produces_unsupported', () => {
  // Simulates the case where active=false in tenant_users but old session still
  // has roles cached. On re-login, projection worker would not re-project for
  // inactive membership — roles in new JWT would be absent.
  const session = { user: { roles: [], tenantId: 'acme-corp' } };
  const principal = resolveConsolePrincipal(session);
  assert.equal(principal.experienceClass, 'unsupported');
});

// ── TC-005: Unbound identity → no roles projected ────────────────────────────

test('TC-005_unbound_identity_no_roles_is_unsupported', () => {
  // identity_binding_status != 'bound' — projection worker won't run → no roles
  const session = { user: { roles: [] } };
  const principal = resolveConsolePrincipal(session);
  assert.equal(principal.experienceClass, 'unsupported');
});

// ── TC-006: Revoked principal → unsupported (no active membership) ────────────

test('TC-006_revoked_principal_produces_unsupported', () => {
  // principal.lifecycle_state = 'deactivated' → endpoint returns 404
  // On next login, roles are absent because projection won't re-project
  const session = { user: { roles: [] } };
  const principal = resolveConsolePrincipal(session);
  assert.equal(principal.experienceClass, 'unsupported');
  assert.equal(principal.isAuthenticated, true);
});

// ── TC-007: Multiple ambiguous memberships → null resolution ──────────────────

test('TC-007_multiple_ambiguous_memberships_leaves_tenant_null', () => {
  // API returns 409 → resolvePrincipalTenant returns null → tenantId stays null
  // Session still has roles from Auth0 but no tenantId → BFF enforces TENANT_AUTHORITY_MISSING
  const session = clientSession(['client_executive'], null);
  const authority = resolveTenantRequestAuthority(session, {});
  assert.equal(authority.ok, false);
  assert.equal(authority.code, 'TENANT_AUTHORITY_MISSING');
});

// ── TC-008: Forged tenant_id from browser is rejected ────────────────────────

test('TC-008_forged_tenant_id_from_browser_is_rejected', () => {
  // Session has tenantId = 'acme-corp', browser sends tenant_id = 'evil-corp'
  const session = clientSession(['client_executive'], 'acme-corp');
  const authority = resolveTenantRequestAuthority(session, {
    queryTenantIds: ['evil-corp'],
  });
  assert.equal(authority.ok, false);
  assert.equal(authority.code, 'TENANT_AUTHORITY_DENIED');
  assert.equal(authority.status, 403);
});

// ── TC-009: Cross-tenant request is denied ────────────────────────────────────

test('TC-009_cross_tenant_request_is_denied', () => {
  // Client bound to 'acme-corp' cannot act on 'rival-corp'
  const session = clientSession(['client_executive'], 'acme-corp');

  const withRivalTenant = resolveTenantRequestAuthority(session, {
    queryTenantIds: ['rival-corp'],
  });
  assert.equal(withRivalTenant.ok, false);
  assert.equal(withRivalTenant.status, 403);

  // Own tenant must succeed
  const ownTenant = resolveTenantRequestAuthority(session, {
    queryTenantIds: ['acme-corp'],
  });
  assert.equal(ownTenant.ok, true);
  assert.equal(ownTenant.tenantId, 'acme-corp');
});

// ── TC-010: Stale Auth0 role projection → unsupported ────────────────────────

test('TC-010_stale_auth0_role_projection_produces_unsupported', () => {
  // app_metadata.roles absent or null → Auth0 Action returns early → no role claims
  // These cases all land on experienceClass = 'unsupported'.
  const unsupportedSessions = [
    { user: {} },            // no roles field
    { user: { roles: null } }, // explicit null
  ];
  for (const session of unsupportedSessions) {
    const principal = resolveConsolePrincipal(session);
    assert.equal(
      principal.experienceClass,
      'unsupported',
      `expected unsupported for ${JSON.stringify(session)}`,
    );
  }

  // consoleAccess.js::toRoleList() handles string roles via CSV split for
  // legacy compat — a string 'client_executive' still resolves the experience
  // class correctly rather than treating it as a stale/missing projection.
  const stringRoleSession = { user: { roles: 'client_executive' } };
  const principal = resolveConsolePrincipal(stringRoleSession);
  assert.equal(principal.experienceClass, 'console_enabled_client');
});

// ── TC-011: Internal operator regression ──────────────────────────────────────

test('TC-011_internal_operator_regression', () => {
  // Internal operators must continue to work without tenantId in their JWT
  const session = internalSession();
  const principal = resolveConsolePrincipal(session);
  assert.equal(principal.experienceClass, 'internal_console');
  assert.equal(principal.tenantId, null); // internal operators have no fixed tenant

  // Can access operator-only route
  assert.equal(canAccessConsoleRoute('/dashboard', session), true);
  assert.equal(canAccessConsoleRoute('/dashboard/control-tower', session), true);
});

// ── TC-012: Unsupported role denial ───────────────────────────────────────────

test('TC-012_unsupported_role_denial', () => {
  // Roles that exist in Auth0 but are not in RECOGNIZED_ROLES
  const session = { user: { roles: ['portal_manager', 'unknown_custom_role'] } };
  const principal = resolveConsolePrincipal(session);
  // portal_manager is not a recognized role; unknown_custom_role neither
  // Both are non-empty unrecognized → unsupported (fail-closed)
  assert.equal(principal.experienceClass, 'unsupported');
});

// ── TC-013: Session renewal preserves resolved tenant_id ─────────────────────

test('TC-013_session_renewal_preserves_tenant_id', () => {
  // After auth.ts resolves tenantId and stores it in the JWT, subsequent
  // reads (including token refresh) read it from token.tenantId.
  // Simulate: token already has tenantId set (as stored after first resolution)
  const session = rawSession(['client_executive'], 'acme-corp');
  const principal = resolveConsolePrincipal(session);
  assert.equal(principal.tenantId, 'acme-corp');
  assert.equal(principal.experienceClass, 'console_enabled_client');
});

// ── TC-014: client_executive cannot access /dashboard ─────────────────────────

test('TC-014_client_executive_cannot_access_internal_only_route', () => {
  const session = clientSession(['client_executive'], 'acme-corp');
  assert.equal(canAccessConsoleRoute('/dashboard', session), false);
  assert.equal(canAccessConsoleRoute('/dashboard/control-tower', session), false);
  assert.equal(canAccessConsoleRoute('/dashboard/providers', session), false);
  assert.equal(canAccessConsoleRoute('/workspace', session), false);
});

// ── TC-015: client_executive can access /dashboard/executive ──────────────────

test('TC-015_client_executive_can_access_client_console_route', () => {
  const session = clientSession(['client_executive'], 'acme-corp');
  assert.equal(canAccessConsoleRoute('/dashboard/executive', session), true);
  assert.equal(canAccessConsoleRoute('/dashboard/readiness', session), true);
  assert.equal(canAccessConsoleRoute('/dashboard/decisions', session), true);
});

// ── TC-016: Platform-admin APIs denied to client ──────────────────────────────

test('TC-016_platform_admin_apis_denied_to_client', () => {
  const session = clientSession(['client_executive'], 'acme-corp');
  assert.equal(canAccessCoreApiPath(['admin', 'connectors'], 'GET', session), false);
  assert.equal(canAccessCoreApiPath(['admin', 'identity', 'tenants'], 'GET', session), false);
  assert.equal(canAccessCoreApiPath(['control-tower', 'snapshot'], 'GET', session), false);
  assert.equal(canAccessCoreApiPath(['keys'], 'GET', session), false);
});

// ── TC-017: auth.config.ts stores principal_id claim ─────────────────────────

test('TC-017_auth_config_stores_principal_id_claim', () => {
  const src = read('auth.config.ts');

  // AUTH-TENANT-CONTEXT-001 header comment must be present
  assert.match(src, /AUTH-TENANT-CONTEXT-001/);

  // Must read from the correct Auth0 claim namespace
  assert.match(src, /https:\/\/frostgate\.ai\/principal_id/);

  // Must validate UUID v4 format before storing
  assert.match(src, /_UUID_V4_RE/);

  // Must store as token.principalId
  assert.match(src, /token\.principalId/);

  // Must not make any network calls (Edge-compatible)
  assert.doesNotMatch(src, /fetch\s*\(/);
  assert.doesNotMatch(src, /await\s+fetch/);
});

// ── TC-018: tenantResolution.ts module invariants ─────────────────────────────

test('TC-018_tenant_resolution_module_invariants', () => {
  const src = read('lib/tenantResolution.ts');

  // Must call the Core API endpoint, not admin_gateway directly
  assert.match(src, /\/admin\/identity\/principal-tenant\//);
  assert.match(src, /CORE_API_URL/);

  // Must send X-FG-Internal-Token (internal service credential)
  assert.match(src, /X-FG-Internal-Token/);

  // Must validate UUID v4 before making any request
  assert.match(src, /_UUID_V4_RE/);

  // Must return null on 404 (no binding found)
  assert.match(src, /status === 404/);

  // Must return null on 409 (ambiguous — multiple memberships)
  assert.match(src, /status === 409/);

  // Must have a timeout to protect the JWT callback latency
  assert.match(src, /AbortSignal\.timeout/);

  // Must fail open (return null) on any exception
  assert.match(src, /return null/);

  // Must never log the principalId (no log statement with principalId as param)
  assert.doesNotMatch(src, /console\.log.*principalId/);
  assert.doesNotMatch(src, /console\.error.*principalId/);
});
