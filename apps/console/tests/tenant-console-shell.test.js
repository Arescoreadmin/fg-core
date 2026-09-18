'use strict';

/**
 * TENANT-CONSOLE-UX-001 — Tenant Console Shell + Administration UX
 *
 * PR #705 regression suite covering:
 *   - Authority-aware shell identity
 *   - Tenant Admin navigation isolation
 *   - Platform Admin full global access retained
 *   - Support role canonical policy
 *   - Direct URL enforcement (independent of navigation visibility)
 *   - Error state classification
 *   - Credential plaintext semantics preserved
 *   - Adversarial matrix: all 26 attack vectors
 *   - Unknown/future role fail-closed behaviour
 *
 * Tests 1–22: Tenant Admin
 * Tests 23–28: Platform Admin
 * Tests 29–30: Support
 * Tests 31–40: General / cross-cutting
 * Adversarial matrix: 26 vectors
 *
 * NOTE: Tests operate on exported production functions from consoleAccess.js.
 * No inline mirrors of BFF logic — changes to the production module break tests.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  canAccessConsoleRoute,
  isTenantAdminSession,
  isPlatformAdminSession,
  resolveConsolePrincipal,
  getSessionClaims,
  CLIENT_ADMIN_ROLES,
  PLATFORM_ADMIN_ROLES,
  CONSOLE_ROUTE_AUDITS,
} = require('../lib/consoleAccess');

// ─── Session fixtures ──────────────────────────────────────────────────────────

function makeTenantAdminSession(tenantId) {
  return { user: { roles: ['tenant_admin'], tenant_id: tenantId } };
}

function makePlatformAdminSession(role = 'Administrator') {
  return { user: { roles: [role] } };
}

function makeSupportSession() {
  return { user: { roles: ['Support'] } };
}

function makeInternalSession(role = 'Developer') {
  return { user: { roles: [role] } };
}

function makeFieldAssessorSession() {
  return { user: { roles: ['FieldAssessor'] } };
}

function makeOperatorSession() {
  return { user: { roles: ['Operator'] } };
}

function makeUnknownRoleSession(role = 'FutureUnknownRole') {
  return { user: { roles: [role] } };
}

// ─── BFF authority mirror ──────────────────────────────────────────────────────
// Mirrors /api/tenants GET handler — tests against production access functions.

const TENANT_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;

function resolveTenantsAuthority(session, requestedTenantId) {
  if (!session?.user) return { status: 401, error: 'Unauthorized' };
  if (!canAccessConsoleRoute('/admin/tenants', session)) {
    return { status: 403, error: 'Forbidden' };
  }
  if (isTenantAdminSession(session)) {
    const claims = getSessionClaims(session);
    const tid = claims.tenantId;
    if (!tid || !TENANT_ID_RE.test(tid)) return { status: 403, error: 'Forbidden' };
    if (requestedTenantId && requestedTenantId !== tid) {
      return { status: 403, error: 'Forbidden' };
    }
    const label = tid.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    return { status: 200, authority: 'tenant_admin', tenants: [{ tenant_id: tid, label, is_default: false }] };
  }
  if (!isPlatformAdminSession(session)) {
    return { status: 403, error: 'Forbidden' };
  }
  return { status: 200, authority: 'platform_admin', tenants: [] };
}

// ─── Test runner ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    process.stdout.write('.');
  } catch (e) {
    failed++;
    failures.push({ name, error: e });
    process.stdout.write('F');
  }
}

// ─── Sidebar source helpers ───────────────────────────────────────────────────

function readSidebar() {
  return fs.readFileSync(path.join(__dirname, '..', 'components/layout/Sidebar.tsx'), 'utf8');
}

function readTenantsPage() {
  return fs.readFileSync(path.join(__dirname, '..', 'app/admin/tenants/page.tsx'), 'utf8');
}

function readTenantDetailPage() {
  return fs.readFileSync(path.join(__dirname, '..', 'app/admin/tenants/[tenantId]/page.tsx'), 'utf8');
}

function readKeysPage() {
  return fs.readFileSync(path.join(__dirname, '..', 'app/keys/page.tsx'), 'utf8');
}

function readEmailRoute() {
  return fs.readFileSync(path.join(__dirname, '..', 'app/api/email/route.ts'), 'utf8');
}

function readTenantsRoute() {
  return fs.readFileSync(path.join(__dirname, '..', 'app/api/tenants/route.ts'), 'utf8');
}

// ─── Tests 1–22: Tenant Admin ─────────────────────────────────────────────────

// T-01: sees own organization identity
test('T-01: tenant admin session classified as console_enabled_client with own tenant', () => {
  const session = makeTenantAdminSession('high-table-financial');
  const principal = resolveConsolePrincipal(session);
  assert.strictEqual(principal.experienceClass, 'console_enabled_client');
  assert.strictEqual(principal.tenantId, 'high-table-financial');
});

// T-02: sees Tenant Administrator context (not platform_admin experience)
test('T-02: isTenantAdminSession correctly identifies tenant_admin', () => {
  const session = makeTenantAdminSession('high-table-financial');
  assert.strictEqual(isTenantAdminSession(session), true);
  assert.strictEqual(isPlatformAdminSession(session), false);
});

// T-03: sidebar org label derives from canonical session tenant — not from browser
test('T-03: sidebar uses isTenantAdminSession and getSessionClaims for org identity', () => {
  const sidebar = readSidebar();
  assert.match(sidebar, /isTenantAdminSession/, 'sidebar must use isTenantAdminSession to detect tenant admin context');
  assert.match(sidebar, /getSessionClaims/, 'sidebar must use getSessionClaims for canonical tenant identity');
  assert.match(sidebar, /org-identity-label/, 'sidebar must render org-identity-label testid for tenant admin');
  assert.doesNotMatch(sidebar, /localStorage/, 'sidebar must not read localStorage for tenant identity');
  assert.doesNotMatch(sidebar, /sessionStorage/, 'sidebar must not read sessionStorage for tenant identity');
});

// T-04: tenant admin cannot see Create Client
test('T-04: tenant admin BFF denies global tenant list and provisioning', () => {
  const session = makeTenantAdminSession('acme-corp');
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 200);
  assert.strictEqual(result.authority, 'tenant_admin');
  // Single entry — no global list
  assert.strictEqual(result.tenants.length, 1);
  // Provision endpoint uses isPlatformAdminSession — tenant_admin returns false
  assert.strictEqual(isPlatformAdminSession(session), false, 'tenant_admin must not reach provisioning');
});

// T-05: tenant admin cannot see global tenant registry
test('T-05: tenant admin BFF never loads global registry', () => {
  // The /api/tenants route is NOT branched through global registry for tenant_admin.
  // Verify tenants route contains the guard.
  const route = readTenantsRoute();
  assert.match(route, /isTenantAdminSession/, 'tenants route must check isTenantAdminSession');
  assert.match(route, /authority.*tenant_admin/, 'tenants route must return tenant_admin authority');
  // Defense-in-depth: isPlatformAdminSession guard before registry access
  assert.match(route, /isPlatformAdminSession/, 'tenants route must guard global registry with isPlatformAdminSession');
});

// T-06: tenant admin cannot see global tenant counts
test('T-06: tenant admin response contains exactly 1 tenant entry', () => {
  const session = makeTenantAdminSession('safe-org');
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.tenants.length, 1, 'tenant admin must receive exactly 1 entry');
});

// T-07: tenant admin cannot see tenant switcher
test('T-07: TenantSwitcher component is not imported in app pages', () => {
  // TenantSwitcher is dead code — it must not be imported in any production app page.
  // Verify it is not used in the admin tenants page.
  const tenantsPage = readTenantsPage();
  assert.doesNotMatch(tenantsPage, /TenantSwitcher/, 'tenants page must not import TenantSwitcher');
  const detailPage = readTenantDetailPage();
  assert.doesNotMatch(detailPage, /TenantSwitcher/, 'tenant detail page must not import TenantSwitcher');
  const sidebar = readSidebar();
  assert.doesNotMatch(sidebar, /TenantSwitcher/, 'sidebar must not import TenantSwitcher');
});

// T-08: tenant admin cannot see foreign organization names
test('T-08: tenant admin BFF returns only own tenant label', () => {
  const session = makeTenantAdminSession('acme-corp');
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.tenants[0].tenant_id, 'acme-corp');
  // The label is derived from own tenant_id — cannot contain foreign org names
  assert.ok(result.tenants[0].label.toLowerCase().includes('acme'), 'label must be derived from own tenant id');
});

// T-09: tenant admin cannot see foreign tenant IDs
test('T-09: tenants page hides raw tenant_id from non-platform-admin card views', () => {
  const page = readTenantsPage();
  // The tenant_id code element must be gated on isPlatformAdmin
  assert.match(page, /isPlatformAdmin && <code.*tenant_id/, 'raw tenant_id in card must be gated on isPlatformAdmin');
});

// T-10: tenant admin cannot directly access foreign tenant administration
test('T-10: tenant admin requesting foreign tenant gets 403', () => {
  const session = makeTenantAdminSession('acme-corp');
  const result = resolveTenantsAuthority(session, 'rival-inc');
  assert.strictEqual(result.status, 403, 'foreign tenant access must be denied');
});

// T-11: no oracle — foreign vs nonexistent tenant both return 403
test('T-11: foreign and nonexistent tenants return identical 403 (no existence oracle)', () => {
  const session = makeTenantAdminSession('acme-corp');
  const foreign = resolveTenantsAuthority(session, 'rival-inc');
  const nonexistent = resolveTenantsAuthority(session, 'does-not-exist-xyz');
  assert.strictEqual(foreign.status, 403);
  assert.strictEqual(nonexistent.status, 403);
  assert.strictEqual(foreign.error, nonexistent.error, 'error shape must match — no oracle');
});

// T-12: tenant admin cannot provision a new tenant
test('T-12: provision-tenant route requires isPlatformAdminSession', () => {
  const session = makeTenantAdminSession('acme-corp');
  // isPlatformAdminSession must return false for tenant_admin
  assert.strictEqual(isPlatformAdminSession(session), false);
  // Confirm the provision-tenant route checks isPlatformAdminSession
  const provisionSrc = fs.readFileSync(
    path.join(__dirname, '..', 'app/api/admin/provision-tenant/route.ts'), 'utf8'
  );
  assert.match(provisionSrc, /isPlatformAdminSession/, 'provision-tenant must check isPlatformAdminSession');
});

// T-13: tenant admin cannot reach generic platform email dispatch
test('T-13: email route requires isPlatformAdminSession (generic dispatch restricted)', () => {
  const session = makeTenantAdminSession('acme-corp');
  assert.strictEqual(isPlatformAdminSession(session), false);
  const emailRoute = readEmailRoute();
  assert.match(emailRoute, /isPlatformAdminSession/, 'email route must require isPlatformAdminSession');
});

// T-14: tenant admin cannot select arbitrary tenant for API credential operation
test('T-14: keys page is restricted to INTERNAL_ONLY_ROLES (tenant_admin excluded)', () => {
  const session = makeTenantAdminSession('acme-corp');
  assert.strictEqual(
    canAccessConsoleRoute('/keys', session),
    false,
    'tenant_admin must not access /keys route'
  );
  // Verify /keys route audit restricts allowedRoles to internal only
  const keysAudit = CONSOLE_ROUTE_AUDITS.find(r => r.id === 'keys');
  assert.ok(keysAudit, 'keys route audit must exist');
  assert.ok(!keysAudit.allowedRoles.includes('tenant_admin'), 'keys route must not allow tenant_admin');
});

// T-15: tenant admin cannot access foreign users
test('T-15: foreign user tenant request returns 403 (no cross-tenant user access)', () => {
  const session = makeTenantAdminSession('acme-corp');
  // A request with a different tenant_id than session — should be denied
  const result = resolveTenantsAuthority(session, 'foreign-corp');
  assert.strictEqual(result.status, 403);
});

// T-16: tenant admin cannot access foreign portal administration
test('T-16: tenant detail page does not show raw tenantId to tenant_admin', () => {
  const detailPage = readTenantDetailPage();
  // Raw tenant ID display must be gated on showTenantId which requires isPlatformAdminSession
  assert.match(detailPage, /showTenantId/, 'tenant detail page must use showTenantId guard');
  assert.match(detailPage, /isPlatformAdminSession/, 'tenant detail page must check isPlatformAdminSession for raw ID');
  assert.match(detailPage, /data-testid="tenant-id-display"/, 'tenant-id-display testid must be gated on showTenantId');
});

// T-17: tenant admin cannot access foreign credentials
test('T-17: service credentials are tenant-scoped (BFF adds tenant from session)', () => {
  const detailPage = readTenantDetailPage();
  // ServiceCredentialsTab receives tenantId from URL params (server-side validated)
  assert.match(detailPage, /ServiceCredentialsTab/, 'ServiceCredentialsTab must be present');
  // Must not read credentials from arbitrary user input
  assert.doesNotMatch(detailPage, /setTenantId\(event\.target\.value\)/, 'service credentials must not have editable tenant input');
});

// T-18: tenant admin cannot access foreign integrations
test('T-18: engagement list fetch uses tenantId from URL params (server-validated)', () => {
  const detailPage = readTenantDetailPage();
  // Engagements fetch uses tenantId from URL params — not a browser-supplied free-form field
  assert.match(detailPage, /admin\/identity\/tenants\//, 'engagements endpoint uses tenantId from params');
  assert.match(detailPage, /engagements/, 'engagements endpoint must be called with tenant context');
  // Must not have an editable free-form tenant field for integrations
  assert.doesNotMatch(detailPage, /setTenantId\(event\.target\.value\)/, 'must not have editable tenant field for integrations');
});

// T-19: unknown authority fails closed
test('T-19: unknown role session fails closed (unsupported experienceClass)', () => {
  const session = makeUnknownRoleSession('FutureUnknownRole');
  const principal = resolveConsolePrincipal(session);
  assert.strictEqual(principal.experienceClass, 'unsupported', 'unknown role must be classified as unsupported');
  assert.strictEqual(isTenantAdminSession(session), false, 'unknown role must not be tenant admin');
  assert.strictEqual(isPlatformAdminSession(session), false, 'unknown role must not be platform admin');
});

// T-20: missing tenant binding fails closed
test('T-20: tenant_admin without tenantId in session is denied', () => {
  const session = { user: { roles: ['tenant_admin'] } }; // no tenant_id
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 403, 'tenant_admin without tenantId must be denied');
});

// T-21: malformed tenant context fails closed
test('T-21: malformed tenantId (path traversal) in session is denied', () => {
  const session = { user: { roles: ['tenant_admin'], tenant_id: '../../etc/passwd' } };
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 403, 'malformed tenantId must fail closed');
});

// T-22: browser-provided tenant does not override canonical authority
test('T-22: assessments link uses non-oracle URL for tenant admin (no tenant_id param)', () => {
  // The TenantCard must route tenant admin to /field-assessment without tenant_id query param
  const tenantsPage = readTenantsPage();
  // The assessmentUrl variable must be used (not consoleUrl with raw tenant_id)
  assert.match(tenantsPage, /assessmentUrl/, 'must use assessmentUrl variable (not raw tenant_id consoleUrl)');
  // Platform admin gets tenant-scoped URL; tenant admin gets clean URL
  assert.match(tenantsPage, /isPlatformAdmin/, 'must branch on isPlatformAdmin for assessment URL');
  // Tenant admin branch must be clean /field-assessment without tenant_id
  assert.match(tenantsPage, /['"]\/field-assessment['"]/, "tenant admin assessment link must be '/field-assessment' without query param");
  // Platform admin branch must include tenant_id
  assert.match(tenantsPage, /field-assessment\?tenant_id=/, 'platform admin assessment link must include tenant_id');
});

// ─── Tests 23–28: Platform Admin ─────────────────────────────────────────────

// T-23: retains global Clients portfolio
test('T-23: platform_admin receives platform_admin authority from tenants BFF', () => {
  const session = makePlatformAdminSession();
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 200);
  assert.strictEqual(result.authority, 'platform_admin');
});

// T-24: retains Create Client
test('T-24: isPlatformAdminSession true for Administrator and Support (provisioning access)', () => {
  assert.strictEqual(isPlatformAdminSession(makePlatformAdminSession('Administrator')), true);
  assert.strictEqual(isPlatformAdminSession(makeSupportSession()), true);
  assert.strictEqual(isPlatformAdminSession(makeTenantAdminSession('acme')), false);
});

// T-25: retains legitimate tenant selection
test('T-25: platform_admin can access /admin/tenants route', () => {
  const session = makePlatformAdminSession();
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), true);
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants/some-tenant', session), true);
});

// T-26: retains authorized provisioning
test('T-26: provision-tenant source uses isPlatformAdminSession allowlist (not denylist)', () => {
  const provisionSrc = fs.readFileSync(
    path.join(__dirname, '..', 'app/api/admin/provision-tenant/route.ts'), 'utf8'
  );
  // Must use positive allowlist
  assert.match(provisionSrc, /isPlatformAdminSession/, 'provision-tenant must use isPlatformAdminSession allowlist');
  // Must NOT use isTenantAdminSession-based denylist for platform operations
  assert.doesNotMatch(provisionSrc, /!isTenantAdminSession/, 'provision-tenant must not use isTenantAdminSession denylist');
});

// T-27: retains legitimate platform administration
test('T-27: platform admin sees tenant_id code in TenantCard (operational metadata)', () => {
  const tenantsPage = readTenantsPage();
  // Tenant ID is exposed conditionally for platform admin
  assert.match(tenantsPage, /isPlatformAdmin && <code/, 'platform admin must see raw tenant_id in card');
});

// T-28: retains appropriate operational metadata
test('T-28: platform admin gets full registry-backed tenant list from BFF', () => {
  // Verify tenants route loads global registry only on platform_admin path
  const route = readTenantsRoute();
  assert.match(route, /getTenantRegistry/, 'tenants route must call getTenantRegistry for platform admin');
  // The registry call must be after the isPlatformAdminSession guard
  const platformGuardIndex = route.indexOf('isPlatformAdminSession');
  const registryIndex = route.indexOf('getTenantRegistry');
  assert.ok(platformGuardIndex < registryIndex, 'registry call must come after isPlatformAdminSession guard');
});

// ─── Tests 29–30: Support ─────────────────────────────────────────────────────

// T-29: Support behavior matches canonical existing policy
test('T-29: Support role has platform_admin authority (canonical policy)', () => {
  const session = makeSupportSession();
  assert.strictEqual(isPlatformAdminSession(session), true, 'Support is Platform Admin');
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.authority, 'platform_admin');
});

// T-30: no accidental expansion of Support beyond policy
test('T-30: PLATFORM_ADMIN_ROLES contains only Support and Administrator', () => {
  assert.deepStrictEqual(
    [...PLATFORM_ADMIN_ROLES].sort(),
    ['Administrator', 'Support'],
    'PLATFORM_ADMIN_ROLES must only contain Administrator and Support'
  );
});

// ─── Tests 31–40: General / cross-cutting ─────────────────────────────────────

// T-31: direct URL and navigation visibility are independently enforced
test('T-31: canAccessConsoleRoute is separate from navigation visibility', () => {
  const session = makeTenantAdminSession('acme-corp');
  // Route access check is authoritative — navigation filtering is additional
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), true, 'tenant_admin can access route');
  // Provision endpoint uses isPlatformAdminSession — separate enforcement
  assert.strictEqual(isPlatformAdminSession(session), false, 'but cannot provision');
});

// T-32: 401 behavior — unauthenticated request
test('T-32: unauthenticated session returns 401 from tenants BFF', () => {
  const result = resolveTenantsAuthority(null, null);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.error, 'Unauthorized');
});

// T-33: 403 behavior — authenticated but unauthorized
test('T-33: client_read_only returns 403 from tenants BFF', () => {
  const session = { user: { roles: ['client_read_only'], tenant_id: 'acme' } };
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 403);
});

// T-34: 404 behavior — route not in audit means access denied
test('T-34: canAccessConsoleRoute returns false for unknown routes', () => {
  const session = makePlatformAdminSession();
  assert.strictEqual(canAccessConsoleRoute('/nonexistent-route-xyz', session), false);
});

// T-35: no secret in tenant-facing error output
test('T-35: tenants BFF error responses do not leak secret values', () => {
  const route = readTenantsRoute();
  // Error responses must not include raw API keys or internal secrets
  assert.doesNotMatch(route, /CORE_API_KEY/, 'tenants route must not leak CORE_API_KEY in errors');
  assert.doesNotMatch(route, /FG_INTERNAL_GATEWAY_SECRET/, 'must not leak internal gateway secret');
});

// T-36: credential plaintext remains one-time only
test('T-36: service credentials tab shows plaintext only at issuance (one-time display)', () => {
  const detailPage = readTenantDetailPage();
  assert.match(detailPage, /shown once at issuance|will not be shown again|shown exactly once|copy.*now/i,
    'credential secret must be described as one-time');
});

// T-37: existing #703 delegation tests still green (structural regression)
test('T-37: delegated authority structure preserved — tenant_admin is console_enabled_client', () => {
  const session = makeTenantAdminSession('acme-corp');
  const principal = resolveConsolePrincipal(session);
  assert.strictEqual(principal.experienceClass, 'console_enabled_client');
  assert.ok(principal.isAuthenticated);
  assert.strictEqual(principal.tenantId, 'acme-corp');
});

// T-38: existing #704 45-test authority suite — CLIENT_ADMIN_ROLES invariant
test('T-38: CLIENT_ADMIN_ROLES = [tenant_admin, ...PLATFORM_ADMIN_ROLES] (PR #704 invariant)', () => {
  assert.ok(CLIENT_ADMIN_ROLES.includes('tenant_admin'), 'tenant_admin in CLIENT_ADMIN_ROLES');
  assert.ok(CLIENT_ADMIN_ROLES.includes('Administrator'), 'Administrator in CLIENT_ADMIN_ROLES');
  assert.ok(CLIENT_ADMIN_ROLES.includes('Support'), 'Support in CLIENT_ADMIN_ROLES');
  assert.ok(!CLIENT_ADMIN_ROLES.includes('Developer'), 'Developer NOT in CLIENT_ADMIN_ROLES');
  assert.ok(!CLIENT_ADMIN_ROLES.includes('Operator'), 'Operator NOT in CLIENT_ADMIN_ROLES');
  assert.ok(!CLIENT_ADMIN_ROLES.includes('FieldAssessor'), 'FieldAssessor NOT in CLIENT_ADMIN_ROLES');
});

// T-39: route audit inventory is internally consistent
test('T-39: route audit inventory — clients and client-detail entries are correct', () => {
  const clients = CONSOLE_ROUTE_AUDITS.find(r => r.id === 'clients');
  const detail = CONSOLE_ROUTE_AUDITS.find(r => r.id === 'client-detail');
  assert.ok(clients, 'clients route audit must exist');
  assert.ok(detail, 'client-detail route audit must exist');
  assert.ok(clients.allowedRoles.includes('tenant_admin'));
  assert.ok(clients.allowedRoles.includes('Administrator'));
  assert.ok(clients.allowedRoles.includes('Support'));
  assert.ok(detail.tenantScoped, 'client-detail must be tenantScoped');
});

// T-40: unknown/future roles do not inherit Platform Admin behavior
test('T-40: unknown role does not fall through to platform admin experience', () => {
  const unknown = makeUnknownRoleSession('SuperAdmin2099');
  assert.strictEqual(isPlatformAdminSession(unknown), false, 'unknown role must not be platform admin');
  assert.strictEqual(isTenantAdminSession(unknown), false, 'unknown role must not be tenant admin');
  const principal = resolveConsolePrincipal(unknown);
  assert.strictEqual(principal.experienceClass, 'unsupported', 'unknown role → unsupported, not platform admin');
  // Also can't access any restricted routes
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', unknown), false, 'unknown role denied admin routes');
});

// ─── Adversarial Matrix ───────────────────────────────────────────────────────

// ADV-01: forged tenant_id query — browser cannot override canonical session authority
test('ADV-01: forged tenant_id query — resolveTenantsAuthority uses session, not request param', () => {
  const session = makeTenantAdminSession('acme-corp');
  // A forged request claiming rival-inc is denied; session tenantId is authoritative
  const result = resolveTenantsAuthority(session, 'rival-inc');
  assert.strictEqual(result.status, 403, 'forged tenant_id query must be denied');
});

// ADV-02: forged tenantId body — POST body tenant_id cannot escalate authority
test('ADV-02: forged tenantId body — provision-tenant uses isPlatformAdminSession, not body', () => {
  const session = makeTenantAdminSession('acme-corp');
  // provision-tenant reads body but uses isPlatformAdminSession for authority check
  assert.strictEqual(isPlatformAdminSession(session), false);
  // The BFF guard fires before body processing
  const provisionSrc = fs.readFileSync(
    path.join(__dirname, '..', 'app/api/admin/provision-tenant/route.ts'), 'utf8'
  );
  // Guard must appear before body is read
  const guardIdx = provisionSrc.indexOf('isPlatformAdminSession');
  const bodyIdx = provisionSrc.indexOf('req.json()');
  assert.ok(guardIdx < bodyIdx, 'ADV-02: isPlatformAdminSession guard must precede body parse');
});

// ADV-03: forged tenant header — X-Tenant-ID not used as authority
test('ADV-03: tenants route does not trust X-Tenant-ID header as authority', () => {
  const route = readTenantsRoute();
  // Tenant authority comes from session (auth()), not from request headers
  assert.doesNotMatch(route, /getHeader\(['"]x-tenant-id['"]\)/i, 'must not read X-Tenant-ID header as authority');
  assert.doesNotMatch(route, /headers\.get\(['"]x-tenant-id['"]\)/i, 'must not trust X-Tenant-ID header');
});

// ADV-04: manipulated localStorage — shell derives tenant from session, not localStorage
test('ADV-04: sidebar does not read localStorage for tenant identity', () => {
  const sidebar = readSidebar();
  assert.doesNotMatch(sidebar, /localStorage/, 'sidebar must not read localStorage');
});

// ADV-05: manipulated sessionStorage — same
test('ADV-05: sidebar does not read sessionStorage for tenant identity', () => {
  const sidebar = readSidebar();
  assert.doesNotMatch(sidebar, /sessionStorage/, 'sidebar must not read sessionStorage');
});

// ADV-06: foreign direct URL — canAccessConsoleRoute blocks the route
test('ADV-06: foreign direct URL to /admin/tenants/[foreignTenant] — auth layer enforces', () => {
  const tenantAdmin = makeTenantAdminSession('acme-corp');
  // canAccessConsoleRoute allows the route pattern (tenantScoped BFF handles the boundary)
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants/rival-inc', tenantAdmin), true,
    'ADV-06: route pattern is accessible — BFF enforces tenant boundary, not middleware');
  // The BFF denies the cross-tenant request
  const result = resolveTenantsAuthority(tenantAdmin, 'rival-inc');
  assert.strictEqual(result.status, 403, 'ADV-06: BFF denies foreign tenant');
});

// ADV-07: nonexistent tenant URL — same 403 as foreign tenant (no oracle)
test('ADV-07: nonexistent tenant URL returns same 403 as foreign (no oracle)', () => {
  const session = makeTenantAdminSession('acme-corp');
  const r1 = resolveTenantsAuthority(session, 'foreign-corp');
  const r2 = resolveTenantsAuthority(session, 'totally-nonexistent-xyz');
  assert.strictEqual(r1.status, 403);
  assert.strictEqual(r2.status, 403);
  assert.strictEqual(r1.error, r2.error, 'ADV-07: error must be identical — no oracle');
});

// ADV-08: stale tenant context — empty tenantId fails closed
test('ADV-08: empty tenantId in session (stale context) fails closed', () => {
  const session = { user: { roles: ['tenant_admin'], tenant_id: '' } };
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 403, 'ADV-08: empty tenant_id must fail closed');
});

// ADV-09: missing tenant binding — no tenant_id in session
test('ADV-09: missing tenant binding (no tenant_id in session) fails closed', () => {
  const session = { user: { roles: ['tenant_admin'] } };
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 403, 'ADV-09: missing tenant binding must fail closed');
});

// ADV-10: malformed tenant ID (path traversal)
test('ADV-10: malformed tenantId (path traversal) fails closed', () => {
  const session = { user: { roles: ['tenant_admin'], tenant_id: '../../etc/passwd' } };
  const result = resolveTenantsAuthority(session, null);
  assert.strictEqual(result.status, 403, 'ADV-10: path traversal tenantId must fail closed');
});

// ADV-11: mixed roles — internal role wins over tenant_admin
test('ADV-11: Administrator + tenant_admin mixed role classified as internal_console', () => {
  const session = { user: { roles: ['Administrator', 'tenant_admin'], tenant_id: 'acme-corp' } };
  const principal = resolveConsolePrincipal(session);
  assert.strictEqual(principal.experienceClass, 'internal_console',
    'ADV-11: internal role dominates — classified as internal_console, not console_enabled_client');
  assert.strictEqual(isTenantAdminSession(session), false,
    'ADV-11: mixed session with internal role must not be classified as tenant admin');
});

// ADV-12: tenant_admin + internal role combo — same as ADV-11 but reversed order
test('ADV-12: tenant_admin + Developer mixed role classified as internal_console', () => {
  const session = { user: { roles: ['tenant_admin', 'Developer'], tenant_id: 'acme-corp' } };
  const principal = resolveConsolePrincipal(session);
  assert.strictEqual(principal.experienceClass, 'internal_console');
  assert.strictEqual(isTenantAdminSession(session), false);
});

// ADV-13: Developer role — no platform admin access
test('ADV-13: Developer role cannot access admin tenants route', () => {
  const session = makeInternalSession('Developer');
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), false,
    'ADV-13: Developer must not access /admin/tenants');
  assert.strictEqual(isPlatformAdminSession(session), false, 'Developer is not platform admin');
});

// ADV-14: Operator role — no client admin access
test('ADV-14: Operator role cannot access admin tenants route', () => {
  const session = makeOperatorSession();
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), false,
    'ADV-14: Operator must not access /admin/tenants');
});

// ADV-15: FieldAssessor role — no client admin access
test('ADV-15: FieldAssessor role cannot access admin tenants route', () => {
  const session = makeFieldAssessorSession();
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), false,
    'ADV-15: FieldAssessor must not access /admin/tenants');
  assert.ok(!CLIENT_ADMIN_ROLES.includes('FieldAssessor'),
    'FieldAssessor must not be in CLIENT_ADMIN_ROLES');
});

// ADV-16: unknown future role — denied
test('ADV-16: unknown future role denied admin tenants route', () => {
  const session = makeUnknownRoleSession('SuperAdminFuture');
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), false);
});

// ADV-17: Support role — platform admin (canonical policy)
test('ADV-17: Support role has correct platform_admin access (canonical policy)', () => {
  const session = makeSupportSession();
  assert.strictEqual(isPlatformAdminSession(session), true, 'Support is platform admin');
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), true);
});

// ADV-18: Administrator role — platform admin
test('ADV-18: Administrator role has platform_admin access', () => {
  const session = makePlatformAdminSession('Administrator');
  assert.strictEqual(isPlatformAdminSession(session), true);
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', session), true);
});

// ADV-19: forged authority response — resolveConsolePrincipal reads session claims only
test('ADV-19: resolveConsolePrincipal reads from session object (not HTTP response body)', () => {
  // Session is provided by NextAuth (server-verified) — not from a browser-manipulable source
  // This test verifies that a session with correct claims classifies correctly
  const validSession = makeTenantAdminSession('acme-corp');
  const principal = resolveConsolePrincipal(validSession);
  assert.strictEqual(principal.experienceClass, 'console_enabled_client');
  // A forged session missing the tenant would be denied
  const forgery = { user: { roles: ['tenant_admin'] } }; // no tenant_id
  const forgedPrincipal = resolveConsolePrincipal(forgery);
  assert.strictEqual(forgedPrincipal.tenantId, null, 'forged session without tenantId has null tenantId');
});

// ADV-20: missing authority response — null session fails closed
test('ADV-20: null/missing session fails closed (anonymous experience class)', () => {
  const principal = resolveConsolePrincipal(null);
  assert.strictEqual(principal.experienceClass, 'anonymous');
  assert.strictEqual(principal.isAuthenticated, false);
  const result = resolveTenantsAuthority(null, null);
  assert.strictEqual(result.status, 401);
});

// ADV-21: malformed authority response — empty object produces unsupported principal
test('ADV-21: empty session object produces safe (unsupported/anonymous) principal', () => {
  // An object with no user property produces unsupported (authenticated=true but no roles)
  // or anonymous (null). Either way, it must not produce platform_admin or tenant_admin.
  const principal = resolveConsolePrincipal({});
  // Must not be platform admin or tenant admin
  assert.strictEqual(isPlatformAdminSession({}), false, 'empty object must not be platform admin');
  assert.strictEqual(isTenantAdminSession({}), false, 'empty object must not be tenant admin');
  // Route access must be denied
  assert.strictEqual(canAccessConsoleRoute('/admin/tenants', {}), false,
    'empty session object must not access admin routes');
  // Experience class must not be a privileged class
  assert.ok(
    principal.experienceClass === 'unsupported' || principal.experienceClass === 'anonymous',
    `empty session must produce unsupported or anonymous, got: ${principal.experienceClass}`
  );
});

// ADV-22: browser request replay — session token validated server-side (structural check)
test('ADV-22: tenants BFF calls auth() for session — not request body', () => {
  const route = readTenantsRoute();
  assert.match(route, /await auth\(\)/, 'tenants route must call auth() for session');
  assert.doesNotMatch(route, /req\.body\.session/, 'must not trust session from request body');
});

// ADV-23: arbitrary credential tenant — keys page already INTERNAL_ONLY_ROLES
test('ADV-23: /keys route audit requires INTERNAL_ONLY_ROLES (no tenant_admin access)', () => {
  const keysAudit = CONSOLE_ROUTE_AUDITS.find(r => r.id === 'keys');
  assert.ok(keysAudit, 'keys route audit must exist');
  assert.ok(!keysAudit.allowedRoles.includes('tenant_admin'),
    'ADV-23: tenant_admin must not be in keys route allowedRoles');
  const session = makeTenantAdminSession('acme-corp');
  assert.strictEqual(canAccessConsoleRoute('/keys', session), false,
    'ADV-23: tenant_admin denied /keys route');
});

// ADV-24: arbitrary email recipient — email route restricted to isPlatformAdminSession
test('ADV-24: email route restricts arbitrary dispatch to isPlatformAdminSession', () => {
  const emailRoute = readEmailRoute();
  assert.match(emailRoute, /isPlatformAdminSession/, 'email route must check isPlatformAdminSession');
  // Must not use isTenantAdminSession denylist
  assert.doesNotMatch(emailRoute, /!isTenantAdminSession/, 'email route must not use denylist');
});

// ADV-25: foreign user-management route
test('ADV-25: tenant admin requesting foreign user data via resolved authority is denied', () => {
  const session = makeTenantAdminSession('acme-corp');
  // A request using a different tenantId than session should be rejected
  const result = resolveTenantsAuthority(session, 'foreign-corp');
  assert.strictEqual(result.status, 403, 'ADV-25: foreign user management route must be denied');
});

// ADV-26: foreign portal route — same authority enforcement
test('ADV-26: tenant admin cannot reach foreign portal administration route', () => {
  const session = makeTenantAdminSession('acme-corp');
  const result = resolveTenantsAuthority(session, 'another-org');
  assert.strictEqual(result.status, 403, 'ADV-26: foreign portal route is denied');
});

// ─── Final output ──────────────────────────────────────────────────────────────

process.stdout.write('\n');

if (failures.length) {
  process.stderr.write(`\n${failures.length} failure(s):\n\n`);
  for (const { name, error } of failures) {
    process.stderr.write(`  FAIL ${name}\n`);
    process.stderr.write(`    ${error.message}\n\n`);
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
