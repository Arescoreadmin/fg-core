'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  CONSOLE_ROUTE_AUDITS,
  canAccessConsoleRoute,
  canAccessCoreApiPath,
  getConsoleRouteAudit,
  getCoreApiPolicy,
  resolveConsolePrincipal,
} = require('../lib/consoleAccess.js');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

function sessionWithRoles(roles) {
  return { user: { roles } };
}

test('every registered console route has an access audit entry', () => {
  const registry = JSON.parse(read('../../packages/navigation/navigation-registry.json'));
  const expectedRoutes = new Set(registry.console.map((item) => item.route));
  expectedRoutes.add('/reports');

  const auditedRoutes = new Set(CONSOLE_ROUTE_AUDITS.map((item) => item.routePattern));
  const missing = [...expectedRoutes].filter((route) => !auditedRoutes.has(route));

  assert.deepEqual(missing, []);
});

test('client-console routes are explicitly classified', () => {
  assert.equal(getConsoleRouteAudit('/dashboard/executive')?.audience, 'client_console_limited');
  assert.equal(getConsoleRouteAudit('/dashboard/readiness')?.audience, 'client_console_limited');
  assert.equal(getConsoleRouteAudit('/dashboard')?.audience, 'frostgate_operator');
  assert.equal(getConsoleRouteAudit('/dashboard/providers')?.audience, 'forbidden_to_clients');
});

test('console-enabled client can access allowed limited console routes', () => {
  const principal = sessionWithRoles(['client_executive']);
  assert.equal(canAccessConsoleRoute('/dashboard/executive', principal), true);
  assert.equal(canAccessConsoleRoute('/dashboard/readiness', principal), true);
  assert.equal(canAccessConsoleRoute('/dashboard/decisions', principal), true);
});

test('console-enabled client cannot access internal operator routes', () => {
  const principal = sessionWithRoles(['client_executive']);
  assert.equal(canAccessConsoleRoute('/dashboard', principal), false);
  assert.equal(canAccessConsoleRoute('/dashboard/control-tower', principal), false);
  assert.equal(canAccessConsoleRoute('/workspace', principal), false);
});

test('console-enabled client cannot access platform admin APIs', () => {
  const principal = sessionWithRoles(['client_executive']);
  assert.equal(canAccessCoreApiPath(['admin', 'connectors'], 'GET', principal), false);
  assert.equal(canAccessCoreApiPath(['admin', 'identity', 'tenants'], 'GET', principal), false);
  assert.equal(canAccessCoreApiPath(['ui', 'provider', 'governance'], 'GET', principal), false);
});

test('client-facing mutable access is role-gated and fails closed by default', () => {
  const executive = sessionWithRoles(['client_executive']);
  const tenantAdmin = sessionWithRoles(['tenant_admin']);

  assert.equal(canAccessCoreApiPath(['field-assessment', 'engagements'], 'POST', executive), false);
  assert.equal(canAccessCoreApiPath(['field-assessment', 'engagements'], 'PATCH', executive), false);
  assert.equal(canAccessCoreApiPath(['field-assessment', 'engagements'], 'POST', tenantAdmin), true);
});

test('client_read_only cannot mutate anything', () => {
  const principal = sessionWithRoles(['client_read_only']);
  const mutablePaths = [
    ['field-assessment', 'engagements'],
    ['ingest', 'assessment', 'reports', 'generate'],
    ['admin', 'connectors'],
    ['keys'],
  ];

  for (const apiPath of mutablePaths) {
    assert.equal(
      canAccessCoreApiPath(apiPath, 'POST', principal),
      false,
      `${apiPath.join('/')} must reject client_read_only mutations`,
    );
  }
});

test('tenant_admin can only mutate tenant-scoped resources', () => {
  const principal = sessionWithRoles(['tenant_admin']);

  const fieldAssessments = getCoreApiPolicy('field-assessment/engagements');
  assert.equal(fieldAssessments?.tenantScoped, true);
  assert.equal(canAccessCoreApiPath('field-assessment/engagements', 'POST', principal), true);

  for (const tenantAdminPath of [
    'workforce/users',
    'portal/grants',
    'admin/identity/tenants/acme/config',
    'admin/identity/invitations/inv-1/revoke',
  ]) {
    const policy = getCoreApiPolicy(tenantAdminPath);
    assert.equal(policy?.tenantScoped, true, `${tenantAdminPath} must be tenant scoped`);
    assert.equal(canAccessCoreApiPath(tenantAdminPath, 'GET', principal), true);
    assert.equal(canAccessCoreApiPath(tenantAdminPath, 'POST', principal), true);
  }

  const adminConnectors = getCoreApiPolicy('admin/connectors');
  assert.equal(adminConnectors?.tenantScoped, false);
  assert.equal(canAccessCoreApiPath('admin/connectors', 'POST', principal), false);
});

test('authenticated user with no recognized role is denied by default', () => {
  assert.equal(canAccessConsoleRoute('/dashboard', { user: {} }), false);
  assert.equal(canAccessConsoleRoute('/dashboard/executive', { user: {} }), false);
  assert.equal(canAccessConsoleRoute('/workspace', { user: {} }), false);
});

test('security invariant: no-role session cannot reach any operator or client-console route', () => {
  const noRole = { user: {} };
  const guardedRoutes = ['/dashboard', '/dashboard/control-tower', '/workspace', '/field-assessment', '/dashboard/executive'];
  for (const route of guardedRoutes) {
    assert.equal(
      canAccessConsoleRoute(route, noRole),
      false,
      `no-role session must be denied ${route}`,
    );
  }
});

test('security invariant: unrecognized role fails closed', () => {
  const unknown = sessionWithRoles(['legacy_console_user']);
  assert.equal(canAccessConsoleRoute('/dashboard', unknown), false);
  assert.equal(canAccessCoreApiPath(['admin', 'connectors'], 'GET', unknown), false);
});

test('portal-only client cannot enter console routes', () => {
  const principal = sessionWithRoles(['Customer']);
  assert.equal(canAccessConsoleRoute('/dashboard/executive', principal), false);
  assert.equal(canAccessConsoleRoute('/field-assessment', principal), false);
  assert.equal(canAccessConsoleRoute('/products', principal), true);
});

test('unsupported role fails closed', () => {
  const principal = sessionWithRoles(['mystery_role']);
  assert.equal(canAccessConsoleRoute('/dashboard/executive', principal), false);
  assert.equal(canAccessCoreApiPath('control-plane/readiness/frameworks', 'GET', principal), false);
});

test('middleware, sidebar, and core proxy all use the shared access policy', () => {
  assert.match(read('middleware.ts'), /canAccessConsoleRoute/);
  assert.match(read('components/layout/Sidebar.tsx'), /getNavigationItemsForPrincipal/);
  assert.match(read('app/api/core/[...path]/route.ts'), /canAccessCoreApiPath/);
});

// ─── PR-SEC-003: middleware edge enforcement ──────────────────────────────────

test('middleware imports resolveConsolePrincipal and enforces unsupported at edge', () => {
  const src = read('middleware.ts');
  assert.match(src, /resolveConsolePrincipal/);
  assert.match(src, /experienceClass === 'unsupported'/);
  assert.match(src, /SESSION_UNSUPPORTED/);
  assert.match(src, /status: 401/);
  // Guard must fire before canAccessConsoleRoute (API paths bypass that check)
  const unsupportedPos = src.indexOf("experienceClass === 'unsupported'");
  const routeCheckPos = src.indexOf('canAccessConsoleRoute(pathname');
  assert.ok(unsupportedPos < routeCheckPos, 'unsupported guard must precede canAccessConsoleRoute');
});

// Inline mirror of the middleware unsupported-session decision.
// Mirrors the logic added in PR-SEC-003 so behavior is verifiable without a Next.js runtime.
function middlewareUnsupportedDecision(session, pathname) {
  const principal = resolveConsolePrincipal(session);
  if (principal.experienceClass !== 'unsupported') return null;
  return pathname.startsWith('/api/') ? 401 : 'redirect:/unauthorized';
}

test('unsupported session on API path is denied 401 at middleware', () => {
  const noRole = { user: {} };
  const unknownRole = sessionWithRoles(['legacy_console_user']);
  const arbitraryRole = sessionWithRoles(['mystery_role']);

  for (const session of [noRole, unknownRole, arbitraryRole]) {
    assert.equal(middlewareUnsupportedDecision(session, '/api/field-assessment/audio-url'), 401);
    assert.equal(middlewareUnsupportedDecision(session, '/api/field-assessment/transcribe'), 401);
    assert.equal(middlewareUnsupportedDecision(session, '/api/core/admin/connectors'), 401);
  }
});

test('unsupported session on page path is redirected at middleware', () => {
  const noRole = { user: {} };
  assert.equal(middlewareUnsupportedDecision(noRole, '/dashboard'), 'redirect:/unauthorized');
  assert.equal(middlewareUnsupportedDecision(noRole, '/workspace'), 'redirect:/unauthorized');
  assert.equal(middlewareUnsupportedDecision(sessionWithRoles(['mystery_role']), '/dashboard/executive'), 'redirect:/unauthorized');
});

test('recognized sessions pass through the unsupported middleware guard', () => {
  const operator = sessionWithRoles(['Operator']);
  const client = sessionWithRoles(['tenant_admin']);
  const portal = sessionWithRoles(['Customer']);

  for (const session of [operator, client, portal]) {
    assert.equal(middlewareUnsupportedDecision(session, '/api/core/anything'), null);
    assert.equal(middlewareUnsupportedDecision(session, '/dashboard'), null);
  }
});

test('proof 3: recognized client role passes guard and reaches allowed client-console routes', () => {
  const client = sessionWithRoles(['client_executive']);
  assert.equal(middlewareUnsupportedDecision(client, '/dashboard/executive'), null);
  assert.equal(middlewareUnsupportedDecision(client, '/api/core/field-assessment/engagements'), null);
  assert.equal(canAccessConsoleRoute('/dashboard/executive', client), true);
  assert.equal(canAccessConsoleRoute('/dashboard/readiness', client), true);
});

test('proof 4: recognized internal operator passes guard and reaches operator routes', () => {
  const operator = sessionWithRoles(['Operator']);
  assert.equal(middlewareUnsupportedDecision(operator, '/dashboard'), null);
  assert.equal(middlewareUnsupportedDecision(operator, '/api/core/admin/connectors'), null);
  assert.equal(canAccessConsoleRoute('/dashboard', operator), true);
  assert.equal(canAccessConsoleRoute('/workspace', operator), true);
});

// ─── TENANT-ACCESS-001: delegated admin path coverage ────────────────────────

const {
  CLIENT_CONSOLE_ROLES,
  INTERNAL_CONSOLE_ROLES,
} = require('../lib/consoleAccess.js');

test('TENANT-ACCESS-001: admin/tenants path is accessible to tenant_admin', () => {
  const tenantAdmin = sessionWithRoles(['tenant_admin']);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants'], 'GET', tenantAdmin), true);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants'], 'POST', tenantAdmin), true);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants', 'acme', 'users', 'invite'], 'POST', tenantAdmin), true);
});

test('TENANT-ACCESS-001: admin/tenants path is accessible to internal operators', () => {
  const operator = sessionWithRoles(['Operator']);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants'], 'GET', operator), true);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants', 'acme', 'bootstrap-admin'], 'POST', operator), true);
});

test('TENANT-ACCESS-001: portal_only is denied admin/tenants', () => {
  for (const role of ['portal_only', 'Customer', 'MSP']) {
    const session = sessionWithRoles([role]);
    assert.equal(canAccessCoreApiPath(['admin', 'tenants'], 'GET', session), false,
      `${role} must be denied admin/tenants`);
  }
});

test('TENANT-ACCESS-001: client_read_only is denied admin/tenants (clientSafe: false)', () => {
  const readOnly = sessionWithRoles(['client_read_only']);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants'], 'GET', readOnly), false);
  assert.equal(canAccessCoreApiPath(['admin', 'tenants', 'acme', 'users', 'invite'], 'POST', readOnly), false);
});

test('TENANT-ACCESS-001: Administrator role is in INTERNAL_CONSOLE_ROLES (internal_console classification)', () => {
  assert.ok(INTERNAL_CONSOLE_ROLES.includes('Administrator'));
  assert.ok(!CLIENT_CONSOLE_ROLES.includes('Administrator'));
  const principal = resolveConsolePrincipal(sessionWithRoles(['Administrator']));
  assert.equal(principal.experienceClass, 'internal_console');
  assert.equal(principal.isAuthenticated, true);
});

test('TENANT-ACCESS-001: tenant_admin is in CLIENT_CONSOLE_ROLES (console_enabled_client classification)', () => {
  assert.ok(CLIENT_CONSOLE_ROLES.includes('tenant_admin'));
  assert.ok(!INTERNAL_CONSOLE_ROLES.includes('tenant_admin'));
  const principal = resolveConsolePrincipal(sessionWithRoles(['tenant_admin']));
  assert.equal(principal.experienceClass, 'console_enabled_client');
});

test('TENANT-ACCESS-001: portal_only classifies as portal_only and is denied console API', () => {
  const principal = resolveConsolePrincipal(sessionWithRoles(['portal_only']));
  assert.equal(principal.experienceClass, 'portal_only');
  assert.equal(canAccessCoreApiPath(['decisions'], 'GET', sessionWithRoles(['portal_only'])), false);
  assert.equal(canAccessCoreApiPath(['workforce', 'users'], 'GET', sessionWithRoles(['portal_only'])), false);
});

test('TENANT-ACCESS-001: client_read_only denied internal-only API paths', () => {
  const session = sessionWithRoles(['client_read_only']);
  assert.equal(canAccessCoreApiPath(['keys'], 'GET', session), false);
  assert.equal(canAccessCoreApiPath(['forensics', 'snapshot'], 'GET', session), false);
  assert.equal(canAccessCoreApiPath(['rag', 'corpora'], 'GET', session), false);
});

test('TENANT-ACCESS-001: mutation on workforce/users requires tenant_admin or internal', () => {
  assert.equal(canAccessCoreApiPath(['workforce', 'users'], 'POST', sessionWithRoles(['client_read_only'])), false);
  assert.equal(canAccessCoreApiPath(['workforce', 'users'], 'POST', sessionWithRoles(['tenant_admin'])), true);
  assert.equal(canAccessCoreApiPath(['workforce', 'users'], 'POST', sessionWithRoles(['Operator'])), true);
});

test('TENANT-ACCESS-001: CLIENT_CONSOLE_ROLES and portal markers are disjoint', () => {
  const portalMarkers = new Set(['portal_only', 'Customer', 'MSP']);
  for (const role of CLIENT_CONSOLE_ROLES) {
    assert.ok(!portalMarkers.has(role), `CLIENT_CONSOLE_ROLES must not include portal marker ${role}`);
  }
});

test('source regression: field-assessment handlers rely on middleware guard for role enforcement', () => {
  // These handlers only check session?.user — no role classification of their own.
  // The middleware unsupported guard is what blocks no-role sessions.
  // If the guard is ever removed, these handlers must add their own role checks.
  const audioUrl = read('app/api/field-assessment/audio-url/route.ts');
  const transcribe = read('app/api/field-assessment/transcribe/route.ts');
  assert.doesNotMatch(audioUrl, /canAccessConsoleRoute|canAccessCoreApiPath|resolveConsolePrincipal/);
  assert.doesNotMatch(transcribe, /canAccessConsoleRoute|canAccessCoreApiPath|resolveConsolePrincipal/);
  assert.match(read('middleware.ts'), /experienceClass === 'unsupported'/);
});
