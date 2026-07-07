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

  const adminConnectors = getCoreApiPolicy('admin/connectors');
  assert.equal(adminConnectors?.tenantScoped, false);
  assert.equal(canAccessCoreApiPath('admin/connectors', 'POST', principal), false);
});

test('legacy internal fallback stays internally routable when enabled', () => {
  assert.equal(canAccessConsoleRoute('/dashboard', { user: {} }), true);
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
