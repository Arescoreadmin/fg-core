const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

test('client API uses BFF /api/core and does not depend on NEXT_PUBLIC_CORE_API_KEY', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /resolveConsoleUrl/);
  assert.match(coreApi, /fetch\(await resolveConsoleUrl\(`\/api\/core\$\{path\}`\), \{/);
  assert.doesNotMatch(coreApi, /NEXT_PUBLIC_CORE_API_KEY/);
  assert.doesNotMatch(coreApi, /NEXT_PUBLIC_CORE_API_URL/);
});

test('dashboard loads core health ready endpoint', () => {
  const page = read('app/dashboard/page.tsx');
  assert.match(page, /\/health\/ready/);
  assert.match(page, /Core unreachable/);
});

test('decisions page calls /api/core/decisions with pagination and filters', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /params\.set\('limit'/);
  assert.match(coreApi, /params\.set\('offset'/);
  assert.match(coreApi, /params\.set\('severity'/);
  assert.match(coreApi, /params\.set\('decision_type'/);
  assert.match(coreApi, /\/decisions\?/);
});

test('404 masking is opt-in and only set on forensics routes', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /forensics\/snapshot[\s\S]*mask404: true/);
  assert.match(coreApi, /forensics\/audit_trail[\s\S]*mask404: true/);
  assert.match(coreApi, /export function getDecision\(decisionId: string\) {[\s\S]*return request<DecisionOut>\(`\/decisions\/\$\{encodeURIComponent\(decisionId\)\}`\);/);
  const errors = read('lib/errors.ts');
  assert.match(errors, /options\.mask404 \? 'NOT_FOUND_OR_FORBIDDEN' : 'NOT_FOUND'/);
});

test('forensics page shows chain verify status and proof copy fields', () => {
  const page = read('app/dashboard/forensics/page.tsx');
  assert.match(page, /Chain Verify Status/);
  assert.match(page, /Copy proof/);
  assert.match(page, /responseHash/);
});

test('alignment fetch builds absolute server URL through the shared console origin helper', () => {
  const coreApi = read('lib/coreApi.ts');
  const consoleUrl = read('lib/consoleUrl.ts');
  assert.match(coreApi, /resolveConsoleUrl/);
  assert.match(coreApi, /alignment-artifact/);
  assert.match(consoleUrl, /await import\('next\/headers'\)/);
  assert.match(consoleUrl, /x-forwarded-host/);
  assert.match(consoleUrl, /CONSOLE_BASE_URL/);
  assert.match(consoleUrl, /NEXTAUTH_URL/);
  assert.match(consoleUrl, /must point to loopback in development/);
});

test('proxy has strict route allowlist and blocks wildcard patterns', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /const PROXY_RULES/);
  assert.match(proxy, /Route\/method is not allowed by proxy policy/);
  assert.doesNotMatch(proxy, /prefix:\s*'\*'/);
});

test('tenant query parameter cannot override server tenant authority', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.doesNotMatch(proxy, /FG_CONSOLE_ALLOW_TENANT_QUERY_OVERRIDE/);
  assert.doesNotMatch(proxy, /searchParams\.get\('tenant_id'\)/);
  assert.match(proxy, /return CORE_TENANT_ID \|\| null/);
});

test('demo tenant selection cannot bypass server tenant authority', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.doesNotMatch(proxy, /FG_CONSOLE_DEMO_TENANTS/);
  assert.doesNotMatch(proxy, /DEMO_TENANT_ALLOWLIST/);
  assert.match(proxy, /query\.delete\('tenant_id'\)/);
});



test('tenant authority cannot be overridden through JSON request body', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /tenant_id: _ignoredTenantId/);
  assert.match(proxy, /JSON\.stringify\(safePayload\)/);
});

test('rate limit and API key tenant authority are server resolved', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /const tenantId = resolveTenant\(request\)/);
  assert.match(proxy, /const key = await getTenantApiKey\(tenantId\)/);
  assert.doesNotMatch(proxy, /searchParams\.get\('tenant_id'\)/);
});

test('proxy never forwards browser cookies or authorization headers', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /headers\.set\('X-API-Key', coreAuth\.apiKey\)/);
  assert.doesNotMatch(proxy, /cookie/i);
  assert.doesNotMatch(proxy, /authorization/i);
  assert.match(proxy, /Cache-Control': 'no-store'/);
});

test('bff error response contract is stable and no-store', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /\{ detail: message, code: `HTTP_\$\{status\}`, request_id: requestId \}/);
  assert.match(proxy, /'Cache-Control': 'no-store'/);
  assert.match(proxy, /'x-request-id': requestId/);
  assert.match(proxy, /crypto\.randomUUID\(\)/);
});

test('no NEXT_PUBLIC_CORE_API_KEY usage anywhere in console source', () => {
  const files = [
    'app/dashboard/page.tsx',
    'app/dashboard/decisions/page.tsx',
    'app/dashboard/forensics/page.tsx',
    'app/api/core/[...path]/route.ts',
    'lib/coreApi.ts',
  ];
  for (const file of files) {
    assert.doesNotMatch(read(file), /NEXT_PUBLIC_CORE_API_KEY/);
  }
});

test('control tower route is canonical in nav and legacy keys route is removed', () => {
  // Routes live in CONSOLE_REGISTRY; validate via the JSON snapshot.
  const reg = JSON.parse(read('../../packages/navigation/navigation-registry.json'));
  const routes = reg.console.map((i) => i.route);
  assert.ok(routes.includes('/dashboard/control-tower'), 'control-tower must be in registry');
  assert.ok(!routes.includes('/dashboard/keys'), '/dashboard/keys must not exist — keys lives at /keys');
});

test('control tower snapshot and action routes are allowlisted in BFF', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  const requiredPaths = [
    'control-tower/snapshot',
    'keys',
    'admin/connectors/status',
    'admin/connectors',
    'admin/agent/devices',
    'admin/agent/quarantine',
    'admin/agent/unquarantine',
    'control-plane/lockers',
    'audit/export',
    'forensics/chain/verify',
  ];
  for (const route of requiredPaths) {
    assert.match(proxy, new RegExp(route.replace(/[-/]/g, (m) => `\\${m}`)));
  }
});
