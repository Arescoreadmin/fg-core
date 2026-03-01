const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

function listFilesRecursive(baseDir) {
  const out = [];
  for (const entry of fs.readdirSync(baseDir, { withFileTypes: true })) {
    const full = path.join(baseDir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listFilesRecursive(full));
      continue;
    }
    out.push(full);
  }
  return out;
}

test('client API uses BFF /api/core and does not depend on NEXT_PUBLIC_CORE_API_KEY', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /fetch\(`\/api\/core\$\{path\}`/);
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

test('alignment fetch builds absolute server URL from headers or explicit base URL', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /await import\('next\/headers'\)/);
  assert.match(coreApi, /x-forwarded-host/);
  assert.match(coreApi, /CONSOLE_BASE_URL/);
  assert.match(coreApi, /must point to loopback in development/);
});

test('proxy has strict route allowlist and blocks wildcard patterns', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /const PROXY_RULES/);
  assert.match(proxy, /Route\/method is not allowed by proxy policy/);
  assert.doesNotMatch(proxy, /prefix:\s*'\*'/);
});

test('proxy forwards browser session cookies and csrf header to admin gateway only', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.doesNotMatch(proxy, /X-API-Key/);
  assert.match(proxy, /headers\.set\('Cookie', cookie\)/);
  assert.match(proxy, /headers\.set\('X-CSRF-Token', csrfToken\)/);
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



test('console api routes do not reference core direct envs or core auth headers', () => {
  const apiRoot = path.join(__dirname, '..', 'app', 'api');
  const apiFiles = listFilesRecursive(apiRoot)
    .filter((file) => file.endsWith('.ts') || file.endsWith('.tsx'));

  for (const fullPath of apiFiles) {
    const content = fs.readFileSync(fullPath, 'utf8');
    assert.doesNotMatch(content, /CORE_API_URL/);
    assert.doesNotMatch(content, /CORE_API_KEY/);
    assert.doesNotMatch(content, /X-API-Key/);
  }
});

test('control tower route is canonical in nav and legacy keys route is removed', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.match(layout, /\/dashboard\/control-tower/);
  assert.doesNotMatch(layout, /\/dashboard\/keys/);
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
