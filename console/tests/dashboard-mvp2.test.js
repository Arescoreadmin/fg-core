const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
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

test('tenant query override is disabled by default and gated to development flag', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /FG_CONSOLE_ALLOW_TENANT_QUERY_OVERRIDE/);
  assert.match(proxy, /NODE_ENV === 'development'/);
  assert.match(proxy, /if \(ALLOW_TENANT_QUERY_OVERRIDE && queryTenant\) return queryTenant/);
});

test('proxy never forwards browser cookies or authorization headers', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /headers\.set\('X-API-Key', CORE_API_KEY\)/);
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
