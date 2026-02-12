const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

test('client API uses BFF /api/core and does not depend on NEXT_PUBLIC_CORE_API_KEY', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /fetch\('\/api\/core/);
  assert.doesNotMatch(coreApi, /NEXT_PUBLIC_CORE_API_KEY/);
  assert.doesNotMatch(coreApi, /NEXT_PUBLIC_CORE_API_URL/);
});

test('server proxy holds server-only key and forwards core requests', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /process\.env\.CORE_API_KEY/);
  assert.match(proxy, /headers\.set\('X-API-Key', CORE_API_KEY\)/);
});

test('proxy has route and method allowlists to avoid open privileged tunnel', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /const PROXY_RULES/);
  assert.match(proxy, /health\/live/);
  assert.match(proxy, /stats\/summary/);
  assert.match(proxy, /isProxyPathAllowed/);
  assert.match(proxy, /Route\/method is not allowed by proxy policy/);
  assert.match(proxy, /export async function HEAD/);
});

test('proxy response disables caching and does not forward browser auth/cookies', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /Cache-Control': 'no-store'/);
  assert.doesNotMatch(proxy, /request\.headers\.get\('cookie'\)/i);
  assert.doesNotMatch(proxy, /request\.headers\.get\('authorization'\)/i);
});

test('alignment artifact path includes SSRF safeguards', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /ALIGNMENT_ARTIFACT_HOST_ALLOWLIST must be set outside development/);
  assert.match(proxy, /isPrivateHost/);
  assert.match(proxy, /must use https outside development/);
});

test('decisions page wires server-side pagination params', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /params\.set\('limit'/);
  assert.match(coreApi, /params\.set\('offset'/);
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

test('decisions page includes empty-tenant empty-state copy', () => {
  const table = read('components/tables/DecisionsTable.tsx');
  assert.match(table, /No decisions for this tenant yet/);
});

test('forensics page normalizes cross-tenant response leak bucket', () => {
  const page = read('app/dashboard/forensics/page.tsx');
  assert.match(page, /Not found or forbidden for current tenant context/);
});
