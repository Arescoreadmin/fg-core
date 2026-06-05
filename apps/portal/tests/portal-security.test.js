/**
 * portal-security.test.js
 *
 * Static structural tests — read source files and assert security contracts.
 * No runtime, no DOM, no Next.js bootstrap required.
 *
 * Mirrors the pattern used in apps/console/tests/*.test.js.
 */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ---------------------------------------------------------------------------
// Portal API client — BFF-only contract
// ---------------------------------------------------------------------------

test('portalApi routes all requests through /api/core BFF — never direct to backend', () => {
  const api = read('lib/portalApi.ts');
  assert.match(api, /const BASE = '\/api\/core'/);
  assert.match(api, /fetch\(`\$\{BASE\}\$\{path\}`/);
});

test('portalApi never sends tenant_id via qs.set or in a JSON body', () => {
  const api = read('lib/portalApi.ts');
  // Must not appear in any runtime call — only permitted in comments
  assert.doesNotMatch(api, /qs\.set\('tenant_id'/);
  assert.doesNotMatch(api, /tenant_id:\s/);
});

test('portalApi throws PortalApiError with status code and code string', () => {
  const api = read('lib/portalApi.ts');
  assert.match(api, /class PortalApiError extends Error/);
  assert.match(api, /public readonly status: number/);
  assert.match(api, /public readonly code: string/);
});

// ---------------------------------------------------------------------------
// BFF proxy — write allowlist and header forwarding
// ---------------------------------------------------------------------------

test('BFF PORTAL_WRITE_PATTERNS is an explicit allowlist with no wildcard prefixes', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /const PORTAL_WRITE_PATTERNS/);
  // Attestations pattern present
  assert.match(proxy, /governance\/assets.*attestations/);
  // Report verify pattern present
  assert.match(proxy, /reports.*verify/);
  // Finding PATCH pattern present (PR 32 closed-loop) — comment has PATCH before findings
  assert.match(proxy, /PATCH.*findings/);
  // No blanket wildcard prefix
  assert.doesNotMatch(proxy, /prefix:\s*['"]\*/);
});

test('BFF exports PATCH handler for finding closed-loop resolution', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /export async function PATCH/);
});

test('BFF never forwards Authorization or Cookie headers to core API', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.doesNotMatch(proxy, /headers\.set\('Authorization'/i);
  assert.doesNotMatch(proxy, /headers\.set\('Cookie'/i);
  assert.doesNotMatch(proxy, /request\.headers\.get\('cookie'/i);
  assert.doesNotMatch(proxy, /request\.headers\.get\('authorization'/i);
});

test('BFF injects X-Tenant-ID from server-resolved context — never from client request', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /resolvePortalTenant/);
  assert.match(proxy, /DEMO_TENANT_ALLOWLIST\.includes\(sessionTenantId\)/);
  assert.match(proxy, /headers\.set\('X-Tenant-ID', tenantId\)/);
  assert.match(proxy, /headers\.set\('X-API-Key', coreApiKey\)/);
  // Client-supplied tenant_id is actively stripped from query params.
  assert.match(proxy, /query\.delete\('tenant_id'\)/);
});

test('BFF has module-level rate limiter and returns 429 on breach', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /_rlBuckets/);
  assert.match(proxy, /Too many requests/);
  assert.match(proxy, /429/);
});

test('BFF error response includes detail, code, and request_id — no-store', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /detail: message/);
  assert.match(proxy, /code: `HTTP_\$\{status\}`/);
  assert.match(proxy, /request_id: requestId/);
  assert.match(proxy, /'Cache-Control': 'no-store'/);
});

test('BFF blocks private hosts in non-development environments', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /isPrivateHost/);
  assert.match(proxy, /NODE_ENV !== 'development' && isPrivateHost/);
  assert.match(proxy, /Target host is not allowed/);
});

// ---------------------------------------------------------------------------
// Portal middleware — auth gate
// ---------------------------------------------------------------------------

test('portal middleware.ts exists and gates all non-login routes', () => {
  const mw = read('middleware.ts');
  assert.match(mw, /\/login/);
  // Must redirect unauthenticated requests
  assert.match(mw, /NextResponse\.redirect/);
});

// ---------------------------------------------------------------------------
// Engagement store — SSR safety
// ---------------------------------------------------------------------------

test('engagementStore guards localStorage access with typeof window check', () => {
  const store = read('lib/engagementStore.ts');
  assert.match(store, /typeof window === 'undefined'/);
  assert.match(store, /localStorage\.getItem/);
  assert.match(store, /localStorage\.setItem/);
  assert.match(store, /localStorage\.removeItem/);
});

test('engagementStore uses fg_portal_eid as the storage key', () => {
  const store = read('lib/engagementStore.ts');
  assert.match(store, /fg_portal_eid/);
});
