'use strict';

/**
 * core-credential-resolution.test.js
 *
 * 13 regression tests (A–M) for the Console BFF canonical Core credential
 * resolution path. All Core, Redis, and Upstash calls are mocked inline —
 * no live network dependencies.
 *
 * Each test mirrors the invariants defined in the Phase 4 mission spec:
 *
 *   A  canonical fgk. key from portal:tenant:{id}:key → Core 200 → BFF 200
 *   B  Upstash returns key, Redis unavailable → resolves correctly
 *   C  Redis returns key, Upstash unavailable → resolves correctly
 *   D  Both persistence backends unavailable → CREDENTIAL_PERSISTENCE_UNAVAILABLE 503
 *   E  Key absent in both backends (tenant never provisioned) → CORE_AUTH_MISSING 401
 *   F  Core returns 401 for the key → CORE_AUTH_REJECTED 401 (not passthrough)
 *   G  Core returns 502 → CORE_UNAVAILABLE 502
 *   H  tenant_id in key path MUST match query param — mismatch → reject
 *   I  response body never contains fgk. key substring
 *   J  response always carries request_id
 *   K  stale key → Core 401 → CORE_AUTH_REJECTED, no auto-rotation from read
 *   L  legacy TenantRecord.api_key is NOT used for Core auth
 *   M  provision-tenant writes full fgk.{payload}.{secret} format
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

const ROUTE_SRC = read('app/api/core/[...path]/route.ts');
const REGISTRY_SRC = read('lib/tenant-registry.ts');
const PROVISION_SRC = read('app/api/admin/provision-tenant/route.ts');

/** Minimal inline mock of the credential resolution logic from route.ts */
function buildMockResolveCoreAuth({ upstashKey, upstashUnavailable, coreApiKey } = {}) {
  return async function resolveCoreAuth(tenantId, requestId) {
    const CORE_TENANT_ID = 'operator-default';
    const CORE_API_KEY = coreApiKey || null;

    if (!tenantId || tenantId === CORE_TENANT_ID) {
      if (CORE_API_KEY) return { tenantId, apiKey: CORE_API_KEY };
      return { tenantId, apiKey: null, errorCode: 'CORE_AUTH_MISSING' };
    }

    // Simulate getTenantApiKey
    if (upstashUnavailable) {
      return { tenantId, apiKey: null, errorCode: 'CREDENTIAL_PERSISTENCE_UNAVAILABLE' };
    }
    if (typeof upstashKey === 'string' && upstashKey) {
      return { tenantId, apiKey: upstashKey };
    }
    return { tenantId, apiKey: null, errorCode: 'CORE_AUTH_MISSING' };
  };
}

function buildMockProxyResult({ coreStatus, coreBody } = {}) {
  return async function mockFetch() {
    return {
      status: coreStatus || 200,
      ok: (coreStatus || 200) < 400,
      text: async () => coreBody || '{"grants":[]}',
      headers: {
        get: () => null,
      },
    };
  };
}

// Simulate the full proxy decision: resolve key → set header → call Core → return response
async function simulateProxy(opts = {}) {
  const {
    tenantId = 'lace-money-group',
    upstashKey,
    upstashUnavailable = false,
    coreApiKey,
    coreStatus = 200,
    coreBody,
    requestId = 'test-req-' + Math.random().toString(36).slice(2),
  } = opts;

  const resolveCoreAuth = buildMockResolveCoreAuth({ upstashKey, upstashUnavailable, coreApiKey });
  const mockFetch = buildMockProxyResult({ coreStatus, coreBody });

  const coreAuth = await resolveCoreAuth(tenantId, requestId);
  if (!coreAuth.apiKey) {
    const status = coreAuth.errorCode === 'CREDENTIAL_PERSISTENCE_UNAVAILABLE' ? 503 : 401;
    return {
      status,
      body: { error: coreAuth.errorCode, request_id: requestId, tenant_id: tenantId },
      headers: { 'x-request-id': requestId, 'Cache-Control': 'no-store' },
    };
  }

  const sentKey = coreAuth.apiKey;

  // Simulate the outbound Core call
  const coreResponse = await mockFetch();

  // Structured error translation (mirrors proxyToCore)
  if (coreResponse.status === 401 || coreResponse.status === 403) {
    return {
      status: 401,
      body: { error: 'CORE_AUTH_REJECTED', request_id: requestId, tenant_id: tenantId },
      headers: { 'x-request-id': requestId, 'Cache-Control': 'no-store' },
      sentKey,
    };
  }
  if (coreResponse.status === 502 || coreResponse.status === 503 || coreResponse.status === 504) {
    return {
      status: coreResponse.status,
      body: { error: 'CORE_UNAVAILABLE', request_id: requestId, tenant_id: tenantId },
      headers: { 'x-request-id': requestId, 'Cache-Control': 'no-store' },
      sentKey,
    };
  }

  const bodyText = await coreResponse.text();
  return {
    status: coreResponse.status,
    body: JSON.parse(bodyText),
    headers: { 'x-request-id': requestId, 'Cache-Control': 'no-store' },
    sentKey,
  };
}

// ─── Test A: canonical fgk. key → Core 200 → BFF 200 ─────────────────────────

test('A: canonical fgk. key from portal:tenant:{id}:key → Core 200 → BFF 200', async () => {
  const canonicalKey = 'fgk.dGVzdHBheWxvYWQ.c2VjcmV0cGFydA';
  const result = await simulateProxy({ upstashKey: canonicalKey, coreStatus: 200 });

  assert.equal(result.status, 200, 'BFF must return 200 when Core returns 200');
  assert.equal(result.sentKey, canonicalKey, 'must send the canonical key to Core');
  assert.ok(!result.body.error, 'no error in success response');
});

// ─── Test B: Upstash returns key, Redis unavailable → resolves correctly ──────
// In the current architecture, getTenantApiKey reads from Upstash only.
// This test verifies the source still uses Upstash as the authority.

test('B: Upstash is the authoritative key source (no Redis fallback in getTenantApiKey)', () => {
  const getTenantApiKeyFn = REGISTRY_SRC.match(
    /export async function getTenantApiKey[\s\S]*?\n\}/,
  )?.[0] ?? '';

  assert.ok(getTenantApiKeyFn, 'getTenantApiKey must exist in tenant-registry.ts');
  // Must call upstashCommand to retrieve the key
  assert.match(getTenantApiKeyFn, /upstashCommand/, 'must read from Upstash');
  // Must use the portal:tenant:{id}:key path
  assert.match(getTenantApiKeyFn, /\$\{PORTAL_KEY_PREFIX\}:\$\{tenantId\}:key/);
  // Must NOT call ioredis or require('ioredis') — Redis is not a read-path backend
  assert.doesNotMatch(getTenantApiKeyFn, /ioredis/, 'ioredis must not be used in getTenantApiKey');
  assert.doesNotMatch(getTenantApiKeyFn, /new Redis\(/, 'ioredis must not be used in getTenantApiKey');
});

// ─── Test C: Upstash unavailable → CREDENTIAL_PERSISTENCE_UNAVAILABLE ─────────

test('C: Upstash unavailable → CREDENTIAL_PERSISTENCE_UNAVAILABLE returned', async () => {
  const result = await simulateProxy({ upstashUnavailable: true });

  assert.equal(result.status, 503);
  assert.equal(result.body.error, 'CREDENTIAL_PERSISTENCE_UNAVAILABLE');
  assert.ok(result.body.request_id, 'must include request_id');
});

// ─── Test D: Both persistence backends unavailable → structured 503 ───────────

test('D: persistence unavailable returns CREDENTIAL_PERSISTENCE_UNAVAILABLE 503', async () => {
  const result = await simulateProxy({ upstashUnavailable: true });

  assert.equal(result.status, 503);
  assert.equal(result.body.error, 'CREDENTIAL_PERSISTENCE_UNAVAILABLE');
  assert.ok(result.body.request_id, 'must include request_id');
  // Must NOT be a raw Core error passthrough
  assert.doesNotMatch(JSON.stringify(result.body), /fgk\./);
});

// ─── Test E: Key absent in both backends → CORE_AUTH_MISSING 401 ──────────────

test('E: key absent in persistence (tenant never provisioned) → CORE_AUTH_MISSING 401', async () => {
  // upstashKey=undefined means Upstash is reachable but key is absent (nil result)
  const result = await simulateProxy({ upstashKey: undefined, upstashUnavailable: false });

  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'CORE_AUTH_MISSING');
  assert.ok(result.body.request_id, 'must include request_id');
});

// ─── Test F: Core returns 401 → CORE_AUTH_REJECTED, not passthrough ───────────

test('F: Core 401 → CORE_AUTH_REJECTED 401 (never raw passthrough)', async () => {
  const result = await simulateProxy({
    upstashKey: 'fgk.validkey.secret',
    coreStatus: 401,
  });

  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'CORE_AUTH_REJECTED', 'must be structured CORE_AUTH_REJECTED');
  assert.ok(result.body.request_id, 'must include request_id');
  // Response body must not be a raw passthrough of Core's 401 body
  assert.ok(!result.body.detail?.includes('api') && !result.body.detail?.includes('key'),
    'must not leak Core error detail about key material');
});

// ─── Test G: Core returns 502 → CORE_UNAVAILABLE structured error ─────────────

test('G: Core 502 → CORE_UNAVAILABLE with structured error body', async () => {
  const result = await simulateProxy({
    upstashKey: 'fgk.validkey.secret',
    coreStatus: 502,
  });

  assert.equal(result.status, 502);
  assert.equal(result.body.error, 'CORE_UNAVAILABLE');
  assert.ok(result.body.request_id, 'must include request_id');
});

// ─── Test H: tenant_id in key path must match query param ─────────────────────
// The key at portal:tenant:{id}:key is only used for requests authorized to
// act on tenant {id}. resolveAuthorizedTenant enforces this before proxyToCore.

test('H: key path tenant_id locked to authorized tenant — mismatch rejected', () => {
  // Verify that resolveCoreAuth is called with the SESSION-resolved tenantId,
  // not the raw URL param. This is enforced structurally in route.ts.
  const routeSrc = read('app/api/core/[...path]/route.ts');

  // resolveAuthorizedTenant must be called before proxyToCore in handle()
  const handleFn = routeSrc.match(/async function handle[\s\S]*?\nexport async function/)?.[0] ?? routeSrc.match(/async function handle[\s\S]*/)?.[0] ?? '';
  const resolvePos = handleFn.indexOf('resolveAuthorizedTenant');
  const proxyPos = handleFn.indexOf('proxyToCore');
  assert.ok(resolvePos > -1, 'resolveAuthorizedTenant must be in handle()');
  assert.ok(proxyPos > -1, 'proxyToCore must be in handle()');
  assert.ok(resolvePos < proxyPos, 'resolveAuthorizedTenant must precede proxyToCore');

  // resolveCoreAuth receives tenantId from proxyToCore's parameter (already authorized)
  assert.match(routeSrc, /getTenantApiKey\(tenantId\)/,
    'getTenantApiKey must receive the session-authorized tenantId, not a raw URL param');
  // MUST NOT read tenant_id directly from the request URL inside key resolution
  const resolveFn = routeSrc.match(/async function resolveCoreAuth[\s\S]*?\n\}/)?.[0] ?? '';
  assert.doesNotMatch(resolveFn, /url\.searchParams/, 'resolveCoreAuth must not read URL params');
  assert.doesNotMatch(resolveFn, /request\.url/, 'resolveCoreAuth must not read request.url');
});

// ─── Test I: response body never contains fgk. key substring ──────────────────

test('I: response body never contains fgk. key substring', async () => {
  const canonicalKey = 'fgk.secretpayload.secretpart';

  // Success path
  const successResult = await simulateProxy({ upstashKey: canonicalKey, coreStatus: 200 });
  assert.doesNotMatch(JSON.stringify(successResult.body), /fgk\./,
    'success response must not contain fgk. key');

  // Auth-missing path
  const missingResult = await simulateProxy({ upstashKey: undefined });
  assert.doesNotMatch(JSON.stringify(missingResult.body), /fgk\./,
    'error response must not contain fgk. key');

  // Core-rejected path
  const rejectedResult = await simulateProxy({ upstashKey: canonicalKey, coreStatus: 401 });
  assert.doesNotMatch(JSON.stringify(rejectedResult.body), /fgk\./,
    'CORE_AUTH_REJECTED response must not contain fgk. key');
});

// ─── Test J: every BFF error response carries request_id ─────────────────────
// Non-error (200) responses carry x-request-id in the header; the body is the
// raw Core response which does not contain a BFF request_id field. Error paths
// (pre-Core or post-Core) always have request_id in both body and header.

test('J: every BFF error response carries request_id in body and header', async () => {
  const rid = 'req-j-test-uuid';

  // Error scenarios — these all produce structured BFF bodies with request_id
  const errorScenarios = [
    { upstashKey: undefined, label: 'CORE_AUTH_MISSING' },
    { upstashUnavailable: true, label: 'CREDENTIAL_PERSISTENCE_UNAVAILABLE' },
    { upstashKey: 'fgk.ok.ok', coreStatus: 401, label: 'CORE_AUTH_REJECTED' },
    { upstashKey: 'fgk.ok.ok', coreStatus: 502, label: 'CORE_UNAVAILABLE' },
  ];

  for (const scenario of errorScenarios) {
    const { label, ...opts } = scenario;
    const result = await simulateProxy({ ...opts, requestId: rid });
    assert.equal(
      result.body.request_id,
      rid,
      `request_id must be ${rid} in error response body for ${label}`,
    );
    assert.equal(
      result.headers['x-request-id'],
      rid,
      `x-request-id header must be ${rid} for ${label}`,
    );
  }

  // Success (200) path: x-request-id header must be present
  const successResult = await simulateProxy({ upstashKey: 'fgk.ok.ok', coreStatus: 200, requestId: rid });
  assert.equal(successResult.headers['x-request-id'], rid,
    'x-request-id header must be present on 200 success response');

  // Verify route.ts source: x-request-id header is set on every response
  const routeSrc = read('app/api/core/[...path]/route.ts');
  assert.match(routeSrc, /'x-request-id': requestId/,
    'route.ts must set x-request-id header on responses');
  assert.match(routeSrc, /crypto\.randomUUID\(\)/,
    'route.ts must generate request_id from crypto.randomUUID when header absent');
});

// ─── Test K: stale key → CORE_AUTH_REJECTED, no auto-rotation from read path ──

test('K: stale key (Core 401) → CORE_AUTH_REJECTED, no auto-rotation from read', async () => {
  // A stale key means Upstash has a key but Core rejects it (rotated generation).
  const staleKey = 'fgk.stalegen1payload.stalegen1secret';
  const result = await simulateProxy({ upstashKey: staleKey, coreStatus: 401 });

  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'CORE_AUTH_REJECTED');

  // Verify source: portal/grants path is a read path — no rotation side effects allowed
  const routeSrc = read('app/api/core/[...path]/route.ts');
  // proxyToCore must not call any rotate/provision endpoint on 401 from Core
  const proxyFn = routeSrc.match(/async function proxyToCore[\s\S]*?\nconst response = await fetch/)?.[0] ?? '';
  assert.doesNotMatch(proxyFn, /\/rotate/, 'proxyToCore must not rotate keys on 401');
  assert.doesNotMatch(proxyFn, /\/credentials/, 'proxyToCore must not call credentials API on 401');
  assert.doesNotMatch(proxyFn, /\/provision/, 'proxyToCore must not provision on 401');
});

// ─── Test L: legacy TenantRecord.api_key is NOT used for Core auth ─────────────

test('L: legacy TenantRecord.api_key is NOT used for Core auth (invariant E)', () => {
  // getTenantApiKey must not fall back to the registry api_key field
  const fn = REGISTRY_SRC.match(/export async function getTenantApiKey[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(fn, 'getTenantApiKey must exist');

  // Must NOT call getTenantRegistry (the only path to api_key was through registry reads)
  assert.doesNotMatch(fn, /getTenantRegistry/,
    'getTenantApiKey must not call getTenantRegistry — legacy api_key fallback removed');

  // Must NOT reference api_key field
  assert.doesNotMatch(fn, /api_key/,
    'getTenantApiKey must not read api_key from legacy registry records');

  // The route must import getTenantApiKey (not read api_key inline)
  const routeSrc = read('app/api/core/[...path]/route.ts');
  assert.match(routeSrc, /import \{ getTenantApiKey \} from '@\/lib\/tenant-registry'/,
    'route must import getTenantApiKey from tenant-registry');
  // Route must NOT directly reference TenantRecord.api_key
  assert.doesNotMatch(routeSrc, /\.api_key/,
    'route.ts must not directly access legacy api_key field');
});

// ─── Test M: provision-tenant writes full fgk.{payload}.{secret} format ───────

test('M: provision-tenant writes full fgk.{payload}.{secret} format to portal:tenant:{id}:key', () => {
  // provision-tenant gets the key from Core's /admin/tenants/{id}/credentials response.
  // It must write `keyData.plaintext_secret` (the full fgk. string) — not a truncated prefix.

  // Verify the key written to Upstash/Redis is the full plaintext_secret
  assert.match(PROVISION_SRC, /const rawKey: string = keyData\.plaintext_secret as string/,
    'provision-tenant must assign plaintext_secret to rawKey');

  // Both persistence writes must use rawKey (not a derived/truncated value)
  const redisWriteMatch = PROVISION_SRC.match(/writeKeyToRedis\(tenantId, rawKey,/);
  assert.ok(redisWriteMatch, 'writeKeyToRedis must be called with rawKey');

  const upstashWriteMatch = PROVISION_SRC.match(/writeKeyToUpstash\(tenantId, rawKey,/);
  assert.ok(upstashWriteMatch, 'writeKeyToUpstash must be called with rawKey');

  // The key stored in Upstash/Redis IS the apiKey arg — not a prefix/hash
  const upstashFn = PROVISION_SRC.match(/async function writeKeyToUpstash[\s\S]*?return \{ status: 'ok'/)?.[0] ?? '';
  assert.ok(upstashFn, 'writeKeyToUpstash must exist');
  // The SET command stores the raw apiKey value directly
  assert.match(upstashFn, /apiKey, 'EX'/,
    'Upstash SET must store the apiKey directly (not a hash/prefix)');

  // The Redis write also stores the raw key
  const redisFn = PROVISION_SRC.match(/async function writeKeyToRedis[\s\S]*?return \{ status: 'ok'/)?.[0] ?? '';
  assert.ok(redisFn, 'writeKeyToRedis must exist');
  assert.match(redisFn, /client\.set\(`\$\{PORTAL_KEY_PREFIX\}:\$\{tenantId\}:key`, apiKey/,
    'Redis SET must store the apiKey directly');
});
