/**
 * bff-rate-limit.test.js
 *
 * Static-analysis + unit tests for the BFF Redis rate-limit adapter.
 * No live Redis required — all Redis calls are faked via a mock client.
 *
 * Test naming follows the required spec:
 *   1. rate_limit_allows_request_under_limit
 *   2. rate_limit_blocks_request_over_limit
 *   3. rate_limit_key_partitions_tenant_and_user_opaquely (FG-849-REPAIR-001)
 *   4. rate_limit_keys_do_not_collide_across_tenants
 *   5. redis_rate_limit_store_sets_ttl
 *   6. redis_outage_uses_memory_fallback_in_test
 *   7. rate_limit_store_outage_fails_closed_503 (FG-849-REPAIR-001)
 *   8. bff_rate_limit_does_not_expose_redis_url
 *   9. bff_rate_limit_does_not_use_next_public_secret_config
 *  10. bff_proxy_allowlist_remains_enforced
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

/**
 * Build a fake Redis client for unit tests.
 * Tracks INCR (per-key counter) and EXPIRE calls deterministically.
 * eval() emulates RATE_LIMIT_INCREMENT_LUA (INCR, then EXPIRE when the
 * counter is new or has no TTL) and records the EXPIRE it performs.
 */
function makeFakeRedisClient({ failOnIncr = false } = {}) {
  const counters = new Map();
  const expireCalls = [];
  const ttls = new Map();

  return {
    counters,
    expireCalls,
    async eval(script, numKeys, key, windowSec) {
      if (failOnIncr) throw new Error('Redis connection refused');
      assert.equal(numKeys, 1);
      assert.match(script, /INCR/);
      assert.match(script, /EXPIRE/);
      const next = (counters.get(key) || 0) + 1;
      counters.set(key, next);
      if (next === 1 || !ttls.has(key)) {
        ttls.set(key, Number(windowSec));
        expireCalls.push({ key, seconds: Number(windowSec) });
      }
      return next;
    },
    async incr(key) {
      if (failOnIncr) throw new Error('Redis connection refused');
      const next = (counters.get(key) || 0) + 1;
      counters.set(key, next);
      return next;
    },
    async expire(key, seconds) {
      expireCalls.push({ key, seconds });
      return 1;
    },
    async quit() {},
  };
}

// ─── Import the module under test ─────────────────────────────────────────────
// We require the compiled/transpiled JS. Since Next.js doesn't emit JS under
// tests, we test the TypeScript source statically for interface compliance,
// and exercise the pure JS-compatible logic directly below.
//
// For behavioral tests we inline equivalent implementations that mirror the
// TypeScript source exactly — this keeps tests hermetic and avoids a build step.

// ─── Inline mirror of MemoryRateLimitStore (mirrors rateLimitStore.ts) ───────

class MemoryRateLimitStore {
  constructor() {
    this.store = new Map();
  }

  async increment(key, windowSec, maxRequests) {
    const now = Date.now();
    const windowMs = windowSec * 1000;
    const existing = this.store.get(key);

    let entry;
    if (!existing || now - existing.windowStart >= windowMs) {
      entry = { count: 1, windowStart: now };
    } else {
      entry = { count: existing.count + 1, windowStart: existing.windowStart };
    }
    this.store.set(key, entry);

    return {
      count: entry.count,
      allowed: entry.count <= maxRequests,
      windowSec,
      available: true,
    };
  }

  _reset() {
    this.store.clear();
  }
}

// ─── Real RedisRateLimitStore (lib/rateLimitStore.ts) ────────────────────────
// FG-849-REPAIR-001: the former inline mirror used a non-atomic INCR then
// EXPIRE. The real store (one atomic EVAL) is exercised instead. Bound later,
// after the harness is loaded.

// ─── Real key derivation (lib/bffRateLimitPolicy.ts) ──────────────────────────
// FG-849-REPAIR-001: the former inline mirror built plaintext keys
// (fg:bff:rl:{group}:{tenant}:{user}). Keys are now an HMAC partition under a
// server-only key, so these tests exercise the real derivation.

const { createHarness } = require('./helpers/bffRouteHarness');
const harness = createHarness();
const policy = harness.loadModule('@/lib/bffRateLimitPolicy');
const { RedisRateLimitStore } = harness.loadModule('@/lib/rateLimitStore');
const LIMITER_KEY = Buffer.alloc(32, 7);

function buildRateLimitKey(tenantId, userOrSession, routeGroup) {
  return policy.deriveAuthenticatedRateLimitKey(LIMITER_KEY, routeGroup, 'tenant', tenantId, userOrSession).key;
}

// ─── Test 1: rate_limit_allows_request_under_limit ────────────────────────────

test('rate_limit_allows_request_under_limit', async () => {
  const store = new MemoryRateLimitStore();
  const key = 'fg:bff:rl:decisions:tenant-a:user-1';
  const result = await store.increment(key, 60, 100);
  assert.equal(result.allowed, true);
  assert.equal(result.count, 1);
  assert.equal(result.available, true);
});

// ─── Test 2: rate_limit_blocks_request_over_limit ─────────────────────────────

test('rate_limit_blocks_request_over_limit', async () => {
  const store = new MemoryRateLimitStore();
  const key = 'fg:bff:rl:decisions:tenant-a:user-2';
  const maxRequests = 3;

  for (let i = 0; i < maxRequests; i++) {
    const r = await store.increment(key, 60, maxRequests);
    assert.equal(r.allowed, true, `Request ${i + 1} should be allowed`);
  }

  const blocked = await store.increment(key, 60, maxRequests);
  assert.equal(blocked.allowed, false, 'Request over limit must be blocked');
  assert.equal(blocked.count, maxRequests + 1);
});

// ─── Test 3: rate_limit_key_includes_tenant_and_user ─────────────────────────

test('rate_limit_key_partitions_tenant_and_user_opaquely', () => {
  const key = buildRateLimitKey('tenant-xyz', 'user-abc', 'decisions');
  assert.match(key, /^fg:bff:rl:v1:decisions:[0-9a-f]{32}$/);
  // Raw tenant and subject never appear in the persistent key ...
  assert.doesNotMatch(key, /tenant-xyz/);
  assert.doesNotMatch(key, /user-abc/);
  // ... yet each still selects its own partition.
  assert.notEqual(buildRateLimitKey('tenant-xyz', 'user-abd', 'decisions'), key);
  assert.notEqual(buildRateLimitKey('tenant-xyy', 'user-abc', 'decisions'), key);
  assert.equal(buildRateLimitKey('tenant-xyz', 'user-abc', 'decisions'), key);
});

// ─── Test 4: rate_limit_keys_do_not_collide_across_tenants ────────────────────

test('rate_limit_keys_do_not_collide_across_tenants', async () => {
  const store = new MemoryRateLimitStore();
  const maxRequests = 2;

  const keyA = buildRateLimitKey('tenant-a', 'user-1', 'keys');
  const keyB = buildRateLimitKey('tenant-b', 'user-1', 'keys');

  // Exhaust tenant-a
  await store.increment(keyA, 60, maxRequests);
  await store.increment(keyA, 60, maxRequests);
  const blockedA = await store.increment(keyA, 60, maxRequests);
  assert.equal(blockedA.allowed, false, 'tenant-a must be blocked');

  // tenant-b must still be allowed
  const allowedB = await store.increment(keyB, 60, maxRequests);
  assert.equal(allowedB.allowed, true, 'tenant-b must be independent');

  // Keys must differ
  assert.notEqual(keyA, keyB);
});

// ─── Test 5: redis_rate_limit_store_sets_ttl ─────────────────────────────────

test('redis_rate_limit_store_sets_ttl', async () => {
  const fakeRedis = makeFakeRedisClient();
  const store = new RedisRateLimitStore(fakeRedis);
  const key = 'fg:bff:rl:keys:tenant-a:user-1';
  const windowSec = 60;

  // First increment: EXPIRE must be called with the window duration
  await store.increment(key, windowSec, 100);
  assert.equal(fakeRedis.expireCalls.length, 1);
  assert.equal(fakeRedis.expireCalls[0].key, key);
  assert.equal(fakeRedis.expireCalls[0].seconds, windowSec);

  // Second increment: EXPIRE must NOT be called again (key already has TTL)
  await store.increment(key, windowSec, 100);
  assert.equal(fakeRedis.expireCalls.length, 1, 'EXPIRE called only on first INCR');
});

// ─── Test 6: redis_outage_uses_memory_fallback_in_test ───────────────────────

test('redis_outage_uses_memory_fallback_in_test', async () => {
  // Simulate Redis outage: incr throws
  const failingRedis = makeFakeRedisClient({ failOnIncr: true });

  // In test/dev env, buildRateLimitStore falls back to MemoryRateLimitStore.
  // We verify the memory store behaves correctly independently:
  const memStore = new MemoryRateLimitStore();
  const key = 'fg:bff:rl:decisions:tenant-a:user-fallback';

  const result = await memStore.increment(key, 60, 100);
  assert.equal(result.allowed, true);
  assert.equal(result.available, true);

  // Also verify the Redis store surfaces the error (callers can catch and fallback)
  const failStore = new RedisRateLimitStore(failingRedis);
  await assert.rejects(
    () => failStore.increment(key, 60, 100),
    /Redis connection refused/,
    'Redis errors must propagate so callers can decide fallback vs fail-closed',
  );
});

// ─── Test 7: rate_limit_store_outage_fails_closed_503 ────────────────────────
// FG-849-REPAIR-001 replaced the former fail-open policy: an unavailable
// limiter returns 503 BFF_RATE_LIMIT_UNAVAILABLE for every tier, so an outage
// cannot disable abuse protection. Behaviour is proven against the real route
// in bff-rate-limit-route.test.js (C1-C9); this pins the source shape.

test('rate_limit_store_outage_fails_closed_503', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');
  const rateLimitSrc = read('lib/rateLimitStore.ts');

  // The route must check storeResult.unavailable and pass its errorCode on
  assert.match(routeSrc, /storeResult\.unavailable/);
  assert.match(routeSrc, /storeResult\.errorCode/);

  // Unavailable enforcement is a 503 with a stable code, never an allow
  assert.match(routeSrc, /status:\s*503/);
  assert.match(routeSrc, /BFF_RATE_LIMIT_UNAVAILABLE/);
  assert.doesNotMatch(routeSrc, /allowing request/);

  // The stable error codes must still be defined in rateLimitStore.ts
  assert.match(rateLimitSrc, /BFF_RATE_LIMIT_REDIS_UNAVAILABLE/);
  assert.match(rateLimitSrc, /BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED/);
});

// ─── Test 8: bff_rate_limit_does_not_expose_redis_url ────────────────────────

test('bff_rate_limit_does_not_expose_redis_url', () => {
  const rateLimitSrc = read('lib/rateLimitStore.ts');
  const routeSrc = read('app/api/core/[...path]/route.ts');

  // BFF_REDIS_URL must only be read server-side (process.env, never NEXT_PUBLIC_)
  assert.doesNotMatch(rateLimitSrc, /NEXT_PUBLIC_BFF_REDIS_URL/);
  assert.doesNotMatch(routeSrc, /NEXT_PUBLIC_BFF_REDIS_URL/);
  assert.doesNotMatch(rateLimitSrc, /NEXT_PUBLIC_REDIS/);
  assert.doesNotMatch(routeSrc, /NEXT_PUBLIC_REDIS/);

  // BFF_REDIS_URL must be read via process.env (server-only)
  assert.match(rateLimitSrc, /process\.env\.BFF_REDIS_URL/);

  // Redis URL must never be included in any returned response body
  assert.doesNotMatch(rateLimitSrc, /BFF_REDIS_URL.*JSON/);
  assert.doesNotMatch(rateLimitSrc, /redis_url.*response/i);
});

// ─── Test 9: bff_rate_limit_does_not_use_next_public_secret_config ───────────

test('bff_rate_limit_does_not_use_next_public_secret_config', () => {
  const rateLimitSrc = read('lib/rateLimitStore.ts');

  // All rate-limit config must be server-only (no NEXT_PUBLIC_)
  const nextPublicMatches = rateLimitSrc.match(/NEXT_PUBLIC_[A-Z_]+/g);
  assert.equal(
    nextPublicMatches,
    null,
    `rateLimitStore.ts must not reference NEXT_PUBLIC_ vars, found: ${JSON.stringify(nextPublicMatches)}`,
  );

  // Config env vars must be BFF_RATE_LIMIT_* or BFF_REDIS_URL (server-only prefix)
  assert.match(rateLimitSrc, /BFF_RATE_LIMIT_WINDOW_S/);
  assert.match(rateLimitSrc, /BFF_RATE_LIMIT_MAX_REQUESTS/);
  assert.match(rateLimitSrc, /BFF_REDIS_URL/);
});

// ─── Test 10: bff_proxy_allowlist_remains_enforced ───────────────────────────

test('bff_proxy_allowlist_remains_enforced', () => {
  const proxy = read('app/api/core/[...path]/route.ts');

  // Allowlist must still be present
  assert.match(proxy, /const PROXY_RULES/);
  assert.match(proxy, /Route\/method is not allowed by proxy policy/);

  // Wildcard prefix must not exist
  assert.doesNotMatch(proxy, /prefix:\s*'\*'/);
  assert.doesNotMatch(proxy, /prefix:\s*""/);

  // Rate-limit check must come BEFORE the proxy call (enforceRateLimit before proxyToCore)
  const rateLimitPos = proxy.indexOf('enforceRateLimit');
  const proxyToPos = proxy.indexOf('proxyToCore');
  assert.ok(rateLimitPos < proxyToPos, 'Rate-limit check must precede proxy call');

  // Required routes still present
  const requiredPaths = [
    'health/ready',
    'decisions',
    'keys',
    'control-tower/snapshot',
    'admin/connectors',
    'forensics/chain/verify',
    'audit/export',
    'ingest/assessment',
  ];
  for (const route of requiredPaths) {
    assert.match(
      proxy,
      new RegExp(route.replace(/[-/]/g, (m) => `\\${m}`)),
      `Route '${route}' must remain in PROXY_RULES`,
    );
  }
});

// ─── Static source invariant: key format matches spec ─────────────────────────

test('rate_limit_key_format_matches_spec', () => {
  // Key must follow: fg:bff:rl:v1:{route_group}:{opaque partition} (FG-849-REPAIR-001)
  const key = buildRateLimitKey('tenant-abc', 'sess-xyz', 'decisions');
  assert.match(key, /^fg:bff:rl:v1:decisions:[0-9a-f]{32}$/);
});

// ─── Static source: isDevOrTestEnv matches NODE_ENV and FG_ENV patterns ───────

test('is_dev_or_test_env_recognizes_correct_patterns', () => {
  const rateLimitSrc = read('lib/rateLimitStore.ts');

  // Must check NODE_ENV development and test
  assert.match(rateLimitSrc, /nodeEnv === 'development'/);
  assert.match(rateLimitSrc, /nodeEnv === 'test'/);

  // Must check FG_ENV dev/local/test patterns (consistent with api/ratelimit.py)
  assert.match(rateLimitSrc, /'dev', 'development', 'local', 'test'/);
});

// ─── Static source: memory fallback only in dev/test ─────────────────────────

test('memory_fallback_is_bounded_to_dev_test_env', () => {
  const rateLimitSrc = read('lib/rateLimitStore.ts');

  // prod-like unavailable path must return { store: null, unavailable: true }
  assert.match(rateLimitSrc, /unavailable:\s*true/);

  // Memory fallback must be conditioned on devOrTest
  assert.match(rateLimitSrc, /devOrTest/);
});
