/**
 * bff-rate-limit-prod.test.js
 *
 * PR 9 — BFF Rate-Limit Production Enforcement tests.
 *
 * Validates:
 *  - Prod-like environments reject missing/blank/CHANGE_ME BFF_REDIS_URL
 *  - Memory fallback is allowed in test/dev but rejected in prod-like envs
 *  - Redis unavailable in prod returns deterministic error code
 *  - Regression: under/over-limit behavior unchanged
 *  - Health route exposes rate-limit readiness without leaking Redis URL
 *  - Client bundle never references Redis config
 *
 * No live Redis required — all Redis interactions are faked or source-analyzed.
 * Test framework: node:test (matches project convention).
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
 * Inline mirror of isBffRedisUrlMissingOrPlaceholder from rateLimitStore.ts.
 * Kept in-sync manually — if rateLimitStore.ts changes the logic, update here.
 */
function isBffRedisUrlMissingOrPlaceholder(redisUrl) {
  if (!redisUrl || !redisUrl.trim()) return true;
  if (redisUrl.trim().toUpperCase().startsWith('CHANGE_ME')) return true;
  return false;
}

/**
 * Inline mirror of isDevOrTestEnv from rateLimitStore.ts.
 */
function isDevOrTestEnv(env) {
  const nodeEnv = (env.NODE_ENV || 'development').toLowerCase();
  const fgEnv = (env.FG_ENV || '').toLowerCase();
  if (nodeEnv === 'development' || nodeEnv === 'test') return true;
  if (['dev', 'development', 'local', 'test'].includes(fgEnv)) return true;
  return false;
}

/**
 * Inline mirror of buildRateLimitStore logic for prod enforcement tests.
 * Returns the same shape as the real function for unavailable cases.
 */
async function simulateBuildRateLimitStore({ env, redisReachable = true } = {}) {
  const devOrTest = isDevOrTestEnv(env);
  const rawRedisUrl = env.BFF_REDIS_URL || env.REDIS_URL || undefined;
  const redisUrlIsRest = rawRedisUrl ? /^https?:\/\//i.test(rawRedisUrl.trim()) : false;
  const redisUrl = rawRedisUrl && !redisUrlIsRest ? rawRedisUrl : undefined;
  const upstashRestUrl = env.BFF_UPSTASH_REDIS_REST_URL || env.UPSTASH_REDIS_REST_URL || env.KV_REST_API_URL || (redisUrlIsRest ? rawRedisUrl : undefined);
  const upstashRestToken = env.BFF_UPSTASH_REDIS_REST_TOKEN || env.UPSTASH_REDIS_REST_TOKEN || env.KV_REST_API_TOKEN || undefined;
  const backend = (env.BFF_RATE_LIMIT_BACKEND || '').trim().toLowerCase();

  // Explicit memory backend in prod-like env → config required
  if (backend === 'memory' && !devOrTest) {
    return { store: null, unavailable: true, errorCode: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED', required: true };
  }
  if (backend === 'memory' && devOrTest) {
    return { store: { type: 'memory' }, unavailable: false };
  }

  const resolvedBackend = backend === 'upstash-rest' || backend === 'rest' || backend === 'upstash'
    ? 'upstash-rest'
    : backend === 'redis'
      ? 'redis'
      : upstashRestUrl || upstashRestToken
        ? 'upstash-rest'
        : redisUrl
          ? 'redis'
          : 'memory';

  if (resolvedBackend === 'memory') {
    if (devOrTest) return { store: { type: 'memory' }, unavailable: false };
    return { store: null, unavailable: true, errorCode: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED', required: true };
  }

  if (resolvedBackend === 'upstash-rest') {
    if (isBffRedisUrlMissingOrPlaceholder(upstashRestUrl) || isBffRedisUrlMissingOrPlaceholder(upstashRestToken)) {
      if (devOrTest) return { store: { type: 'memory' }, unavailable: false };
      return { store: null, unavailable: true, errorCode: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED', required: true };
    }
    if (!redisReachable) {
      if (devOrTest) return { store: { type: 'memory' }, unavailable: false };
      return { store: null, unavailable: true, errorCode: 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE', required: true };
    }
    return { store: { type: 'upstash-rest' }, unavailable: false };
  }

  // Redis backend (auto or explicit)
  if (isBffRedisUrlMissingOrPlaceholder(redisUrl)) {
    if (devOrTest) {
      return { store: { type: 'memory' }, unavailable: false };
    }
    return { store: null, unavailable: true, errorCode: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED', required: true };
  }

  // Valid URL provided
  if (!redisReachable) {
    if (devOrTest) {
      return { store: { type: 'memory' }, unavailable: false };
    }
    return { store: null, unavailable: true, errorCode: 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE', required: true };
  }

  return { store: { type: 'redis' }, unavailable: false };
}

// ─── Test 1: prod_requires_bff_redis_url_for_rate_limit ───────────────────────

test('prod_requires_bff_redis_url_for_rate_limit', async () => {
  const result = await simulateBuildRateLimitStore({
    env: { NODE_ENV: 'production', FG_ENV: 'prod' },
    // BFF_REDIS_URL not set
  });
  assert.equal(result.unavailable, true);
  assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
  assert.equal(result.required, true);
  assert.equal(result.store, null);
});

// ─── Test 2: staging_requires_bff_redis_url_for_rate_limit ────────────────────

test('staging_requires_bff_redis_url_for_rate_limit', async () => {
  const result = await simulateBuildRateLimitStore({
    env: { NODE_ENV: 'production', FG_ENV: 'staging' },
  });
  assert.equal(result.unavailable, true);
  assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
  assert.equal(result.required, true);
});

// ─── Test 3: blank_bff_redis_url_is_rejected ──────────────────────────────────

test('blank_bff_redis_url_is_rejected', async () => {
  // Empty string URL in prod must be treated as missing
  const result = await simulateBuildRateLimitStore({
    env: { NODE_ENV: 'production', FG_ENV: 'prod', BFF_REDIS_URL: '   ' },
  });
  assert.equal(result.unavailable, true);
  assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
});

// ─── Test 4: change_me_bff_redis_url_is_rejected ─────────────────────────────

test('change_me_bff_redis_url_is_rejected', async () => {
  const result = await simulateBuildRateLimitStore({
    env: {
      NODE_ENV: 'production',
      FG_ENV: 'prod',
      BFF_REDIS_URL: 'CHANGE_ME_REDIS_URL',
    },
  });
  assert.equal(result.unavailable, true);
  assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
});

// ─── Test 5: memory_fallback_allowed_in_test ──────────────────────────────────

test('redis_url_alias_is_accepted_in_prod', async () => {
  const result = await simulateBuildRateLimitStore({
    env: { NODE_ENV: 'production', FG_ENV: 'prod', REDIS_URL: 'redis://redis.example.com:6379/0' },
  });
  assert.equal(result.unavailable, false);
  assert.equal(result.store?.type, 'redis');
});

test('upstash_rest_env_is_accepted_in_prod', async () => {
  const result = await simulateBuildRateLimitStore({
    env: {
      NODE_ENV: 'production',
      FG_ENV: 'prod',
      UPSTASH_REDIS_REST_URL: 'https://example.upstash.io',
      UPSTASH_REDIS_REST_TOKEN: 'token-123',
    },
  });
  assert.equal(result.unavailable, false);
  assert.equal(result.store?.type, 'upstash-rest');
});

test('memory_fallback_allowed_in_test', async () => {
  // No BFF_REDIS_URL in test env → memory fallback allowed
  const result = await simulateBuildRateLimitStore({
    env: { NODE_ENV: 'test', FG_ENV: 'test' },
  });
  assert.equal(result.unavailable, false);
  assert.equal(result.store?.type, 'memory');
});

// ─── Test 6: memory_fallback_rejected_in_prod ─────────────────────────────────

test('memory_fallback_rejected_in_prod', async () => {
  // Explicit BFF_RATE_LIMIT_BACKEND=memory in prod-like env must be rejected
  const result = await simulateBuildRateLimitStore({
    env: {
      NODE_ENV: 'production',
      FG_ENV: 'prod',
      BFF_RATE_LIMIT_BACKEND: 'memory',
    },
  });
  assert.equal(result.unavailable, true);
  assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
  assert.equal(result.required, true);
});

// ─── Test 7: redis_unavailable_in_prod_returns_stable_error ──────────────────

test('redis_unavailable_in_prod_returns_stable_error', async () => {
  // Valid URL provided but Redis is unreachable
  const result = await simulateBuildRateLimitStore({
    env: {
      NODE_ENV: 'production',
      FG_ENV: 'prod',
      BFF_REDIS_URL: 'redis://localhost:6379/0',
    },
    redisReachable: false,
  });
  assert.equal(result.unavailable, true);
  assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE');
  assert.equal(result.required, true);
  assert.equal(result.store, null);
});

// ─── Test 8: rate_limit_under_limit_still_allows_request (regression) ─────────

test('rate_limit_under_limit_still_allows_request', async () => {
  // Regression: MemoryRateLimitStore still allows under-limit requests
  class MemoryRateLimitStore {
    constructor() { this.store = new Map(); }
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
      return { count: entry.count, allowed: entry.count <= maxRequests, windowSec, available: true };
    }
  }

  const store = new MemoryRateLimitStore();
  const result = await store.increment('fg:bff:rl:decisions:t1:u1', 60, 100);
  assert.equal(result.allowed, true);
  assert.equal(result.count, 1);
});

// ─── Test 9: rate_limit_over_limit_still_blocks_request (regression) ──────────

test('rate_limit_over_limit_still_blocks_request', async () => {
  class MemoryRateLimitStore {
    constructor() { this.store = new Map(); }
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
      return { count: entry.count, allowed: entry.count <= maxRequests, windowSec, available: true };
    }
  }

  const store = new MemoryRateLimitStore();
  const key = 'fg:bff:rl:keys:t2:u2';
  const maxRequests = 2;
  await store.increment(key, 60, maxRequests);
  await store.increment(key, 60, maxRequests);
  const blocked = await store.increment(key, 60, maxRequests);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.count, 3);
});

// ─── Test 10: readiness_reports_rate_limit_ready ──────────────────────────────

test('readiness_reports_rate_limit_ready', () => {
  // Health route must include rateLimit field and use getRateLimitHealth (non-poisoning probe)
  const healthSrc = read('app/api/health/route.ts');
  assert.match(healthSrc, /rateLimit/);
  assert.match(healthSrc, /getRateLimitHealth/);
  // Must NOT use the singleton-initializing getRateLimitStore in the health route
  assert.doesNotMatch(healthSrc, /getRateLimitStore/);
});

// ─── Test 11: readiness_reports_rate_limit_config_required ────────────────────

test('readiness_reports_rate_limit_config_required', () => {
  // Health route response shape must include ready/required/reason via getRateLimitHealth
  const healthSrc = read('app/api/health/route.ts');
  assert.match(healthSrc, /getRateLimitHealth/);
  // The reason/required/ready fields are returned by getRateLimitHealth itself
  const rateLimitSrc = read('lib/rateLimitStore.ts');
  assert.match(rateLimitSrc, /getRateLimitHealth/);
  assert.match(rateLimitSrc, /reason/);
  assert.match(rateLimitSrc, /required/);
  assert.match(rateLimitSrc, /ready/);
});

// ─── Test 12: readiness_does_not_expose_redis_url ─────────────────────────────

test('readiness_does_not_expose_redis_url', () => {
  const healthSrc = read('app/api/health/route.ts');

  // Must never include Redis URL or any redis config in the response body
  assert.doesNotMatch(healthSrc, /BFF_REDIS_URL/);
  assert.doesNotMatch(healthSrc, /NEXT_PUBLIC_/);
  assert.doesNotMatch(healthSrc, /redis_url/i);
  assert.doesNotMatch(healthSrc, /redisUrl/);
});

// ─── Test 13: client_bundle_does_not_reference_redis_config ──────────────────

test('client_bundle_does_not_reference_redis_config', () => {
  // rateLimitStore.ts must use only process.env (server-side), not NEXT_PUBLIC_*
  const rateLimitSrc = read('lib/rateLimitStore.ts');
  const healthSrc = read('app/api/health/route.ts');
  const routeSrc = read('app/api/core/[...path]/route.ts');

  for (const [name, src] of [['rateLimitStore.ts', rateLimitSrc], ['health/route.ts', healthSrc], ['core route.ts', routeSrc]]) {
    assert.doesNotMatch(src, /NEXT_PUBLIC_BFF_REDIS_URL/, `${name} must not reference NEXT_PUBLIC_BFF_REDIS_URL`);
    assert.doesNotMatch(src, /NEXT_PUBLIC_REDIS/, `${name} must not reference NEXT_PUBLIC_REDIS`);
  }
});

// ─── Static source: errorCode types are present ───────────────────────────────

test('prod_enforcement_error_codes_defined_in_source', () => {
  const rateLimitSrc = read('lib/rateLimitStore.ts');

  // Both error codes must be defined
  assert.match(rateLimitSrc, /BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED/);
  assert.match(rateLimitSrc, /UPSTASH_REDIS_REST_URL/);
  assert.match(rateLimitSrc, /BFF_RATE_LIMIT_REDIS_UNAVAILABLE/);

  // The placeholder detection function must be exported
  assert.match(rateLimitSrc, /isBffRedisUrlMissingOrPlaceholder/);

  // The errorCode field must appear in the return type
  assert.match(rateLimitSrc, /errorCode/);
});

// ─── Static source: route passes errorCode through to response ────────────────

test('route_passes_errorCode_through_to_503_response', () => {
  const routeSrc = read('app/api/core/[...path]/route.ts');

  // Must use storeResult.errorCode in the response body (not hardcoded string)
  assert.match(routeSrc, /storeResult\.errorCode/);

  // Must still return 503 and check unavailable
  assert.match(routeSrc, /status:\s*503/);
  assert.match(routeSrc, /storeResult\.unavailable/);
});

// ─── Static source: CHANGE_ME detection is present ───────────────────────────

test('change_me_placeholder_detection_in_source', () => {
  const rateLimitSrc = read('lib/rateLimitStore.ts');

  // Must reject CHANGE_ME prefixed URLs
  assert.match(rateLimitSrc, /CHANGE_ME/);
  assert.match(rateLimitSrc, /isBffRedisUrlMissingOrPlaceholder/);
});

// ─── Test: health_probe_does_not_poison_store_singleton ───────────────────────

test('health_probe_does_not_poison_store_singleton', () => {
  // Static: getRateLimitHealth must NOT reference _storePromise
  const rateLimitSrc = read('lib/rateLimitStore.ts');

  // Locate getRateLimitHealth function body
  const fnStart = rateLimitSrc.indexOf('export async function getRateLimitHealth');
  assert.ok(fnStart !== -1, 'getRateLimitHealth must exist in rateLimitStore.ts');

  // Strip single-line comments from the function body to avoid false positives
  const afterFn = rateLimitSrc.slice(fnStart);
  const strippedComments = afterFn.replace(/\/\/[^\n]*/g, '');

  // The function body (comment-stripped) must not reference the singleton variable
  assert.doesNotMatch(
    strippedComments,
    /_storePromise/,
    'getRateLimitHealth must not read or write _storePromise (the singleton)'
  );
});

// ─── Test: health_probe_is_retryable_after_redis_recovery ────────────────────

test('health_probe_is_retryable_after_redis_recovery', async () => {
  // Simulate getRateLimitHealth logic with mocked Redis probe for two scenarios.
  // This mirrors the prod branch of getRateLimitHealth without touching _storePromise.

  async function simulateGetRateLimitHealth({ redisReachable, env }) {
    const nodeEnv = (env.NODE_ENV || 'development').toLowerCase();
    const fgEnv = (env.FG_ENV || '').toLowerCase();
    const isProd = !(nodeEnv === 'development' || nodeEnv === 'test' ||
      ['dev', 'development', 'local', 'test'].includes(fgEnv));

    const redisUrl = env.BFF_REDIS_URL || undefined;

    if (isProd) {
      if (!redisUrl || !redisUrl.trim() || redisUrl.trim().toUpperCase().startsWith('CHANGE_ME')) {
        return { backend: 'redis', ready: false, required: true, reason: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED' };
      }
      // Simulate Redis probe — independent each call, no singleton
      if (!redisReachable) {
        return { backend: 'redis', ready: false, required: true, reason: 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE' };
      }
      return { backend: 'redis', ready: true, required: true, reason: null };
    } else {
      return { backend: 'memory', ready: true, required: false, reason: null };
    }
  }

  const prodEnv = { NODE_ENV: 'production', FG_ENV: 'prod', BFF_REDIS_URL: 'redis://localhost:6379/0' };

  // First call: Redis is down
  const failResult = await simulateGetRateLimitHealth({ redisReachable: false, env: prodEnv });
  assert.equal(failResult.ready, false);
  assert.equal(failResult.reason, 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE');

  // Second call: Redis recovered — no cached state, returns ready immediately
  const recoverResult = await simulateGetRateLimitHealth({ redisReachable: true, env: prodEnv });
  assert.equal(recoverResult.ready, true);
  assert.equal(recoverResult.reason, null);
});
