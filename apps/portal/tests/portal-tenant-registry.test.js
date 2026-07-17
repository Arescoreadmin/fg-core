/**
 * portal-tenant-registry.test.js
 *
 * Static and behavioral tests for the Redis-backed tenant key registry.
 * Covers: key format, fallback chain, error safety, and provision-tenant write contract.
 *
 * No live Redis required — Redis calls are faked inline.
 */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

function readConsole(relPath) {
  return fs.readFileSync(
    path.join(__dirname, '../../../apps/console', relPath),
    'utf8',
  );
}

// ─── Key format shared between writer (console) and reader (portal) ───────────

const PORTAL_KEY_PREFIX = 'portal:tenant';
const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;

function portalRedisKey(tenantId) {
  return `${PORTAL_KEY_PREFIX}:${tenantId}:key`;
}

// ─── Fake Redis factory ───────────────────────────────────────────────────────

function makeFakeRedis(store = {}, { failOnGet = false, failOnSet = false } = {}) {
  const setCalls = [];
  return {
    setCalls,
    async get(key) {
      if (failOnGet) throw new Error('Redis ECONNREFUSED');
      return store[key] ?? null;
    },
    async set(key, value, ex, ttl) {
      if (failOnSet) throw new Error('Redis ECONNREFUSED');
      setCalls.push({ key, value, ex, ttl });
      store[key] = value;
      return 'OK';
    },
    async ping() {
      return 'PONG';
    },
  };
}

// ─── Inline mirrors of registry logic ────────────────────────────────────────
// These are pure-logic mirrors of the TypeScript source that run without a
// build step. They mirror the exact behaviour being tested.

async function readKeyFromRedis(tenantId, redisClient) {
  if (!redisClient) return null;
  try {
    const key = await redisClient.get(portalRedisKey(tenantId));
    return key || null;
  } catch {
    return null;
  }
}

async function writeKeyToRedis(tenantId, apiKey, redisClient) {
  try {
    await redisClient.set(portalRedisKey(tenantId), apiKey, 'EX', ONE_YEAR_SECONDS);
    return true;
  } catch {
    return false;
  }
}

// ─── Static: portal tenant-registry.ts structure ─────────────────────────────

test('tenant_registry_edge_config_is_checked_first', () => {
  const src = read('lib/tenant-registry.ts');
  // Edge Config block must appear before Redis block
  const ecPos = src.indexOf('EDGE_CONFIG');
  const redisPos = src.indexOf('getRedisClient');
  assert.ok(ecPos > -1, 'EDGE_CONFIG check must be present');
  assert.ok(redisPos > -1, 'getRedisClient call must be present');
  assert.ok(ecPos < redisPos, 'Edge Config must be checked before Redis');
});

test('tenant_registry_falls_back_to_redis_after_edge_config', () => {
  const src = read('lib/tenant-registry.ts');
  assert.match(src, /getRedisClient\(\)/);
  assert.match(src, /redis\.get\(`\$\{PORTAL_KEY_PREFIX\}/);
});

test('tenant_registry_falls_back_to_upstash_rest_after_ioredis', () => {
  const src = read('lib/tenant-registry.ts');
  // Upstash REST env vars must be checked
  assert.match(src, /UPSTASH_REDIS_REST_URL/);
  assert.match(src, /UPSTASH_REDIS_REST_TOKEN/);
  // Must use Authorization: Bearer token pattern
  assert.match(src, /Bearer.*upstashToken/);
  // Upstash block must come after ioredis block (use process.env. prefix to skip doc comment)
  const redisPos = src.indexOf('getRedisClient()');
  const upstashPos = src.indexOf('process.env.UPSTASH_REDIS_REST_URL');
  assert.ok(redisPos > -1, 'getRedisClient() call must be present');
  assert.ok(upstashPos > -1, 'process.env.UPSTASH_REDIS_REST_URL must be present');
  assert.ok(redisPos < upstashPos, 'ioredis must be checked before Upstash REST');
});

test('tenant_registry_upstash_rest_uses_same_key_prefix', () => {
  const src = read('lib/tenant-registry.ts');
  // Upstash GET command must reference the same key prefix constant
  assert.match(src, /\['GET', `\$\{PORTAL_KEY_PREFIX\}/);
});

test('tenant_registry_key_format_uses_portal_tenant_prefix', () => {
  const src = read('lib/tenant-registry.ts');
  assert.match(src, /portal:tenant/);
  assert.match(src, /PORTAL_KEY_PREFIX/);
  // Full key pattern: portal:tenant:{tenantId}:key
  assert.match(src, /\$\{PORTAL_KEY_PREFIX\}:\$\{tenantId\}:key/);
});

test('tenant_registry_redis_errors_are_caught_and_return_null', () => {
  const src = read('lib/tenant-registry.ts');
  // The Redis block must be in a try/catch
  assert.match(src, /} catch \{/);
  // Must return null after catching, not rethrow
  assert.match(src, /return null/);
  // Must not rethrow or propagate
  assert.doesNotMatch(src, /throw.*redis/i);
});

test('tenant_registry_does_not_use_next_public_env_vars', () => {
  const registrySrc = read('lib/tenant-registry.ts');
  const redisSrc = read('lib/redis.ts');
  // Neither file may expose config through NEXT_PUBLIC_ vars
  assert.doesNotMatch(registrySrc, /NEXT_PUBLIC_/);
  assert.doesNotMatch(redisSrc, /NEXT_PUBLIC_/);
  // Redis URL must be read from server-side env vars (in the redis client module)
  assert.match(redisSrc, /process\.env\.PORTAL_REDIS_URL/);
  assert.match(redisSrc, /process\.env\.REDIS_URL/);
});

// ─── Static: provision-tenant write contract ──────────────────────────────────

test('provision_tenant_redis_write_uses_same_key_prefix_as_portal_read', () => {
  const consoleSrc = readConsole('app/api/admin/provision-tenant/route.ts');
  const portalSrc = read('lib/tenant-registry.ts');

  // Both sides must declare the same prefix constant
  assert.match(consoleSrc, /PORTAL_KEY_PREFIX = 'portal:tenant'/);
  assert.match(portalSrc, /PORTAL_KEY_PREFIX = 'portal:tenant'/);

  // Both must use the :key suffix
  assert.match(consoleSrc, /:\$\{tenantId\}:key/);
  assert.match(portalSrc, /:\$\{tenantId\}:key/);
});

test('provision_tenant_sets_one_year_expiry_on_redis_key', () => {
  const src = readConsole('app/api/admin/provision-tenant/route.ts');
  // ONE_YEAR_SECONDS must be defined and used as TTL
  assert.match(src, /ONE_YEAR_SECONDS = 365 \* 24 \* 60 \* 60/);
  assert.match(src, /'EX', ONE_YEAR_SECONDS/);
});

test('provision_tenant_redis_write_fails_safely_without_url', () => {
  const src = readConsole('app/api/admin/provision-tenant/route.ts');
  // Must check for URL presence before connecting
  assert.match(src, /BFF_REDIS_URL.*REDIS_URL/);
  assert.match(src, /if \(!url\) return false/);
});

test('provision_tenant_suppresses_raw_key_when_registry_write_succeeds', () => {
  const src = readConsole('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /api_key: registryLive \? null : rawKey/);
});

test('provision_tenant_tries_redis_when_edge_config_is_not_configured', () => {
  const src = readConsole('app/api/admin/provision-tenant/route.ts');
  // Use the call-site of writeKeyToRedis (inside the handler), not the function definition
  const ecPos = src.indexOf('isRegistryConfigured()');
  const redisCallPos = src.indexOf('registryLive = await writeKeyToRedis');
  assert.ok(ecPos > -1, 'isRegistryConfigured() call must be present');
  assert.ok(redisCallPos > -1, 'Redis write call-site must be present');
  assert.ok(ecPos < redisCallPos, 'Edge Config must be attempted before Redis fallback');
  assert.match(src, /if \(!registryLive\)/);
});

// ─── Static: portal health route ─────────────────────────────────────────────

test('portal_health_route_reports_redis_status_in_response', () => {
  const src = read('app/api/health/route.ts');
  assert.match(src, /status:\s*'ok'/);
  assert.match(src, /redis:/);
  assert.match(src, /not_configured/);
  assert.match(src, /getRedisClient/);
});

// ─── Behavioral: Redis read path ─────────────────────────────────────────────

test('redis_hit_returns_stored_key_value', async () => {
  const store = { [portalRedisKey('acme-corp')]: 'fgk.test-key-value' };
  const redis = makeFakeRedis(store);
  const result = await readKeyFromRedis('acme-corp', redis);
  assert.equal(result, 'fgk.test-key-value');
});

test('redis_miss_returns_null', async () => {
  const redis = makeFakeRedis({});
  const result = await readKeyFromRedis('unknown-tenant', redis);
  assert.equal(result, null);
});

test('redis_connection_failure_returns_null_and_does_not_throw', async () => {
  const redis = makeFakeRedis({}, { failOnGet: true });
  // Must not throw — callers depend on null meaning "not found or unavailable"
  const result = await readKeyFromRedis('acme-corp', redis);
  assert.equal(result, null);
});

test('null_redis_client_returns_null_immediately', async () => {
  const result = await readKeyFromRedis('acme-corp', null);
  assert.equal(result, null);
});

// ─── Behavioral: Redis write path ────────────────────────────────────────────

test('redis_write_returns_true_on_success', async () => {
  const store = {};
  const redis = makeFakeRedis(store);
  const ok = await writeKeyToRedis('acme-corp', 'fgk.my-api-key', redis);
  assert.equal(ok, true);
  assert.equal(store[portalRedisKey('acme-corp')], 'fgk.my-api-key');
});

test('redis_write_sets_expiry_of_exactly_one_year', async () => {
  const redis = makeFakeRedis();
  await writeKeyToRedis('acme-corp', 'fgk.my-api-key', redis);
  const call = redis.setCalls[0];
  assert.ok(call, 'SET must have been called');
  assert.equal(call.ex, 'EX', 'expiry mode must be EX (seconds)');
  assert.equal(call.ttl, ONE_YEAR_SECONDS, `TTL must be ${ONE_YEAR_SECONDS}s (one year)`);
});

test('redis_write_failure_returns_false_and_does_not_throw', async () => {
  const redis = makeFakeRedis({}, { failOnSet: true });
  const ok = await writeKeyToRedis('acme-corp', 'fgk.my-api-key', redis);
  assert.equal(ok, false);
});

test('written_key_is_readable_by_portal_read_function', async () => {
  const store = {};
  const redis = makeFakeRedis(store);
  await writeKeyToRedis('the-trust-group', 'fgk.portal-key', redis);
  const result = await readKeyFromRedis('the-trust-group', redis);
  assert.equal(result, 'fgk.portal-key');
});

test('different_tenants_do_not_share_keys', async () => {
  const store = {};
  const redis = makeFakeRedis(store);
  await writeKeyToRedis('tenant-a', 'fgk.key-a', redis);
  await writeKeyToRedis('tenant-b', 'fgk.key-b', redis);

  const a = await readKeyFromRedis('tenant-a', redis);
  const b = await readKeyFromRedis('tenant-b', redis);
  assert.equal(a, 'fgk.key-a');
  assert.equal(b, 'fgk.key-b');
  assert.notEqual(a, b);
});
