/**
 * DEP-REMEDIATE-003 — behavioural coverage for lib/rateLimitStore.ts.
 *
 * The retired apps/console/console/ tree tested an inline *copy* of the store
 * builder. These tests execute the real module (transpiled with the Console's
 * own TypeScript compiler so they run on CI's Node 20) and pin the deployed
 * contract:
 *
 *   - prod/staging without a BFF Redis/Upstash config is reported unavailable
 *     with BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED (never a silent memory store);
 *   - CHANGE_ME placeholders and blank values count as missing;
 *   - dev/test fall back to the in-memory store;
 *   - a configured Redis URL builds a RedisRateLimitStore lazily (no eager
 *     connect, per 225d21c25) — the route then fails open on outage by design;
 *   - the counters allow up to the limit, block above it, and set EXPIRE only
 *     on the first increment of a window;
 *   - the health probe never leaks the Redis URL.
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');
const ts = require('typescript');

const SOURCE = path.join(__dirname, '..', 'lib', 'rateLimitStore.ts');
const ENV_KEYS = [
  'NODE_ENV',
  'FG_ENV',
  'BFF_REDIS_URL',
  'REDIS_URL',
  'UPSTASH_REDIS_REST_URL',
  'UPSTASH_REDIS_REST_TOKEN',
  'KV_REST_API_URL',
  'KV_REST_API_TOKEN',
];

function loadRealModule() {
  const { outputText } = ts.transpileModule(fs.readFileSync(SOURCE, 'utf8'), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
    },
    fileName: SOURCE,
  });
  const mod = new Module(SOURCE, module);
  mod.filename = SOURCE;
  mod.paths = Module._nodeModulePaths(path.dirname(SOURCE));
  mod._compile(outputText, SOURCE);
  return mod.exports;
}

const rl = loadRealModule();
const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));

function withEnv(env) {
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, env);
  rl._resetRateLimitStoreSingleton();
}

test.after(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rl._resetRateLimitStoreSingleton();
});

for (const env of [
  { NODE_ENV: 'production', FG_ENV: 'prod' },
  { NODE_ENV: 'production', FG_ENV: 'staging' },
]) {
  test(`${env.FG_ENV} without redis config is unavailable with CONFIG_REQUIRED`, async () => {
    withEnv(env);
    const result = await rl.buildRateLimitStore();
    assert.equal(result.store, null);
    assert.equal(result.unavailable, true);
    assert.equal(result.required, true);
    assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
  });
}

for (const url of ['CHANGE_ME_redis_url', '   ', '']) {
  test(`prod rejects placeholder or blank BFF_REDIS_URL ${JSON.stringify(url)}`, async () => {
    withEnv({ NODE_ENV: 'production', FG_ENV: 'prod', BFF_REDIS_URL: url });
    const result = await rl.buildRateLimitStore();
    assert.equal(result.unavailable, true);
    assert.equal(result.store, null);
    assert.equal(result.errorCode, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
  });
}

test('test env falls back to the in-memory store', async () => {
  withEnv({ NODE_ENV: 'test', FG_ENV: 'test' });
  const result = await rl.buildRateLimitStore();
  assert.equal(result.unavailable, false);
  assert.ok(result.store instanceof rl.MemoryRateLimitStore);
});

test('prod with a redis url builds a lazy RedisRateLimitStore without connecting', async () => {
  // Port 1 is never listening: an eager connect would surface as an error or hang.
  withEnv({ NODE_ENV: 'production', FG_ENV: 'prod', BFF_REDIS_URL: 'redis://127.0.0.1:1/0' });
  const result = await rl.buildRateLimitStore();
  assert.equal(result.unavailable, false);
  assert.ok(result.store instanceof rl.RedisRateLimitStore);
});

test('memory store allows up to the limit and blocks above it', async () => {
  const store = new rl.MemoryRateLimitStore();
  const seen = [];
  for (let i = 0; i < 4; i += 1) seen.push(await store.increment('tenant-a:core', 60, 3));
  assert.deepEqual(seen.map((r) => r.allowed), [true, true, true, false]);
  assert.deepEqual(seen.map((r) => r.count), [1, 2, 3, 4]);
  // Keys are independent: another tenant's budget is untouched.
  assert.equal((await store.increment('tenant-b:core', 60, 3)).allowed, true);
});

test('redis store blocks above the limit and sets EXPIRE only on first increment', async () => {
  const counters = new Map();
  const expires = [];
  const client = {
    async incr(key) {
      counters.set(key, (counters.get(key) || 0) + 1);
      return counters.get(key);
    },
    async expire(key, seconds) {
      expires.push([key, seconds]);
      return 1;
    },
    async quit() {},
  };
  const store = new rl.RedisRateLimitStore(client);
  const results = [];
  for (let i = 0; i < 3; i += 1) results.push(await store.increment('k', 30, 2));
  assert.deepEqual(results.map((r) => r.allowed), [true, true, false]);
  assert.deepEqual(expires, [['k', 30]]);
});

test('redis store propagates client errors so the route can apply its outage policy', async () => {
  const store = new rl.RedisRateLimitStore({
    async incr() {
      throw new Error('ECONNREFUSED');
    },
    async expire() {
      return 1;
    },
    async quit() {},
  });
  await assert.rejects(store.increment('k', 30, 2), /ECONNREFUSED/);
});

test('health probe reports config-required without leaking the redis url', async () => {
  withEnv({ NODE_ENV: 'production', FG_ENV: 'prod', BFF_REDIS_URL: 'CHANGE_ME_secret_host' });
  const health = await rl.getRateLimitHealth();
  assert.equal(health.ready, false);
  assert.equal(health.required, true);
  assert.equal(health.reason, 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED');
  const text = JSON.stringify(health);
  assert.doesNotMatch(text, /CHANGE_ME_secret_host/);
  assert.doesNotMatch(text, /redis:\/\//);
});
