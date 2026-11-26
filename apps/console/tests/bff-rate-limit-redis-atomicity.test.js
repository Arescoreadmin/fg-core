/**
 * FG-849-REPAIR-001 — opt-in proof of RATE_LIMIT_INCREMENT_LUA against a
 * REAL Redis server through the real ioredis client and RedisRateLimitStore.
 *
 * Skipped unless FG849_REAL_REDIS_URL is set (CI has no Redis service for the
 * Console lane). Use a disposable database, e.g.
 *   FG849_REAL_REDIS_URL=redis://127.0.0.1:6379/15 node --test tests/bff-rate-limit-redis-atomicity.test.js
 * Keys are namespaced with a random prefix and deleted afterwards.
 */

'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');
const ts = require('typescript');

const REDIS_URL = process.env.FG849_REAL_REDIS_URL || '';
const SOURCE = path.join(__dirname, '..', 'lib', 'rateLimitStore.ts');

function loadRealStoreModule() {
  const { outputText } = ts.transpileModule(fs.readFileSync(SOURCE, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: SOURCE,
  });
  const mod = new Module(SOURCE, module);
  mod.filename = SOURCE;
  mod.paths = Module._nodeModulePaths(path.dirname(SOURCE));
  mod._compile(outputText, SOURCE);
  return mod.exports;
}

test('real Redis: concurrent first increments, atomic TTL, TTL-less counter repair', { skip: !REDIS_URL && 'FG849_REAL_REDIS_URL not set' }, async () => {
  const rl = loadRealStoreModule();
  const Redis = require('ioredis');
  const client = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 0, enableOfflineQueue: false });
  const prefix = `fg849-test:${crypto.randomBytes(8).toString('hex')}`;
  try {
    const store = new rl.RedisRateLimitStore(client, 2000);

    // 50 concurrent first requests: every count is unique, exactly `max` allowed.
    const key = `${prefix}:concurrent`;
    const results = await Promise.all(Array.from({ length: 50 }, () => store.increment(key, 30, 10)));
    const counts = results.map((r) => r.count).sort((a, b) => a - b);
    assert.deepEqual(counts, Array.from({ length: 50 }, (_, i) => i + 1));
    assert.equal(results.filter((r) => r.allowed).length, 10);
    const ttl = await client.pttl(key);
    assert.ok(ttl > 0 && ttl <= 30_000, `TTL must be set atomically (pttl=${ttl})`);

    // Later increments never extend the window.
    await new Promise((resolve) => setTimeout(resolve, 50));
    await store.increment(key, 30, 10);
    assert.ok((await client.pttl(key)) < ttl, 'window is not extended by later increments');

    // A counter left without TTL by an interrupted non-atomic write is repaired.
    const legacy = `${prefix}:legacy`;
    await client.set(legacy, '5');
    assert.equal(await client.pttl(legacy), -1);
    const repaired = await store.increment(legacy, 30, 10);
    assert.equal(repaired.count, 6);
    const repairedTtl = await client.pttl(legacy);
    assert.ok(repairedTtl > 0 && repairedTtl <= 30_000, `TTL-less counter repaired (pttl=${repairedTtl})`);
  } finally {
    const keys = await client.keys(`${prefix}:*`).catch(() => []);
    if (keys.length) await client.del(...keys).catch(() => {});
    await client.quit().catch(() => {});
  }
});
