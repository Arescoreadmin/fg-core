'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

test('provisioned console keys can manage tenant workforce users', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  const scopes = src.match(/const PROVISION_SCOPES = \[([\s\S]*?)\];/)?.[1] ?? '';
  assert.match(scopes, /'admin:write'/);
});

test('tenant provisioning authenticates admin core calls with the internal token', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  const headers = src.match(/function adminHeaders\(\): HeadersInit \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(headers, /const token = internalGatewaySecret\(\)/);
  assert.match(headers, /'X-API-Key': token/);
  assert.match(headers, /'X-FG-Internal-Token': token/);
  assert.match(headers, /'X-Admin-Gateway-Internal': 'true'/);
  assert.doesNotMatch(headers, /'X-API-Key': CORE_API_KEY/);
});

test('provision tenant always writes portal auth key to Redis then Upstash', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  // Portal key write (Redis) always runs — no longer gated on Edge Config success
  assert.match(src, /writeKeyToRedis/);
  assert.match(src, /registryLive = await writeKeyToRedis/);
  // Upstash portal key write is the Redis fallback (still gated on !registryLive)
  assert.match(src, /if \(!registryLive\)/);
  assert.match(src, /registryLive = await writeKeyToUpstash/);
  // Redis write must clear registryError on success
  assert.match(src, /if \(registryLive\) registryError = null/);
});

test('provision tenant Redis write uses portal:tenant key prefix and one-year TTL', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /PORTAL_KEY_PREFIX = 'portal:tenant'/);
  assert.match(src, /`\$\{PORTAL_KEY_PREFIX\}:\$\{tenantId\}:key`/);
  assert.match(src, /ONE_YEAR_SECONDS = 365 \* 24 \* 60 \* 60/);
  assert.match(src, /'EX', ONE_YEAR_SECONDS/);
});

test('provision tenant Redis write returns false without throwing on connection failure', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  // The catch block inside writeKeyToRedis must return false, not rethrow
  assert.match(src, /async function writeKeyToRedis/);
  assert.match(src, /} catch \{/);
  assert.match(src, /return false/);
  assert.doesNotMatch(src, /throw.*writeKeyToRedis/i);
});

test('provision tenant reads Redis URL from BFF_REDIS_URL or REDIS_URL — not a public env var', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /process\.env\.BFF_REDIS_URL/);
  assert.match(src, /process\.env\.REDIS_URL/);
  assert.doesNotMatch(src, /NEXT_PUBLIC_/);
});

test('provision tenant never exposes raw API key in any response', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  // Raw key must not appear in any response body
  assert.doesNotMatch(src, /api_key:.*rawKey/);
  assert.doesNotMatch(src, /api_key: registryLive \? null : rawKey/);
});

test('provision tenant fails closed with 503 when credential persistence fails', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /PERSISTENCE_UNAVAILABLE/);
  assert.match(src, /status: 503/);
  // Must attempt key revocation before returning error (prevent dangling Postgres keys)
  assert.match(src, /revokeKey/);
  // The 503 path must follow the registryLive persistence check
  const registryCheck = src.indexOf('if (!registryLive)');
  const persistenceError = src.indexOf('PERSISTENCE_UNAVAILABLE');
  assert.ok(registryCheck >= 0, 'registryLive check must exist');
  assert.ok(registryCheck < persistenceError, '503 path must follow persistence check');
});

test('provision tenant tries Upstash REST as third fallback after ioredis', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /async function writeKeyToUpstash/);
  assert.match(src, /registryLive = await writeKeyToUpstash/);
  // Must use same key prefix and TTL
  assert.match(src, /\['SET', `\$\{PORTAL_KEY_PREFIX\}/);
  assert.match(src, /'EX', ONE_YEAR_SECONDS/);
  // Upstash block must appear after Redis block
  const redisCallPos = src.indexOf('registryLive = await writeKeyToRedis');
  const upstashCallPos = src.indexOf('registryLive = await writeKeyToUpstash');
  assert.ok(redisCallPos < upstashCallPos, 'ioredis must be tried before Upstash REST');
});

test('provision tenant Upstash REST write uses BFF or shared env vars — not public vars', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /BFF_UPSTASH_REDIS_REST_URL/);
  assert.match(src, /UPSTASH_REDIS_REST_URL/);
  assert.match(src, /BFF_UPSTASH_REDIS_REST_TOKEN/);
  assert.match(src, /UPSTASH_REDIS_REST_TOKEN/);
  assert.doesNotMatch(src, /NEXT_PUBLIC_/);
});
