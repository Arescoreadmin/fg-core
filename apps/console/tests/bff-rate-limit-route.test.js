/**
 * FG-849-REPAIR-001 — adversarial tests against the REAL Core BFF route.
 *
 * Every request here runs through app/api/core/[...path]/route.ts with the
 * real rate-limit store, policy module, console access policy and
 * next/server. Only the session source, tenant key registry, Redis client
 * and outbound fetch are faked (tests/helpers/bffRouteHarness.js).
 *
 * The environment is prod-like (NODE_ENV=production, FG_ENV=prod), so the
 * memory store is never used and the production failure policy applies.
 *
 * Baseline proof: with FG849_HARNESS_ROOT pointing at the pre-repair
 * apps/console tree, the fail-open, header-rotation, atomicity and privacy
 * tests fail (see docs/ai/PR_FIX_LOG.md, FG-849-REPAIR-001).
 */

'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createHarness, snapshotEnv, applyEnv, restoreEnv } = require('./helpers/bffRouteHarness');

// ─── Sentinels: must never appear in limiter keys or limiter logs ────────────

const SUBJECT_A = 'auth0|SENTINELSUBJECTALPHA';
const SUBJECT_B = 'auth0|SENTINELSUBJECTBRAVO';
const ADMIN_SUBJECT = 'auth0|SENTINELSUBJECTADMIN';
const TENANT_A = 'SENTINEL-TENANT-ALPHA';
const TENANT_B = 'SENTINEL-TENANT-BRAVO';
const CLIENT_IP = '203.0.113.77';
const AUTH_SECRET = 'SENTINEL-AUTH-SECRET-0123456789abcdefghijklmnop';
const UPSTASH_TOKEN = 'SENTINEL-UPSTASH-TOKEN-0123456789';
const TOKEN_1 = `fgwi1.${'deadbeef'.repeat(8)}`;
const TOKEN_2 = `fgwi1.${'cafebabe'.repeat(8)}`;
const SENTINELS = [SUBJECT_A, SUBJECT_B, ADMIN_SUBJECT, 'SENTINELSUBJECT', TENANT_A, TENANT_B, CLIENT_IP, AUTH_SECRET, UPSTASH_TOKEN, TOKEN_1, TOKEN_2, 'deadbeefdeadbeef'];

const BASE_ENV = {
  NODE_ENV: 'production',
  FG_ENV: 'prod',
  CORE_API_URL: 'http://core.test',
  CORE_TENANT_ID: 'fg-operator',
  AUTH_SECRET,
  BFF_REDIS_URL: 'redis://redis.internal.test:6379/0',
  BFF_RATE_LIMIT_WINDOW_S: '60',
  BFF_RATE_LIMIT_MAX_REQUESTS: '3',
  BFF_RATE_LIMIT_TIMEOUT_MS: '150',
  BFF_RATE_LIMIT_PUBLIC_INVITATION_MAX_REQUESTS: '5',
  BFF_RATE_LIMIT_PUBLIC_INVITATION_TOKEN_MAX_REQUESTS: '2',
  FG_INTERNAL_GATEWAY_SECRET: 'synthetic-gateway-secret-0123456789abcdef',
  FG_GATEWAY_DELEGATION_SECRET_CURRENT: 'synthetic-delegation-secret-0123456789',
};

const UPSTASH_ENV = {
  BFF_REDIS_URL: undefined,
  BFF_UPSTASH_REDIS_REST_URL: 'https://upstash.test',
  BFF_UPSTASH_REDIS_REST_TOKEN: UPSTASH_TOKEN,
};

function clientSession(sub = SUBJECT_A, tenantId = TENANT_A, roles = ['client_read_only']) {
  return {
    user: { id: sub, email: 'client@example.test' },
    roles,
    tenantId,
    experienceClass: 'console_enabled_client',
    emailVerified: true,
    expires: '2099-01-01T00:00:00.000Z',
  };
}

function adminSession(sub = ADMIN_SUBJECT) {
  return {
    user: { id: sub, email: 'admin@example.test' },
    roles: ['Administrator'],
    tenantId: null,
    experienceClass: 'internal_console',
    emailVerified: true,
    expires: '2099-01-01T00:00:00.000Z',
  };
}

const savedEnv = snapshotEnv();
test.after(() => restoreEnv(savedEnv));

function setup(envOverrides = {}) {
  applyEnv({ ...BASE_ENV, ...envOverrides });
  return createHarness();
}

function assertUnavailable(res, h) {
  assert.equal(res.status, 503, `expected 503, got ${res.status} ${res.text}`);
  assert.equal(res.json?.code, 'BFF_RATE_LIMIT_UNAVAILABLE');
  assert.equal(h.state.coreCalls.length, 0, 'no Core request may be made when enforcement is unavailable');
  assert.equal(h.state.tenantKeyLookups.length, 0, 'no tenant credential may be fetched before the limiter decision');
  assert.doesNotMatch(res.text, /redis|upstash|ECONNREFUSED|NOAUTH|stack|\.test/i, '503 body must not reveal backend detail');
}

function limiterKeys(h) {
  return [...h.backend.entries.keys()];
}

// ─── A. Authentication and authorization (unchanged, precede the limiter) ───

test('A1 missing session is denied before any limiter or Core call', async () => {
  const h = setup();
  const res = await h.call('GET', ['decisions']);
  assert.equal(res.status, 401);
  assert.equal(h.backend.calls.eval + h.backend.calls.incr, 0);
  assert.equal(h.state.coreCalls.length, 0);
});

test('A2 unsupported (invalid) session role is denied', async () => {
  const h = setup();
  h.state.session = { user: { id: SUBJECT_A }, roles: ['NotARole'], experienceClass: 'unsupported' };
  const res = await h.call('GET', ['decisions']);
  assert.equal(res.status, 403);
  assert.equal(h.state.coreCalls.length, 0);
});

test('A3 cross-tenant request from a client session is denied', async () => {
  const h = setup();
  h.state.session = clientSession();
  const res = await h.call('GET', ['decisions'], { query: `?tenant_id=${TENANT_B}` });
  assert.equal(res.status, 403);
  assert.equal(res.json?.error, 'TENANT_AUTHORITY_DENIED');
  assert.equal(h.state.coreCalls.length, 0);
});

test('A4 duplicate tenant_id keys are rejected', async () => {
  const h = setup();
  h.state.session = adminSession();
  const res = await h.call('GET', ['decisions'], { query: `?tenant_id=${TENANT_A}&tenant_id=${TENANT_A}` });
  assert.equal(res.status, 422);
  assert.equal(h.state.coreCalls.length, 0);
});

test('A5 client session missing canonical tenant authority fails closed', async () => {
  const h = setup();
  h.state.session = clientSession(SUBJECT_A, null);
  const res = await h.call('GET', ['decisions']);
  assert.equal(res.status, 403);
  assert.equal(res.json?.error, 'TENANT_AUTHORITY_MISSING');
  assert.equal(h.state.coreCalls.length, 0);
});

test('A6 unauthorized mutation (read-only client POST keys) is denied', async () => {
  const h = setup();
  h.state.session = clientSession();
  const res = await h.call('POST', ['keys'], { body: { name: 'x' } });
  assert.equal(res.status, 403);
  assert.equal(h.state.coreCalls.length, 0);
});

test('A7 session without a subject is denied; the limiter never invents an identity', async () => {
  const h = setup();
  const session = clientSession();
  session.user = { email: 'client@example.test' };
  h.state.session = session;
  const res = await h.call('GET', ['decisions'], { headers: { 'x-frostgate-user': 'attacker-chosen' } });
  assert.equal(res.status, 401);
  assert.equal(h.backend.calls.eval, 0);
  assert.equal(h.state.coreCalls.length, 0);
});

test('A8 valid authenticated request with a healthy backend reaches Core unchanged', async () => {
  const h = setup();
  h.state.session = clientSession();
  const res = await h.call('GET', ['decisions'], { query: '?limit=5' });
  assert.equal(res.status, 200);
  assert.equal(h.state.coreCalls.length, 1);
  const core = h.state.coreCalls[0];
  assert.equal(core.headers['x-tenant-id'], TENANT_A);
  assert.equal(core.headers['x-api-key'], `synthetic-core-key-for-${TENANT_A}`);
  assert.match(core.url, /\/decisions\?limit=5&tenant_id=SENTINEL-TENANT-ALPHA$/);
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('A9 the limiter grants no authority: an exceeded quota never forwards, and a fresh quota never bypasses RBAC', async () => {
  const h = setup();
  h.state.session = clientSession();
  for (let i = 0; i < 3; i += 1) assert.equal((await h.call('GET', ['decisions'])).status, 200);
  const res = await h.call('GET', ['decisions']);
  assert.equal(res.status, 429);
  assert.equal(h.state.coreCalls.length, 3);
  // A forbidden route with quota available is still forbidden.
  assert.equal((await h.call('GET', ['forensics', 'snapshot'])).status, 403);
});

// ─── B. Principal spoofing ───────────────────────────────────────────────────

test('B1 rotating x-frostgate-user / x-real-ip / x-forwarded-for / x-tenant-id / query params cannot mint quota', async () => {
  const h = setup();
  h.state.session = clientSession();
  const attempts = [
    { headers: { 'x-frostgate-user': 'rotated-1', 'x-real-ip': '198.51.100.1' }, query: '?a=1' },
    { headers: { 'x-frostgate-user': 'rotated-2', 'x-forwarded-for': `${CLIENT_IP}, 10.0.0.1` }, query: '?b=2&b=3' },
    { headers: { 'x-tenant-id': TENANT_B, 'x-real-ip': '198.51.100.3' }, query: '?c=3' },
    { headers: { 'x-frostgate-user': 'rotated-4', 'x-forwarded-for': '198.51.100.4' }, query: '?d=4' },
  ];
  const statuses = [];
  for (const attempt of attempts) statuses.push((await h.call('GET', ['decisions'], attempt)).status);
  assert.deepEqual(statuses, [200, 200, 200, 429], 'all four requests share one authoritative quota');
  assert.equal(limiterKeys(h).length, 1, 'exactly one limiter partition for one principal+tenant');
});

test('B2 distinct verified principals receive distinct quotas', async () => {
  const h = setup();
  h.state.session = clientSession(SUBJECT_A);
  for (let i = 0; i < 3; i += 1) await h.call('GET', ['decisions']);
  assert.equal((await h.call('GET', ['decisions'])).status, 429);
  h.state.session = clientSession(SUBJECT_B);
  assert.equal((await h.call('GET', ['decisions'])).status, 200);
  assert.equal(limiterKeys(h).length, 2);
});

test('B3 distinct canonical tenants receive distinct partitions for the same principal', async () => {
  const h = setup();
  h.state.session = adminSession();
  for (let i = 0; i < 3; i += 1) await h.call('GET', ['decisions'], { query: `?tenant_id=${TENANT_A}` });
  assert.equal((await h.call('GET', ['decisions'], { query: `?tenant_id=${TENANT_A}` })).status, 429);
  assert.equal((await h.call('GET', ['decisions'], { query: `?tenant_id=${TENANT_B}` })).status, 200);
  assert.equal(limiterKeys(h).length, 2);
});

test('B4 body-provided tenant aliases do not change the quota partition or the Core tenant', async () => {
  const h = setup();
  h.state.session = adminSession();
  const statuses = [];
  for (const alias of [TENANT_B, 'other-1', 'other-2', 'other-3']) {
    const res = await h.call('POST', ['keys'], {
      query: `?tenant_id=${TENANT_A}`,
      body: { name: 'k', tenant_id: alias, tenantId: alias },
    });
    statuses.push(res.status);
  }
  assert.deepEqual(statuses, [200, 200, 200, 429]);
  assert.equal(limiterKeys(h).length, 1);
  for (const call of h.state.coreCalls) {
    assert.equal(call.headers['x-tenant-id'], TENANT_A);
    assert.doesNotMatch(call.body, /tenant_id|tenantId/);
  }
});

// ─── C. Store failure: fail closed, no upstream call ─────────────────────────

test('C1 missing Redis/Upstash configuration in prod returns 503 (regression: baseline allowed the request)', async () => {
  const h = setup({ BFF_REDIS_URL: undefined });
  h.state.session = clientSession();
  assertUnavailable(await h.call('GET', ['decisions']), h);
});

for (const [mode, label] of [
  ['refuse', 'connection refused'],
  ['auth', 'authentication error'],
  ['throw', 'increment exception'],
  ['malformed', 'malformed reply'],
]) {
  test(`C2 Redis ${label} returns 503 with no Core call`, async () => {
    const h = setup();
    h.state.session = clientSession();
    h.backend.mode = mode;
    assertUnavailable(await h.call('GET', ['decisions']), h);
  });
}

test('C3 stalled Redis is bounded by BFF_RATE_LIMIT_TIMEOUT_MS and fails closed', async () => {
  const h = setup();
  h.state.session = clientSession();
  h.backend.mode = 'hang';
  const started = Date.now();
  const res = await h.call('GET', ['decisions']);
  const elapsed = Date.now() - started;
  assertUnavailable(res, h);
  assert.ok(elapsed < 1500, `limiter decision must be bounded (took ${elapsed} ms)`);
});

for (const [mode, label] of [
  ['hang', 'HTTP timeout'],
  ['http5xx', 'HTTP 5xx'],
  ['malformed', 'non-JSON body'],
  ['nonnumeric', 'non-numeric result'],
  ['refuse', 'network error'],
]) {
  test(`C4 Upstash ${label} returns 503 with no Core call`, async () => {
    const h = setup(UPSTASH_ENV);
    h.state.session = clientSession();
    h.backend.mode = mode;
    const started = Date.now();
    assertUnavailable(await h.call('GET', ['decisions']), h);
    assert.ok(Date.now() - started < 1500);
  });
}

test('C5 privileged mutations are never forwarded during an outage (keys, quarantine, tenant admin, governance)', async () => {
  const h = setup();
  h.backend.mode = 'refuse';
  h.state.session = adminSession();
  assertUnavailable(await h.call('POST', ['keys'], { query: `?tenant_id=${TENANT_A}`, body: { name: 'k' } }), h);
  assertUnavailable(await h.call('POST', ['admin', 'agent', 'quarantine'], { query: `?tenant_id=${TENANT_A}`, body: {} }), h);
  assertUnavailable(await h.call('POST', ['governance', 'graph'], { query: `?tenant_id=${TENANT_A}`, body: {} }), h);
  assertUnavailable(
    await h.call('POST', ['field-assessment', 'engagements', 'e1', 'reports', 'r1', 'release'], { query: `?tenant_id=${TENANT_A}`, body: {} }),
    h,
  );
  h.state.session = clientSession(SUBJECT_A, TENANT_A, ['tenant_admin']);
  assertUnavailable(await h.call('POST', ['admin', 'tenants', TENANT_A, 'users'], { body: { email: 'x@example.test' } }), h);
});

test('C6 exports and health reads also fail closed (no tier is fail-open)', async () => {
  const h = setup();
  h.backend.mode = 'refuse';
  h.state.session = adminSession();
  assertUnavailable(await h.call('GET', ['audit', 'export'], { query: `?tenant_id=${TENANT_A}` }), h);
  assertUnavailable(await h.call('GET', ['health', 'live']), h);
});

test('C7 missing limiter key material in prod fails closed', async () => {
  const h = setup({ AUTH_SECRET: undefined });
  h.state.session = clientSession();
  assertUnavailable(await h.call('GET', ['decisions']), h);
});

test('C8 a configured-but-weak dedicated limiter secret never falls back silently', async () => {
  const h = setup({ BFF_RATE_LIMIT_KEY_SECRET: 'short' });
  h.state.session = clientSession();
  assertUnavailable(await h.call('GET', ['decisions']), h);
});

test('C9 enforcement recovers after Redis is restored without a restart', async () => {
  const h = setup();
  h.state.session = clientSession();
  h.backend.mode = 'refuse';
  assertUnavailable(await h.call('GET', ['decisions']), h);
  h.backend.mode = 'ok';
  // ioredis reconnects in the background; requests fail closed until the
  // client is ready again, then enforcement resumes on the same client.
  const statuses = [];
  for (let i = 0; i < 3 && statuses[statuses.length - 1] !== 200; i += 1) {
    statuses.push((await h.call('GET', ['decisions'])).status);
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(statuses[statuses.length - 1], 200, `recovered: ${statuses}`);
  assert.ok(statuses.every((s) => s === 200 || s === 503), 'never fails open while reconnecting');
  assert.equal(h.state.redisClients.length, 1, 'recovery reuses the single worker client');
});

test('C10 Redis client is configured with bounded, non-retrying commands', async () => {
  const h = setup();
  h.state.session = clientSession();
  await h.call('GET', ['decisions']);
  const { options } = h.state.redisClients[0];
  assert.equal(options.lazyConnect, true);
  assert.equal(options.enableOfflineQueue, false);
  assert.equal(options.maxRetriesPerRequest, 0);
  assert.equal(options.commandTimeout, 150);
  assert.ok(options.connectTimeout > 0 && options.connectTimeout <= 2000);
  assert.ok(options.retryStrategy(1000) <= 2000, 'reconnect backoff is capped');
});

// ─── D. Atomicity and concurrency ────────────────────────────────────────────

test('D1 each request is one atomic EVAL — never a separate INCR or EXPIRE (regression)', async () => {
  const h = setup();
  h.state.session = clientSession();
  await h.call('GET', ['decisions']);
  await h.call('GET', ['decisions']);
  assert.equal(h.backend.calls.eval, 2);
  assert.equal(h.backend.calls.incr, 0);
  assert.equal(h.backend.calls.expire, 0);
  const script = h.backend.scripts[0];
  assert.match(script, /redis\.call\('INCR', KEYS\[1\]\)/);
  assert.match(script, /redis\.call\('EXPIRE', KEYS\[1\], tonumber\(ARGV\[1\]\)\)/);
  assert.match(script, /PTTL/);
});

test('D2 concurrent first requests near quota: exactly maxRequests allowed, TTL set once', async () => {
  const h = setup();
  h.state.session = clientSession();
  const results = await Promise.all(Array.from({ length: 6 }, () => h.call('GET', ['decisions'])));
  const statuses = results.map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 200, 200, 429, 429, 429]);
  const [key] = limiterKeys(h);
  assert.equal(h.backend.ttlMs(key), 60_000, 'TTL equals the configured window');
  assert.equal(h.state.coreCalls.length, 3);
});

test('D3 counter expiry restores quota after the window', async () => {
  const h = setup();
  h.state.session = clientSession();
  for (let i = 0; i < 3; i += 1) await h.call('GET', ['decisions']);
  assert.equal((await h.call('GET', ['decisions'])).status, 429);
  h.backend.advance(60_001);
  assert.equal((await h.call('GET', ['decisions'])).status, 200);
});

test('D4 a counter left without TTL (interrupted legacy write) is repaired on next increment', async () => {
  const h = setup();
  h.state.session = clientSession();
  await h.call('GET', ['decisions']);
  const [key] = limiterKeys(h);
  h.backend.entries.get(key).expiresAt = null; // simulate a TTL-less counter
  assert.equal(h.backend.ttlMs(key), -1);
  await h.call('GET', ['decisions']);
  assert.equal(h.backend.ttlMs(key), 60_000);
});

test('D5 transient failures do not reset or double-count quota', async () => {
  const h = setup();
  h.state.session = clientSession();
  await h.call('GET', ['decisions']);
  await h.call('GET', ['decisions']);
  h.backend.mode = 'refuse';
  assert.equal((await h.call('GET', ['decisions'])).status, 503);
  h.backend.mode = 'ok';
  const [key] = limiterKeys(h);
  assert.equal(h.backend.entries.get(key).count, 2, 'failed attempt did not increment');
  assert.equal((await h.call('GET', ['decisions'])).status, 200);
  assert.equal((await h.call('GET', ['decisions'])).status, 429, 'quota was not reset by the outage');
});

test('D6 backend failure during first-connect initialization fails closed, then recovers', async () => {
  const h = setup();
  h.state.session = clientSession();
  h.backend.mode = 'hang';
  const res = await h.call('GET', ['decisions']);
  assert.equal(res.status, 503);
  assert.ok(h.backend.calls.connect >= 1, 'lazy connect was attempted under the deadline');
});

// ─── E. Route-risk classification ────────────────────────────────────────────

function parseProxyRules(source) {
  const rules = new Map();
  for (const match of source.matchAll(/\{ prefix: '([^']+)', methods: new Set\(\[([^\]]*)\]\) \}/g)) {
    const methods = match[2].split(',').map((m) => m.trim().replace(/'/g, '')).filter(Boolean).sort();
    rules.set(match[1], methods);
  }
  return rules;
}

test('E1 every PROXY_RULES (prefix, method) has an explicit tier, and the policy names no unproxied pair', () => {
  const h = setup();
  const policy = h.loadModule('@/lib/bffRateLimitPolicy');
  const rules = parseProxyRules(h.routeSource());
  assert.ok(rules.size >= 50, `parsed ${rules.size} PROXY_RULES`);
  const families = new Map(policy.BFF_ROUTE_FAMILIES.map((f) => [f.prefix, Object.keys(f.tiers).sort()]));
  assert.deepEqual([...families.keys()].sort(), [...rules.keys()].sort(), 'policy families must equal PROXY_RULES prefixes');
  for (const [prefix, methods] of rules) {
    assert.deepEqual(families.get(prefix), methods, `methods for ${prefix} must match PROXY_RULES`);
    for (const method of methods) {
      const result = policy.classifyBffRoute(prefix.split('/'), method);
      assert.equal(result.ok, true, `${method} ${prefix} must classify`);
      assert.match(result.tier, /^R[0-3]$/);
    }
  }
  const ids = policy.BFF_ROUTE_FAMILIES.map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length, 'family ids are unique');
});

test('E2 unknown routes, unknown methods and malformed segments default to deny', () => {
  const h = setup();
  const { classifyBffRoute } = h.loadModule('@/lib/bffRateLimitPolicy');
  assert.equal(classifyBffRoute(['nope'], 'GET').ok, false);
  assert.equal(classifyBffRoute([], 'GET').ok, false);
  assert.equal(classifyBffRoute(['decisions'], 'DELETE').ok, false);
  assert.equal(classifyBffRoute(['decisions'], 'OPTIONS').ok, false);
  assert.equal(classifyBffRoute(['decisions'], '').ok, false);
  assert.equal(classifyBffRoute(['decisionsx'], 'GET').ok, false, 'no prefix confusion');
  assert.equal(classifyBffRoute(['admin', 'connectors', 'status'], 'POST').ok, false, 'longest prefix governs');
  assert.equal(classifyBffRoute(['decisions', '..', 'keys'], 'GET').reason, 'MALFORMED_PATH');
  assert.equal(classifyBffRoute(['decisions', '.'], 'GET').reason, 'MALFORMED_PATH');
  assert.equal(classifyBffRoute(['decisions', 'a/b'], 'GET').reason, 'MALFORMED_PATH');
  assert.equal(classifyBffRoute(['decisions', ''], 'GET').reason, 'MALFORMED_PATH');
  assert.equal(classifyBffRoute(['alignment-artifact', 'x'], 'GET').ok, false);
  assert.equal(classifyBffRoute(['alignment-artifact'], 'POST').ok, false);
});

test('E3 a dot-segment path is denied at the real route before Core (no upstream path normalisation)', async () => {
  const h = setup();
  h.state.session = clientSession();
  const res = await h.call('GET', ['decisions', '..', 'keys'], { rawPath: 'decisions/%2E%2E/keys' });
  assert.equal(res.status, 403);
  assert.equal(res.json?.code, 'BFF_ROUTE_UNCLASSIFIED');
  assert.equal(h.state.coreCalls.length, 0);
});

test('E4 high-risk sub-actions override their parent tier; exports never inherit read tier', () => {
  const h = setup();
  const { classifyBffRoute: c } = h.loadModule('@/lib/bffRateLimitPolicy');
  const fa = ['field-assessment', 'engagements', 'e1'];
  assert.equal(c(fa, 'GET').tier, 'R1');
  assert.equal(c([...fa, 'reports', 'r1', 'export'], 'GET').tier, 'R2');
  assert.equal(c([...fa, 'reports', 'r1', 'verify'], 'GET').tier, 'R2');
  assert.equal(c([...fa, 'verification-bundle', 'manifest'], 'GET').tier, 'R2');
  assert.equal(c([...fa, 'reports', 'r1', 'release'], 'POST').tier, 'R3');
  assert.equal(c([...fa, 'reports', 'r1', 'qa-approve'], 'POST').tier, 'R3');
  assert.equal(c(['audit', 'export'], 'GET').tier, 'R2');
  assert.equal(c(['forensics', 'chain', 'verify'], 'GET').tier, 'R2');
  assert.equal(c(['keys'], 'GET').tier, 'R2');
  assert.equal(c(['keys'], 'POST').tier, 'R3');
  assert.equal(c(['ui', 'ai', 'chat'], 'POST').tier, 'R2');
  assert.equal(c(['rag', 'retrieval-policy'], 'PUT').tier, 'R3');
  assert.equal(c(['admin', 'connectors'], 'POST').tier, 'R3');
  assert.equal(c(['admin', 'agent', 'quarantine'], 'POST').tier, 'R3');
  assert.equal(c(['governance', 'graph'], 'POST').tier, 'R3');
  assert.equal(c(['admin', 'tenants', 't', 'users'], 'POST').tier, 'R3');
  assert.equal(c(['admin', 'msp', 'reports', 'r1'], 'GET').tier, 'R2');
  assert.equal(c(['api', 'executive', 'overview'], 'GET').tier, 'R1');
  assert.equal(c(['health', 'live'], 'GET').tier, 'R0');
  assert.equal(c(['identity', 'invitations', TOKEN_1, 'accept'], 'POST').tier, 'R3');
});

test('E5 invitation preflight uses the special public policy; alignment artifact is classified', () => {
  const h = setup();
  const { classifyBffRoute: c } = h.loadModule('@/lib/bffRateLimitPolicy');
  const preflight = c(['identity', 'invitations', TOKEN_1], 'GET');
  assert.equal(preflight.familyId, 'identity.invitations.preflight');
  assert.equal(preflight.publicEndpoint, true);
  assert.equal(preflight.failureMode, 'deny');
  assert.equal(c(['identity', 'invitations', TOKEN_1, 'accept'], 'POST').publicEndpoint, false);
  assert.equal(c(['alignment-artifact'], 'GET').familyId, 'alignment-artifact');
});

test('E6 every tier fails closed', () => {
  const h = setup();
  const policy = h.loadModule('@/lib/bffRateLimitPolicy');
  assert.deepEqual(Object.values(policy.TIER_FAILURE_MODE), ['deny', 'deny', 'deny', 'deny']);
  for (const family of policy.BFF_ROUTE_FAMILIES) {
    for (const method of Object.keys(family.tiers)) {
      assert.equal(policy.classifyBffRoute(family.prefix.split('/'), method).failureMode, 'deny');
    }
  }
});

// ─── F. Public invitation safety ─────────────────────────────────────────────

test('F1 malformed tokens and any query parameters are rejected without Core call or quota use', async () => {
  const h = setup();
  for (const [token, query] of [
    ['not-a-token', ''],
    [`fgwi1.${'z'.repeat(64)}`, ''],
    [`${TOKEN_1}0`, ''],
    [TOKEN_1, `?token=${TOKEN_2}`],
    [TOKEN_1, '?x=1&x=2'],
  ]) {
    const res = await h.call('GET', ['identity', 'invitations', token], { query });
    assert.equal(res.status, 404, `${token}${query}`);
    assert.equal(res.json?.detail?.code, 'INVITATION_NOT_FOUND');
  }
  assert.equal(h.state.coreCalls.length, 0);
  assert.equal(h.backend.calls.eval, 0);
});

test('F2 token preflight is bounded per token; rotating headers cannot mint quota', async () => {
  const h = setup();
  const statuses = [];
  for (let i = 0; i < 3; i += 1) {
    const res = await h.call('GET', ['identity', 'invitations', TOKEN_1], {
      headers: { 'x-forwarded-for': `198.51.100.${i}`, 'x-real-ip': `198.51.100.${i}`, 'x-frostgate-user': `u${i}` },
    });
    statuses.push(res.status);
  }
  assert.deepEqual(statuses, [200, 200, 429]);
  assert.equal(h.state.coreCalls.length, 2);
});

test('F3 preflight is bounded deployment-wide across tokens (token guessing is bounded)', async () => {
  const h = setup();
  const statuses = [];
  for (let i = 0; i < 6; i += 1) {
    const token = `fgwi1.${i.toString(16).padStart(2, '0').repeat(32)}`;
    statuses.push((await h.call('GET', ['identity', 'invitations', token])).status);
  }
  assert.deepEqual(statuses, [200, 200, 200, 200, 200, 429]);
});

test('F4 Redis failure on preflight fails closed (no unlimited token guessing)', async () => {
  const h = setup();
  h.backend.mode = 'refuse';
  assertUnavailable(await h.call('GET', ['identity', 'invitations', TOKEN_1]), h);
});

test('F5 preflight never borrows operator tenant or credentials', async () => {
  const h = setup();
  const res = await h.call('GET', ['identity', 'invitations', TOKEN_1]);
  assert.equal(res.status, 200);
  const core = h.state.coreCalls[0];
  assert.equal(core.headers['x-tenant-id'], undefined);
  assert.equal(core.headers['x-api-key'], undefined);
  assert.equal(core.headers['x-fg-internal-token'], undefined);
  assert.equal(h.state.tenantKeyLookups.length, 0);
});

test('F6 authenticated invitation acceptance is bounded by the session principal and fails closed', async () => {
  const h = setup();
  h.state.session = clientSession();
  const statuses = [];
  for (let i = 0; i < 4; i += 1) {
    statuses.push((await h.call('POST', ['identity', 'invitations', TOKEN_1, 'accept'], {
      headers: { 'x-frostgate-user': `rot${i}`, 'x-forwarded-for': `198.51.100.${i}` },
    })).status);
  }
  assert.deepEqual(statuses, [200, 200, 200, 429]);
  const h2 = setup();
  h2.state.session = clientSession();
  h2.backend.mode = 'refuse';
  assertUnavailable(await h2.call('POST', ['identity', 'invitations', TOKEN_1, 'accept']), h2);
});

test('F7 no invitation token appears in any log line or limiter key', async () => {
  const h = setup();
  h.state.session = clientSession();
  await h.call('GET', ['identity', 'invitations', TOKEN_1]);
  await h.call('GET', ['identity', 'invitations', TOKEN_1]);
  await h.call('GET', ['identity', 'invitations', TOKEN_1]); // 429, emits event
  await h.call('POST', ['identity', 'invitations', TOKEN_1, 'accept']);
  h.backend.mode = 'refuse';
  await h.call('GET', ['identity', 'invitations', TOKEN_2]);
  const text = `${h.allLogText()}\n${limiterKeys(h).join('\n')}`;
  assert.ok(h.state.logs.length > 0);
  assert.doesNotMatch(text, /deadbeef|cafebabe|fgwi1\./);
});

// ─── G. Availability and compatibility ───────────────────────────────────────

test('G1 quota exceeded is 429 and distinct from 503 enforcement-unavailable', async () => {
  const h = setup();
  h.state.session = clientSession();
  for (let i = 0; i < 3; i += 1) await h.call('GET', ['decisions']);
  const limited = await h.call('GET', ['decisions']);
  assert.equal(limited.status, 429);
  assert.equal(limited.json?.code, 'HTTP_429');
  h.backend.mode = 'refuse';
  const unavailable = await h.call('GET', ['decisions']);
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.headers.get('retry-after'), '5');
});

test('G2 tenant-admin delegated routes keep working with a healthy backend', async () => {
  const h = setup();
  h.state.session = clientSession(SUBJECT_A, TENANT_A, ['tenant_admin']);
  const res = await h.call('GET', ['admin', 'tenants', TENANT_A, 'users']);
  assert.equal(res.status, 200);
  const core = h.state.coreCalls[0];
  assert.equal(core.headers['x-fg-named-user-sub'], SUBJECT_A);
  assert.equal(core.headers['x-fg-actor-authority'], 'tenant_human');
  assert.equal(core.headers['x-tenant-id'], TENANT_A);
  assert.ok(core.headers['x-fg-delegation-proof']);
});

test('G3 Upstash backend preserves normal behaviour and uses one atomic EVAL per request', async () => {
  const h = setup(UPSTASH_ENV);
  h.state.session = clientSession();
  const statuses = [];
  for (let i = 0; i < 4; i += 1) statuses.push((await h.call('GET', ['decisions'])).status);
  assert.deepEqual(statuses, [200, 200, 200, 429]);
  assert.equal(h.backend.calls.incr + h.backend.calls.expire, 0);
  for (const call of h.state.upstashCalls) {
    assert.equal(call.url, 'https://upstash.test');
    assert.equal(JSON.parse(call.body)[0], 'EVAL');
  }
});

// ─── H. Privacy ──────────────────────────────────────────────────────────────

test('H1 limiter keys and limiter events contain no raw subject, tenant, IP, token or secret', async () => {
  const h = setup();
  h.state.session = clientSession();
  const spoof = { headers: { 'x-forwarded-for': CLIENT_IP, 'x-real-ip': CLIENT_IP, authorization: `Bearer ${AUTH_SECRET}` } };
  for (let i = 0; i < 4; i += 1) await h.call('GET', ['decisions'], spoof);
  h.state.session = adminSession();
  for (let i = 0; i < 4; i += 1) await h.call('GET', ['decisions'], { ...spoof, query: `?tenant_id=${TENANT_B}` });
  h.backend.mode = 'refuse';
  await h.call('GET', ['decisions'], { ...spoof, query: `?tenant_id=${TENANT_B}` });

  const keys = limiterKeys(h);
  assert.equal(keys.length, 2);
  for (const key of keys) {
    assert.match(key, /^fg:bff:rl:v1:decisions:[0-9a-f]{32}$/);
    for (const sentinel of SENTINELS) assert.ok(!key.includes(sentinel), `key leaks ${sentinel}`);
  }
  const events = h.state.logs.filter((entry) => entry.text.includes('bff_rate_limit'));
  assert.ok(events.some((e) => e.text.includes('bff_rate_limit_quota_exceeded')));
  assert.ok(events.some((e) => e.text.includes('bff_rate_limit_enforcement_unavailable')));
  for (const event of events) {
    for (const sentinel of SENTINELS) assert.ok(!event.text.includes(sentinel), `limiter event leaks ${sentinel}`);
    const payload = JSON.parse(event.text.replace(/^\[core-proxy\] /, ''));
    assert.equal(payload.policy_version, 'fg-849.v1');
    assert.match(payload.risk_tier, /^R[0-3]$/);
    assert.equal(payload.route_family, 'decisions');
  }
  // No log line at all may carry the subject, client IP, auth header or secret.
  const all = h.allLogText();
  for (const sentinel of [SUBJECT_A, ADMIN_SUBJECT, 'SENTINELSUBJECT', CLIENT_IP, AUTH_SECRET]) {
    assert.ok(!all.includes(sentinel), `operational log leaks ${sentinel}`);
  }
});

test('H2 Upstash token never appears in logs or 503 bodies', async () => {
  const h = setup(UPSTASH_ENV);
  h.state.session = clientSession();
  h.backend.mode = 'http5xx';
  const res = await h.call('GET', ['decisions']);
  assert.equal(res.status, 503);
  assert.ok(!res.text.includes(UPSTASH_TOKEN));
  assert.ok(!h.allLogText().includes(UPSTASH_TOKEN));
});

test('H3 outage logging is throttled (no log amplification)', async () => {
  const h = setup();
  h.state.session = clientSession();
  h.backend.mode = 'refuse';
  for (let i = 0; i < 25; i += 1) await h.call('GET', ['decisions']);
  const events = h.state.logs.filter((e) => e.text.includes('bff_rate_limit_enforcement_unavailable'));
  assert.equal(events.length, 1);
});

test('H4 partition is deterministic within a key epoch and changes on rotation', () => {
  const h = setup();
  const policy = h.loadModule('@/lib/bffRateLimitPolicy');
  const a = policy.resolveLimiterKeyMaterial();
  const b = policy.resolveLimiterKeyMaterial();
  assert.equal(a.ok && b.ok, true);
  assert.equal(a.source, 'derived-auth-secret');
  const k1 = policy.deriveAuthenticatedRateLimitKey(a.key, 'decisions', 'tenant', TENANT_A, SUBJECT_A).key;
  assert.equal(policy.deriveAuthenticatedRateLimitKey(b.key, 'decisions', 'tenant', TENANT_A, SUBJECT_A).key, k1);
  // Component boundaries cannot be shifted to forge another partition.
  assert.notEqual(policy.deriveAuthenticatedRateLimitKey(a.key, 'decisions', 'tenant', 'ab', 'c').key,
    policy.deriveAuthenticatedRateLimitKey(a.key, 'decisions', 'tenant', 'a', 'bc').key);
  // Scope separates tenant-independent partitions from a tenant literally named "invitation".
  assert.notEqual(policy.deriveAuthenticatedRateLimitKey(a.key, 'identity', 'tenant', 'invitation', SUBJECT_A).key,
    policy.deriveAuthenticatedRateLimitKey(a.key, 'identity', 'tenant-independent', 'invitation', SUBJECT_A).key);
  process.env.BFF_RATE_LIMIT_KEY_SECRET = 'rotated-dedicated-secret-0123456789abcdef';
  const rotated = policy.resolveLimiterKeyMaterial();
  assert.equal(rotated.source, 'dedicated');
  assert.notEqual(policy.deriveAuthenticatedRateLimitKey(rotated.key, 'decisions', 'tenant', TENANT_A, SUBJECT_A).key, k1);
});
