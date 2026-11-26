/**
 * FG-849-REPAIR-001 — Redis outage behaviour with the REAL ioredis client.
 *
 * No Redis service is needed: failures are produced by a closed local port
 * and by small local TCP servers that drop connections, never answer, or
 * answer every command with NOAUTH. Deterministic and bounded.
 *
 * Proves (found by real-Redis validation, missed by mocks):
 *   - the limiter client never prints raw ioredis errors (host:port, stack)
 *     during an outage, while the route still returns 503 and emits the
 *     throttled bff_rate_limit_enforcement_unavailable event;
 *   - failed /api/health Redis probes never reconnect and leave no sockets or
 *     timers behind, so repeated probes during an outage do not accumulate.
 *
 * FG849_STORE_SOURCE may point at another rateLimitStore.ts (baseline proof).
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const Module = require('node:module');
const net = require('node:net');
const path = require('node:path');
const test = require('node:test');
const ts = require('typescript');
const { createHarness, snapshotEnv, applyEnv, restoreEnv } = require('./helpers/bffRouteHarness');

const SOURCE = process.env.FG849_STORE_SOURCE || path.join(__dirname, '..', 'lib', 'rateLimitStore.ts');
const CONSOLE_ROOT = path.join(__dirname, '..');

function loadStore() {
  const { outputText } = ts.transpileModule(fs.readFileSync(SOURCE, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: SOURCE,
  });
  const mod = new Module(SOURCE, module);
  mod.filename = SOURCE;
  mod.paths = Module._nodeModulePaths(CONSOLE_ROOT);
  mod._compile(outputText, SOURCE);
  return mod.exports;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function captureConsole() {
  const lines = [];
  const originals = { error: console.error, warn: console.warn, log: console.log, info: console.info };
  for (const level of Object.keys(originals)) console[level] = (...args) => lines.push(args.map(String).join(' '));
  return { lines, restore: () => Object.assign(console, originals) };
}

function activeNetResources() {
  const info = process.getActiveResourcesInfo();
  return {
    sockets: info.filter((r) => r === 'TCPSocketWrap' || r === 'TCPWRAP').length,
    timers: info.filter((r) => r === 'Timeout').length,
  };
}

async function closedPort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

/** behaviour: 'drop' (accept then destroy), 'silent' (never reply), 'noauth'. */
async function failingServer(behaviour) {
  const sockets = new Set();
  let connections = 0;
  const server = net.createServer((socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    if (behaviour === 'drop') socket.destroy();
    // Read (and ignore) client data so a client close is observed as 'end'.
    if (behaviour === 'silent') socket.resume();
    if (behaviour === 'noauth') socket.on('data', () => socket.write('-NOAUTH Authentication required.\r\n'));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `redis://127.0.0.1:${server.address().port}/0`,
    connections: () => connections,
    openSockets: () => sockets.size,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

const savedEnv = snapshotEnv();
test.after(() => restoreEnv(savedEnv));

function prodEnv(redisUrl) {
  applyEnv({
    NODE_ENV: 'production',
    FG_ENV: 'prod',
    BFF_REDIS_URL: redisUrl,
    BFF_RATE_LIMIT_TIMEOUT_MS: '200',
    AUTH_SECRET: 'synthetic-auth-secret-for-outage-tests-0123456789',
    CORE_API_URL: 'http://core.test',
    CORE_TENANT_ID: 'fg-operator',
  });
}

// ─── Health probe: bounded, single attempt, always closed ────────────────────

for (const scenario of ['refused', 'drop', 'silent', 'noauth']) {
  test(`health probe (${scenario}): 5 failed probes leave no reconnects, sockets, timers or raw errors`, async () => {
    const server = scenario === 'refused' ? null : await failingServer(scenario);
    const url = server ? server.url : `redis://127.0.0.1:${await closedPort()}/0`;
    prodEnv(url);
    const store = loadStore();
    const before = activeNetResources();
    const output = captureConsole();
    try {
      for (let i = 0; i < 5; i += 1) {
        const started = Date.now();
        const health = await store.getRateLimitHealth();
        assert.equal(health.ready, false);
        assert.equal(health.reason, 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE');
        assert.ok(Date.now() - started < 3000, `probe bounded (${Date.now() - started} ms)`);
      }
      const connectionsAfterProbes = server ? server.connections() : 0;
      // Longer than any ioredis reconnect delay and than the probe's 1500 ms
      // connectTimeout: ioredis leaves that one timer to expire on its own,
      // which is bounded and never accumulates past this point.
      await sleep(2300);
      if (server) {
        assert.equal(server.connections(), connectionsAfterProbes, 'no reconnect cycle after the probes returned');
        assert.ok(connectionsAfterProbes <= 5, `at most one connection per probe (${connectionsAfterProbes})`);
        assert.equal(server.openSockets(), 0, 'every probe connection was closed');
      }
      const after = activeNetResources();
      assert.ok(after.sockets <= before.sockets, `no leaked sockets (${before.sockets} -> ${after.sockets})`);
      assert.ok(after.timers <= before.timers, `no leaked reconnect timers (${before.timers} -> ${after.timers})`);
    } finally {
      output.restore();
      if (server) await server.close();
    }
    assert.equal(output.lines.filter((l) => l.includes('[ioredis]')).length, 0, `raw ioredis output: ${output.lines.join(' | ')}`);
  });
}

// ─── Limiter client: no raw error output, still fails closed ─────────────────

test('limiter client under outage: rejects (fail closed) without printing raw ioredis errors', async () => {
  const port = await closedPort();
  prodEnv(`redis://127.0.0.1:${port}/0`);
  const store = loadStore();
  const built = await store.buildRateLimitStore();
  assert.equal(built.unavailable, false);
  const output = captureConsole();
  try {
    for (let i = 0; i < 5; i += 1) await assert.rejects(built.store.increment('fg849:outage', 60, 10));
    await sleep(2500); // several background reconnect attempts
  } finally {
    output.restore();
    built.store.client.disconnect();
  }
  const raw = output.lines.filter((l) => l.includes('[ioredis]') || l.includes(String(port)));
  assert.equal(raw.length, 0, `raw ioredis output leaked: ${raw.slice(0, 2).join(' | ')}`);
  assert.ok(built.store.client.listenerCount('error') >= 1, 'an error listener prevents unhandled error events');
});

test('real route with real ioredis under outage: 503, no Core call, sanitized throttled event only', async () => {
  const port = await closedPort();
  prodEnv(`redis://127.0.0.1:${port}/0`);
  const h = createHarness({ realIoredis: true });
  h.state.session = {
    user: { id: 'auth0|synthetic-outage-subject' },
    roles: ['Administrator'],
    experienceClass: 'internal_console',
  };
  const output = captureConsole();
  const statuses = [];
  try {
    for (let i = 0; i < 4; i += 1) {
      statuses.push((await h.call('POST', ['keys'], { query: '?tenant_id=synthetic-tenant', body: { name: 'k' } })).status);
    }
    await sleep(1500);
  } finally {
    output.restore();
    const store = await h.loadModule('@/lib/rateLimitStore').getRateLimitStore();
    if (store.store && store.store.client) store.store.client.disconnect();
  }
  assert.deepEqual(statuses, [503, 503, 503, 503]);
  assert.equal(h.state.coreCalls.length, 0);
  const all = `${output.lines.join('\n')}\n${h.allLogText()}`;
  assert.doesNotMatch(all, /\[ioredis\]/);
  assert.ok(!all.includes(`127.0.0.1:${port}`), 'no Redis endpoint in diagnostics');
  const events = h.state.logs.filter((e) => e.text.includes('bff_rate_limit_enforcement_unavailable'));
  assert.equal(events.length, 1, 'structured event retained and throttled');
  assert.match(events[0].text, /"backend_health":"(backend_error|timeout)"/);
});
