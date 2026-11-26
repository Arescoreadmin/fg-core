/**
 * FG-849-REPAIR-001 — executes the REAL Core BFF route handler
 * (app/api/core/[...path]/route.ts) and its real dependencies
 * (lib/rateLimitStore.ts, lib/bffRateLimitPolicy.ts, lib/consoleAccess.js,
 * lib/internal-gateway-secret.ts, next/server) under Node's test runner.
 *
 * Only the true external boundaries are replaced:
 *   - '@/auth'                → returns the session the test sets
 *   - '@/lib/tenant-registry' → returns a synthetic per-tenant Core key
 *   - 'ioredis'               → FakeRedis bound to a controllable backend
 *   - globalThis.fetch        → Core API and Upstash REST fakes
 *
 * Each createHarness() call loads a fresh module graph, i.e. a fresh worker
 * with its own rate-limit store singleton.
 *
 * FG849_HARNESS_ROOT may point at another checkout of apps/console (used to
 * demonstrate the defects on the pre-repair baseline). node_modules always
 * resolve from this Console's package.
 */

'use strict';

const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const ts = require('typescript');

const CONSOLE_ROOT = path.join(__dirname, '..', '..');
const ROUTE_REL = path.join('app', 'api', 'core', '[...path]', 'route.ts');
const consoleRequire = Module.createRequire(path.join(CONSOLE_ROOT, 'package.json'));

// ─── Fake Redis backend ──────────────────────────────────────────────────────

/**
 * Emulates the Redis server for one key space. eval() emulates the semantics
 * of RATE_LIMIT_INCREMENT_LUA (INCR; EXPIRE when count == 1 or no TTL). The
 * real Lua against a real Redis is covered by the opt-in test in
 * bff-rate-limit-redis-atomicity.test.js.
 */
class FakeRedisBackend {
  constructor() {
    this.mode = 'ok';
    this.entries = new Map();
    this.clock = 0;
    this.calls = { eval: 0, incr: 0, expire: 0, connect: 0 };
    this.scripts = [];
  }

  now() {
    return this.clock;
  }

  advance(ms) {
    this.clock += ms;
  }

  live(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return null;
    }
    return entry;
  }

  ttlMs(key) {
    const entry = this.live(key);
    if (!entry) return -2;
    return entry.expiresAt === null ? -1 : entry.expiresAt - this.now();
  }

  failure() {
    switch (this.mode) {
      case 'refuse': {
        const err = new Error('connect ECONNREFUSED 10.0.0.1:6379');
        err.code = 'ECONNREFUSED';
        return err;
      }
      case 'auth':
        return new Error('NOAUTH Authentication required.');
      case 'throw':
        return new Error('ERR unexpected failure');
      default:
        return null;
    }
  }

  async connect() {
    this.calls.connect += 1;
    const err = this.failure();
    if (err) throw err;
    if (this.mode === 'hang') return new Promise(() => {});
    return 'OK';
  }

  async eval(script, numKeys, key, windowSec) {
    this.calls.eval += 1;
    this.scripts.push(script);
    const err = this.failure();
    if (err) throw err;
    if (this.mode === 'hang') return new Promise(() => {});
    if (this.mode === 'malformed') return 'OK';
    assert1(numKeys === 1, 'script must declare exactly one key');
    const entry = this.live(key) || { count: 0, expiresAt: null };
    entry.count += 1;
    if (entry.count === 1 || entry.expiresAt === null) {
      entry.expiresAt = this.now() + Number(windowSec) * 1000;
    }
    this.entries.set(key, entry);
    return entry.count;
  }

  // Non-atomic primitives used by the pre-repair store; counted so tests can
  // prove the repaired store never issues a separate INCR/EXPIRE.
  async incr(key) {
    this.calls.incr += 1;
    const err = this.failure();
    if (err) throw err;
    if (this.mode === 'hang') return new Promise(() => {});
    const entry = this.live(key) || { count: 0, expiresAt: null };
    entry.count += 1;
    this.entries.set(key, entry);
    return entry.count;
  }

  async expire(key, seconds) {
    this.calls.expire += 1;
    const err = this.failure();
    if (err) throw err;
    const entry = this.live(key);
    if (!entry) return 0;
    entry.expiresAt = this.now() + Number(seconds) * 1000;
    return 1;
  }
}

function assert1(cond, message) {
  if (!cond) throw new Error(message);
}

function makeFakeIoredis(backend, state) {
  class FakeRedis {
    constructor(url, options) {
      state.redisClients.push({ url, options });
      this.options = options || {};
      this.status = this.options.lazyConnect ? 'wait' : 'ready';
    }
    connect() {
      // Like ioredis: status leaves 'wait' synchronously; resolves on 'ready'.
      this.status = 'connecting';
      return backend.connect().then(
        (result) => {
          this.status = 'ready';
          return result;
        },
        (err) => {
          this.status = 'reconnecting';
          throw err;
        },
      );
    }
    notWritable() {
      // ioredis with enableOfflineQueue:false rejects commands until 'ready'.
      if (this.status === 'ready' || this.options.enableOfflineQueue !== false) return null;
      if ((this.status === 'wait' && this.options.lazyConnect) || this.status === 'reconnecting') {
        // ioredis auto-connects on the first command, and its retryStrategy
        // timer reconnects after a failure; the command itself still fails
        // because the offline queue is disabled.
        this.connect().catch(() => {});
      }
      return Promise.reject(new Error("Stream isn't writeable and enableOfflineQueue options is false"));
    }
    eval(...args) {
      return this.notWritable() || backend.eval(...args);
    }
    incr(key) {
      return this.notWritable() || backend.incr(key);
    }
    expire(key, seconds) {
      return this.notWritable() || backend.expire(key, seconds);
    }
    async ping() {
      const err = backend.failure();
      if (err) throw err;
      return 'PONG';
    }
    async quit() {
      return 'OK';
    }
  }
  return { __esModule: true, default: FakeRedis };
}

// ─── Upstash REST fake ───────────────────────────────────────────────────────

function upstashResponder(backend, state) {
  return async (url, init) => {
    state.upstashCalls.push({ url: String(url), body: init && init.body });
    if (backend.mode === 'http5xx') return new Response('upstream error', { status: 503 });
    if (backend.mode === 'hang') {
      return new Promise((_, reject) => {
        const signal = init && init.signal;
        if (!signal) return; // unbounded: the test's own timeout would catch this
        signal.addEventListener('abort', () => reject(signal.reason || new Error('aborted')), { once: true });
      });
    }
    if (backend.mode === 'malformed') return new Response('<html>not json</html>', { status: 200 });
    if (backend.mode === 'nonnumeric') return Response.json({ result: 'QUEUED' });
    const err = backend.failure();
    if (err) throw err;
    const args = JSON.parse(String(init.body));
    const command = String(args[0]).toUpperCase();
    if (command === 'PING') return Response.json({ result: 'PONG' });
    if (command === 'EVAL') {
      const [, script, numKeys, key, windowSec] = args;
      return Response.json({ result: await backend.eval(script, Number(numKeys), key, windowSec) });
    }
    if (command === 'INCR') return Response.json({ result: await backend.incr(args[1]) });
    if (command === 'EXPIRE') return Response.json({ result: await backend.expire(args[1], args[2]) });
    // Pre-repair path-style commands: /incr/{key}, /expire/{key}/{s}
    return Response.json({ error: `unsupported command ${command}` });
  };
}

// ─── Module loader ───────────────────────────────────────────────────────────

function resolveFile(base) {
  for (const candidate of [base, `${base}.ts`, `${base}.js`, path.join(base, 'index.ts'), path.join(base, 'index.js')]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  throw new Error(`harness cannot resolve ${base}`);
}

function createHarness(options = {}) {
  const root = options.root || process.env.FG849_HARNESS_ROOT || CONSOLE_ROOT;
  const backend = new FakeRedisBackend();
  const state = {
    session: null,
    coreCalls: [],
    tenantKeyLookups: [],
    upstashCalls: [],
    redisClients: [],
    logs: [],
    coreResponder: null,
  };
  const stubs = {
    '@/auth': { auth: async () => state.session },
    '@/lib/tenant-registry': {
      getTenantApiKey: async (tenantId) => {
        state.tenantKeyLookups.push(tenantId);
        return { key: `synthetic-core-key-for-${tenantId}` };
      },
    },
    ioredis: makeFakeIoredis(backend, state),
  };
  const cache = new Map();

  function load(file) {
    if (cache.has(file)) return cache.get(file).exports;
    const source = fs.readFileSync(file, 'utf8');
    const code = file.endsWith('.ts')
      ? ts.transpileModule(source, {
          compilerOptions: {
            module: ts.ModuleKind.CommonJS,
            target: ts.ScriptTarget.ES2020,
            esModuleInterop: true,
          },
          fileName: file,
        }).outputText
      : source;
    const mod = new Module(file, module);
    mod.filename = file;
    mod.paths = Module._nodeModulePaths(CONSOLE_ROOT);
    cache.set(file, mod);
    mod.require = (spec) => {
      if (Object.prototype.hasOwnProperty.call(stubs, spec)) return stubs[spec];
      if (spec.startsWith('@/')) return load(resolveFile(path.join(root, spec.slice(2))));
      if (spec.startsWith('./') || spec.startsWith('../')) return load(resolveFile(path.resolve(path.dirname(file), spec)));
      return consoleRequire(spec);
    };
    const wrapper = Module.wrap(code);
    const compiled = require('node:vm').runInThisContext(wrapper, { filename: file });
    compiled.call(mod.exports, mod.exports, mod.require, mod, file, path.dirname(file));
    return mod.exports;
  }

  const coreApiUrl = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
  const upstashUrl = () =>
    (process.env.BFF_UPSTASH_REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, '');
  const upstash = upstashResponder(backend, state);

  async function fakeFetch(input, init = {}) {
    const url = String(input);
    const restRoot = upstashUrl();
    if (restRoot && (url === restRoot || url.startsWith(`${restRoot}/`))) return upstash(url, init);
    if (url.startsWith(coreApiUrl)) {
      const headers = Object.fromEntries(new Headers(init.headers || {}).entries());
      let body = init.body;
      if (body && typeof body !== 'string') body = '[stream]';
      state.coreCalls.push({ url, method: init.method || 'GET', headers, body });
      if (state.coreResponder) return state.coreResponder(url, init);
      return Response.json({ ok: true, surface: new URL(url).pathname });
    }
    throw new Error(`harness: unexpected outbound fetch to ${url}`);
  }

  const routeFile = path.join(root, ROUTE_REL);
  const nextServer = consoleRequire('next/server');

  async function call(method, segments, { query = '', headers = {}, body, rawPath } = {}) {
    const pathname = rawPath ?? segments.map((s) => encodeURIComponent(s)).join('/');
    const url = `http://console.test/api/core/${pathname}${query}`;
    const init = { method, headers: { ...headers } };
    if (body !== undefined) {
      init.body = typeof body === 'string' ? body : JSON.stringify(body);
      if (!Object.keys(init.headers).some((h) => h.toLowerCase() === 'content-type')) {
        init.headers['content-type'] = 'application/json';
      }
    }
    const request = new nextServer.NextRequest(url, init);
    const originalFetch = globalThis.fetch;
    const originals = { warn: console.warn, info: console.info, error: console.error, log: console.log };
    globalThis.fetch = fakeFetch;
    for (const level of Object.keys(originals)) {
      console[level] = (...args) => state.logs.push({ level, text: args.map(String).join(' ') });
    }
    try {
      const routeModule = load(routeFile);
      const handler = routeModule[method];
      if (typeof handler !== 'function') throw new Error(`route exports no ${method} handler`);
      const response = await handler(request, { params: Promise.resolve({ path: segments }) });
      let json = null;
      const text = await response.text();
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
      return { status: response.status, json, text, headers: response.headers };
    } finally {
      globalThis.fetch = originalFetch;
      Object.assign(console, originals);
    }
  }

  return {
    backend,
    state,
    call,
    loadModule(spec) {
      return load(resolveFile(path.join(root, spec.replace(/^@\//, ''))));
    },
    routeSource() {
      return fs.readFileSync(routeFile, 'utf8');
    },
    allLogText() {
      return state.logs.map((entry) => entry.text).join('\n');
    },
  };
}

// ─── Environment helpers ─────────────────────────────────────────────────────

const MANAGED_ENV = [
  'NODE_ENV',
  'FG_ENV',
  'CORE_API_URL',
  'CORE_TENANT_ID',
  'FG_CORE_API_KEY',
  'CORE_API_KEY',
  'AUTH_SECRET',
  'BFF_RATE_LIMIT_KEY_SECRET',
  'BFF_RATE_LIMIT_BACKEND',
  'BFF_REDIS_URL',
  'REDIS_URL',
  'BFF_UPSTASH_REDIS_REST_URL',
  'BFF_UPSTASH_REDIS_REST_TOKEN',
  'UPSTASH_REDIS_REST_URL',
  'UPSTASH_REDIS_REST_TOKEN',
  'KV_REST_API_URL',
  'KV_REST_API_TOKEN',
  'BFF_RATE_LIMIT_WINDOW_S',
  'BFF_RATE_LIMIT_MAX_REQUESTS',
  'BFF_RATE_LIMIT_TIMEOUT_MS',
  'BFF_RATE_LIMIT_PUBLIC_INVITATION_MAX_REQUESTS',
  'BFF_RATE_LIMIT_PUBLIC_INVITATION_TOKEN_MAX_REQUESTS',
  'FG_INTERNAL_GATEWAY_SECRET',
  'FG_ADMIN_GATEWAY_TOKEN',
  'FG_INTERNAL_AUTH_SECRET',
  'FG_INTERNAL_TOKEN',
  'FG_GATEWAY_DELEGATION_SECRET_CURRENT',
  'PLATFORM_AUTH_MODE',
  'FG_PLATFORM_ADMIN_KEY',
  'ALIGNMENT_ARTIFACT_URL',
];

function snapshotEnv() {
  return Object.fromEntries(MANAGED_ENV.map((key) => [key, process.env[key]]));
}

function applyEnv(env) {
  for (const key of MANAGED_ENV) delete process.env[key];
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) process.env[key] = value;
  }
}

function restoreEnv(snapshot) {
  for (const [key, value] of Object.entries(snapshot)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

module.exports = { createHarness, snapshotEnv, applyEnv, restoreEnv, FakeRedisBackend };
