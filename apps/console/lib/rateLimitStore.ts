/**
 * BFF Redis Rate-Limit Storage Adapter
 *
 * Architecture:
 *   - RedisRateLimitStore: production — ioredis EVAL of RATE_LIMIT_INCREMENT_LUA
 *   - UpstashRestRateLimitStore: production — Upstash/Vercel KV REST EVAL of the same script
 *   - MemoryRateLimitStore: dev/test only — in-process sliding window
 *   - getRateLimitStore(): factory — server-side only, never called in browser
 *
 * Secret safety:
 *   - BFF_REDIS_URL and all config read via process.env (server-only)
 *   - Never NEXT_PUBLIC_* for any rate-limit config
 *
 * Redis unavailable behavior:
 *   - dev/test: falls back to MemoryRateLimitStore (deterministic)
 *   - prod-like: returns { unavailable: true, errorCode } — the Core BFF route
 *     returns 503 BFF_RATE_LIMIT_UNAVAILABLE (FG-849-REPAIR-001, fail closed)
 *   - per-request backend failures (timeout, refusal, auth, HTTP 5xx,
 *     malformed reply) reject from increment(); the route also returns 503
 *
 * Atomicity (FG-849-REPAIR-001): increment and expiry run as one Lua script,
 * so no caller can observe a counter without a TTL, a failure cannot leave a
 * TTL-less counter, and a counter left without a TTL by an older release is
 * repaired on its next increment.
 *
 * Bounded latency: every remote operation is bounded by
 * BFF_RATE_LIMIT_TIMEOUT_MS (default 1000 ms, clamped 50-5000). Commands are
 * never retried, so a timed-out command can increment at most once.
 *
 * Prod-like enforcement (NODE_ENV=production or FG_ENV=prod/staging/production):
 *   - Missing/blank/CHANGE_ME Redis/Upstash config → errorCode: BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED
 *   - Valid config but Redis/Upstash unreachable → errorCode: BFF_RATE_LIMIT_REDIS_UNAVAILABLE
 *   - Memory fallback is NEVER allowed in prod-like environments
 *
 * Key format: fg:bff:rl:v1:{route_group}:{opaque HMAC partition}
 *   (derived in lib/bffRateLimitPolicy.ts; no raw subject, tenant or IP)
 * TTL: BFF_RATE_LIMIT_WINDOW_S (default 60s)
 */

import Redis from 'ioredis';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RateLimitResult {
  count: number;
  allowed: boolean;
  windowSec: number;
  /** false only when Redis is unavailable in prod-like mode */
  available: boolean;
}

export interface RateLimitStore {
  increment(key: string, windowSec: number, maxRequests: number): Promise<RateLimitResult>;
}

// ─── Error codes ──────────────────────────────────────────────────────────────

/** Stable error codes for BFF rate-limit unavailability. */
export type BffRateLimitErrorCode =
  /** BFF_REDIS_URL is missing, blank, or is a CHANGE_ME placeholder in prod-like env */
  | 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED'
  /** BFF_REDIS_URL is present but Redis is unreachable in prod-like env */
  | 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE';

// ─── Atomic increment ─────────────────────────────────────────────────────────

/**
 * INCR and EXPIRE in one server-side script. The TTL is set on the first
 * increment of a window, and also whenever the key has no TTL (PTTL < 0), so a
 * counter left without expiry by an interrupted non-atomic write is repaired.
 * The window comes from server config only (ARGV[1]); callers cannot extend it.
 */
export const RATE_LIMIT_INCREMENT_LUA = [
  "local c = redis.call('INCR', KEYS[1])",
  "if c == 1 or redis.call('PTTL', KEYS[1]) < 0 then",
  "  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))",
  'end',
  'return c',
].join('\n');

export type RateLimitBackendFailure = 'timeout' | 'malformed_response' | 'backend_error';

/** Raised by stores so the route can classify the failure without parsing text. */
export class RateLimitBackendError extends Error {
  readonly failure: RateLimitBackendFailure;
  constructor(failure: RateLimitBackendFailure, message: string) {
    super(message);
    this.name = 'RateLimitBackendError';
    this.failure = failure;
  }
}

export function classifyRateLimitFailure(err: unknown): RateLimitBackendFailure {
  if (err instanceof RateLimitBackendError) return err.failure;
  const name = (err as { name?: string } | null)?.name;
  if (name === 'TimeoutError' || name === 'AbortError') return 'timeout';
  return 'backend_error';
}

function parseCount(result: unknown): number {
  const count = typeof result === 'string' && /^[0-9]+$/.test(result) ? Number(result) : result;
  if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 1) {
    throw new RateLimitBackendError('malformed_response', 'rate-limit backend returned a malformed count');
  }
  return count;
}

async function withDeadline<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new RateLimitBackendError('timeout', 'rate-limit backend deadline exceeded')),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([operation, deadline]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ─── Config ───────────────────────────────────────────────────────────────────

export const DEFAULT_RATE_LIMIT_TIMEOUT_MS = 1000;

export function getBffRateLimitConfig(): {
  windowSec: number;
  maxRequests: number;
  timeoutMs: number;
  backend: 'redis' | 'upstash-rest' | 'memory';
  redisUrl: string | undefined;
  upstashRestUrl: string | undefined;
  upstashRestToken: string | undefined;
} {
  const windowSec = Math.max(1, parseInt(process.env.BFF_RATE_LIMIT_WINDOW_S || '60', 10) || 60);
  const maxRequests = Math.max(1, parseInt(process.env.BFF_RATE_LIMIT_MAX_REQUESTS || '100', 10) || 100);
  const rawTimeout = parseInt(process.env.BFF_RATE_LIMIT_TIMEOUT_MS || '', 10);
  const timeoutMs = Number.isFinite(rawTimeout)
    ? Math.min(5000, Math.max(50, rawTimeout))
    : DEFAULT_RATE_LIMIT_TIMEOUT_MS;
  const backend = (process.env.BFF_RATE_LIMIT_BACKEND || '').trim().toLowerCase();
  const rawRedisUrl = process.env.BFF_REDIS_URL || process.env.REDIS_URL || undefined;
  const redisUrlIsRest = rawRedisUrl ? /^https?:\/\//i.test(rawRedisUrl.trim()) : false;
  const redisUrl = rawRedisUrl && !redisUrlIsRest ? rawRedisUrl : undefined;
  const upstashRestUrl =
    process.env.BFF_UPSTASH_REDIS_REST_URL ||
    process.env.UPSTASH_REDIS_REST_URL ||
    process.env.KV_REST_API_URL ||
    (redisUrlIsRest ? rawRedisUrl : undefined);
  const upstashRestToken =
    process.env.BFF_UPSTASH_REDIS_REST_TOKEN ||
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    process.env.KV_REST_API_TOKEN ||
    undefined;

  // Explicit backend override, otherwise auto-detect by configured transport.
  let resolvedBackend: 'redis' | 'upstash-rest' | 'memory';
  if (backend === 'memory') {
    resolvedBackend = 'memory';
  } else if (backend === 'upstash-rest' || backend === 'rest' || backend === 'upstash') {
    resolvedBackend = 'upstash-rest';
  } else if (backend === 'redis') {
    resolvedBackend = 'redis';
  } else {
    // Auto: prefer REST when Upstash/Vercel KV REST envs are present; otherwise Redis protocol.
    resolvedBackend = upstashRestUrl || upstashRestToken ? 'upstash-rest' : redisUrl ? 'redis' : 'memory';
  }

  return { windowSec, maxRequests, timeoutMs, backend: resolvedBackend, redisUrl, upstashRestUrl, upstashRestToken };
}

/** Returns true for NODE_ENV=development|test or FG_ENV=dev|development|local|test */
export function isDevOrTestEnv(): boolean {
  const nodeEnv = (process.env.NODE_ENV || 'development').toLowerCase();
  const fgEnv = (process.env.FG_ENV || '').toLowerCase();
  if (nodeEnv === 'development' || nodeEnv === 'test') return true;
  if (['dev', 'development', 'local', 'test'].includes(fgEnv)) return true;
  return false;
}

/**
 * Returns true when BFF_REDIS_URL is missing, blank, or starts with "CHANGE_ME"
 * (i.e. was never configured beyond placeholder value).
 */
export function isBffRedisUrlMissingOrPlaceholder(redisUrl: string | undefined): boolean {
  if (!redisUrl || !redisUrl.trim()) return true;
  if (redisUrl.trim().toUpperCase().startsWith('CHANGE_ME')) return true;
  return false;
}

export function isBffUpstashRestConfigMissingOrPlaceholder(
  restUrl: string | undefined,
  restToken: string | undefined,
): boolean {
  return isBffRedisUrlMissingOrPlaceholder(restUrl) || isBffRedisUrlMissingOrPlaceholder(restToken);
}

// ─── Memory Store (dev/test only) ────────────────────────────────────────────

interface MemoryEntry {
  count: number;
  windowStart: number;
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly store = new Map<string, MemoryEntry>();

  async increment(key: string, windowSec: number, maxRequests: number): Promise<RateLimitResult> {
    const now = Date.now();
    const windowMs = windowSec * 1000;
    const existing = this.store.get(key);

    let entry: MemoryEntry;
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

  /** Exposed for testing only — reset all state */
  _reset(): void {
    this.store.clear();
  }
}

// ─── Redis Store (production) ─────────────────────────────────────────────────

/**
 * Minimal Redis client interface — only the methods we use.
 * This lets tests inject a fake without importing ioredis.
 */
export interface RedisClientInterface {
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown>;
  quit(): Promise<unknown>;
  /** ioredis connection state; 'wait' means lazyConnect has not connected yet. */
  status?: string;
  connect?(): Promise<unknown>;
}

export class RedisRateLimitStore implements RateLimitStore {
  private readonly client: RedisClientInterface;
  private readonly timeoutMs: number;
  private connecting: Promise<unknown> | null = null;

  constructor(client: RedisClientInterface, timeoutMs: number = DEFAULT_RATE_LIMIT_TIMEOUT_MS) {
    this.client = client;
    this.timeoutMs = timeoutMs;
  }

  private ensureConnected(): Promise<unknown> | null {
    // One shared connect attempt: concurrent first requests wait on the same
    // promise (connect() moves status off 'wait' synchronously, so the status
    // alone cannot tell later callers a connect is in flight). After a failed
    // attempt the promise is cleared and ioredis reconnects in the background.
    if (this.connecting) return this.connecting;
    if (this.client.status !== 'wait' || !this.client.connect) return null;
    this.connecting = this.client.connect().catch((err: unknown) => {
      this.connecting = null;
      throw err;
    });
    return this.connecting;
  }

  async increment(key: string, windowSec: number, maxRequests: number): Promise<RateLimitResult> {
    // Fixed window aligned to the first request; INCR+EXPIRE are atomic in
    // RATE_LIMIT_INCREMENT_LUA. The whole operation, including a lazy first
    // connect, shares one deadline.
    const operation = (async () => {
      const connecting = this.ensureConnected();
      if (connecting) await connecting;
      return this.client.eval(RATE_LIMIT_INCREMENT_LUA, 1, key, String(windowSec));
    })();
    const count = parseCount(await withDeadline(operation, this.timeoutMs));
    return {
      count,
      allowed: count <= maxRequests,
      windowSec,
      available: true,
    };
  }
}

// ─── Upstash REST Store (Vercel/Upstash serverless) ─────────────────────────

export class UpstashRestRateLimitStore implements RateLimitStore {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, token: string, timeoutMs: number = DEFAULT_RATE_LIMIT_TIMEOUT_MS) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  /**
   * One command as a JSON array POSTed to the REST root (the same transport
   * lib/tenant-registry.ts uses). The request is aborted at the deadline and
   * never retried. Error messages never include the URL or token.
   */
  private async command(args: string[]): Promise<unknown> {
    const name = args[0];
    const operation = (async () => {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(args),
        cache: 'no-store',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!response.ok) {
        throw new RateLimitBackendError('backend_error', `Upstash REST ${name} failed with HTTP ${response.status}`);
      }
      let payload: { result?: unknown; error?: string } | null;
      try {
        payload = (await response.json()) as { result?: unknown; error?: string } | null;
      } catch {
        throw new RateLimitBackendError('malformed_response', `Upstash REST ${name} returned a non-JSON body`);
      }
      if (!payload || typeof payload !== 'object') {
        throw new RateLimitBackendError('malformed_response', `Upstash REST ${name} returned a malformed body`);
      }
      if (payload.error) {
        throw new RateLimitBackendError('backend_error', `Upstash REST ${name} failed`);
      }
      return payload.result;
    })();
    return withDeadline(operation, this.timeoutMs);
  }

  async ping(): Promise<void> {
    await this.command(['PING']);
  }

  async increment(key: string, windowSec: number, maxRequests: number): Promise<RateLimitResult> {
    const count = parseCount(await this.command(['EVAL', RATE_LIMIT_INCREMENT_LUA, '1', key, String(windowSec)]));
    return {
      count,
      allowed: count <= maxRequests,
      windowSec,
      available: true,
    };
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Build a RateLimitStore for the current environment.
 *
 * Returns { store, unavailable: false } on success.
 * Returns { store: null, unavailable: true, errorCode, required: true } when Redis is
 * required but unavailable in a prod-like environment — callers MUST return 503.
 *
 * Prod-like (NODE_ENV=production or FG_ENV=prod/staging/production):
 *   - Missing/blank/CHANGE_ME BFF_REDIS_URL → errorCode: BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED
 *   - Valid URL but Redis unreachable → errorCode: BFF_RATE_LIMIT_REDIS_UNAVAILABLE
 *   - Memory fallback is NEVER allowed.
 *
 * Dev/test: always succeeds (falls back to memory when Redis unavailable).
 */
export async function buildRateLimitStore(): Promise<
  | { store: RateLimitStore; unavailable: false }
  | { store: null; unavailable: true; errorCode: BffRateLimitErrorCode; required: true }
> {
  const { backend, redisUrl, upstashRestUrl, upstashRestToken, timeoutMs } = getBffRateLimitConfig();
  const devOrTest = isDevOrTestEnv();

  if (backend === 'memory') {
    if (!devOrTest) {
      // Explicit memory backend in prod-like env is treated as missing config.
      return {
        store: null,
        unavailable: true,
        errorCode: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED',
        required: true,
      };
    }
    return { store: new MemoryRateLimitStore(), unavailable: false };
  }

  if (backend === 'upstash-rest') {
    if (isBffUpstashRestConfigMissingOrPlaceholder(upstashRestUrl, upstashRestToken)) {
      if (devOrTest) {
        return { store: new MemoryRateLimitStore(), unavailable: false };
      }
      return {
        store: null,
        unavailable: true,
        errorCode: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED',
        required: true,
      };
    }

    // No connectivity check at cold start — a transient Upstash failure during
    // initialization would permanently brick this singleton for the worker's lifetime.
    // Per-request failures reject from increment() and the route fails closed.
    return { store: new UpstashRestRateLimitStore(upstashRestUrl!, upstashRestToken!, timeoutMs), unavailable: false };
  }

  // Redis backend
  if (isBffRedisUrlMissingOrPlaceholder(redisUrl)) {
    if (devOrTest) {
      // No valid URL in dev/test → fall back to memory
      return { store: new MemoryRateLimitStore(), unavailable: false };
    }
    // Prod-like with missing/placeholder URL → config required error
    return {
      store: null,
      unavailable: true,
      errorCode: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED',
      required: true,
    };
  }

  // ioredis is a server-only dependency — top-level ESM import is safe here
  // because this file is never imported into browser/client components.
  // lazyConnect: true defers the TCP handshake to the first command; no eager
  // connect so a transient DNS/network issue at cold start doesn't brick the singleton.
  // One client per worker. maxRetriesPerRequest: 0 and no offline queue mean a
  // command is sent at most once and fails fast while disconnected; ioredis
  // reconnects in the background with capped backoff, so enforcement recovers
  // without a restart once Redis is reachable again.
  return {
    store: new RedisRateLimitStore(new Redis(redisUrl!, {
      lazyConnect: true,
      connectTimeout: 2000,
      commandTimeout: timeoutMs,
      maxRetriesPerRequest: 0,
      enableOfflineQueue: false,
      retryStrategy: (times: number) => Math.min(times * 200, 2000),
    }) as unknown as RedisClientInterface, timeoutMs),
    unavailable: false,
  };
}

/**
 * Module-level singleton — one store per serverless worker lifetime.
 * Re-created on each cold start. Not shared across processes.
 */
let _storePromise: ReturnType<typeof buildRateLimitStore> | null = null;

export function getRateLimitStore(): ReturnType<typeof buildRateLimitStore> {
  if (!_storePromise) {
    // A construction error must not cache a rejected promise for the worker's
    // lifetime: report unavailable (the route fails closed) and retry next call.
    _storePromise = buildRateLimitStore().catch(() => {
      _storePromise = null;
      return {
        store: null,
        unavailable: true as const,
        errorCode: 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE' as const,
        required: true as const,
      };
    });
  }
  return _storePromise;
}

/** Test helper: reset singleton so next call re-initializes */
export function _resetRateLimitStoreSingleton(): void {
  _storePromise = null;
}

/**
 * Probe Redis reachability/config for health checks WITHOUT initializing or
 * touching the shared store singleton. Non-poisoning, retryable.
 */
export async function getRateLimitHealth(): Promise<{
  backend: string;
  ready: boolean;
  required: boolean;
  reason: string | null;
}> {
  const config = getBffRateLimitConfig();
  const isProd = !isDevOrTestEnv();

  if (isProd) {
    if (config.backend === 'upstash-rest') {
      if (isBffUpstashRestConfigMissingOrPlaceholder(config.upstashRestUrl, config.upstashRestToken)) {
        return { backend: 'upstash-rest', ready: false, required: true, reason: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED' };
      }
      try {
        const probe = new UpstashRestRateLimitStore(config.upstashRestUrl!, config.upstashRestToken!, config.timeoutMs);
        await probe.ping();
        return { backend: 'upstash-rest', ready: true, required: true, reason: null };
      } catch {
        return { backend: 'upstash-rest', ready: false, required: true, reason: 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE' };
      }
    }

    if (isBffRedisUrlMissingOrPlaceholder(config.redisUrl)) {
      return { backend: 'redis', ready: false, required: true, reason: 'BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED' };
    }
    // Probe Redis directly — side-effect-free, does not touch the module singleton
    try {
      const RedisModule = await import('ioredis');
      const RedisClient = RedisModule.default;
      const probe = new RedisClient(config.redisUrl!, {
        lazyConnect: true,
        connectTimeout: 1500,
        commandTimeout: 1000,
        maxRetriesPerRequest: 0,
        enableOfflineQueue: false,
      });
      await probe.ping();
      await probe.quit().catch(() => {}); // clean up probe connection
      return { backend: 'redis', ready: true, required: true, reason: null };
    } catch {
      return { backend: 'redis', ready: false, required: true, reason: 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE' };
    }
  } else {
    // dev/test: memory fallback, always ready, not required
    return { backend: config.backend ?? 'memory', ready: true, required: false, reason: null };
  }
}
