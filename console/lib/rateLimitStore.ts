/**
 * BFF Redis Rate-Limit Storage Adapter
 *
 * Architecture:
 *   - RedisRateLimitStore: production — uses ioredis INCR+EXPIRE atomic pattern
 *   - MemoryRateLimitStore: dev/test only — in-process sliding window
 *   - getRateLimitStore(): factory — server-side only, never called in browser
 *
 * Secret safety:
 *   - BFF_REDIS_URL and all config read via process.env (server-only)
 *   - Never NEXT_PUBLIC_* for any rate-limit config
 *
 * Redis unavailable behavior:
 *   - dev/test: falls back to MemoryRateLimitStore (deterministic)
 *   - prod-like: returns { unavailable: true, errorCode } — caller must return 503
 *
 * Prod-like enforcement (NODE_ENV=production or FG_ENV=prod/staging/production):
 *   - Missing/blank/CHANGE_ME BFF_REDIS_URL → errorCode: BFF_RATE_LIMIT_REDIS_CONFIG_REQUIRED
 *   - Valid URL but Redis unreachable → errorCode: BFF_RATE_LIMIT_REDIS_UNAVAILABLE
 *   - Memory fallback is NEVER allowed in prod-like environments
 *
 * Key format: fg:bff:rl:{route_group}:{tenant_id}:{user_id_or_session}
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

// ─── Config ───────────────────────────────────────────────────────────────────

export function getBffRateLimitConfig(): {
  windowSec: number;
  maxRequests: number;
  backend: 'redis' | 'memory';
  redisUrl: string | undefined;
} {
  const windowSec = Math.max(1, parseInt(process.env.BFF_RATE_LIMIT_WINDOW_S || '60', 10) || 60);
  const maxRequests = Math.max(1, parseInt(process.env.BFF_RATE_LIMIT_MAX_REQUESTS || '100', 10) || 100);
  const backend = (process.env.BFF_RATE_LIMIT_BACKEND || '').trim().toLowerCase();
  const redisUrl = process.env.BFF_REDIS_URL || undefined;

  // Explicit backend override, otherwise auto-detect by presence of BFF_REDIS_URL
  let resolvedBackend: 'redis' | 'memory';
  if (backend === 'memory') {
    resolvedBackend = 'memory';
  } else if (backend === 'redis') {
    resolvedBackend = 'redis';
  } else {
    // Auto: use redis if URL is set
    resolvedBackend = redisUrl ? 'redis' : 'memory';
  }

  return { windowSec, maxRequests, backend: resolvedBackend, redisUrl };
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
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<0 | 1>;
  quit(): Promise<void>;
}

export class RedisRateLimitStore implements RateLimitStore {
  private readonly client: RedisClientInterface;

  constructor(client: RedisClientInterface) {
    this.client = client;
  }

  async increment(key: string, windowSec: number, maxRequests: number): Promise<RateLimitResult> {
    // INCR + EXPIRE: atomic per-key counter with TTL
    // INCR is idempotent and serialized server-side — safe under concurrency.
    const count = await this.client.incr(key);
    // Only set EXPIRE on the first increment (count === 1) to avoid resetting TTL.
    // This implements a fixed window aligned to first request in the window.
    if (count === 1) {
      await this.client.expire(key, windowSec);
    }
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
  const { backend, redisUrl } = getBffRateLimitConfig();
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

  try {
    // ioredis is a server-only dependency — top-level ESM import is safe here
    // because this file is never imported into browser/client components.
    const client = new Redis(redisUrl!, {
      lazyConnect: true,
      connectTimeout: 2000,
      commandTimeout: 1000,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
    });

    // Eagerly test connectivity
    await (client as unknown as { connect(): Promise<void> }).connect();

    return { store: new RedisRateLimitStore(client as unknown as RedisClientInterface), unavailable: false };
  } catch {
    if (devOrTest) {
      // Dev/test: Redis unavailable → fall back to memory (deterministic)
      return { store: new MemoryRateLimitStore(), unavailable: false };
    }
    // Prod-like: Redis unreachable → unavailable
    return {
      store: null,
      unavailable: true,
      errorCode: 'BFF_RATE_LIMIT_REDIS_UNAVAILABLE',
      required: true,
    };
  }
}

/**
 * Module-level singleton — one store per serverless worker lifetime.
 * Re-created on each cold start. Not shared across processes.
 */
let _storePromise: ReturnType<typeof buildRateLimitStore> | null = null;

export function getRateLimitStore(): ReturnType<typeof buildRateLimitStore> {
  if (!_storePromise) {
    _storePromise = buildRateLimitStore();
  }
  return _storePromise;
}

/** Test helper: reset singleton so next call re-initializes */
export function _resetRateLimitStoreSingleton(): void {
  _storePromise = null;
}
