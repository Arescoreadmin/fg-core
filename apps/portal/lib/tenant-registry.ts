/**
 * Portal tenant registry — reads from Edge Config, ioredis, or Upstash REST (in priority order).
 *
 * Mirrors the shape written by the console's provision-tenant flow.
 * Read-only; write path lives in the console.
 *
 * Resolution order:
 *   1. EDGE_CONFIG — Vercel Edge Config (auto-set when store is connected)
 *   2. PORTAL_REDIS_URL / REDIS_URL — ioredis (Redis protocol, e.g. rediss://)
 *   3. UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN — Upstash REST API
 */

import { getRedisClient } from './redis';

const PORTAL_KEY_PREFIX = 'portal:tenant';

interface TenantRecord {
  label: string;
  api_key: string;
  created_at: string;
}

let _cache: { data: Record<string, TenantRecord>; at: number } | null = null;
const CACHE_TTL_MS = 30_000;

export async function getPortalTenantApiKey(tenantId: string): Promise<string | null> {
  // 1. Edge Config (low-latency, Vercel-native)
  if (process.env.EDGE_CONFIG) {
    if (_cache && Date.now() - _cache.at < CACHE_TTL_MS) {
      const hit = _cache.data[tenantId]?.api_key ?? null;
      if (hit) return hit;
    }
    try {
      const { get } = await import('@vercel/edge-config');
      const tenants = (await get<Record<string, TenantRecord>>('tenants')) ?? {};
      _cache = { data: tenants, at: Date.now() };
      if (tenants[tenantId]?.api_key) return tenants[tenantId].api_key;
    } catch {
      // Edge Config unavailable — fall through to Redis
    }
  }

  // 2. Redis fallback (ioredis, requires PORTAL_REDIS_URL or REDIS_URL in redis:// format)
  const redis = getRedisClient();
  if (redis) {
    try {
      const key = await redis.get(`${PORTAL_KEY_PREFIX}:${tenantId}:key`);
      if (key) return key;
    } catch {
      // Redis unavailable — fall through
    }
  }

  // 3. Upstash REST fallback (UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN)
  const upstashUrl = (process.env.UPSTASH_REDIS_REST_URL || '').trim();
  const upstashToken = (process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
  if (upstashUrl && upstashToken) {
    try {
      const res = await fetch(upstashUrl, {
        method: 'POST',
        headers: { Authorization: `Bearer ${upstashToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(['GET', `${PORTAL_KEY_PREFIX}:${tenantId}:key`]),
        cache: 'no-store',
      });
      if (res.ok) {
        const { result } = await res.json() as { result: string | null };
        if (typeof result === 'string') return result;
      }
    } catch {
      // Upstash unavailable — fall through
    }
  }

  return null;
}
