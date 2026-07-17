/**
 * Portal tenant registry — reads from Vercel Edge Config (primary) or Redis (fallback).
 *
 * Mirrors the shape written by the console's provision-tenant flow.
 * Read-only; write path lives in the console.
 *
 * Required env var (read path only):
 *   EDGE_CONFIG — connection string (auto-set when you connect the store in Vercel dashboard)
 *   PORTAL_REDIS_URL — Redis URL (used if Edge Config is not configured; share with console's REDIS_URL)
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

  // 2. Redis fallback (zero-touch when Edge Config not configured)
  const redis = getRedisClient();
  if (redis) {
    try {
      const key = await redis.get(`${PORTAL_KEY_PREFIX}:${tenantId}:key`);
      if (key) return key;
    } catch {
      // Redis unavailable — fall through
    }
  }

  return null;
}
