/**
 * Portal tenant registry — reads from Vercel Edge Config.
 *
 * Mirrors the shape written by the console's provision-tenant flow.
 * Read-only; write path lives in the console.
 *
 * Required env var (read path only):
 *   EDGE_CONFIG — connection string (auto-set when you connect the store in Vercel dashboard)
 */

interface TenantRecord {
  label: string;
  api_key: string;
  created_at: string;
}

let _cache: { data: Record<string, TenantRecord>; at: number } | null = null;
const CACHE_TTL_MS = 30_000;

export async function getPortalTenantApiKey(tenantId: string): Promise<string | null> {
  if (!process.env.EDGE_CONFIG) return null;

  if (_cache && Date.now() - _cache.at < CACHE_TTL_MS) {
    return _cache.data[tenantId]?.api_key ?? null;
  }

  try {
    const { get } = await import('@vercel/edge-config');
    const tenants = (await get<Record<string, TenantRecord>>('tenants')) ?? {};
    _cache = { data: tenants, at: Date.now() };
    return tenants[tenantId]?.api_key ?? null;
  } catch {
    return null;
  }
}
