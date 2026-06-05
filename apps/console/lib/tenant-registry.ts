/**
 * Tenant registry backed by Vercel Edge Config.
 *
 * Read:  @vercel/edge-config (near-zero latency, no redeployment needed)
 * Write: Vercel REST API PATCH /v1/edge-config/{id}/items
 *
 * Fallback: FG_CONSOLE_DEMO_TENANT_KEYS / FG_CONSOLE_DEMO_TENANTS env vars
 * are still read so existing tenants keep working without migration.
 *
 * Required env vars (for write path):
 *   EDGE_CONFIG            — connection string (auto-set when you connect the store in Vercel dashboard)
 *   VERCEL_API_TOKEN       — a Vercel API token with edge-config write access
 */

export interface TenantRecord {
  label: string;
  api_key: string;
  created_at: string;
}

export type TenantMap = Record<string, TenantRecord>;

// ─── Read ─────────────────────────────────────────────────────────────────────

let _cache: { data: TenantMap; at: number } | null = null;
const CACHE_TTL_MS = 30_000;

export async function getTenantRegistry(): Promise<TenantMap> {
  // In-process cache so the BFF doesn't hit Edge Config on every single request
  if (_cache && Date.now() - _cache.at < CACHE_TTL_MS) return _cache.data;

  let ecData: TenantMap = {};

  if (process.env.EDGE_CONFIG) {
    try {
      const { get } = await import('@vercel/edge-config');
      ecData = (await get<TenantMap>('tenants')) ?? {};
    } catch {
      // Edge Config unavailable — fall through to env var fallback
    }
  }

  // Merge in legacy env var keys so existing tenants keep working
  const legacy = parseLegacyEnvKeys();
  const merged: TenantMap = { ...legacy, ...ecData };

  _cache = { data: merged, at: Date.now() };
  return merged;
}

export async function getTenantApiKey(tenantId: string): Promise<string | null> {
  const registry = await getTenantRegistry();
  return registry[tenantId]?.api_key ?? null;
}

function parseLegacyEnvKeys(): TenantMap {
  const raw = process.env.FG_CONSOLE_DEMO_TENANT_KEYS || process.env.FG_DEMO_TENANT_API_KEYS || '';
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const result: TenantMap = {};
    for (const [id, key] of Object.entries(parsed)) {
      if (typeof key === 'string' && key.trim()) {
        result[id.trim()] = {
          label: id.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
          api_key: key.trim(),
          created_at: '',
        };
      }
    }
    return result;
  } catch {
    return {};
  }
}

// ─── Write ────────────────────────────────────────────────────────────────────

function getStoreId(): string {
  if (process.env.EDGE_CONFIG_STORE_ID) return process.env.EDGE_CONFIG_STORE_ID;
  // Extract from connection string: https://edge-config.vercel.com/ecfg_xxx?token=yyy
  const match = process.env.EDGE_CONFIG?.match(/edge-config\.vercel\.com\/(ecfg_[^?/]+)/);
  if (match) return match[1];
  throw new Error('Cannot determine Edge Config store ID. Set EDGE_CONFIG_STORE_ID or EDGE_CONFIG.');
}

export async function upsertTenantInRegistry(
  tenantId: string,
  record: TenantRecord,
): Promise<void> {
  const token = process.env.VERCEL_API_TOKEN;
  if (!token || !process.env.EDGE_CONFIG) {
    throw new Error('EDGE_CONFIG and VERCEL_API_TOKEN must be set to write to the tenant registry.');
  }

  const storeId = getStoreId();

  // Read current state, then merge
  let current: TenantMap = {};
  try {
    const { get } = await import('@vercel/edge-config');
    current = (await get<TenantMap>('tenants')) ?? {};
  } catch {
    // Start fresh if unreadable
  }

  const updated: TenantMap = { ...current, [tenantId]: record };

  const res = await fetch(`https://api.vercel.com/v1/edge-config/${storeId}/items`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      items: [{ operation: 'upsert', key: 'tenants', value: updated }],
    }),
    cache: 'no-store',
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Edge Config write failed: ${err?.error?.message ?? `HTTP ${res.status}`}`);
  }

  // Invalidate in-process cache immediately
  _cache = null;
}

export function isRegistryConfigured(): boolean {
  return !!(process.env.EDGE_CONFIG && process.env.VERCEL_API_TOKEN);
}
