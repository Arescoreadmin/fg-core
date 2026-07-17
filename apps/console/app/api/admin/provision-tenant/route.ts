import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { canAccessConsoleRoute } from '@/lib/consoleAccess';
import { upsertTenantInRegistry, isRegistryConfigured, upsertTenantInUpstash } from '@/lib/tenant-registry';
import Redis from 'ioredis';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

function internalToken(): string {
  return (
    process.env.FG_ADMIN_GATEWAY_TOKEN ||
    process.env.FG_INTERNAL_AUTH_SECRET ||
    process.env.FG_INTERNAL_TOKEN ||
    ''
  ).trim();
}

const PROVISION_SCOPES = [
  'governance:read',
  'governance:write',
  'governance:qa_approve',
  'ui:read',
  'control-plane:read',
  'audit:read',
  'audit:export',
  'decisions:read',
  'feed:read',
  'ingest:write',
  'keys:read',
  'keys:write',
  'admin:read',
  'admin:write',
];

const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;
const PORTAL_KEY_PREFIX = 'portal:tenant';

function adminHeaders(): HeadersInit {
  const token = internalToken();
  return {
    'Content-Type': 'application/json',
    'X-API-Key': token,
    'X-FG-Internal-Token': token,
    'X-Admin-Gateway-Internal': 'true',
  };
}

async function writeKeyToUpstash(tenantId: string, apiKey: string): Promise<boolean> {
  const url = (
    process.env.BFF_UPSTASH_REDIS_REST_URL ||
    process.env.UPSTASH_REDIS_REST_URL ||
    ''
  ).trim();
  const token = (
    process.env.BFF_UPSTASH_REDIS_REST_TOKEN ||
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    ''
  ).trim();
  if (!url || !token) {
    console.warn('[provision-tenant] writeKeyToUpstash: url or token missing', { hasUrl: !!url, hasToken: !!token });
    return false;
  }
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['SET', `${PORTAL_KEY_PREFIX}:${tenantId}:key`, apiKey, 'EX', ONE_YEAR_SECONDS]),
    });
    if (!res.ok) {
      console.warn('[provision-tenant] writeKeyToUpstash: non-ok response', { status: res.status });
      return false;
    }
    const data = await res.json() as { result: string };
    console.info('[provision-tenant] writeKeyToUpstash result:', data.result);
    return data.result === 'OK';
  } catch (e) {
    console.error('[provision-tenant] writeKeyToUpstash threw:', e instanceof Error ? e.message : e);
    return false;
  }
}

async function writeKeyToRedis(tenantId: string, apiKey: string): Promise<boolean> {
  const url = (process.env.BFF_REDIS_URL || process.env.REDIS_URL || '').trim();
  if (!url) return false;
  let client: Redis | null = null;
  try {
    client = new Redis(url, {
      maxRetriesPerRequest: 1,
      connectTimeout: 2000,
      enableOfflineQueue: false,
      lazyConnect: true,
    });
    await client.connect();
    await client.set(`${PORTAL_KEY_PREFIX}:${tenantId}:key`, apiKey, 'EX', ONE_YEAR_SECONDS);
    return true;
  } catch {
    return false;
  } finally {
    try { client?.disconnect(); } catch { /* ignore */ }
  }
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  if (!canAccessConsoleRoute('/admin/tenants', session)) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  if (!internalToken()) {
    return NextResponse.json(
      { error: 'Tenant provisioning is not configured. Set FG_ADMIN_GATEWAY_TOKEN in Vercel.' },
      { status: 503 },
    );
  }
  let body: { tenant_id?: string; name?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400 });
  }

  const tenantId = (body.tenant_id ?? '').trim().toLowerCase().replace(/\s+/g, '-');
  const name = (body.name ?? tenantId).trim();

  if (!/^[a-zA-Z0-9_-]{2,128}$/.test(tenantId)) {
    return NextResponse.json(
      { error: 'tenant_id must be 2–128 characters: letters, numbers, hyphens, underscores only.' },
      { status: 422 },
    );
  }

  // Step 1: Create tenant record (skip 409 — tenant already exists, just regenerate key)
  const tenantRes = await fetch(`${CORE_API_URL}/admin/tenants`, {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({ tenant_id: tenantId, name }),
    cache: 'no-store',
  });

  const tenantAlreadyExisted = tenantRes.status === 409;

  if (!tenantRes.ok && !tenantAlreadyExisted) {
    const err = await tenantRes.json().catch(() => ({}));
    return NextResponse.json(
      { error: `Failed to create tenant: ${err?.detail ?? `HTTP ${tenantRes.status}`}` },
      { status: tenantRes.status },
    );
  }

  // Step 2: Create BFF API key scoped to the tenant
  const keyRes = await fetch(`${CORE_API_URL}/admin/keys`, {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({
      name: 'console-bff-key',
      scopes: PROVISION_SCOPES,
      tenant_id: tenantId,
      ttl_seconds: ONE_YEAR_SECONDS,
    }),
    cache: 'no-store',
  });

  if (!keyRes.ok) {
    const err = await keyRes.json().catch(() => ({}));
    return NextResponse.json(
      { error: `Key generation failed: ${err?.detail ?? keyRes.status}` },
      { status: 500 },
    );
  }

  const keyData = await keyRes.json();
  const rawKey: string = keyData.key;

  // Step 3a: Write display metadata to Edge Config (does NOT store the auth key).
  // Fire-and-forget — Edge Config is for the client list UI, not portal authentication.
  if (isRegistryConfigured()) {
    upsertTenantInRegistry(tenantId, {
      label: name,
      created_at: new Date().toISOString(),
    }).catch(() => {});
  }

  // Step 3b: Write the portal auth key (portal:tenant:{id}:key) so the portal can
  // authenticate on behalf of this tenant. Always runs — independent of Edge Config.
  // Priority: ioredis (REDIS_URL) → Upstash REST (UPSTASH_REDIS_REST_URL)
  let registryLive = false;
  let registryError: string | null = null;

  try {
    registryLive = await writeKeyToRedis(tenantId, rawKey);
    if (registryLive) registryError = null;
  } catch (e) {
    registryError = e instanceof Error ? e.message : 'Redis write failed';
  }

  if (!registryLive) {
    try {
      registryLive = await writeKeyToUpstash(tenantId, rawKey);
      if (registryLive) registryError = null;
    } catch (e) {
      if (!registryError) registryError = e instanceof Error ? e.message : 'Upstash write failed';
    }
  }

  // Always write full tenant record to Upstash console registry so the client
  // list persists across sessions even without Edge Config.
  await upsertTenantInUpstash(tenantId, {
    label: name,
    created_at: new Date().toISOString(),
  }).catch(() => {});

  return NextResponse.json({
    tenant_id: tenantId,
    name,
    already_existed: tenantAlreadyExisted,
    registry_live: registryLive,
    registry_error: registryError,
    // Only expose the raw key if both registry paths failed — otherwise it's already stored
    api_key: registryLive ? null : rawKey,
    api_key_prefix: keyData.prefix,
    api_key_expires_at: keyData.expires_at,
  });
}
