import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { canAccessConsoleRoute } from '@/lib/consoleAccess';
import { upsertTenantInRegistry, isRegistryConfigured, upsertTenantInUpstash } from '@/lib/tenant-registry';
import { internalGatewaySecret } from '@/lib/internal-gateway-secret';
import Redis from 'ioredis';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

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
  const token = internalGatewaySecret();
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

async function revokeKey(credentialId: string, tenantId: string): Promise<void> {
  try {
    await fetch(
      `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials/${encodeURIComponent(credentialId)}/revoke`,
      {
        method: 'POST',
        headers: adminHeaders(),
        body: JSON.stringify({ reason: 'provision-tenant: persistence failure rollback' }),
        cache: 'no-store',
      },
    );
  } catch (e) {
    console.error('[provision-tenant] revokeKey failed (best-effort):', e instanceof Error ? e.message : e);
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

  if (!internalGatewaySecret()) {
    return NextResponse.json(
      { error: 'Tenant provisioning is not configured. Set FG_INTERNAL_GATEWAY_SECRET in Vercel.' },
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

  // Step 2: Create BFF credential scoped to the tenant (R4.8: /admin/keys retired).
  // On slot conflict (409) the tenant was partially provisioned before — rotate instead.
  const keyRes = await fetch(
    `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials`,
    {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({
        credential_slot: 'console-bff-key',
        scopes: PROVISION_SCOPES,
        expires_in_seconds: ONE_YEAR_SECONDS,
      }),
      cache: 'no-store',
    },
  );

  let keyData: Record<string, unknown>;
  let wasRotated = false;

  if (keyRes.status === 409) {
    // Slot already occupied — the tenant was partially provisioned before. Rotate.
    // A slot conflict implies the tenant definitively existed before this request.
    wasRotated = true;
    const listRes = await fetch(
      `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials?status=active&limit=50`,
      { method: 'GET', headers: adminHeaders(), cache: 'no-store' },
    );
    if (!listRes.ok) {
      const err = await listRes.json().catch(() => ({}));
      return NextResponse.json(
        { error: `Key generation failed (slot conflict, list failed): ${err?.detail ?? listRes.status}` },
        { status: 500 },
      );
    }
    const list = await listRes.json() as { items?: Array<{ credential_id: string; credential_slot: string }> };
    const existing = (list.items ?? []).find(c => c.credential_slot === 'console-bff-key');
    if (!existing) {
      return NextResponse.json(
        { error: 'Key generation failed: slot conflict but no active console-bff-key credential found.' },
        { status: 500 },
      );
    }
    const rotateRes = await fetch(
      `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials/${encodeURIComponent(existing.credential_id)}/rotate`,
      {
        method: 'POST',
        headers: adminHeaders(),
        body: JSON.stringify({ expires_in_seconds: ONE_YEAR_SECONDS }),
        cache: 'no-store',
      },
    );
    if (!rotateRes.ok) {
      const err = await rotateRes.json().catch(() => ({}));
      return NextResponse.json(
        { error: `Key generation failed (rotate): ${err?.detail ?? rotateRes.status}` },
        { status: 500 },
      );
    }
    keyData = await rotateRes.json();
  } else if (!keyRes.ok) {
    const err = await keyRes.json().catch(() => ({}));
    return NextResponse.json(
      { error: `Key generation failed: ${err?.detail ?? keyRes.status}` },
      { status: 500 },
    );
  } else {
    keyData = await keyRes.json();
  }

  // A slot conflict means the tenant existed regardless of what Step 1 returned.
  const alreadyExisted = tenantAlreadyExisted || wasRotated;

  const rawKey: string = keyData.plaintext_secret as string;

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

  // Fail closed: both persistence paths failed.
  if (!registryLive) {
    const isProduction = (process.env.FG_ENV ?? '').trim().toLowerCase() === 'production';
    const devOverride =
      !isProduction &&
      (process.env.FG_ALLOW_UNPERSISTED_TENANT_KEYS ?? '').trim().toLowerCase() === 'true';

    if (isProduction && (process.env.FG_ALLOW_UNPERSISTED_TENANT_KEYS ?? '') !== '') {
      // Hard block: override flag must never be honoured in production.
      console.error(
        '[provision-tenant] FG_ALLOW_UNPERSISTED_TENANT_KEYS is set but FG_ENV=production — ignoring override',
        { tenantId },
      );
    }

    if (!devOverride) {
      if (wasRotated) {
        // The predecessor credential is already superseded — revoking the new one
        // would leave the tenant with zero usable credentials. Do not revoke.
        // The new credential exists live in Postgres but has no portal route to it.
        // Operator must configure persistence and manually reprovision.
        console.error(
          '[provision-tenant] persistence failed after rotate — NOT revoking (predecessor already superseded)',
          { tenantId, credentialId: keyData.credential_id, registryError },
        );
        return NextResponse.json(
          {
            error: 'PERSISTENCE_UNAVAILABLE',
            detail:
              `Credential rotated (${keyData.credential_id as string}) but could not be persisted. ` +
              'The new credential is live in Postgres but unreachable by the portal. ' +
              'Configure REDIS_URL or UPSTASH_REDIS_REST_URL, then reprovision to rotate again.',
          },
          { status: 503 },
        );
      }

      // Fresh create: revoke the dangling credential so Postgres does not accumulate
      // unreachable credentials. R7 will make Postgres the rebuild source.
      console.error('[provision-tenant] credential persistence failed — revoking and aborting', {
        tenantId,
        registryError,
      });
      await revokeKey(keyData.credential_id as string, tenantId);
      return NextResponse.json(
        {
          error: 'PERSISTENCE_UNAVAILABLE',
          detail: registryError ?? 'Both Redis and Upstash writes failed. Tenant key not persisted.',
        },
        { status: 503 },
      );
    }

    // Dev/staging explicit override: return the one-time secret so the operator can
    // wire it manually. Only reachable when FG_ALLOW_UNPERSISTED_TENANT_KEYS=true
    // AND FG_ENV != production.
    console.warn('[provision-tenant] persistence skipped via dev override — returning plaintext secret', {
      tenantId,
    });
    return NextResponse.json({
      tenant_id: tenantId,
      name,
      already_existed: alreadyExisted,
      registry_live: false,
      credential_id: keyData.credential_id,
      api_key_expires_at: keyData.expires_at,
      api_key: keyData.plaintext_secret,
      warning: 'Credential was NOT persisted. Set REDIS_URL or UPSTASH_REDIS_REST_URL before provisioning production tenants.',
    });
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
    already_existed: alreadyExisted,
    registry_live: true,
    credential_id: keyData.credential_id,
    api_key_expires_at: keyData.expires_at,
  });
}
