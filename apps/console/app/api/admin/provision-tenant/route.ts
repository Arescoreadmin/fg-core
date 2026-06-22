import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { upsertTenantInRegistry, isRegistryConfigured } from '@/lib/tenant-registry';

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

function adminHeaders(): HeadersInit {
  const token = internalToken();
  return {
    'Content-Type': 'application/json',
    'X-API-Key': token,
    'X-FG-Internal-Token': token,
    'X-Admin-Gateway-Internal': 'true',
  };
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
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

  // Step 3: Write to Edge Config registry so client is live immediately
  let registryLive = false;
  let registryError: string | null = null;

  if (isRegistryConfigured()) {
    try {
      await upsertTenantInRegistry(tenantId, {
        label: name,
        api_key: rawKey,
        created_at: new Date().toISOString(),
      });
      registryLive = true;
    } catch (e) {
      registryError = e instanceof Error ? e.message : 'Unknown error writing to registry';
    }
  }

  return NextResponse.json({
    tenant_id: tenantId,
    name,
    already_existed: tenantAlreadyExisted,
    registry_live: registryLive,
    registry_error: registryError,
    // Only expose the raw key if registry write failed — otherwise it's already stored
    api_key: registryLive ? null : rawKey,
    api_key_prefix: keyData.prefix,
    api_key_expires_at: keyData.expires_at,
  });
}
