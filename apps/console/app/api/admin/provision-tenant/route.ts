import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.FG_CORE_API_KEY ?? process.env.CORE_API_KEY ?? '';
const CORE_TENANT_ID = process.env.CORE_TENANT_ID ?? '';

// Token resolution matches require_internal_admin_gateway in api/admin.py
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
];

const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;

function adminHeaders(): HeadersInit {
  return {
    'Content-Type': 'application/json',
    'X-API-Key': CORE_API_KEY,
    'X-Tenant-ID': CORE_TENANT_ID,
    'X-FG-Internal-Token': internalToken(),
  };
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  // Must be logged in to the console
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  if (!internalToken()) {
    return NextResponse.json(
      { error: 'Tenant provisioning is not configured on this deployment. Set FG_ADMIN_GATEWAY_TOKEN in Vercel.' },
      { status: 503 },
    );
  }
  if (!CORE_API_KEY || !CORE_TENANT_ID) {
    return NextResponse.json({ error: 'Core API not configured.' }, { status: 503 });
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

  // Step 1: Create tenant record
  const tenantRes = await fetch(`${CORE_API_URL}/admin/tenants`, {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({ tenant_id: tenantId, name }),
    cache: 'no-store',
  });

  if (!tenantRes.ok) {
    const err = await tenantRes.json().catch(() => ({}));
    const msg = err?.detail ?? `HTTP ${tenantRes.status}`;
    if (tenantRes.status === 409) {
      return NextResponse.json({ error: `Tenant "${tenantId}" already exists.` }, { status: 409 });
    }
    return NextResponse.json({ error: `Failed to create tenant: ${msg}` }, { status: tenantRes.status });
  }

  // Step 2: Create BFF API key scoped to the new tenant
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
      { error: `Tenant created but key generation failed: ${err?.detail ?? keyRes.status}. Run the seed script manually.` },
      { status: 500 },
    );
  }

  const keyData = await keyRes.json();

  return NextResponse.json({
    tenant_id: tenantId,
    name,
    api_key: keyData.key,
    api_key_prefix: keyData.prefix,
    api_key_expires_at: keyData.expires_at,
    next_steps: {
      vercel_env_FG_CONSOLE_DEMO_TENANTS: `Add "${tenantId}" to FG_CONSOLE_DEMO_TENANTS in Vercel (comma-separated)`,
      vercel_env_FG_CONSOLE_DEMO_TENANT_KEYS: `Add "${tenantId}":"<api_key>" to FG_CONSOLE_DEMO_TENANT_KEYS JSON in Vercel`,
      vercel_env_FG_PORTAL_DEMO_TENANTS: `Add "${tenantId}" to FG_PORTAL_DEMO_TENANTS in portal Vercel project`,
      vercel_env_FG_PORTAL_DEMO_TENANT_KEYS: `Add "${tenantId}":"<api_key>" to FG_PORTAL_DEMO_TENANT_KEYS in portal Vercel project`,
    },
  });
}
