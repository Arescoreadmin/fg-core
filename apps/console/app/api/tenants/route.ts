import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { canAccessConsoleRoute, getSessionClaims, isPlatformAdminSession, isTenantAdminSession } from '@/lib/consoleAccess';
import { getTenantRegistry } from '@/lib/tenant-registry';

export interface TenantEntry {
  tenant_id: string;
  label: string;
  is_default: boolean;
}

const TENANT_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;
const PROD_LIKE_FG_ENVS = new Set(['prod', 'production', 'staging']);

function isProdLikeEnv(): boolean {
  const nodeEnv = (process.env.NODE_ENV || '').trim().toLowerCase();
  const fgEnv = (process.env.FG_ENV || '').trim().toLowerCase();
  return nodeEnv === 'production' || PROD_LIKE_FG_ENVS.has(fgEnv);
}

function getRequestId(request: NextRequest): string {
  return request.headers.get('x-request-id') || crypto.randomUUID();
}

function tenantContextError(
  code: 'TENANT_CONTEXT_MISSING' | 'TENANT_CONTEXT_INVALID',
  requestId: string,
  tenantId?: string,
) {
  const body: Record<string, string> = { error: code, request_id: requestId };
  if (tenantId) body.tenant_id = tenantId;
  return NextResponse.json(body, {
    status: 500,
    headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId },
  });
}

function resolveConfiguredOperatorTenant(requestId: string): { tenantId: string } | NextResponse {
  const tenantId = (process.env.CORE_TENANT_ID || '').trim();

  if (!tenantId) {
    if (!isProdLikeEnv()) return { tenantId: 'default' };
    console.warn(`[tenants] TENANT_CONTEXT_MISSING CORE_TENANT_ID absent request_id=${requestId}`);
    return tenantContextError('TENANT_CONTEXT_MISSING', requestId);
  }

  if (isProdLikeEnv() && tenantId.toLowerCase() === 'default') {
    console.warn(`[tenants] TENANT_CONTEXT_INVALID CORE_TENANT_ID=default request_id=${requestId}`);
    return tenantContextError('TENANT_CONTEXT_INVALID', requestId, tenantId);
  }

  if (!TENANT_ID_RE.test(tenantId)) {
    console.warn(`[tenants] TENANT_CONTEXT_INVALID malformed CORE_TENANT_ID request_id=${requestId}`);
    return tenantContextError('TENANT_CONTEXT_INVALID', requestId);
  }

  return { tenantId };
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  const requestId = getRequestId(request);
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  if (!canAccessConsoleRoute('/admin/tenants', session)) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  // TENANT-ADMIN authority path: tenant_admin may only see their own tenant.
  // The session tenantId is the canonical authority — it was proved by Core
  // during authentication (DB-canonical membership + active state).
  // We do NOT retrieve the global registry and then filter in the browser —
  // the tenant_admin path never loads global tenant data at all.
  if (isTenantAdminSession(session)) {
    const claims = getSessionClaims(session);
    const tenantId = claims.tenantId;
    if (!tenantId || !TENANT_ID_RE.test(tenantId)) {
      // Tenant admin without a bound tenant ID — fail closed.
      console.warn(`[tenants] TENANT_CONTEXT_MISSING tenant_admin has no session tenantId request_id=${requestId}`);
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
    // Return only the session-bound tenant. Label is derived from the ID
    // (the registry is Platform Admin infrastructure; tenant admins do not
    // have access to registry metadata about other tenants).
    const tenantLabel = tenantId.replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
    const tenants: TenantEntry[] = [{ tenant_id: tenantId, label: tenantLabel, is_default: false }];
    return NextResponse.json({ tenants, authority: 'tenant_admin' });
  }

  // PLATFORM ADMIN path: defense-in-depth — require explicit Platform Admin authority
  // before the global registry is touched. This catches any future CLIENT_ADMIN_ROLES
  // drift that would otherwise let a non-admin internal session reach global data.
  if (!isPlatformAdminSession(session)) {
    console.warn(`[tenants] FORBIDDEN non-platform-admin-fallthrough request_id=${requestId}`);
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  const operatorTenant = resolveConfiguredOperatorTenant(requestId);
  if (operatorTenant instanceof NextResponse) return operatorTenant;

  const operatorTenantId = operatorTenant.tenantId;
  const registry = await getTenantRegistry();

  const tenants: TenantEntry[] = Object.entries(registry)
    .filter(([id]) => id !== operatorTenantId)
    .map(([id, rec]) => ({ tenant_id: id, label: rec.label, is_default: false }));

  return NextResponse.json({ tenants, authority: 'platform_admin' });
}
