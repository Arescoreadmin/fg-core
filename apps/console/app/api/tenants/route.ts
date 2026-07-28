import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { canAccessConsoleRoute } from '@/lib/consoleAccess';
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

  const operatorTenant = resolveConfiguredOperatorTenant(requestId);
  if (operatorTenant instanceof NextResponse) return operatorTenant;

  const defaultId = operatorTenant.tenantId;
  const registry = await getTenantRegistry();

  const tenants: TenantEntry[] = [
    { tenant_id: defaultId, label: 'Default (operator)', is_default: true },
    ...Object.entries(registry)
      .filter(([id]) => id !== defaultId)
      .map(([id, rec]) => ({ tenant_id: id, label: rec.label, is_default: false })),
  ];

  return NextResponse.json({ tenants });
}
