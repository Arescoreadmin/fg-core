import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { canAccessConsoleRoute } from '@/lib/consoleAccess';
import { getTenantRegistry } from '@/lib/tenant-registry';

export interface TenantEntry {
  tenant_id: string;
  label: string;
  is_default: boolean;
}

export async function GET(): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  if (!canAccessConsoleRoute('/admin/tenants', session)) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  const defaultId = process.env.CORE_TENANT_ID || 'default';
  const registry = await getTenantRegistry();

  const tenants: TenantEntry[] = [
    { tenant_id: defaultId, label: 'Default (operator)', is_default: true },
    ...Object.entries(registry)
      .filter(([id]) => id !== defaultId)
      .map(([id, rec]) => ({ tenant_id: id, label: rec.label, is_default: false })),
  ];

  return NextResponse.json({ tenants });
}
