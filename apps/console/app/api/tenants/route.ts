import { NextResponse } from 'next/server';
import { getTenantRegistry } from '@/lib/tenant-registry';

export interface TenantEntry {
  tenant_id: string;
  label: string;
  is_default: boolean;
}

export async function GET(): Promise<NextResponse> {
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
