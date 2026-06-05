import { NextResponse } from 'next/server';

export interface TenantEntry {
  tenant_id: string;
  label: string;
  is_default: boolean;
}

export async function GET(): Promise<NextResponse> {
  const defaultId = process.env.CORE_TENANT_ID || 'default';
  const demoRaw = process.env.FG_CONSOLE_DEMO_TENANTS || '';
  const demoIds = demoRaw
    .split(',')
    .map((v) => v.trim())
    .filter((v) => /^[a-zA-Z0-9_-]{1,128}$/.test(v));

  const tenants: TenantEntry[] = [
    { tenant_id: defaultId, label: 'Default (operator)', is_default: true },
    ...demoIds
      .filter((id) => id !== defaultId)
      .map((id) => ({
        tenant_id: id,
        label: id.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
        is_default: false,
      })),
  ];

  return NextResponse.json({ tenants });
}
