import Link from 'next/link';
import { TenantBadge } from '@/components/common/TenantBadge';

const tenantId = process.env.NEXT_PUBLIC_TENANT_ID;
const scopes = process.env.NEXT_PUBLIC_SCOPE_BADGE;

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <main style={{ maxWidth: 1200, margin: '0 auto', padding: '1.5rem' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
        <nav style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <Link href="/dashboard">Overview</Link>
          <Link href="/dashboard/decisions">Decisions</Link>
          <Link href="/dashboard/forensics">Forensics</Link>
          <Link href="/dashboard/keys">Keys</Link>
          <Link href="/dashboard/alignment">Alignment</Link>
        </nav>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <TenantBadge tenantId={tenantId} />
          {scopes ? <span style={{ border: '1px solid var(--border)', padding: '0.2rem 0.5rem', borderRadius: 8, fontSize: 12 }}>Scopes: {scopes}</span> : null}
        </div>
      </header>
      {children}
    </main>
  );
}
