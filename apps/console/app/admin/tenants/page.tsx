'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Building2, ExternalLink, Users, ShieldCheck } from 'lucide-react';

interface TenantEntry {
  tenant_id: string;
  label: string;
  is_default: boolean;
}

export default function ClientRosterPage() {
  const [tenants, setTenants] = useState<TenantEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/tenants')
      .then(r => r.json())
      .then(d => setTenants(d.tenants ?? []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <main style={s.main}>
      <div style={s.header}>
        <div>
          <h1 style={s.title}>Clients</h1>
          <p style={s.subtitle}>All tenants accessible from this console. Select a client to manage their users and portal access.</p>
        </div>
      </div>

      {error && <div style={s.errorBanner}>{error}</div>}

      {loading ? (
        <p style={s.muted}>Loading tenants…</p>
      ) : (
        <div style={s.grid}>
          {tenants.map(t => (
            <TenantCard key={t.tenant_id} tenant={t} />
          ))}
        </div>
      )}

      <div style={s.hint}>
        <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--muted)' }}>
          To add a new demo tenant, update <code>FG_CONSOLE_DEMO_TENANTS</code> in Vercel and redeploy.
          Real client tenants are provisioned via the seed script or the onboarding flow.
        </p>
      </div>
    </main>
  );
}

function TenantCard({ tenant }: { tenant: TenantEntry }) {
  const sectorIcon = tenant.tenant_id.includes('bank') ? '🏦'
    : tenant.tenant_id.includes('health') ? '🏥'
    : tenant.tenant_id.includes('law') ? '⚖️'
    : '🏢';

  const consoleUrl = `/field-assessment?tenant_id=${tenant.tenant_id}`;
  const portalUrl = `/login?tenant_id=${tenant.tenant_id}`;

  return (
    <div style={s.card}>
      <div style={s.cardTop}>
        <span style={s.icon}>{sectorIcon}</span>
        <div style={{ flex: 1 }}>
          <div style={s.cardTitle}>{tenant.label}</div>
          <code style={s.cardId}>{tenant.tenant_id}</code>
        </div>
        {tenant.is_default && (
          <span style={s.defaultBadge}>default</span>
        )}
      </div>

      <div style={s.cardActions}>
        <Link href={`/admin/tenants/${tenant.tenant_id}`} style={s.manageBtn}>
          <Users size={13} style={{ marginRight: 4 }} />
          Manage users
        </Link>

        <a href={consoleUrl} style={s.viewBtn} title="View this tenant's field assessments">
          <ShieldCheck size={13} style={{ marginRight: 4 }} />
          Assessments
        </a>

        <a
          href={`${typeof window !== 'undefined' ? window.location.origin.replace('console.', 'app.') : ''}${portalUrl}`}
          target="_blank"
          rel="noopener noreferrer"
          style={s.externalBtn}
          title="Open portal login for this tenant"
        >
          <ExternalLink size={12} style={{ marginRight: 4 }} />
          Portal
        </a>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  main: { minHeight: '100vh', padding: '2rem', maxWidth: '1100px', margin: '0 auto' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.75rem' },
  title: { fontSize: '1.5rem', fontWeight: 600, marginBottom: '0.25rem' },
  subtitle: { fontSize: '0.875rem', color: 'var(--muted)', maxWidth: '520px' },
  muted: { color: 'var(--muted)', fontSize: '0.875rem' },
  errorBanner: { padding: '0.75rem 1rem', borderRadius: '6px', backgroundColor: 'rgba(239,68,68,0.08)', color: '#ef4444', marginBottom: '1rem', fontSize: '0.875rem' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1rem', marginBottom: '2rem' },
  card: { border: '1px solid var(--border)', borderRadius: '10px', padding: '1.25rem', backgroundColor: 'var(--surface, var(--background))', display: 'flex', flexDirection: 'column', gap: '1rem' },
  cardTop: { display: 'flex', alignItems: 'flex-start', gap: '0.75rem' },
  icon: { fontSize: '1.5rem', lineHeight: 1, marginTop: 2 },
  cardTitle: { fontWeight: 600, fontSize: '0.95rem', marginBottom: '0.2rem' },
  cardId: { fontSize: '0.75rem', color: 'var(--muted)', fontFamily: 'monospace' },
  defaultBadge: { fontSize: '0.65rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', padding: '2px 7px', borderRadius: '9999px', backgroundColor: '#2563eb22', color: '#2563eb', border: '1px solid #2563eb44', whiteSpace: 'nowrap' },
  cardActions: { display: 'flex', gap: '0.5rem', flexWrap: 'wrap' },
  manageBtn: { display: 'inline-flex', alignItems: 'center', padding: '0.4rem 0.75rem', borderRadius: '6px', border: 'none', backgroundColor: '#2563eb', color: '#fff', cursor: 'pointer', fontSize: '0.8rem', textDecoration: 'none', fontWeight: 500 },
  viewBtn: { display: 'inline-flex', alignItems: 'center', padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'transparent', cursor: 'pointer', fontSize: '0.8rem', textDecoration: 'none', color: 'var(--foreground)' },
  externalBtn: { display: 'inline-flex', alignItems: 'center', padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'transparent', cursor: 'pointer', fontSize: '0.8rem', textDecoration: 'none', color: 'var(--muted)' },
  hint: { padding: '1rem', border: '1px solid var(--border)', borderRadius: '8px', backgroundColor: 'var(--surface-2, var(--background))' },
};
