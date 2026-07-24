'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Building2, ExternalLink, Users, ShieldCheck, Plus } from 'lucide-react';

interface TenantEntry {
  tenant_id: string;
  label: string;
  is_default: boolean;
}

interface ProvisionResult {
  tenant_id: string;
  name: string;
  already_existed?: boolean;
  registry_live?: boolean;
  registry_error?: string | null;
  api_key: string | null;
  credential_id?: string;
  warning?: string;
}

// ─── Create Client Modal ──────────────────────────────────────────────────────

function CreateClientModal({ onClose, onCreated }: { onClose: () => void; onCreated: (r: ProvisionResult) => void }) {
  const [tenantId, setTenantId] = useState('');
  const [name, setName] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-generate tenant_id slug from name
  function handleNameChange(v: string) {
    setName(v);
    setTenantId(v.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 64));
  }

  async function handleSubmit() {
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/admin/provision-tenant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenantId, name }),
      });
      const data = await res.json();
      if (!res.ok) {
        const msg = [data.error ?? `HTTP ${res.status}`, data.detail].filter(Boolean).join(' — ');
        const rid = data.request_id ? ` (request_id: ${data.request_id})` : '';
        throw new Error(msg + rid);
      }
      onCreated(data as ProvisionResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create client');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div style={s.backdrop}>
      <div style={s.modal}>
        <h2 style={s.modalTitle}>Create new client</h2>
        <p style={{ fontSize: '0.8rem', color: 'var(--muted)', marginTop: 0 }}>
          Provisions a new tenant and generates an API key. You will need to add the key to Vercel env vars after creation.
        </p>
        <label style={s.field}>
          Client name
          <input style={s.input} value={name} onChange={e => handleNameChange(e.target.value)} placeholder="Acme Financial Group" autoFocus />
        </label>
        <label style={s.field}>
          Tenant ID <span style={{ color: 'var(--muted)', fontWeight: 400 }}>(auto-generated, editable)</span>
          <input
            style={s.input}
            value={tenantId}
            onChange={e => setTenantId(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, '').slice(0, 64))}
            placeholder="acme-financial-group"
          />
          <span style={{ fontSize: '0.72rem', color: 'var(--muted)' }}>Letters, numbers, hyphens only. Cannot be changed later.</span>
        </label>
        {error && <div style={s.errorBanner}>{error}</div>}
        <div style={s.modalActions}>
          <button style={s.secondaryBtn} onClick={onClose} disabled={submitting}>Cancel</button>
          <button style={s.primaryBtn} onClick={handleSubmit} disabled={submitting || !tenantId || !name}>
            {submitting ? 'Creating…' : 'Create client'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Provision Result Modal ───────────────────────────────────────────────────

function ProvisionResultModal({ result, onClose }: { result: ProvisionResult; onClose: () => void }) {
  const [copied, setCopied] = useState(false);

  function copy(text: string) {
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  }

  const isLive = result.registry_live;

  return (
    <div style={s.backdrop}>
      <div style={{ ...s.modal, maxWidth: 520 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ fontSize: '1.4rem' }}>{isLive ? '✅' : '⚠️'}</span>
          <h2 style={{ ...s.modalTitle, margin: 0 }}>
            {isLive
              ? result.already_existed ? 'Key regenerated — client is live' : 'Client created — live immediately'
              : result.already_existed ? 'Key regenerated — manual step required' : 'Client created — manual step required'}
          </h2>
        </div>

        {isLive ? (
          <p style={{ fontSize: '0.875rem', color: 'var(--muted)', marginTop: 4, lineHeight: 1.6 }}>
            <strong>{result.name}</strong> is now active in your console. No further steps needed.
            To give clients portal access, go to <strong>Manage users → Portal Access</strong>.
          </p>
        ) : (
          <>
            {result.warning && (
              <div style={{ background: '#7c2d00', color: '#fef3c7', borderRadius: 6, padding: '8px 12px', fontSize: '0.8rem', marginBottom: 8 }}>
                ⚠ {result.warning}
              </div>
            )}
            <p style={{ fontSize: '0.875rem', color: 'var(--muted)', marginTop: 4, lineHeight: 1.6 }}>
              {result.registry_error
                ? `Registry write failed: ${result.registry_error}`
                : 'Neither Edge Config nor Redis is configured — copy the API key below and add it manually.'}
            </p>
            {result.api_key && (
              <label style={s.field}>
                API key <span style={{ fontWeight: 400 }}>(shown once — save it now)</span>
                <div style={{ position: 'relative' }}>
                  <code style={{ ...s.code, paddingRight: '4.5rem' }}>{result.api_key}</code>
                  <button style={s.copyBtn} onClick={() => copy(result.api_key!)}>{copied ? 'Copied!' : 'Copy'}</button>
                </div>
              </label>
            )}
            <div style={s.stepsBox}>
              <p style={{ margin: '0 0 6px', fontWeight: 600, fontSize: '0.8rem' }}>
                Set one of the following to enable zero-touch provisioning:
              </p>
              <div style={s.stepRow}>
                <span style={s.envName}>REDIS_URL</span>
                <span style={s.stepDesc}>Shared Redis — set same value in console and portal (recommended)</span>
              </div>
              <div style={s.stepRow}>
                <span style={s.envName}>EDGE_CONFIG + VERCEL_API_TOKEN</span>
                <span style={s.stepDesc}>Vercel Edge Config store with a write-enabled API token</span>
              </div>
            </div>
          </>
        )}

        <div style={s.modalActions}>
          <button style={s.primaryBtn} onClick={onClose}>
            {isLive ? 'Go to client' : 'Done'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Roster Page ──────────────────────────────────────────────────────────────

export default function ClientRosterPage() {
  const [tenants, setTenants] = useState<TenantEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [provisionResult, setProvisionResult] = useState<ProvisionResult | null>(null);
  const [regenLoading, setRegenLoading] = useState<string | null>(null);

  function loadTenants() {
    setLoading(true);
    fetch('/api/tenants')
      .then(r => r.json())
      .then(d => setTenants(d.tenants ?? []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => { loadTenants(); }, []);

  function handleCreated(result: ProvisionResult) {
    setShowCreate(false);
    setProvisionResult(result);
    setTenants(prev => [
      ...prev,
      { tenant_id: result.tenant_id, label: result.name, is_default: false },
    ]);
  }

  async function handleRegenKey(tenant: TenantEntry) {
    if (!confirm(`Regenerate API key for "${tenant.label}"? The old key will still work until you update Vercel.`)) return;
    setRegenLoading(tenant.tenant_id);
    setError(null);
    try {
      const res = await fetch('/api/admin/provision-tenant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenant.tenant_id, name: tenant.label }),
      });
      const data = await res.json();
      if (!res.ok) {
        const msg = [data.error ?? `HTTP ${res.status}`, data.detail].filter(Boolean).join(' — ');
        const rid = data.request_id ? ` (request_id: ${data.request_id})` : '';
        throw new Error(msg + rid);
      }
      setProvisionResult(data as ProvisionResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to regenerate key');
    } finally {
      setRegenLoading(null);
    }
  }

  return (
    <main style={s.main}>
      <div style={s.header}>
        <div>
          <h1 style={s.title}>Clients</h1>
          <p style={s.subtitle}>All tenants accessible from this console. Select a client to manage their users and portal access.</p>
        </div>
        <button style={s.primaryBtn} onClick={() => setShowCreate(true)}>
          <Plus size={14} style={{ marginRight: 5 }} />
          Create client
        </button>
      </div>

      {error && <div style={s.errorBanner}>{error}</div>}

      {loading ? (
        <p style={s.muted}>Loading tenants…</p>
      ) : (
        <div style={s.grid}>
          {tenants.map(t => (
            <TenantCard
              key={t.tenant_id}
              tenant={t}
              onRegenKey={regenLoading ? () => {} : handleRegenKey}
            />
          ))}
        </div>
      )}
      {regenLoading && <p style={s.muted}>Regenerating key for {regenLoading}…</p>}

      <div style={s.hint}>
        <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--muted)' }}>
          Click <strong>Create client</strong> to provision a new tenant — it registers immediately with no Vercel redeployment required.
          Use <strong>Regen key</strong> on any card to rotate a compromised or stale API key.
        </p>
      </div>

      {showCreate && <CreateClientModal onClose={() => setShowCreate(false)} onCreated={handleCreated} />}
      {provisionResult && <ProvisionResultModal result={provisionResult} onClose={() => setProvisionResult(null)} />}
    </main>
  );
}

function TenantCard({ tenant, onRegenKey }: { tenant: TenantEntry; onRegenKey: (t: TenantEntry) => void }) {
  const sectorIcon = tenant.tenant_id.includes('bank') ? '🏦'
    : tenant.tenant_id.includes('health') ? '🏥'
    : tenant.tenant_id.includes('law') ? '⚖️'
    : '🏢';

  const consoleUrl = `/field-assessment?tenant_id=${tenant.tenant_id}`;
  const portalBase = typeof window !== 'undefined' ? window.location.origin.replace('console.', 'app.') : '';

  return (
    <div style={s.card}>
      <div style={s.cardTop}>
        <span style={s.icon}>{sectorIcon}</span>
        <div style={{ flex: 1 }}>
          <div style={s.cardTitle}>{tenant.label}</div>
          <code style={s.cardId}>{tenant.tenant_id}</code>
        </div>
        {tenant.is_default && <span style={s.defaultBadge}>default</span>}
      </div>
      <div style={s.cardActions}>
        <Link href={`/admin/tenants/${tenant.tenant_id}`} style={s.manageBtn}>
          <Users size={13} style={{ marginRight: 4 }} />Manage users
        </Link>
        <a href={consoleUrl} style={s.viewBtn}>
          <ShieldCheck size={13} style={{ marginRight: 4 }} />Assessments
        </a>
        <a href={`${portalBase}/login?tenant_id=${tenant.tenant_id}`} target="_blank" rel="noopener noreferrer" style={s.externalBtn}>
          <ExternalLink size={12} style={{ marginRight: 4 }} />Portal
        </a>
        {!tenant.is_default && (
          <button style={s.regenBtn} onClick={() => onRegenKey(tenant)} title="Generate a new API key for this tenant">
            Regen key
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────

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
  // Modal
  backdrop: { position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem', zIndex: 50 },
  modal: { background: 'var(--background, #fff)', borderRadius: '12px', padding: '1.5rem', width: '100%', maxWidth: '460px', display: 'flex', flexDirection: 'column', gap: '1rem', border: '1px solid var(--border)', maxHeight: '90vh', overflowY: 'auto' },
  modalTitle: { fontSize: '1.1rem', fontWeight: 600 },
  field: { display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--muted)' },
  input: { padding: '0.5rem', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '0.875rem', background: 'var(--background)', color: 'var(--foreground)' },
  modalActions: { display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.25rem' },
  primaryBtn: { display: 'inline-flex', alignItems: 'center', padding: '0.5rem 1rem', borderRadius: '6px', border: 'none', backgroundColor: '#2563eb', color: '#fff', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 500 },
  secondaryBtn: { padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'transparent', cursor: 'pointer', fontSize: '0.875rem' },
  code: { display: 'block', padding: '0.5rem 0.75rem', background: 'var(--surface-2, var(--background))', border: '1px solid var(--border)', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem', overflowX: 'auto', wordBreak: 'break-all' },
  copyBtn: { position: 'absolute', top: '50%', right: '0.5rem', transform: 'translateY(-50%)', padding: '2px 8px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--background)', fontSize: '0.72rem', cursor: 'pointer' },
  stepsBox: { padding: '0.875rem', border: '1px solid var(--border)', borderRadius: '8px', backgroundColor: 'var(--surface-2, var(--background))', display: 'flex', flexDirection: 'column', gap: '0.6rem' },
  stepRow: { display: 'flex', gap: '0.75rem', alignItems: 'flex-start', fontSize: '0.78rem' },
  envName: { fontFamily: 'monospace', fontSize: '0.72rem', fontWeight: 600, backgroundColor: '#1d4ed822', color: '#1d4ed8', padding: '1px 5px', borderRadius: '3px', whiteSpace: 'nowrap', marginTop: 2 },
  stepDesc: { color: 'var(--muted)', flex: 1 },
  regenBtn: { display: 'inline-flex', alignItems: 'center', padding: '0.4rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'transparent', cursor: 'pointer', fontSize: '0.75rem', color: 'var(--muted)' },
};
