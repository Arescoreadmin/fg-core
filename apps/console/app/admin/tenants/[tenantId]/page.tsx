'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ConsoleUser {
  user_id: string;
  email: string;
  display_name: string;
  role: 'user' | 'admin' | 'auditor';
  active: boolean;
  invite_pending: boolean;
  last_active_at: string | null;
  created_at: string;
}

interface PortalGrant {
  grant_id: string;
  client_id: string;
  engagement_id: string;
  portal_role: string;
  status: 'active' | 'revoked' | 'expired';
  created_by: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  rotation_counter: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(v: string | null | undefined) {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleString();
}
function fmtDate(v: string | null | undefined) {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleDateString();
}
function roleBadge(role: string): React.CSSProperties {
  const map: Record<string, string> = {
    admin: '#1d4ed8', auditor: '#7c3aed', executive: '#0891b2',
    remediation: '#b45309', technical: '#374151', compliance: '#065f46', general: '#374151', user: '#374151',
  };
  const c = map[role] ?? '#374151';
  return { display: 'inline-block', padding: '2px 8px', borderRadius: '9999px', fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', backgroundColor: c + '22', color: c, border: `1px solid ${c}44` };
}
function statusDot(status: string) {
  const c = status === 'active' ? '#22c55e' : status === 'revoked' ? '#ef4444' : '#f59e0b';
  return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}><span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: c, display: 'inline-block' }} />{status}</span>;
}

const PORTAL_ROLES = [
  { value: 'executive', label: 'Executive', desc: 'Risk posture & KPIs, no technical detail' },
  { value: 'remediation', label: 'Remediation', desc: 'Findings with remediation steps' },
  { value: 'technical', label: 'Technical', desc: 'Full detail including evidence' },
  { value: 'compliance', label: 'Compliance', desc: 'Framework mapping and posture' },
  { value: 'general', label: 'General', desc: 'Default full-access view' },
];

// ─── API helper ───────────────────────────────────────────────────────────────

function coreUrl(path: string, tenantId: string) {
  return `/api/core/${path}?tenant_id=${encodeURIComponent(tenantId)}`;
}

async function coreApi<T>(path: string, tenantId: string, options?: RequestInit): Promise<T> {
  const res = await fetch(coreUrl(path, tenantId), {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ─── Console Users tab ────────────────────────────────────────────────────────

function ConsoleUsersTab({ tenantId }: { tenantId: string }) {
  const [users, setUsers] = useState<ConsoleUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [inviteRole, setInviteRole] = useState<'user' | 'admin' | 'auditor'>('user');
  const [inviteResult, setInviteResult] = useState<{ invite_token: string; invite_url_hint: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function load() {
    setLoading(true); setError(null);
    try { setUsers((await coreApi<{ items: ConsoleUser[] }>('workforce/users', tenantId)).items ?? []); }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load'); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, [tenantId]);

  async function handleInvite() {
    setSubmitting(true); setError(null);
    try {
      const r = await coreApi<{ invite_token: string; invite_url_hint: string }>('workforce/users', tenantId, {
        method: 'POST',
        body: JSON.stringify({ email: inviteEmail, display_name: inviteName, role: inviteRole }),
      });
      setInviteResult(r); setShowInvite(false); setInviteEmail(''); setInviteName('');
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Invite failed'); }
    finally { setSubmitting(false); }
  }

  async function patch(userId: string, active: boolean) {
    setError(null);
    try { await coreApi(`workforce/users/${userId}`, tenantId, { method: 'PATCH', body: JSON.stringify({ active }) }); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Update failed'); }
  }

  return (
    <div>
      <div style={s.sectionHeader}>
        <div>
          <p style={s.sectionTitle}>Console users</p>
          <p style={s.sectionDesc}>Staff with direct console access. <strong>admin</strong> = full access, <strong>auditor</strong> = read-only audit, <strong>user</strong> = standard.</p>
        </div>
        <button style={s.primaryBtn} onClick={() => { setShowInvite(true); setInviteResult(null); }}>Invite user</button>
      </div>

      {error && <div style={s.errorBanner}>{error}</div>}
      {inviteResult && (
        <div style={s.successBanner}>
          <strong>Invite created — share this link (expires in 72 h):</strong>
          <code style={s.code}>{typeof window !== 'undefined' ? window.location.origin : ''}{inviteResult.invite_url_hint}</code>
        </div>
      )}

      {showInvite && (
        <div style={s.backdrop}>
          <div style={s.modal}>
            <h2 style={s.modalTitle}>Invite console user</h2>
            <label style={s.field}>Email<input style={s.input} type="email" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="user@client.com" /></label>
            <label style={s.field}>Display name<input style={s.input} value={inviteName} onChange={e => setInviteName(e.target.value)} placeholder="Jane Smith" /></label>
            <label style={s.field}>Console role
              <select style={s.input} value={inviteRole} onChange={e => setInviteRole(e.target.value as 'user' | 'admin' | 'auditor')}>
                <option value="user">User — standard access</option>
                <option value="admin">Admin — full tenant access</option>
                <option value="auditor">Auditor — read-only + audit logs</option>
              </select>
            </label>
            <div style={s.modalActions}>
              <button style={s.secondaryBtn} onClick={() => setShowInvite(false)} disabled={submitting}>Cancel</button>
              <button style={s.primaryBtn} onClick={handleInvite} disabled={submitting || !inviteEmail || !inviteName}>{submitting ? 'Sending…' : 'Send invite'}</button>
            </div>
          </div>
        </div>
      )}

      <div style={s.tableWrap}>
        {loading ? <p style={s.muted}>Loading…</p> : (
          <table style={s.table}>
            <thead><tr>{['Email', 'Name', 'Role', 'Status', 'Last active', 'Joined', 'Actions'].map(h => <th key={h} style={s.th}>{h}</th>)}</tr></thead>
            <tbody>
              {users.length === 0
                ? <tr><td style={s.td} colSpan={7}>No console users yet.</td></tr>
                : users.map(u => (
                  <tr key={u.user_id}>
                    <td style={s.td}>{u.email}</td>
                    <td style={s.td}>{u.display_name || '—'}</td>
                    <td style={s.td}><span style={roleBadge(u.role)}>{u.role}</span></td>
                    <td style={s.td}>
                      {u.invite_pending ? <span style={{ color: '#f59e0b', fontSize: '0.8rem' }}>Invite pending</span>
                        : u.active ? <span style={{ color: '#22c55e', fontSize: '0.8rem' }}>Active</span>
                        : <span style={{ color: '#ef4444', fontSize: '0.8rem' }}>Inactive</span>}
                    </td>
                    <td style={s.td}>{fmt(u.last_active_at)}</td>
                    <td style={s.td}>{fmtDate(u.created_at)}</td>
                    <td style={s.td}>
                      {u.active
                        ? <button style={s.dangerBtn} onClick={() => patch(u.user_id, false)}>Deactivate</button>
                        : <button style={s.secondaryBtn} onClick={() => patch(u.user_id, true)}>Reactivate</button>}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Portal Access tab ────────────────────────────────────────────────────────

function PortalAccessTab({ tenantId }: { tenantId: string }) {
  const [grants, setGrants] = useState<PortalGrant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [clientId, setClientId] = useState('');
  const [engagementId, setEngagementId] = useState('');
  const [portalRole, setPortalRole] = useState('general');
  const [ttlDays, setTtlDays] = useState(365);
  const [created, setCreated] = useState<{ raw_secret: string; portal_login_url: string; portal_role: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function load() {
    setLoading(true); setError(null);
    try { setGrants((await coreApi<{ items: PortalGrant[] }>('portal/grants', tenantId)).items ?? []); }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load'); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, [tenantId]);

  async function handleCreate() {
    setSubmitting(true); setError(null);
    try {
      const r = await coreApi<{ raw_secret: string; portal_login_url: string; portal_role: string }>('portal/grants', tenantId, {
        method: 'POST',
        body: JSON.stringify({ client_id: clientId, engagement_id: engagementId, portal_role: portalRole, ttl_days: ttlDays }),
      });
      setCreated(r); setShowCreate(false); setClientId(''); setEngagementId('');
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed to create'); }
    finally { setSubmitting(false); }
  }

  async function handleRevoke(grantId: string) {
    setError(null);
    try { await coreApi(`portal/grants/${grantId}`, tenantId, { method: 'DELETE' }); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to revoke'); }
  }

  const portalOrigin = typeof window !== 'undefined' ? window.location.origin.replace('console.', 'app.') : '';

  return (
    <div>
      <div style={s.sectionHeader}>
        <div>
          <p style={s.sectionTitle}>Portal access grants</p>
          <p style={s.sectionDesc}>Password-protected links for client-facing portal access. Choose a view type to control what the client sees.</p>
        </div>
        <button style={s.primaryBtn} onClick={() => { setShowCreate(true); setCreated(null); }}>Create grant</button>
      </div>

      {error && <div style={s.errorBanner}>{error}</div>}

      {created && (
        <div style={s.successBanner}>
          <strong>Grant created — copy this password now. Not shown again.</strong>
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>Portal access password</span>
            <code style={s.code}>{created.raw_secret}</code>
            <span style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>Login URL (send to client)</span>
            <code style={s.code}>{portalOrigin}{created.portal_login_url}</code>
            <span style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>View type: <span style={roleBadge(created.portal_role)}>{created.portal_role}</span></span>
          </div>
        </div>
      )}

      <div style={s.viewGrid}>
        {PORTAL_ROLES.map(r => (
          <div key={r.value} style={s.viewCard}>
            <span style={roleBadge(r.value)}>{r.label}</span>
            <p style={{ margin: '6px 0 0', fontSize: '0.78rem', color: 'var(--muted)' }}>{r.desc}</p>
          </div>
        ))}
      </div>

      {showCreate && (
        <div style={s.backdrop}>
          <div style={s.modal}>
            <h2 style={s.modalTitle}>Create portal grant</h2>
            <label style={s.field}>Client ID<input style={s.input} value={clientId} onChange={e => setClientId(e.target.value)} placeholder="acme-corp" /></label>
            <label style={s.field}>Engagement ID<input style={s.input} value={engagementId} onChange={e => setEngagementId(e.target.value)} placeholder="acme-corp-assessment-2026" /></label>
            <label style={s.field}>Portal view type
              <select style={s.input} value={portalRole} onChange={e => setPortalRole(e.target.value)}>
                {PORTAL_ROLES.map(r => <option key={r.value} value={r.value}>{r.label} — {r.desc}</option>)}
              </select>
            </label>
            <label style={s.field}>Access duration (days)<input style={s.input} type="number" min={1} max={730} value={ttlDays} onChange={e => setTtlDays(Number(e.target.value))} /></label>
            <div style={s.modalActions}>
              <button style={s.secondaryBtn} onClick={() => setShowCreate(false)} disabled={submitting}>Cancel</button>
              <button style={s.primaryBtn} onClick={handleCreate} disabled={submitting || !clientId || !engagementId}>{submitting ? 'Creating…' : 'Create grant'}</button>
            </div>
          </div>
        </div>
      )}

      <div style={s.tableWrap}>
        {loading ? <p style={s.muted}>Loading…</p> : (
          <table style={s.table}>
            <thead><tr>{['Client', 'Engagement', 'View', 'Status', 'Created by', 'Expires', 'Last used', ''].map((h, i) => <th key={i} style={s.th}>{h}</th>)}</tr></thead>
            <tbody>
              {grants.length === 0
                ? <tr><td style={s.td} colSpan={8}>No portal grants yet.</td></tr>
                : grants.map(g => (
                  <tr key={g.grant_id} style={{ opacity: g.status !== 'active' ? 0.5 : 1 }}>
                    <td style={s.td}>{g.client_id}</td>
                    <td style={{ ...s.td, fontFamily: 'monospace', fontSize: '0.78rem' }}>{g.engagement_id}</td>
                    <td style={s.td}><span style={roleBadge(g.portal_role)}>{g.portal_role}</span></td>
                    <td style={s.td}>{statusDot(g.status)}</td>
                    <td style={s.td}>{g.created_by}</td>
                    <td style={s.td}>{fmtDate(g.expires_at)}</td>
                    <td style={s.td}>{fmt(g.last_used_at)}</td>
                    <td style={s.td}>{g.status === 'active' && <button style={s.dangerBtn} onClick={() => handleRevoke(g.grant_id)}>Revoke</button>}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'users' | 'portal';

export default function TenantDetailPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const [tab, setTab] = useState<Tab>('users');

  const label = tenantId.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

  return (
    <main style={s.main}>
      <div style={s.pageHeader}>
        <Link href="/admin/tenants" style={s.backLink}><ArrowLeft size={14} style={{ marginRight: 4 }} />All clients</Link>
        <h1 style={s.pageTitle}>{label}</h1>
        <p style={s.pageSubtitle}>
          Tenant ID: <code style={{ fontSize: '0.8rem' }}>{tenantId}</code>
        </p>
      </div>

      <div style={s.tabs}>
        {(['users', 'portal'] as const).map(t => (
          <button key={t} style={{ ...s.tab, ...(tab === t ? s.tabActive : {}) }} onClick={() => setTab(t)}>
            {t === 'users' ? 'Console users' : 'Portal access'}
          </button>
        ))}
      </div>

      <div style={s.card}>
        {tab === 'users' ? <ConsoleUsersTab tenantId={tenantId} /> : <PortalAccessTab tenantId={tenantId} />}
      </div>
    </main>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const s: Record<string, React.CSSProperties> = {
  main: { minHeight: '100vh', padding: '2rem', maxWidth: '1200px', margin: '0 auto' },
  pageHeader: { marginBottom: '1.5rem' },
  backLink: { display: 'inline-flex', alignItems: 'center', fontSize: '0.8rem', color: 'var(--muted)', textDecoration: 'none', marginBottom: '0.5rem' },
  pageTitle: { fontSize: '1.5rem', fontWeight: 600, marginBottom: '0.25rem', textTransform: 'capitalize' },
  pageSubtitle: { fontSize: '0.875rem', color: 'var(--muted)' },
  tabs: { display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: 0 },
  tab: { padding: '0.5rem 1rem', border: 'none', background: 'transparent', cursor: 'pointer', fontSize: '0.875rem', color: 'var(--muted)', borderBottom: '2px solid transparent', marginBottom: '-1px' },
  tabActive: { color: 'var(--foreground)', borderBottom: '2px solid #2563eb', fontWeight: 500 },
  card: { border: '1px solid var(--border)', borderRadius: '8px', padding: '1.5rem', backgroundColor: 'var(--surface, var(--background))' },
  sectionHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' },
  sectionTitle: { fontWeight: 600, marginBottom: '0.25rem' },
  sectionDesc: { fontSize: '0.8rem', color: 'var(--muted)', maxWidth: '540px' },
  tableWrap: { overflowX: 'auto', marginTop: '1rem' },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { textAlign: 'left', padding: '0.6rem 0.75rem', borderBottom: '1px solid var(--border)', fontSize: '0.72rem', textTransform: 'uppercase', color: 'var(--muted)', whiteSpace: 'nowrap' },
  td: { padding: '0.65rem 0.75rem', borderBottom: '1px solid var(--border)', fontSize: '0.875rem' },
  muted: { color: 'var(--muted)', fontSize: '0.875rem' },
  errorBanner: { padding: '0.75rem 1rem', borderRadius: '6px', backgroundColor: 'rgba(239,68,68,0.08)', color: '#ef4444', marginBottom: '1rem', fontSize: '0.875rem' },
  successBanner: { padding: '1rem', borderRadius: '6px', backgroundColor: 'rgba(34,197,94,0.08)', marginBottom: '1rem', fontSize: '0.875rem' },
  code: { display: 'block', marginTop: 6, padding: '0.5rem 0.75rem', background: 'var(--background)', border: '1px solid var(--border)', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem', overflowX: 'auto', wordBreak: 'break-all' },
  primaryBtn: { padding: '0.5rem 1rem', borderRadius: '6px', border: 'none', backgroundColor: '#2563eb', color: '#fff', cursor: 'pointer', fontSize: '0.875rem', whiteSpace: 'nowrap' },
  secondaryBtn: { padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'transparent', cursor: 'pointer', fontSize: '0.875rem' },
  dangerBtn: { padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.4)', color: '#ef4444', background: 'transparent', cursor: 'pointer', fontSize: '0.875rem' },
  backdrop: { position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem', zIndex: 50 },
  modal: { background: 'var(--background, #fff)', borderRadius: '12px', padding: '1.5rem', width: '100%', maxWidth: '460px', display: 'flex', flexDirection: 'column', gap: '1rem', border: '1px solid var(--border)' },
  modalTitle: { fontSize: '1.1rem', fontWeight: 600 },
  field: { display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--muted)' },
  input: { padding: '0.5rem', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '0.875rem', background: 'var(--background)', color: 'var(--foreground)' },
  modalActions: { display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' },
  viewGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' },
  viewCard: { padding: '0.75rem', border: '1px solid var(--border)', borderRadius: '8px', backgroundColor: 'var(--surface-2, var(--background))' },
};
