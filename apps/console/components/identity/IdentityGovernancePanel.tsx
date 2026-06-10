'use client';

import { useState, useCallback, useEffect } from 'react';
import {
  getIdentityConfig,
  getIdentityReadiness,
  listInvitations,
  createInvitation,
  revokeInvitation,
  resendInvitation,
  getAuditSummary,
  getGovernanceScore,
  getDrift,
  getIdentityTimeline,
  getReadinessHistory,
  getIdentityRisk,
  getIdentityTypeGovernance,
  getSessionProvenance,
  upsertIdentityConfig,
  type IdentityConfig,
  type IdentityReadiness,
  type IdentityInvitation,
  type GovernanceScore,
  type DriftReport,
  type IdentityTimeline,
  type ReadinessHistory,
  type IdentityRisk,
  type AuditSummary,
  type IdentityTypeGovernance,
  type ProvenanceResult,
} from '@/lib/identityApi';

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt(v: string | null | undefined): string {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleString();
}

function fmtShort(v: string | null | undefined): string {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleDateString();
}

type SeverityBand = 'critical' | 'high' | 'medium' | 'low';

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#dc2626';
    case 'high': return '#ea580c';
    case 'medium': return '#ca8a04';
    case 'low': return '#16a34a';
    default: return '#6b7280';
  }
}

function gradeBg(grade: string): string {
  switch (grade) {
    case 'A': return 'rgba(22,163,74,0.12)';
    case 'B': return 'rgba(37,99,235,0.12)';
    case 'C': return 'rgba(202,138,4,0.12)';
    case 'D': return 'rgba(234,88,12,0.12)';
    default: return 'rgba(220,38,38,0.12)';
  }
}

function statusBadgeStyle(status: string): React.CSSProperties {
  const colors: Record<string, string> = {
    bound: '#16a34a',
    pending: '#ca8a04',
    auth_started: '#2563eb',
    accepted_identity_pending_binding: '#7c3aed',
    revoked: '#6b7280',
    expired: '#6b7280',
    failed: '#dc2626',
    ready: '#16a34a',
    not_configured: '#6b7280',
    provisioning: '#2563eb',
    disabled: '#6b7280',
  };
  const c = colors[status] ?? '#6b7280';
  return {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '9999px',
    fontSize: '0.7rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    backgroundColor: c + '22',
    color: c,
    border: `1px solid ${c}44`,
  };
}

// ── Styles ────────────────────────────────────────────────────────────────────

const s: Record<string, React.CSSProperties> = {
  root: { display: 'flex', flexDirection: 'column', gap: '1.5rem' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' },
  headerLeft: { display: 'flex', flexDirection: 'column', gap: '0.25rem' },
  title: { fontSize: '1.1rem', fontWeight: 700, margin: 0 },
  subtitle: { fontSize: '0.8rem', color: 'var(--muted)' },
  scoreRow: { display: 'flex', gap: '1rem', flexWrap: 'wrap' },
  scoreCard: { padding: '1rem 1.25rem', border: '1px solid var(--border)', borderRadius: '8px', minWidth: '140px', backgroundColor: 'var(--surface-2, var(--background))' },
  scoreLabel: { fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--muted)', letterSpacing: '0.05em', marginBottom: '0.4rem' },
  scoreValue: { fontSize: '1.5rem', fontWeight: 700 },
  gradeCircle: { display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 36, height: 36, borderRadius: '50%', fontSize: '1.1rem', fontWeight: 800 },
  innerTabs: { display: 'flex', gap: '0.25rem', borderBottom: '1px solid var(--border)', paddingBottom: 0, flexWrap: 'wrap' },
  innerTab: { padding: '0.4rem 0.875rem', border: 'none', background: 'transparent', cursor: 'pointer', fontSize: '0.8rem', color: 'var(--muted)', borderBottom: '2px solid transparent', marginBottom: '-1px' },
  innerTabActive: { color: 'var(--foreground)', borderBottom: '2px solid #2563eb', fontWeight: 500 },
  panel: { marginTop: '1rem' },
  sectionTitle: { fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.75rem' },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { textAlign: 'left', padding: '0.5rem 0.6rem', borderBottom: '1px solid var(--border)', fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--muted)', whiteSpace: 'nowrap' },
  td: { padding: '0.6rem 0.6rem', borderBottom: '1px solid var(--border)', fontSize: '0.8rem', verticalAlign: 'top' },
  emptyRow: { textAlign: 'center', padding: '2rem', color: 'var(--muted)', fontSize: '0.875rem' },
  errorBanner: { padding: '0.75rem 1rem', borderRadius: '6px', backgroundColor: 'rgba(239,68,68,0.08)', color: '#ef4444', fontSize: '0.8rem' },
  btn: { padding: '0.4rem 0.875rem', borderRadius: '6px', border: 'none', backgroundColor: '#2563eb', color: '#fff', cursor: 'pointer', fontSize: '0.8rem', whiteSpace: 'nowrap' },
  outlineBtn: { padding: '0.35rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'transparent', cursor: 'pointer', fontSize: '0.8rem' },
  dangerBtn: { padding: '0.35rem 0.75rem', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.4)', color: '#ef4444', background: 'transparent', cursor: 'pointer', fontSize: '0.8rem' },
  btnRow: { display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' },
  backdrop: { position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem', zIndex: 50 },
  modal: { background: 'var(--background, #fff)', borderRadius: '12px', padding: '1.5rem', width: '100%', maxWidth: '460px', display: 'flex', flexDirection: 'column', gap: '1rem', border: '1px solid var(--border)' },
  modalTitle: { fontSize: '1rem', fontWeight: 600 },
  field: { display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.78rem', color: 'var(--muted)' },
  input: { padding: '0.45rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '0.875rem', background: 'var(--background)', color: 'var(--foreground)' },
  modalActions: { display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.25rem' },
  driftItem: { padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border)', marginBottom: '0.5rem', display: 'flex', gap: '1rem', alignItems: 'flex-start' },
  checkRow: { display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.4rem 0', fontSize: '0.85rem' },
  evidenceRow: { padding: '0.5rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border)', marginBottom: '0.4rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  dimRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.45rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.85rem' },
  kvGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.5rem' },
  kvCard: { padding: '0.6rem 0.75rem', border: '1px solid var(--border)', borderRadius: '6px' },
  kvLabel: { fontSize: '0.68rem', textTransform: 'uppercase', color: 'var(--muted)', letterSpacing: '0.05em', marginBottom: '0.2rem' },
  kvValue: { fontSize: '0.875rem', fontWeight: 500, wordBreak: 'break-all' },
  timelineItem: { display: 'flex', gap: '0.75rem', padding: '0.5rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.82rem' },
  dot: { width: 8, height: 8, borderRadius: '50%', marginTop: 4, flexShrink: 0 },
};

// ── Risk score progress bar ────────────────────────────────────────────────────

function RiskBar({ score, band }: { score: number; band: string }) {
  const color = severityColor(band);
  return (
    <div style={{ marginBottom: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
        <span style={{ fontWeight: 600, fontSize: '1.25rem' }}>{score}<span style={{ fontSize: '0.8rem', color: 'var(--muted)' }}>/100</span></span>
        <span style={{ ...statusBadgeStyle(band) }}>{band}</span>
      </div>
      <div style={{ height: 8, borderRadius: 4, backgroundColor: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${score}%`, backgroundColor: color, borderRadius: 4, transition: 'width 0.4s' }} />
      </div>
    </div>
  );
}

// ── Sub-panels ────────────────────────────────────────────────────────────────

function ScorePanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<GovernanceScore | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getGovernanceScore(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <div style={s.scoreRow}>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Governance grade</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ ...s.gradeCircle, backgroundColor: gradeBg(data.grade), color: severityColor(data.grade === 'A' || data.grade === 'B' ? 'low' : data.grade === 'C' ? 'medium' : 'high') }}>
              {data.grade}
            </span>
            <span style={s.scoreValue}>{data.percent}%</span>
          </div>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Score</div>
          <div style={s.scoreValue}>{data.score}<span style={{ fontSize: '0.9rem', color: 'var(--muted)' }}>/{data.max_score}</span></div>
        </div>
      </div>
      <div style={{ marginTop: '1.25rem' }}>
        <div style={s.sectionTitle}>Dimension breakdown</div>
        {Object.entries(data.dimensions).map(([key, dim]) => (
          <div key={key} style={s.dimRow}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ color: dim.pass ? '#16a34a' : '#dc2626', fontWeight: 600 }}>{dim.pass ? '✓' : '✗'}</span>
              <span>{key.replace(/_/g, ' ')}</span>
            </span>
            <span style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>{String(dim.detail)}</span>
              <span style={{ fontSize: '0.75rem', fontWeight: 500 }}>{dim.weight} pts</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReadinessPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<IdentityReadiness | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getIdentityReadiness(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginBottom: '1.25rem' }}>
        <span style={statusBadgeStyle(data.ready ? 'ready' : 'not_configured')}>{data.ready ? 'Ready' : 'Not ready'}</span>
        <span style={{ fontSize: '0.85rem', color: 'var(--muted)' }}>Status: <strong>{data.status}</strong></span>
        {data.identity_mode && <span style={{ fontSize: '0.85rem', color: 'var(--muted)' }}>Mode: <strong>{data.identity_mode}</strong></span>}
      </div>
      <div style={{ marginBottom: '1.25rem' }}>
        <div style={s.sectionTitle}>Checks</div>
        {data.checks.map(c => (
          <div key={c.id} style={s.checkRow}>
            <span style={{ color: c.pass ? '#16a34a' : '#dc2626', fontWeight: 700, fontSize: '1rem' }}>{c.pass ? '✓' : '✗'}</span>
            <span>{c.id.replace(/_/g, ' ')}</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--muted)', marginLeft: 'auto' }}>{c.detail}</span>
          </div>
        ))}
      </div>
      {data.evidence.length > 0 && (
        <div>
          <div style={s.sectionTitle}>Evidence</div>
          {data.evidence.map(ev => (
            <div key={ev.id} style={s.evidenceRow}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: ev.pass ? '#16a34a' : '#dc2626', fontWeight: 700 }}>{ev.pass ? '✓' : '✗'}</span>
                <span style={{ fontSize: '0.82rem' }}>{ev.label}</span>
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--muted)' }}>{ev.source}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function DriftPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<DriftReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getDrift(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginBottom: '1.25rem' }}>
        <span style={statusBadgeStyle(data.drift_detected ? 'failed' : 'ready')}>
          {data.drift_detected ? 'Drift detected' : 'No drift'}
        </span>
        <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>Checked {fmt(data.checked_at)}</span>
      </div>
      {data.items.length === 0 ? (
        <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>Configuration is consistent — no drift items found.</p>
      ) : (
        data.items.map((item, i) => (
          <div key={i} style={{ ...s.driftItem, borderLeftColor: severityColor(item.severity), borderLeftWidth: 3 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.25rem' }}>
                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{item.type.replace(/_/g, ' ')}</span>
                <span style={{ fontSize: '0.7rem', fontWeight: 600, color: severityColor(item.severity), textTransform: 'uppercase' }}>{item.severity}</span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>{item.detail}</div>
              {item.error_code && <div style={{ fontSize: '0.75rem', color: '#dc2626', marginTop: '0.2rem' }}>Error: {item.error_code}</div>}
              {item.recommended_action && (
                <div style={{ fontSize: '0.75rem', marginTop: '0.35rem', display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                  <span style={{ color: '#2563eb', fontWeight: 600 }}>→</span>
                  <span style={{ color: 'var(--foreground)' }}>{item.recommended_action}</span>
                  {item.remediation_risk && (
                    <span style={{ fontSize: '0.7rem', color: severityColor(item.remediation_risk), fontWeight: 600, textTransform: 'uppercase' }}>
                      {item.remediation_risk} risk
                    </span>
                  )}
                </div>
              )}
            </div>
            {item.count !== undefined && (
              <span style={{ fontWeight: 700, fontSize: '1.1rem', color: severityColor(item.severity) }}>{item.count}</span>
            )}
          </div>
        ))
      )}
    </div>
  );
}

function RiskPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<IdentityRisk | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getIdentityRisk(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <RiskBar score={data.risk_score} band={data.risk_band} />
      <div style={{ fontSize: '0.75rem', color: 'var(--muted)', marginBottom: '1rem' }}>Assessed {fmt(data.assessed_at)}</div>
      {data.factors.length === 0 ? (
        <p style={{ color: '#16a34a', fontSize: '0.875rem' }}>No risk factors detected.</p>
      ) : (
        <>
          <div style={s.sectionTitle}>Risk factors</div>
          {data.factors.map((f, i) => (
            <div key={i} style={{ ...s.driftItem, borderLeftColor: severityColor(f.severity), borderLeftWidth: 3 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{f.factor.replace(/_/g, ' ')}</span>
                  <span style={{ fontSize: '0.7rem', color: severityColor(f.severity), textTransform: 'uppercase', fontWeight: 600 }}>{f.severity}</span>
                  {f.count !== undefined && <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>({f.count} items)</span>}
                </div>
              </div>
              <span style={{ fontWeight: 700, color: severityColor(f.severity) }}>+{f.points}</span>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function TimelinePanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<IdentityTimeline | null>(null);
  const [history, setHistory] = useState<ReadinessHistory | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([getIdentityTimeline(tenantId), getReadinessHistory(tenantId)]).then(([tl, rh]) => {
      if (tl.ok) setData(tl.data); else setError(tl.error);
      if (rh.ok) setHistory(rh.data);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;

  const typeColor = (t: string) => {
    if (t.includes('rejected') || t.includes('failed') || t.includes('failed')) return '#dc2626';
    if (t.includes('issued') || t.includes('bound') || t.includes('ready')) return '#16a34a';
    if (t.includes('started') || t.includes('pending')) return '#ca8a04';
    return '#6b7280';
  };

  return (
    <div>
      {history && history.transitions.length > 0 && (
        <div style={{ marginBottom: '1.5rem' }}>
          <div style={s.sectionTitle}>Readiness history</div>
          {history.transitions.map((t, i) => (
            <div key={i} style={s.timelineItem}>
              <span style={{ ...s.dot, backgroundColor: typeColor(t.event_type) }} />
              <div>
                <div style={{ fontWeight: 500 }}>{t.event_type.replace('tenant.identity_config.', '')}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>{fmt(t.occurred_at)}{t.reason_code ? ` — ${t.reason_code}` : ''}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      <div style={s.sectionTitle}>Identity audit timeline {data ? `(${data.count} events)` : ''}</div>
      {data && data.events.length === 0 && (
        <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>No audit events yet.</p>
      )}
      {data && data.events.map(ev => (
        <div key={ev.id} style={s.timelineItem}>
          <span style={{ ...s.dot, backgroundColor: typeColor(ev.event_type) }} />
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
              <span style={{ fontWeight: 500, fontSize: '0.82rem' }}>{ev.label || ev.event_type}</span>
              <span style={{ fontSize: '0.72rem', color: 'var(--muted)', whiteSpace: 'nowrap' }}>{fmt(ev.created_at)}</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--muted)', marginTop: '0.15rem' }}>
              {ev.affected_email && <span>{ev.affected_email} · </span>}
              {ev.identity_type && <span>{ev.identity_type} · </span>}
              {ev.reason_code && <span style={{ color: '#dc2626' }}>{ev.reason_code}</span>}
              <span style={{ opacity: 0.5 }}>{ev.event_type}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

interface InviteModalProps {
  tenantId: string;
  onClose: () => void;
  onCreated: () => void;
}

function InviteModal({ tenantId, onClose, onCreated }: InviteModalProps) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('user');
  const [identityType, setIdentityType] = useState('human');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!email.trim()) { setError('Email is required'); return; }
    setSubmitting(true); setError(null);
    const r = await createInvitation(tenantId, { email: email.trim(), role, identity_type: identityType });
    setSubmitting(false);
    if (r.ok) { onCreated(); onClose(); }
    else setError(r.error);
  };

  return (
    <div style={s.backdrop} onClick={onClose}>
      <div style={s.modal} onClick={e => e.stopPropagation()}>
        <div style={s.modalTitle}>New identity invitation</div>
        {error && <div style={s.errorBanner}>{error}</div>}
        <div style={s.field}>
          Email
          <input style={s.input} value={email} onChange={e => setEmail(e.target.value)} placeholder="user@company.com" autoFocus />
        </div>
        <div style={s.field}>
          Role
          <select style={s.input} value={role} onChange={e => setRole(e.target.value)}>
            <option value="user">User</option>
            <option value="admin">Admin</option>
            <option value="auditor">Auditor</option>
          </select>
        </div>
        <div style={s.field}>
          Identity type
          <select style={s.input} value={identityType} onChange={e => setIdentityType(e.target.value)}>
            <option value="human">Human</option>
            <option value="service">Service</option>
            <option value="agent">Agent</option>
            <option value="system">System</option>
            <option value="workload">Workload</option>
          </select>
        </div>
        <div style={s.modalActions}>
          <button style={s.outlineBtn} onClick={onClose} disabled={submitting}>Cancel</button>
          <button style={s.btn} onClick={submit} disabled={submitting}>{submitting ? 'Sending…' : 'Send invitation'}</button>
        </div>
      </div>
    </div>
  );
}

function InvitationsPanel({ tenantId }: { tenantId: string }) {
  const [invitations, setInvitations] = useState<IdentityInvitation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true); setError(null);
    listInvitations(tenantId).then(r => {
      if (r.ok) setInvitations(r.data.invitations); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleRevoke = async (id: string) => {
    const r = await revokeInvitation(id);
    if (r.ok) { setActionMsg('Invitation revoked.'); load(); }
    else setActionMsg(`Error: ${r.error}`);
  };

  const handleResend = async (id: string) => {
    const r = await resendInvitation(id);
    if (r.ok) { setActionMsg('Invitation resent.'); load(); }
    else setActionMsg(`Error: ${r.error}`);
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
        <div style={s.sectionTitle}>Invitations ({invitations.length})</div>
        <button style={s.btn} onClick={() => setShowModal(true)}>+ Invite</button>
      </div>
      {actionMsg && <div style={{ ...s.errorBanner, backgroundColor: actionMsg.startsWith('Error') ? undefined : 'rgba(34,197,94,0.08)', color: actionMsg.startsWith('Error') ? undefined : '#16a34a', marginBottom: '0.75rem' }}>{actionMsg}</div>}
      {error && <div style={s.errorBanner}>{error}</div>}
      {loading ? <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span> : (
        <div style={{ overflowX: 'auto' }}>
          <table style={s.table}>
            <thead>
              <tr>
                {['Email', 'Role', 'Identity type', 'Status', 'Mode', 'Expires', 'Actions'].map(h => (
                  <th key={h} style={s.th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {invitations.length === 0 && (
                <tr><td colSpan={7} style={s.emptyRow}>No invitations yet</td></tr>
              )}
              {invitations.map(inv => (
                <tr key={inv.id}>
                  <td style={s.td}>{inv.email}</td>
                  <td style={s.td}>{inv.role}</td>
                  <td style={s.td}>{inv.identity_mode_at_invite ?? '—'}</td>
                  <td style={s.td}><span style={statusBadgeStyle(inv.status)}>{inv.status}</span></td>
                  <td style={s.td}>{inv.identity_mode_at_invite ?? '—'}</td>
                  <td style={s.td}>{fmtShort(inv.expires_at)}</td>
                  <td style={{ ...s.td, display: 'flex', gap: '0.4rem' }}>
                    {(inv.status === 'pending' || inv.status === 'auth_started') && (
                      <button style={s.dangerBtn} onClick={() => handleRevoke(inv.id)}>Revoke</button>
                    )}
                    {(inv.status === 'failed' || inv.status === 'expired') && (
                      <button style={s.outlineBtn} onClick={() => handleResend(inv.id)}>Resend</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {showModal && <InviteModal tenantId={tenantId} onClose={() => setShowModal(false)} onCreated={load} />}
    </div>
  );
}

function ConfigPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<IdentityConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    getIdentityConfig(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data || !data.configured) return <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>No identity configuration has been provisioned for this tenant.</p>;

  const fields: Array<[string, string | boolean | null | undefined]> = [
    ['Identity mode', data.identity_mode ?? null],
    ['Provider', data.provider ?? null],
    ['Provisioning status', data.provisioning_status ?? null],
    ['Maturity level', data.maturity_level ?? null],
    ['SSO enforced', String(data.sso_enforced)],
    ['OIDC issuer', data.oidc_issuer ?? null],
    ['Auth0 org ID', data.auth0_organization_id ?? null],
    ['Auth0 connection ID', data.auth0_connection_id ?? null],
    ['Configured at', fmt(data.configured_at)],
    ['Updated at', fmt(data.updated_at)],
  ];

  return (
    <div>
      <div style={s.kvGrid}>
        {fields.map(([label, value]) => (
          <div key={label} style={s.kvCard}>
            <div style={s.kvLabel}>{label}</div>
            <div style={s.kvValue}>{value ?? '—'}</div>
          </div>
        ))}
      </div>
      {data.allowed_email_domains && data.allowed_email_domains.length > 0 && (
        <div style={{ marginTop: '1rem' }}>
          <div style={s.sectionTitle}>Allowed domains</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            {data.allowed_email_domains.map(d => (
              <span key={d} style={{ padding: '2px 10px', border: '1px solid var(--border)', borderRadius: '9999px', fontSize: '0.78rem' }}>{d}</span>
            ))}
          </div>
        </div>
      )}
      {data.providers && data.providers.length > 0 && (
        <div style={{ marginTop: '1rem' }}>
          <div style={s.sectionTitle}>Providers ({data.providers.length})</div>
          <table style={s.table}>
            <thead><tr>{['Provider', 'Issuer', 'Connection', 'Status', 'Primary'].map(h => <th key={h} style={s.th}>{h}</th>)}</tr></thead>
            <tbody>
              {data.providers.map(p => (
                <tr key={p.id}>
                  <td style={s.td}>{p.provider}</td>
                  <td style={s.td}>{p.oidc_issuer ?? '—'}</td>
                  <td style={s.td}>{p.connection_id ?? '—'}</td>
                  <td style={s.td}><span style={statusBadgeStyle(p.status)}>{p.status}</span></td>
                  <td style={s.td}>{p.is_primary ? '✓' : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data.domains && data.domains.length > 0 && (
        <div style={{ marginTop: '1rem' }}>
          <div style={s.sectionTitle}>Domains ({data.domains.length})</div>
          <table style={s.table}>
            <thead><tr>{['Domain', 'Type', 'Verification', 'Verified at'].map(h => <th key={h} style={s.th}>{h}</th>)}</tr></thead>
            <tbody>
              {data.domains.map(d => (
                <tr key={d.id}>
                  <td style={s.td}>{d.domain}</td>
                  <td style={s.td}>{d.domain_type}</td>
                  <td style={s.td}><span style={statusBadgeStyle(d.verification_status)}>{d.verification_status}</span></td>
                  <td style={s.td}>{fmtShort(d.verified_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AuditPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<AuditSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getAuditSummary(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <div style={s.scoreRow}>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Total events</div>
          <div style={s.scoreValue}>{data.total_events}</div>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Event types</div>
          <div style={s.scoreValue}>{Object.keys(data.by_type).length}</div>
        </div>
      </div>
      {Object.keys(data.by_type).length > 0 && (
        <div style={{ marginTop: '1rem', marginBottom: '1.25rem' }}>
          <div style={s.sectionTitle}>By event type</div>
          {Object.entries(data.by_type).sort(([, a], [, b]) => b - a).map(([type, count]) => (
            <div key={type} style={s.dimRow}>
              <span style={{ fontSize: '0.82rem' }}>{type}</span>
              <span style={{ fontWeight: 600 }}>{count}</span>
            </div>
          ))}
        </div>
      )}
      <div style={s.sectionTitle}>Recent events</div>
      {data.recent.length === 0 ? (
        <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>No events recorded yet.</p>
      ) : (
        <table style={s.table}>
          <thead><tr>{['Event type', 'Actor', 'Email', 'Reason', 'At'].map(h => <th key={h} style={s.th}>{h}</th>)}</tr></thead>
          <tbody>
            {data.recent.map(ev => (
              <tr key={ev.id}>
                <td style={s.td}>{ev.event_type}</td>
                <td style={s.td}>{ev.actor_user_id ?? '—'}</td>
                <td style={s.td}>{ev.affected_email ?? '—'}</td>
                <td style={{ ...s.td, color: ev.reason_code ? '#dc2626' : undefined }}>{ev.reason_code ?? '—'}</td>
                <td style={{ ...s.td, whiteSpace: 'nowrap' }}>{fmt(ev.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Identity Type Governance panel ────────────────────────────────────────────

function IdentityTypesPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<IdentityTypeGovernance | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getIdentityTypeGovernance(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  const allTypes = Object.keys(data.distribution).filter(t => data.distribution[t] > 0 || t !== 'unknown');

  return (
    <div>
      <div style={s.scoreRow}>
        {allTypes.map(t => (
          <div key={t} style={s.scoreCard}>
            <div style={s.scoreLabel}>{t}</div>
            <div style={s.scoreValue}>{data.distribution[t] ?? 0}</div>
          </div>
        ))}
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Total</div>
          <div style={s.scoreValue}>{data.total}</div>
        </div>
      </div>
      {Object.keys(data.risk_by_type).length > 0 && (
        <div style={{ marginTop: '1.5rem' }}>
          <div style={s.sectionTitle}>Risk by identity type</div>
          <table style={s.table}>
            <thead>
              <tr>
                {['Type', 'Total', 'Bound', 'Failed', 'Bind rate', 'Risk'].map(h => <th key={h} style={s.th}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.risk_by_type).map(([itype, r]) => (
                <tr key={itype}>
                  <td style={s.td}><strong>{itype}</strong></td>
                  <td style={s.td}>{r.total}</td>
                  <td style={{ ...s.td, color: '#16a34a' }}>{r.bound}</td>
                  <td style={{ ...s.td, color: r.failed > 0 ? '#dc2626' : undefined }}>{r.failed}</td>
                  <td style={s.td}>{r.bind_rate}%</td>
                  <td style={s.td}><span style={statusBadgeStyle(r.risk_band)}>{r.risk_band}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Session Provenance panel ───────────────────────────────────────────────────

function ProvenancePanel({ tenantId }: { tenantId: string }) {
  const [email, setEmail] = useState('');
  const [data, setData] = useState<ProvenanceResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const lookup = () => {
    if (!email.trim()) return;
    setLoading(true); setError(null); setData(null);
    getSessionProvenance(tenantId, { email: email.trim() }).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  };

  return (
    <div>
      <div style={{ ...s.btnRow, marginBottom: '1.25rem' }}>
        <input
          style={{ ...s.input, flex: 1 }}
          value={email}
          onChange={e => setEmail(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && lookup()}
          placeholder="user@company.com"
        />
        <button style={s.btn} onClick={lookup} disabled={loading || !email.trim()}>
          {loading ? 'Looking up…' : 'Look up'}
        </button>
      </div>
      {error && <div style={s.errorBanner}>{error}</div>}
      {data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={s.kvGrid}>
            {[
              ['Email', data.identity.email],
              ['Identity type', data.identity.identity_type],
              ['Binding status', data.identity.binding_status],
              ['Role', data.identity.role],
              ['Provider', data.provider],
              ['Bound at', fmt(data.binding_event_at)],
              ['Session authority', data.session_authority],
            ].map(([label, value]) => (
              <div key={label as string} style={s.kvCard}>
                <div style={s.kvLabel}>{label}</div>
                <div style={s.kvValue}>{value ?? '—'}</div>
              </div>
            ))}
          </div>
          {data.invitation_chain.length > 0 && (
            <div>
              <div style={s.sectionTitle}>Invitation chain</div>
              <table style={s.table}>
                <thead>
                  <tr>{['Status', 'Type', 'Provider', 'Created', 'Bound'].map(h => <th key={h} style={s.th}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {data.invitation_chain.map(inv => (
                    <tr key={inv.id}>
                      <td style={s.td}><span style={statusBadgeStyle(inv.status)}>{inv.status}</span></td>
                      <td style={s.td}>{inv.identity_type ?? '—'}</td>
                      <td style={s.td}>{inv.required_provider ?? '—'}</td>
                      <td style={s.td}>{fmtShort(inv.created_at)}</td>
                      <td style={s.td}>{fmtShort(inv.bound_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {data.audit_chain.length > 0 && (
            <div>
              <div style={s.sectionTitle}>Audit chain</div>
              {data.audit_chain.map((ev, i) => (
                <div key={i} style={s.timelineItem}>
                  <span style={{ ...s.dot, backgroundColor: ev.reason_code ? '#dc2626' : '#2563eb' }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
                      <span style={{ fontWeight: 500, fontSize: '0.82rem' }}>{ev.label}</span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--muted)', whiteSpace: 'nowrap' }}>{fmt(ev.created_at)}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--muted)', marginTop: '0.1rem' }}>
                      {ev.provider && <span>{ev.provider} · </span>}
                      {ev.reason_code && <span style={{ color: '#dc2626' }}>{ev.reason_code}</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Top scorecard summary ─────────────────────────────────────────────────────

function SummaryRow({ tenantId }: { tenantId: string }) {
  const [score, setScore] = useState<GovernanceScore | null>(null);
  const [risk, setRisk] = useState<IdentityRisk | null>(null);
  const [drift, setDrift] = useState<DriftReport | null>(null);

  useEffect(() => {
    getGovernanceScore(tenantId).then(r => r.ok && setScore(r.data));
    getIdentityRisk(tenantId).then(r => r.ok && setRisk(r.data));
    getDrift(tenantId).then(r => r.ok && setDrift(r.data));
  }, [tenantId]);

  return (
    <div style={s.scoreRow}>
      <div style={s.scoreCard}>
        <div style={s.scoreLabel}>Governance grade</div>
        {score ? (
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ ...s.gradeCircle, backgroundColor: gradeBg(score.grade), color: '#1e293b', fontSize: '0.95rem' }}>{score.grade}</span>
            <span style={{ fontSize: '1rem', fontWeight: 600 }}>{score.percent}%</span>
          </div>
        ) : <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>—</span>}
      </div>
      <div style={s.scoreCard}>
        <div style={s.scoreLabel}>Risk score</div>
        {risk ? (
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ fontSize: '1.25rem', fontWeight: 700, color: severityColor(risk.risk_band) }}>{risk.risk_score}</span>
            <span style={statusBadgeStyle(risk.risk_band)}>{risk.risk_band}</span>
          </div>
        ) : <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>—</span>}
      </div>
      <div style={s.scoreCard}>
        <div style={s.scoreLabel}>Drift</div>
        {drift ? (
          <span style={statusBadgeStyle(drift.drift_detected ? 'failed' : 'ready')}>
            {drift.drift_detected ? `${drift.items.length} item${drift.items.length !== 1 ? 's' : ''}` : 'None'}
          </span>
        ) : <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>—</span>}
      </div>
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

type InnerTab = 'scorecard' | 'readiness' | 'invitations' | 'drift' | 'risk' | 'timeline' | 'identity-types' | 'provenance' | 'config' | 'audit';

const INNER_TABS: Array<{ id: InnerTab; label: string }> = [
  { id: 'scorecard', label: 'Scorecard' },
  { id: 'readiness', label: 'Readiness' },
  { id: 'invitations', label: 'Invitations' },
  { id: 'drift', label: 'Drift' },
  { id: 'risk', label: 'Risk' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'identity-types', label: 'Identity Types' },
  { id: 'provenance', label: 'Provenance' },
  { id: 'config', label: 'Config' },
  { id: 'audit', label: 'Audit' },
];

export function IdentityGovernancePanel({ tenantId }: { tenantId: string }) {
  const [tab, setTab] = useState<InnerTab>('scorecard');

  return (
    <div style={s.root}>
      <div style={s.header}>
        <div style={s.headerLeft}>
          <h2 style={s.title}>Identity Governance Control Plane</h2>
          <span style={s.subtitle}>Tenant: <code style={{ fontSize: '0.78rem' }}>{tenantId}</code></span>
        </div>
      </div>

      <SummaryRow tenantId={tenantId} />

      <div style={s.innerTabs}>
        {INNER_TABS.map(t => (
          <button
            key={t.id}
            style={{ ...s.innerTab, ...(tab === t.id ? s.innerTabActive : {}) }}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div style={s.panel}>
        {tab === 'scorecard' && <ScorePanel tenantId={tenantId} />}
        {tab === 'readiness' && <ReadinessPanel tenantId={tenantId} />}
        {tab === 'invitations' && <InvitationsPanel tenantId={tenantId} />}
        {tab === 'drift' && <DriftPanel tenantId={tenantId} />}
        {tab === 'risk' && <RiskPanel tenantId={tenantId} />}
        {tab === 'timeline' && <TimelinePanel tenantId={tenantId} />}
        {tab === 'identity-types' && <IdentityTypesPanel tenantId={tenantId} />}
        {tab === 'provenance' && <ProvenancePanel tenantId={tenantId} />}
        {tab === 'config' && <ConfigPanel tenantId={tenantId} />}
        {tab === 'audit' && <AuditPanel tenantId={tenantId} />}
      </div>
    </div>
  );
}
