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
  getPolicyViolations,
  approveInvitation,
  rejectApproval,
  getApprovalQueue,
  takeGovernanceSnapshot,
  getGovernanceSnapshots,
  getRecommendations,
  getGovernanceTrend,
  getGovernanceForecast,
  getGovernanceSla,
  getGovernanceBenchmark,
  getGovernanceFindings,
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
  type PolicyViolationsReport,
  type ApprovalQueueResponse,
  type GovernanceSnapshotsReport,
  type RecommendationsReport,
  type GovernanceTrend,
  type GovernanceForecast,
  type GovernanceSlaReport,
  type GovernanceBenchmark,
  type GovernanceFindingsReport,
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
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

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

  const toggle = (key: string) =>
    setExpanded(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });

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
          <div key={key}>
            <div
              style={{ ...s.dimRow, cursor: dim.evidence && Object.keys(dim.evidence).length > 0 ? 'pointer' : 'default' }}
              onClick={() => dim.evidence && Object.keys(dim.evidence).length > 0 && toggle(key)}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: dim.pass ? '#16a34a' : '#dc2626', fontWeight: 600 }}>{dim.pass ? '✓' : '✗'}</span>
                <span>{key.replace(/_/g, ' ')}</span>
                {dim.evidence && Object.keys(dim.evidence).length > 0 && (
                  <span style={{ fontSize: '0.68rem', color: 'var(--muted)' }}>{expanded.has(key) ? '▲' : '▼'}</span>
                )}
              </span>
              <span style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>{String(dim.detail)}</span>
                <span style={{ fontSize: '0.75rem', fontWeight: 500 }}>{dim.weight} pts</span>
              </span>
            </div>
            {expanded.has(key) && dim.evidence && (
              <div style={{ padding: '0.5rem 0.75rem 0.75rem 1.5rem', display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                {Object.entries(dim.evidence).map(([ek, ev]) => (
                  <span key={ek} style={{ fontSize: '0.72rem', padding: '2px 8px', borderRadius: '4px', border: '1px solid var(--border)', backgroundColor: 'var(--surface-2, var(--background))' }}>
                    <span style={{ color: 'var(--muted)' }}>{ek}: </span><strong>{String(ev)}</strong>
                  </span>
                ))}
              </div>
            )}
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
                {['Email', 'Role', 'Type', 'Status', 'Approval', 'Expires', 'Actions'].map(h => (
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
                  <td style={s.td}>
                    {inv.approval_required
                      ? <span style={statusBadgeStyle(inv.approval_state === 'approved' ? 'ready' : inv.approval_state === 'rejected' ? 'failed' : 'pending')}>{inv.approval_state}</span>
                      : <span style={{ color: 'var(--muted)', fontSize: '0.75rem' }}>—</span>}
                  </td>
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

// ── Gap 1: Policy Violations ──────────────────────────────────────────────────

function PolicyViolationsPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<PolicyViolationsReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getPolicyViolations(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
        <span style={statusBadgeStyle(data.critical_count > 0 ? 'failed' : data.high_count > 0 ? 'auth_started' : 'ready')}>
          {data.violation_count === 0 ? 'No violations' : `${data.violation_count} violation${data.violation_count !== 1 ? 's' : ''}`}
        </span>
        {data.critical_count > 0 && <span style={{ fontSize: '0.75rem', color: '#dc2626', fontWeight: 600 }}>{data.critical_count} critical</span>}
        {data.high_count > 0 && <span style={{ fontSize: '0.75rem', color: '#ea580c', fontWeight: 600 }}>{data.high_count} high</span>}
      </div>
      {data.violations.length === 0 ? (
        <p style={{ color: '#16a34a', fontSize: '0.875rem' }}>All policy rules are satisfied.</p>
      ) : (
        data.violations.map((v, i) => (
          <div key={i} style={{ ...s.driftItem, borderLeftColor: severityColor(v.severity), borderLeftWidth: 3 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.2rem', flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{v.rule_id.replace(/_/g, ' ')}</span>
                <span style={{ fontSize: '0.7rem', color: severityColor(v.severity), textTransform: 'uppercase', fontWeight: 600 }}>{v.severity}</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--muted)' }}>{v.category}</span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--muted)', marginBottom: '0.2rem' }}>{v.description}</div>
              <div style={{ fontSize: '0.78rem' }}>{v.detail}</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--muted)', marginTop: '0.2rem' }}>{v.affected_email}</div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

// ── Gap 2: Approval Queue ─────────────────────────────────────────────────────

function ApprovalQueuePanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<ApprovalQueueResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true); setError(null);
    getApprovalQueue(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleApprove = async (id: string) => {
    const r = await approveInvitation(id, {});
    if (r.ok) { setActionMsg('Approved.'); load(); } else setActionMsg(`Error: ${r.error}`);
  };

  const handleReject = async (id: string) => {
    const reason = window.prompt('Rejection reason (optional):') ?? undefined;
    const r = await rejectApproval(id, { reason });
    if (r.ok) { setActionMsg('Rejected.'); load(); } else setActionMsg(`Error: ${r.error}`);
  };

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
        <div style={s.sectionTitle}>Pending approvals ({data.pending_count})</div>
      </div>
      {actionMsg && (
        <div style={{ ...s.errorBanner, backgroundColor: actionMsg.startsWith('Error') ? undefined : 'rgba(34,197,94,0.08)', color: actionMsg.startsWith('Error') ? undefined : '#16a34a', marginBottom: '0.75rem' }}>
          {actionMsg}
        </div>
      )}
      {data.items.length === 0 ? (
        <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>No pending approvals.</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={s.table}>
            <thead>
              <tr>{['Email', 'Role', 'Type', 'Status', 'Created', 'Actions'].map(h => <th key={h} style={s.th}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {data.items.map(inv => (
                <tr key={inv.id}>
                  <td style={s.td}>{inv.email}</td>
                  <td style={s.td}>{inv.role}</td>
                  <td style={s.td}>{inv.identity_mode_at_invite ?? '—'}</td>
                  <td style={s.td}><span style={statusBadgeStyle(inv.status)}>{inv.status}</span></td>
                  <td style={s.td}>{fmtShort(inv.created_at)}</td>
                  <td style={{ ...s.td, display: 'flex', gap: '0.4rem' }}>
                    <button style={s.btn} onClick={() => handleApprove(inv.id)}>Approve</button>
                    <button style={s.dangerBtn} onClick={() => handleReject(inv.id)}>Reject</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Gap 4: Governance Snapshots ───────────────────────────────────────────────

function SnapshotsPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<GovernanceSnapshotsReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [snapping, setSnapping] = useState(false);
  const [snapMsg, setSnapMsg] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    getGovernanceSnapshots(tenantId, 90).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleSnapshot = async () => {
    setSnapping(true); setSnapMsg(null);
    const r = await takeGovernanceSnapshot(tenantId);
    setSnapping(false);
    if (r.ok) { setSnapMsg('Snapshot recorded.'); load(); } else setSnapMsg(`Error: ${r.error}`);
  };

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
        <div style={s.sectionTitle}>Governance snapshots — last 90 days {data ? `(${data.snapshot_count})` : ''}</div>
        <button style={s.btn} onClick={handleSnapshot} disabled={snapping}>{snapping ? 'Capturing…' : 'Capture now'}</button>
      </div>
      {snapMsg && (
        <div style={{ ...s.errorBanner, backgroundColor: snapMsg.startsWith('Error') ? undefined : 'rgba(34,197,94,0.08)', color: snapMsg.startsWith('Error') ? undefined : '#16a34a', marginBottom: '0.75rem' }}>
          {snapMsg}
        </div>
      )}
      {data && data.score_delta_pct !== null && (
        <div style={{ marginBottom: '0.75rem', fontSize: '0.82rem' }}>
          Score trend over period:&nbsp;
          <strong style={{ color: data.score_delta_pct >= 0 ? '#16a34a' : '#dc2626' }}>
            {data.score_delta_pct >= 0 ? '+' : ''}{data.score_delta_pct}%
          </strong>
        </div>
      )}
      {!data || data.snapshots.length === 0 ? (
        <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>No snapshots yet. Capture one to start tracking posture over time.</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={s.table}>
            <thead>
              <tr>{['Date', 'Grade', 'Score', 'Percent', 'Passing dims'].map(h => <th key={h} style={s.th}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {data.snapshots.map(snap => {
                const passing = Object.values(snap.dimensions).filter(d => d.pass).length;
                const total = Object.keys(snap.dimensions).length;
                return (
                  <tr key={snap.snapshot_id}>
                    <td style={s.td}>{fmt(snap.created_at)}</td>
                    <td style={s.td}><span style={{ ...s.gradeCircle, width: 28, height: 28, fontSize: '0.85rem', backgroundColor: gradeBg(snap.grade) }}>{snap.grade}</span></td>
                    <td style={s.td}>{snap.score}/{snap.max_score}</td>
                    <td style={s.td}>{snap.percent}%</td>
                    <td style={s.td}>{passing}/{total}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Gap 5: Recommendations Engine ────────────────────────────────────────────

function RecommendationsPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<RecommendationsReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getRecommendations(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  return (
    <div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Current grade</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ ...s.gradeCircle, backgroundColor: gradeBg(data.current_grade) }}>{data.current_grade}</span>
            <span style={{ fontWeight: 600 }}>{data.current_percent}%</span>
          </div>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Projected (if all applied)</div>
          <span style={{ fontSize: '1.25rem', fontWeight: 700, color: '#16a34a' }}>{data.projected_percent_if_all_applied}%</span>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Score gain available</div>
          <span style={{ fontSize: '1.25rem', fontWeight: 700 }}>+{data.total_expected_score_gain} pts</span>
        </div>
      </div>
      {data.recommendations.length === 0 ? (
        <p style={{ color: '#16a34a', fontSize: '0.875rem' }}>All governance dimensions are passing — no recommendations at this time.</p>
      ) : (
        data.recommendations.map((rec, i) => (
          <div key={i} style={{ ...s.driftItem, borderLeftColor: severityColor(rec.risk_reduction === 'critical' ? 'critical' : rec.risk_reduction === 'high' ? 'high' : rec.risk_reduction === 'medium' ? 'medium' : 'low'), borderLeftWidth: 3 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.2rem', flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>#{i + 1} {rec.action}</span>
                <span style={{ fontSize: '0.7rem', color: severityColor(rec.risk_reduction as string), textTransform: 'uppercase', fontWeight: 600 }}>{rec.risk_reduction} risk</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--muted)' }}>{rec.category}</span>
              </div>
              {rec.detail && <div style={{ fontSize: '0.78rem', color: 'var(--muted)', marginBottom: '0.2rem' }}>{rec.detail}</div>}
              <div style={{ fontSize: '0.75rem' }}>
                Dimension: <code style={{ fontSize: '0.72rem' }}>{rec.dimension}</code>
              </div>
            </div>
            <span style={{ fontWeight: 700, color: '#16a34a', fontSize: '0.9rem', whiteSpace: 'nowrap' }}>+{rec.expected_score_gain} pts</span>
          </div>
        ))
      )}
    </div>
  );
}

// ── Gap A: Governance Trend Analytics ────────────────────────────────────────

function TrendPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<GovernanceTrend | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getGovernanceTrend(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  if (!data.has_trend) return (
    <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>{data.message ?? 'Capture more snapshots to see trend analysis.'}</p>
  );

  const deltaColor = (data.percent_delta ?? 0) >= 0 ? '#16a34a' : '#dc2626';

  return (
    <div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Grade change</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1rem', fontWeight: 700 }}>
            <span style={{ ...s.gradeCircle, width: 28, height: 28, fontSize: '0.85rem', backgroundColor: gradeBg(data.grade_from!) }}>{data.grade_from}</span>
            <span style={{ color: 'var(--muted)' }}>→</span>
            <span style={{ ...s.gradeCircle, width: 28, height: 28, fontSize: '0.85rem', backgroundColor: gradeBg(data.grade_to!) }}>{data.grade_to}</span>
          </div>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Score delta</div>
          <span style={{ fontSize: '1.25rem', fontWeight: 700, color: deltaColor }}>
            {(data.percent_delta ?? 0) >= 0 ? '+' : ''}{data.percent_delta}%
          </span>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Period</div>
          <span style={{ fontSize: '0.75rem' }}>{fmtShort(data.period_start)} → {fmtShort(data.period_end)}</span>
        </div>
      </div>

      {data.narrative.length > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={s.sectionTitle}>Why it changed</div>
          {data.narrative.map((n, i) => (
            <div key={i} style={{ padding: '0.6rem 0.75rem', borderLeft: '3px solid #2563eb', marginBottom: '0.5rem', fontSize: '0.85rem', backgroundColor: 'rgba(37,99,235,0.04)', borderRadius: '0 4px 4px 0' }}>
              {n}
            </div>
          ))}
        </div>
      )}

      {data.degraded.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ ...s.sectionTitle, color: '#dc2626' }}>Degraded ({data.degraded.length})</div>
          {data.degraded.map((d, i) => (
            <div key={i} style={s.dimRow}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: '#dc2626', fontWeight: 700 }}>↓</span>
                <span>{d.label}</span>
              </span>
              <span style={{ color: '#dc2626', fontWeight: 600, fontSize: '0.8rem' }}>{d.score_impact} pts</span>
            </div>
          ))}
        </div>
      )}

      {data.improved.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ ...s.sectionTitle, color: '#16a34a' }}>Improved ({data.improved.length})</div>
          {data.improved.map((d, i) => (
            <div key={i} style={s.dimRow}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: '#16a34a', fontWeight: 700 }}>↑</span>
                <span>{d.label}</span>
              </span>
              <span style={{ color: '#16a34a', fontWeight: 600, fontSize: '0.8rem' }}>+{d.score_impact} pts</span>
            </div>
          ))}
        </div>
      )}

      {data.stable_failing.length > 0 && (
        <div>
          <div style={{ ...s.sectionTitle, color: 'var(--muted)' }}>Persistently failing ({data.stable_failing.length})</div>
          {data.stable_failing.map((d, i) => (
            <div key={i} style={s.dimRow}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: '#6b7280' }}>—</span>
                <span style={{ color: 'var(--muted)' }}>{d.label}</span>
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>{d.score_impact} pts</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Gap B: Governance Forecasting ────────────────────────────────────────────

function ForecastPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<GovernanceForecast | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getGovernanceForecast(tenantId, 30).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  if (!data.has_forecast) return (
    <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>{data.message ?? 'Capture more snapshots to enable forecasting.'}</p>
  );

  const trendColor = data.trend_direction === 'declining' ? '#dc2626' : data.trend_direction === 'improving' ? '#16a34a' : '#ca8a04';
  const projectedDelta = (data.projected_percent ?? 0) - (data.current_percent ?? 0);

  return (
    <div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Current</div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ ...s.gradeCircle, width: 28, height: 28, fontSize: '0.85rem', backgroundColor: gradeBg(data.current_grade!) }}>{data.current_grade}</span>
            <span style={{ fontWeight: 600 }}>{data.current_percent}%</span>
          </div>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Projected in {data.forecast_days}d</div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ ...s.gradeCircle, width: 28, height: 28, fontSize: '0.85rem', backgroundColor: gradeBg(data.projected_grade!) }}>{data.projected_grade}</span>
            <span style={{ fontWeight: 600 }}>{data.projected_percent}%</span>
          </div>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Trend</div>
          <span style={{ fontWeight: 700, color: trendColor, textTransform: 'capitalize' }}>{data.trend_direction}</span>
        </div>
        <div style={s.scoreCard}>
          <div style={s.scoreLabel}>Expected change</div>
          <span style={{ fontWeight: 700, color: projectedDelta >= 0 ? '#16a34a' : '#dc2626' }}>
            {projectedDelta >= 0 ? '+' : ''}{projectedDelta.toFixed(1)}%
          </span>
        </div>
      </div>

      {data.at_risk_dimensions.length > 0 && (
        <div>
          <div style={s.sectionTitle}>Dimensions driving decline</div>
          {data.at_risk_dimensions.map((d, i) => (
            <div key={i} style={{ ...s.driftItem, borderLeftColor: d.trend === 'worsening' ? '#dc2626' : '#ca8a04', borderLeftWidth: 3 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{d.label}</span>
                  <span style={{ fontSize: '0.7rem', textTransform: 'uppercase', fontWeight: 600, color: d.trend === 'worsening' ? '#dc2626' : '#ca8a04' }}>{d.trend}</span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--muted)', marginTop: '0.15rem' }}>Failing in {d.fail_rate_pct}% of snapshots</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Gap C: Governance SLA Tracking ───────────────────────────────────────────

function SlaPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<GovernanceSlaReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getGovernanceSla(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  const slaColor = (status: string) =>
    status === 'breached' ? '#dc2626' : status === 'at_risk' ? '#ca8a04' : status === 'on_track' ? '#16a34a' : '#6b7280';

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        <span style={statusBadgeStyle(data.breached_count > 0 ? 'failed' : data.at_risk_count > 0 ? 'pending' : 'ready')}>
          {data.total_open_items === 0 ? 'No open items' : `${data.total_open_items} open`}
        </span>
        {data.breached_count > 0 && <span style={{ fontSize: '0.75rem', color: '#dc2626', fontWeight: 600 }}>{data.breached_count} SLA breached</span>}
        {data.at_risk_count > 0 && <span style={{ fontSize: '0.75rem', color: '#ca8a04', fontWeight: 600 }}>{data.at_risk_count} at risk</span>}
      </div>
      {data.items.length === 0 ? (
        <p style={{ color: '#16a34a', fontSize: '0.875rem' }}>All governance SLAs are on track.</p>
      ) : (
        data.items.map((item, i) => (
          <div key={i} style={{ ...s.driftItem, borderLeftColor: slaColor(item.sla_status), borderLeftWidth: 3 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.2rem', flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{item.title}</span>
                <span style={{ fontSize: '0.7rem', color: severityColor(item.severity), textTransform: 'uppercase', fontWeight: 600 }}>{item.severity}</span>
                <span style={{ fontSize: '0.7rem', padding: '1px 6px', borderRadius: '9999px', backgroundColor: slaColor(item.sla_status) + '22', color: slaColor(item.sla_status), fontWeight: 600 }}>
                  {item.sla_status.replace('_', ' ')}
                </span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>{item.detail}</div>
            </div>
            <div style={{ textAlign: 'right', minWidth: '80px' }}>
              <div style={{ fontWeight: 700, fontSize: '1rem', color: slaColor(item.sla_status) }}>
                {item.days_open !== null ? `${item.days_open}d` : '—'}
              </div>
              <div style={{ fontSize: '0.68rem', color: 'var(--muted)' }}>SLA: {item.sla_days}d</div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

// ── Gap D: Cross-Tenant Benchmarking ─────────────────────────────────────────

function BenchmarkPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<GovernanceBenchmark | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getGovernanceBenchmark(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  if (!data.has_benchmark) return (
    <div>
      <p style={{ color: 'var(--muted)', fontSize: '0.875rem', marginBottom: '0.5rem' }}>{data.message ?? 'No benchmark data available.'}</p>
      <p style={{ color: 'var(--muted)', fontSize: '0.78rem' }}>Capture governance snapshots to participate in anonymized benchmarking.</p>
    </div>
  );

  const own = data.own_score;
  const bm = data.benchmark;

  const barWidth = (v: number | null | undefined) => v != null ? `${Math.min(100, v)}%` : '0%';

  return (
    <div>
      <div style={{ marginBottom: '1.5rem', fontSize: '0.75rem', color: 'var(--muted)' }}>
        Based on {data.participating_tenants} participating tenant{data.participating_tenants !== 1 ? 's' : ''} · {bm?.description}
      </div>

      {own && (
        <div style={{ marginBottom: '1.5rem' }}>
          <div style={s.sectionTitle}>Your position</div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            <div style={s.scoreCard}>
              <div style={s.scoreLabel}>Your score</div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                {own.grade && <span style={{ ...s.gradeCircle, width: 28, height: 28, fontSize: '0.85rem', backgroundColor: gradeBg(own.grade) }}>{own.grade}</span>}
                <span style={{ fontWeight: 600, fontSize: '1rem' }}>{own.percent}%</span>
              </div>
            </div>
            <div style={s.scoreCard}>
              <div style={s.scoreLabel}>Percentile rank</div>
              <span style={{ fontSize: '1.25rem', fontWeight: 700, color: (own.percentile_rank ?? 0) >= 75 ? '#16a34a' : (own.percentile_rank ?? 0) >= 50 ? '#2563eb' : '#ca8a04' }}>
                {own.percentile_rank != null ? `${own.percentile_rank}th` : '—'}
              </span>
            </div>
          </div>
        </div>
      )}

      {bm && (
        <div>
          <div style={s.sectionTitle}>Industry distribution</div>
          {[
            { label: 'Top 10% (p90)', value: bm.p90, color: '#16a34a' },
            { label: 'Top quartile (p75)', value: bm.p75, color: '#2563eb' },
            { label: 'Median (p50)', value: bm.median, color: '#ca8a04' },
            { label: 'Bottom quartile (p25)', value: bm.p25, color: '#6b7280' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ marginBottom: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem', fontSize: '0.78rem' }}>
                <span style={{ color: 'var(--muted)' }}>{label}</span>
                <span style={{ fontWeight: 600 }}>{value}%</span>
              </div>
              <div style={{ height: 6, borderRadius: 3, backgroundColor: 'var(--border)', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: barWidth(value), backgroundColor: color, borderRadius: 3 }} />
              </div>
              {own?.percent != null && Math.abs(own.percent - value) < 3 && (
                <div style={{ fontSize: '0.68rem', color, marginTop: '0.1rem' }}>← your score is near this threshold</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Gap E: Governance Findings ────────────────────────────────────────────────

function FindingsPanel({ tenantId }: { tenantId: string }) {
  const [data, setData] = useState<GovernanceFindingsReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    setLoading(true);
    getGovernanceFindings(tenantId).then(r => {
      if (r.ok) setData(r.data); else setError(r.error);
      setLoading(false);
    });
  }, [tenantId]);

  if (loading) return <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Loading…</span>;
  if (error) return <div style={s.errorBanner}>{error}</div>;
  if (!data) return null;

  const toggle = (id: string) =>
    setExpanded(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const typeColor = (t: string) => t === 'policy_violation' ? '#dc2626' : t === 'risk' ? '#ea580c' : '#ca8a04';
  const typeLabel = (t: string) => t === 'policy_violation' ? 'Violation' : t === 'risk' ? 'Risk' : 'Drift';

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        <span style={statusBadgeStyle(data.critical_count > 0 ? 'failed' : data.high_count > 0 ? 'auth_started' : 'ready')}>
          {data.finding_count === 0 ? 'Clean' : `${data.finding_count} finding${data.finding_count !== 1 ? 's' : ''}`}
        </span>
        {data.critical_count > 0 && <span style={{ fontSize: '0.75rem', color: '#dc2626', fontWeight: 600 }}>{data.critical_count} critical</span>}
        {data.high_count > 0 && <span style={{ fontSize: '0.75rem', color: '#ea580c', fontWeight: 600 }}>{data.high_count} high</span>}
        <span style={{ fontSize: '0.75rem', color: 'var(--muted)', marginLeft: 'auto' }}>
          Score: {data.governance_score}pts · {data.governance_percent}% · {data.governance_grade}
        </span>
      </div>

      {data.findings.length === 0 ? (
        <p style={{ color: '#16a34a', fontSize: '0.875rem' }}>No governance findings. All risk, violation, and drift checks are passing.</p>
      ) : (
        data.findings.map(f => (
          <div key={f.finding_id} style={{ ...s.driftItem, borderLeftColor: severityColor(f.severity), borderLeftWidth: 3, cursor: 'pointer' }} onClick={() => toggle(f.finding_id)}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.2rem', flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{f.title}</span>
                <span style={{ fontSize: '0.68rem', padding: '1px 6px', borderRadius: '4px', backgroundColor: typeColor(f.type) + '22', color: typeColor(f.type), fontWeight: 600 }}>
                  {typeLabel(f.type)}
                </span>
                <span style={{ fontSize: '0.7rem', color: severityColor(f.severity), textTransform: 'uppercase', fontWeight: 600 }}>{f.severity}</span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>{f.detail}</div>
              {expanded.has(f.finding_id) && Object.keys(f.evidence).length > 0 && (
                <div style={{ marginTop: '0.6rem', display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {Object.entries(f.evidence).map(([k, v]) => (
                    <span key={k} style={{ fontSize: '0.7rem', padding: '2px 7px', borderRadius: '4px', border: '1px solid var(--border)', backgroundColor: 'var(--surface-2, var(--background))' }}>
                      <span style={{ color: 'var(--muted)' }}>{k}: </span><strong>{String(v)}</strong>
                    </span>
                  ))}
                </div>
              )}
              <div style={{ marginTop: '0.35rem', display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                {f.sources.map(src => (
                  <span key={src} style={{ fontSize: '0.65rem', padding: '1px 5px', borderRadius: '3px', backgroundColor: 'var(--border)', color: 'var(--muted)' }}>{src.replace('_', ' ')}</span>
                ))}
              </div>
            </div>
            <span style={{ fontSize: '0.68rem', color: 'var(--muted)', flexShrink: 0 }}>{expanded.has(f.finding_id) ? '▲' : '▼'}</span>
          </div>
        ))
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

// ── ActionsLedgerPanel ────────────────────────────────────────────────────────

import {
  recordGovernanceAction,
  getGovernanceActionSummary,
  listGovernanceActions,
  type GovernanceActionSummary,
  type GovernanceActionsLedger,
  type RecordGovernanceActionPayload,
} from '@/lib/identityApi';

const STATE_COLORS: Record<string, string> = {
  accepted: '#2563eb',
  deferred: '#ca8a04',
  rejected: '#6b7280',
  implemented: '#16a34a',
  unaddressed: '#9ca3af',
};

function ActionStateBadge({ state }: { state: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4,
      fontSize: '0.72rem', fontWeight: 600, letterSpacing: '0.03em',
      background: STATE_COLORS[state] ? `${STATE_COLORS[state]}22` : '#f3f4f6',
      color: STATE_COLORS[state] ?? '#6b7280',
      border: `1px solid ${STATE_COLORS[state] ?? '#d1d5db'}`,
    }}>
      {state.toUpperCase()}
    </span>
  );
}

function ActionsLedgerPanel({ tenantId }: { tenantId: string }) {
  const [summary, setSummary] = useState<GovernanceActionSummary | null>(null);
  const [ledger, setLedger] = useState<GovernanceActionsLedger | null>(null);
  const [loading, setLoading] = useState(true);
  const [showLedger, setShowLedger] = useState(false);
  const [recordingDim, setRecordingDim] = useState<string | null>(null);
  const [form, setForm] = useState<RecordGovernanceActionPayload>({
    dimension: '', action_state: 'accepted',
  });
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const [s, l] = await Promise.all([
      getGovernanceActionSummary(tenantId),
      listGovernanceActions(tenantId, { limit: 200 }),
    ]);
    if (s.ok) setSummary(s.data);
    if (l.ok) setLedger(l.data);
    setLoading(false);
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const openRecord = (dim: string, currentState: string) => {
    setRecordingDim(dim);
    setFormError(null);
    const nextStates: Record<string, string[]> = {
      unaddressed: ['accepted', 'rejected', 'deferred'],
      accepted: ['implemented', 'deferred'],
      deferred: ['accepted', 'rejected'],
    };
    const allowed = nextStates[currentState] ?? [];
    setForm({
      dimension: dim,
      action_state: (allowed[0] ?? 'accepted') as RecordGovernanceActionPayload['action_state'],
    });
  };

  const submitRecord = async () => {
    setSubmitting(true);
    setFormError(null);
    const r = await recordGovernanceAction(tenantId, form);
    setSubmitting(false);
    if (!r.ok) { setFormError(r.error); return; }
    setRecordingDim(null);
    load();
  };

  if (loading) return <div style={{ padding: 24, color: 'var(--muted)' }}>Loading…</div>;

  const counts = summary ? [
    { label: 'Implemented', value: summary.implemented, color: '#16a34a' },
    { label: 'Accepted', value: summary.accepted, color: '#2563eb' },
    { label: 'Deferred', value: summary.deferred, color: '#ca8a04' },
    { label: 'Rejected', value: summary.rejected, color: '#6b7280' },
    { label: 'Unaddressed', value: summary.unaddressed, color: '#9ca3af' },
  ] : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Summary row */}
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {counts.map(c => (
          <div key={c.label} style={{
            background: `${c.color}11`, border: `1px solid ${c.color}44`,
            borderRadius: 8, padding: '8px 14px', minWidth: 90, textAlign: 'center',
          }}>
            <div style={{ fontSize: '1.4rem', fontWeight: 700, color: c.color }}>{c.value}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--muted)' }}>{c.label}</div>
          </div>
        ))}
      </div>

      {/* Dimension table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Dimension', 'Recommendation', 'State', 'Actor', 'Reason / Outcome', 'Decided', ''].map(h => (
                <th key={h} style={{ padding: '6px 8px', textAlign: 'left', color: 'var(--muted)', fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(summary?.dimensions ?? []).map(d => (
              <tr key={d.dimension} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '6px 8px', fontFamily: 'monospace', fontSize: '0.78rem', whiteSpace: 'nowrap' }}>{d.dimension}</td>
                <td style={{ padding: '6px 8px', maxWidth: 240, color: 'var(--muted)' }}>{d.recommendation_action}</td>
                <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}><ActionStateBadge state={d.current_state} /></td>
                <td style={{ padding: '6px 8px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>{d.actor_email ?? '—'}</td>
                <td style={{ padding: '6px 8px', color: 'var(--muted)', maxWidth: 200 }}>
                  {d.reason ? <span title={d.outcome ?? undefined}>{d.reason}</span> : '—'}
                  {d.deferred_until && <span style={{ marginLeft: 4, color: '#ca8a04' }}>until {d.deferred_until}</span>}
                </td>
                <td style={{ padding: '6px 8px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>{d.decided_at ? fmtShort(d.decided_at) : '—'}</td>
                <td style={{ padding: '6px 8px' }}>
                  {!d.is_terminal && (
                    <button
                      style={{ fontSize: '0.72rem', padding: '2px 8px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface)', cursor: 'pointer' }}
                      onClick={() => openRecord(d.dimension, d.current_state)}
                    >
                      Record
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Record action modal */}
      {recordingDim && (
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 480 }}>
          <div style={{ fontWeight: 600 }}>Record decision: <code style={{ fontSize: '0.82rem' }}>{recordingDim}</code></div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {[
              { label: 'Decision', field: 'action_state', type: 'select', options: ['accepted', 'rejected', 'deferred', 'implemented'] },
              { label: 'Actor email', field: 'actor_email', type: 'text' },
              { label: 'Actor role', field: 'actor_role', type: 'text' },
              { label: 'Reason (why)', field: 'reason', type: 'text' },
              { label: 'Outcome (what happened)', field: 'outcome', type: 'text' },
              { label: 'Defer until (YYYY-MM-DD)', field: 'deferred_until', type: 'text' },
            ].map(({ label, field, type, options }) => (
              <label key={field} style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: '0.8rem' }}>
                <span style={{ color: 'var(--muted)' }}>{label}</span>
                {type === 'select' ? (
                  <select
                    value={(form as unknown as Record<string, string>)[field] ?? ''}
                    onChange={e => setForm(f => ({ ...f, [field]: e.target.value }))}
                    style={{ padding: '4px 8px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface)' }}
                  >
                    {(options ?? []).map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                ) : (
                  <input
                    value={(form as unknown as Record<string, string>)[field] ?? ''}
                    onChange={e => setForm(f => ({ ...f, [field]: e.target.value || undefined }))}
                    style={{ padding: '4px 8px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface)' }}
                  />
                )}
              </label>
            ))}
          </div>
          {formError && <div style={{ color: '#dc2626', fontSize: '0.8rem' }}>{formError}</div>}
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={submitRecord}
              disabled={submitting}
              style={{ padding: '6px 14px', borderRadius: 4, background: '#2563eb', color: '#fff', border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: '0.82rem' }}
            >
              {submitting ? 'Saving…' : 'Save decision'}
            </button>
            <button
              onClick={() => setRecordingDim(null)}
              style={{ padding: '6px 14px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface)', cursor: 'pointer', fontSize: '0.82rem' }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Full audit ledger toggle */}
      <div>
        <button
          onClick={() => setShowLedger(v => !v)}
          style={{ fontSize: '0.8rem', padding: '4px 10px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--surface)', cursor: 'pointer' }}
        >
          {showLedger ? 'Hide' : 'Show'} full audit ledger ({ledger?.total ?? 0} entries)
        </button>
        {showLedger && ledger && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem', marginTop: 8 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['When', 'Dimension', 'Decision', 'Actor', 'Reason', 'Outcome'].map(h => (
                  <th key={h} style={{ padding: '5px 8px', textAlign: 'left', color: 'var(--muted)', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ledger.actions.map(a => (
                <tr key={a.action_id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '5px 8px', whiteSpace: 'nowrap', color: 'var(--muted)' }}>{fmtShort(a.created_at)}</td>
                  <td style={{ padding: '5px 8px', fontFamily: 'monospace' }}>{a.dimension}</td>
                  <td style={{ padding: '5px 8px' }}><ActionStateBadge state={a.action_state} /></td>
                  <td style={{ padding: '5px 8px', color: 'var(--muted)' }}>{a.actor_email ?? '—'}</td>
                  <td style={{ padding: '5px 8px', color: 'var(--muted)' }}>{a.reason ?? '—'}</td>
                  <td style={{ padding: '5px 8px', color: 'var(--muted)' }}>{a.outcome ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

type InnerTab = 'scorecard' | 'readiness' | 'invitations' | 'drift' | 'risk' | 'timeline' | 'identity-types' | 'provenance' | 'config' | 'audit' | 'violations' | 'approvals' | 'snapshots' | 'recommendations' | 'trend' | 'forecast' | 'sla' | 'benchmark' | 'findings' | 'actions';

const INNER_TABS: Array<{ id: InnerTab; label: string }> = [
  { id: 'findings', label: 'Findings' },
  { id: 'actions', label: 'Actions Ledger' },
  { id: 'scorecard', label: 'Scorecard' },
  { id: 'violations', label: 'Violations' },
  { id: 'sla', label: 'SLA' },
  { id: 'approvals', label: 'Approvals' },
  { id: 'recommendations', label: 'Recommendations' },
  { id: 'trend', label: 'Trend' },
  { id: 'forecast', label: 'Forecast' },
  { id: 'benchmark', label: 'Benchmark' },
  { id: 'snapshots', label: 'Snapshots' },
  { id: 'risk', label: 'Risk' },
  { id: 'drift', label: 'Drift' },
  { id: 'readiness', label: 'Readiness' },
  { id: 'invitations', label: 'Invitations' },
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
        {tab === 'violations' && <PolicyViolationsPanel tenantId={tenantId} />}
        {tab === 'approvals' && <ApprovalQueuePanel tenantId={tenantId} />}
        {tab === 'snapshots' && <SnapshotsPanel tenantId={tenantId} />}
        {tab === 'recommendations' && <RecommendationsPanel tenantId={tenantId} />}
        {tab === 'trend' && <TrendPanel tenantId={tenantId} />}
        {tab === 'forecast' && <ForecastPanel tenantId={tenantId} />}
        {tab === 'sla' && <SlaPanel tenantId={tenantId} />}
        {tab === 'benchmark' && <BenchmarkPanel tenantId={tenantId} />}
        {tab === 'findings' && <FindingsPanel tenantId={tenantId} />}
        {tab === 'actions' && <ActionsLedgerPanel tenantId={tenantId} />}
        {tab === 'config' && <ConfigPanel tenantId={tenantId} />}
        {tab === 'audit' && <AuditPanel tenantId={tenantId} />}
      </div>
    </div>
  );
}
