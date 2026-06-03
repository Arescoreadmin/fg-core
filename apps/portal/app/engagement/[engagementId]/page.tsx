'use client';

import { Fragment, useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  portalApi,
  PortalApiError,
  type EngagementDetail,
  type EngagementCounts,
  type ScanResult,
  type ScanResultDetail,
  type EngagementDocument,
  type Observation,
  type EvidenceLink,
  type AuditEvent,
  type VerificationBundle,
} from '@/lib/portalApi';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null | undefined) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  });
}

function fmtDateTime(iso: string | null | undefined) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function truncate(s: string, n = 12) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

// ─── Style maps ───────────────────────────────────────────────────────────────

const STATUS_CLASS: Record<string, string> = {
  scheduled:          'border-blue-500/30 bg-blue-500/5 text-blue-300',
  pre_visit:          'border-blue-500/30 bg-blue-500/5 text-blue-300',
  in_progress:        'border-amber-500/30 bg-amber-500/5 text-amber-200',
  evidence_collected: 'border-amber-500/30 bg-amber-500/5 text-amber-200',
  report_generation:  'border-purple-500/30 bg-purple-500/5 text-purple-300',
  delivered:          'border-green-500/30 bg-green-500/5 text-green-300',
  remediation:        'border-orange-500/30 bg-orange-500/5 text-orange-300',
  monitoring:         'border-teal-500/30 bg-teal-500/5 text-teal-300',
  closed:             'border-border bg-surface-3 text-muted',
  cancelled:          'border-border bg-surface-3 text-muted',
};

const SEV_CLASS: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high:     'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium:   'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low:      'border-blue-500/40 bg-blue-500/10 text-blue-300',
  info:     'border-border bg-surface-2 text-muted',
};

const OBS_TYPE_CLASS: Record<string, string> = {
  gap:       'border-red-500/30 bg-red-500/5 text-red-300',
  concern:   'border-orange-500/30 bg-orange-500/5 text-orange-300',
  finding:   'border-amber-500/30 bg-amber-500/5 text-amber-200',
  strength:  'border-green-500/30 bg-green-500/5 text-green-300',
  note:      'border-border bg-surface-3 text-muted',
  interview: 'border-blue-500/30 bg-blue-500/5 text-blue-300',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-3 text-muted';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
    </span>
  );
}

function SevBadge({ severity }: { severity: string }) {
  const cls = SEV_CLASS[severity] ?? SEV_CLASS.info;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function ObsTypeBadge({ type }: { type: string }) {
  const cls = OBS_TYPE_CLASS[type] ?? 'border-border bg-surface-3 text-muted';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {type.charAt(0).toUpperCase() + type.slice(1)}
    </span>
  );
}

// ─── Tab definitions ──────────────────────────────────────────────────────────

const TABS = [
  { id: 'overview',     label: 'Overview' },
  { id: 'scans',        label: 'Scans' },
  { id: 'documents',    label: 'Documents' },
  { id: 'observations', label: 'Observations' },
  { id: 'evidence',     label: 'Evidence' },
  { id: 'history',      label: 'History' },
] as const;

type TabId = typeof TABS[number]['id'];

// ─── Count card ───────────────────────────────────────────────────────────────

function CountCard({ label, value, sub }: { label: string; value: number; sub?: string }) {
  return (
    <div className="rounded border border-border bg-surface-2 px-4 py-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-0.5 text-xl font-semibold text-foreground">{value}</p>
      {sub && <p className="mt-0.5 text-xs text-muted">{sub}</p>}
    </div>
  );
}

// ─── Async state helper ───────────────────────────────────────────────────────

type Async<T> = { data: T | null; loading: boolean; error: string | null };

function idle<T>(): Async<T> {
  return { data: null, loading: false, error: null };
}

function apiError(e: unknown): string {
  if (e instanceof PortalApiError) return `Error ${e.status}: ${e.code}`;
  return 'Failed to load.';
}

// ─── Tab panels ───────────────────────────────────────────────────────────────

const BUNDLE_STATUS_CLASS: Record<string, string> = {
  verified:        'border-green-500/30 bg-green-500/5 text-green-300',
  incomplete:      'border-amber-500/30 bg-amber-500/5 text-amber-200',
  tamper_detected: 'border-red-500/30 bg-red-500/5 text-red-300',
};
const BUNDLE_STATUS_LABEL: Record<string, string> = {
  verified:        'Verified',
  incomplete:      'Incomplete',
  tamper_detected: 'Tamper Detected',
};

function VerificationBundleCard({ engagementId }: { engagementId: string }) {
  const [bundle, setBundle] = useState<VerificationBundle | null>(null);
  const [bundleLoading, setBundleLoading] = useState(true);

  useEffect(() => {
    portalApi.getVerificationBundle(engagementId)
      .then(setBundle)
      .catch(() => setBundle(null))
      .finally(() => setBundleLoading(false));
  }, [engagementId]);

  if (bundleLoading) return null;
  if (!bundle) {
    return (
      <div className="rounded border border-border bg-surface p-4">
        <h3 className="text-sm font-medium text-foreground mb-1">Verification Bundle</h3>
        <p className="text-xs text-muted">No verification bundle available yet.</p>
      </div>
    );
  }

  const statusCls = BUNDLE_STATUS_CLASS[bundle.verification_status] ?? 'border-border bg-surface-3 text-muted';
  const statusLabel = BUNDLE_STATUS_LABEL[bundle.verification_status] ?? bundle.verification_status;

  return (
    <div className="rounded border border-border bg-surface p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium text-foreground">Verification Bundle</h3>
        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${statusCls}`}>
          {statusLabel}
        </span>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt className="text-muted">Generated</dt>
        <dd className="text-foreground">{fmtDateTime(bundle.generated_at)}</dd>
        <dt className="text-muted">Bundle Hash</dt>
        <dd className="font-mono text-muted truncate">{bundle.bundle_hash.slice(0, 20)}…</dd>
        <dt className="text-muted">Manifest Hash</dt>
        <dd className="font-mono text-muted truncate">{bundle.manifest_hash.slice(0, 20)}…</dd>
        <dt className="text-muted">Findings</dt>
        <dd className="text-foreground">{bundle.finding_count}</dd>
        <dt className="text-muted">Evidence</dt>
        <dd className="text-foreground">{bundle.evidence_count}</dd>
        <dt className="text-muted">Decisions</dt>
        <dd className="text-foreground">{bundle.decision_count}</dd>
      </dl>
      {bundle.tamper_details && bundle.tamper_details.length > 0 && (
        <div className="rounded border border-red-500/30 bg-red-500/5 p-2.5 space-y-1">
          <p className="text-xs font-semibold text-red-300">
            {bundle.tamper_details.length} integrity issue{bundle.tamper_details.length !== 1 ? 's' : ''} detected
          </p>
          {bundle.tamper_details.slice(0, 3).map((issue, i) => (
            <p key={i} className="text-xs text-red-300/80 font-mono">{issue}</p>
          ))}
          {bundle.tamper_details.length > 3 && (
            <p className="text-xs text-red-300/60">+{bundle.tamper_details.length - 3} more</p>
          )}
        </div>
      )}
    </div>
  );
}

function OverviewTab({
  engagement,
  counts,
  engagementId,
}: {
  engagement: EngagementDetail;
  counts: EngagementCounts | null;
  engagementId: string;
}) {
  return (
    <div className="space-y-6">
      {/* Metadata */}
      <div className="rounded border border-border bg-surface p-4 space-y-3">
        <h3 className="text-sm font-medium text-foreground">Engagement Details</h3>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3 text-xs">
          {[
            { label: 'Client', value: engagement.client_name },
            { label: 'Domain', value: engagement.client_domain ?? '—' },
            { label: 'Type', value: engagement.assessment_type.replace(/_/g, ' ').toUpperCase() },
            { label: 'Status', value: <StatusBadge status={engagement.status} /> },
            { label: 'Assessor', value: engagement.assessor_id },
            { label: 'Scheduled', value: fmtDate(engagement.scheduled_date) },
            { label: 'Created', value: fmtDate(engagement.created_at) },
            { label: 'Updated', value: fmtDate(engagement.updated_at) },
            { label: 'Schema', value: engagement.schema_version },
          ].map(({ label, value }) => (
            <div key={label}>
              <dt className="text-muted">{label}</dt>
              <dd className="mt-0.5 text-foreground font-medium">{value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Count cards */}
      {counts && (
        <div className="grid grid-cols-3 gap-3 sm:grid-cols-5">
          <CountCard label="Scans" value={counts.scan_results} />
          <CountCard label="Documents" value={counts.document_analyses} />
          <CountCard label="Observations" value={counts.field_observations} />
          <CountCard
            label="Findings"
            value={counts.normalized_findings}
            sub={counts.open_findings > 0 ? `${counts.open_findings} open` : 'all resolved'}
          />
          <CountCard label="Evidence Links" value={counts.evidence_links} />
        </div>
      )}

      {/* Critical finding callout */}
      {counts && counts.critical_findings > 0 && (
        <div className="rounded border border-red-500/30 bg-red-500/5 p-3 flex items-center justify-between gap-4">
          <p className="text-sm text-red-300">
            <span className="font-semibold">{counts.critical_findings} critical finding{counts.critical_findings !== 1 ? 's' : ''}</span> require immediate attention.
          </p>
          <Link
            href={`/findings?engagement=${engagementId}&severity=critical`}
            className="shrink-0 text-xs text-red-300 hover:text-red-200 underline underline-offset-2"
          >
            View →
          </Link>
        </div>
      )}

      {/* Verification bundle */}
      <VerificationBundleCard engagementId={engagementId} />

      {/* Quick navigation */}
      <div className="rounded border border-border bg-surface p-4 space-y-2">
        <h3 className="text-sm font-medium text-foreground">Assessment pages</h3>
        <div className="flex flex-wrap gap-2">
          {[
            { href: `/findings?engagement=${engagementId}`, label: 'Findings' },
            { href: `/reports?engagement=${engagementId}`, label: 'Reports' },
            { href: `/coverage?engagement=${engagementId}`, label: 'NIST Coverage' },
            { href: `/remediation?engagement=${engagementId}`, label: 'Remediation Roadmap' },
          ].map(({ href, label }) => (
            <Link
              key={href}
              href={href}
              className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground hover:border-primary/40 transition-colors"
            >
              {label} →
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}


function sourceLabel(sourceType: string) {
  if (sourceType === 'ai_tool_discovery') return 'AI Tool Discovery';
  return sourceType.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

type AiTool = {
  tool_name?: string;
  vendor?: string;
  publisher?: string;
  verified_publisher?: boolean;
  permissions_summary?: string;
  admin_consent?: boolean;
  last_seen?: string;
  risk_indicators?: string[];
  evidence_refs?: string[];
  confidence?: string;
};

function AiToolDetails({ detail }: { detail: ScanResultDetail }) {
  const payload = detail.normalized_payload ?? {};
  const tools = Array.isArray(payload.tools) ? (payload.tools as AiTool[]) : [];
  if (!tools.length) return <p className="text-xs text-muted">No AI tools were discovered in this scan.</p>;
  return (
    <div className="space-y-2">
      {tools.slice(0, 8).map((tool, idx) => (
        <div key={`${tool.vendor}-${tool.tool_name}-${idx}`} className="rounded border border-border bg-surface-2 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-foreground">{tool.tool_name ?? 'Unknown AI tool'}</span>
            <span className="text-xs text-muted">{tool.vendor ?? 'Unknown vendor'}</span>
            <span className="rounded border border-border px-1.5 py-0.5 text-[11px] text-muted">{tool.confidence ?? 'unknown'}</span>
          </div>
          <dl className="mt-2 grid gap-2 text-xs sm:grid-cols-3">
            <div><dt className="text-muted">Publisher</dt><dd className="text-foreground">{tool.publisher ?? 'unknown'}</dd></div>
            <div><dt className="text-muted">Verified</dt><dd className="text-foreground">{tool.verified_publisher ? 'yes' : 'no'}</dd></div>
            <div><dt className="text-muted">Admin consent</dt><dd className="text-foreground">{tool.admin_consent ? 'yes' : 'no'}</dd></div>
            <div><dt className="text-muted">Permissions</dt><dd className="text-foreground">{tool.permissions_summary ?? 'unknown'}</dd></div>
            <div><dt className="text-muted">Last seen</dt><dd className="text-foreground">{tool.last_seen ?? 'unknown'}</dd></div>
            <div><dt className="text-muted">Evidence refs</dt><dd className="font-mono text-muted">{(tool.evidence_refs ?? []).slice(0, 2).join(', ') || 'unknown'}</dd></div>
          </dl>
          {tool.risk_indicators?.length ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {tool.risk_indicators.slice(0, 8).map((risk) => (
                <span key={risk} className="rounded border border-amber-500/30 bg-amber-500/5 px-1.5 py-0.5 text-[11px] text-amber-200">{risk.replace(/_/g, ' ')}</span>
              ))}
            </div>
          ) : null}
        </div>
      ))}
      {tools.length > 8 && <p className="text-xs text-muted">Showing 8 of {tools.length} discovered tools.</p>}
    </div>
  );
}

function ScansTab({ engagementId }: { engagementId: string }) {
  const [state, setState] = useState<Async<ScanResult[]>>(idle());
  const [aiDetails, setAiDetails] = useState<Record<string, ScanResultDetail>>({});

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    portalApi
      .listScans(engagementId)
      .then((data) => {
        setState({ data, loading: false, error: null });
        const aiScans = data.filter((scan) => scan.source_type === 'ai_tool_discovery');
        Promise.all(aiScans.map((scan) => portalApi.getScan(engagementId, scan.id).catch(() => null)))
          .then((details) => {
            const next: Record<string, ScanResultDetail> = {};
            details.forEach((detail) => { if (detail) next[detail.id] = detail; });
            setAiDetails(next);
          })
          .catch(() => {});
      })
      .catch((e) => setState({ data: null, loading: false, error: apiError(e) }));
  }, [engagementId]);

  if (state.loading) return <Loading />;
  if (state.error)   return <ErrorMsg msg={state.error} />;
  if (!state.data?.length) return <Empty label="No scans have been imported yet." />;

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border bg-surface-2 text-left text-muted">
            <th className="px-3 py-2 font-medium">Source</th>
            <th className="px-3 py-2 font-medium">Objects</th>
            <th className="px-3 py-2 font-medium">Evidence Hash</th>
            <th className="px-3 py-2 font-medium">Collected</th>
            <th className="px-3 py-2 font-medium">Imported</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {state.data.map((scan) => (
            <Fragment key={scan.id}>
              <tr className="bg-surface hover:bg-surface-2 transition-colors">
                <td className="px-3 py-2 text-foreground font-medium">
                  {sourceLabel(scan.source_type)}
                </td>
                <td className="px-3 py-2 text-foreground">{scan.object_count.toLocaleString()}</td>
                <td className="px-3 py-2 font-mono text-muted" title={scan.evidence_hash}>
                  {truncate(scan.evidence_hash, 16)}
                </td>
                <td className="px-3 py-2 text-muted">{fmtDateTime(scan.collected_at)}</td>
                <td className="px-3 py-2 text-muted">{fmtDateTime(scan.created_at)}</td>
              </tr>
              {scan.source_type === 'ai_tool_discovery' && aiDetails[scan.id] && (
                <tr key={`${scan.id}-ai-details`} className="bg-surface">
                  <td colSpan={5} className="px-3 py-3">
                    <AiToolDetails detail={aiDetails[scan.id]} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DocumentsTab({ engagementId }: { engagementId: string }) {
  const [state, setState] = useState<Async<EngagementDocument[]>>(idle());

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    portalApi
      .listDocuments(engagementId)
      .then((data) => {
        setState({ data, loading: false, error: null });
      })
      .catch((e) => setState({ data: null, loading: false, error: apiError(e) }));
  }, [engagementId]);

  if (state.loading) return <Loading />;
  if (state.error)   return <ErrorMsg msg={state.error} />;
  if (!state.data?.length) return <Empty label="No documents have been registered yet." />;

  return (
    <div className="space-y-2">
      {state.data.map((doc) => {
        const isStale =
          doc.freshness_date ? new Date(doc.freshness_date) < new Date() : false;
        return (
          <div
            key={doc.id}
            className="rounded border border-border bg-surface p-3 space-y-1.5"
          >
            <div className="flex flex-wrap items-start gap-2">
              <p className="flex-1 text-sm font-medium text-foreground">{doc.document_name}</p>
              <span className="text-xs text-muted border border-border rounded px-1.5 py-0.5">
                {doc.document_classification.replace(/_/g, ' ')}
              </span>
              {isStale && (
                <span className="text-xs border border-red-500/30 bg-red-500/5 text-red-300 rounded px-1.5 py-0.5">
                  Stale
                </span>
              )}
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
              {doc.version_label && (
                <div>
                  <dt className="text-muted">Version</dt>
                  <dd className="text-foreground">{doc.version_label}</dd>
                </div>
              )}
              {doc.approved_by && (
                <div>
                  <dt className="text-muted">Approved by</dt>
                  <dd className="text-foreground">{doc.approved_by}</dd>
                </div>
              )}
              {doc.approval_date && (
                <div>
                  <dt className="text-muted">Approval date</dt>
                  <dd className="text-foreground">{fmtDate(doc.approval_date)}</dd>
                </div>
              )}
              {doc.freshness_date && (
                <div>
                  <dt className="text-muted">Fresh until</dt>
                  <dd className={isStale ? 'text-red-300' : 'text-foreground'}>
                    {fmtDate(doc.freshness_date)}
                  </dd>
                </div>
              )}
            </dl>
            {doc.gaps_identified.length > 0 && (
              <div>
                <p className="text-xs text-muted mb-1">Gaps identified</p>
                <ul className="space-y-0.5">
                  {doc.gaps_identified.map((g, i) => (
                    <li key={i} className="text-xs text-amber-200 flex gap-1.5">
                      <span className="text-amber-500/50 shrink-0">▸</span>
                      {g}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ObservationsTab({ engagementId }: { engagementId: string }) {
  const [filter, setFilter] = useState<string>('all');
  const [state, setState] = useState<Async<Observation[]>>(idle());

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    portalApi
      .listObservations(engagementId)
      .then((data) => {
        setState({ data, loading: false, error: null });
      })
      .catch((e) => setState({ data: null, loading: false, error: apiError(e) }));
  }, [engagementId]);

  const filtered =
    state.data?.filter((o) => filter === 'all' || o.observation_type === filter) ?? [];

  const filterOptions = [
    'all', 'gap', 'strength', 'concern', 'finding', 'note', 'interview',
  ];

  if (state.loading) return <Loading />;
  if (state.error)   return <ErrorMsg msg={state.error} />;

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap gap-1.5">
        {filterOptions.map((opt) => {
          const count =
            opt === 'all'
              ? state.data?.length ?? 0
              : state.data?.filter((o) => o.observation_type === opt).length ?? 0;
          return (
            <button
              key={opt}
              onClick={() => setFilter(opt)}
              className={`rounded border px-2.5 py-1 text-xs font-medium transition-colors ${
                filter === opt
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border bg-surface-2 text-muted hover:text-foreground'
              }`}
            >
              {opt.charAt(0).toUpperCase() + opt.slice(1)}{' '}
              <span className="opacity-60">({count})</span>
            </button>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <Empty label={`No ${filter === 'all' ? '' : filter + ' '}observations recorded yet.`} />
      )}

      <div className="space-y-2">
        {filtered.map((obs) => (
          <div
            key={obs.id}
            className="rounded border border-border bg-surface p-3 space-y-2"
          >
            <div className="flex flex-wrap items-start gap-2">
              <ObsTypeBadge type={obs.observation_type} />
              {obs.severity && obs.severity !== 'none' && (
                <SevBadge severity={obs.severity} />
              )}
              <p className="flex-1 text-sm font-medium text-foreground">{obs.title}</p>
            </div>
            <p className="text-xs text-muted leading-relaxed">{obs.description}</p>
            <dl className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
              <div>
                <dt className="inline text-muted">Domain: </dt>
                <dd className="inline text-foreground">
                  {obs.domain.replace(/_/g, ' ')}
                </dd>
              </div>
              {obs.interview_role && (
                <div>
                  <dt className="inline text-muted">Role: </dt>
                  <dd className="inline text-foreground">{obs.interview_role}</dd>
                </div>
              )}
              <div>
                <dt className="inline text-muted">Recorded: </dt>
                <dd className="inline text-foreground">{fmtDate(obs.created_at)}</dd>
              </div>
            </dl>
          </div>
        ))}
      </div>
    </div>
  );
}

function EvidenceTab({ engagementId }: { engagementId: string }) {
  const [state, setState] = useState<Async<EvidenceLink[]>>(idle());

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    portalApi
      .listEvidenceLinks(engagementId)
      .then((data) => {
        setState({ data, loading: false, error: null });
      })
      .catch((e) => setState({ data: null, loading: false, error: apiError(e) }));
  }, [engagementId]);

  if (state.loading) return <Loading />;
  if (state.error)   return <ErrorMsg msg={state.error} />;
  if (!state.data?.length) return <Empty label="No evidence links recorded yet." />;

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border bg-surface-2 text-left text-muted">
            <th className="px-3 py-2 font-medium">Source Entity</th>
            <th className="px-3 py-2 font-medium">Source ID</th>
            <th className="px-3 py-2 font-medium">Evidence Entity</th>
            <th className="px-3 py-2 font-medium">Evidence ID</th>
            <th className="px-3 py-2 font-medium">Linked</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {state.data.map((link) => (
            <tr key={link.id} className="bg-surface hover:bg-surface-2 transition-colors">
              <td className="px-3 py-2 text-foreground">
                {link.source_entity_type.replace(/_/g, ' ')}
              </td>
              <td className="px-3 py-2 font-mono text-muted" title={link.source_entity_id}>
                {truncate(link.source_entity_id, 14)}
              </td>
              <td className="px-3 py-2 text-foreground">
                {link.evidence_entity_type.replace(/_/g, ' ')}
              </td>
              <td className="px-3 py-2 font-mono text-muted" title={link.evidence_entity_id}>
                {truncate(link.evidence_entity_id, 14)}
              </td>
              <td className="px-3 py-2 text-muted">{fmtDate(link.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HistoryTab({ engagementId }: { engagementId: string }) {
  const [state, setState] = useState<Async<AuditEvent[]>>(idle());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    portalApi
      .listAuditEvents(engagementId)
      .then((data) => {
        setState({ data, loading: false, error: null });
      })
      .catch((e) => setState({ data: null, loading: false, error: apiError(e) }));
  }, [engagementId]);

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  if (state.loading) return <Loading />;
  if (state.error)   return <ErrorMsg msg={state.error} />;
  if (!state.data?.length) return <Empty label="No audit events recorded yet." />;

  return (
    <div className="space-y-1.5">
      {state.data.map((evt) => {
        const open = expanded.has(evt.id);
        const hasPayload = Object.keys(evt.payload ?? {}).length > 0;
        return (
          <div key={evt.id} className="rounded border border-border bg-surface p-3 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono font-medium text-foreground">
                {evt.event_type}
              </span>
              {evt.reason_code && (
                <span className="text-xs text-muted border border-border rounded px-1 py-0.5">
                  {evt.reason_code}
                </span>
              )}
              <span className="ml-auto text-xs text-muted">{fmtDateTime(evt.created_at)}</span>
            </div>
            <p className="text-xs text-muted">
              Actor: <span className="text-foreground">{evt.actor}</span>
            </p>
            {hasPayload && (
              <button
                onClick={() => toggleExpand(evt.id)}
                className="text-xs text-muted hover:text-foreground underline underline-offset-2"
              >
                {open ? 'Hide payload ↑' : 'Show payload ↓'}
              </button>
            )}
            {open && hasPayload && (
              <pre className="mt-1 overflow-x-auto rounded bg-surface-3 border border-border p-2 text-xs text-muted font-mono leading-relaxed">
                {JSON.stringify(evt.payload, null, 2)}
              </pre>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Shared UI atoms ──────────────────────────────────────────────────────────

function Loading() {
  return (
    <div className="rounded border border-border bg-surface p-8 text-center text-sm text-muted">
      Loading…
    </div>
  );
}

function ErrorMsg({ msg }: { msg: string }) {
  return (
    <div className="rounded border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
      {msg}
    </div>
  );
}

function Empty({ label }: { label: string }) {
  return (
    <div className="rounded border border-border bg-surface p-8 text-center text-sm text-muted">
      {label}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function EngagementDetailPage() {
  const params = useParams<{ engagementId: string }>();
  const engagementId = params.engagementId;

  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [engagement, setEngagement] = useState<EngagementDetail | null>(null);
  const [counts, setCounts] = useState<EngagementCounts | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!engagementId) return;
    Promise.allSettled([
      portalApi.getEngagement(engagementId),
      portalApi.getEngagementSummary(engagementId),
    ]).then(([engResult, countResult]) => {
      if (engResult.status === 'fulfilled') {
        setEngagement(engResult.value);
      } else {
        setPageError(apiError(engResult.reason));
      }
      if (countResult.status === 'fulfilled') {
        setCounts(countResult.value);
      }
      setLoading(false);
    });
  }, [engagementId]);

  if (loading) {
    return (
      <div className="py-16 text-center text-sm text-muted">Loading assessment…</div>
    );
  }

  if (pageError || !engagement) {
    return (
      <div className="space-y-4">
        <Link href="/engagement" className="text-xs text-muted hover:text-foreground">
          ← All Assessments
        </Link>
        <div className="rounded border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
          {pageError ?? 'Engagement not found.'}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Back + header */}
      <div>
        <Link href="/engagement" className="text-xs text-muted hover:text-foreground">
          ← All Assessments
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-lg font-semibold text-foreground">{engagement.client_name}</h1>
          <StatusBadge status={engagement.status} />
          <span className="text-xs text-muted">
            {engagement.assessment_type.replace(/_/g, ' ').toUpperCase()}
          </span>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted hover:text-foreground'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'overview' && (
          <OverviewTab
            engagement={engagement}
            counts={counts}
            engagementId={engagementId}
          />
        )}
        {activeTab === 'scans'        && <ScansTab        engagementId={engagementId} />}
        {activeTab === 'documents'    && <DocumentsTab    engagementId={engagementId} />}
        {activeTab === 'observations' && <ObservationsTab engagementId={engagementId} />}
        {activeTab === 'evidence'     && <EvidenceTab     engagementId={engagementId} />}
        {activeTab === 'history'      && <HistoryTab      engagementId={engagementId} />}
      </div>
    </div>
  );
}
