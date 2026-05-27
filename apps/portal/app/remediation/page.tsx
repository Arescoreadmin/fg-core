'use client';

import { Suspense, useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError, type FindingSummary } from '@/lib/portalApi';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  info: 'border-border bg-surface-2 text-muted',
};

const STATUS_CLASS: Record<string, string> = {
  open: 'text-red-300',
  in_progress: 'text-amber-200',
  resolved: 'text-green-300',
  deferred: 'text-muted',
  accepted: 'text-blue-300',
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function RemediationCard({ finding }: { finding: FindingSummary }) {
  const [expanded, setExpanded] = useState(false);
  const statusCls = STATUS_CLASS[finding.status] ?? 'text-muted';

  return (
    <div
      className="rounded border border-border bg-surface-2 p-3 space-y-2 cursor-pointer hover:border-border/80 transition-colors"
      onClick={() => setExpanded((v) => !v)}
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      onKeyDown={(e) => e.key === 'Enter' && setExpanded((v) => !v)}
    >
      <div className="flex flex-wrap items-start gap-2">
        <SeverityBadge severity={finding.severity} />
        <span className="flex-1 min-w-0 text-sm font-medium text-foreground">{finding.title}</span>
        <span className={`text-xs font-medium capitalize ${statusCls}`}>
          {finding.status.replace(/_/g, ' ')}
        </span>
      </div>

      {!finding.remediation_hint && !expanded && (
        <p className="text-xs text-muted">No remediation guidance recorded.</p>
      )}

      {finding.remediation_hint && (
        <div className="rounded border border-border bg-surface-3 px-3 py-2">
          <p className="text-xs text-muted font-medium mb-0.5">Guidance</p>
          <p className="text-xs text-foreground leading-relaxed">
            {expanded
              ? finding.remediation_hint
              : `${finding.remediation_hint.slice(0, 160)}${finding.remediation_hint.length > 160 ? '…' : ''}`}
          </p>
          {finding.remediation_hint.length > 160 && (
            <button className="text-xs text-primary mt-1 hover:underline">
              {expanded ? 'Show less' : 'Show more'}
            </button>
          )}
        </div>
      )}

      {expanded && (
        <div className="space-y-1.5 pt-1">
          {finding.nist_ai_rmf_mappings.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.nist_ai_rmf_mappings.map((m) => (
                <span key={m} className="rounded px-1.5 py-0.5 text-xs border border-blue-500/20 bg-blue-500/5 text-blue-300">
                  {m}
                </span>
              ))}
            </div>
          )}
          {finding.framework_mappings.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.framework_mappings.map((m) => (
                <span key={m} className="rounded px-1.5 py-0.5 text-xs border border-border bg-surface-3 text-muted">
                  {m}
                </span>
              ))}
            </div>
          )}
          <p className="text-xs text-muted font-mono">ID: {finding.finding_id}</p>
        </div>
      )}
    </div>
  );
}

const STATUS_FILTERS = [
  { value: '', label: 'All statuses' },
  { value: 'open', label: 'Open' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'deferred', label: 'Deferred' },
  { value: 'resolved', label: 'Resolved' },
];

const PAGE_SIZE = 20;

function RemediationPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') ?? '';

  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('open');

  const load = useCallback(
    async (offset: number, status: string) => {
      if (!engagementId) return;
      setLoading(true);
      setError(null);
      try {
        const result = await portalApi.listFindings(engagementId, {
          limit: PAGE_SIZE,
          offset,
          status: status || undefined,
        });
        const sorted = [...result.items].sort(
          (a, b) =>
            (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
        );
        // Only show findings that have a remediation path
        const withRemediation = sorted.filter(
          (f) => f.remediation_hint || ['open', 'in_progress', 'deferred'].includes(f.status),
        );
        setFindings(withRemediation);
        setTotal(result.total);
      } catch (e) {
        if (e instanceof PortalApiError && e.status === 404) {
          setError('Engagement not found.');
        } else {
          setError('Failed to load remediation data.');
        }
      } finally {
        setLoading(false);
      }
    },
    [engagementId],
  );

  useEffect(() => {
    setPage(0);
    load(0, statusFilter);
  }, [engagementId, statusFilter, load]);

  function handlePage(newPage: number) {
    setPage(newPage);
    load(newPage * PAGE_SIZE, statusFilter);
  }

  const totalPages = Math.ceil(total / PAGE_SIZE);

  if (!engagementId) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <p className="text-sm font-semibold text-foreground">No engagement selected</p>
        <p className="mt-1 text-xs text-muted">
          Add <code className="font-mono">?e=&lt;engagement_id&gt;</code> to the URL.
        </p>
      </div>
    );
  }

  const criticalOpen = findings.filter(
    (f) => f.severity === 'critical' && f.status === 'open',
  ).length;

  return (
    <div className="space-y-4" aria-label="remediation-page">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-foreground">Remediation Guidance</h2>
          {!loading && criticalOpen > 0 && (
            <p className="text-xs text-red-300 mt-0.5">
              {criticalOpen} critical finding{criticalOpen !== 1 ? 's' : ''} require immediate action
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-muted" htmlFor="status-filter">Status</label>
          <select
            id="status-filter"
            className="rounded border border-border bg-surface-2 text-xs px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            {STATUS_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>{f.label}</option>
            ))}
          </select>
        </div>
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {error && !loading && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {!loading && !error && findings.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center text-muted">
          <p className="text-sm font-medium">No findings with remediation guidance</p>
          <p className="text-xs mt-1">
            {statusFilter ? 'Try changing the status filter.' : 'All findings have been addressed.'}
          </p>
        </div>
      )}

      {!loading && findings.length > 0 && (
        <>
          <div className="space-y-2">
            {findings.map((f) => (
              <RemediationCard key={f.finding_id} finding={f} />
            ))}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 text-xs text-muted pt-2">
              <button
                className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
                onClick={() => handlePage(page - 1)}
                disabled={page === 0}
                aria-label="Previous page"
              >
                ‹ Prev
              </button>
              <span>{page + 1} / {totalPages}</span>
              <button
                className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
                onClick={() => handlePage(page + 1)}
                disabled={page >= totalPages - 1}
                aria-label="Next page"
              >
                Next ›
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default function RemediationPage() {
  return (
    <Suspense fallback={<div className="space-y-2" aria-busy="true">{[1,2,3].map(i=><div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse"/>)}</div>}>
      <RemediationPageInner />
    </Suspense>
  );
}
