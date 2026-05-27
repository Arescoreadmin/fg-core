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

const STATUS_LABEL: Record<string, string> = {
  open: 'Open',
  accepted: 'Accepted',
  resolved: 'Resolved',
  in_progress: 'In Progress',
  deferred: 'Deferred',
};

const PAGE_SIZE = 20;

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function FindingCard({ finding }: { finding: FindingSummary }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      className="rounded border border-border bg-surface-2 p-3 space-y-2 cursor-pointer hover:border-border/80"
      onClick={() => setExpanded((v) => !v)}
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      onKeyDown={(e) => e.key === 'Enter' && setExpanded((v) => !v)}
    >
      <div className="flex flex-wrap items-start gap-2">
        <SeverityBadge severity={finding.severity} />
        <span className="flex-1 min-w-0 text-sm font-medium text-foreground">{finding.title}</span>
        <span className="text-xs text-muted">{STATUS_LABEL[finding.status] ?? finding.status}</span>
      </div>
      <div className="text-xs text-muted font-mono">{finding.finding_id}</div>
      {expanded && (
        <div className="pt-1 space-y-2">
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
          {finding.remediation_hint && (
            <p className="text-xs text-muted">
              <span className="text-foreground font-medium">Guidance: </span>
              {finding.remediation_hint}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function FindingsPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') ?? '';

  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');

  const load = useCallback(
    async (offset: number, severity: string) => {
      if (!engagementId) return;
      setLoading(true);
      setError(null);
      try {
        const result = await portalApi.listFindings(engagementId, {
          limit: PAGE_SIZE,
          offset,
          severity: severity || undefined,
        });
        const sorted = [...result.items].sort(
          (a, b) =>
            (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
        );
        setFindings(sorted);
        setTotal(result.total_count);
      } catch (e) {
        if (e instanceof PortalApiError && e.status === 404) {
          setError('Engagement not found.');
        } else {
          setError('Failed to load findings. Please try again.');
        }
      } finally {
        setLoading(false);
      }
    },
    [engagementId],
  );

  useEffect(() => {
    setPage(0);
    load(0, severityFilter);
  }, [engagementId, severityFilter, load]);

  function handlePage(newPage: number) {
    setPage(newPage);
    load(newPage * PAGE_SIZE, severityFilter);
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

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const openCount = findings.filter((f) => f.status === 'open').length;

  return (
    <div className="space-y-4" aria-label="findings-page">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-foreground">Findings</h2>
          {!loading && total > 0 && (
            <p className="text-xs text-muted mt-0.5">
              {total} total · {criticalCount + highCount} critical/high · {openCount} open
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-muted" htmlFor="severity-filter">Severity</label>
          <select
            id="severity-filter"
            className="rounded border border-border bg-surface-2 text-xs px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
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
          <p className="text-sm font-medium">No findings</p>
          <p className="text-xs mt-1">
            {severityFilter ? 'No findings match the selected severity filter.' : 'No findings have been recorded for this engagement.'}
          </p>
        </div>
      )}

      {!loading && findings.length > 0 && (
        <>
          <div className="space-y-2">
            {findings.map((f) => (
              <FindingCard key={f.finding_id} finding={f} />
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

export default function FindingsPage() {
  return (
    <Suspense fallback={<div className="space-y-2" aria-busy="true">{[1,2,3].map(i=><div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse"/>)}</div>}>
      <FindingsPageInner />
    </Suspense>
  );
}
