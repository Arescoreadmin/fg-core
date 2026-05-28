'use client';

import { Suspense, useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  portalApi,
  PortalApiError,
  type ReportVersionSummary,
  type ReportVerifyResult,
  type ReportDocument,
} from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';

const STATUS_CLASS: Record<string, string> = {
  finalized: 'border-green-500/30 bg-green-500/5 text-green-300',
  ready: 'border-green-500/30 bg-green-500/5 text-green-300',
  generating: 'border-amber-500/30 bg-amber-500/5 text-amber-200',
  draft: 'border-border bg-surface-3 text-muted',
  failed: 'border-red-500/30 bg-red-500/5 text-red-300',
  superseded: 'border-border bg-surface-3 text-muted',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-3 text-muted';
  const label = status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, ' ');
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {label}
    </span>
  );
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = window.document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function safeExportMsg(e: unknown): string {
  if (e instanceof PortalApiError) {
    if (e.status === 403) return 'Access denied.';
    if (e.status === 404) return 'Report not found.';
    if (e.status === 501) return 'PDF export is not available.';
  }
  return 'Export failed. Please try again.';
}

const POSTURE_CLASS: Record<string, string> = {
  critical: 'border-red-500/30 bg-red-500/5 text-red-300',
  high: 'border-amber-500/30 bg-amber-500/5 text-amber-200',
  medium: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-200',
  low: 'border-green-500/30 bg-green-500/5 text-green-300',
};

function safeStr(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

function safeArr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function safeObj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}

interface ReportRowProps {
  report: ReportVersionSummary;
  engagementId: string;
}

function ReportRow({ report, engagementId }: ReportRowProps) {
  const [exportingJson, setExportingJson] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<ReportVerifyResult | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [summaryOpen, setSummaryOpen] = useState(false);
  const [summaryDoc, setSummaryDoc] = useState<ReportDocument | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const busy = exportingJson || exportingPdf || verifying;

  async function handleToggleSummary() {
    if (summaryOpen) { setSummaryOpen(false); return; }
    setSummaryOpen(true);
    if (summaryDoc) return;
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      const doc = await portalApi.getReport(engagementId, report.version);
      setSummaryDoc(doc);
    } catch (e) {
      setSummaryError(
        e instanceof PortalApiError && e.status === 404
          ? 'Report not found.'
          : 'Could not load report summary.',
      );
    } finally {
      setSummaryLoading(false);
    }
  }
  const filename = (fmt: string) =>
    `frostgate-report-${engagementId}-v${report.version}.${fmt}`;

  async function handleExport(fmt: 'json' | 'pdf') {
    const setter = fmt === 'json' ? setExportingJson : setExportingPdf;
    setter(true);
    setExportError(null);
    try {
      const blob = await portalApi.exportReport(engagementId, report.version, fmt);
      downloadBlob(blob, filename(fmt));
    } catch (e) {
      setExportError(safeExportMsg(e));
    } finally {
      setter(false);
    }
  }

  async function handleVerify() {
    setVerifying(true);
    setExportError(null);
    setVerifyResult(null);
    try {
      const result = await portalApi.verifyReport(engagementId, report.version);
      setVerifyResult(result);
    } catch (e) {
      setExportError(
        e instanceof PortalApiError && e.status === 503
          ? 'Signing key unavailable.'
          : 'Verification failed.',
      );
    } finally {
      setVerifying(false);
    }
  }

  return (
    <div className="rounded border border-border bg-surface-2 p-3 space-y-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-semibold text-foreground text-sm">v{report.version}</span>
        <StatusBadge status={report.status} />
        {report.report_type && (
          <span className="text-xs text-muted capitalize">{report.report_type.replace(/_/g, ' ')}</span>
        )}
        <span className="ml-auto text-xs text-muted">
          {new Date(report.compiled_at).toLocaleString()}
        </span>
      </div>

      {report.compiled_by && (
        <p className="text-xs text-muted">
          Compiled by: <span className="text-foreground">{report.compiled_by}</span>
        </p>
      )}

      <div className="flex flex-wrap gap-2 pt-1">
        <button
          className="rounded border border-primary/30 bg-primary/5 px-2.5 py-1 text-xs text-primary hover:bg-primary/10 disabled:opacity-40 disabled:cursor-not-allowed"
          onClick={handleToggleSummary}
          aria-expanded={summaryOpen}
        >
          {summaryOpen ? 'Hide Summary ▲' : 'View Summary ▼'}
        </button>
        <button
          className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
          onClick={() => handleExport('json')}
          disabled={busy}
          aria-busy={exportingJson}
        >
          {exportingJson ? 'Downloading…' : 'Export JSON'}
        </button>
        <button
          className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
          onClick={() => handleExport('pdf')}
          disabled={busy}
          aria-busy={exportingPdf}
        >
          {exportingPdf ? 'Downloading…' : 'Export PDF'}
        </button>
        <button
          className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
          onClick={handleVerify}
          disabled={busy}
          aria-busy={verifying}
        >
          {verifying ? 'Verifying…' : 'Verify Signature'}
        </button>
      </div>

      {summaryOpen && (
        <div className="rounded border border-border bg-surface-3 p-3 space-y-2.5 text-xs">
          {summaryLoading && (
            <div className="space-y-2" aria-busy="true">
              <div className="h-3 w-3/4 rounded bg-surface-2 animate-pulse" />
              <div className="h-3 w-full rounded bg-surface-2 animate-pulse" />
              <div className="h-3 w-2/3 rounded bg-surface-2 animate-pulse" />
            </div>
          )}
          {summaryError && !summaryLoading && (
            <p className="text-red-300">{summaryError}</p>
          )}
          {summaryDoc && !summaryLoading && (() => {
            const body = safeObj(summaryDoc.report);
            const exec = safeObj(body.executive_summary);
            const narrative = safeStr(exec.narrative);
            const posture = safeStr(exec.risk_posture);
            const concerns = safeArr(exec.key_concerns);
            const note = safeStr(exec.generation_note);
            if (!narrative) {
              return <p className="text-muted">No executive summary available for this report version.</p>;
            }
            return (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-foreground uppercase tracking-wide text-[11px]">Executive Summary</span>
                  {posture && (
                    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium capitalize ${POSTURE_CLASS[posture] ?? 'border-border bg-surface-3 text-muted'}`}>
                      {posture} risk
                    </span>
                  )}
                </div>
                <p className="text-foreground leading-relaxed whitespace-pre-line">{narrative}</p>
                {concerns.length > 0 && (
                  <ul className="space-y-1">
                    {concerns.map((c, i) => (
                      <li key={i} className="flex items-start gap-2 text-muted">
                        <span className="text-amber-400 mt-px shrink-0">▸</span>
                        <span>{safeStr(c)}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {note && (
                  <p className="text-[11px] text-muted border-t border-border pt-2">{note}</p>
                )}
              </>
            );
          })()}
        </div>
      )}

      {exportError && (
        <p className="text-xs text-red-300">{exportError}</p>
      )}

      {verifyResult && (
        <div className="flex flex-wrap gap-3 text-xs p-2 rounded border border-border bg-surface-3">
          {verifyResult.valid ? (
            <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-green-500/30 bg-green-500/5 text-green-300 font-medium">
              ✓ Signature Verified
            </span>
          ) : (
            <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-red-500/30 bg-red-500/5 text-red-300 font-medium">
              ✗ Signature Invalid
            </span>
          )}
          <span className="text-muted font-mono truncate max-w-[180px]">
            {verifyResult.manifest_hash}
          </span>
        </div>
      )}
    </div>
  );
}

const PAGE_SIZE = 10;

function ReportsPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') || getStoredEngagementId();

  const [reports, setReports] = useState<ReportVersionSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const seqRef = useRef(0);

  const load = useCallback(
    async (offset: number) => {
      if (!engagementId) return;
      const seq = ++seqRef.current;
      setLoading(true);
      setError(null);
      try {
        const result = await portalApi.listReports(engagementId, { limit: PAGE_SIZE, offset });
        if (seq !== seqRef.current) return;
        setReports(result.items);
        setTotal(result.total);
      } catch (e) {
        if (seq !== seqRef.current) return;
        setError(
          e instanceof PortalApiError && e.status === 404
            ? 'Engagement not found.'
            : 'Failed to load reports.',
        );
      } finally {
        if (seq !== seqRef.current) return;
        setLoading(false);
      }
    },
    [engagementId],
  );

  useEffect(() => {
    setPage(0);
    load(0);
  }, [load]);

  function handlePage(newPage: number) {
    setPage(newPage);
    load(newPage * PAGE_SIZE);
  }

  const totalPages = Math.ceil(total / PAGE_SIZE);

  if (!engagementId) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <p className="text-sm font-semibold text-foreground">No engagement selected</p>
        <p className="mt-1 text-xs text-muted">
          <Link href="/" className="underline hover:text-foreground transition-colors">
            Select an engagement from the dashboard.
          </Link>
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4" aria-label="reports-page">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-foreground">Reports</h2>
          {!loading && total > 0 && (
            <p className="text-xs text-muted mt-0.5">{total} version{total !== 1 ? 's' : ''}</p>
          )}
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

      {!loading && !error && reports.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center text-muted">
          <p className="text-sm font-medium">No reports available</p>
          <p className="text-xs mt-1">Reports will appear here once generated by your assessor.</p>
        </div>
      )}

      {!loading && reports.length > 0 && (
        <>
          <div className="space-y-2">
            {reports.map((r) => (
              <ReportRow key={r.report_id} report={r} engagementId={engagementId} />
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

export default function ReportsPage() {
  return (
    <Suspense fallback={<div className="space-y-2" aria-busy="true">{[1,2,3].map(i=><div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse"/>)}</div>}>
      <ReportsPageInner />
    </Suspense>
  );
}
