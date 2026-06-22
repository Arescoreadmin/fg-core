'use client';

import { useCallback, useEffect, useState } from 'react';
import { Button } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type ReportVersionSummary } from '@/lib/fieldAssessmentApi';

const PAGE_SIZE = 10;

const STATUS_LABEL: Record<string, string> = {
  finalized: 'Finalized',
  draft: 'Draft',
  generating: 'Generating',
  ready: 'Ready',
  failed: 'Failed',
  superseded: 'Superseded',
};

const STATUS_COLOR: Record<string, string> = {
  finalized: 'text-success border-success/30 bg-success/5',
  ready: 'text-success border-success/30 bg-success/5',
  draft: 'text-muted border-border bg-surface-2',
  generating: 'text-warning border-warning/30 bg-warning/5',
  failed: 'text-danger border-danger/30 bg-danger/5',
  superseded: 'text-muted border-border bg-surface-2',
};

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? 'text-muted border-border bg-surface-2';
  const label = STATUS_LABEL[status] ?? status;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${color}`}>
      {label}
    </span>
  );
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

interface Props {
  engagementId: string;
  refreshKey: number;
  selectedVersion: number | null;
  onSelectVersion: (version: number) => void;
  onQaApproved?: () => void;
}

export function ReportVersionHistory({ engagementId, refreshKey, selectedVersion, onSelectVersion, onQaApproved }: Props) {
  const [versions, setVersions] = useState<ReportVersionSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [reviewerName, setReviewerName] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [approveError, setApproveError] = useState<string | null>(null);
  const [clientAccessCode, setClientAccessCode] = useState<string | null>(null);

  const loadVersions = useCallback(async (offset: number) => {
    setLoading(true);
    setError(null);
    try {
      const result = await fieldAssessmentApi.listReports(engagementId, {
        limit: PAGE_SIZE,
        offset,
      });
      setVersions(result.items);
      setTotal(result.total);
    } catch {
      setError('Failed to load report versions.');
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    setPage(0);
    loadVersions(0);
  }, [refreshKey, loadVersions]);

  function handlePage(newPage: number) {
    setPage(newPage);
    loadVersions(newPage * PAGE_SIZE);
  }

  function openConfirm(e: React.MouseEvent, reportId: string) {
    e.stopPropagation();
    setConfirmingId(reportId);
    setReviewerName('');
    setConfirmed(false);
    setApproveError(null);
  }

  function cancelConfirm(e: React.MouseEvent) {
    e.stopPropagation();
    setConfirmingId(null);
  }

  async function handleQaApprove(e: React.MouseEvent) {
    e.stopPropagation();
    if (!confirmingId || !confirmed) return;
    setApprovingId(confirmingId);
    setApproveError(null);
    setClientAccessCode(null);
    try {
      const result = await fieldAssessmentApi.qaApproveReport(engagementId, confirmingId, reviewerName.trim() || undefined);
      if (result.client_access_code) {
        setClientAccessCode(result.client_access_code);
      }
      setConfirmingId(null);
      loadVersions(page * PAGE_SIZE);
      onQaApproved?.();
    } catch (err) {
      setApproveError(err instanceof Error ? err.message : 'QA approval failed');
    } finally {
      setApprovingId(null);
    }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="space-y-2" aria-label="report-version-history">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold text-muted uppercase tracking-wider">
          Report Versions {total > 0 && `(${total})`}
        </p>
        {totalPages > 1 && (
          <div className="flex items-center gap-1 text-xs text-muted">
            <button
              className="px-1.5 py-0.5 rounded border border-border hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
              onClick={() => handlePage(page - 1)}
              disabled={page === 0 || loading}
              aria-label="Previous page"
            >
              ‹
            </button>
            <span>{page + 1} / {totalPages}</span>
            <button
              className="px-1.5 py-0.5 rounded border border-border hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
              onClick={() => handlePage(page + 1)}
              disabled={page >= totalPages - 1 || loading}
              aria-label="Next page"
            >
              ›
            </button>
          </div>
        )}
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {error && !loading && (
        <Alert variant="destructive">
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
      )}

      {!loading && !error && versions.length === 0 && (
        <div className="flex flex-col items-center justify-center py-10 text-center text-muted">
          <p className="text-sm font-medium">No reports yet</p>
          <p className="text-xs mt-1">Generate a report using the panel above</p>
        </div>
      )}

      {approveError && (
        <Alert variant="destructive">
          <AlertDescription className="text-xs">{approveError}</AlertDescription>
        </Alert>
      )}

      {clientAccessCode && (
        <div className="p-3 rounded border border-success/40 bg-success/5 space-y-1">
          <p className="text-xs font-semibold text-success uppercase tracking-wider">Report Delivered — Client Access Code</p>
          <p className="font-mono text-lg font-bold text-foreground tracking-widest">{clientAccessCode}</p>
          <p className="text-xs text-muted">Give this code to the client. It is their access key for the delivered report.</p>
        </div>
      )}

      {!loading && versions.length > 0 && (
        <div className="space-y-1.5">
          {versions.map((v) => {
            const isSelected = selectedVersion === v.version;
            const isApproving = approvingId === v.report_id;
            return (
              <div
                key={v.report_id}
                className={`p-3 rounded border text-xs cursor-pointer transition-colors ${
                  isSelected
                    ? 'border-primary/50 bg-primary/5'
                    : 'border-border bg-surface-2 hover:bg-surface-3'
                }`}
                onClick={() => onSelectVersion(v.version)}
                role="button"
                aria-pressed={isSelected}
                tabIndex={0}
                onKeyDown={(e) => e.key === 'Enter' && onSelectVersion(v.version)}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-semibold text-foreground">v{v.version}</span>
                  <StatusBadge status={v.status} />
                  {v.report_type && (
                    <span className="capitalize text-muted">{v.report_type.replace(/_/g, ' ')}</span>
                  )}
                  <span className="ml-auto text-muted">{formatDate(v.compiled_at)}</span>
                </div>
                {v.compiled_by && (
                  <div className="mt-1 text-muted">
                    Compiled by: <span className="text-foreground">{v.compiled_by}</span>
                  </div>
                )}
                {v.qa_approved_by && v.qa_approved_at && (
                  <div className="mt-1 text-emerald-300 text-[11px]">
                    QA approved by <span className="font-medium">{v.qa_approved_by}</span>
                    {' · '}{formatDate(v.qa_approved_at)}
                  </div>
                )}

                {/* QA Approve — inline confirmation step */}
                {v.status === 'finalized' && !v.qa_approved_by && (
                  <div className="mt-2" onClick={(e) => e.stopPropagation()}>
                    {confirmingId !== v.report_id ? (
                      <Button
                        type="button"
                        disabled={isApproving}
                        onClick={(e) => openConfirm(e, v.report_id)}
                        className="h-6 text-[11px] px-2"
                      >
                        QA Approve
                      </Button>
                    ) : (
                      <div className="mt-1 space-y-2 rounded border border-primary/30 bg-primary/5 p-2">
                        <p className="text-[11px] font-medium text-foreground">Confirm QA approval</p>
                        <p className="text-[11px] text-muted">
                          This marks the report as reviewed and ready for client delivery. The approval is recorded in the audit log and cannot be undone.
                        </p>
                        <div className="space-y-1">
                          <label className="text-[11px] text-muted" htmlFor={`reviewer-${v.report_id}`}>
                            Reviewer name <span className="text-foreground">(who is approving this?)</span>
                          </label>
                          <input
                            id={`reviewer-${v.report_id}`}
                            type="text"
                            placeholder="e.g. Jane Smith, Senior Assessor"
                            value={reviewerName}
                            onChange={(e) => setReviewerName(e.target.value)}
                            className="w-full rounded border border-border bg-surface-1 px-2 py-1 text-xs text-foreground placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary/40"
                          />
                        </div>
                        <label className="flex items-start gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={confirmed}
                            onChange={(e) => setConfirmed(e.target.checked)}
                            className="mt-0.5 shrink-0"
                          />
                          <span className="text-[11px] text-foreground">
                            I confirm I have reviewed this report and it is accurate and ready for client delivery.
                          </span>
                        </label>
                        <div className="flex gap-2">
                          <Button
                            type="button"
                            disabled={!confirmed || isApproving || !reviewerName.trim()}
                            onClick={handleQaApprove}
                            className="h-6 text-[11px] px-2"
                          >
                            {isApproving ? 'Approving…' : 'Confirm Approval'}
                          </Button>
                          <button
                            type="button"
                            onClick={cancelConfirm}
                            className="text-[11px] text-muted hover:text-foreground"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
