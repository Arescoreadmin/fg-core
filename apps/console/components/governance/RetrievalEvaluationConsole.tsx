'use client';

import { useState, useCallback } from 'react';
import {
  getEvaluationRuns,
  getEvaluationRun,
  getEvaluationQuality,
  type EvaluationRun,
  type EvaluationRunPage,
  type EvaluationQualitySummary,
  type EvaluationRunStatus,
  type EvaluationRunsQuery,
} from '@/lib/coreApi';
import { toErrorDisplay } from '@/lib/errors';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusLabel(status: EvaluationRunStatus): string {
  switch (status) {
    case 'pending': return 'Pending';
    case 'running': return 'Running';
    case 'completed': return 'Completed';
    case 'failed': return 'Failed';
    default: return status;
  }
}

function statusClass(status: EvaluationRunStatus): string {
  switch (status) {
    case 'pending': return 'text-muted';
    case 'running': return 'text-warning';
    case 'completed': return 'text-success';
    case 'failed': return 'text-danger';
    default: return 'text-muted';
  }
}

function normalizeError(err: unknown): string {
  const display = toErrorDisplay(err) as Partial<{ message: string }>;
  return display?.message || (err instanceof Error ? err.message : 'An error occurred');
}

function hasIndicators(obj: Record<string, unknown>): boolean {
  return obj != null && Object.keys(obj).length > 0;
}

// ─── RetrievalEvaluationPanel ─────────────────────────────────────────────────

export interface RetrievalEvaluationPanelProps {
  runs: EvaluationRun[];
  loading: boolean;
  error: string | null;
  total: number;
  limit: number;
  offset: number;
  onPageChange: (offset: number) => void;
  onRunSelect: (run: EvaluationRun) => void;
}

export function RetrievalEvaluationPanel({
  runs,
  loading,
  error,
  total,
  limit,
  offset,
  onPageChange,
  onRunSelect,
}: RetrievalEvaluationPanelProps) {
  if (loading && runs.length === 0) {
    return (
      <div aria-label="evaluation-runs-loading" className="text-muted text-sm py-4">
        Loading evaluation runs…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="evaluation-runs-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (runs.length === 0) {
    return (
      <div aria-label="evaluation-runs-empty" className="text-muted text-sm py-4">
        No evaluation runs found. Evaluation runs are created by the evaluation pipeline.
      </div>
    );
  }

  const hasPrev = offset > 0;
  const hasNext = offset + limit < total;

  return (
    <div aria-label="retrieval-evaluation-panel" className="space-y-3">
      <div className="text-xs text-muted">
        Showing {offset + 1}–{Math.min(offset + runs.length, total)} of {total}
      </div>
      <div className="space-y-2">
        {runs.map((run) => (
          <button
            key={run.run_ref}
            onClick={() => onRunSelect(run)}
            aria-label={`evaluation-run-${run.run_ref}`}
            className="w-full text-left rounded border border-border bg-surface-2 px-4 py-3 hover:border-primary/50 transition-colors"
          >
            <div className="flex flex-wrap items-center gap-4">
              <span className="font-mono text-xs text-foreground truncate max-w-xs">
                {run.run_ref}
              </span>
              <span className={`text-xs ${statusClass(run.status)}`}>
                {statusLabel(run.status)}
              </span>
              {run.corpus_id && (
                <span className="text-xs text-muted">corpus: {run.corpus_id}</span>
              )}
              <span className="text-xs text-muted">
                {run.query_count} queries
              </span>
              {run.created_at && (
                <span className="text-xs text-muted">
                  {run.created_at.slice(0, 16)}
                </span>
              )}
            </div>
          </button>
        ))}
      </div>
      {(hasPrev || hasNext) && (
        <div className="flex gap-2 pt-1">
          <button
            onClick={() => onPageChange(Math.max(0, offset - limit))}
            disabled={!hasPrev || loading}
            aria-label="Previous page"
            className="text-xs text-muted border border-border rounded px-2 py-1 hover:text-foreground disabled:opacity-40"
          >
            Previous
          </button>
          <button
            onClick={() => onPageChange(offset + limit)}
            disabled={!hasNext || loading}
            aria-label="Next page"
            className="text-xs text-muted border border-border rounded px-2 py-1 hover:text-foreground disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

// ─── RetrievalQualityPanel ────────────────────────────────────────────────────

export interface RetrievalQualityPanelProps {
  summary: EvaluationQualitySummary | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export function RetrievalQualityPanel({
  summary,
  loading,
  error,
  onRefresh,
}: RetrievalQualityPanelProps) {
  if (loading && !summary) {
    return (
      <div aria-label="quality-summary-loading" className="text-muted text-sm py-4">
        Loading quality summary…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="quality-summary-error" className="text-danger text-sm py-4">
        {error}
        <button
          onClick={onRefresh}
          aria-label="Retry quality summary"
          className="ml-2 text-xs underline text-muted hover:text-foreground"
        >
          Retry
        </button>
      </div>
    );
  }
  if (!summary) {
    return (
      <div aria-label="quality-summary-empty" className="text-muted text-sm py-4">
        No quality summary available.
      </div>
    );
  }

  return (
    <div aria-label="retrieval-quality-panel" className="space-y-3">
      <div className="rounded border border-border bg-surface-2 px-4 py-3 text-xs text-muted">
        {summary.quality_note}
      </div>
      {!summary.evaluation_algorithms_available && (
        <div aria-label="no-algorithms-notice" className="text-xs text-muted">
          Evaluation algorithms not yet deployed. This panel shows structural run metadata only.
        </div>
      )}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div
          aria-label="completed-runs-count"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className="text-xl font-semibold text-foreground">
            {summary.completed_run_count}
          </div>
          <div className="text-xs text-muted mt-1">Completed runs</div>
        </div>
        <div
          aria-label="total-queries-count"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className="text-xl font-semibold text-foreground">
            {summary.total_queries_evaluated}
          </div>
          <div className="text-xs text-muted mt-1">Queries evaluated</div>
        </div>
        <div
          aria-label="relevance-indicator-count"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className="text-xl font-semibold text-foreground">
            {summary.runs_with_relevance_indicators}
          </div>
          <div className="text-xs text-muted mt-1">With relevance data</div>
        </div>
      </div>
    </div>
  );
}

// ─── Run detail inline view ───────────────────────────────────────────────────

interface EvaluationRunDetailProps {
  run: EvaluationRun;
  onClose: () => void;
}

function EvaluationRunDetail({ run, onClose }: EvaluationRunDetailProps) {
  return (
    <div
      aria-label={`evaluation-run-detail-${run.run_ref}`}
      className="rounded border border-border bg-surface-2 px-4 py-4 space-y-3"
    >
      <div className="flex items-center justify-between">
        <h4 className="font-mono text-sm font-semibold text-foreground truncate">
          {run.run_ref}
        </h4>
        <button
          onClick={onClose}
          aria-label="Close run detail"
          className="text-xs text-muted hover:text-foreground"
        >
          Close
        </button>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-muted">Status: </span>
          <span className={statusClass(run.status)}>{statusLabel(run.status)}</span>
        </div>
        {run.corpus_id && (
          <div>
            <span className="text-muted">Corpus: </span>
            <span className="font-mono text-foreground">{run.corpus_id}</span>
          </div>
        )}
        <div>
          <span className="text-muted">Queries: </span>
          <span className="text-foreground">{run.query_count}</span>
        </div>
        {run.evaluator_ref && (
          <div>
            <span className="text-muted">Evaluator: </span>
            <span className="font-mono text-foreground">{run.evaluator_ref}</span>
          </div>
        )}
        {run.started_at && (
          <div>
            <span className="text-muted">Started: </span>
            <span className="text-foreground">{run.started_at.slice(0, 16)}</span>
          </div>
        )}
        {run.completed_at && (
          <div>
            <span className="text-muted">Completed: </span>
            <span className="text-foreground">{run.completed_at.slice(0, 16)}</span>
          </div>
        )}
      </div>
      <div className="space-y-2 text-xs">
        <div aria-label="relevance-indicators">
          <span className="text-muted font-semibold">Relevance indicators: </span>
          {hasIndicators(run.relevance_indicators)
            ? <span className="text-success">Present</span>
            : <span className="text-muted">None</span>}
        </div>
        <div aria-label="coverage-indicators">
          <span className="text-muted font-semibold">Coverage indicators: </span>
          {hasIndicators(run.coverage_indicators)
            ? <span className="text-success">Present</span>
            : <span className="text-muted">None</span>}
        </div>
        <div aria-label="correctness-indicators">
          <span className="text-muted font-semibold">Correctness indicators: </span>
          {hasIndicators(run.correctness_indicators)
            ? <span className="text-success">Present</span>
            : <span className="text-muted">None</span>}
        </div>
      </div>
    </div>
  );
}

// ─── RetrievalEvaluationConsole ───────────────────────────────────────────────

export interface RetrievalEvaluationConsoleProps {
  defaultTab?: 'runs' | 'quality';
}

type EvalTab = 'runs' | 'quality';

export function RetrievalEvaluationConsole({
  defaultTab = 'runs',
}: RetrievalEvaluationConsoleProps) {
  const [tab, setTab] = useState<EvalTab>(defaultTab);

  const [runsPage, setRunsPage] = useState<EvaluationRunPage | null>(null);
  const [runsLoading, setRunsLoading] = useState(false);
  const [runsError, setRunsError] = useState<string | null>(null);
  const [runsOffset, setRunsOffset] = useState(0);
  const runsLimit = 20;

  const [selectedRun, setSelectedRun] = useState<EvaluationRun | null>(null);

  const [quality, setQuality] = useState<EvaluationQualitySummary | null>(null);
  const [qualityLoading, setQualityLoading] = useState(false);
  const [qualityError, setQualityError] = useState<string | null>(null);

  const loadRuns = useCallback(async (offset: number) => {
    setRunsLoading(true);
    setRunsError(null);
    try {
      const page = await getEvaluationRuns({ limit: runsLimit, offset });
      setRunsPage(page);
      setRunsOffset(offset);
    } catch (err) {
      setRunsError(normalizeError(err));
    } finally {
      setRunsLoading(false);
    }
  }, [runsLimit]);

  const loadQuality = useCallback(async () => {
    setQualityLoading(true);
    setQualityError(null);
    try {
      const summary = await getEvaluationQuality();
      setQuality(summary);
    } catch (err) {
      setQualityError(normalizeError(err));
    } finally {
      setQualityLoading(false);
    }
  }, []);

  function handleTabChange(newTab: EvalTab) {
    setTab(newTab);
    if (newTab === 'runs' && !runsPage && !runsLoading) {
      loadRuns(0);
    }
    if (newTab === 'quality' && !quality && !qualityLoading) {
      loadQuality();
    }
  }

  const tabs: { id: EvalTab; label: string }[] = [
    { id: 'runs', label: 'Evaluation Runs' },
    { id: 'quality', label: 'Quality Summary' },
  ];

  return (
    <div aria-label="retrieval-evaluation-console" className="space-y-4">
      <nav aria-label="evaluation-tabs" className="flex gap-1 flex-wrap">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => handleTabChange(t.id)}
            aria-label={`tab-${t.id}`}
            aria-pressed={tab === t.id}
            className={`rounded px-3 py-1.5 text-xs font-medium border transition-colors ${
              tab === t.id
                ? 'border-primary bg-primary/10 text-primary'
                : 'border-border text-muted hover:text-foreground'
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <div className="mt-4">
        {tab === 'runs' && (
          <section aria-label="runs-tab-content">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-foreground">Evaluation Runs</h3>
              <button
                onClick={() => loadRuns(runsOffset)}
                disabled={runsLoading}
                aria-label="Refresh evaluation runs"
                className="text-xs text-muted hover:text-foreground disabled:opacity-40"
              >
                {runsLoading ? 'Loading…' : 'Refresh'}
              </button>
            </div>
            {selectedRun ? (
              <EvaluationRunDetail
                run={selectedRun}
                onClose={() => setSelectedRun(null)}
              />
            ) : (
              <RetrievalEvaluationPanel
                runs={runsPage?.runs ?? []}
                loading={runsLoading}
                error={runsError}
                total={runsPage?.total ?? 0}
                limit={runsLimit}
                offset={runsOffset}
                onPageChange={(offset) => loadRuns(offset)}
                onRunSelect={setSelectedRun}
              />
            )}
          </section>
        )}

        {tab === 'quality' && (
          <section aria-label="quality-tab-content">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-foreground">Quality Summary</h3>
              <button
                onClick={loadQuality}
                disabled={qualityLoading}
                aria-label="Refresh quality summary"
                className="text-xs text-muted hover:text-foreground disabled:opacity-40"
              >
                {qualityLoading ? 'Loading…' : 'Refresh'}
              </button>
            </div>
            <RetrievalQualityPanel
              summary={quality}
              loading={qualityLoading}
              error={qualityError}
              onRefresh={loadQuality}
            />
          </section>
        )}
      </div>
    </div>
  );
}
