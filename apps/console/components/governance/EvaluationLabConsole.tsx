'use client';

import { useState, useCallback } from 'react';
import {
  getEvaluationQuerySets,
  getEvaluationQuerySetDetail,
  getEvaluationRunComparison,
  getEvaluationRunConfidence,
  getEvaluationRunHallucination,
  getEvaluationRunReranker,
  getEvaluationRunExport,
  getEvaluationRuns,
  type EvaluationQuerySetRecord,
  type EvaluationQuerySetDetail,
  type EvaluationQuerySetsPage,
  type EvaluationRunComparison,
  type EvaluationRunConfidence,
  type EvaluationRunHallucination,
  type EvaluationRunReranker,
  type EvaluationRunExport,
  type EvaluationRunPage,
} from '@/lib/coreApi';
import { toErrorDisplay } from '@/lib/errors';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeError(err: unknown): string {
  const display = toErrorDisplay(err) as Partial<{ message: string }>;
  return display?.message || (err instanceof Error ? err.message : 'An error occurred');
}

function safeStr(v: unknown): string {
  if (v == null) return '—';
  return String(v);
}

// ─── QuerySetPanel ────────────────────────────────────────────────────────────

export interface QuerySetPanelProps {
  page: EvaluationQuerySetsPage | null;
  loading: boolean;
  error: string | null;
  onPageChange: (offset: number) => void;
  onSetSelect: (s: EvaluationQuerySetRecord) => void;
}

export function QuerySetPanel({
  page,
  loading,
  error,
  onPageChange,
  onSetSelect,
}: QuerySetPanelProps) {
  if (loading && !page) {
    return (
      <div aria-label="query-sets-loading" className="text-muted text-sm py-4">
        Loading query sets…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="query-sets-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!page || page.query_sets.length === 0) {
    return (
      <div aria-label="query-sets-empty" className="text-muted text-sm py-4">
        No evaluation query sets found. Query sets define expected sources and retrieval
        expectations for evaluation runs.
      </div>
    );
  }

  const { query_sets, total, limit, offset } = page;
  const hasPrev = offset > 0;
  const hasNext = offset + limit < total;

  return (
    <div aria-label="query-set-panel" className="space-y-3">
      <div className="text-xs text-muted">
        Showing {offset + 1}–{Math.min(offset + query_sets.length, total)} of {total}
      </div>
      <div className="space-y-2">
        {query_sets.map((qs) => (
          <button
            key={qs.set_ref}
            onClick={() => onSetSelect(qs)}
            aria-label={`query-set-${qs.set_ref}`}
            className="w-full text-left rounded border border-border bg-surface-2 px-4 py-3 hover:border-primary/50 transition-colors"
          >
            <div className="flex flex-wrap items-center gap-4">
              <span className="font-semibold text-xs text-foreground truncate max-w-xs">
                {qs.name}
              </span>
              <span className="font-mono text-xs text-muted truncate max-w-xs">
                {qs.set_ref}
              </span>
              {qs.corpus_id && (
                <span className="text-xs text-muted">corpus: {qs.corpus_id}</span>
              )}
              {qs.created_at && (
                <span className="text-xs text-muted">{qs.created_at.slice(0, 10)}</span>
              )}
            </div>
            {qs.description && (
              <div className="mt-1 text-xs text-muted truncate">{qs.description}</div>
            )}
          </button>
        ))}
      </div>
      {(hasPrev || hasNext) && (
        <div className="flex gap-2 pt-1">
          <button
            onClick={() => onPageChange(Math.max(0, offset - limit))}
            disabled={!hasPrev || loading}
            aria-label="Previous query sets page"
            className="text-xs text-muted border border-border rounded px-2 py-1 hover:text-foreground disabled:opacity-40"
          >
            Previous
          </button>
          <button
            onClick={() => onPageChange(offset + limit)}
            disabled={!hasNext || loading}
            aria-label="Next query sets page"
            className="text-xs text-muted border border-border rounded px-2 py-1 hover:text-foreground disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

// ─── QuerySetDetailView ───────────────────────────────────────────────────────

interface QuerySetDetailViewProps {
  detail: EvaluationQuerySetDetail;
  onClose: () => void;
}

function QuerySetDetailView({ detail, onClose }: QuerySetDetailViewProps) {
  return (
    <div
      aria-label={`query-set-detail-${detail.set_ref}`}
      className="rounded border border-border bg-surface-2 px-4 py-4 space-y-4"
    >
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-foreground truncate">{detail.name}</h4>
        <button
          onClick={onClose}
          aria-label="Close query set detail"
          className="text-xs text-muted hover:text-foreground"
        >
          Close
        </button>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-muted">Ref: </span>
          <span className="font-mono text-foreground">{detail.set_ref}</span>
        </div>
        {detail.corpus_id && (
          <div>
            <span className="text-muted">Corpus: </span>
            <span className="font-mono text-foreground">{detail.corpus_id}</span>
          </div>
        )}
        <div>
          <span className="text-muted">Items: </span>
          <span className="text-foreground">{detail.items_total}</span>
        </div>
        {detail.created_at && (
          <div>
            <span className="text-muted">Created: </span>
            <span className="text-foreground">{detail.created_at.slice(0, 16)}</span>
          </div>
        )}
      </div>
      {detail.description && (
        <div className="text-xs text-muted">{detail.description}</div>
      )}
      {detail.items.length > 0 ? (
        <div aria-label="query-items-list" className="space-y-2">
          <div className="text-xs font-semibold text-foreground">
            Query Items ({detail.items.length} of {detail.items_total})
          </div>
          {detail.items.map((item) => (
            <div
              key={item.item_ref}
              aria-label={`query-item-${item.item_ref}`}
              className="rounded border border-border bg-surface-3 px-3 py-2 text-xs space-y-1"
            >
              <div className="flex flex-wrap gap-3">
                <span className="font-mono text-muted truncate">{item.item_ref}</span>
                {item.query_category && (
                  <span className="text-muted">category: {item.query_category}</span>
                )}
              </div>
              <div aria-label="expected-sources" className="flex flex-wrap gap-2 text-muted">
                <span>Expected sources: {item.expected_source_ids.length}</span>
                <span>Expected chunks: {item.expected_chunk_ids.length}</span>
                <span>Source hashes: {item.expected_source_hashes.length}</span>
                <span>Provenance IDs: {item.expected_provenance_ids.length}</span>
              </div>
              {item.operator_notes && (
                <div className="text-muted italic">{item.operator_notes}</div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div aria-label="query-items-empty" className="text-muted text-xs">
          No query items in this set.
        </div>
      )}
    </div>
  );
}

// ─── RetrievalPrecisionPanel ──────────────────────────────────────────────────

export interface RetrievalPrecisionPanelProps {
  comparison: EvaluationRunComparison | null;
  loading: boolean;
  error: string | null;
  runRef: string | null;
  onLoad: (runRef: string) => void;
}

export function RetrievalPrecisionPanel({
  comparison,
  loading,
  error,
  runRef,
  onLoad,
}: RetrievalPrecisionPanelProps) {
  const [input, setInput] = useState(runRef ?? '');

  if (!comparison && !loading && !error) {
    return (
      <div aria-label="retrieval-precision-panel" className="space-y-3">
        <div className="text-xs text-muted">
          Enter a run reference to view retrieval comparison metadata.
        </div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Run reference input"
            placeholder="run_ref"
            className="flex-1 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground"
          />
          <button
            onClick={() => input && onLoad(input.trim())}
            disabled={!input.trim() || loading}
            aria-label="Load retrieval comparison"
            className="rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Load
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div aria-label="retrieval-precision-loading" className="text-muted text-sm py-4">
        Loading retrieval comparison…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="retrieval-precision-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!comparison) return null;

  const rc = comparison.retrieval_comparison;

  return (
    <div aria-label="retrieval-precision-panel" className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3">
        <div
          aria-label="has-relevance-data"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${rc.has_relevance_data ? 'text-success' : 'text-muted'}`}>
            {rc.has_relevance_data ? 'Present' : 'None'}
          </div>
          <div className="text-xs text-muted mt-1">Relevance data</div>
        </div>
        <div
          aria-label="has-coverage-data"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${rc.has_coverage_data ? 'text-success' : 'text-muted'}`}>
            {rc.has_coverage_data ? 'Present' : 'None'}
          </div>
          <div className="text-xs text-muted mt-1">Coverage data</div>
        </div>
        <div
          aria-label="reranker-comparison-available"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${rc.reranker_comparison_available ? 'text-success' : 'text-muted'}`}>
            {rc.reranker_comparison_available ? 'Available' : 'Not available'}
          </div>
          <div className="text-xs text-muted mt-1">Reranker comparison</div>
        </div>
      </div>
      {rc.retrieval_strategy && (
        <div className="text-xs text-muted">
          Strategy: <span className="font-mono text-foreground">{rc.retrieval_strategy}</span>
        </div>
      )}
      <div
        aria-label="precision-note"
        className="rounded border border-border bg-surface-2 px-3 py-2 text-xs text-muted"
      >
        {rc.comparison_note}
      </div>
      {!rc.has_relevance_data && !rc.has_coverage_data && (
        <div aria-label="no-precision-data-notice" className="text-xs text-muted">
          Retrieval precision data is not yet available for this run. Evaluation algorithms
          are external — this panel shows structural indicator presence only.
        </div>
      )}
    </div>
  );
}

// ─── GroundingReviewPanel ─────────────────────────────────────────────────────

export interface GroundingReviewPanelProps {
  hallucination: EvaluationRunHallucination | null;
  loading: boolean;
  error: string | null;
  runRef: string | null;
  onLoad: (runRef: string) => void;
}

export function GroundingReviewPanel({
  hallucination,
  loading,
  error,
  runRef,
  onLoad,
}: GroundingReviewPanelProps) {
  const [input, setInput] = useState(runRef ?? '');

  if (!hallucination && !loading && !error) {
    return (
      <div aria-label="grounding-review-panel" className="space-y-3">
        <div className="text-xs text-muted">
          Enter a run reference to view grounding review metadata.
        </div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Run reference input for grounding"
            placeholder="run_ref"
            className="flex-1 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground"
          />
          <button
            onClick={() => input && onLoad(input.trim())}
            disabled={!input.trim() || loading}
            aria-label="Load grounding review"
            className="rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Load
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div aria-label="grounding-review-loading" className="text-muted text-sm py-4">
        Loading grounding review…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="grounding-review-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!hallucination) return null;

  const hr = hallucination.hallucination_review;

  return (
    <div aria-label="grounding-review-panel" className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3">
        <div
          aria-label="grounding-data-available"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${hr.grounding_data_available ? 'text-success' : 'text-muted'}`}>
            {hr.grounding_data_available ? 'Present' : 'None'}
          </div>
          <div className="text-xs text-muted mt-1">Grounding data</div>
        </div>
        {hr.missing_evidence_count != null && (
          <div
            aria-label="missing-evidence-count"
            className="rounded border border-border bg-surface-2 px-3 py-2"
          >
            <div className="text-sm font-semibold text-foreground">
              {hr.missing_evidence_count}
            </div>
            <div className="text-xs text-muted mt-1">Missing evidence</div>
          </div>
        )}
        {hr.weak_grounding_count != null && (
          <div
            aria-label="weak-grounding-count"
            className="rounded border border-border bg-surface-2 px-3 py-2"
          >
            <div className="text-sm font-semibold text-foreground">
              {hr.weak_grounding_count}
            </div>
            <div className="text-xs text-muted mt-1">Weak grounding</div>
          </div>
        )}
      </div>
      <div
        aria-label="grounding-review-note"
        className="rounded border border-border bg-surface-2 px-3 py-2 text-xs text-muted"
      >
        {hr.review_note}
      </div>
    </div>
  );
}

// ─── HallucinationReviewPanel ─────────────────────────────────────────────────

export interface HallucinationReviewPanelProps {
  hallucination: EvaluationRunHallucination | null;
  loading: boolean;
  error: string | null;
  runRef: string | null;
  onLoad: (runRef: string) => void;
}

export function HallucinationReviewPanel({
  hallucination,
  loading,
  error,
  runRef,
  onLoad,
}: HallucinationReviewPanelProps) {
  const [input, setInput] = useState(runRef ?? '');

  if (!hallucination && !loading && !error) {
    return (
      <div aria-label="hallucination-review-panel" className="space-y-3">
        <div className="text-xs text-muted">
          Enter a run reference to view hallucination review metadata.
        </div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Run reference input for hallucination"
            placeholder="run_ref"
            className="flex-1 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground"
          />
          <button
            onClick={() => input && onLoad(input.trim())}
            disabled={!input.trim() || loading}
            aria-label="Load hallucination review"
            className="rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Load
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div aria-label="hallucination-review-loading" className="text-muted text-sm py-4">
        Loading hallucination review…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="hallucination-review-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!hallucination) return null;

  const hr = hallucination.hallucination_review;

  return (
    <div aria-label="hallucination-review-panel" className="space-y-3">
      <div
        aria-label="heuristic-label"
        className="inline-flex items-center rounded border border-warning/40 bg-warning/10 px-2 py-1 text-xs text-warning"
      >
        {hr.review_type === 'heuristic' ? 'Heuristic review — operator validation required' : hr.review_type}
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3">
        <div
          aria-label="unsupported-answer-detection"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${hr.unsupported_answer_detection_available ? 'text-success' : 'text-muted'}`}>
            {hr.unsupported_answer_detection_available ? 'Available' : 'Not available'}
          </div>
          <div className="text-xs text-muted mt-1">Unsupported answer detection</div>
        </div>
        <div
          aria-label="evidence-mismatch-available"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${hr.evidence_mismatch_available ? 'text-success' : 'text-muted'}`}>
            {hr.evidence_mismatch_available ? 'Available' : 'Not available'}
          </div>
          <div className="text-xs text-muted mt-1">Evidence mismatch</div>
        </div>
        <div
          aria-label="export-safe-flag"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className="text-sm font-semibold text-success">
            {hr.export_safe ? 'Yes' : 'No'}
          </div>
          <div className="text-xs text-muted mt-1">Export safe</div>
        </div>
      </div>
      <div
        aria-label="hallucination-review-note"
        className="rounded border border-border bg-surface-2 px-3 py-2 text-xs text-muted"
      >
        {hr.review_note}
      </div>
    </div>
  );
}

// ─── ConfidenceDistributionPanel ──────────────────────────────────────────────

export interface ConfidenceDistributionPanelProps {
  confidence: EvaluationRunConfidence | null;
  loading: boolean;
  error: string | null;
  runRef: string | null;
  onLoad: (runRef: string) => void;
}

export function ConfidenceDistributionPanel({
  confidence,
  loading,
  error,
  runRef,
  onLoad,
}: ConfidenceDistributionPanelProps) {
  const [input, setInput] = useState(runRef ?? '');

  if (!confidence && !loading && !error) {
    return (
      <div aria-label="confidence-distribution-panel" className="space-y-3">
        <div className="text-xs text-muted">
          Enter a run reference to view confidence distribution metadata.
        </div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Run reference input for confidence"
            placeholder="run_ref"
            className="flex-1 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground"
          />
          <button
            onClick={() => input && onLoad(input.trim())}
            disabled={!input.trim() || loading}
            aria-label="Load confidence distribution"
            className="rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Load
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div aria-label="confidence-distribution-loading" className="text-muted text-sm py-4">
        Loading confidence distribution…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="confidence-distribution-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!confidence) return null;

  const cd = confidence.confidence_distribution;
  const sourceUnknown = !cd.confidence_source || cd.confidence_source === 'unknown';

  return (
    <div aria-label="confidence-distribution-panel" className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3">
        <div
          aria-label="has-confidence-data"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${cd.has_confidence_data ? 'text-success' : 'text-muted'}`}>
            {cd.has_confidence_data ? 'Present' : 'None'}
          </div>
          <div className="text-xs text-muted mt-1">Confidence data</div>
        </div>
        <div
          aria-label="confidence-source"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${sourceUnknown ? 'text-muted' : 'text-foreground'}`}>
            {cd.confidence_source_labeled
              ? safeStr(cd.confidence_source)
              : 'unknown'}
          </div>
          <div className="text-xs text-muted mt-1">Confidence source</div>
        </div>
        <div
          aria-label="reranker-score-available"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${cd.reranker_score_available ? 'text-success' : 'text-muted'}`}>
            {cd.reranker_score_available ? 'Available' : 'Not available'}
          </div>
          <div className="text-xs text-muted mt-1">Reranker scores</div>
        </div>
      </div>
      {sourceUnknown && (
        <div aria-label="unknown-confidence-notice" className="text-xs text-muted">
          Confidence source is unknown — rendered safely as &quot;unknown&quot;, not fabricated.
        </div>
      )}
      <div
        aria-label="confidence-distribution-note"
        className="rounded border border-border bg-surface-2 px-3 py-2 text-xs text-muted"
      >
        {cd.distribution_note}
      </div>
    </div>
  );
}

// ─── RerankerComparisonPanel ──────────────────────────────────────────────────

export interface RerankerComparisonPanelProps {
  reranker: EvaluationRunReranker | null;
  loading: boolean;
  error: string | null;
  runRef: string | null;
  onLoad: (runRef: string) => void;
}

export function RerankerComparisonPanel({
  reranker,
  loading,
  error,
  runRef,
  onLoad,
}: RerankerComparisonPanelProps) {
  const [input, setInput] = useState(runRef ?? '');

  if (!reranker && !loading && !error) {
    return (
      <div aria-label="reranker-comparison-panel" className="space-y-3">
        <div className="text-xs text-muted">
          Enter a run reference to view reranker comparison metadata.
        </div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Run reference input for reranker"
            placeholder="run_ref"
            className="flex-1 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground"
          />
          <button
            onClick={() => input && onLoad(input.trim())}
            disabled={!input.trim() || loading}
            aria-label="Load reranker comparison"
            className="rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Load
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div aria-label="reranker-comparison-loading" className="text-muted text-sm py-4">
        Loading reranker comparison…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="reranker-comparison-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!reranker) return null;

  const rc = reranker.reranker_comparison;

  return (
    <div aria-label="reranker-comparison-panel" className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3">
        <div
          aria-label="reranker-available"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className={`text-sm font-semibold ${rc.reranker_available ? 'text-success' : 'text-muted'}`}>
            {rc.reranker_available ? 'Available' : 'Not available'}
          </div>
          <div className="text-xs text-muted mt-1">Reranker data</div>
        </div>
        <div
          aria-label="ordering-deterministic"
          className="rounded border border-border bg-surface-2 px-3 py-2"
        >
          <div className="text-sm font-semibold text-success">
            {rc.ordering_deterministic ? 'Yes' : 'No'}
          </div>
          <div className="text-xs text-muted mt-1">Deterministic ordering</div>
        </div>
        {rc.reranker_strategy && (
          <div
            aria-label="reranker-strategy"
            className="rounded border border-border bg-surface-2 px-3 py-2"
          >
            <div className="text-sm font-semibold font-mono text-foreground truncate">
              {rc.reranker_strategy}
            </div>
            <div className="text-xs text-muted mt-1">Reranker strategy</div>
          </div>
        )}
      </div>
      {rc.retrieval_strategy && (
        <div className="text-xs text-muted">
          Retrieval strategy:{' '}
          <span className="font-mono text-foreground">{rc.retrieval_strategy}</span>
        </div>
      )}
      <div
        aria-label="reranker-comparison-note"
        className="rounded border border-border bg-surface-2 px-3 py-2 text-xs text-muted"
      >
        {rc.reranker_note}
      </div>
      {!rc.reranker_available && (
        <div aria-label="no-reranker-data-notice" className="text-xs text-muted">
          Reranker data is not available for this run. Comparison requires reranker
          metadata to be present in the evaluation run record.
        </div>
      )}
    </div>
  );
}

// ─── EvaluationExportPanel ────────────────────────────────────────────────────

export interface EvaluationExportPanelProps {
  exportData: EvaluationRunExport | null;
  loading: boolean;
  error: string | null;
  runRef: string | null;
  onLoad: (runRef: string) => void;
}

export function EvaluationExportPanel({
  exportData,
  loading,
  error,
  runRef,
  onLoad,
}: EvaluationExportPanelProps) {
  const [input, setInput] = useState(runRef ?? '');

  if (!exportData && !loading && !error) {
    return (
      <div aria-label="evaluation-export-panel" className="space-y-3">
        <div className="text-xs text-muted">
          Enter a run reference to generate an export-safe evaluation payload.
          Exports exclude secrets, raw auth headers, provider payloads, and
          internal topology.
        </div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Run reference input for export"
            placeholder="run_ref"
            className="flex-1 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground"
          />
          <button
            onClick={() => input && onLoad(input.trim())}
            disabled={!input.trim() || loading}
            aria-label="Load evaluation export"
            className="rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Export
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div aria-label="evaluation-export-loading" className="text-muted text-sm py-4">
        Generating export…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="evaluation-export-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!exportData) return null;

  function handleDownload() {
    if (!exportData) return;
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `evaluation-export-${exportData.run_ref.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div aria-label="evaluation-export-panel" className="space-y-3">
      <div className="flex items-center justify-between">
        <div
          aria-label="export-safe-badge"
          className="inline-flex items-center rounded border border-success/40 bg-success/10 px-2 py-1 text-xs text-success"
        >
          Export safe
        </div>
        <button
          onClick={handleDownload}
          aria-label="Download export JSON"
          className="rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground"
        >
          Download JSON
        </button>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3">
        <div aria-label="export-run-ref" className="rounded border border-border bg-surface-2 px-3 py-2">
          <div className="text-sm font-mono text-foreground truncate">{exportData.run_ref}</div>
          <div className="text-xs text-muted mt-1">Run ref</div>
        </div>
        <div aria-label="export-status" className="rounded border border-border bg-surface-2 px-3 py-2">
          <div className="text-sm text-foreground">{exportData.status}</div>
          <div className="text-xs text-muted mt-1">Status</div>
        </div>
        <div aria-label="export-query-count" className="rounded border border-border bg-surface-2 px-3 py-2">
          <div className="text-sm text-foreground">{exportData.query_count}</div>
          <div className="text-xs text-muted mt-1">Queries</div>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 text-xs">
        <div
          aria-label="has-relevance-indicators"
          className={`rounded border border-border px-3 py-2 ${exportData.has_relevance_indicators ? 'bg-success/10' : 'bg-surface-2'}`}
        >
          <div className="text-xs text-muted">Relevance indicators</div>
          <div className={exportData.has_relevance_indicators ? 'text-success' : 'text-muted'}>
            {exportData.has_relevance_indicators ? 'Present' : 'None'}
          </div>
        </div>
        <div
          aria-label="has-coverage-indicators"
          className={`rounded border border-border px-3 py-2 ${exportData.has_coverage_indicators ? 'bg-success/10' : 'bg-surface-2'}`}
        >
          <div className="text-xs text-muted">Coverage indicators</div>
          <div className={exportData.has_coverage_indicators ? 'text-success' : 'text-muted'}>
            {exportData.has_coverage_indicators ? 'Present' : 'None'}
          </div>
        </div>
        <div
          aria-label="has-correctness-indicators"
          className={`rounded border border-border px-3 py-2 ${exportData.has_correctness_indicators ? 'bg-success/10' : 'bg-surface-2'}`}
        >
          <div className="text-xs text-muted">Correctness indicators</div>
          <div className={exportData.has_correctness_indicators ? 'text-success' : 'text-muted'}>
            {exportData.has_correctness_indicators ? 'Present' : 'None'}
          </div>
        </div>
      </div>
      <div
        aria-label="export-note"
        className="rounded border border-border bg-surface-2 px-3 py-2 text-xs text-muted"
      >
        {exportData.export_note}
      </div>
    </div>
  );
}

// ─── EvaluationLabConsole ─────────────────────────────────────────────────────

export interface EvaluationLabConsoleProps {
  defaultTab?: EvalLabTab;
}

type EvalLabTab =
  | 'runs'
  | 'query-sets'
  | 'comparison'
  | 'grounding'
  | 'hallucination'
  | 'confidence'
  | 'reranker'
  | 'export';

export function EvaluationLabConsole({
  defaultTab = 'runs',
}: EvaluationLabConsoleProps) {
  const [tab, setTab] = useState<EvalLabTab>(defaultTab);

  // Evaluation runs (re-uses existing API)
  const [runsPage, setRunsPage] = useState<EvaluationRunPage | null>(null);
  const [runsLoading, setRunsLoading] = useState(false);
  const [runsError, setRunsError] = useState<string | null>(null);
  const [runsOffset, setRunsOffset] = useState(0);
  const runsLimit = 20;

  // Query sets
  const [querySetsPage, setQuerySetsPage] = useState<EvaluationQuerySetsPage | null>(null);
  const [querySetsLoading, setQuerySetsLoading] = useState(false);
  const [querySetsError, setQuerySetsError] = useState<string | null>(null);
  const [querySetsOffset, setQuerySetsOffset] = useState(0);
  const [selectedQuerySet, setSelectedQuerySet] = useState<EvaluationQuerySetRecord | null>(null);
  const [querySetDetail, setQuerySetDetail] = useState<EvaluationQuerySetDetail | null>(null);
  const [querySetDetailLoading, setQuerySetDetailLoading] = useState(false);
  const querySetsLimit = 20;

  // Run sub-resources — shared run_ref input
  const [activeRunRef, setActiveRunRef] = useState<string | null>(null);

  const [comparison, setComparison] = useState<EvaluationRunComparison | null>(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);

  const [hallucinationData, setHallucinationData] = useState<EvaluationRunHallucination | null>(null);
  const [hallucinationLoading, setHallucinationLoading] = useState(false);
  const [hallucinationError, setHallucinationError] = useState<string | null>(null);

  const [confidenceData, setConfidenceData] = useState<EvaluationRunConfidence | null>(null);
  const [confidenceLoading, setConfidenceLoading] = useState(false);
  const [confidenceError, setConfidenceError] = useState<string | null>(null);

  const [rerankerData, setRerankerData] = useState<EvaluationRunReranker | null>(null);
  const [rerankerLoading, setRerankerLoading] = useState(false);
  const [rerankerError, setRerankerError] = useState<string | null>(null);

  const [exportData, setExportData] = useState<EvaluationRunExport | null>(null);
  const [exportLoading, setExportLoading] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

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

  const loadQuerySets = useCallback(async (offset: number) => {
    setQuerySetsLoading(true);
    setQuerySetsError(null);
    try {
      const page = await getEvaluationQuerySets({ limit: querySetsLimit, offset });
      setQuerySetsPage(page);
      setQuerySetsOffset(offset);
    } catch (err) {
      setQuerySetsError(normalizeError(err));
    } finally {
      setQuerySetsLoading(false);
    }
  }, [querySetsLimit]);

  const loadQuerySetDetail = useCallback(async (qs: EvaluationQuerySetRecord) => {
    setSelectedQuerySet(qs);
    setQuerySetDetailLoading(true);
    try {
      const detail = await getEvaluationQuerySetDetail(qs.set_ref);
      setQuerySetDetail(detail);
    } catch (err) {
      setQuerySetDetail(null);
    } finally {
      setQuerySetDetailLoading(false);
    }
  }, []);

  const loadComparison = useCallback(async (runRef: string) => {
    setActiveRunRef(runRef);
    setComparisonLoading(true);
    setComparisonError(null);
    try {
      const data = await getEvaluationRunComparison(runRef);
      setComparison(data);
    } catch (err) {
      setComparisonError(normalizeError(err));
    } finally {
      setComparisonLoading(false);
    }
  }, []);

  const loadHallucination = useCallback(async (runRef: string) => {
    setActiveRunRef(runRef);
    setHallucinationLoading(true);
    setHallucinationError(null);
    try {
      const data = await getEvaluationRunHallucination(runRef);
      setHallucinationData(data);
    } catch (err) {
      setHallucinationError(normalizeError(err));
    } finally {
      setHallucinationLoading(false);
    }
  }, []);

  const loadConfidence = useCallback(async (runRef: string) => {
    setActiveRunRef(runRef);
    setConfidenceLoading(true);
    setConfidenceError(null);
    try {
      const data = await getEvaluationRunConfidence(runRef);
      setConfidenceData(data);
    } catch (err) {
      setConfidenceError(normalizeError(err));
    } finally {
      setConfidenceLoading(false);
    }
  }, []);

  const loadReranker = useCallback(async (runRef: string) => {
    setActiveRunRef(runRef);
    setRerankerLoading(true);
    setRerankerError(null);
    try {
      const data = await getEvaluationRunReranker(runRef);
      setRerankerData(data);
    } catch (err) {
      setRerankerError(normalizeError(err));
    } finally {
      setRerankerLoading(false);
    }
  }, []);

  const loadExport = useCallback(async (runRef: string) => {
    setActiveRunRef(runRef);
    setExportLoading(true);
    setExportError(null);
    try {
      const data = await getEvaluationRunExport(runRef);
      setExportData(data);
    } catch (err) {
      setExportError(normalizeError(err));
    } finally {
      setExportLoading(false);
    }
  }, []);

  function handleTabChange(newTab: EvalLabTab) {
    setTab(newTab);
    if (newTab === 'runs' && !runsPage && !runsLoading) {
      loadRuns(0);
    }
    if (newTab === 'query-sets' && !querySetsPage && !querySetsLoading) {
      loadQuerySets(0);
    }
  }

  const tabs: { id: EvalLabTab; label: string }[] = [
    { id: 'runs', label: 'Evaluation Runs' },
    { id: 'query-sets', label: 'Query Sets' },
    { id: 'comparison', label: 'Retrieval Comparison' },
    { id: 'grounding', label: 'Grounding Review' },
    { id: 'hallucination', label: 'Hallucination Review' },
    { id: 'confidence', label: 'Confidence Distribution' },
    { id: 'reranker', label: 'Reranker Comparison' },
    { id: 'export', label: 'Export' },
  ];

  return (
    <div aria-label="evaluation-lab-console" className="space-y-4">
      <nav aria-label="evaluation-lab-tabs" className="flex gap-1 flex-wrap">
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
            {runsError && (
              <div aria-label="runs-error" className="text-danger text-sm mb-3">
                {runsError}
              </div>
            )}
            {runsLoading && !runsPage ? (
              <div className="text-muted text-sm py-4">Loading evaluation runs…</div>
            ) : runsPage && runsPage.runs.length === 0 ? (
              <div aria-label="runs-empty" className="text-muted text-sm py-4">
                No evaluation runs found. Runs are created by the evaluation pipeline.
              </div>
            ) : runsPage ? (
              <div className="space-y-2">
                <div className="text-xs text-muted">
                  Showing {runsOffset + 1}–{Math.min(runsOffset + runsPage.runs.length, runsPage.total)} of {runsPage.total}
                </div>
                {runsPage.runs.map((run) => (
                  <div
                    key={run.run_ref}
                    aria-label={`evaluation-run-${run.run_ref}`}
                    className="rounded border border-border bg-surface-2 px-4 py-3"
                  >
                    <div className="flex flex-wrap items-center gap-4 text-xs">
                      <span className="font-mono text-foreground truncate max-w-xs">
                        {run.run_ref}
                      </span>
                      <span className="text-muted">{run.status}</span>
                      {run.corpus_id && (
                        <span className="text-muted">corpus: {run.corpus_id}</span>
                      )}
                      <span className="text-muted">{run.query_count} queries</span>
                    </div>
                  </div>
                ))}
                {(runsOffset > 0 || runsOffset + runsLimit < runsPage.total) && (
                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={() => loadRuns(Math.max(0, runsOffset - runsLimit))}
                      disabled={runsOffset === 0 || runsLoading}
                      aria-label="Previous runs page"
                      className="text-xs text-muted border border-border rounded px-2 py-1 hover:text-foreground disabled:opacity-40"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => loadRuns(runsOffset + runsLimit)}
                      disabled={runsOffset + runsLimit >= runsPage.total || runsLoading}
                      aria-label="Next runs page"
                      className="text-xs text-muted border border-border rounded px-2 py-1 hover:text-foreground disabled:opacity-40"
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>
            ) : null}
          </section>
        )}

        {tab === 'query-sets' && (
          <section aria-label="query-sets-tab-content">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-foreground">Query Sets</h3>
              <button
                onClick={() => {
                  setSelectedQuerySet(null);
                  setQuerySetDetail(null);
                  loadQuerySets(querySetsOffset);
                }}
                disabled={querySetsLoading}
                aria-label="Refresh query sets"
                className="text-xs text-muted hover:text-foreground disabled:opacity-40"
              >
                {querySetsLoading ? 'Loading…' : 'Refresh'}
              </button>
            </div>
            {selectedQuerySet && querySetDetailLoading ? (
              <div className="text-muted text-sm py-4">Loading query set detail…</div>
            ) : selectedQuerySet && querySetDetail ? (
              <QuerySetDetailView
                detail={querySetDetail}
                onClose={() => {
                  setSelectedQuerySet(null);
                  setQuerySetDetail(null);
                }}
              />
            ) : (
              <QuerySetPanel
                page={querySetsPage}
                loading={querySetsLoading}
                error={querySetsError}
                onPageChange={(offset) => loadQuerySets(offset)}
                onSetSelect={loadQuerySetDetail}
              />
            )}
          </section>
        )}

        {tab === 'comparison' && (
          <section aria-label="comparison-tab-content">
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-foreground">Retrieval Comparison</h3>
              <p className="text-xs text-muted mt-1">
                Retrieval hit/miss state and expected vs retrieved overlap derived from
                evaluation run indicators. No fabricated precision metrics.
              </p>
            </div>
            <RetrievalPrecisionPanel
              comparison={comparison}
              loading={comparisonLoading}
              error={comparisonError}
              runRef={activeRunRef}
              onLoad={loadComparison}
            />
          </section>
        )}

        {tab === 'grounding' && (
          <section aria-label="grounding-tab-content">
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-foreground">Grounding Review</h3>
              <p className="text-xs text-muted mt-1">
                Evidence grounding indicators and missing evidence visibility.
                Operator-reviewable. Heuristic where labeled.
              </p>
            </div>
            <GroundingReviewPanel
              hallucination={hallucinationData}
              loading={hallucinationLoading}
              error={hallucinationError}
              runRef={activeRunRef}
              onLoad={loadHallucination}
            />
          </section>
        )}

        {tab === 'hallucination' && (
          <section aria-label="hallucination-tab-content">
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-foreground">Hallucination Review</h3>
              <p className="text-xs text-muted mt-1">
                Operator-grade heuristic review of unsupported answers and evidence mismatches.
                Not guaranteed automated detection — requires operator validation.
              </p>
            </div>
            <HallucinationReviewPanel
              hallucination={hallucinationData}
              loading={hallucinationLoading}
              error={hallucinationError}
              runRef={activeRunRef}
              onLoad={loadHallucination}
            />
          </section>
        )}

        {tab === 'confidence' && (
          <section aria-label="confidence-tab-content">
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-foreground">Confidence Distribution</h3>
              <p className="text-xs text-muted mt-1">
                Retrieval and evidence confidence metadata. Confidence sources are labeled.
                Unknown confidence renders safely as &quot;unknown&quot; — not fabricated.
              </p>
            </div>
            <ConfidenceDistributionPanel
              confidence={confidenceData}
              loading={confidenceLoading}
              error={confidenceError}
              runRef={activeRunRef}
              onLoad={loadConfidence}
            />
          </section>
        )}

        {tab === 'reranker' && (
          <section aria-label="reranker-tab-content">
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-foreground">Reranker Comparison</h3>
              <p className="text-xs text-muted mt-1">
                Reranker ordering comparison derived from actual retrieval state.
                Unsupported metrics are not fabricated. Ordering is deterministic.
              </p>
            </div>
            <RerankerComparisonPanel
              reranker={rerankerData}
              loading={rerankerLoading}
              error={rerankerError}
              runRef={activeRunRef}
              onLoad={loadReranker}
            />
          </section>
        )}

        {tab === 'export' && (
          <section aria-label="export-tab-content">
            <div className="mb-3">
              <h3 className="text-sm font-semibold text-foreground">Evaluation Export</h3>
              <p className="text-xs text-muted mt-1">
                Export-safe evaluation payload suitable for audit review and compliance workflows.
                Excludes secrets, raw auth headers, provider payloads, and internal topology.
              </p>
            </div>
            <EvaluationExportPanel
              exportData={exportData}
              loading={exportLoading}
              error={exportError}
              runRef={activeRunRef}
              onLoad={loadExport}
            />
          </section>
        )}
      </div>
    </div>
  );
}
