'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  AlertCircle,
  ChevronDown,
  ChevronRight,
  Database,
  FileText,
  Layers,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';

import {
  type CorpusDetail,
  type DocumentDetail,
  type DocumentPage,
  type DocumentListQuery,
  type IngestionStatus,
  type SortBy,
  type SortDir,
  getCorpusDetail,
  listCorpusDocuments,
  getDocumentDetail,
} from '@/lib/corpusConsoleApi';
import { getCorpora } from '@/lib/retrievalPolicyApi';
import type { CorpusListEntry } from '@/lib/retrievalPolicyApi';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CorpusManagementConsoleProps {
  /** Override corpus list (for static tests). When absent, loads from API. */
  initialCorpora?: CorpusListEntry[] | null;
}

// ─── Ingestion Status Config ──────────────────────────────────────────────────

interface IngestionStatusConfig {
  label: string;
  textClass: string;
  bgClass: string;
}

const INGESTION_STATUS_CONFIG: Record<string, IngestionStatusConfig> = {
  indexed: {
    label: 'Indexed',
    textClass: 'text-green-700',
    bgClass: 'bg-green-50 border-green-200',
  },
  duplicate: {
    label: 'Duplicate',
    textClass: 'text-yellow-700',
    bgClass: 'bg-yellow-50 border-yellow-200',
  },
  quarantined: {
    label: 'Quarantined',
    textClass: 'text-red-700',
    bgClass: 'bg-red-50 border-red-200',
  },
  failed: {
    label: 'Failed',
    textClass: 'text-red-700',
    bgClass: 'bg-red-50 border-red-200',
  },
  superseded: {
    label: 'Superseded',
    textClass: 'text-muted',
    bgClass: 'bg-muted/10 border-border',
  },
  embedding: {
    label: 'Embedding',
    textClass: 'text-blue-700',
    bgClass: 'bg-blue-50 border-blue-200',
  },
  chunking: {
    label: 'Chunking',
    textClass: 'text-blue-700',
    bgClass: 'bg-blue-50 border-blue-200',
  },
  validating: {
    label: 'Validating',
    textClass: 'text-blue-700',
    bgClass: 'bg-blue-50 border-blue-200',
  },
  received: {
    label: 'Received',
    textClass: 'text-blue-700',
    bgClass: 'bg-blue-50 border-blue-200',
  },
  reindexing: {
    label: 'Re-indexing',
    textClass: 'text-yellow-700',
    bgClass: 'bg-yellow-50 border-yellow-200',
  },
};

function resolveIngestionStatusConfig(status: IngestionStatus): IngestionStatusConfig {
  return (
    INGESTION_STATUS_CONFIG[status] ?? {
      label: `Unknown: ${status}`,
      textClass: 'text-muted',
      bgClass: 'bg-muted/10 border-border',
    }
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

export function IngestionLifecycleBadge({
  status,
}: {
  status: IngestionStatus | null | undefined;
}) {
  if (!status) {
    return (
      <span
        className="inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium bg-muted/10 border-border text-muted"
        aria-label="ingestion-status-unavailable"
      >
        Unavailable
      </span>
    );
  }
  const cfg = resolveIngestionStatusConfig(status);
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${cfg.bgClass} ${cfg.textClass}`}
      aria-label={`ingestion-status-${status}`}
    >
      {cfg.label}
    </span>
  );
}

export function EmbeddingStatusBadge({
  state,
}: {
  state: string | null | undefined;
}) {
  if (!state) {
    return (
      <span
        className="inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium bg-muted/10 border-border text-muted"
        aria-label="embedding-state-unavailable"
      >
        Unavailable
      </span>
    );
  }
  const config: Record<string, { label: string; textClass: string }> = {
    'completed': { label: 'Indexed', textClass: 'text-green-700' },
    'pending': { label: 'Pending', textClass: 'text-yellow-700' },
    'processing': { label: 'Processing', textClass: 'text-blue-700' },
    'failed': { label: 'Failed', textClass: 'text-red-700' },
    'skipped': { label: 'Skipped', textClass: 'text-muted' },
  };
  const cfg = config[state] ?? { label: `Unknown: ${state}`, textClass: 'text-muted' };
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium bg-muted/10 border-border ${cfg.textClass}`}
      aria-label={`embedding-state-${state}`}
    >
      {cfg.label}
    </span>
  );
}

export function CorpusEmptyState() {
  return (
    <div
      className="flex flex-col items-center gap-3 py-10 text-center"
      aria-label="corpus-empty-state"
      role="status"
    >
      <Database className="h-8 w-8 text-muted/40" aria-hidden="true" />
      <p className="text-sm font-medium text-foreground">No corpora found</p>
      <p className="max-w-sm text-xs text-muted">
        No corpora have been ingested for this tenant yet. Documents must be
        ingested before they appear here.
      </p>
    </div>
  );
}

export function CorpusLoadingState({ label }: { label?: string }) {
  return (
    <div
      className="flex items-center justify-center gap-2 py-8"
      aria-label="corpus-loading-state"
      role="status"
      aria-busy="true"
    >
      <RefreshCw className="h-4 w-4 animate-spin text-muted" aria-hidden="true" />
      <span className="text-xs text-muted">{label ?? 'Loading…'}</span>
    </div>
  );
}

export function CorpusHealthPanel({ corpus }: { corpus: CorpusDetail }) {
  const total = corpus.total_document_count;
  const active = corpus.active_document_count;
  const failed =
    (corpus.ingestion_status_summary['failed'] ?? 0) +
    (corpus.ingestion_status_summary['quarantined'] ?? 0);
  const superseded = corpus.ingestion_status_summary['superseded'] ?? 0;

  return (
    <div
      className="grid grid-cols-2 gap-3 sm:grid-cols-4"
      aria-label="corpus-health-panel"
    >
      <div className="rounded border border-border bg-card p-3">
        <p className="text-[10px] text-muted">Total Documents</p>
        <p className="text-lg font-semibold text-foreground">{total}</p>
      </div>
      <div className="rounded border border-border bg-card p-3">
        <p className="text-[10px] text-muted">Active / Indexed</p>
        <p className="text-lg font-semibold text-green-700">{active}</p>
      </div>
      <div className="rounded border border-border bg-card p-3">
        <p className="text-[10px] text-muted">Active Chunks</p>
        <p className="text-lg font-semibold text-foreground">
          {corpus.active_chunk_count}
        </p>
      </div>
      <div className="rounded border border-border bg-card p-3">
        <p className="text-[10px] text-muted">Failed / Quarantined</p>
        <p
          className={`text-lg font-semibold ${failed > 0 ? 'text-red-700' : 'text-foreground'}`}
          aria-label={`failed-quarantined-count-${failed}`}
        >
          {failed}
        </p>
      </div>
      {superseded > 0 && (
        <div
          className="col-span-2 rounded border border-border bg-muted/10 p-3 sm:col-span-4"
          aria-label="superseded-documents-note"
        >
          <p className="text-[10px] text-muted">
            {superseded} superseded document version{superseded !== 1 ? 's' : ''} are
            retained for audit. They are excluded from retrieval.
          </p>
        </div>
      )}
    </div>
  );
}

export function CorpusMetadataViewer({
  metadata,
}: {
  metadata: Record<string, unknown> | null | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  if (!metadata || Object.keys(metadata).length === 0) return null;

  const safeEntries = Object.entries(metadata).filter(
    ([, v]) => typeof v !== 'object' || v === null,
  );
  const displayEntries = expanded ? safeEntries : safeEntries.slice(0, 5);

  return (
    <div className="mt-3" aria-label="corpus-metadata-viewer">
      <button
        type="button"
        className="flex items-center gap-1 text-[10px] font-medium text-muted hover:text-foreground"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        aria-controls="metadata-detail"
      >
        {expanded ? (
          <ChevronDown className="h-3 w-3" aria-hidden="true" />
        ) : (
          <ChevronRight className="h-3 w-3" aria-hidden="true" />
        )}
        Metadata ({safeEntries.length} field{safeEntries.length !== 1 ? 's' : ''})
      </button>
      {expanded && (
        <dl
          id="metadata-detail"
          className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 rounded border border-border bg-muted/5 p-2"
        >
          {displayEntries.map(([k, v]) => (
            <div key={k} className="col-span-1">
              <dt className="text-[9px] font-medium text-muted">{String(k)}</dt>
              <dd className="truncate text-[10px] text-foreground">
                {String(v ?? '')}
              </dd>
            </div>
          ))}
          {safeEntries.length > 5 && !expanded && (
            <p className="col-span-2 text-[9px] text-muted">
              …and {safeEntries.length - 5} more
            </p>
          )}
        </dl>
      )}
    </div>
  );
}

// ─── CorpusFilterBar ──────────────────────────────────────────────────────────

const INGESTION_STATUS_OPTIONS: Array<{ value: string; label: string }> = [
  { value: '', label: 'All statuses' },
  { value: 'indexed', label: 'Indexed' },
  { value: 'duplicate', label: 'Duplicate' },
  { value: 'quarantined', label: 'Quarantined' },
  { value: 'failed', label: 'Failed' },
  { value: 'superseded', label: 'Superseded' },
  { value: 'chunking', label: 'Chunking' },
  { value: 'embedding', label: 'Embedding' },
  { value: 'validating', label: 'Validating' },
  { value: 'received', label: 'Received' },
  { value: 'reindexing', label: 'Re-indexing' },
];

export interface CorpusFilterBarProps {
  statusFilter: string;
  isCurrentFilter: '' | 'true' | 'false';
  onStatusChange: (v: string) => void;
  onIsCurrentChange: (v: '' | 'true' | 'false') => void;
}

export function CorpusFilterBar({
  statusFilter,
  isCurrentFilter,
  onStatusChange,
  onIsCurrentChange,
}: CorpusFilterBarProps) {
  return (
    <div
      className="flex flex-wrap items-center gap-3"
      aria-label="corpus-filter-bar"
      role="search"
    >
      <div className="flex items-center gap-1.5">
        <Search className="h-3 w-3 text-muted" aria-hidden="true" />
        <label htmlFor="status-filter" className="text-[10px] text-muted">
          Status
        </label>
        <select
          id="status-filter"
          className="rounded border border-border bg-card px-2 py-1 text-[10px] text-foreground"
          value={statusFilter}
          onChange={(e) => onStatusChange(e.target.value)}
          aria-label="filter-by-ingestion-status"
        >
          {INGESTION_STATUS_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-1.5">
        <label htmlFor="current-filter" className="text-[10px] text-muted">
          Version
        </label>
        <select
          id="current-filter"
          className="rounded border border-border bg-card px-2 py-1 text-[10px] text-foreground"
          value={isCurrentFilter}
          onChange={(e) =>
            onIsCurrentChange(e.target.value as '' | 'true' | 'false')
          }
          aria-label="filter-by-version-state"
        >
          <option value="">All versions</option>
          <option value="true">Current only</option>
          <option value="false">Superseded only</option>
        </select>
      </div>
    </div>
  );
}

// ─── CorpusPaginationControls ─────────────────────────────────────────────────

export interface CorpusPaginationControlsProps {
  total: number;
  limit: number;
  offset: number;
  onPrev: () => void;
  onNext: () => void;
}

export function CorpusPaginationControls({
  total,
  limit,
  offset,
  onPrev,
  onNext,
}: CorpusPaginationControlsProps) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);
  const hasPrev = offset > 0;
  const hasNext = offset + limit < total;

  return (
    <div
      className="flex items-center justify-between"
      aria-label="corpus-pagination-controls"
    >
      <p className="text-[10px] text-muted" aria-live="polite">
        {total === 0
          ? 'No items'
          : `Showing ${from}–${to} of ${total}`}
      </p>
      <div className="flex items-center gap-2">
        <button
          type="button"
          className="rounded border border-border px-2 py-1 text-[10px] text-foreground disabled:opacity-40"
          disabled={!hasPrev}
          onClick={onPrev}
          aria-label="previous-page"
        >
          Previous
        </button>
        <button
          type="button"
          className="rounded border border-border px-2 py-1 text-[10px] text-foreground disabled:opacity-40"
          disabled={!hasNext}
          onClick={onNext}
          aria-label="next-page"
        >
          Next
        </button>
      </div>
    </div>
  );
}

// ─── DocumentDetailPanel ──────────────────────────────────────────────────────

export function DocumentDetailPanel({
  doc,
  onClose,
}: {
  doc: DocumentDetail;
  onClose: () => void;
}) {
  const embStates = doc.embedding_state_summary ?? {};
  const dominantState =
    Object.entries(embStates).sort(([, a], [, b]) => b - a)[0]?.[0] ?? null;

  return (
    <div
      className="rounded border border-border bg-card p-4"
      aria-label="document-detail-panel"
      role="region"
    >
      <div className="mb-3 flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold text-foreground">
            {doc.title ?? doc.document_id}
          </p>
          <p className="text-[10px] text-muted font-mono">{doc.document_id}</p>
        </div>
        <button
          type="button"
          className="rounded p-1 text-muted hover:text-foreground"
          onClick={onClose}
          aria-label="close-document-detail"
        >
          <XCircle className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[10px]">
        <div>
          <span className="text-muted">Status</span>
          <div className="mt-0.5">
            <IngestionLifecycleBadge status={doc.ingestion_status} />
          </div>
        </div>
        <div>
          <span className="text-muted">Embedding</span>
          <div className="mt-0.5">
            <EmbeddingStatusBadge state={dominantState} />
          </div>
        </div>
        <div>
          <span className="text-muted">Version</span>
          <p className="text-foreground">
            v{doc.version_number} {doc.is_current ? '(current)' : '(superseded)'}
          </p>
        </div>
        <div>
          <span className="text-muted">Active Chunks</span>
          <p className="text-foreground">
            {doc.active_chunk_count} / {doc.total_chunk_count}
          </p>
        </div>
        {doc.source_hash_prefix && (
          <div>
            <span className="text-muted">Source Hash (prefix)</span>
            <p className="font-mono text-foreground">{doc.source_hash_prefix}…</p>
          </div>
        )}
        {doc.indexed_at && (
          <div>
            <span className="text-muted">Indexed At</span>
            <p className="text-foreground">{doc.indexed_at}</p>
          </div>
        )}
        {doc.quarantine_reason && (
          <div className="col-span-2" role="alert">
            <span className="text-muted">Quarantine Reason</span>
            <p className="text-red-700">{doc.quarantine_reason}</p>
          </div>
        )}
        {doc.failure_reason && (
          <div className="col-span-2" role="alert">
            <span className="text-muted">Failure Reason</span>
            <p className="text-red-700">{doc.failure_reason}</p>
          </div>
        )}
      </div>

      {Object.keys(embStates).length > 0 && (
        <div className="mt-3">
          <p className="mb-1 text-[10px] font-medium text-muted">
            Embedding State Distribution
          </p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(embStates).map(([state, count]) => (
              <div key={state} className="flex items-center gap-1">
                <EmbeddingStatusBadge state={state} />
                <span className="text-[10px] text-muted">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div
        className="mt-3 rounded border border-border bg-muted/5 p-2"
        aria-label="future-hooks-placeholder"
      >
        <p className="text-[9px] text-muted">
          Future: duplicate detection, stale detection, evidence lineage — not yet available.
        </p>
      </div>
    </div>
  );
}

// ─── DocumentBrowser ──────────────────────────────────────────────────────────

export function DocumentBrowser({
  corpusId,
}: {
  corpusId: string;
}) {
  const [page, setPage] = useState<DocumentPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState('');
  const [isCurrentFilter, setIsCurrentFilter] = useState<'' | 'true' | 'false'>('');
  const [sortBy] = useState<SortBy>('created_at');
  const [sortDir] = useState<SortDir>('desc');
  const [offset, setOffset] = useState(0);
  const limit = 20;

  const [selectedDocId, setSelectedDocId] = useState<string | null>(null);
  const [docDetail, setDocDetail] = useState<DocumentDetail | null>(null);
  const [docDetailLoading, setDocDetailLoading] = useState(false);
  const [docDetailError, setDocDetailError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const query: DocumentListQuery = {
      limit,
      offset,
      sort_by: sortBy,
      sort_dir: sortDir,
    };
    if (statusFilter) query.ingestion_status = statusFilter as IngestionStatus;
    if (isCurrentFilter === 'true') query.is_current = true;
    else if (isCurrentFilter === 'false') query.is_current = false;

    const result = await listCorpusDocuments(corpusId, query);
    setLoading(false);
    if (result.ok) {
      setPage(result.data);
    } else {
      setError(result.error);
    }
  }, [corpusId, limit, offset, statusFilter, isCurrentFilter, sortBy, sortDir]);

  useEffect(() => {
    setOffset(0);
  }, [statusFilter, isCurrentFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const handleDocClick = useCallback(
    async (docId: string) => {
      if (selectedDocId === docId) {
        setSelectedDocId(null);
        setDocDetail(null);
        return;
      }
      setSelectedDocId(docId);
      setDocDetailLoading(true);
      setDocDetailError(null);
      const result = await getDocumentDetail(docId);
      setDocDetailLoading(false);
      if (result.ok) {
        setDocDetail(result.data);
      } else {
        setDocDetailError(result.error);
        setDocDetail(null);
      }
    },
    [selectedDocId],
  );

  return (
    <div className="space-y-3" aria-label="document-browser">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-foreground">Documents</h3>
        <button
          type="button"
          className="flex items-center gap-1 text-[10px] text-muted hover:text-foreground"
          onClick={load}
          aria-label="refresh-documents"
        >
          <RefreshCw className="h-3 w-3" aria-hidden="true" />
          Refresh
        </button>
      </div>

      <CorpusFilterBar
        statusFilter={statusFilter}
        isCurrentFilter={isCurrentFilter}
        onStatusChange={(v) => setStatusFilter(v)}
        onIsCurrentChange={(v) => setIsCurrentFilter(v)}
      />

      {loading && <CorpusLoadingState label="Loading documents…" />}

      {!loading && error && (
        <div
          className="flex items-center gap-2 rounded border border-red-200 bg-red-50 p-3"
          role="alert"
          aria-label="document-load-error"
        >
          <AlertCircle className="h-4 w-4 text-red-600" aria-hidden="true" />
          <p className="text-xs text-red-700">Failed to load documents: {error}</p>
        </div>
      )}

      {!loading && !error && page && (
        <>
          {page.items.length === 0 ? (
            <div
              className="flex flex-col items-center gap-2 py-8 text-center"
              aria-label="no-documents-state"
              role="status"
            >
              <FileText className="h-6 w-6 text-muted/40" aria-hidden="true" />
              <p className="text-xs text-muted">No documents match the current filters.</p>
            </div>
          ) : (
            <div className="space-y-1" aria-label="document-list" role="list">
              {page.items.map((doc) => (
                <div key={doc.document_id} role="listitem">
                  <button
                    type="button"
                    className={`w-full rounded border px-3 py-2 text-left transition-colors ${
                      selectedDocId === doc.document_id
                        ? 'border-primary/30 bg-primary/5'
                        : 'border-border bg-card hover:bg-muted/10'
                    }`}
                    onClick={() => handleDocClick(doc.document_id)}
                    aria-expanded={selectedDocId === doc.document_id}
                    aria-label={`document-row-${doc.document_id}`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <FileText
                          className="h-3 w-3 shrink-0 text-muted"
                          aria-hidden="true"
                        />
                        <span className="truncate text-xs font-medium text-foreground">
                          {doc.title ?? doc.document_id}
                        </span>
                      </div>
                      <div className="flex shrink-0 items-center gap-2 ml-2">
                        <IngestionLifecycleBadge status={doc.ingestion_status} />
                        {!doc.is_current && (
                          <span
                            className="text-[9px] text-muted"
                            aria-label="superseded-marker"
                          >
                            (superseded)
                          </span>
                        )}
                        <span className="text-[10px] text-muted">
                          {doc.active_chunk_count} chunk{doc.active_chunk_count !== 1 ? 's' : ''}
                        </span>
                      </div>
                    </div>
                    {doc.source_hash_prefix && (
                      <p className="mt-0.5 font-mono text-[9px] text-muted">
                        hash: {doc.source_hash_prefix}…
                      </p>
                    )}
                  </button>

                  {selectedDocId === doc.document_id && (
                    <div className="mt-1 pl-4">
                      {docDetailLoading && (
                        <CorpusLoadingState label="Loading document detail…" />
                      )}
                      {!docDetailLoading && docDetailError && (
                        <div
                          className="rounded border border-red-200 bg-red-50 p-2"
                          role="alert"
                          aria-label="document-detail-error"
                        >
                          <p className="text-xs text-red-700">
                            Failed to load detail: {docDetailError}
                          </p>
                        </div>
                      )}
                      {!docDetailLoading && docDetail && (
                        <DocumentDetailPanel
                          doc={docDetail}
                          onClose={() => {
                            setSelectedDocId(null);
                            setDocDetail(null);
                          }}
                        />
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <CorpusPaginationControls
            total={page.total}
            limit={page.limit}
            offset={page.offset}
            onPrev={() => setOffset((o) => Math.max(0, o - limit))}
            onNext={() => setOffset((o) => o + limit)}
          />
        </>
      )}
    </div>
  );
}

// ─── CorpusBrowser ────────────────────────────────────────────────────────────

export function CorpusBrowser({
  corpora,
  selectedCorpusId,
  onSelect,
}: {
  corpora: CorpusListEntry[];
  selectedCorpusId: string | null;
  onSelect: (id: string) => void;
}) {
  if (corpora.length === 0) {
    return <CorpusEmptyState />;
  }

  return (
    <div className="space-y-1" aria-label="corpus-browser" role="list">
      {corpora.map((c) => (
        <button
          key={c.corpus_id}
          type="button"
          className={`w-full rounded border px-3 py-2 text-left transition-colors ${
            selectedCorpusId === c.corpus_id
              ? 'border-primary/30 bg-primary/5'
              : 'border-border bg-card hover:bg-muted/10'
          }`}
          onClick={() => onSelect(c.corpus_id)}
          aria-selected={selectedCorpusId === c.corpus_id}
          aria-label={`corpus-row-${c.corpus_id}`}
          role="option"
        >
          <div className="flex items-center gap-2">
            <Database className="h-3 w-3 shrink-0 text-muted" aria-hidden="true" />
            <span className="truncate text-xs font-medium text-foreground">
              {c.name ?? c.corpus_id}
            </span>
          </div>
          {c.description && (
            <p className="mt-0.5 truncate text-[10px] text-muted">{c.description}</p>
          )}
          <p className="mt-0.5 font-mono text-[9px] text-muted">{c.corpus_id}</p>
        </button>
      ))}
    </div>
  );
}

// ─── ChunkStatePanel ──────────────────────────────────────────────────────────

export function ChunkStatePanel({ corpus }: { corpus: CorpusDetail }) {
  const embSummary = corpus.embedding_state_summary;
  const hasEmbeddingData = Object.keys(embSummary).length > 0;

  return (
    <div className="rounded border border-border bg-card p-3" aria-label="chunk-state-panel">
      <h4 className="mb-2 text-[10px] font-semibold text-foreground">
        Chunk &amp; Embedding State
      </h4>
      <div className="grid grid-cols-2 gap-2 text-[10px]">
        <div>
          <span className="text-muted">Total Chunks</span>
          <p className="font-semibold text-foreground">{corpus.total_chunk_count}</p>
        </div>
        <div>
          <span className="text-muted">Active Chunks</span>
          <p className="font-semibold text-foreground">{corpus.active_chunk_count}</p>
        </div>
      </div>

      {hasEmbeddingData ? (
        <div className="mt-2">
          <p className="mb-1 text-[9px] text-muted">Embedding state distribution</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(embSummary).map(([state, count]) => (
              <div key={state} className="flex items-center gap-1">
                <EmbeddingStatusBadge state={state} />
                <span className="text-[10px] text-muted">{count}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="mt-2 text-[9px] text-muted">
          Embedding state data unavailable for this corpus.
        </p>
      )}

      <div
        className="mt-3 rounded border border-border bg-muted/5 p-2"
        aria-label="raw-vectors-not-exposed"
      >
        <p className="text-[9px] text-muted">
          Raw vectors and embedding payloads are not exposed. Only operational state
          metadata is shown.
        </p>
      </div>
    </div>
  );
}

// ─── CorpusManagementConsole ──────────────────────────────────────────────────

export function CorpusManagementConsole({
  initialCorpora,
}: CorpusManagementConsoleProps) {
  const [corpora, setCorpora] = useState<CorpusListEntry[]>(initialCorpora ?? []);
  const [corporaLoading, setCorporaLoading] = useState(!initialCorpora);
  const [corporaError, setCorporaError] = useState<string | null>(null);

  const [selectedCorpusId, setSelectedCorpusId] = useState<string | null>(null);
  const [corpusDetail, setCorpusDetail] = useState<CorpusDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const loadCorpora = useCallback(async () => {
    if (initialCorpora) return;
    setCorporaLoading(true);
    setCorporaError(null);
    try {
      const data = await getCorpora();
      setCorpora(data);
    } catch (err) {
      setCorporaError(err instanceof Error ? err.message : 'fetch_error');
    } finally {
      setCorporaLoading(false);
    }
  }, [initialCorpora]);

  useEffect(() => {
    loadCorpora();
  }, [loadCorpora]);

  const handleSelectCorpus = useCallback(async (corpusId: string) => {
    if (selectedCorpusId === corpusId) {
      setSelectedCorpusId(null);
      setCorpusDetail(null);
      return;
    }
    setSelectedCorpusId(corpusId);
    setDetailLoading(true);
    setDetailError(null);
    const result = await getCorpusDetail(corpusId);
    setDetailLoading(false);
    if (result.ok) {
      setCorpusDetail(result.data);
    } else {
      setDetailError(result.error);
      setCorpusDetail(null);
    }
  }, [selectedCorpusId]);

  return (
    <div className="space-y-4" aria-label="corpus-management-console">
      {/* Corpus Browser */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-primary" aria-hidden="true" />
            <h3 className="text-xs font-semibold text-foreground">Corpus Browser</h3>
          </div>
          {!initialCorpora && (
            <button
              type="button"
              className="flex items-center gap-1 text-[10px] text-muted hover:text-foreground"
              onClick={loadCorpora}
              aria-label="refresh-corpora"
            >
              <RefreshCw className="h-3 w-3" aria-hidden="true" />
              Refresh
            </button>
          )}
        </div>

        {corporaLoading && <CorpusLoadingState label="Loading corpora…" />}

        {!corporaLoading && corporaError && (
          <div
            className="flex items-center gap-2 rounded border border-red-200 bg-red-50 p-3"
            role="alert"
            aria-label="corpora-load-error"
          >
            <AlertCircle className="h-4 w-4 text-red-600" aria-hidden="true" />
            <p className="text-xs text-red-700">Failed to load corpora: {corporaError}</p>
          </div>
        )}

        {!corporaLoading && !corporaError && (
          <CorpusBrowser
            corpora={corpora}
            selectedCorpusId={selectedCorpusId}
            onSelect={handleSelectCorpus}
          />
        )}
      </div>

      {/* Corpus Detail */}
      {selectedCorpusId && (
        <div className="space-y-3" aria-label="corpus-detail-section">
          <div className="flex items-center gap-2 border-t border-border pt-3">
            <Layers className="h-4 w-4 text-primary" aria-hidden="true" />
            <h3 className="text-xs font-semibold text-foreground">
              Corpus Detail
            </h3>
            <span className="ml-auto font-mono text-[9px] text-muted">
              {selectedCorpusId}
            </span>
          </div>

          {detailLoading && <CorpusLoadingState label="Loading corpus detail…" />}

          {!detailLoading && detailError && (
            <div
              className="flex items-center gap-2 rounded border border-red-200 bg-red-50 p-3"
              role="alert"
              aria-label="corpus-detail-error"
            >
              <ShieldAlert className="h-4 w-4 text-red-600" aria-hidden="true" />
              <p className="text-xs text-red-700">
                Failed to load corpus detail: {detailError}
              </p>
            </div>
          )}

          {!detailLoading && corpusDetail && (
            <>
              <CorpusHealthPanel corpus={corpusDetail} />
              <ChunkStatePanel corpus={corpusDetail} />

              {/* Ingestion status breakdown */}
              {Object.keys(corpusDetail.ingestion_status_summary).length > 0 && (
                <div
                  className="rounded border border-border bg-card p-3"
                  aria-label="ingestion-status-breakdown"
                >
                  <h4 className="mb-2 text-[10px] font-semibold text-foreground">
                    Ingestion Status Breakdown
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(corpusDetail.ingestion_status_summary).map(
                      ([status, count]) => (
                        <div
                          key={status}
                          className="flex items-center gap-1"
                          aria-label={`ingestion-status-${status}-count`}
                        >
                          <IngestionLifecycleBadge status={status} />
                          <span className="text-[10px] text-muted">{count}</span>
                        </div>
                      ),
                    )}
                  </div>
                </div>
              )}

              <CorpusMetadataViewer metadata={corpusDetail.metadata} />

              {/* Future hooks */}
              <div
                className="rounded border border-border bg-muted/5 p-3"
                aria-label="corpus-future-hooks"
              >
                <div className="flex items-center gap-1 mb-1">
                  <ShieldCheck className="h-3 w-3 text-muted" aria-hidden="true" />
                  <p className="text-[10px] font-medium text-muted">
                    Future capabilities (not yet available)
                  </p>
                </div>
                <ul className="space-y-0.5 text-[9px] text-muted">
                  <li>Connector sync health — not yet available</li>
                  <li>Stale corpus detection — not yet available</li>
                  <li>Duplicate detection — not yet available</li>
                  <li>Evidence lineage — not yet available</li>
                </ul>
              </div>

              {/* Document Browser */}
              <div
                className="rounded border border-border bg-card p-3"
                aria-label="document-browser-section"
              >
                <DocumentBrowser corpusId={selectedCorpusId} />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
