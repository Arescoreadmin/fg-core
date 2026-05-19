'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Database,
  FileText,
  Layers,
  RefreshCw,
  ShieldAlert,
  Upload,
  XCircle,
} from 'lucide-react';

import {
  type DocumentIngestionDetail,
  type IngestionStatus,
  type UploadResult,
  getDocumentIngestion,
  listUploads,
  uploadDocument,
} from '@/lib/ingestionApi';
import { getCorpora } from '@/lib/retrievalPolicyApi';
import type { CorpusListEntry } from '@/lib/retrievalPolicyApi';

interface QueuedFile {
  id: string;
  file: File;
  corpusId: string;
  state: 'pending' | 'uploading' | 'complete' | 'error';
  result: UploadResult | null;
  ingestionDetail: DocumentIngestionDetail | null;
  error: string | null;
  refreshing: boolean;
}

export interface DocumentIngestionConsoleProps {
  initialCorpora?: CorpusListEntry[] | null;
}

interface StatusConfig {
  label: string;
  textClass: string;
  bgClass: string;
}

const STATUS_CONFIG: Record<string, StatusConfig> = {
  'indexed':    { label: 'Indexed',    textClass: 'text-green-700',  bgClass: 'bg-green-50 border-green-200' },
  'duplicate':  { label: 'Duplicate',  textClass: 'text-yellow-700', bgClass: 'bg-yellow-50 border-yellow-200' },
  'quarantined':{ label: 'Quarantined',textClass: 'text-red-700',    bgClass: 'bg-red-50 border-red-200' },
  'failed':     { label: 'Failed',     textClass: 'text-red-700',    bgClass: 'bg-red-50 border-red-200' },
  'superseded': { label: 'Superseded', textClass: 'text-muted',      bgClass: 'bg-muted/10 border-border' },
  'embedding':  { label: 'Embedding',  textClass: 'text-blue-700',   bgClass: 'bg-blue-50 border-blue-200' },
  'chunking':   { label: 'Chunking',   textClass: 'text-blue-700',   bgClass: 'bg-blue-50 border-blue-200' },
  'received':   { label: 'Received',   textClass: 'text-blue-700',   bgClass: 'bg-blue-50 border-blue-200' },
  'validating': { label: 'Validating', textClass: 'text-blue-700',   bgClass: 'bg-blue-50 border-blue-200' },
  'reindexing': { label: 'Re-indexing',textClass: 'text-blue-700',   bgClass: 'bg-blue-50 border-blue-200' },
};

function getStatusConfig(status: string): StatusConfig {
  return STATUS_CONFIG[status] ?? { label: `Unknown (${status})`, textClass: 'text-muted', bgClass: 'bg-muted/10 border-border' };
}

function IngestionStatusBadge({ status }: { status: IngestionStatus }) {
  const cfg = getStatusConfig(status);
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium ${cfg.textClass} ${cfg.bgClass}`}
      aria-label={`Ingestion status: ${cfg.label}`}
    >
      {cfg.label}
    </span>
  );
}

function EmbeddingStateBadge({ state }: { state: string }) {
  const labels: Record<string, string> = {
    'pending': 'Pending', 'processing': 'Processing', 'completed': 'Completed',
    'failed': 'Failed', 'skipped': 'Skipped',
  };
  const label = labels[state] ?? `Unknown (${state})`;
  const tc = state === 'completed' ? 'text-green-700' : state === 'failed' ? 'text-red-700' : state === 'processing' ? 'text-blue-700' : 'text-muted';
  return (
    <span className={`inline-flex rounded border border-border px-1.5 py-0.5 text-[10px] font-medium ${tc}`} aria-label={`Embedding state: ${label}`}>
      {label}
    </span>
  );
}

interface UploadDropzoneProps {
  corpora: CorpusListEntry[];
  selectedCorpusId: string;
  onCorpusChange: (id: string) => void;
  onFiles: (files: File[], corpusId: string) => void;
  disabled: boolean;
}

export function UploadDropzone({ corpora, selectedCorpusId, onCorpusChange, onFiles, disabled }: UploadDropzoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const canUpload = !disabled && !!selectedCorpusId;

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    if (!canUpload) return;
    const files = Array.from(e.dataTransfer.files).filter(f => f.size > 0);
    if (files.length > 0) onFiles(files, selectedCorpusId);
  }, [canUpload, selectedCorpusId, onFiles]);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (!selectedCorpusId) return;
    const files = Array.from(e.target.files ?? []).filter(f => f.size > 0);
    if (files.length > 0) onFiles(files, selectedCorpusId);
    if (inputRef.current) inputRef.current.value = '';
  }, [selectedCorpusId, onFiles]);

  return (
    <div className="space-y-3" aria-label="upload-dropzone">
      <div className="flex flex-col gap-1">
        <label htmlFor="ingestion-corpus-select" className="text-[10px] font-medium text-foreground">Target Corpus</label>
        {corpora.length === 0 ? (
          <p className="text-[10px] text-muted" aria-label="no-corpora-available">No corpora available. Create a corpus before uploading.</p>
        ) : (
          <select
            id="ingestion-corpus-select"
            value={selectedCorpusId}
            onChange={e => onCorpusChange(e.target.value)}
            disabled={disabled}
            className="rounded border border-border bg-background px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            aria-label="corpus-selector"
          >
            <option value="">— select a corpus —</option>
            {corpora.map(c => <option key={c.corpus_id} value={c.corpus_id}>{c.name || c.corpus_id}</option>)}
          </select>
        )}
      </div>
      <div
        role="region"
        aria-label="file-drop-zone"
        className={`flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 text-center transition-colors ${dragOver && canUpload ? 'border-primary bg-primary/5' : 'border-border bg-muted/5'} ${!canUpload ? 'cursor-not-allowed opacity-50' : 'cursor-pointer hover:border-primary/60'}`}
        onDragOver={e => { e.preventDefault(); if (canUpload) setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => canUpload && inputRef.current?.click()}
      >
        <Upload className={`h-8 w-8 ${dragOver && canUpload ? 'text-primary' : 'text-muted'}`} aria-hidden="true" />
        <p className="text-xs text-foreground">
          {canUpload ? 'Drop files here or click to select' : selectedCorpusId ? 'Upload in progress…' : 'Select a corpus first'}
        </p>
        <p className="text-[10px] text-muted">Supported: .txt, .md — Max 1 MB per file</p>
        <input
          ref={inputRef}
          type="file"
          multiple
          accept=".txt,.md,.markdown,text/plain,text/markdown"
          className="hidden"
          onChange={handleInputChange}
          disabled={!canUpload}
          aria-label="file-input"
          data-testid="file-input"
        />
      </div>
    </div>
  );
}

export function ChunkingProgressPanel({ activeChunkCount, totalChunkCount }: { activeChunkCount: number; totalChunkCount: number }) {
  const supersededCount = Math.max(0, totalChunkCount - activeChunkCount);
  return (
    <div className="rounded border border-border bg-muted/5 p-2" aria-label="chunking-progress-panel">
      <p className="mb-1.5 text-[10px] font-semibold text-foreground">Chunking Visibility</p>
      <dl className="grid grid-cols-3 gap-2 text-[10px]">
        <div><dt className="text-muted">Total Chunks</dt><dd className="font-medium text-foreground" aria-label="total-chunk-count">{totalChunkCount}</dd></div>
        <div><dt className="text-muted">Active</dt><dd className="font-medium text-green-700" aria-label="active-chunk-count">{activeChunkCount}</dd></div>
        <div><dt className="text-muted">Superseded</dt><dd className="font-medium text-muted" aria-label="superseded-chunk-count">{supersededCount}</dd></div>
      </dl>
      <p className="mt-1 text-[9px] text-muted">Raw chunk text is not exposed. Counts reflect actual backend state.</p>
    </div>
  );
}

export function EmbeddingProgressPanel({ embeddingStateSummary }: { embeddingStateSummary: Record<string, number> }) {
  const entries = Object.entries(embeddingStateSummary);
  if (entries.length === 0) {
    return (
      <div className="rounded border border-border bg-muted/5 p-2" aria-label="embedding-progress-panel">
        <p className="text-[10px] font-semibold text-foreground">Embedding State</p>
        <p className="mt-1 text-[10px] text-muted">Embedding state unavailable.</p>
      </div>
    );
  }
  return (
    <div className="rounded border border-border bg-muted/5 p-2" aria-label="embedding-progress-panel">
      <p className="mb-1.5 text-[10px] font-semibold text-foreground">Embedding State</p>
      <div className="flex flex-wrap gap-2">
        {entries.map(([state, count]) => (
          <div key={state} className="flex flex-col items-center gap-0.5" aria-label={`embedding-state-${state}`}>
            <EmbeddingStateBadge state={state} />
            <span className="text-[10px] text-muted">{count}</span>
          </div>
        ))}
      </div>
      <p className="mt-1 text-[9px] text-muted">Raw vectors and embeddings are not exposed.</p>
    </div>
  );
}

export function IngestionFailurePanel({
  ingestionStatus, quarantineReason, quarantineReasonLabel, failureReason,
}: {
  ingestionStatus: IngestionStatus;
  quarantineReason: string | null;
  quarantineReasonLabel: string | null;
  failureReason: string | null;
}) {
  const isFailure = ingestionStatus === 'failed';
  const isQuarantined = ingestionStatus === 'quarantined';
  const isDuplicate = ingestionStatus === 'duplicate';
  if (!isFailure && !isQuarantined && !isDuplicate) return null;
  return (
    <div className="space-y-1">
      {isQuarantined && (
        <div className="rounded border border-red-200 bg-red-50 p-2" role="alert" aria-label="ingestion-failure-panel">
          <p className="text-[10px] font-semibold text-red-700">Quarantined</p>
          <p className="mt-0.5 text-[10px] text-red-600">{quarantineReasonLabel || quarantineReason || 'Unknown quarantine reason'}</p>
          <p className="mt-1 text-[9px] text-red-500">This document was quarantined and will not be retrieved.</p>
        </div>
      )}
      {isFailure && (
        <div className="rounded border border-red-200 bg-red-50 p-2" role="alert" aria-label="ingestion-failure-panel">
          <p className="text-[10px] font-semibold text-red-700">Ingestion Failed</p>
          {failureReason && <p className="mt-0.5 text-[10px] text-red-600">{failureReason}</p>}
          <p className="mt-1 text-[9px] text-red-500">Retry ingestion is not yet available.</p>
        </div>
      )}
      {isDuplicate && (
        <div className="rounded border border-yellow-200 bg-yellow-50 p-2" role="alert" aria-label="ingestion-failure-panel">
          <p className="text-[10px] font-semibold text-yellow-700">Duplicate Detected</p>
          <p className="mt-0.5 text-[10px] text-yellow-600">An identical document already exists in this corpus.</p>
        </div>
      )}
    </div>
  );
}

const _LIFECYCLE_ORDER: IngestionStatus[] = ['received', 'validating', 'chunking', 'embedding', 'indexed'];

export function IngestionLifecycleTimeline({
  ingestionStatus, createdAt, indexedAt,
}: { ingestionStatus: IngestionStatus; createdAt: string | null; indexedAt: string | null }) {
  const terminalStatuses = new Set(['failed', 'quarantined', 'duplicate', 'superseded']);
  const isTerminal = terminalStatuses.has(ingestionStatus);
  return (
    <div className="rounded border border-border bg-muted/5 p-2" aria-label="ingestion-lifecycle-timeline">
      <p className="mb-2 text-[10px] font-semibold text-foreground">Lifecycle Timeline</p>
      {isTerminal ? (
        <div className="flex items-center gap-2 text-[10px] text-muted">
          <IngestionStatusBadge status={ingestionStatus} />
          <span>Terminal state</span>
        </div>
      ) : (
        <ol className="flex items-center gap-0" aria-label="lifecycle-steps">
          {_LIFECYCLE_ORDER.map((step, i) => {
            const isCurrent = step === ingestionStatus;
            const isPast = _LIFECYCLE_ORDER.indexOf(ingestionStatus) > i;
            return (
              <li key={step} className="flex items-center">
                <div className={`flex h-5 w-5 items-center justify-center rounded-full border text-[9px] font-bold ${isPast ? 'border-green-500 bg-green-100 text-green-700' : isCurrent ? 'border-primary bg-primary/10 text-primary' : 'border-border bg-muted/10 text-muted'}`} aria-label={`step-${step}`}>
                  {isPast ? '✓' : i + 1}
                </div>
                <span className={`mx-1 text-[9px] ${isCurrent ? 'font-semibold text-foreground' : 'text-muted'}`}>{getStatusConfig(step).label}</span>
                {i < _LIFECYCLE_ORDER.length - 1 && <span className="mx-1 text-muted" aria-hidden="true">→</span>}
              </li>
            );
          })}
        </ol>
      )}
      <div className="mt-2 flex gap-4 text-[9px] text-muted">
        {createdAt && <span>Received: {new Date(createdAt).toLocaleString()}</span>}
        {indexedAt && <span>Indexed: {new Date(indexedAt).toLocaleString()}</span>}
      </div>
    </div>
  );
}

export function UploadAuditSummary({ result }: { result: UploadResult | DocumentIngestionDetail }) {
  return (
    <div className="rounded border border-border bg-muted/5 p-2" aria-label="upload-audit-summary">
      <p className="mb-1.5 text-[10px] font-semibold text-foreground">Audit Summary</p>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[10px]">
        <div><dt className="text-muted">Document ID</dt><dd className="truncate font-mono text-[9px] text-foreground" aria-label="audit-document-id">{result.document_id}</dd></div>
        {result.version_id && <div><dt className="text-muted">Version ID</dt><dd className="truncate font-mono text-[9px] text-foreground" aria-label="audit-version-id">{result.version_id}</dd></div>}
        {result.source_hash_prefix && <div><dt className="text-muted">Source Hash (prefix)</dt><dd className="font-mono text-[9px] text-foreground" aria-label="audit-source-hash-prefix">{result.source_hash_prefix}…</dd></div>}
        <div><dt className="text-muted">Version</dt><dd className="text-foreground" aria-label="audit-version-number">v{result.version_number}</dd></div>
      </dl>
      <p className="mt-1.5 text-[9px] text-muted">Export-safe. No raw vectors, prompts, or provider data. audit_safe: true.</p>
    </div>
  );
}

export function ConnectorIngestionPlaceholder() {
  return (
    <div className="rounded border border-dashed border-border p-3" aria-label="connector-ingestion-placeholder">
      <p className="text-[10px] font-semibold text-muted">Connector Ingestion — Planned</p>
      <p className="mt-0.5 text-[9px] text-muted">Future capability: SharePoint, Google Drive, Confluence, and custom connector ingestion. Not yet available. future_hooks are placeholders only.</p>
      <ul className="mt-2 space-y-0.5 text-[9px] text-muted">
        {['SharePoint ingestion', 'Google Drive ingestion', 'Confluence ingestion', 'Batch ingestion', 'Delta sync', 'Sync scheduling', 'Ingestion replay', 'GraphRAG lineage'].map(item => (
          <li key={item} className="flex items-center gap-1">
            <span className="h-1 w-1 rounded-full bg-muted/40" aria-hidden="true" />
            {item} — <em>not yet available</em>
          </li>
        ))}
      </ul>
    </div>
  );
}

interface UploadQueueItemProps {
  item: QueuedFile;
  onRefresh: (id: string) => void;
  onExpand: (id: string) => void;
  expanded: boolean;
}

function UploadQueueItem({ item, onRefresh, onExpand, expanded }: UploadQueueItemProps) {
  const result = item.result;
  const detail = item.ingestionDetail;
  const displayStatus: IngestionStatus = item.state === 'uploading' ? 'received' : item.state === 'error' ? 'failed' : result?.ingestion_status ?? 'received';
  return (
    <li className="rounded border border-border bg-background" aria-label={`upload-queue-item-${item.id}`}>
      <div className="flex items-center gap-2 p-2">
        <FileText className="h-4 w-4 shrink-0 text-muted" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="truncate text-xs font-medium text-foreground">{item.file.name}</p>
          <p className="text-[10px] text-muted">{(item.file.size / 1024).toFixed(1)} KB</p>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          {item.state === 'uploading' && <span className="text-[10px] text-blue-600" aria-live="polite">Uploading…</span>}
          {item.state !== 'uploading' && <IngestionStatusBadge status={displayStatus} />}
          {item.state === 'complete' && result && (
            <>
              <button type="button" onClick={() => onRefresh(item.id)} disabled={item.refreshing} className="rounded p-0.5 text-muted hover:text-foreground focus:outline-none focus:ring-1 focus:ring-primary" aria-label="refresh-ingestion-status" title="Refresh ingestion status">
                <RefreshCw className={`h-3 w-3 ${item.refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
              </button>
              <button type="button" onClick={() => onExpand(item.id)} className="rounded p-0.5 text-muted hover:text-foreground focus:outline-none focus:ring-1 focus:ring-primary" aria-label={expanded ? 'collapse-detail' : 'expand-detail'}>
                {expanded ? <ChevronDown className="h-3 w-3" aria-hidden="true" /> : <ChevronRight className="h-3 w-3" aria-hidden="true" />}
              </button>
            </>
          )}
        </div>
      </div>
      {item.state === 'error' && item.error && (
        <div className="border-t border-red-200 bg-red-50 px-2 py-1.5" role="alert" aria-label="upload-error">
          <p className="text-[10px] text-red-600">{item.error}</p>
        </div>
      )}
      {expanded && item.state === 'complete' && result && (
        <div className="space-y-2 border-t border-border p-2" aria-label="upload-detail-expanded">
          <IngestionLifecycleTimeline
            ingestionStatus={(detail?.ingestion_status ?? result.ingestion_status) as IngestionStatus}
            createdAt={detail?.created_at ?? result.created_at}
            indexedAt={detail?.indexed_at ?? result.indexed_at}
          />
          <IngestionFailurePanel
            ingestionStatus={(detail?.ingestion_status ?? result.ingestion_status) as IngestionStatus}
            quarantineReason={detail?.quarantine_reason ?? result.quarantine_reason}
            quarantineReasonLabel={detail?.quarantine_reason_label ?? result.quarantine_reason_label}
            failureReason={detail?.failure_reason ?? result.failure_reason}
          />
          <ChunkingProgressPanel
            activeChunkCount={detail?.active_chunk_count ?? result.active_chunk_count}
            totalChunkCount={detail?.total_chunk_count ?? result.total_chunk_count}
          />
          <EmbeddingProgressPanel embeddingStateSummary={detail?.embedding_state_summary ?? result.embedding_state_summary} />
          <UploadAuditSummary result={detail ?? result} />
        </div>
      )}
    </li>
  );
}

export function DocumentIngestionConsole({ initialCorpora }: DocumentIngestionConsoleProps) {
  const [corpora, setCorpora] = useState<CorpusListEntry[]>(initialCorpora ?? []);
  const [corporaLoading, setCorporaLoading] = useState(!initialCorpora);
  const [corporaError, setCorporaError] = useState<string | null>(null);
  const [selectedCorpusId, setSelectedCorpusId] = useState('');
  const [queue, setQueue] = useState<QueuedFile[]>([]);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [uploading, setUploading] = useState(false);

  const loadCorpora = useCallback(async () => {
    setCorporaLoading(true);
    setCorporaError(null);
    try {
      const data = await getCorpora();
      setCorpora(data);
    } catch (err) {
      setCorporaError(err instanceof Error ? err.message : 'Failed to load corpora');
    }
    setCorporaLoading(false);
  }, []);

  useEffect(() => {
    if (!initialCorpora) {
      void loadCorpora();
    }
  }, [initialCorpora, loadCorpora]);

  const handleFiles = useCallback(async (files: File[], corpusId: string) => {
    if (!corpusId || files.length === 0) return;
    setUploading(true);
    const newItems: QueuedFile[] = files.map(f => ({
      id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      file: f, corpusId, state: 'uploading', result: null, ingestionDetail: null, error: null, refreshing: false,
    }));
    setQueue(prev => [...newItems, ...prev]);
    for (const item of newItems) {
      const res = await uploadDocument(item.file, corpusId);
      setQueue(prev => prev.map(q => q.id === item.id ? { ...q, state: res.ok ? 'complete' : 'error', result: res.ok ? res.data : null, error: res.ok ? null : res.error } : q));
      if (res.ok) setExpandedIds(prev => { const next = new Set(prev); next.add(item.id); return next; });
    }
    setUploading(false);
  }, []);

  const handleRefresh = useCallback(async (id: string) => {
    const item = queue.find(q => q.id === id);
    if (!item || !item.result) return;
    setQueue(prev => prev.map(q => q.id === id ? { ...q, refreshing: true } : q));
    const res = await getDocumentIngestion(item.result.document_id);
    setQueue(prev => prev.map(q => q.id === id ? { ...q, refreshing: false, ingestionDetail: res.ok ? res.data : q.ingestionDetail } : q));
  }, [queue]);

  const handleExpand = useCallback((id: string) => {
    setExpandedIds(prev => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }, []);

  return (
    <div className="space-y-4" aria-label="document-ingestion-console">
      <div className="rounded border border-border bg-background p-3">
        <div className="mb-2 flex items-center gap-2">
          <Upload className="h-4 w-4 text-primary" aria-hidden="true" />
          <h3 className="text-xs font-semibold text-foreground">Upload Documents</h3>
        </div>
        {corporaLoading ? (
          <p className="text-[10px] text-muted" aria-label="corpora-loading">Loading corpora…</p>
        ) : corporaError ? (
          <div role="alert" aria-label="corpora-error">
            <p className="text-[10px] text-red-600">{corporaError}</p>
            <button type="button" onClick={loadCorpora} className="mt-1 text-[10px] text-primary hover:underline">Retry</button>
          </div>
        ) : (
          <UploadDropzone corpora={corpora} selectedCorpusId={selectedCorpusId} onCorpusChange={setSelectedCorpusId} onFiles={handleFiles} disabled={uploading} />
        )}
      </div>
      {queue.length > 0 && (
        <div className="rounded border border-border bg-background p-3" aria-label="upload-queue">
          <div className="mb-2 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-muted" aria-hidden="true" />
              <h3 className="text-xs font-semibold text-foreground">Upload Queue</h3>
              <span className="rounded-full bg-muted/20 px-1.5 py-0.5 text-[10px] text-muted">{queue.length}</span>
            </div>
            {uploading && <span className="flex items-center gap-1 text-[10px] text-blue-600" aria-live="polite"><RefreshCw className="h-3 w-3 animate-spin" aria-hidden="true" />Processing…</span>}
          </div>
          <ul className="space-y-1" aria-label="upload-queue-list">
            {queue.map(item => <UploadQueueItem key={item.id} item={item} onRefresh={handleRefresh} onExpand={handleExpand} expanded={expandedIds.has(item.id)} />)}
          </ul>
        </div>
      )}
      <ConnectorIngestionPlaceholder />
    </div>
  );
}

export {
  IngestionStatusBadge as IngestionUXStatusBadge,
  EmbeddingStateBadge as IngestionUXEmbeddingBadge,
};
