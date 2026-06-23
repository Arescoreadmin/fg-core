/**
 * Thin API client for Corpus Management Console endpoints.
 *
 * All requests are proxied through /api/core which injects CORE_API_KEY and
 * CORE_TENANT_ID — no credentials handled client-side.
 *
 * Tenant isolation: the BFF proxy enforces one tenant per session.
 * These functions never accept or forward a tenant_id parameter.
 */

import { mapHttpError } from '@/lib/errors';

// ─── Types ───────────────────────────────────────────────────────────────────

export type IngestionStatus =
  | 'received'
  | 'validating'
  | 'duplicate'
  | 'quarantined'
  | 'chunking'
  | 'embedding'
  | 'indexed'
  | 'failed'
  | 'superseded'
  | 'reindexing'
  | string;

export type EmbeddingState =
  | 'pending'
  | 'processing'
  | 'completed'
  | 'failed'
  | 'skipped'
  | string;

export interface CorpusDetail {
  corpus_id: string;
  name: string;
  description?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  total_document_count: number;
  active_document_count: number;
  total_chunk_count: number;
  active_chunk_count: number;
  ingestion_status_summary: Record<string, number>;
  embedding_state_summary: Record<string, number>;
  metadata?: Record<string, unknown> | null;
  future_hooks: {
    connector_type: null;
    sync_health: null;
    stale_warning: null;
    duplicate_detection: null;
  };
}

export interface DocumentSummary {
  document_id: string;
  title?: string | null;
  source?: string | null;
  version_id?: string | null;
  version_number: number;
  is_current: boolean;
  ingestion_status: IngestionStatus;
  quarantine_reason?: string | null;
  failure_reason?: string | null;
  source_hash_prefix?: string | null;
  indexed_at?: string | null;
  superseded_at?: string | null;
  active_chunk_count: number;
  total_chunk_count: number;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface DocumentPage {
  corpus_id: string;
  items: DocumentSummary[];
  total: number;
  limit: number;
  offset: number;
  sort_by: string;
  sort_dir: string;
}

export interface DocumentDetail extends DocumentSummary {
  corpus_id?: string | null;
  superseded_by_version_id?: string | null;
  embedding_state_summary: Record<string, number>;
  metadata?: Record<string, unknown> | null;
  future_hooks: {
    duplicate_detection: null;
    stale_detection: null;
    evidence_lineage: null;
  };
}

export type SortBy =
  | 'created_at'
  | 'updated_at'
  | 'title'
  | 'ingestion_status'
  | 'version_number';

export type SortDir = 'asc' | 'desc';

export interface DocumentListQuery {
  limit?: number;
  offset?: number;
  ingestion_status?: IngestionStatus | null;
  is_current?: boolean | null;
  sort_by?: SortBy;
  sort_dir?: SortDir;
}

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status?: number };

// ─── Internal request helper ──────────────────────────────────────────────────

async function coreRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has('Content-Type') && init.method && init.method !== 'GET') {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(`/api/core${path}`, {
    ...init,
    headers,
    cache: 'no-store',
  });
  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }
  if (!response.ok) {
    throw mapHttpError(response.status, payload, {});
  }
  return payload as T;
}

// ─── API functions ────────────────────────────────────────────────────────────

/** Fetch corpus detail with operational stats. Returns SafeResult to allow graceful UI error handling. */
export async function getCorpusDetail(
  corpusId: string,
): Promise<SafeResult<CorpusDetail>> {
  try {
    const data = await coreRequest<CorpusDetail>(
      `/rag/corpora/${encodeURIComponent(corpusId)}`,
    );
    return { ok: true, data };
  } catch (err) {
    const status = err instanceof Error && 'status' in err
      ? (err as { status?: number }).status
      : undefined;
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'fetch_error',
      status,
    };
  }
}

/** List documents in a corpus with pagination and filtering. */
export async function listCorpusDocuments(
  corpusId: string,
  query: DocumentListQuery = {},
): Promise<SafeResult<DocumentPage>> {
  try {
    const params = new URLSearchParams();
    if (query.limit != null) params.set('limit', String(query.limit));
    if (query.offset != null) params.set('offset', String(query.offset));
    if (query.ingestion_status != null) params.set('ingestion_status', query.ingestion_status);
    if (query.is_current != null) params.set('is_current', String(query.is_current));
    if (query.sort_by) params.set('sort_by', query.sort_by);
    if (query.sort_dir) params.set('sort_dir', query.sort_dir);
    const qs = params.toString();
    const data = await coreRequest<DocumentPage>(
      `/rag/corpora/${encodeURIComponent(corpusId)}/documents${qs ? `?${qs}` : ''}`,
    );
    return { ok: true, data };
  } catch (err) {
    const status = err instanceof Error && 'status' in err
      ? (err as { status?: number }).status
      : undefined;
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'fetch_error',
      status,
    };
  }
}

/** Fetch single document detail with chunk summary. */
export async function getDocumentDetail(
  documentId: string,
): Promise<SafeResult<DocumentDetail>> {
  try {
    const data = await coreRequest<DocumentDetail>(
      `/rag/documents/${encodeURIComponent(documentId)}`,
    );
    return { ok: true, data };
  } catch (err) {
    const status = err instanceof Error && 'status' in err
      ? (err as { status?: number }).status
      : undefined;
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'fetch_error',
      status,
    };
  }
}
