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
  | 'reindexing';

export interface UploadResult {
  document_id: string;
  corpus_id: string;
  title: string | null;
  source: string | null;
  ingestion_status: IngestionStatus;
  ingestion_status_label: string;
  source_hash_prefix: string | null;
  quarantine_reason: string | null;
  quarantine_reason_label: string | null;
  failure_reason: string | null;
  is_current: boolean;
  version_id: string | null;
  version_number: number;
  active_chunk_count: number;
  total_chunk_count: number;
  embedding_state_summary: Record<string, number>;
  duplicate_of_document_id: string | null;
  created_at: string | null;
  indexed_at: string | null;
  audit_safe: true;
}

export interface UploadListItem {
  document_id: string;
  corpus_id: string;
  title: string | null;
  source: string | null;
  ingestion_status: IngestionStatus;
  ingestion_status_label: string;
  is_current: boolean;
  version_number: number;
  created_at: string | null;
  indexed_at: string | null;
}

export interface UploadListPage {
  items: UploadListItem[];
  total: number;
  limit: number;
  offset: number;
  sort_dir: string;
  corpus_id_filter: string | null;
  ingestion_status_filter: string | null;
}

export interface DocumentIngestionDetail {
  document_id: string;
  corpus_id: string;
  title: string | null;
  source: string | null;
  ingestion_status: IngestionStatus;
  ingestion_status_label: string;
  is_current: boolean;
  version_id: string | null;
  version_number: number;
  source_hash_prefix: string | null;
  quarantine_reason: string | null;
  quarantine_reason_label: string | null;
  failure_reason: string | null;
  active_chunk_count: number;
  total_chunk_count: number;
  embedding_state_summary: Record<string, number>;
  duplicate_of_document_id: string | null;
  created_at: string | null;
  indexed_at: string | null;
  audit_safe: true;
}

export interface UploadListQuery {
  corpus_id?: string;
  ingestion_status?: IngestionStatus;
  limit?: number;
  offset?: number;
  sort_dir?: 'asc' | 'desc';
}

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status?: number };

async function coreRequest<T>(path: string, init?: RequestInit): Promise<SafeResult<T>> {
  try {
    const res = await fetch(`/api/core/${path}`, {
      ...init,
      headers:
        init?.body instanceof FormData
          ? (init.headers ?? undefined)
          : { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
      cache: 'no-store',
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, error: text || res.statusText, status: res.status };
    }
    const data = (await res.json()) as T;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function uploadDocument(
  file: File,
  corpusId: string,
  title?: string,
): Promise<SafeResult<UploadResult>> {
  const form = new FormData();
  form.append('file', file);
  form.append('corpus_id', corpusId);
  if (title) form.append('title', title);
  return coreRequest<UploadResult>('rag/upload', { method: 'POST', body: form });
}

export async function listUploads(
  query: UploadListQuery = {},
): Promise<SafeResult<UploadListPage>> {
  const params = new URLSearchParams();
  if (query.corpus_id) params.set('corpus_id', query.corpus_id);
  if (query.ingestion_status) params.set('ingestion_status', query.ingestion_status);
  if (query.limit != null) params.set('limit', String(query.limit));
  if (query.offset != null) params.set('offset', String(query.offset));
  if (query.sort_dir) params.set('sort_dir', query.sort_dir);
  const qs = params.toString();
  return coreRequest<UploadListPage>(`rag/uploads${qs ? '?' + qs : ''}`);
}

export async function getDocumentIngestion(
  documentId: string,
): Promise<SafeResult<DocumentIngestionDetail>> {
  return coreRequest<DocumentIngestionDetail>(`rag/documents/${encodeURIComponent(documentId)}/ingestion`);
}
