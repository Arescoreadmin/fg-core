/**
 * Thin API client for tenant-scoped retrieval policy endpoints.
 *
 * All requests are proxied through /api/core which injects the CORE_API_KEY
 * and CORE_TENANT_ID — no credentials are handled client-side.
 *
 * Tenant isolation: the proxy enforces one tenant per session.
 * These functions never accept or forward a tenant_id parameter.
 */

import { mapHttpError } from '@/lib/errors';

export interface StoredRetrievalPolicy {
  tenant_id: string;
  rag_enabled: boolean;
  allowed_corpus_ids: string[];
  denied_corpus_ids: string[];
  max_top_k: number;
  allowed_retrieval_strategies: string[];
  require_grounded_response: boolean;
  no_answer_on_ungrounded: boolean;
  require_grounded_context: boolean;
  allow_lexical_fallback: boolean;
  allow_semantic: boolean;
  allow_no_context_answer: boolean;
  reranking_enabled: boolean;
  policy_version: number;
  updated_by: string | null;
  updated_at: string | null;
}

export interface CorpusListEntry {
  corpus_id: string;
  name: string;
  description?: string | null;
}

export type RetrievalPolicySaveRequest = Omit<
  StoredRetrievalPolicy,
  'tenant_id' | 'policy_version' | 'updated_by' | 'updated_at'
>;

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

/** Fetch the current retrieval policy. Throws NOT_FOUND if not configured. */
export function getRetrievalPolicy(): Promise<StoredRetrievalPolicy> {
  return coreRequest<StoredRetrievalPolicy>('/rag/retrieval-policy');
}

/** Validate and persist the retrieval policy. Throws on invalid config (422). */
export function putRetrievalPolicy(
  body: RetrievalPolicySaveRequest,
): Promise<StoredRetrievalPolicy> {
  return coreRequest<StoredRetrievalPolicy>('/rag/retrieval-policy', {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

/** List tenant-scoped corpora for the policy UI. Returns [] if none ingested. */
export function getCorpora(): Promise<CorpusListEntry[]> {
  return coreRequest<CorpusListEntry[]>('/rag/corpora');
}
