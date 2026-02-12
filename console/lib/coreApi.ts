import { mapHttpError } from '@/lib/errors';

export interface DecisionsQuery {
  limit?: number;
  offset?: number;
  event_type?: string;
  threat_level?: string;
}

export interface DecisionsPage {
  items: DecisionOut[];
  limit: number;
  offset: number;
  total: number;
}

export interface DecisionOut {
  id: string;
  tenant_id: string;
  source: string;
  event_id: string;
  event_type: string;
  threat_level: string;
  created_at?: string;
  explain_summary?: string;
  [key: string]: unknown;
}

export interface ListKeysResponse {
  keys: Array<Record<string, unknown>>;
  total: number;
}

export interface AlignmentArtifact {
  pass?: boolean;
  drift_status?: string;
  drift_count?: number;
  checked_count?: number;
  generated_at?: string;
  commit?: string;
  [key: string]: unknown;
}

interface RequestOptions {
  mask404?: boolean;
}

async function request<T>(path: string, init: RequestInit = {}, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (!headers.has('Content-Type') && init.method && init.method !== 'GET') {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`/api/core${path}`, {
    ...init,
    headers,
    cache: 'no-store',
  });

  let payload: unknown = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) throw mapHttpError(response.status, payload, options);
  return payload as T;
}

export function getHealthLive() {
  return request<Record<string, unknown>>('/health/live');
}

export function getHealthReady() {
  return request<Record<string, unknown>>('/health/ready');
}

export function getStatsSummary() {
  return request<Record<string, unknown>>('/stats/summary');
}

export function getFeedLive(limit = 1) {
  return request<{ items: Array<Record<string, unknown>>; next_since_id?: string }>(`/feed/live?limit=${encodeURIComponent(String(limit))}`);
}

export function getChainVerify() {
  return request<Record<string, unknown>>('/forensics/chain/verify');
}

export function listDecisions(query: DecisionsQuery) {
  const params = new URLSearchParams();
  params.set('limit', String(query.limit ?? 20));
  params.set('offset', String(query.offset ?? 0));
  if (query.event_type) params.set('event_type', query.event_type);
  if (query.threat_level) params.set('threat_level', query.threat_level);
  return request<DecisionsPage>(`/decisions?${params.toString()}`);
}

export function getDecision(decisionId: string) {
  return request<DecisionOut>(`/decisions/${encodeURIComponent(decisionId)}`);
}

export function getForensicsSnapshot(eventId: string) {
  return request<Record<string, unknown>>(`/forensics/snapshot/${encodeURIComponent(eventId)}`, {}, { mask404: true });
}

export function getForensicsAuditTrail(eventId: string) {
  return request<Record<string, unknown>>(`/forensics/audit_trail/${encodeURIComponent(eventId)}`, {}, { mask404: true });
}

export function listKeys() {
  return request<ListKeysResponse>('/keys');
}

export function createKey(body: { name?: string; scopes: string[]; tenant_id?: string; ttl_seconds: number }) {
  return request<Record<string, unknown>>('/keys', { method: 'POST', body: JSON.stringify(body) });
}

export function revokeKey(prefix: string) {
  return request<Record<string, unknown>>('/keys/revoke', {
    method: 'POST',
    body: JSON.stringify({ prefix }),
  });
}

export function rotateKey(currentKey: string, ttlSeconds: number) {
  return request<Record<string, unknown>>('/keys/rotate', {
    method: 'POST',
    body: JSON.stringify({ current_key: currentKey, ttl_seconds: ttlSeconds, revoke_old: true }),
  });
}

export function deleteKey(prefix: string) {
  return request<Record<string, unknown>>(`/keys/${encodeURIComponent(prefix)}`, {
    method: 'DELETE',
  });
}

export async function readAlignmentArtifact(): Promise<AlignmentArtifact | null> {
  const response = await fetch('/api/core/alignment-artifact', { cache: 'no-store' });
  if (!response.ok) return null;
  const payload = (await response.json()) as { artifact?: AlignmentArtifact | null };
  return payload.artifact || null;
}
