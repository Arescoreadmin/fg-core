import { mapHttpError } from '@/lib/errors';

export interface DecisionsQuery {
  limit?: number;
  offset?: number;
  event_type?: string;
  threat_level?: string;
  decision_type?: string;
  severity?: string;
  search?: string;
  from?: string;
  to?: string;
}

export interface ApiMeta {
  requestId?: string;
  idempotentReplay?: string;
  responseHash?: string;
  receivedAt: string;
}

export interface ApiResult<T> {
  data: T;
  meta: ApiMeta;
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
  const result = await requestWithMeta<T>(path, init, options);
  return result.data;
}

async function requestWithMeta<T>(path: string, init: RequestInit = {}, options: RequestOptions = {}): Promise<ApiResult<T>> {
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
  return {
    data: payload as T,
    meta: {
      requestId: response.headers.get('x-request-id') || undefined,
      idempotentReplay: response.headers.get('idempotent-replay') || undefined,
      responseHash: response.headers.get('x-response-hash') || undefined,
      receivedAt: new Date().toISOString(),
    },
  };
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

export function getChainVerifyWithMeta() {
  return requestWithMeta<Record<string, unknown>>('/forensics/chain/verify');
}

export function listDecisions(query: DecisionsQuery) {
  const params = new URLSearchParams();
  params.set('limit', String(query.limit ?? 20));
  params.set('offset', String(query.offset ?? 0));
  if (query.event_type) params.set('event_type', query.event_type);
  if (query.threat_level) params.set('threat_level', query.threat_level);
  if (query.decision_type) params.set('decision_type', query.decision_type);
  if (query.severity) params.set('severity', query.severity);
  if (query.search) params.set('search', query.search);
  if (query.from) params.set('from', query.from);
  if (query.to) params.set('to', query.to);
  return request<DecisionsPage>(`/decisions?${params.toString()}`);
}

export function listDecisionsWithMeta(query: DecisionsQuery) {
  const params = new URLSearchParams();
  params.set('limit', String(query.limit ?? 20));
  params.set('offset', String(query.offset ?? 0));
  if (query.event_type) params.set('event_type', query.event_type);
  if (query.threat_level) params.set('threat_level', query.threat_level);
  if (query.decision_type) params.set('decision_type', query.decision_type);
  if (query.severity) params.set('severity', query.severity);
  if (query.search) params.set('search', query.search);
  if (query.from) params.set('from', query.from);
  if (query.to) params.set('to', query.to);
  return requestWithMeta<DecisionsPage>(`/decisions?${params.toString()}`);
}

export function getDecision(decisionId: string) {
  return request<DecisionOut>(`/decisions/${encodeURIComponent(decisionId)}`);
}

export function getForensicsSnapshot(eventId: string) {
  return request<Record<string, unknown>>(`/forensics/snapshot/${encodeURIComponent(eventId)}`, {}, { mask404: true });
}

export function getForensicsSnapshotWithMeta(eventId: string) {
  return requestWithMeta<Record<string, unknown>>(`/forensics/snapshot/${encodeURIComponent(eventId)}`, {}, { mask404: true });
}

export function getForensicsAuditTrail(eventId: string) {
  return request<Record<string, unknown>>(`/forensics/audit_trail/${encodeURIComponent(eventId)}`, {}, { mask404: true });
}

export function getForensicsAuditTrailWithMeta(eventId: string) {
  return requestWithMeta<Record<string, unknown>>(`/forensics/audit_trail/${encodeURIComponent(eventId)}`, {}, { mask404: true });
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

function isSafeDevHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

async function getServerCoreProxyUrl(): Promise<string> {
  const explicitBase = process.env.CONSOLE_BASE_URL;
  if (explicitBase) {
    const parsed = new URL(explicitBase);
    if ((process.env.NODE_ENV || 'development') === 'development' && !isSafeDevHost(parsed.hostname)) {
      throw new Error('CONSOLE_BASE_URL must point to loopback in development.');
    }
    return `${parsed.toString().replace(/\/$/, '')}/api/core/alignment-artifact`;
  }

  const { headers } = await import('next/headers');
  const headerStore = headers();
  const host = headerStore.get('x-forwarded-host') || headerStore.get('host');
  const proto = headerStore.get('x-forwarded-proto') || 'http';
  if (!host) throw new Error('Unable to resolve server host for alignment artifact fetch.');
  return `${proto}://${host}/api/core/alignment-artifact`;
}

export async function readAlignmentArtifact(): Promise<AlignmentArtifact | null> {
  const target = typeof window === 'undefined'
    ? await getServerCoreProxyUrl()
    : '/api/core/alignment-artifact';
  const response = await fetch(target, { cache: 'no-store' });
  if (!response.ok) return null;
  const payload = (await response.json()) as { artifact?: AlignmentArtifact | null };
  return payload.artifact || null;
}
