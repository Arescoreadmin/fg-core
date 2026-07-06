import { mapHttpError } from '@/lib/errors';
import { resolveConsoleUrl } from '@/lib/consoleUrl';

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

// ─── Dashboard money-path types ───────────────────────────────────────────────

export interface BillingReadiness {
  provider: string;
  ready: boolean;
  reasons: string[];
}

export interface HealthReadyResponse {
  status: string;
  service?: string;
  version?: string;
  dependencies?: Record<string, string>;
  billing?: BillingReadiness;
}

export interface AssessmentStatus {
  id: string;
  org_id: string;
  profile_type: string;
  schema_version?: string;
  status: 'draft' | 'in_progress' | 'submitted' | 'scored';
  overall_score: number | null;
  risk_band: 'critical' | 'high' | 'medium' | 'low' | null;
  scores: Record<string, number> | null;
  payment_status: 'unpaid' | 'paid';
  tier: string | null;
  created_at?: string | null;
  submitted_at?: string | null;
}

export type ReportJobStatus = 'pending' | 'generating' | 'complete' | 'failed';

export interface ReportStatus {
  id: string;
  assessment_id: string;
  org_id: string;
  status: ReportJobStatus;
  prompt_type: string;
  overall_score: number | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface FeedItem {
  id: number;
  event_id?: string | null;
  event_type?: string | null;
  source?: string | null;
  tenant_id?: string | null;
  threat_level?: string | null;
  timestamp?: string | null;
  severity?: string | null;
  title?: string | null;
  summary?: string | null;
  action_taken?: string | null;
}

export interface FeedLiveResponse {
  items: FeedItem[];
  next_since_id?: number | null;
}

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

// ─── Dashboard API helpers ────────────────────────────────────────────────────

export async function getBillingReadiness(): Promise<SafeResult<BillingReadiness>> {
  try {
    const data = await request<HealthReadyResponse>('/health/ready');
    if (!data.billing) {
      return { ok: false, error: 'billing_field_missing' };
    }
    return { ok: true, data: data.billing };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error' };
  }
}

export async function getAssessmentStatusById(
  assessmentId: string,
): Promise<SafeResult<AssessmentStatus>> {
  try {
    const data = await request<AssessmentStatus>(
      `/ingest/assessment/${encodeURIComponent(assessmentId)}`,
    );
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error' };
  }
}

export async function getReportStatusById(
  reportId: string,
): Promise<SafeResult<ReportStatus>> {
  try {
    const data = await request<ReportStatus>(
      `/ingest/assessment/reports/${encodeURIComponent(reportId)}`,
    );
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error' };
  }
}

export async function getRecentFeedEvents(
  limit = 5,
): Promise<SafeResult<FeedLiveResponse>> {
  try {
    const data = await request<FeedLiveResponse>(`/feed/live?limit=${encodeURIComponent(String(limit))}`);
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error' };
  }
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

  const response = await fetch(await resolveConsoleUrl(`/api/core${path}`), {
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

export async function readAlignmentArtifact(): Promise<AlignmentArtifact | null> {
  const target = await resolveConsoleUrl('/api/core/alignment-artifact');
  const response = await fetch(target, { cache: 'no-store' });
  if (!response.ok) return null;
  const payload = (await response.json()) as { artifact?: AlignmentArtifact | null };
  return payload.artifact || null;
}

export interface ControlTowerSnapshotV1 {
  version: 'ControlTowerSnapshotV1';
  tenant: { tenant_id: string; clamp: { requested_tenant_id: string | null; effective_tenant_id: string; clamped: boolean } };
  planes: Record<string, string>;
  last_replay: { event_id: string | null; timestamp: string | null; result: string; request_id: string | null };
  chain_integrity: { status: string; first_bad: string | null; chain_head_hash: string | null };
  key_lifecycle: { active_key_count: number; last_rotation: string | null; grace_window_seconds: number | null; recent_actions: Array<Record<string, unknown>> };
  connectors: { enabled: number; last_sync: string | null; errors: Array<Record<string, unknown>> };
  agents: { total: number; quarantine_count: number; update_channel_status: string };
  lockers: { status: string; last_restart: string | null; count: number };
  audit_incidents: { recent_events: Array<Record<string, unknown>>; facets: Record<string, string[]> };
  links: Record<string, string>;
}

export function getControlTowerSnapshot() {
  return requestWithMeta<ControlTowerSnapshotV1>('/control-tower/snapshot');
}

export function getConnectorStatus() {
  return request<Record<string, unknown>>('/admin/connectors/status');
}

export function toggleConnector(connectorId: string) {
  return request<Record<string, unknown>>(`/admin/connectors/${encodeURIComponent(connectorId)}/revoke`, { method: 'POST' });
}

export function listAgents() {
  return request<Record<string, unknown>>('/admin/agent/devices');
}

export function quarantineAgent(deviceId: string, reason: string) {
  return request<Record<string, unknown>>(`/admin/agent/quarantine/${encodeURIComponent(deviceId)}`, { method: 'POST', body: JSON.stringify({ reason }) });
}

export function restoreAgent(deviceId: string, reason: string) {
  return request<Record<string, unknown>>(`/admin/agent/unquarantine/${encodeURIComponent(deviceId)}`, { method: 'POST', body: JSON.stringify({ reason }) });
}

export function listLockers() {
  return request<Record<string, unknown>>('/control-plane/lockers');
}

export function lockerRestart(lockerId: string, reason: string) {
  return request<Record<string, unknown>>(`/control-plane/lockers/${encodeURIComponent(lockerId)}/restart`, { method: 'POST', body: JSON.stringify({ reason, idempotency_key: `console-${Date.now()}` }) });
}

export function lockerResume(lockerId: string, reason: string) {
  return request<Record<string, unknown>>(`/control-plane/lockers/${encodeURIComponent(lockerId)}/resume`, { method: 'POST', body: JSON.stringify({ reason, idempotency_key: `console-${Date.now()}` }) });
}

export function exportEvidenceBundle() {
  return request<Record<string, unknown>>('/audit/export?format=json');
}

export async function getCommandCenterSnapshot(): Promise<SafeResult<ControlTowerSnapshotV1>> {
  try {
    const result = await getControlTowerSnapshot();
    return { ok: true, data: result.data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error' };
  }
}

// ─── Forensics Console types ──────────────────────────────────────────────────

export interface ForensicsEvent {
  event_id: number;
  event_type: string;
  event_category: string;
  severity: string;
  request_id: string | null;
  request_path: string | null;
  request_method: string | null;
  success: boolean;
  reason: string | null;
  created_at: string | null;
}

export interface ForensicsEventsPage {
  events: ForensicsEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface ForensicsTrace {
  request_id: string;
  events: ForensicsEvent[];
  event_count: number;
  trace_available: boolean;
}

export interface ForensicsExportPayload {
  export_safe: true;
  redactions_applied: boolean;
  generated_at: string;
  filters_applied: Record<string, string>;
  event_count: number;
  limitation_note: string;
  events: ForensicsEvent[];
}

export interface ForensicsEventsQuery {
  limit?: number;
  offset?: number;
  event_type?: string;
  severity?: string;
  success?: boolean;
  request_id?: string;
  from?: string;
  to?: string;
}

export async function getForensicsEvents(query?: ForensicsEventsQuery): Promise<ForensicsEventsPage> {
  const params = new URLSearchParams();
  if (query?.limit != null) params.set('limit', String(query.limit));
  if (query?.offset != null) params.set('offset', String(query.offset));
  if (query?.event_type) params.set('event_type', query.event_type);
  if (query?.severity) params.set('severity', query.severity);
  if (query?.success != null) params.set('success', String(query.success));
  if (query?.request_id) params.set('request_id', query.request_id);
  if (query?.from) params.set('from', query.from);
  if (query?.to) params.set('to', query.to);
  const qs = params.toString();
  return request<ForensicsEventsPage>(`/ui/forensics/events${qs ? `?${qs}` : ''}`);
}

export async function getForensicsTrace(requestId: string): Promise<ForensicsTrace> {
  return request<ForensicsTrace>(`/ui/forensics/trace/${encodeURIComponent(requestId)}`);
}

export async function getForensicsExport(query?: Pick<ForensicsEventsQuery, 'from' | 'to' | 'event_type' | 'severity'>): Promise<ForensicsExportPayload> {
  const params = new URLSearchParams();
  if (query?.event_type) params.set('event_type', query.event_type);
  if (query?.severity) params.set('severity', query.severity);
  if (query?.from) params.set('from', query.from);
  if (query?.to) params.set('to', query.to);
  const qs = params.toString();
  return request<ForensicsExportPayload>(`/ui/forensics/events/export${qs ? `?${qs}` : ''}`);
}

// ─── Provider Governance types ────────────────────────────────────────────────

export type ProviderOperationalState =
  | 'healthy'
  | 'degraded'
  | 'unavailable'
  | 'blocked'
  | 'restricted'
  | 'maintenance';

export type ProviderGovernanceState =
  | 'approved'
  | 'restricted'
  | 'blocked'
  | 'pending_review';

export type ProviderTrustClassification =
  | 'trusted'
  | 'regulated'
  | 'untrusted'
  | 'unknown';

export type BaaStatus = 'active' | 'expired' | 'missing' | 'revoked' | 'pending';

export interface ProviderBaaDetail {
  provider_id: string;
  baa_status: BaaStatus;
  expiry_date: string | null;
  signed_at: string | null;
  created_at: string | null;
}

export interface ProviderGovernanceRecord {
  provider_id: string;
  operational_state: ProviderOperationalState;
  governance_state: ProviderGovernanceState;
  trust_classification: ProviderTrustClassification;
  routing_eligible: boolean;
  failover_eligible: boolean;
  restrictions: string[];
  blocked_at: string | null;
  block_reason: string | null;
  policy_version: number;
  created_at: string | null;
  updated_at: string | null;
}

export interface ProviderGovernancePage {
  providers: ProviderGovernanceRecord[];
  total: number;
  limit: number;
  offset: number;
  note: string;
}

export interface ProviderGovernanceDetail {
  provider_id: string;
  governance: ProviderGovernanceRecord | null;
  baa: ProviderBaaDetail | null;
  governance_available: boolean;
  baa_available: boolean;
}

export interface ProviderRoutingEntry {
  provider_id: string;
  operational_state: ProviderOperationalState;
  governance_state: ProviderGovernanceState;
  routing_eligible: boolean;
  failover_eligible: boolean;
  baa_status: BaaStatus | 'missing';
  trust_classification: ProviderTrustClassification;
  restrictions: string[];
}

export interface ProviderRoutingPolicy {
  tenant_id: string;
  allowed_providers: ProviderRoutingEntry[];
  blocked_providers: ProviderRoutingEntry[];
  restricted_providers: ProviderRoutingEntry[];
  failover_providers: ProviderRoutingEntry[];
  routing_policy_note: string;
}

export interface ProviderFailoverEntry {
  provider_id: string;
  operational_state: ProviderOperationalState;
  governance_state: ProviderGovernanceState;
  routing_eligible: boolean;
  failover_eligible: boolean;
}

export interface ProviderFailoverState {
  degraded_providers: ProviderFailoverEntry[];
  failover_ready_providers: ProviderFailoverEntry[];
  failover_note: string;
  telemetry_available: false;
}

export interface ProviderGovernanceQuery {
  limit?: number;
  offset?: number;
  operational_state?: ProviderOperationalState;
  governance_state?: ProviderGovernanceState;
}

export async function getProviderGovernance(
  query?: ProviderGovernanceQuery,
): Promise<ProviderGovernancePage> {
  const params = new URLSearchParams();
  if (query?.limit != null) params.set('limit', String(query.limit));
  if (query?.offset != null) params.set('offset', String(query.offset));
  if (query?.operational_state) params.set('operational_state', query.operational_state);
  if (query?.governance_state) params.set('governance_state', query.governance_state);
  const qs = params.toString();
  return request<ProviderGovernancePage>(`/ui/provider/governance${qs ? `?${qs}` : ''}`);
}

export async function getProviderGovernanceDetail(
  providerId: string,
): Promise<ProviderGovernanceDetail> {
  return request<ProviderGovernanceDetail>(
    `/ui/provider/governance/${encodeURIComponent(providerId)}`,
  );
}

export async function getProviderRoutingPolicy(): Promise<ProviderRoutingPolicy> {
  return request<ProviderRoutingPolicy>('/ui/provider/routing');
}

export async function getProviderFailoverState(): Promise<ProviderFailoverState> {
  return request<ProviderFailoverState>('/ui/provider/failover');
}

// ─── Retrieval Evaluation types ───────────────────────────────────────────────

export type EvaluationRunStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface RetrievalIndicators {
  [key: string]: unknown;
}

export interface EvaluationRun {
  run_ref: string;
  corpus_id: string | null;
  status: EvaluationRunStatus;
  started_at: string | null;
  completed_at: string | null;
  query_count: number;
  relevance_indicators: RetrievalIndicators;
  coverage_indicators: RetrievalIndicators;
  correctness_indicators: RetrievalIndicators;
  evaluator_ref: string | null;
  evaluation_metadata: Record<string, unknown>;
  created_at: string | null;
  updated_at: string | null;
}

export interface EvaluationRunPage {
  runs: EvaluationRun[];
  total: number;
  limit: number;
  offset: number;
}

export interface EvaluationQualitySummary {
  corpus_id: string | null;
  completed_run_count: number;
  total_queries_evaluated: number;
  runs_with_relevance_indicators: number;
  runs_with_coverage_indicators: number;
  runs_with_correctness_indicators: number;
  quality_note: string;
  evaluation_algorithms_available: false;
}

export interface EvaluationRunsQuery {
  limit?: number;
  offset?: number;
  status?: EvaluationRunStatus;
  corpus_id?: string;
}

export async function getEvaluationRuns(
  query?: EvaluationRunsQuery,
): Promise<EvaluationRunPage> {
  const params = new URLSearchParams();
  if (query?.limit != null) params.set('limit', String(query.limit));
  if (query?.offset != null) params.set('offset', String(query.offset));
  if (query?.status) params.set('status', query.status);
  if (query?.corpus_id) params.set('corpus_id', query.corpus_id);
  const qs = params.toString();
  return request<EvaluationRunPage>(`/ui/evaluation/runs${qs ? `?${qs}` : ''}`);
}

export async function getEvaluationRun(runRef: string): Promise<EvaluationRun> {
  return request<EvaluationRun>(`/ui/evaluation/runs/${encodeURIComponent(runRef)}`);
}

export async function getEvaluationQuality(
  corpusId?: string,
): Promise<EvaluationQualitySummary> {
  const params = new URLSearchParams();
  if (corpusId) params.set('corpus_id', corpusId);
  const qs = params.toString();
  return request<EvaluationQualitySummary>(`/ui/evaluation/quality${qs ? `?${qs}` : ''}`);
}

// ─── Evaluation Lab types (PR 54) ─────────────────────────────────────────────

export interface EvaluationQuerySetRecord {
  set_ref: string;
  name: string;
  corpus_id: string | null;
  description: string | null;
  operator_notes: unknown[];
  export_safe_metadata: Record<string, unknown>;
  created_at: string | null;
  updated_at: string | null;
}

export interface EvaluationQueryItemRecord {
  item_ref: string;
  set_ref: string;
  query_category: string | null;
  expected_source_ids: string[];
  expected_chunk_ids: string[];
  expected_source_hashes: string[];
  expected_provenance_ids: string[];
  retrieval_expectations: Record<string, unknown>;
  operator_notes: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface EvaluationQuerySetDetail extends EvaluationQuerySetRecord {
  items: EvaluationQueryItemRecord[];
  items_total: number;
  items_limit: number;
  items_offset: number;
}

export interface EvaluationQuerySetsPage {
  query_sets: EvaluationQuerySetRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface EvaluationRunComparison {
  run_ref: string;
  corpus_id: string | null;
  status: EvaluationRunStatus;
  query_count: number;
  retrieval_comparison: {
    has_relevance_data: boolean;
    has_coverage_data: boolean;
    relevance_keys: string[];
    coverage_keys: string[];
    comparison_note: string;
    reranker_comparison_available: boolean;
    retrieval_strategy: string | null;
    comparison_strategy: string | null;
  };
}

export interface EvaluationRunConfidence {
  run_ref: string;
  corpus_id: string | null;
  status: EvaluationRunStatus;
  query_count: number;
  confidence_distribution: {
    has_confidence_data: boolean;
    confidence_source: string;
    confidence_source_labeled: boolean;
    correctness_keys: string[];
    provider_confidence_available: boolean;
    reranker_score_available: boolean;
    distribution_note: string;
  };
}

export interface EvaluationRunHallucination {
  run_ref: string;
  corpus_id: string | null;
  status: EvaluationRunStatus;
  query_count: number;
  hallucination_review: {
    review_type: string;
    review_note: string;
    grounding_data_available: boolean;
    missing_evidence_count: number | null;
    weak_grounding_count: number | null;
    unsupported_answer_detection_available: boolean;
    evidence_mismatch_available: boolean;
    export_safe: boolean;
    tenant_scoped: boolean;
  };
}

export interface EvaluationRunReranker {
  run_ref: string;
  corpus_id: string | null;
  status: EvaluationRunStatus;
  query_count: number;
  reranker_comparison: {
    reranker_available: boolean;
    reranker_strategy: string | null;
    retrieval_strategy: string | null;
    ordering_deterministic: boolean;
    overlap_keys: string[];
    reranker_note: string;
  };
}

export interface EvaluationRunExport {
  export_safe: boolean;
  export_schema_version: string;
  run_ref: string;
  corpus_id: string | null;
  status: EvaluationRunStatus;
  query_count: number;
  evaluator_ref: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string | null;
  has_relevance_indicators: boolean;
  has_coverage_indicators: boolean;
  has_correctness_indicators: boolean;
  evaluation_metadata: Record<string, unknown>;
  export_note: string;
}

export interface EvaluationQuerySetsQuery {
  limit?: number;
  offset?: number;
  corpus_id?: string;
}

export async function getEvaluationQuerySets(
  query?: EvaluationQuerySetsQuery,
): Promise<EvaluationQuerySetsPage> {
  const params = new URLSearchParams();
  if (query?.limit != null) params.set('limit', String(query.limit));
  if (query?.offset != null) params.set('offset', String(query.offset));
  if (query?.corpus_id) params.set('corpus_id', query.corpus_id);
  const qs = params.toString();
  return request<EvaluationQuerySetsPage>(`/ui/evaluation/query-sets${qs ? `?${qs}` : ''}`);
}

export async function getEvaluationQuerySetDetail(
  setRef: string,
  itemsOffset?: number,
): Promise<EvaluationQuerySetDetail> {
  const params = new URLSearchParams();
  if (itemsOffset != null) params.set('items_offset', String(itemsOffset));
  const qs = params.toString();
  return request<EvaluationQuerySetDetail>(
    `/ui/evaluation/query-sets/${encodeURIComponent(setRef)}${qs ? `?${qs}` : ''}`,
  );
}

export async function getEvaluationRunComparison(
  runRef: string,
): Promise<EvaluationRunComparison> {
  return request<EvaluationRunComparison>(
    `/ui/evaluation/runs/${encodeURIComponent(runRef)}/comparison`,
  );
}

export async function getEvaluationRunConfidence(
  runRef: string,
): Promise<EvaluationRunConfidence> {
  return request<EvaluationRunConfidence>(
    `/ui/evaluation/runs/${encodeURIComponent(runRef)}/confidence`,
  );
}

export async function getEvaluationRunHallucination(
  runRef: string,
): Promise<EvaluationRunHallucination> {
  return request<EvaluationRunHallucination>(
    `/ui/evaluation/runs/${encodeURIComponent(runRef)}/hallucination`,
  );
}

export async function getEvaluationRunReranker(
  runRef: string,
): Promise<EvaluationRunReranker> {
  return request<EvaluationRunReranker>(
    `/ui/evaluation/runs/${encodeURIComponent(runRef)}/reranker`,
  );
}

export async function getEvaluationRunExport(
  runRef: string,
): Promise<EvaluationRunExport> {
  return request<EvaluationRunExport>(
    `/ui/evaluation/runs/${encodeURIComponent(runRef)}/export`,
  );
}
