/**
 * Identity Governance Control Plane — Console API client (PR4).
 *
 * All calls proxy through /api/core → admin/identity/... on the Core API.
 * Tenant-scoped: every call includes the target tenantId in the path.
 */

import { mapHttpError } from '@/lib/errors';
import type { SafeResult } from '@/lib/coreApi';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface IdentityProvider {
  id: string;
  provider: string;
  oidc_issuer: string | null;
  organization_id: string | null;
  connection_id: string | null;
  status: string;
  is_primary: boolean;
}

export interface IdentityDomain {
  id: string;
  domain: string;
  domain_type: string;
  verification_status: string;
  verified_at: string | null;
}

export interface IdentityConfig {
  id?: string;
  tenant_id: string;
  configured: boolean;
  identity_mode?: string;
  provider?: string;
  oidc_issuer?: string | null;
  auth0_organization_id?: string | null;
  auth0_connection_id?: string | null;
  allowed_email_domains?: string[];
  sso_enforced?: boolean;
  provisioning_status?: string;
  provisioning_error_code?: string | null;
  maturity_level?: string;
  capability_flags?: Record<string, boolean>;
  configured_by_user_id?: string | null;
  configured_at?: string | null;
  created_at?: string;
  updated_at?: string;
  providers?: IdentityProvider[];
  domains?: IdentityDomain[];
}

export interface ReadinessCheck {
  id: string;
  pass: boolean;
  detail: string;
}

export interface ReadinessEvidence {
  id: string;
  label: string;
  pass: boolean;
  source: string;
  value: unknown;
}

export interface IdentityReadiness {
  tenant_id: string;
  ready: boolean;
  status: string;
  identity_mode?: string;
  checks: ReadinessCheck[];
  evidence: ReadinessEvidence[];
}

export interface IdentityInvitation {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  status: string;
  required_provider: string | null;
  required_connection_id: string | null;
  identity_mode_at_invite: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  accepted_at: string | null;
  bound_at: string | null;
  created_at: string;
  updated_at: string;
  approval_required: boolean;
  approval_state: string;
  approved_by_user_id: string | null;
  approved_at: string | null;
  approval_reason: string | null;
}

export interface InvitationsResponse {
  tenant_id: string;
  invitations: IdentityInvitation[];
}

export interface InviteCreatePayload {
  email: string;
  role?: string;
  required_provider?: string | null;
  required_connection_id?: string | null;
  identity_type?: string;
  configured_by_user_id?: string | null;
}

export interface ConfigUpsertPayload {
  identity_mode: string;
  provider?: string;
  oidc_issuer?: string | null;
  auth0_organization_id?: string | null;
  auth0_connection_id?: string | null;
  allowed_email_domains?: string[];
  sso_enforced?: boolean;
  maturity_level?: string;
  capability_flags?: Record<string, boolean>;
}

export interface AuditSummary {
  tenant_id: string;
  total_events: number;
  by_type: Record<string, number>;
  recent: Array<{
    id: string;
    event_type: string;
    actor_user_id: string | null;
    affected_email: string | null;
    invitation_id: string | null;
    reason_code: string | null;
    identity_type: string | null;
    created_at: string;
  }>;
}

export interface ScoreDimension {
  pass: boolean;
  weight: number;
  detail: unknown;
  evidence?: Record<string, unknown>;
}

export interface GovernanceScore {
  tenant_id: string;
  score: number;
  max_score: number;
  percent: number;
  grade: string;
  dimensions: Record<string, ScoreDimension>;
}

export interface DriftItem {
  type: string;
  severity: string;
  detail?: string;
  count?: number;
  error_code?: string | null;
  recommended_action?: string;
  remediation_risk?: string;
}

export interface DriftReport {
  tenant_id: string;
  drift_detected: boolean;
  items: DriftItem[];
  checked_at: string;
}

export interface TimelineEvent {
  id: string;
  event_type: string;
  label: string;
  actor_user_id: string | null;
  affected_email: string | null;
  invitation_id: string | null;
  membership_id: string | null;
  identity_mode: string | null;
  provider: string | null;
  connection_id: string | null;
  reason_code: string | null;
  identity_type: string | null;
  identity_subject: string | null;
  created_at: string;
}

export interface IdentityTimeline {
  tenant_id: string;
  count: number;
  events: TimelineEvent[];
}

export interface ReadinessTransition {
  event_type: string;
  identity_mode: string | null;
  provider: string | null;
  reason_code: string | null;
  occurred_at: string;
}

export interface ReadinessHistory {
  tenant_id: string;
  transitions: ReadinessTransition[];
}

export interface RiskFactor {
  factor: string;
  severity: string;
  points: number;
  count?: number;
}

export interface IdentityRisk {
  tenant_id: string;
  risk_score: number;
  risk_band: string;
  factors: RiskFactor[];
  assessed_at: string;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async function identityRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
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
    try { payload = JSON.parse(text); } catch { payload = text; }
  }
  if (!response.ok) throw mapHttpError(response.status, payload, {});
  return payload as T;
}

async function safe<T>(fn: () => Promise<T>): Promise<SafeResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'fetch_error' };
  }
}

const base = (tenantId: string) => `/admin/identity/tenants/${encodeURIComponent(tenantId)}`;

// ── Public API ────────────────────────────────────────────────────────────────

export async function getIdentityConfig(tenantId: string): Promise<SafeResult<IdentityConfig>> {
  return safe(() => identityRequest<IdentityConfig>(`${base(tenantId)}/config`));
}

export async function upsertIdentityConfig(
  tenantId: string,
  payload: ConfigUpsertPayload,
): Promise<SafeResult<IdentityConfig>> {
  return safe(() =>
    identityRequest<IdentityConfig>(`${base(tenantId)}/config`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  );
}

export async function getIdentityReadiness(tenantId: string): Promise<SafeResult<IdentityReadiness>> {
  return safe(() => identityRequest<IdentityReadiness>(`${base(tenantId)}/readiness`));
}

export async function listInvitations(tenantId: string): Promise<SafeResult<InvitationsResponse>> {
  return safe(() => identityRequest<InvitationsResponse>(`${base(tenantId)}/invitations`));
}

export async function createInvitation(
  tenantId: string,
  payload: InviteCreatePayload,
): Promise<SafeResult<IdentityInvitation>> {
  return safe(() =>
    identityRequest<IdentityInvitation>(`${base(tenantId)}/invitations`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  );
}

export async function revokeInvitation(invitationId: string): Promise<SafeResult<{ invitation_id: string; status: string }>> {
  return safe(() =>
    identityRequest(`/admin/identity/invitations/${encodeURIComponent(invitationId)}/revoke`, {
      method: 'POST',
    }),
  );
}

export async function resendInvitation(invitationId: string): Promise<SafeResult<{ invitation_id: string; status: string; resent: boolean }>> {
  return safe(() =>
    identityRequest(`/admin/identity/invitations/${encodeURIComponent(invitationId)}/resend`, {
      method: 'POST',
    }),
  );
}

export async function getAuditSummary(tenantId: string): Promise<SafeResult<AuditSummary>> {
  return safe(() => identityRequest<AuditSummary>(`${base(tenantId)}/audit-summary`));
}

export async function getGovernanceScore(tenantId: string): Promise<SafeResult<GovernanceScore>> {
  return safe(() => identityRequest<GovernanceScore>(`${base(tenantId)}/governance-score`));
}

export async function getDrift(tenantId: string): Promise<SafeResult<DriftReport>> {
  return safe(() => identityRequest<DriftReport>(`${base(tenantId)}/drift`));
}

export async function getIdentityTimeline(tenantId: string, limit = 50): Promise<SafeResult<IdentityTimeline>> {
  return safe(() =>
    identityRequest<IdentityTimeline>(`${base(tenantId)}/timeline?limit=${limit}`),
  );
}

export async function getReadinessHistory(tenantId: string): Promise<SafeResult<ReadinessHistory>> {
  return safe(() => identityRequest<ReadinessHistory>(`${base(tenantId)}/readiness-history`));
}

export async function getIdentityRisk(tenantId: string): Promise<SafeResult<IdentityRisk>> {
  return safe(() => identityRequest<IdentityRisk>(`${base(tenantId)}/risk`));
}

// ── Identity Type Governance ──────────────────────────────────────────────────

export interface IdentityTypeRisk {
  total: number;
  bound: number;
  failed: number;
  bind_rate: number;
  risk_band: string;
}

export interface IdentityTypeGovernance {
  tenant_id: string;
  distribution: Record<string, number>;
  risk_by_type: Record<string, IdentityTypeRisk>;
  total: number;
}

export async function getIdentityTypeGovernance(tenantId: string): Promise<SafeResult<IdentityTypeGovernance>> {
  return safe(() => identityRequest<IdentityTypeGovernance>(`${base(tenantId)}/identity-types`));
}

// ── Session Provenance ────────────────────────────────────────────────────────

export interface ProvenanceChainEntry {
  event_type: string;
  label: string;
  provider: string | null;
  reason_code: string | null;
  created_at: string;
}

export interface ProvenanceInvitation {
  id: string;
  status: string;
  identity_type: string | null;
  required_provider: string | null;
  created_at: string;
  bound_at: string | null;
}

export interface ProvenanceResult {
  tenant_id: string;
  email: string | null;
  user_id: string | null;
  identity: {
    email: string | null;
    identity_type: string | null;
    binding_status: string | null;
    role: string | null;
  };
  provider: string | null;
  binding_event_at: string | null;
  session_authority: string | null;
  invitation_chain: ProvenanceInvitation[];
  audit_chain: ProvenanceChainEntry[];
}

export async function getSessionProvenance(
  tenantId: string,
  params: { email?: string; user_id?: string },
): Promise<SafeResult<ProvenanceResult>> {
  const qs = new URLSearchParams();
  if (params.email) qs.set('email', params.email);
  if (params.user_id) qs.set('user_id', params.user_id);
  return safe(() =>
    identityRequest<ProvenanceResult>(`${base(tenantId)}/provenance?${qs.toString()}`),
  );
}

// ── Policy Violations ─────────────────────────────────────────────────────────

export interface PolicyViolation {
  rule_id: string;
  severity: string;
  category: string;
  description: string;
  affected_email: string;
  invitation_id: string | null;
  detail: string;
}

export interface PolicyViolationsReport {
  tenant_id: string;
  violation_count: number;
  critical_count: number;
  high_count: number;
  violations: PolicyViolation[];
}

export async function getPolicyViolations(tenantId: string): Promise<SafeResult<PolicyViolationsReport>> {
  return safe(() => identityRequest<PolicyViolationsReport>(`${base(tenantId)}/policy-violations`));
}

// ── Approval Workflows ────────────────────────────────────────────────────────

export interface ApprovalActionPayload {
  approver_user_id?: string | null;
  reason?: string | null;
}

export interface ApprovalQueueResponse {
  tenant_id: string;
  pending_count: number;
  items: IdentityInvitation[];
}

export async function requestApproval(
  invitationId: string,
  payload: ApprovalActionPayload = {},
): Promise<SafeResult<{ invitation_id: string; approval_state: string }>> {
  return safe(() =>
    identityRequest(`/admin/identity/invitations/${encodeURIComponent(invitationId)}/request-approval`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  );
}

export async function approveInvitation(
  invitationId: string,
  payload: ApprovalActionPayload = {},
): Promise<SafeResult<{ invitation_id: string; approval_state: string; approved_by_user_id: string | null; approved_at: string }>> {
  return safe(() =>
    identityRequest(`/admin/identity/invitations/${encodeURIComponent(invitationId)}/approve`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  );
}

export async function rejectApproval(
  invitationId: string,
  payload: ApprovalActionPayload = {},
): Promise<SafeResult<{ invitation_id: string; approval_state: string; reason: string | null }>> {
  return safe(() =>
    identityRequest(`/admin/identity/invitations/${encodeURIComponent(invitationId)}/reject-approval`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  );
}

export async function getApprovalQueue(tenantId: string): Promise<SafeResult<ApprovalQueueResponse>> {
  return safe(() => identityRequest<ApprovalQueueResponse>(`${base(tenantId)}/approval-queue`));
}

// ── Governance Snapshots ──────────────────────────────────────────────────────

export interface GovernanceSnapshot {
  snapshot_id: string;
  score: number;
  max_score: number;
  percent: number;
  grade: string;
  dimensions: Record<string, { pass: boolean; weight: number }>;
  created_at: string;
}

export interface GovernanceSnapshotsReport {
  tenant_id: string;
  days: number;
  snapshot_count: number;
  score_delta_pct: number | null;
  snapshots: GovernanceSnapshot[];
}

export async function takeGovernanceSnapshot(tenantId: string): Promise<SafeResult<GovernanceSnapshot & { snapshot_id: string; tenant_id: string }>> {
  return safe(() =>
    identityRequest(`${base(tenantId)}/governance-snapshots`, { method: 'POST' }),
  );
}

export async function getGovernanceSnapshots(
  tenantId: string,
  days = 90,
): Promise<SafeResult<GovernanceSnapshotsReport>> {
  return safe(() =>
    identityRequest<GovernanceSnapshotsReport>(`${base(tenantId)}/governance-snapshots?days=${days}`),
  );
}

// ── Recommendations Engine ────────────────────────────────────────────────────

export interface Recommendation {
  dimension: string;
  action: string;
  detail: string | null;
  expected_score_gain: number;
  risk_reduction: string;
  category: string;
  priority: number;
}

export interface RecommendationsReport {
  tenant_id: string;
  current_score: number;
  current_percent: number;
  current_grade: string;
  recommendation_count: number;
  total_expected_score_gain: number;
  projected_percent_if_all_applied: number;
  recommendations: Recommendation[];
}

export async function getRecommendations(tenantId: string): Promise<SafeResult<RecommendationsReport>> {
  return safe(() => identityRequest<RecommendationsReport>(`${base(tenantId)}/recommendations`));
}

// ── Gap A: Governance Trend Analytics ────────────────────────────────────────

export interface TrendDimension {
  dimension: string;
  label: string;
  score_impact: number;
}

export interface GovernanceTrend {
  tenant_id: string;
  has_trend: boolean;
  message?: string;
  snapshot_count?: number;
  period_start?: string;
  period_end?: string;
  snapshots_compared?: number;
  grade_from?: string;
  grade_to?: string;
  score_delta?: number;
  percent_delta?: number;
  degraded: TrendDimension[];
  improved: TrendDimension[];
  stable_failing: TrendDimension[];
  narrative: string[];
}

export async function getGovernanceTrend(
  tenantId: string,
  snapshots = 5,
): Promise<SafeResult<GovernanceTrend>> {
  return safe(() =>
    identityRequest<GovernanceTrend>(`${base(tenantId)}/governance-trend?snapshots=${snapshots}`),
  );
}

// ── Gap B: Governance Forecasting ────────────────────────────────────────────

export interface ForecastRiskDimension {
  dimension: string;
  label: string;
  fail_rate_pct: number;
  trend: string;
}

export interface GovernanceForecast {
  tenant_id: string;
  has_forecast: boolean;
  message?: string;
  snapshot_count?: number;
  current_percent?: number;
  current_grade?: string;
  slope_per_day?: number;
  trend_direction?: string;
  forecast_days?: number;
  projected_percent?: number;
  projected_grade?: string;
  at_risk_dimensions: ForecastRiskDimension[];
}

export async function getGovernanceForecast(
  tenantId: string,
  days = 30,
): Promise<SafeResult<GovernanceForecast>> {
  return safe(() =>
    identityRequest<GovernanceForecast>(`${base(tenantId)}/governance-forecast?days=${days}`),
  );
}

// ── Gap C: Governance SLA Tracking ───────────────────────────────────────────

export interface SlaItem {
  item_id: string;
  type: string;
  severity: string;
  title: string;
  detail: string;
  open_since: string | null;
  days_open: number | null;
  sla_days: number;
  sla_status: 'on_track' | 'at_risk' | 'breached' | 'unknown';
}

export interface GovernanceSlaReport {
  tenant_id: string;
  total_open_items: number;
  breached_count: number;
  at_risk_count: number;
  items: SlaItem[];
}

export async function getGovernanceSla(tenantId: string): Promise<SafeResult<GovernanceSlaReport>> {
  return safe(() => identityRequest<GovernanceSlaReport>(`${base(tenantId)}/governance-sla`));
}

// ── Gap D: Cross-Tenant Benchmarking ─────────────────────────────────────────

export interface GovernanceBenchmark {
  tenant_id: string;
  has_benchmark: boolean;
  message?: string;
  participating_tenants?: number;
  own_score?: {
    percent: number | null;
    grade: string | null;
    snapshot_at: string | null;
    percentile_rank: number | null;
  };
  benchmark?: {
    p25: number;
    median: number;
    p75: number;
    p90: number;
    description: string;
  };
}

export async function getGovernanceBenchmark(tenantId: string): Promise<SafeResult<GovernanceBenchmark>> {
  return safe(() => identityRequest<GovernanceBenchmark>(`${base(tenantId)}/governance-benchmark`));
}

// ── Gap E: Governance Findings ────────────────────────────────────────────────

export interface GovernanceFinding {
  finding_id: string;
  type: 'policy_violation' | 'risk' | 'drift';
  severity: string;
  category: string;
  title: string;
  detail: string;
  sources: string[];
  evidence: Record<string, unknown>;
  affected_email: string | null;
  invitation_id: string | null;
}

export interface GovernanceFindingsReport {
  tenant_id: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  governance_score: number;
  governance_percent: number;
  governance_grade: string;
  findings: GovernanceFinding[];
}

export async function getGovernanceFindings(tenantId: string): Promise<SafeResult<GovernanceFindingsReport>> {
  return safe(() =>
    identityRequest<GovernanceFindingsReport>(`${base(tenantId)}/governance-findings`),
  );
}

// ── Governance Actions Ledger ─────────────────────────────────────────────────

export type GovernanceActionState = 'accepted' | 'rejected' | 'deferred' | 'implemented' | 'unaddressed';

export interface GovernanceAction {
  action_id: string;
  dimension: string;
  action_state: GovernanceActionState;
  actor_id: string | null;
  actor_email: string | null;
  actor_role: string | null;
  reason: string | null;
  outcome: string | null;
  deferred_until: string | null;
  snapshot_id: string | null;
  previous_action_id: string | null;
  recommendation_action: string | null;
  created_at: string;
}

export interface GovernanceActionsLedger {
  tenant_id: string;
  total: number;
  actions: GovernanceAction[];
}

export interface GovernanceActionSummaryEntry {
  dimension: string;
  recommendation_action: string;
  priority: number;
  risk_reduction: string;
  current_state: GovernanceActionState;
  is_terminal: boolean;
  actor_email: string | null;
  reason: string | null;
  outcome: string | null;
  deferred_until: string | null;
  decided_at: string | null;
  action_id: string | null;
}

export interface GovernanceActionSummary {
  tenant_id: string;
  total_dimensions: number;
  unaddressed: number;
  accepted: number;
  deferred: number;
  rejected: number;
  implemented: number;
  dimensions: GovernanceActionSummaryEntry[];
}

export interface RecordGovernanceActionPayload {
  dimension: string;
  action_state: 'accepted' | 'rejected' | 'deferred' | 'implemented';
  actor_id?: string;
  actor_email?: string;
  actor_role?: string;
  reason?: string;
  outcome?: string;
  deferred_until?: string;
  snapshot_id?: string;
}

export async function recordGovernanceAction(
  tenantId: string,
  payload: RecordGovernanceActionPayload,
): Promise<SafeResult<GovernanceAction>> {
  return safe(() =>
    identityRequest<GovernanceAction>(`${base(tenantId)}/governance-actions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  );
}

export async function listGovernanceActions(
  tenantId: string,
  opts?: { dimension?: string; state?: string; limit?: number },
): Promise<SafeResult<GovernanceActionsLedger>> {
  const params = new URLSearchParams();
  if (opts?.dimension) params.set('dimension', opts.dimension);
  if (opts?.state) params.set('state', opts.state);
  if (opts?.limit) params.set('limit', String(opts.limit));
  const qs = params.toString();
  return safe(() =>
    identityRequest<GovernanceActionsLedger>(
      `${base(tenantId)}/governance-actions${qs ? `?${qs}` : ''}`,
    ),
  );
}

export async function getGovernanceActionSummary(
  tenantId: string,
): Promise<SafeResult<GovernanceActionSummary>> {
  return safe(() =>
    identityRequest<GovernanceActionSummary>(`${base(tenantId)}/governance-action-summary`),
  );
}
