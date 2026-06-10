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
