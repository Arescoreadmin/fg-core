/**
 * MSP-002 console API client — MSP portfolio and customer approval.
 *
 * Every call goes through the BFF (/api/core/admin/msp/...), which attaches the
 * admin-gateway credential and a delegation proof for the signed-in user's OWN
 * tenant. No function here accepts or sends a tenant id for the caller: Core
 * derives it from the verified session. A customer id appears only as the
 * target of a proposal or context selection, never as the caller's identity.
 *
 * Fail-closed: never throws. Non-2xx returns { ok: false, status, code } where
 * code is Core's error code (for example MSP_CUSTOMER_NOT_FOUND). Callers show
 * only safeErrorMessage() text, never the raw server body.
 */

import { collectAllPages } from './mspConsole';

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status?: number; code?: string };

export type SectionState = 'available' | 'not_authorized' | 'not_configured' | 'unavailable';

export interface AssessmentSummary {
  state: SectionState;
  engagements_by_status?: Record<string, number>;
  observed?: number;
  truncated?: boolean;
  last_activity_at?: string | null;
}

export interface FindingsSummary {
  state: SectionState;
  outstanding_by_severity?: Record<string, number>;
  outstanding_total?: number;
  observed?: number;
  truncated?: boolean;
  last_activity_at?: string | null;
}

export interface PortfolioItem {
  customer_tenant_id: string;
  display_name: string;
  relationship_id: string;
  relationship_status: string;
  effective_permissions: string[];
  expires_at: string | null;
  assessment: AssessmentSummary;
  findings: FindingsSummary;
}

export interface PortfolioPage {
  msp_tenant_id: string;
  items: PortfolioItem[];
  total: number;
  limit: number;
  offset: number;
  next_offset: number | null;
  generated_at: string;
}

export interface Relationship {
  relationship_id: string;
  msp_tenant_id: string;
  customer_tenant_id: string;
  status: string;
  requested_capabilities: string[];
  authorized_capabilities: string[];
  proposed_at: string | null;
  approved_at: string | null;
  effective_at: string | null;
  expires_at: string | null;
  suspended_at: string | null;
  revoked_at: string | null;
  revoked_by_party: string | null;
  version: number;
  party: 'customer' | 'msp';
  counterparty_display_name: string | null;
}

export interface RelationshipPage {
  tenant_id: string;
  items: Relationship[];
  total: number;
  next_offset: number | null;
}

export interface RelationshipEvent {
  event_type: string;
  occurred_at: string | null;
  operation: string;
  capabilities: string[];
  result: string | null;
  actor_party: 'customer' | 'msp' | 'platform';
  actor_subject: string | null;
  correlation_id: string | null;
  event_hash: string;
}

export interface RelationshipHistory {
  relationship_id: string;
  party: 'customer' | 'msp';
  chain_verified: boolean;
  items: RelationshipEvent[];
  total: number;
  next_offset: number | null;
}

export interface CustomerContext {
  msp_tenant_id: string;
  customer_tenant_id: string;
  relationship_id: string;
  effective_permissions: string[];
  valid_until: string | null;
  revalidation: string;
}

const BASE = '/api/core/admin/msp';

async function call<T>(url: string, init?: RequestInit): Promise<SafeResult<T>> {
  try {
    const res = await fetch(url, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
      cache: 'no-store',
      credentials: 'same-origin',
    });
    let payload: unknown = null;
    const text = await res.text();
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = null;
      }
    }
    if (!res.ok) {
      const detail =
        payload && typeof payload === 'object'
          ? (payload as Record<string, unknown>).detail
          : undefined;
      const code =
        detail && typeof detail === 'object'
          ? String((detail as Record<string, unknown>).code ?? '') || undefined
          : undefined;
      return { ok: false, error: `HTTP ${res.status}`, status: res.status, code };
    }
    return { ok: true, data: payload as T };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

function page(limit: number, offset: number): string {
  const l = Math.max(1, Math.floor(limit));
  const o = Math.max(0, Math.floor(offset));
  return `limit=${l}&offset=${o}`;
}

/** MSP side: one page of authorized customers with capability-gated summaries. */
export function getPortfolio(limit = 25, offset = 0): Promise<SafeResult<PortfolioPage>> {
  return call(`${BASE}/portfolio?${page(Math.min(limit, 50), offset)}`);
}

/** Either side: relationships in which the signed-in user's organization is a party. */
export function listRelationships(limit = 100, offset = 0): Promise<SafeResult<RelationshipPage>> {
  return call(`${BASE}/relationships?${page(Math.min(limit, 200), offset)}`);
}

/**
 * Either side: every relationship of the signed-in user's organization,
 * following next_offset. Pages use this so no relationship (and its controls)
 * silently drops off the end; an over-large list fails closed.
 */
export function listAllRelationships(): Promise<SafeResult<RelationshipPage>> {
  return collectAllPages((offset) => listRelationships(200, offset));
}

/** Either side: one page (newest first) of this relationship's events from the organization's own audit chain. */
export function getRelationshipHistory(
  relationshipId: string,
  offset = 0,
): Promise<SafeResult<RelationshipHistory>> {
  return call(
    `${BASE}/relationships/${encodeURIComponent(relationshipId)}/events?${page(100, offset)}`,
  );
}

/** MSP side: request access to a customer. The customer must approve. */
export function proposeRelationship(body: {
  customer_tenant_id: string;
  requested_capabilities: string[];
}): Promise<SafeResult<Relationship & { created: boolean }>> {
  return call(`${BASE}/relationships`, { method: 'POST', body: JSON.stringify(body) });
}

/** Customer side: approve a bounded, possibly narrowed, delegation. */
export function approveRelationship(
  relationshipId: string,
  body: { authorized_capabilities: string[]; expires_at: string },
): Promise<SafeResult<Relationship>> {
  return call(`${BASE}/relationships/${encodeURIComponent(relationshipId)}/approve`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export type LifecycleAction = 'suspend' | 'resume' | 'revoke';

/** Customer (suspend, resume, revoke) or MSP (revoke) lifecycle change. */
export function changeRelationship(
  relationshipId: string,
  action: LifecycleAction,
): Promise<SafeResult<Relationship & { changed?: boolean }>> {
  return call(`${BASE}/relationships/${encodeURIComponent(relationshipId)}/${action}`, {
    method: 'POST',
  });
}

/** MSP side: validate and audit a customer selection. Grants nothing. */
export function selectCustomerContext(customerTenantId: string): Promise<SafeResult<CustomerContext>> {
  return call(`${BASE}/customers/${encodeURIComponent(customerTenantId)}/context`, {
    method: 'POST',
  });
}

// ---------------------------------------------------------------------------
// MSP-003 — onboarding referrals and customer-approved assessment requests.
// Same transport rules: the caller's tenant is never sent; a customer id is
// only the target of a request. Core decides every action.
// ---------------------------------------------------------------------------

export interface GrantNextAction {
  owner: 'customer' | 'msp' | 'platform' | 'assessor';
  code: string;
}

export interface AssessmentGrant {
  grant_id: string;
  relationship_id: string;
  msp_tenant_id: string;
  customer_tenant_id: string;
  party: 'customer' | 'msp';
  request_key: string | null;
  status: string;
  effective_status: string;
  capabilities: string[];
  scope: { assessment_type: string; assessor_id: string };
  requested_at: string | null;
  expires_at: string | null;
  decided_at: string | null;
  initiated_at: string | null;
  revoked_at: string | null;
  engagement_id: string | null;
  version: number;
  blockers: string[];
  progress: { state: string; engagement_status?: string; updated_at?: string };
  next_actions: GrantNextAction[];
}

export interface AssessmentGrantPage {
  tenant_id: string;
  items: AssessmentGrant[];
  total: number;
  next_offset: number | null;
}

export interface OnboardingRequest {
  onboarding_request_id: string;
  msp_tenant_id: string;
  request_key: string;
  organization_name: string;
  contact_email: string;
  requested_capabilities: string[];
  status: string;
  stage: string;
  next_actions: GrantNextAction[];
  requested_at: string | null;
  expires_at: string | null;
  reviewed_at: string | null;
  customer_tenant_id: string | null;
  version: number;
}

export interface OnboardingPage {
  msp_tenant_id: string;
  items: OnboardingRequest[];
  total: number;
  next_offset: number | null;
}

/** Either side: assessment requests where the organization is a party. */
export function listAssessmentGrants(
  customerTenantId?: string,
  offset = 0,
): Promise<SafeResult<AssessmentGrantPage>> {
  // The customer id is a display filter on the caller's own grants, never the caller's tenant.
  const filter = customerTenantId ? `&${new URLSearchParams({ customer_tenant_id: customerTenantId })}` : '';
  return call(`${BASE}/assessments/grants?${page(200, offset)}${filter}`);
}

/** Either side: every assessment request, following next_offset (fail-closed). */
export function listAllAssessmentGrants(customerTenantId?: string): Promise<SafeResult<AssessmentGrantPage>> {
  return collectAllPages((offset) => listAssessmentGrants(customerTenantId, offset));
}

/** MSP side: ask a customer to approve one assessment. Grants nothing yet. */
export function requestAssessmentGrant(body: {
  customer_tenant_id: string;
  request_key: string;
  assessment_type: string;
  assessor_id: string;
  expires_at: string;
}): Promise<SafeResult<AssessmentGrant & { created: boolean }>> {
  return call(`${BASE}/assessments/grants`, { method: 'POST', body: JSON.stringify(body) });
}

export type GrantDecision = 'approve' | 'reject' | 'revoke' | 'withdraw';

/** Customer (approve, reject, revoke) or MSP (withdraw), bound to the version reviewed. */
export function decideAssessmentGrant(
  grantId: string,
  action: GrantDecision,
  expectedVersion: number,
  expiresAt?: string,
): Promise<SafeResult<AssessmentGrant>> {
  const body: Record<string, unknown> = { expected_version: expectedVersion };
  if (action === 'approve' && expiresAt) body.expires_at = expiresAt;
  return call(`${BASE}/assessments/grants/${encodeURIComponent(grantId)}/${action}`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/** MSP side: start the approved assessment. Idempotent; never billable by itself. */
export function initiateAssessment(
  grantId: string,
): Promise<SafeResult<AssessmentGrant & { engagement_id: string; created: boolean }>> {
  return call(`${BASE}/assessments/grants/${encodeURIComponent(grantId)}/initiate`, {
    method: 'POST',
    body: JSON.stringify({}),
  });
}

/** MSP side: the organization's own onboarding referrals. */
export function listOnboardingRequests(offset = 0): Promise<SafeResult<OnboardingPage>> {
  return call(`${BASE}/onboarding/requests?${page(200, offset)}`);
}

/** MSP side: refer a new organization for FrostGate review. Creates no account. */
export function requestOnboarding(body: {
  request_key: string;
  organization_name: string;
  contact_email: string;
  requested_capabilities: string[];
}): Promise<SafeResult<OnboardingRequest & { created: boolean }>> {
  return call(`${BASE}/onboarding/requests`, { method: 'POST', body: JSON.stringify(body) });
}

/** MSP side: cancel a referral that has not been reviewed. */
export function cancelOnboarding(
  requestId: string,
  expectedVersion: number,
): Promise<SafeResult<OnboardingRequest>> {
  return call(`${BASE}/onboarding/requests/${encodeURIComponent(requestId)}/cancel`, {
    method: 'POST',
    body: JSON.stringify({ expected_version: expectedVersion }),
  });
}
