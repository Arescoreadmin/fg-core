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
  | { ok: false; error: string; status?: number; code?: string; blockers?: string[] };

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
      // MSP-007: Core's reason codes for an unavailable share (codes only).
      const rawBlockers =
        detail && typeof detail === 'object' ? (detail as Record<string, unknown>).blockers : undefined;
      const blockers = Array.isArray(rawBlockers)
        ? rawBlockers.filter((b): b is string => typeof b === 'string' && /^[A-Z_]{1,64}$/.test(b))
        : undefined;
      return { ok: false, error: `HTTP ${res.status}`, status: res.status, code, blockers };
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

/**
 * MSP side: every onboarding referral, following next_offset. Terminal
 * referrals stay in the list, so a single page could hide older pending ones;
 * an over-large or non-advancing list fails closed (collectAllPages).
 */
export function listAllOnboardingRequests(): Promise<SafeResult<OnboardingPage>> {
  return collectAllPages((offset) => listOnboardingRequests(offset));
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

// ---------------------------------------------------------------------------
// MSP-007 — customer-controlled report sharing and partner managed reporting.
// Same transport rules: the caller's tenant is never sent. A share is one
// customer decision for one exact report version; Core re-checks it on every
// read. Nothing here caches report content or authorizes anything.
// ---------------------------------------------------------------------------

export interface ReportLifecycle {
  exists: boolean;
  state: string;
  status: string;
  qa_approved: boolean;
  independent_qa: boolean;
  production_qualified: boolean;
  released: boolean;
  limited_coverage: boolean;
  release_blockers: string[];
  delivery_authorized: boolean;
  delivered: boolean;
}

export interface ReportIntegrity {
  content: string;
  signature: string;
  signature_kind: string;
  evidence_chain: string;
}

export interface ShareableReport {
  report_id: string;
  engagement_id: string;
  version: number;
  report_type: string | null;
  generated_at: string;
  manifest_hash: string;
  lifecycle: ReportLifecycle;
  integrity: ReportIntegrity;
  share_eligible: boolean;
  share_blockers: string[];
}

export interface ShareableReportPage {
  tenant_id: string;
  items: ShareableReport[];
  total: number;
  next_offset: number | null;
}

export interface ReportShare {
  share_id: string;
  party: 'customer' | 'msp';
  customer_tenant_id: string;
  customer_name: string | null;
  msp_tenant_id: string;
  relationship_id: string;
  origin: 'customer' | 'msp';
  engagement_id: string;
  grant_id: string | null;
  report_id: string | null;
  report_version: number | null;
  manifest_hash: string | null;
  status: string;
  requested_at: string | null;
  decided_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  version: number;
  next_actions: GrantNextAction[];
  access?: { state: 'available' | 'blocked'; blockers: string[] };
}

export interface ReportSharePage {
  tenant_id: string;
  party: 'customer' | 'msp';
  items: ReportShare[];
  total: number;
  next_offset: number | null;
}

export interface ShareEvent {
  event_type: string;
  occurred_at: string | null;
  operation: string;
  decision: string | null;
  blockers: string[];
  report_id: string | null;
  report_version: number | null;
  manifest_hash: string | null;
  actor_party: 'customer' | 'msp';
  actor_subject: string | null;
  correlation_id: string | null;
  event_hash: string;
}

export interface ShareHistory {
  share_id: string;
  party: 'customer' | 'msp';
  chain_verified: boolean;
  items: ShareEvent[];
  total: number;
  next_offset: number | null;
}

export interface SharedReportSummary {
  share_id: string;
  customer_tenant_id: string;
  report_id: string;
  engagement_id: string;
  version: number;
  report_type: string | null;
  generated_at: string;
  manifest_hash: string;
  lifecycle: ReportLifecycle;
  integrity: ReportIntegrity;
  provenance: Record<string, unknown>;
  evidence_references: { count: number; ids: string[]; truncated: boolean };
  expires_at: string | null;
  verified_at: string;
}

/** Customer side: one page of the organization's own report versions, with every lifecycle fact. */
export function listShareableReports(
  offset = 0,
  engagementId?: string,
): Promise<SafeResult<ShareableReportPage>> {
  const filter = engagementId ? `&${new URLSearchParams({ engagement_id: engagementId })}` : '';
  return call(`${BASE}/reports/shareable?${page(200, offset)}${filter}`);
}

/** Customer side: every report version, following next_offset (fail-closed). */
export function listAllShareableReports(engagementId?: string): Promise<SafeResult<ShareableReportPage>> {
  return collectAllPages((offset) => listShareableReports(offset, engagementId));
}

/** Either side: one page of shares where the organization is `party`. */
export function listReportShares(
  party: 'customer' | 'msp',
  customerTenantId?: string,
  offset = 0,
): Promise<SafeResult<ReportSharePage>> {
  const params = new URLSearchParams({ party });
  // The customer id is a display filter on the MSP's own shares, never the caller's tenant.
  if (customerTenantId) params.set('customer_tenant_id', customerTenantId);
  return call(`${BASE}/report-shares?${page(200, offset)}&${params}`);
}

/** Either side: every share, following next_offset (fail-closed: no partial list). */
export function listAllReportShares(
  party: 'customer' | 'msp',
  customerTenantId?: string,
): Promise<SafeResult<ReportSharePage>> {
  return collectAllPages((offset) => listReportShares(party, customerTenantId, offset));
}

/** Customer side: share one exact report version (the fingerprint reviewed) with one MSP. */
export function shareReport(body: {
  relationship_id: string;
  report_id: string;
  manifest_hash: string;
  expires_at: string;
  request_key: string;
}): Promise<SafeResult<ReportShare & { created: boolean }>> {
  return call(`${BASE}/report-shares`, { method: 'POST', body: JSON.stringify(body) });
}

/** MSP side: ask for the report of an engagement started under one of its grants. Grants nothing. */
export function requestReportShare(body: {
  grant_id: string;
  request_key: string;
}): Promise<SafeResult<ReportShare & { created: boolean }>> {
  return call(`${BASE}/report-shares/requests`, { method: 'POST', body: JSON.stringify(body) });
}

export type ShareDecision = 'approve' | 'reject' | 'revoke' | 'withdraw';

/** Customer (approve, reject, revoke) or MSP (withdraw), bound to the version reviewed. */
export function decideReportShare(
  shareId: string,
  action: ShareDecision,
  expectedVersion: number,
  approval?: { report_id: string; manifest_hash: string; expires_at: string },
): Promise<SafeResult<ReportShare>> {
  const body: Record<string, unknown> = { expected_version: expectedVersion };
  if (action === 'approve' && approval) Object.assign(body, approval);
  return call(`${BASE}/report-shares/${encodeURIComponent(shareId)}/${action}`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/** Either side: one page of this share's history, including every read, from the organization's own chain. */
export function getShareHistory(shareId: string, offset = 0): Promise<SafeResult<ShareHistory>> {
  return call(`${BASE}/report-shares/${encodeURIComponent(shareId)}/events?${page(100, offset)}`);
}

/** MSP side: re-verify a shared report now (lifecycle, integrity, provenance). Audited. */
export function verifySharedReport(shareId: string): Promise<SafeResult<SharedReportSummary>> {
  return call(`${BASE}/report-shares/${encodeURIComponent(shareId)}/verify`);
}

/** MSP side: the canonical report document of the shared version. Audited; nothing is cached. */
export function downloadSharedReport(shareId: string): Promise<SafeResult<Record<string, unknown>>> {
  return call(`${BASE}/report-shares/${encodeURIComponent(shareId)}/download`);
}
