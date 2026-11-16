'use strict';

/**
 * MSP-003 console helpers — partner-guided onboarding and assessment requests.
 *
 * Presentation and form validation only. Whether an MSP may request, initiate
 * or see anything is decided by Core (api/msp_orchestration.py) on every
 * request; a hidden or disabled button here is never a control. Core
 * validates every body again.
 */

// Mirrors services/field_assessment/models.py AssessmentType (tested for drift).
const ASSESSMENT_TYPES = Object.freeze([
  { id: 'ai_governance', label: 'AI governance' },
  { id: 'soc2', label: 'SOC 2' },
  { id: 'hipaa', label: 'HIPAA' },
  { id: 'iso27001', label: 'ISO 27001' },
  { id: 'cmmc', label: 'CMMC' },
  { id: 'pci_dss', label: 'PCI DSS' },
  { id: 'dora', label: 'DORA' },
  { id: 'fedramp', label: 'FedRAMP' },
  { id: 'nist_800_171', label: 'NIST 800-171' },
  { id: 'comprehensive', label: 'Comprehensive' },
]);
const ASSESSMENT_TYPE_IDS = new Set(ASSESSMENT_TYPES.map((t) => t.id));

// Mirrors MAX_GRANT_DAYS in api/msp_orchestration.py.
const MAX_GRANT_DAYS = 90;
const DEFAULT_GRANT_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

const GRANT_STATUS = Object.freeze({
  requested: { label: 'Awaiting customer approval', tone: 'warning' },
  approved: { label: 'Approved — ready to start', tone: 'success' },
  initiated: { label: 'Assessment started', tone: 'secondary' },
  rejected: { label: 'Declined by customer', tone: 'outline' },
  withdrawn: { label: 'Withdrawn', tone: 'outline' },
  revoked: { label: 'Revoked by customer', tone: 'danger' },
  expired: { label: 'Expired', tone: 'outline' },
});

// Reasons Core gives for why an assessment cannot start (initiation_blockers).
const BLOCKER_LABELS = Object.freeze({
  CUSTOMER_APPROVAL_PENDING: 'Waiting for the customer’s administrator to approve.',
  GRANT_REJECTED: 'The customer declined this request.',
  GRANT_WITHDRAWN: 'This request was withdrawn.',
  GRANT_REVOKED: 'The customer revoked this authority.',
  GRANT_EXPIRED: 'The approval period ended. Send a new request.',
  MSP_ORGANIZATION_INACTIVE: 'Your organization is not an active managed service provider.',
  RELATIONSHIP_INACTIVE: 'The customer relationship is not active (suspended, revoked or expired).',
  CUSTOMER_TENANT_INACTIVE: 'The customer account is not active.',
  NOT_ENTITLED: 'No billing arrangement covers this assessment yet. FrostGate must set one up.',
});

const OWNER_LABELS = Object.freeze({
  customer: 'Customer',
  msp: 'You',
  platform: 'FrostGate',
  assessor: 'Assessor',
});

const ACTION_LABELS = Object.freeze({
  REVIEW_ASSESSMENT_REQUEST: 'Review the assessment request',
  INITIATE_ASSESSMENT: 'Start the assessment',
  ASSIGN_PAYER: 'Set up billing for this customer',
  CONDUCT_ASSESSMENT: 'Carry out the assessment',
  REVIEW_ONBOARDING_REQUEST: 'Review the onboarding referral',
  INVITE_INITIAL_ADMIN: 'Invite the customer’s first administrator',
  ACCEPT_INVITATION: 'Accept the FrostGate invitation',
  PROPOSE_RELATIONSHIP: 'Request access to the customer',
  REVIEW_RELATIONSHIP: 'Approve the relationship request',
});

const ONBOARDING_STAGES = Object.freeze({
  requested: { label: 'Waiting for FrostGate review', tone: 'warning' },
  expired: { label: 'Expired — not reviewed in time', tone: 'outline' },
  rejected: { label: 'Not accepted by FrostGate', tone: 'outline' },
  canceled: { label: 'Canceled', tone: 'outline' },
  provisioning: { label: 'Account being set up', tone: 'secondary' },
  invited: { label: 'Customer invited', tone: 'secondary' },
  customer_accepted: { label: 'Customer joined — request access', tone: 'success' },
  awaiting_customer_approval: { label: 'Awaiting customer approval', tone: 'warning' },
  active: { label: 'Active', tone: 'success' },
  relationship_inactive: { label: 'Relationship not active', tone: 'outline' },
  customer_inactive: { label: 'Customer account inactive', tone: 'outline' },
});

const SAFE_ERRORS = Object.freeze({
  MSP_ASSESSMENT_GRANT_NOT_FOUND: 'This assessment request is not available.',
  MSP_ASSESSMENT_GRANT_CONFLICT: 'A different request already uses this reference. Refresh and try again.',
  MSP_ASSESSMENT_GRANT_INVALID_TRANSITION: 'This request changed since you loaded it, or is no longer in a state that allows this. Refresh and try again.',
  MSP_ASSESSMENT_GRANT_EXPIRED: BLOCKER_LABELS.GRANT_EXPIRED,
  MSP_ASSESSMENT_NOT_ENTITLED: BLOCKER_LABELS.NOT_ENTITLED,
  MSP_RELATIONSHIP_INACTIVE: BLOCKER_LABELS.RELATIONSHIP_INACTIVE,
  MSP_CUSTOMER_TENANT_INACTIVE: BLOCKER_LABELS.CUSTOMER_TENANT_INACTIVE,
  MSP_CUSTOMER_NOT_FOUND: 'This customer is not available to your organization. Access may be pending, suspended, revoked or expired.',
  MSP_APPROVAL_REQUIRES_CUSTOMER: 'Only the customer organization can decide this request.',
  MSP_SELF_APPROVAL_DENIED: 'You also belong to the requesting MSP, so you cannot approve this request.',
  MSP_APPROVAL_WINDOW_INVALID: `The approval period is not valid (at most ${MAX_GRANT_DAYS} days, and never longer than requested).`,
  MSP_ORGANIZATION_INACTIVE: BLOCKER_LABELS.MSP_ORGANIZATION_INACTIVE,
  MSP_ONBOARDING_REQUEST_NOT_FOUND: 'This referral is not available.',
  MSP_ONBOARDING_REQUEST_CONFLICT: 'A different referral already uses this reference.',
  MSP_ONBOARDING_INVALID_TRANSITION: 'This referral changed since you loaded it. Refresh and try again.',
});

function assessmentTypeLabel(id) {
  const found = ASSESSMENT_TYPES.find((t) => t.id === id);
  return found ? found.label : 'Unrecognized assessment type';
}

function grantStatusView(grant) {
  const key = grant && grant.effective_status ? grant.effective_status : grant && grant.status;
  return GRANT_STATUS[key] || { label: 'Unknown status', tone: 'outline' };
}

function blockerLabel(code) {
  return BLOCKER_LABELS[code] || 'Not available right now.';
}

function nextActionLabel(action) {
  if (!action) return '';
  const owner = OWNER_LABELS[action.owner] || 'Someone';
  const what = ACTION_LABELS[action.code] || 'Follow up';
  return `${owner}: ${what}`;
}

function onboardingStageView(stage) {
  return ONBOARDING_STAGES[stage] || { label: 'Unknown stage', tone: 'outline' };
}

/**
 * Which buttons to offer for a grant. Presentation only: Core re-checks every
 * action. The MSP may withdraw a pending request and start an approved one
 * with no blockers; the customer may approve or decline a pending request and
 * revoke an approved or started one.
 */
function grantActions(grant) {
  if (!grant) return [];
  const status = grant.effective_status || grant.status;
  if (grant.party === 'customer') {
    if (status === 'requested') return ['approve', 'reject'];
    if (status === 'approved' || status === 'initiated') return ['revoke'];
    return [];
  }
  if (grant.party === 'msp') {
    if (status === 'requested') return ['withdraw'];
    if (status === 'approved' && Array.isArray(grant.blockers) && grant.blockers.length === 0) return ['initiate'];
  }
  return [];
}

function progressLabel(progress) {
  if (!progress) return '—';
  switch (progress.state) {
    case 'not_started':
      return 'Not started';
    case 'not_authorized':
      return 'Not visible: the customer has not delegated assessment status, or revoked this authority.';
    case 'unavailable':
      return 'Temporarily unavailable';
    case 'available':
      return String(progress.engagement_status || '').replace(/_/g, ' ') || '—';
    default:
      return '—';
  }
}

function newRequestKey(prefix = 'req') {
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}-${Date.now().toString(36)}-${rand}`;
}

function buildGrantRequestBody({ customerTenantId, assessmentType, assessorId, days, requestKey, now = Date.now() }) {
  const id = String(customerTenantId || '').trim();
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id)) return { ok: false, error: 'Choose a customer.' };
  if (!ASSESSMENT_TYPE_IDS.has(assessmentType)) return { ok: false, error: 'Choose an assessment type.' };
  const assessor = String(assessorId || '').trim();
  if (!/^[A-Za-z0-9._@|:-]{1,128}$/.test(assessor)) {
    return { ok: false, error: 'Enter the assessor identifier (letters, digits and . _ @ | : - only).' };
  }
  const n = Number(days);
  if (!Number.isInteger(n) || n < 1 || n > MAX_GRANT_DAYS) {
    return { ok: false, error: `The request can last 1 to ${MAX_GRANT_DAYS} days.` };
  }
  const key = String(requestKey || '').trim();
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(key)) return { ok: false, error: 'Internal reference missing. Reload the page.' };
  return {
    ok: true,
    body: {
      customer_tenant_id: id,
      request_key: key,
      assessment_type: assessmentType,
      assessor_id: assessor,
      expires_at: new Date(now + n * DAY_MS).toISOString(),
    },
  };
}

function buildOnboardingBody({ organizationName, contactEmail, selected, requestKey }) {
  const name = String(organizationName || '').trim();
  if (name.length < 1 || name.length > 200) return { ok: false, error: 'Enter the organization’s name.' };
  const email = String(contactEmail || '').trim().toLowerCase();
  if (!/^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{1,63}$/.test(email) || email.length > 254) {
    return { ok: false, error: 'Enter a valid contact email address.' };
  }
  const chosen = Array.from(new Set(selected || [])).sort();
  if (chosen.length === 0) return { ok: false, error: 'Request at least one capability.' };
  const key = String(requestKey || '').trim();
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(key)) return { ok: false, error: 'Internal reference missing. Reload the page.' };
  return {
    ok: true,
    body: { request_key: key, organization_name: name, contact_email: email, requested_capabilities: chosen },
  };
}

function safeOrchestrationError(result) {
  if (!result || result.ok) return '';
  if (result.status === 401) return 'Your session has expired. Sign in again to continue.';
  if (result.code && SAFE_ERRORS[result.code]) return SAFE_ERRORS[result.code];
  if (result.status === 403) return 'You do not have permission to do this. Only organization administrators can manage MSP assessments.';
  if (result.status === 404) return 'Not found, or not available to your organization.';
  if (result.status === 409) return SAFE_ERRORS.MSP_ASSESSMENT_GRANT_INVALID_TRANSITION;
  if (result.status === 422) return 'Some of the information entered is not valid.';
  if (result.status === undefined) return 'Network error — the service could not be reached.';
  return 'Something went wrong. Try again.';
}

module.exports = {
  ASSESSMENT_TYPES,
  MAX_GRANT_DAYS,
  DEFAULT_GRANT_DAYS,
  assessmentTypeLabel,
  grantStatusView,
  blockerLabel,
  nextActionLabel,
  onboardingStageView,
  grantActions,
  progressLabel,
  newRequestKey,
  buildGrantRequestBody,
  buildOnboardingBody,
  safeOrchestrationError,
};
