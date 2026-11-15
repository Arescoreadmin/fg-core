'use strict';

/**
 * MSP-002 console helpers — presentation only.
 *
 * Nothing here is an authorization decision. Which customers an MSP may see,
 * which permissions apply and whether an action succeeds are decided by Core
 * (api/msp_authority.py) on every request. These helpers only shape what Core
 * returned and validate form input before it is sent (Core validates again).
 */

// Mirrors MSP_DELEGABLE_PERMISSIONS in api/msp_authority.py (tested for drift).
const DELEGABLE_CAPABILITIES = Object.freeze([
  { id: 'assessment.read', label: 'Assessments (read)', description: 'See assessment engagements and their lifecycle status.' },
  { id: 'finding.read', label: 'Findings (read)', description: 'See outstanding findings counted by severity.' },
  { id: 'evidence.read', label: 'Evidence (read)', description: 'Read evidence records. Not shown in the MSP-002 portfolio.' },
  { id: 'scan.read', label: 'Scans (read)', description: 'See scan results. Not shown in the MSP-002 portfolio.' },
  { id: 'report.read', label: 'Reports (read)', description: 'Read delivered reports. Not shown in the MSP-002 portfolio.' },
  { id: 'bundle.read', label: 'Evidence bundles (read)', description: 'Read verification bundles. Not shown in the MSP-002 portfolio.' },
  { id: 'governance.read', label: 'Governance (read)', description: 'Read governance and control-plane records.' },
]);

const DELEGABLE_IDS = new Set(DELEGABLE_CAPABILITIES.map((c) => c.id));

// Mirrors MAX_RELATIONSHIP_DAYS in api/msp_authority.py.
const MAX_RELATIONSHIP_DAYS = 366;
const DEFAULT_APPROVAL_DAYS = 90;
const EXPIRING_SOON_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

const STATUS_LABELS = Object.freeze({
  proposed: { label: 'Awaiting customer approval', tone: 'warning' },
  approved: { label: 'Approved — not yet in effect', tone: 'secondary' },
  active: { label: 'Active', tone: 'success' },
  suspended: { label: 'Suspended by customer', tone: 'warning' },
  revoked: { label: 'Revoked', tone: 'danger' },
  expired: { label: 'Expired', tone: 'outline' },
});

const SECTION_STATE_LABELS = Object.freeze({
  available: 'Available',
  not_authorized: 'Not delegated by the customer',
  not_configured: 'No data recorded yet',
  unavailable: 'Temporarily unavailable',
});

function capabilityLabel(id) {
  const found = DELEGABLE_CAPABILITIES.find((c) => c.id === id);
  return found ? found.label : 'Unrecognized capability';
}

function statusView(status) {
  return STATUS_LABELS[status] || { label: 'Unknown status', tone: 'outline' };
}

function sectionStateLabel(state) {
  return SECTION_STATE_LABELS[state] || 'Unknown';
}

function isExpiringSoon(relationship, now = Date.now()) {
  if (!relationship || relationship.status !== 'active' || !relationship.expires_at) return false;
  const expires = Date.parse(relationship.expires_at);
  if (Number.isNaN(expires)) return false;
  return expires - now <= EXPIRING_SOON_DAYS * DAY_MS;
}

/** Overview counts from GET /admin/msp/relationships items. */
function summarizeRelationships(items, now = Date.now()) {
  const counts = { active: 0, pending: 0, approved: 0, suspended: 0, expiring: 0, revoked: 0, expired: 0 };
  for (const r of items || []) {
    if (r.status === 'proposed') counts.pending += 1;
    else if (r.status in counts) counts[r.status] += 1;
    if (isExpiringSoon(r, now)) counts.expiring += 1;
  }
  return counts;
}

/**
 * Actions the console offers for one relationship. Core enforces the same
 * rules (and compare-and-set); this only avoids offering impossible buttons.
 */
function availableActions(relationship, party) {
  if (!relationship) return [];
  const s = relationship.status;
  if (party === 'customer') {
    if (s === 'proposed') return ['approve', 'revoke'];
    if (s === 'active' || s === 'approved') return ['suspend', 'revoke'];
    if (s === 'suspended') return ['resume', 'revoke'];
    if (s === 'expired') return ['revoke'];
    return [];
  }
  if (party === 'msp') {
    return s === 'revoked' ? [] : ['revoke'];
  }
  return [];
}

/** The next thing an MSP operator can do for an authorized customer. */
function nextAction(item) {
  if (!item) return 'Unavailable';
  const perms = new Set(item.effective_permissions || []);
  const findings = item.findings || {};
  if (perms.has('finding.read') && findings.state === 'available' && findings.outstanding_total > 0) {
    return 'Review outstanding findings with the customer';
  }
  if (perms.has('assessment.read') && (item.assessment || {}).state === 'not_configured') {
    return 'No assessment recorded yet — plan one with the customer';
  }
  if (perms.has('assessment.read')) return 'Review assessment status';
  return 'Open the customer context to see what is delegated';
}

/**
 * Validate the customer's approval form and build the request body.
 * The customer may narrow, never widen, the requested capabilities.
 */
function buildApprovalBody({ requested, selected, days, now = Date.now() }) {
  const requestedSet = new Set(requested || []);
  const chosen = Array.from(new Set(selected || []));
  if (chosen.length === 0) return { ok: false, error: 'Select at least one capability to approve.' };
  for (const id of chosen) {
    if (!requestedSet.has(id)) return { ok: false, error: 'You can only approve capabilities the MSP requested.' };
    if (!DELEGABLE_IDS.has(id)) return { ok: false, error: 'That capability cannot be delegated.' };
  }
  const n = Number(days);
  if (!Number.isInteger(n) || n < 1 || n > MAX_RELATIONSHIP_DAYS) {
    return { ok: false, error: `Access must end within 1 to ${MAX_RELATIONSHIP_DAYS} days.` };
  }
  return {
    ok: true,
    body: {
      authorized_capabilities: chosen.sort(),
      expires_at: new Date(now + n * DAY_MS).toISOString(),
    },
  };
}

/** Validate the MSP's proposal form. Core decides whether the customer exists. */
function buildProposalBody({ customerTenantId, selected }) {
  const id = String(customerTenantId || '').trim();
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id)) {
    return { ok: false, error: 'Enter the customer organization ID they gave you.' };
  }
  const chosen = Array.from(new Set(selected || []));
  if (chosen.length === 0) return { ok: false, error: 'Request at least one capability.' };
  if (chosen.some((c) => !DELEGABLE_IDS.has(c))) return { ok: false, error: 'That capability cannot be requested.' };
  return { ok: true, body: { customer_tenant_id: id, requested_capabilities: chosen.sort() } };
}

const SAFE_ERRORS = Object.freeze({
  MSP_CUSTOMER_NOT_FOUND: 'This customer is not available to your organization. Access may be pending, suspended, revoked or expired.',
  MSP_RELATIONSHIP_NOT_FOUND: 'This relationship is not available.',
  MSP_RELATIONSHIP_EXISTS: 'A request for this customer is already open.',
  MSP_RELATIONSHIP_INVALID_TRANSITION: 'This relationship changed since you loaded it. Refresh and try again.',
  MSP_APPROVAL_REQUIRES_CUSTOMER: 'Only the customer organization can approve this request.',
  MSP_SELF_APPROVAL_DENIED: 'You also belong to the requesting MSP, so you cannot approve this request.',
  MSP_CAPABILITY_NOT_DELEGABLE: 'One of the selected capabilities cannot be delegated.',
  MSP_APPROVAL_WINDOW_INVALID: 'The access period is not valid.',
  MSP_ORGANIZATION_INACTIVE: 'Your organization is not an active managed service provider.',
  MSP_ACCESS_DENIED: 'Your organization is not set up as an active managed service provider, or your account cannot use it.',
  MSP_TENANT_NOT_ELIGIBLE: 'That organization cannot take part in MSP relationships.',
  MSP_RELATIONSHIPS_INCOMPLETE: 'Your organization has more relationships than this page can show. Contact support.',
});

/** Upper bound on pages collectAllPages follows (200 per page = 10,000 rows). */
const MAX_COLLECTED_PAGES = 50;

/**
 * Follow next_offset until the server reports no more pages, so a page never
 * acts on a silently truncated list. Fail-closed: a failed page is returned
 * as-is; a page that does not advance, or more than maxPages pages, returns
 * MSP_RELATIONSHIPS_INCOMPLETE instead of a partial list.
 */
async function collectAllPages(fetchPage, maxPages = MAX_COLLECTED_PAGES) {
  const items = [];
  let offset = 0;
  let first = null;
  for (let n = 0; n < maxPages; n += 1) {
    const res = await fetchPage(offset);
    if (!res || !res.ok) return res;
    if (first === null) first = res.data;
    items.push(...(res.data.items || []));
    const next = res.data.next_offset;
    if (next === null || next === undefined) {
      return { ok: true, data: { ...first, items, total: items.length, next_offset: null } };
    }
    if (typeof next !== 'number' || next <= offset) break;
    offset = next;
  }
  return { ok: false, error: 'Incomplete relationship list', code: 'MSP_RELATIONSHIPS_INCOMPLETE' };
}

/**
 * Map a failed API result to a message safe to show. Never shows server text:
 * only known codes, or a generic message for the HTTP status.
 */
function safeErrorMessage(result) {
  if (!result || result.ok) return '';
  if (result.status === 401) return 'Your session has expired. Sign in again to continue.';
  if (result.code && SAFE_ERRORS[result.code]) return SAFE_ERRORS[result.code];
  if (result.status === 403) return 'You do not have permission to do this. Only organization administrators can manage MSP relationships.';
  if (result.status === 404) return 'Not found, or not available to your organization.';
  if (result.status === 409) return SAFE_ERRORS.MSP_RELATIONSHIP_INVALID_TRANSITION;
  if (result.status === 422) return 'Some of the information entered is not valid.';
  if (result.status === undefined) return 'Network error — the service could not be reached.';
  return 'Something went wrong. Try again.';
}

module.exports = {
  DELEGABLE_CAPABILITIES,
  MAX_RELATIONSHIP_DAYS,
  DEFAULT_APPROVAL_DAYS,
  EXPIRING_SOON_DAYS,
  capabilityLabel,
  statusView,
  sectionStateLabel,
  isExpiringSoon,
  summarizeRelationships,
  availableActions,
  nextAction,
  buildApprovalBody,
  buildProposalBody,
  safeErrorMessage,
  MAX_COLLECTED_PAGES,
  collectAllPages,
};
