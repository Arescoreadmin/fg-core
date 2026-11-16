'use strict';

/**
 * MSP-007 console helpers — customer-controlled report sharing and partner
 * managed reporting.
 *
 * Presentation and form validation only. Whether a report may be shared or
 * read is decided by Core (api/msp_reporting.py) on every request, from the
 * canonical release, integrity and relationship authorities; a hidden or
 * disabled button here is never a control. Nothing here computes a rating.
 */

// Mirrors MAX_SHARE_DAYS in api/msp_reporting.py (tested for drift).
const MAX_SHARE_DAYS = 90;
const DEFAULT_SHARE_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

const SHARE_STATUS = Object.freeze({
  requested: { label: 'Requested — awaiting the customer', tone: 'warning' },
  active: { label: 'Shared', tone: 'success' },
  expired: { label: 'Expired', tone: 'outline' },
  rejected: { label: 'Declined by the customer', tone: 'outline' },
  withdrawn: { label: 'Withdrawn', tone: 'outline' },
  revoked: { label: 'Revoked by the customer', tone: 'danger' },
});

// Display groups for the partner report index, in order.
const SHARE_GROUPS = Object.freeze([
  { id: 'available', title: 'Available to you' },
  { id: 'blocked', title: 'Shared, but not available right now' },
  { id: 'awaiting_customer', title: 'Awaiting the customer' },
  { id: 'ended', title: 'Ended' },
]);

// Reasons Core gives for why a shared report cannot be read now.
const BLOCKER_LABELS = Object.freeze({
  SHARE_PENDING_CUSTOMER: 'Waiting for the customer’s administrator to choose a report version.',
  SHARE_REJECTED: 'The customer declined this request.',
  SHARE_WITHDRAWN: 'This request was withdrawn.',
  SHARE_REVOKED: 'The customer revoked access to this report.',
  SHARE_EXPIRED: 'The sharing period ended. The customer can share it again.',
  RELATIONSHIP_NOT_DELEGATING_REPORT_READ:
    'The customer relationship is not active, or no longer delegates report access.',
  RELATIONSHIP_INACTIVE: 'The customer relationship is not active.',
  CUSTOMER_TENANT_INACTIVE: 'The customer account is not active.',
  REPORT_UNAVAILABLE: 'The shared report is no longer available.',
  REPORT_VERSION_CHANGED:
    'The stored report no longer matches the version and fingerprint that was shared.',
  REPORT_NOT_RELEASED: 'The report is not released (final) at the moment.',
  REPORT_INTEGRITY_FAILED: 'The report content does not match its recorded fingerprint.',
  SIGNATURE_FAILED: 'The report signature did not verify.',
  EVIDENCE_CHAIN_FAILED: 'The evidence chain behind the report did not verify.',
  TRUST_ENFORCEMENT_BLOCKED: 'FrostGate’s trust checks blocked this download.',
  REPORT_TOO_LARGE: 'The report is too large to download here.',
  MSP_ACCESS_DENIED: 'Your account cannot read shared reports for this organization.',
});

// Every distinct verification outcome Core can return. A hash is never shown
// as a signature, and nothing is described as externally certified.
const INTEGRITY_LABELS = Object.freeze({
  HASH_VERIFIED: { label: 'Fingerprint matches content', tone: 'success' },
  SIGNATURE_VERIFIED: { label: 'Signature verified', tone: 'success' },
  AUDIT_CHAIN_VERIFIED: { label: 'Evidence chain verified', tone: 'success' },
  VERIFICATION_UNAVAILABLE: { label: 'Not available', tone: 'outline' },
  VERIFICATION_FAILED: { label: 'Failed', tone: 'danger' },
});

const SIGNATURE_KINDS = Object.freeze({
  trust_binding: 'FrostGate trust-binding signature',
  legacy_ed25519: 'FrostGate report signature (legacy)',
  none: 'Unsigned',
});

// Separate lifecycle facts, in canonical order. Never collapsed into one flag.
const LIFECYCLE_FACTS = Object.freeze([
  { id: 'exists', label: 'Report generated' },
  { id: 'qa_approved', label: 'QA approved' },
  { id: 'independent_qa', label: 'Independent human QA' },
  { id: 'production_qualified', label: 'Production qualified' },
  { id: 'released', label: 'Released (final)' },
  { id: 'delivery_authorized', label: 'Delivery authorized' },
  { id: 'delivered', label: 'Delivered' },
]);

const ACTION_LABELS = Object.freeze({
  REVIEW_REPORT_SHARE_REQUEST: 'Choose a report version to share, or decline',
  RENEW_REPORT_SHARE: 'Share the report again',
  SHARE_CURRENT_RELEASED_VERSION: 'Share the current released version',
  DELEGATE_REPORT_READ: 'Restore report access in the relationship',
});

const OWNER_LABELS = Object.freeze({ customer: 'Customer', msp: 'You' });

const SAFE_ERRORS = Object.freeze({
  MSP_REPORT_SHARE_NOT_FOUND: 'This shared report is not available.',
  MSP_REPORT_SHARE_CONFLICT:
    'This report is already shared with this partner, or the reference is in use. Refresh and try again.',
  MSP_REPORT_SHARE_INVALID_TRANSITION:
    'This share changed since you loaded it, or is no longer in a state that allows this. Refresh and try again.',
  MSP_REPORT_SHARE_UNAVAILABLE: 'This shared report is not available right now.',
  MSP_REPORT_NOT_FOUND: 'This report is not available.',
  MSP_REPORT_NOT_SHAREABLE: 'This report cannot be shared yet: it is not released, or it did not verify.',
  MSP_REPORT_FINGERPRINT_MISMATCH: 'The report changed since you loaded it. Refresh and review it again.',
  MSP_REPORT_READ_NOT_DELEGATED: 'This partner relationship does not include report access.',
  MSP_RELATIONSHIP_INACTIVE: 'The partner relationship is not active.',
  MSP_RELATIONSHIP_NOT_FOUND: 'This partner relationship is not available.',
  MSP_ASSESSMENT_GRANT_NOT_FOUND: 'This assessment is not available to your organization.',
  MSP_APPROVAL_REQUIRES_CUSTOMER: 'Only the customer organization can decide this.',
  MSP_SELF_APPROVAL_DENIED: 'You also belong to the partner organization, so you cannot approve its access.',
  MSP_APPROVAL_WINDOW_INVALID: `The sharing period is not valid (1 to ${MAX_SHARE_DAYS} days).`,
  MSP_ORGANIZATION_INACTIVE: 'The partner is not an active managed service provider.',
  CAPABILITY_DENIED: 'Your organization’s plan does not include managed service features.',
});

function shareStatusView(share) {
  const key = share && share.status;
  return SHARE_STATUS[key] || { label: 'Unknown status', tone: 'outline' };
}

function blockerLabel(code) {
  return BLOCKER_LABELS[code] || 'Not available right now.';
}

function integrityView(value) {
  return INTEGRITY_LABELS[value] || INTEGRITY_LABELS.VERIFICATION_UNAVAILABLE;
}

function signatureKindLabel(kind) {
  return SIGNATURE_KINDS[kind] || SIGNATURE_KINDS.none;
}

function lifecycleFacts(lifecycle) {
  const src = lifecycle || {};
  return LIFECYCLE_FACTS.map((f) => ({ id: f.id, label: f.label, value: src[f.id] === true }));
}

function nextActionLabel(action) {
  if (!action) return '';
  const owner = OWNER_LABELS[action.owner] || 'Someone';
  const what = ACTION_LABELS[action.code] || 'Follow up';
  return `${owner}: ${what}`;
}

/** Which group a share belongs to in the partner index. Presentation only. */
function shareGroup(share) {
  const status = share && share.status;
  if (status === 'requested') return 'awaiting_customer';
  if (status === 'active') {
    return share.access && share.access.state === 'available' ? 'available' : 'blocked';
  }
  return 'ended';
}

function groupShares(items) {
  const groups = Object.fromEntries(SHARE_GROUPS.map((g) => [g.id, []]));
  for (const item of items || []) groups[shareGroup(item)].push(item);
  return SHARE_GROUPS.map((g) => ({ ...g, items: groups[g.id] }));
}

/**
 * Which buttons to offer. Presentation only: Core re-checks every action.
 * The customer approves or declines a request and revokes an active share;
 * the MSP withdraws its own request and verifies or downloads an available
 * share. The MSP never gets approve.
 */
function shareActions(share) {
  if (!share) return [];
  if (share.party === 'customer') {
    if (share.status === 'requested') return ['approve', 'reject'];
    // An expired share needs no revoke; sharing the report again retires it.
    if (share.status === 'active') return ['revoke'];
    return [];
  }
  if (share.party === 'msp') {
    if (share.status === 'requested') return ['withdraw'];
    if (share.status === 'active' && share.access && share.access.state === 'available') {
      return ['verify', 'download'];
    }
  }
  return [];
}

function shortHash(hash) {
  const h = String(hash || '');
  return /^[0-9a-f]{64}$/.test(h) ? `${h.slice(0, 12)}…${h.slice(-6)}` : '—';
}

function newShareKey(prefix = 'share') {
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}-${Date.now().toString(36)}-${rand}`;
}

function buildShareBody({ relationshipId, report, days, requestKey, now = Date.now() }) {
  const rel = String(relationshipId || '').trim();
  if (!/^[A-Za-z0-9-]{1,36}$/.test(rel)) return { ok: false, error: 'Choose a partner.' };
  if (!report || report.share_eligible !== true) {
    return { ok: false, error: 'Choose a released report that verified.' };
  }
  if (!/^[0-9a-f]{64}$/.test(String(report.manifest_hash || ''))) {
    return { ok: false, error: 'This report has no valid fingerprint.' };
  }
  const n = Number(days);
  if (!Number.isInteger(n) || n < 1 || n > MAX_SHARE_DAYS) {
    return { ok: false, error: `Sharing can last 1 to ${MAX_SHARE_DAYS} days.` };
  }
  const key = String(requestKey || '').trim();
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(key)) return { ok: false, error: 'Internal reference missing. Reload the page.' };
  return {
    ok: true,
    body: {
      relationship_id: rel,
      report_id: report.report_id,
      manifest_hash: report.manifest_hash,
      expires_at: new Date(now + n * DAY_MS).toISOString(),
      request_key: key,
    },
  };
}

function buildApprovalBody({ report, days, now = Date.now() }) {
  if (!report || report.share_eligible !== true) {
    return { ok: false, error: 'Choose a released report that verified.' };
  }
  const n = Number(days);
  if (!Number.isInteger(n) || n < 1 || n > MAX_SHARE_DAYS) {
    return { ok: false, error: `Sharing can last 1 to ${MAX_SHARE_DAYS} days.` };
  }
  return {
    ok: true,
    body: {
      report_id: report.report_id,
      manifest_hash: report.manifest_hash,
      expires_at: new Date(now + n * DAY_MS).toISOString(),
    },
  };
}

function safeReportingError(result) {
  if (!result || result.ok) return '';
  if (result.status === 401) return 'Your session has expired. Sign in again to continue.';
  if (Array.isArray(result.blockers) && result.blockers.length > 0) {
    return result.blockers.map(blockerLabel).join(' ');
  }
  if (result.code && SAFE_ERRORS[result.code]) return SAFE_ERRORS[result.code];
  if (result.status === 403) return 'You do not have permission to do this.';
  if (result.status === 404) return 'Not found, or not available to your organization.';
  if (result.status === 409) return SAFE_ERRORS.MSP_REPORT_SHARE_INVALID_TRANSITION;
  if (result.status === 422) return 'Some of the information entered is not valid.';
  if (result.status === undefined) return 'Network error — the service could not be reached.';
  return 'Something went wrong. Try again.';
}

/** A safe local filename for a downloaded report document. */
function downloadFilename(doc) {
  const eng = String((doc && doc.engagement_id) || 'report').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64) || 'report';
  const v = Number.isInteger(doc && doc.version) ? doc.version : 0;
  return `report-${eng}-v${v}.json`;
}

module.exports = {
  MAX_SHARE_DAYS,
  DEFAULT_SHARE_DAYS,
  SHARE_GROUPS,
  LIFECYCLE_FACTS,
  shareStatusView,
  blockerLabel,
  integrityView,
  signatureKindLabel,
  lifecycleFacts,
  nextActionLabel,
  shareGroup,
  groupShares,
  shareActions,
  shortHash,
  newShareKey,
  buildShareBody,
  buildApprovalBody,
  safeReportingError,
  downloadFilename,
};
