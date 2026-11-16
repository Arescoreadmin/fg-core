'use strict';

/**
 * MSP-002 — MSP portfolio + customer approval console.
 *
 * Behavioural tests of the pure helpers (lib/mspConsole.js) and the shared
 * access policy (lib/consoleAccess.js), plus source-contract tests of the BFF
 * rules, API client and pages (the repo has no React rendering harness).
 * Authorization itself is Core's; Core-side behaviour is covered by
 * tests/security/test_msp_002_*.py.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const msp = require('../lib/mspConsole');
const { canAccessConsoleRoute, canAccessCoreApiPath, getCoreApiPolicy } = require('../lib/consoleAccess');

function read(rel) {
  return fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
}

const PAGE_MSP = 'app/msp/page.tsx';
const PAGE_PARTNERS = 'app/partners/page.tsx';
const API = 'lib/mspApi.ts';
const BFF = 'app/api/core/[...path]/route.ts';
const DIALOG = 'components/msp/ConfirmDialog.tsx';
const HISTORY = 'components/msp/RelationshipHistory.tsx';

const tenantAdmin = { user: { roles: ['tenant_admin'], tenant_id: 'cust-1' } };
const readOnly = { user: { roles: ['client_read_only'], tenant_id: 'cust-1' } };
const remediationOwner = { user: { roles: ['client_remediation_owner'], tenant_id: 'cust-1' } };
const portalOnly = { user: { roles: ['portal_user'], tenant_id: 'cust-1' } };

// ── Drift: the console mirrors Core's delegation ceiling exactly ──────────────

test('capability list mirrors MSP_DELEGABLE_PERMISSIONS in api/msp_authority.py', () => {
  const py = fs.readFileSync(path.join(__dirname, '../../../api/msp_authority.py'), 'utf8');
  const block = py.match(/MSP_DELEGABLE_PERMISSIONS[^=]*=\s*frozenset\(\s*\{([\s\S]*?)\}\s*\)/);
  assert.ok(block, 'MSP_DELEGABLE_PERMISSIONS not found');
  const core = Array.from(block[1].matchAll(/"([a-z_.]+)"/g)).map((m) => m[1]).sort();
  assert.deepEqual(msp.DELEGABLE_CAPABILITIES.map((c) => c.id).sort(), core);
  const days = py.match(/MAX_RELATIONSHIP_DAYS\s*=\s*(\d+)/);
  assert.equal(msp.MAX_RELATIONSHIP_DAYS, Number(days[1]));
});

test('every delegable capability has a plain description and is read-only', () => {
  for (const cap of msp.DELEGABLE_CAPABILITIES) {
    assert.match(cap.id, /\.read$/);
    assert.ok(cap.label && cap.description.length > 10, cap.id);
  }
});

// ── 27, 28. Pending, suspended and revoked states ─────────────────────────────

test('27/28: status labels distinguish pending, suspended, revoked and expired', () => {
  assert.equal(msp.statusView('proposed').label, 'Awaiting customer approval');
  assert.equal(msp.statusView('suspended').label, 'Suspended by customer');
  assert.equal(msp.statusView('revoked').label, 'Revoked');
  assert.equal(msp.statusView('expired').label, 'Expired');
  assert.equal(msp.statusView('nonsense').label, 'Unknown status');
});

test('customer actions follow the MSP-001 lifecycle; MSP may only end its own access', () => {
  const c = (status) => msp.availableActions({ status }, 'customer');
  assert.deepEqual(c('proposed'), ['approve', 'revoke']);
  assert.deepEqual(c('active'), ['suspend', 'revoke']);
  assert.deepEqual(c('suspended'), ['resume', 'revoke']);
  assert.deepEqual(c('revoked'), []);
  assert.deepEqual(msp.availableActions({ status: 'proposed' }, 'msp'), ['revoke']);
  assert.deepEqual(msp.availableActions({ status: 'revoked' }, 'msp'), []);
  // The MSP side is never offered approve, suspend or resume.
  for (const s of ['proposed', 'active', 'suspended', 'expired']) {
    assert.ok(!msp.availableActions({ status: s }, 'msp').some((a) => a !== 'revoke'), s);
  }
});

test('overview counts come only from the relationships Core returned', () => {
  const now = Date.parse('2026-11-14T00:00:00Z');
  const counts = msp.summarizeRelationships(
    [
      { status: 'active', expires_at: '2026-11-30T00:00:00Z' },
      { status: 'active', expires_at: '2027-06-01T00:00:00Z' },
      { status: 'proposed' },
      { status: 'suspended' },
      { status: 'revoked' },
    ],
    now,
  );
  assert.deepEqual(counts, { active: 2, pending: 1, approved: 0, suspended: 1, expiring: 1, revoked: 1, expired: 0 });
  assert.deepEqual(msp.summarizeRelationships([]).active, 0);
});

test('absent and undelegated summaries are labelled, never shown as zero', () => {
  assert.equal(msp.sectionStateLabel('not_authorized'), 'Not delegated by the customer');
  assert.equal(msp.sectionStateLabel('not_configured'), 'No data recorded yet');
  assert.equal(msp.sectionStateLabel('unavailable'), 'Temporarily unavailable');
  assert.equal(msp.nextAction({ effective_permissions: [], assessment: { state: 'not_authorized' } }),
    'Open the customer context to see what is delegated');
});

// ── 21, 22. Form validation mirrors Core (which validates again) ──────────────

test('22: approval narrows only and stays within the expiry limit', () => {
  const now = Date.parse('2026-11-14T00:00:00Z');
  const requested = ['assessment.read', 'finding.read'];
  const ok = msp.buildApprovalBody({ requested, selected: ['finding.read'], days: 90, now });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.body.authorized_capabilities, ['finding.read']);
  assert.equal(ok.body.expires_at, '2027-02-12T00:00:00.000Z');
  assert.equal(msp.buildApprovalBody({ requested, selected: ['evidence.read'], days: 90 }).ok, false);
  assert.equal(msp.buildApprovalBody({ requested, selected: [], days: 90 }).ok, false);
  assert.equal(msp.buildApprovalBody({ requested, selected: requested, days: 367 }).ok, false);
  assert.equal(msp.buildApprovalBody({ requested, selected: requested, days: 0 }).ok, false);
  assert.equal(msp.buildApprovalBody({ requested, selected: requested, days: 1.5 }).ok, false);
});

test('21: proposals reject non-delegable capabilities and malformed ids', () => {
  assert.equal(msp.buildProposalBody({ customerTenantId: 'cust-1', selected: ['key.manage'] }).ok, false);
  assert.equal(msp.buildProposalBody({ customerTenantId: '../x', selected: ['finding.read'] }).ok, false);
  assert.equal(msp.buildProposalBody({ customerTenantId: 'cust-1', selected: [] }).ok, false);
  const ok = msp.buildProposalBody({ customerTenantId: ' cust-1 ', selected: ['finding.read', 'assessment.read'] });
  assert.deepEqual(ok.body, { customer_tenant_id: 'cust-1', requested_capabilities: ['assessment.read', 'finding.read'] });
});

// ── 30, 31. Safe errors ───────────────────────────────────────────────────────

test('30: an expired session is reported as such', () => {
  assert.match(msp.safeErrorMessage({ ok: false, status: 401 }), /session has expired/);
});

test('31: errors never echo server text or foreign identities', () => {
  const leaky = { ok: false, status: 404, code: 'SOMETHING', error: 'tenant cust-2 belongs to Acme' };
  const msg = msp.safeErrorMessage(leaky);
  assert.doesNotMatch(msg, /cust-2|Acme/);
  assert.equal(
    msp.safeErrorMessage({ ok: false, status: 404, code: 'MSP_CUSTOMER_NOT_FOUND' }),
    'This customer is not available to your organization. Access may be pending, suspended, revoked or expired.',
  );
  assert.match(msp.safeErrorMessage({ ok: false, status: 409 }), /changed since you loaded it/);
  assert.match(msp.safeErrorMessage({ ok: false }), /Network error/);
});

// ── 34. Access policy: who can reach the pages and the BFF routes ─────────────

test('34: tenant admins reach both MSP pages; other client roles do not', () => {
  for (const route of ['/msp', '/partners']) {
    assert.equal(canAccessConsoleRoute(route, tenantAdmin), true, route);
    assert.equal(canAccessConsoleRoute(route, readOnly), false, route);
    assert.equal(canAccessConsoleRoute(route, remediationOwner), false, route);
    assert.equal(canAccessConsoleRoute(route, portalOnly), false, route);
    assert.equal(canAccessConsoleRoute(route, { user: {} }), false, route);
  }
});

test('BFF policy: admin/msp is tenant-scoped, tenant_admin only among client roles', () => {
  const policy = getCoreApiPolicy('admin/msp/portfolio');
  assert.equal(policy.tenantScoped, true);
  assert.equal(canAccessCoreApiPath('admin/msp/portfolio', 'GET', tenantAdmin), true);
  assert.equal(canAccessCoreApiPath('admin/msp/relationships/r1/approve', 'POST', tenantAdmin), true);
  assert.equal(canAccessCoreApiPath('admin/msp/portfolio', 'GET', readOnly), false);
  assert.equal(canAccessCoreApiPath('admin/msp/relationships', 'POST', remediationOwner), false);
});

// ── BFF transport contract ────────────────────────────────────────────────────

test('BFF proxies only GET/POST MSP routes and never the platform designation', () => {
  const src = read(BFF);
  const rules = Array.from(src.matchAll(/\{ prefix: '(admin\/msp[^']*)', methods: new Set\(\[([^\]]*)\]\) \}/g));
  const byPrefix = Object.fromEntries(rules.map((m) => [m[1], m[2]]));
  // MSP-003 added admin/msp/assessments and admin/msp/onboarding (GET/POST only);
  // MSP-007 added admin/msp/report-shares (GET/POST) and admin/msp/reports (GET).
  assert.deepEqual(Object.keys(byPrefix).sort(), [
    'admin/msp/assessments',
    'admin/msp/customers',
    'admin/msp/onboarding',
    'admin/msp/portfolio',
    'admin/msp/relationships',
    'admin/msp/report-shares',
    'admin/msp/reports',
  ]);
  for (const methods of Object.values(byPrefix)) {
    assert.doesNotMatch(methods, /PUT|PATCH|DELETE/);
  }
  // No broad admin/msp rule, so admin/msp/organizations can never match.
  assert.doesNotMatch(src, /\{ prefix: 'admin\/msp(\/organizations)?',/);
});

test('BFF sends MSP routes as delegated named-actor calls for the session tenant', () => {
  const src = read(BFF);
  const fn = src.slice(src.indexOf('function isTenantAdminCorePath'), src.indexOf('function isFieldAssessmentMutationPath'));
  assert.match(fn, /admin\/msp\/relationships/);
  assert.match(fn, /admin\/msp\/customers/);
  assert.match(fn, /admin\/msp\/portfolio/);
  assert.match(fn, /isMspConsolePath \|\|/);
  // The customer id in customers/{id}/context must not be parsed as a tenant.
  const tenantFn = src.slice(src.indexOf('function tenantIdFromCorePath'), src.indexOf('function isInvitationAcceptancePath'));
  assert.doesNotMatch(tenantFn, /msp/);
});

// ── 11, 13, 33. Client never asserts authority ────────────────────────────────

test('11/13: the API client never sends a caller tenant id', () => {
  const src = read(API);
  assert.doesNotMatch(src, /X-Tenant-I[dD]/);
  assert.doesNotMatch(src, /tenant_id=/);
  assert.match(src, /customer_tenant_id/); // only as a proposal/context target
});

test('33: every MSP request is uncached', () => {
  const src = read(API);
  assert.match(src, /cache: 'no-store'/);
  assert.equal((src.match(/fetch\(/g) || []).length, 1, 'single fetch path');
});

test('no client-side storage, HTML injection or raw server errors on MSP pages', () => {
  for (const file of [PAGE_MSP, PAGE_PARTNERS, HISTORY, API]) {
    const src = read(file);
    assert.doesNotMatch(src, /localStorage|sessionStorage|document\.cookie/, file);
    assert.doesNotMatch(src, /dangerouslySetInnerHTML/, file);
    assert.doesNotMatch(src, /\.error\}/, `${file} renders a raw error`);
  }
});

// ── 29. Duplicate-submission resistance and confirmation ──────────────────────

test('29: mutations are guarded against duplicate submission', () => {
  const partners = read(PAGE_PARTNERS);
  assert.match(partners, /if \(!pending \|\| busy\) return;/);
  const page = read(PAGE_MSP);
  assert.match(page, /if \(proposing\) return;/);
  assert.match(page, /if \(!revokeTarget \|\| revoking\) return;/);
  assert.match(page, /if \(selecting\) return;/);
  const dialog = read(DIALOG);
  assert.match(dialog, /loading=\{busy\}/);
  assert.match(dialog, /disabled=\{busy\}/);
});

test('approve, suspend, resume and revoke all go through the confirmation dialog', () => {
  const partners = read(PAGE_PARTNERS);
  assert.match(partners, /<ConfirmDialog/);
  for (const action of ['suspend', 'resume', 'revoke']) {
    assert.match(partners, new RegExp(`${action}: \\{\\s*title:`), action);
  }
  assert.match(partners, /Approve access/);
  assert.match(read(PAGE_MSP), /<ConfirmDialog/);
});

test('30: both pages handle an expired session safely', () => {
  for (const file of [PAGE_MSP, PAGE_PARTNERS]) {
    const src = read(file);
    assert.match(src, /status === 401/, file);
    assert.match(src, /Sign in again/, file);
  }
});

test('pages render the required operational states', () => {
  const page = read(PAGE_MSP);
  for (const id of ['msp-overview', 'msp-customer-list', 'msp-empty-portfolio', 'msp-not-configured', 'msp-relationship-requests', 'msp-propose']) {
    assert.match(page, new RegExp(`data-testid="${id}"`), id);
  }
  const partners = read(PAGE_PARTNERS);
  for (const id of ['msp-requests', 'msp-current', 'msp-ended']) {
    assert.match(partners, new RegExp(`'${id}'`), id);
  }
});

test('accessibility: labelled sections, table caption, live regions and alerts', () => {
  const page = read(PAGE_MSP);
  assert.match(page, /<caption className="sr-only">/);
  assert.match(page, /scope="col"/);
  assert.match(page, /aria-labelledby="msp-customers-h"/);
  assert.match(page, /aria-live="polite"/);
  assert.match(page, /role="alert"/);
  const partners = read(PAGE_PARTNERS);
  assert.match(partners, /htmlFor="approval-days"/);
  assert.match(partners, /aria-describedby="approval-days-help"/);
  assert.match(read('components/msp/CapabilityPicker.tsx'), /<fieldset/);
});

test('no fabricated metrics: summaries render only Core-provided fields', () => {
  const page = read(PAGE_MSP);
  assert.doesNotMatch(page, /score|grade|benchmark/i);
  assert.match(page, /sectionStateLabel\(a\.state\)/);
  assert.match(page, /sectionStateLabel\(f\.state\)/);
});

// ---------------------------------------------------------------------------
// Relationship lists follow next_offset; history pages reach the oldest event
// ---------------------------------------------------------------------------

function pager(pages) {
  const calls = [];
  const fetchPage = async (offset) => {
    calls.push(offset);
    const p = pages[offset];
    return p ? { ok: true, data: { tenant_id: 't', ...p } } : { ok: false, error: 'HTTP 500', status: 500 };
  };
  return { calls, fetchPage };
}

test('collectAllPages follows next_offset to the last page', async () => {
  const { calls, fetchPage } = pager({
    0: { items: [1, 2], next_offset: 2, total: 5 },
    2: { items: [3, 4], next_offset: 4, total: 5 },
    4: { items: [5], next_offset: null, total: 5 },
  });
  const res = await msp.collectAllPages(fetchPage);
  assert.equal(res.ok, true);
  assert.deepEqual(res.data.items, [1, 2, 3, 4, 5]);
  assert.equal(res.data.next_offset, null);
  assert.equal(res.data.tenant_id, 't');
  assert.deepEqual(calls, [0, 2, 4]);
});

test('collectAllPages fails closed instead of returning a partial list', async () => {
  const failing = pager({ 0: { items: [1], next_offset: 1 } });
  const failed = await msp.collectAllPages(failing.fetchPage);
  assert.equal(failed.ok, false);
  assert.equal(failed.status, 500);

  const stuck = pager({ 0: { items: [1], next_offset: 0 } });
  const res = await msp.collectAllPages(stuck.fetchPage);
  assert.equal(res.ok, false);
  assert.equal(res.code, 'MSP_RELATIONSHIPS_INCOMPLETE');

  const endless = { fetchPage: async (o) => ({ ok: true, data: { items: [o], next_offset: o + 1 } }) };
  const capped = await msp.collectAllPages(endless.fetchPage, 3);
  assert.equal(capped.ok, false);
  assert.equal(capped.code, 'MSP_RELATIONSHIPS_INCOMPLETE');
  assert.match(msp.safeErrorMessage(capped), /more relationships than this page can show/);
});

test('both pages load every relationship page and history exposes older events', () => {
  const api = read(API);
  assert.match(api, /export function listAllRelationships\(\)/);
  assert.match(api, /collectAllPages\(\(offset\) => listRelationships\(200, offset\)\)/);
  for (const pagePath of [PAGE_MSP, PAGE_PARTNERS]) {
    const src = read(pagePath);
    assert.match(src, /await listAllRelationships\(\)|listAllRelationships\(\)\]/, pagePath);
    assert.doesNotMatch(src, /listRelationships\(/, pagePath);
  }
  assert.match(read(PAGE_MSP), /setLoadError\(r\.ok \? '' : safeErrorMessage\(r\)\)/);
  const history = read(HISTORY);
  assert.match(history, /getRelationshipHistory\(relationshipId, history\.next_offset\)/);
  assert.match(history, /Show older events/);
  assert.match(history, /seen\.has\(ev\.event_hash\)/);
});
