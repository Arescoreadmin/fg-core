'use strict';

/**
 * MSP-007 — customer-controlled report sharing in the console.
 *
 * Behavioural tests of the pure helpers (lib/mspReporting.js) and
 * source-contract tests of the BFF rules, API client, components and pages
 * (the repo has no React rendering harness). Authorization is Core's; the
 * Core-side behaviour is covered by tests/security/test_msp_007_report_sharing.py.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const rep = require('../lib/mspReporting');
const { canAccessCoreApiPath } = require('../lib/consoleAccess');

function read(rel) {
  return fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
}

const API = 'lib/mspApi.ts';
const BFF = 'app/api/core/[...path]/route.ts';
const SHARED = 'components/msp/SharedReports.tsx';
const SHARING = 'components/msp/ReportSharing.tsx';
const HISTORY = 'components/msp/ShareHistory.tsx';
const PAGE_MSP = 'app/msp/page.tsx';
const PAGE_PARTNERS = 'app/partners/page.tsx';
const CORE = path.join(__dirname, '../../../api/msp_reporting.py');

const tenantAdmin = { user: { roles: ['tenant_admin'], tenant_id: 'cust-1' } };
const readOnly = { user: { roles: ['client_read_only'], tenant_id: 'cust-1' } };
const NOW = Date.parse('2026-11-16T12:00:00Z');
const HASH = 'a'.repeat(64);
const released = { report_id: 'r-1', manifest_hash: HASH, share_eligible: true };

// ── Drift with Core ───────────────────────────────────────────────────────────

test('share window mirrors api/msp_reporting.py', () => {
  const py = fs.readFileSync(CORE, 'utf8');
  assert.equal(Number(py.match(/^MAX_SHARE_DAYS = (\d+)$/m)[1]), rep.MAX_SHARE_DAYS);
  assert.match(py, /^SHARE_READ_CAPABILITY = "report\.read"$/m);
});

test('every blocker Core can return has a plain explanation', () => {
  const py = fs.readFileSync(CORE, 'utf8');
  const codes = new Set();
  for (const m of py.matchAll(/MspShareAccess\(membership, \["([A-Z_]+)"\]/g)) codes.add(m[1]);
  for (const m of py.matchAll(/blockers\.append\("([A-Z_]+)"\)/g)) codes.add(m[1]);
  for (const m of py.matchAll(/blockers=\["([A-Z_]+)"\]/g)) codes.add(m[1]);
  for (const m of py.matchAll(/^    "[a-z]+": "([A-Z_]+)",$/gm)) codes.add(m[1]); // _STATUS_BLOCKERS
  assert.ok(codes.size >= 15, `found ${codes.size}`);
  for (const code of codes) assert.notEqual(rep.blockerLabel(code), 'Not available right now.', code);
});

test('the integrity vocabulary is exactly what Core can report; a hash is never a signature', () => {
  const py = fs.readFileSync(CORE, 'utf8');
  for (const v of ['HASH_VERIFIED', 'SIGNATURE_VERIFIED', 'AUDIT_CHAIN_VERIFIED', 'VERIFICATION_UNAVAILABLE', 'VERIFICATION_FAILED']) {
    assert.match(py, new RegExp(`^${v} = "${v}"$`, 'm'));
    assert.ok(rep.integrityView(v).label);
  }
  assert.doesNotMatch(rep.integrityView('HASH_VERIFIED').label, /signature|signed|certif/i);
  assert.equal(rep.integrityView('something-else').label, 'Not available');
  const all = JSON.stringify([rep.integrityView('HASH_VERIFIED'), rep.integrityView('SIGNATURE_VERIFIED')]);
  assert.doesNotMatch(all, /notar|certified|third.party/i);
});

// ── Actions are presentation only and follow Core's lifecycle ─────────────────

test('the customer decides; the MSP never gets approve', () => {
  assert.deepEqual(rep.shareActions({ party: 'customer', status: 'requested' }), ['approve', 'reject']);
  assert.deepEqual(rep.shareActions({ party: 'customer', status: 'active' }), ['revoke']);
  for (const s of ['rejected', 'withdrawn', 'revoked', 'expired']) {
    assert.deepEqual(rep.shareActions({ party: 'customer', status: s }), [], s);
  }
  assert.deepEqual(rep.shareActions({ party: 'msp', status: 'requested' }), ['withdraw']);
  assert.deepEqual(rep.shareActions({ party: 'msp', status: 'active', access: { state: 'available', blockers: [] } }), [
    'verify',
    'download',
  ]);
  assert.deepEqual(
    rep.shareActions({ party: 'msp', status: 'active', access: { state: 'blocked', blockers: ['REPORT_NOT_RELEASED'] } }),
    [],
  );
  for (const status of ['requested', 'active', 'expired']) {
    assert.ok(!rep.shareActions({ party: 'msp', status, access: { state: 'available', blockers: [] } }).includes('approve'));
  }
  assert.deepEqual(rep.shareActions({ status: 'active' }), []);
});

test('shares group by what Core says, never by a browser-side guess', () => {
  const groups = rep.groupShares([
    { party: 'msp', status: 'active', access: { state: 'available', blockers: [] } },
    { party: 'msp', status: 'active', access: { state: 'blocked', blockers: ['SHARE_EXPIRED'] } },
    { party: 'msp', status: 'active' },
    { party: 'msp', status: 'requested' },
    { party: 'msp', status: 'revoked' },
    { party: 'msp', status: 'expired' },
  ]);
  const counts = Object.fromEntries(groups.map((g) => [g.id, g.items.length]));
  assert.deepEqual(counts, { available: 1, blocked: 2, awaiting_customer: 1, ended: 2 });
});

test('lifecycle facts stay separate booleans, never one readiness flag or score', () => {
  const facts = rep.lifecycleFacts({ exists: true, qa_approved: true, released: false, score: 99 });
  assert.deepEqual(
    facts.map((f) => f.id),
    ['exists', 'qa_approved', 'independent_qa', 'production_qualified', 'released', 'delivery_authorized', 'delivered'],
  );
  assert.equal(facts.find((f) => f.id === 'qa_approved').value, true);
  assert.equal(facts.find((f) => f.id === 'released').value, false);
  assert.equal(facts.find((f) => f.id === 'delivered').value, false);
  for (const src of [read('lib/mspReporting.js'), read(SHARED), read(SHARING)]) {
    assert.doesNotMatch(src, /score|percent|readiness_score|grade/i);
  }
});

// ── Form validation (Core validates again) ────────────────────────────────────

test('a share names one released, fingerprinted version and a bounded window', () => {
  const ok = rep.buildShareBody({ relationshipId: 'rel-1', report: released, days: 30, requestKey: 'k-1', now: NOW });
  assert.equal(ok.ok, true);
  assert.deepEqual(Object.keys(ok.body).sort(), ['expires_at', 'manifest_hash', 'relationship_id', 'report_id', 'request_key']);
  assert.equal(ok.body.manifest_hash, HASH);
  assert.equal(ok.body.expires_at, new Date(NOW + 30 * 86400000).toISOString());
  assert.equal(rep.buildShareBody({ relationshipId: 'rel-1', report: { ...released, share_eligible: false }, days: 30, requestKey: 'k' }).ok, false);
  assert.equal(rep.buildShareBody({ relationshipId: 'rel-1', report: { ...released, manifest_hash: 'x' }, days: 30, requestKey: 'k' }).ok, false);
  assert.equal(rep.buildShareBody({ relationshipId: 'rel-1', report: released, days: 91, requestKey: 'k' }).ok, false);
  assert.equal(rep.buildShareBody({ relationshipId: 'rel-1', report: released, days: 0, requestKey: 'k' }).ok, false);
  assert.equal(rep.buildShareBody({ relationshipId: '', report: released, days: 5, requestKey: 'k' }).ok, false);
  const body = JSON.stringify(ok.body);
  assert.doesNotMatch(body, /tenant/);
});

test('an approval answers a request with one released version only', () => {
  const ok = rep.buildApprovalBody({ report: released, days: 7, now: NOW });
  assert.equal(ok.ok, true);
  assert.deepEqual(Object.keys(ok.body).sort(), ['expires_at', 'manifest_hash', 'report_id']);
  assert.equal(rep.buildApprovalBody({ report: null, days: 7 }).ok, false);
});

test('errors are safe text: codes and blockers only, never server bodies', () => {
  assert.match(rep.safeReportingError({ ok: false, status: 409, blockers: ['SHARE_REVOKED'] }), /revoked/i);
  assert.match(rep.safeReportingError({ ok: false, status: 409, code: 'MSP_REPORT_NOT_SHAREABLE' }), /cannot be shared/);
  assert.match(rep.safeReportingError({ ok: false, status: 403, code: 'MSP_SELF_APPROVAL_DENIED' }), /partner/);
  assert.match(rep.safeReportingError({ ok: false, status: 401 }), /session/);
  assert.equal(rep.safeReportingError({ ok: true }), '');
  assert.equal(rep.shortHash('not-a-hash'), '—');
  assert.equal(rep.shortHash(HASH), `${'a'.repeat(12)}…${'a'.repeat(6)}`);
  assert.equal(rep.downloadFilename({ engagement_id: '../../etc', version: 2 }), 'report-etc-v2.json');
  assert.equal(rep.downloadFilename(null), 'report-report-v0.json');
});

// ── Transport ─────────────────────────────────────────────────────────────────

test('the BFF proxies MSP-007 paths with GET/POST only, as delegated MSP calls', () => {
  const src = read(BFF);
  assert.match(src, /\{ prefix: 'admin\/msp\/report-shares', methods: new Set\(\['GET', 'POST'\]\) \}/);
  assert.match(src, /\{ prefix: 'admin\/msp\/reports', methods: new Set\(\['GET'\]\) \}/);
  assert.match(src, /joined === 'admin\/msp\/report-shares' \|\|/);
  assert.match(src, /joined\.startsWith\('admin\/msp\/report-shares\/'\)/);
  assert.match(src, /joined\.startsWith\('admin\/msp\/reports\/'\)/);
});

test('only organization administrators reach MSP-007 paths through the console', () => {
  for (const [p, method] of [
    ['admin/msp/report-shares', 'GET'],
    ['admin/msp/report-shares', 'POST'],
    ['admin/msp/report-shares/s-1/download', 'GET'],
    ['admin/msp/report-shares/s-1/revoke', 'POST'],
    ['admin/msp/reports/shareable', 'GET'],
  ]) {
    assert.equal(canAccessCoreApiPath(p, method, tenantAdmin), true, p);
    assert.equal(canAccessCoreApiPath(p, method, readOnly), false, p);
  }
});

test('the API client never sends a caller tenant, follows every page and keeps blocker codes', () => {
  const src = read(API);
  const block = src.slice(src.indexOf('MSP-007 — customer-controlled report sharing'));
  // Request bodies carry no tenant; a customer id is only a list filter.
  for (const m of block.matchAll(/body: JSON\.stringify\(([^)]*)\)/g)) assert.doesNotMatch(m[1], /tenant/);
  for (const m of block.matchAll(/export function (shareReport|requestReportShare)\(body: \{([^}]*)\}/g)) {
    assert.doesNotMatch(m[2], /tenant/);
  }
  assert.match(block, /collectAllPages\(\(offset\) => listReportShares\(party, customerTenantId, offset\)\)/);
  assert.match(block, /collectAllPages\(\(offset\) => listShareableReports\(offset, engagementId\)\)/);
  assert.match(block, /new URLSearchParams\(\{ party \}\)/);
  assert.match(src, /\^\[A-Z_\]\{1,64\}\$/); // blockers are codes only
});

// ── Components and pages ──────────────────────────────────────────────────────

test('the MSP view is keyed by customer and never shows another customer', () => {
  const page = read(PAGE_MSP);
  assert.match(page, /<SharedReports\s+key=\{`reports-\$\{selected\.item\.customer_tenant_id\}`\}/);
  const src = read(SHARED);
  assert.match(src, /listAllReportShares\('msp', customerTenantId\)/);
  assert.match(src, /filter\(\(s\) => s\.customer_tenant_id === customerTenantId\)/);
  assert.match(src, /res\.data\.customer_tenant_id === customerTenantId/);
  // No browser-side storage of report content.
  for (const s of [src, read(SHARING), read(HISTORY)]) {
    assert.doesNotMatch(s, /localStorage|sessionStorage|indexedDB/);
  }
});

test('a failed page load never presents a partial list', () => {
  const src = read(SHARING);
  assert.match(src, /Fail closed: if any list is incomplete, show none of it as complete\./);
  assert.match(src, /setShares\(\[\]\);\s*setReports\(\[\]\);/);
  const shared = read(SHARED);
  assert.match(shared, /setShares\(\[\]\);\s*return;/);
});

test('direct customers see no partner controls', () => {
  const src = read(SHARING);
  assert.match(
    src,
    /if \(relationships !== null && relationships\.length === 0 && shares\.length === 0 && !error\) return null;/,
  );
  assert.match(src, /r\.authorized_capabilities\.includes\('report\.read'\)/);
  const page = read(PAGE_PARTNERS);
  assert.match(page, /<ReportSharing onSessionExpired=/);
});

test('sharing is confirmed against the exact version and fingerprint, and revocation limits are stated', () => {
  const src = read(SHARING);
  assert.match(src, /Only this version \(fingerprint \$\{shortHash\(pending\.report\.manifest_hash\)\}\) is shared/);
  assert.match(src, /a copy already downloaded cannot be recalled/);
  assert.match(src, /eligible\.filter\(\(r\) => r\.engagement_id === s\.engagement_id\)/);
});

test('history shows the chain verification result and refused reads', () => {
  const src = read(HISTORY);
  assert.match(src, /history\.chain_verified \? 'verified intact'/);
  assert.match(src, /ev\.decision === 'denied' \? ' — refused' : ''/);
});
