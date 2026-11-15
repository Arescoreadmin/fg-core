'use strict';

/**
 * MSP-003 — partner-guided onboarding and assessment requests in the console.
 *
 * Behavioural tests of the pure helpers (lib/mspOrchestration.js) and
 * source-contract tests of the BFF rules, API client, components and pages
 * (the repo has no React rendering harness). Authorization is Core's; the
 * Core-side behaviour is covered by tests/security/test_msp_003_orchestration.py.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const orch = require('../lib/mspOrchestration');
const { canAccessCoreApiPath } = require('../lib/consoleAccess');

function read(rel) {
  return fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
}

const API = 'lib/mspApi.ts';
const BFF = 'app/api/core/[...path]/route.ts';
const GRANTS = 'components/msp/AssessmentGrants.tsx';
const ONBOARDING = 'components/msp/OnboardingRequests.tsx';
const PAGE_MSP = 'app/msp/page.tsx';
const PAGE_PARTNERS = 'app/partners/page.tsx';

const tenantAdmin = { user: { roles: ['tenant_admin'], tenant_id: 'msp-a' } };
const readOnly = { user: { roles: ['client_read_only'], tenant_id: 'cust-1' } };
const NOW = Date.parse('2026-11-15T12:00:00Z');

// ── Drift with Core ───────────────────────────────────────────────────────────

test('assessment types mirror services/field_assessment/models.py AssessmentType', () => {
  const py = fs.readFileSync(path.join(__dirname, '../../../services/field_assessment/models.py'), 'utf8');
  const block = py.match(/class AssessmentType\(str, Enum\):([\s\S]*?)\n\n/);
  assert.ok(block, 'AssessmentType not found');
  const values = Array.from(block[1].matchAll(/=\s*"([a-z0-9_]+)"/g)).map((m) => m[1]).sort();
  assert.deepEqual(orch.ASSESSMENT_TYPES.map((t) => t.id).sort(), values);
});

test('grant limits mirror api/msp_orchestration.py', () => {
  const py = fs.readFileSync(path.join(__dirname, '../../../api/msp_orchestration.py'), 'utf8');
  assert.equal(Number(py.match(/^MAX_GRANT_DAYS = (\d+)$/m)[1]), orch.MAX_GRANT_DAYS);
  assert.match(py, /GRANT_CAPABILITIES: frozenset\[str\] = frozenset\(\{"assessment\.create"\}\)/);
});

// ── Actions are presentation only and follow Core's lifecycle ─────────────────

test('customer may approve or decline a pending request, and revoke an approved or started one', () => {
  assert.deepEqual(orch.grantActions({ party: 'customer', status: 'requested', effective_status: 'requested' }), ['approve', 'reject']);
  assert.deepEqual(orch.grantActions({ party: 'customer', status: 'approved', effective_status: 'approved' }), ['revoke']);
  assert.deepEqual(orch.grantActions({ party: 'customer', status: 'initiated', effective_status: 'initiated' }), ['revoke']);
  for (const s of ['rejected', 'withdrawn', 'revoked', 'expired']) {
    assert.deepEqual(orch.grantActions({ party: 'customer', status: s, effective_status: s }), [], s);
  }
});

test('MSP never gets approve; it may withdraw pending and start only an unblocked approval', () => {
  assert.deepEqual(orch.grantActions({ party: 'msp', status: 'requested', effective_status: 'requested', blockers: ['CUSTOMER_APPROVAL_PENDING'] }), ['withdraw']);
  assert.deepEqual(orch.grantActions({ party: 'msp', status: 'approved', effective_status: 'approved', blockers: [] }), ['initiate']);
  assert.deepEqual(orch.grantActions({ party: 'msp', status: 'approved', effective_status: 'approved', blockers: ['NOT_ENTITLED'] }), []);
  assert.deepEqual(orch.grantActions({ party: 'msp', status: 'approved', effective_status: 'expired', blockers: ['GRANT_EXPIRED'] }), []);
  assert.deepEqual(orch.grantActions({ party: 'msp', status: 'initiated', effective_status: 'initiated', blockers: [] }), []);
  for (const g of [{ party: 'msp', status: 'requested' }, { party: 'msp', status: 'approved', blockers: [] }]) {
    assert.ok(!orch.grantActions(g).includes('approve'));
  }
  assert.deepEqual(orch.grantActions({ status: 'approved', blockers: [] }), []); // unknown party: nothing
});

test('every Core blocker has a clear, non-identifying explanation', () => {
  const py = fs.readFileSync(path.join(__dirname, '../../../api/msp_orchestration.py'), 'utf8');
  const block = py.match(/BLOCKER_ERRORS: dict\[str, tuple\[int, str\]\] = \{([\s\S]*?)\n\}/);
  const codes = Array.from(block[1].matchAll(/"([A-Z_]+)": \(/g)).map((m) => m[1]);
  assert.ok(codes.length >= 9);
  for (const code of codes) {
    const label = orch.blockerLabel(code);
    assert.notEqual(label, 'Not available right now.', code);
    assert.doesNotMatch(label, /tenant|cust-|msp-/i, code);
  }
  assert.equal(orch.blockerLabel('SOMETHING_NEW'), 'Not available right now.');
});

test('progress shows only Core-provided status, and says why it is hidden', () => {
  assert.equal(orch.progressLabel({ state: 'available', engagement_status: 'in_progress' }), 'in progress');
  assert.match(orch.progressLabel({ state: 'not_authorized' }), /not delegated|revoked/);
  assert.equal(orch.progressLabel({ state: 'not_started' }), 'Not started');
  assert.equal(orch.progressLabel(null), '—');
});

// ── Form validation (Core validates again) ────────────────────────────────────

test('assessment requests are bounded and carry no caller tenant', () => {
  const ok = orch.buildGrantRequestBody({
    customerTenantId: 'cust-1',
    assessmentType: 'soc2',
    assessorId: 'assessor-1',
    days: 30,
    requestKey: 'grant-1',
    now: NOW,
  });
  assert.equal(ok.ok, true);
  assert.deepEqual(Object.keys(ok.body).sort(), ['assessment_type', 'assessor_id', 'customer_tenant_id', 'expires_at', 'request_key']);
  assert.equal(ok.body.expires_at, new Date(NOW + 30 * 86400000).toISOString());
  const bad = [
    { days: 91 },
    { days: 0 },
    { days: 1.5 },
    { assessmentType: 'pentest' },
    { assessorId: 'has space' },
    { customerTenantId: '../x' },
    { requestKey: '' },
  ];
  for (const override of bad) {
    const res = orch.buildGrantRequestBody({
      customerTenantId: 'cust-1',
      assessmentType: 'soc2',
      assessorId: 'a',
      days: 10,
      requestKey: 'k',
      now: NOW,
      ...override,
    });
    assert.equal(res.ok, false, JSON.stringify(override));
  }
});

test('onboarding referrals validate name, email and capabilities', () => {
  const ok = orch.buildOnboardingBody({
    organizationName: ' Prospect Co ',
    contactEmail: 'IT@Prospect.example',
    selected: ['finding.read', 'assessment.read', 'finding.read'],
    requestKey: 'onb-1',
  });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.body, {
    request_key: 'onb-1',
    organization_name: 'Prospect Co',
    contact_email: 'it@prospect.example',
    requested_capabilities: ['assessment.read', 'finding.read'],
  });
  assert.equal(orch.buildOnboardingBody({ organizationName: '', contactEmail: 'a@b.co', selected: ['x'], requestKey: 'k' }).ok, false);
  assert.equal(orch.buildOnboardingBody({ organizationName: 'A', contactEmail: 'nope', selected: ['x'], requestKey: 'k' }).ok, false);
  assert.equal(orch.buildOnboardingBody({ organizationName: 'A', contactEmail: 'a@b.co', selected: [], requestKey: 'k' }).ok, false);
});

test('request keys are fresh per form, so a replay is the only duplicate', () => {
  const a = orch.newRequestKey('grant');
  const b = orch.newRequestKey('grant');
  assert.notEqual(a, b);
  assert.match(a, /^[A-Za-z0-9._:-]{1,128}$/);
});

test('errors never echo server text', () => {
  const msg = orch.safeOrchestrationError({ ok: false, status: 404, code: 'MSP_ASSESSMENT_GRANT_NOT_FOUND', error: 'cust-2 secret' });
  assert.doesNotMatch(msg, /cust-2|secret/);
  assert.match(orch.safeOrchestrationError({ ok: false, status: 401 }), /session has expired/);
  assert.match(orch.safeOrchestrationError({ ok: false, status: 403 }), /permission/);
  assert.equal(orch.safeOrchestrationError({ ok: true }), '');
});

// ── BFF and client transport ──────────────────────────────────────────────────

test('BFF proxies MSP-003 routes as GET/POST only and never the platform review routes', () => {
  const src = read(BFF);
  assert.match(src, /\{ prefix: 'admin\/msp\/assessments', methods: new Set\(\['GET', 'POST'\]\) \}/);
  assert.match(src, /\{ prefix: 'admin\/msp\/onboarding', methods: new Set\(\['GET', 'POST'\]\) \}/);
  assert.doesNotMatch(src, /prefix: 'admin\/msp\/platform/);
  const fn = src.slice(src.indexOf('function isTenantAdminCorePath'), src.indexOf('function isFieldAssessmentMutationPath'));
  assert.match(fn, /admin\/msp\/assessments\//);
  assert.match(fn, /admin\/msp\/onboarding\//);
});

test('only tenant administrators reach the MSP-003 routes through the console', () => {
  assert.equal(canAccessCoreApiPath('admin/msp/assessments/grants', 'GET', tenantAdmin), true);
  assert.equal(canAccessCoreApiPath('admin/msp/assessments/grants/g1/approve', 'POST', tenantAdmin), true);
  assert.equal(canAccessCoreApiPath('admin/msp/assessments/grants/g1/approve', 'POST', readOnly), false);
  assert.equal(canAccessCoreApiPath('admin/msp/onboarding/requests', 'POST', readOnly), false);
});

test('the client never sends a caller tenant, an engagement id or a status', () => {
  const src = read(API);
  // Request-building code only (response interfaces legitimately name engagement_id).
  const mspThree = src.slice(src.indexOf('export function listAssessmentGrants'));
  assert.doesNotMatch(mspThree, /X-Tenant-I[dD]/);
  // Bodies never carry an engagement id, a status or a client name.
  assert.doesNotMatch(mspThree, /JSON\.stringify\(\{[^}]*(engagement_id|new_status|client_name)/);
  assert.doesNotMatch(mspThree, /body\.(engagement_id|new_status|client_name|status)\s*=/);
  assert.match(mspThree, /initiate`, \{\s*method: 'POST',\s*body: JSON\.stringify\(\{\}\)/);
  assert.match(mspThree, /expected_version: expectedVersion/);
});

// ── Components and pages ──────────────────────────────────────────────────────

test('direct customers see no MSP assessment controls', () => {
  const src = read(GRANTS);
  assert.match(src, /if \(party === 'customer' && grants !== null && grants\.length === 0 && !error\) return null;/);
  assert.match(read(PAGE_PARTNERS), /<AssessmentGrants party="customer"/);
});

test('switching customers remounts the grant list, so nothing carries over', () => {
  const page = read(PAGE_MSP);
  assert.match(page, /<AssessmentGrants\s+key=\{selected\.item\.customer_tenant_id\}\s+party="msp"\s+customerTenantId=\{selected\.item\.customer_tenant_id\}/);
  const src = read(GRANTS);
  // Every action reloads Core's view; no stale row authorizes anything.
  assert.ok((src.match(/await load\(\);/g) || []).length >= 4);
});

test('decisions go through confirmation and are guarded against double submission', () => {
  const src = read(GRANTS);
  assert.match(src, /if \(!pending \|\| busy\) return;/);
  assert.match(src, /if \(busy\) return;/);
  assert.match(src, /<ConfirmDialog/);
  for (const a of ['approve', 'reject', 'revoke', 'withdraw']) assert.match(src, new RegExp(`${a}: \\{`));
  assert.match(read(ONBOARDING), /if \(busy\) return;/);
});

test('copy is truthful: approval never covers QA, delivery or billing', () => {
  const src = read(GRANTS);
  assert.match(src, /never lets the MSP approve QA, deliver reports/);
  assert.match(src, /not billed until it is delivered/);
  assert.match(src, /not cancelled; it remains yours/);
  assert.doesNotMatch(read(PAGE_PARTNERS), /MSPs never get write access/);
  assert.match(read(ONBOARDING), /No account or access is created/);
});

test('no client-side storage, HTML injection or raw server errors', () => {
  for (const file of [GRANTS, ONBOARDING, 'lib/mspOrchestration.js']) {
    const src = read(file);
    assert.doesNotMatch(src, /localStorage|sessionStorage|document\.cookie/, file);
    assert.doesNotMatch(src, /dangerouslySetInnerHTML/, file);
    assert.doesNotMatch(src, /\.error\}/, `${file} renders a raw error`);
  }
});

test('the MSP page shows onboarding only for an active MSP', () => {
  assert.match(read(PAGE_MSP), /\{!notConfigured \? <OnboardingRequests/);
});
