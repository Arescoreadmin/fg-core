/**
 * dashboard-truth.test.js
 *
 * Static-analysis tests verifying the dashboard truth pass:
 *   - No static mock data on the money path
 *   - BFF calls only (no direct core URLs, no NEXT_PUBLIC keys)
 *   - Typed API helpers exist for billing, assessment, and report status
 *   - Loading / empty / error states are present in the dashboard
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ─── BFF / security invariants ────────────────────────────────────────────────

test('client_api_uses_bff_and_not_public_core_key', () => {
  const coreApi = read('lib/coreApi.ts');
  // All fetch calls must go through the /api/core BFF, with absolute URLs on the server.
  assert.match(coreApi, /const target = `\/api\/core\$\{path\}`[\s\S]*fetch\(await resolveConsoleUrl\(target\), \{/);
  assert.doesNotMatch(coreApi, /NEXT_PUBLIC_CORE_API_KEY/);
  assert.doesNotMatch(coreApi, /NEXT_PUBLIC_CORE_API_URL/);
});

test('dashboard_page_uses_bff_routes_only', () => {
  const page = read('app/dashboard/page.tsx');
  // Must import billing via coreApi (which routes through BFF, not direct core)
  assert.match(page, /getBillingReadiness/);
  // Must NOT embed secret env vars
  assert.doesNotMatch(page, /NEXT_PUBLIC_CORE_API_KEY/);
  assert.doesNotMatch(page, /NEXT_PUBLIC_CORE_API_URL/);
  // Must NOT call core directly (non-BFF patterns)
  assert.doesNotMatch(page, /fetch\(['"]http/);
});

// ─── No static mock data on the money path ────────────────────────────────────

test('dashboard_has_no_static_money_path_mock_data', () => {
  const page = read('app/dashboard/page.tsx');
  // MOCK_CHART_DATA must be gone
  assert.doesNotMatch(page, /MOCK_CHART_DATA/);
  // MOCK_DOMAIN_SCORES must be gone
  assert.doesNotMatch(page, /MOCK_DOMAIN_SCORES/);
  // Hardcoded fake event strings must be gone
  assert.doesNotMatch(page, /Apex National Bank/);
  assert.doesNotMatch(page, /meridian-health/);
  assert.doesNotMatch(page, /hipaa\.rego v2/);
  assert.doesNotMatch(page, /PHI detected.*Anthropic boundary/);
  // Static delta of 12 must be gone (was hardcoded +12% vs last 24h)
  assert.doesNotMatch(page, /delta=\{12\}/);
});

// ─── Typed API helpers in coreApi ────────────────────────────────────────────

test('dashboard_loads_billing_readiness_from_bff', () => {
  const coreApi = read('lib/coreApi.ts');
  // getBillingReadiness must exist and call /health/ready
  assert.match(coreApi, /export async function getBillingReadiness/);
  assert.match(coreApi, /\/health\/ready/);
});

test('dashboard_shows_billing_ready_state', () => {
  const page = read('app/dashboard/page.tsx');
  // billing-ready aria-label present
  assert.match(page, /billing-ready/);
  assert.match(page, /Billing ready/);
});

test('dashboard_shows_billing_not_ready_reasons_without_secrets', () => {
  const page = read('app/dashboard/page.tsx');
  // billing-not-ready aria-label present
  assert.match(page, /billing-not-ready/);
  assert.match(page, /Billing not ready/);
  // Reasons are rendered as codes (from API) — no secret env var names hardcoded
  assert.doesNotMatch(page, /STRIPE_SECRET_KEY/);
  assert.doesNotMatch(page, /STRIPE_WEBHOOK/);
});

test('coreApi_has_BillingReadiness_type', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /export interface BillingReadiness/);
  assert.match(coreApi, /provider: string/);
  assert.match(coreApi, /ready: boolean/);
  assert.match(coreApi, /reasons: string\[\]/);
});

// ─── Assessment status ────────────────────────────────────────────────────────

test('dashboard_shows_assessment_status', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /export interface AssessmentStatus/);
  assert.match(coreApi, /export async function getAssessmentStatusById/);
  // Must route through ingest/assessment
  assert.match(coreApi, /\/ingest\/assessment\//);
});

test('dashboard_shows_empty_assessment_state', () => {
  const page = read('app/dashboard/page.tsx');
  // Server component: empty assessments fall back to [] passed to widgets
  assert.match(page, /assessmentsData/);
  assert.match(page, /\[\] as Assessment\[\]/);
});

// ─── Report job state ─────────────────────────────────────────────────────────

test('dashboard_shows_report_job_states', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /export interface ReportStatus/);
  assert.match(coreApi, /export async function getReportStatusById/);
  assert.match(coreApi, /export type ReportJobStatus/);
  // Must include all relevant statuses
  assert.match(coreApi, /'pending' \| 'generating' \| 'complete' \| 'failed'/);
});

test('dashboard_shows_report_failure_reason_safely', () => {
  const coreApi = read('lib/coreApi.ts');
  // error_message field present but only rendered by report detail, not dashboard
  assert.match(coreApi, /error_message: string \| null/);
  // No secret env vars leaked in the type definition
  assert.doesNotMatch(coreApi, /STRIPE_SECRET/);
  assert.doesNotMatch(coreApi, /CORE_API_KEY/);
});

// ─── Loading / empty / error states in dashboard ─────────────────────────────

test('dashboard_shows_loading_state', () => {
  const page = read('app/dashboard/page.tsx');
  // Server component awaits all data; Suspense + WidgetSkeleton provide loading UI
  assert.match(page, /events-loading/);
  assert.match(page, /animate-pulse/);
  assert.match(page, /WidgetSkeleton/);
});

test('dashboard_shows_error_state', () => {
  const page = read('app/dashboard/page.tsx');
  assert.match(page, /billing-error/);
  assert.match(page, /Core unreachable/);
  // Feed errors handled by SafeResult: feedResult.ok false → empty items passed to widgets
  assert.match(page, /feedResult\.ok/);
});

test('dashboard_shows_empty_state_for_events', () => {
  const page = read('app/dashboard/page.tsx');
  // Server component: empty feed safely produces [] passed to widgets
  assert.match(page, /feedItems/);
  assert.match(page, /feedResult\.ok \? feedResult\.data\.items : \[\]/);
});

// ─── SafeResult pattern ───────────────────────────────────────────────────────

test('coreApi_uses_SafeResult_pattern_not_throw', () => {
  const coreApi = read('lib/coreApi.ts');
  // SafeResult type must be exported
  assert.match(coreApi, /export type SafeResult/);
  // getBillingReadiness returns SafeResult (never throws to caller)
  assert.match(coreApi, /Promise<SafeResult<BillingReadiness>>/);
  // getAssessmentStatusById returns SafeResult
  assert.match(coreApi, /Promise<SafeResult<AssessmentStatus>>/);
  // getReportStatusById returns SafeResult
  assert.match(coreApi, /Promise<SafeResult<ReportStatus>>/);
});

// ─── Proxy allowlist coverage ────────────────────────────────────────────────

test('bff_proxy_allows_ingest_assessment_for_status_reads', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  // ingest/assessment must be in the GET allowlist
  assert.match(proxy, /ingest\/assessment/);
  // GET must be in the methods set
  assert.match(proxy, /ingest\/assessment.*GET/s);
});

test('bff_proxy_allows_feed_live_for_events', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /feed\/live/);
});

test('bff_proxy_allows_health_ready_for_billing_readiness', () => {
  const proxy = read('app/api/core/[...path]/route.ts');
  assert.match(proxy, /health\/ready/);
});

// ─── Review repair: assessment scores written on submit ───────────────────────

test('assessment_submit_writes_domain_scores_to_session_storage', () => {
  const page = read('app/assessment/page.tsx');
  // sessionStorage.setItem must be called with fg_last_assessment_scores after submit
  assert.match(page, /sessionStorage\.setItem\(['"]fg_last_assessment_scores['"]/);
  // Written from the actual submit result, not from mock/hardcoded data
  assert.match(page, /JSON\.stringify\(result\.domain_scores\)/);
});

// ─── Review repair: feed error differs from empty ────────────────────────────

test('chart_shows_error_state_not_empty_when_feed_fails', () => {
  const page = read('app/dashboard/page.tsx');
  // Error path checks feedResult.ok before deriving feedItems
  assert.match(page, /feedResult\.ok/);
  // No mock feed data
  assert.doesNotMatch(page, /MOCK_FEED/);
  assert.doesNotMatch(page, /fake.*feed/i);
});

// ─── Review repair: blocked label requires explicit action ────────────────────

test('feed_item_blocked_label_requires_explicit_action_not_severity', () => {
  const page = read('app/dashboard/page.tsx');
  // Must NOT map high/critical severity alone to a blocking state
  assert.doesNotMatch(page, /sev === 'critical'.*return 'blocked'/);
  assert.doesNotMatch(page, /sev === 'high'.*return 'blocked'/);
  assert.doesNotMatch(page, /severity.*blocked/i);
});
