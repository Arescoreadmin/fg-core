/**
 * command-center.test.js
 *
 * Static-analysis tests for the PR 44 Command Center dashboard:
 *   - Operational widgets present (SystemHealth, RetrievalHealth, AuditStatus, etc.)
 *   - Severity model is deterministic and text-labelled (not color-only)
 *   - Unavailable metrics render safe placeholder states (no fake data)
 *   - API failure paths exist for control tower snapshot
 *   - Loading states are deterministic (no random IDs, no Date.now at module level)
 *   - Future placeholders do not contain operational metrics
 *   - Tenant summary is display-only (no switching authority)
 *   - No secret leakage in new files
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

function exists(relPath) {
  return fs.existsSync(path.join(__dirname, '..', relPath));
}

// ─── Dashboard structure ──────────────────────────────────────────────────────

test('command center renders operational dashboard', () => {
  const page = read('app/dashboard/page.tsx');
  // Must have MCIM section headings
  assert.match(page, /kpi-heading/);
  assert.match(page, /health-heading/);
  assert.match(page, /risk-heading/);
  assert.match(page, /actions-heading/);
  // TopBar title must be Command Center
  assert.match(page, /Command Center/);
});

test('command center includes required widgets', () => {
  const page = read('app/dashboard/page.tsx');
  // MCIM command-center widget imports
  assert.match(page, /ExecutiveKPIBar/);
  assert.match(page, /ExecutiveHealthPanel/);
  assert.match(page, /TrustCenterSummary/);
  assert.match(page, /GovernanceOverview/);
  assert.match(page, /DecisionProvenancePanel/);
  assert.match(page, /ExecutiveActionQueue/);
  assert.match(page, /FieldAssessmentStatus/);
  assert.match(page, /ReadinessSummary/);
  assert.match(page, /ComplianceSummary/);
});

// ─── Severity model ───────────────────────────────────────────────────────────

test('severity map includes chain_integrity pass and fail strings', () => {
  const severity = read('lib/severity.ts');
  // chain_integrity.status emits exactly "pass" or "fail" — both must be mapped
  assert.match(severity, /pass: 'ok'/);
  assert.match(severity, /fail: 'critical'/);
  // "failed" and "failure" must also remain (other callers)
  assert.match(severity, /failed: 'critical'/);
  assert.match(severity, /failure: 'critical'/);
});

test('severity mapping is deterministic', () => {
  const severity = read('lib/severity.ts');
  // Type must enumerate all five values
  assert.match(severity, /export type Severity = 'ok' \| 'info' \| 'warning' \| 'critical' \| 'unknown'/);
  // mapToSeverity must be exported
  assert.match(severity, /export function mapToSeverity/);
  // Must handle null/undefined safely
  assert.match(severity, /if \(!status\) return 'unknown'/);
  // No Math.random — must be deterministic
  assert.doesNotMatch(severity, /Math\.random/);
});

test('severity config provides text labels not only colors', () => {
  const panel = read('components/command-center/ExecutiveHealthPanel.tsx');
  // STATE_CONFIG must have explicit text labels for each health state
  assert.match(panel, /label: 'Healthy'/);
  assert.match(panel, /label: 'Needs Attention'/);
  assert.match(panel, /label: 'Critical'/);
  assert.match(panel, /label: 'Blocked'/);
  // Must use aria-label for accessibility
  assert.match(panel, /aria-label/);
  // Icons must be aria-hidden (not the only indicator)
  assert.match(panel, /aria-hidden="true"/);
});

// ─── Unavailable metric states ────────────────────────────────────────────────

test('command center renders safe unavailable metric states', () => {
  const kpi = read('components/command-center/ExecutiveKPIBar.tsx');
  // KPI tiles must display '—' when value is null — no fake numbers
  assert.match(kpi, /displayValue !== null \? displayValue : '—'/);
  // No fake percentages hardcoded into tiles
  assert.doesNotMatch(kpi, /groundedAnswerRate\s*=\s*[0-9]/);
  assert.doesNotMatch(kpi, /grounded.*97%/i);
  assert.doesNotMatch(kpi, /grounded.*98%/i);
});

// ─── API failure safety ───────────────────────────────────────────────────────

test('command center handles api failure safely', () => {
  const page = read('app/dashboard/page.tsx');
  // All 7 data sources wrapped in Promise.allSettled — individual failures safe
  assert.match(page, /Promise\.allSettled/);
  // Snapshot failure handled via SafeResult
  assert.match(page, /snapshotResult\.ok/);
  // Null snapshot passed safely to widgets
  assert.match(page, /ControlTowerSnapshotV1 \| null/);
  // getCommandCenterSnapshot must use SafeResult (not throw)
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /export async function getCommandCenterSnapshot/);
  assert.match(coreApi, /Promise<SafeResult<ControlTowerSnapshotV1>>/);
});

test('control tower snapshot uses SafeResult not throw', () => {
  const coreApi = read('lib/coreApi.ts');
  // getCommandCenterSnapshot wraps in try/catch
  assert.match(coreApi, /getCommandCenterSnapshot/);
  assert.match(coreApi, /\{ ok: true, data: result\.data \}/);
  assert.match(coreApi, /ok: false.*fetch_error/s);
});

// ─── Loading states ───────────────────────────────────────────────────────────

test('command center renders deterministic loading state', () => {
  const page = read('app/dashboard/page.tsx');
  // Server component: Suspense + WidgetSkeleton for loading (no client polling)
  assert.match(page, /WidgetSkeleton/);
  assert.match(page, /animate-pulse/);
  assert.match(page, /Suspense/);
  // No client-side polling state
  assert.doesNotMatch(page, /useState\(true\)/);
  // No Math.random or module-level Date.now
  assert.doesNotMatch(page, /const.*=.*Math\.random/);
  assert.doesNotMatch(page, /^const.*Date\.now\(\)/m);
});

// ─── Future placeholders ──────────────────────────────────────────────────────

test('future placeholders do not fake operational metrics', () => {
  const page = read('app/dashboard/page.tsx');
  // Unimplemented metrics must be null, not fake values
  assert.match(page, /criticalFindingsCount: null/);
  assert.match(page, /openGaps: null/);
  assert.match(page, /projectedCompletion: null/);
  // No hardcoded fake metric numbers
  assert.doesNotMatch(page, /criticalFindingsCount:\s*[0-9]/);
  assert.doesNotMatch(page, /openGaps:\s*[0-9]/);
});

// ─── Tenant display ───────────────────────────────────────────────────────────

test('tenant summary is display only', () => {
  const page = read('app/dashboard/page.tsx');
  // Must render tenant_id from snapshot read-only
  assert.match(page, /tenant_id/);
  // Must NOT have a tenant switcher or form element
  assert.doesNotMatch(page, /<select.*tenant/i);
  assert.doesNotMatch(page, /switchTenant/);
  assert.doesNotMatch(page, /onTenantChange/);
});

// ─── No secrets ───────────────────────────────────────────────────────────────

test('dashboard does not expose browser secrets', () => {
  const page = read('app/dashboard/page.tsx');
  assert.doesNotMatch(page, /NEXT_PUBLIC_CORE_API_KEY/);
  assert.doesNotMatch(page, /NEXT_PUBLIC_CORE_API_URL/);
  assert.doesNotMatch(page, /STRIPE_SECRET/);
  assert.doesNotMatch(page, /process\.env\.CORE_API_KEY/);

  const severity = read('lib/severity.ts');
  assert.doesNotMatch(severity, /process\.env\./);
  assert.doesNotMatch(severity, /NEXT_PUBLIC/);
});

// ─── Polling cleanup ──────────────────────────────────────────────────────────

test('control tower polling has cancellation guard and cleanup', () => {
  const page = read('app/dashboard/page.tsx');
  // New: server component awaits all data upfront — no client polling needed
  assert.match(page, /async function DashboardOverviewPage/);
  assert.match(page, /await Promise\.allSettled/);
  // Must NOT have unguarded polling patterns
  assert.doesNotMatch(page, /setInterval.*60_000(?![\s\S]*clearInterval)/s);
});

// ─── ControlTowerSnapshotV1 type ──────────────────────────────────────────────

test('coreApi exports ControlTowerSnapshotV1 with required fields', () => {
  const coreApi = read('lib/coreApi.ts');
  assert.match(coreApi, /export interface ControlTowerSnapshotV1/);
  assert.match(coreApi, /planes: Record<string, string>/);
  assert.match(coreApi, /chain_integrity/);
  assert.match(coreApi, /connectors/);
  assert.match(coreApi, /audit_incidents/);
  assert.match(coreApi, /tenant/);
});

// ─── Retrieval plane fallback ─────────────────────────────────────────────────

test('retrieval health widget handles missing plane gracefully', () => {
  const panel = read('components/command-center/ExecutiveHealthPanel.tsx');
  // Must handle null snapshot with blocked state
  assert.match(panel, /if \(!snapshot\)/);
  assert.match(panel, /health-blocked/);
  assert.match(panel, /Control tower snapshot unavailable/);
});

// ─── severity.ts file existence ───────────────────────────────────────────────

test('severity module exists as a dedicated file', () => {
  assert.ok(exists('lib/severity.ts'), 'lib/severity.ts must exist');
});
