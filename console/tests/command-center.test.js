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
  // Must have the four main sections
  assert.match(page, /cc-operational-heading/);
  assert.match(page, /cc-governance-heading/);
  assert.match(page, /cc-metrics-heading/);
  assert.match(page, /cc-future-heading/);
  // TopBar title must be Command Center
  assert.match(page, /Command Center/);
});

test('command center includes required widgets', () => {
  const page = read('app/dashboard/page.tsx');
  // All six operational + governance widgets
  assert.match(page, /system-health-widget/);
  assert.match(page, /retrieval-health-widget/);
  assert.match(page, /audit-status-widget/);
  assert.match(page, /tenant-summary-widget/);
  assert.match(page, /provider-health-widget/);
  assert.match(page, /active-alerts-widget/);
  // Three quality metric widgets
  assert.match(page, /grounded-answer-rate-widget/);
  assert.match(page, /provenance-failures-widget/);
  assert.match(page, /readiness-summary-widget/);
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
  const page = read('app/dashboard/page.tsx');
  // SEVERITY_CONFIG must have explicit text labels for each severity
  assert.match(page, /label: 'Healthy'/);
  assert.match(page, /label: 'Warning'/);
  assert.match(page, /label: 'Critical'/);
  assert.match(page, /label: 'Unknown'/);
  // SeverityIndicator must render displayLabel (text), not just icon/color
  assert.match(page, /displayLabel/);
  // Icons must be aria-hidden (not the only indicator)
  assert.match(page, /aria-hidden="true"/);
});

// ─── Unavailable metric states ────────────────────────────────────────────────

test('command center renders safe unavailable metric states', () => {
  const page = read('app/dashboard/page.tsx');
  // UnavailableMetricWidget must use metric-not-configured label
  assert.match(page, /metric-not-configured/);
  // Must say "Not yet measured" — not a fake number
  assert.match(page, /Not yet measured/);
  // Grounded answer rate must have a reason string, not a fake percentage
  assert.match(page, /Grounded Answer Rate/);
  assert.match(page, /No metric source configured/);
  // No fake percentages for quality metrics
  assert.doesNotMatch(page, /groundedAnswerRate\s*=\s*[0-9]/);
  assert.doesNotMatch(page, /grounded.*97%/i);
  assert.doesNotMatch(page, /grounded.*98%/i);
});

// ─── API failure safety ───────────────────────────────────────────────────────

test('command center handles api failure safely', () => {
  const page = read('app/dashboard/page.tsx');
  // ctResult failure path must exist for each widget
  assert.match(page, /retrieval-health-unavailable/);
  assert.match(page, /audit-status-unavailable/);
  assert.match(page, /tenant-context-unavailable/);
  assert.match(page, /provider-health-unavailable/);
  assert.match(page, /active-alerts-unavailable/);
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
  // Loading aria-labels must exist for all six widgets
  assert.match(page, /system-health-loading/);
  assert.match(page, /retrieval-health-loading/);
  assert.match(page, /audit-status-loading/);
  assert.match(page, /tenant-summary-loading/);
  assert.match(page, /provider-health-loading/);
  assert.match(page, /active-alerts-loading/);
  // ctLoading initial state must be true (renders loading server-side safely)
  assert.match(page, /useState<SafeResult<ControlTowerSnapshotV1> \| null>\(null\)/);
  assert.match(page, /useState\(true\)/);
  // No Math.random or Date.now at module level
  assert.doesNotMatch(page, /const.*=.*Math\.random/);
  // Date.now is only used inside event handlers / callbacks, not at module scope
  // (Static check: no top-level const assigned from Date.now)
  assert.doesNotMatch(page, /^const.*Date\.now\(\)/m);
});

// ─── Future placeholders ──────────────────────────────────────────────────────

test('future placeholders do not fake operational metrics', () => {
  const page = read('app/dashboard/page.tsx');
  // future-placeholder aria-label must exist
  assert.match(page, /future-placeholder/);
  // Future Capabilities section heading
  assert.match(page, /Future Capabilities/);
  // Required four placeholders
  assert.match(page, /SLA Health/);
  assert.match(page, /Retrieval Latency/);
  assert.match(page, /Hallucination Trends/);
  assert.match(page, /Drift Metrics/);
  // Placeholders must say "Not configured" or "Not yet measured" — not fake numbers
  assert.match(page, /Not configured/);
  assert.match(page, /Not yet measured/);
  // Placeholder cards must have dashed border (visual signal they're not live)
  assert.match(page, /border-dashed/);
  // No hardcoded latency values (e.g. "45ms") in placeholder labels
  assert.doesNotMatch(page, /FuturePlaceholderWidget.*45ms/s);
  assert.doesNotMatch(page, /FuturePlaceholderWidget.*99\.9%/s);
});

// ─── Tenant display ───────────────────────────────────────────────────────────

test('tenant summary is display only', () => {
  const page = read('app/dashboard/page.tsx');
  // Must render the tenant_id read-only
  assert.match(page, /tenant-context-display/);
  // Must include explicit "Display only" disclaimer
  assert.match(page, /Display only — no switching authority/);
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
  // Must use a cancelled flag to avoid state updates after unmount
  assert.match(page, /let cancelled = false/);
  assert.match(page, /if \(!cancelled\)/);
  // Must clear the interval on unmount
  assert.match(page, /clearInterval\(interval\)/);
  assert.match(page, /cancelled = true/);
  // Must poll at 60s cadence
  assert.match(page, /60_000/);
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
  const page = read('app/dashboard/page.tsx');
  // Must check for retrieval-related key names
  assert.match(page, /RETRIEVAL_PLANE_KEYS/);
  assert.match(page, /retrieval-health-no-plane/);
  assert.match(page, /No retrieval plane registered/);
});

// ─── severity.ts file existence ───────────────────────────────────────────────

test('severity module exists as a dedicated file', () => {
  assert.ok(exists('lib/severity.ts'), 'lib/severity.ts must exist');
});
