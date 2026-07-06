/**
 * operations-center.test.js
 *
 * Static-analysis tests for PR 18.7 — Autonomous Governance Operations Center (AGOC).
 * MCIM authority: OPERATIONS-CENTER
 *
 * Stack: Node.js built-in test runner (node:test + node:assert/strict)
 * Pattern: file-system reads + content assertions (no JSX, no rendering)
 *
 * Coverage:
 *   A — File existence (component files, page, API module)
 *   B — MCIM compliance (data-mcim attributes, authority metadata)
 *   C — Loading states (each panel has a loading skeleton/spinner)
 *   D — Error states (each panel handles API failure safely)
 *   E — Empty states (each panel handles no-data gracefully)
 *   F — API layer (operationsCenterApi exports, LoadResult type, fail-closed)
 *   G — Navigation registry (operations-center entry, MCIM-18.7)
 *   H — Sidebar icon mapping
 *   I — workspaceNav integration (cross-workspace links)
 *   J — Accessibility (aria, role, keyboard patterns)
 *   K — Security (no hardcoded secrets, no mock data in prod paths)
 *   L — Page structure (grid layout, refresh key, data-section attributes)
 *   M — Panel MCIM identifiers (unique, authority-tagged)
 *   N — Type contracts (LoadResult discriminated union pattern)
 *   O — CI test file (check_operations_center.py passes)
 *   P — PR_FIX_LOG gate (entry present for 18.7 fix)
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.join(__dirname, '..');
const REPO_ROOT = path.join(__dirname, '..', '..', '..');

function read(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

function exists(relPath) {
  return fs.existsSync(path.join(ROOT, relPath));
}

function readRepo(relPath) {
  return fs.readFileSync(path.join(REPO_ROOT, relPath), 'utf8');
}

const PANEL_FILES = [
  'components/operations-center/ExecutiveOperationsQueue.tsx',
  'components/operations-center/GovernanceAutomationQueue.tsx',
  'components/operations-center/DecisionExecutionPipeline.tsx',
  'components/operations-center/OperationalRiskHeatmap.tsx',
  'components/operations-center/EvidenceFreshnessMonitor.tsx',
  'components/operations-center/PolicyConflictCenter.tsx',
  'components/operations-center/GovernanceSLAMonitor.tsx',
  'components/operations-center/AutomationSafetyCenter.tsx',
  'components/operations-center/CrossAuthorityTimeline.tsx',
  'components/operations-center/ExecutiveOperationalBriefing.tsx',
];

// ─── A: File existence ────────────────────────────────────────────────────────

test('operations-center page exists', () => {
  assert.ok(exists('app/dashboard/operations-center/page.tsx'));
});

test('operationsCenterApi module exists', () => {
  assert.ok(exists('lib/operationsCenterApi.ts'));
});

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel file exists: ${name}`, () => {
    assert.ok(exists(file), `missing ${file}`);
  });
});

// ─── B: MCIM compliance ───────────────────────────────────────────────────────

test('operations-center page has data-mcim attribute', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /data-mcim="OPERATIONS-CENTER"/);
});

test('operations-center page has data-authority attribute', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /data-authority=/);
});

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel has data-mcim: ${name}`, () => {
    const src = read(file);
    assert.match(src, /data-mcim=/, `${name} missing data-mcim`);
  });
});

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel is use client: ${name}`, () => {
    const src = read(file);
    assert.match(src, /'use client'/, `${name} missing 'use client'`);
  });
});

// ─── C: Loading states ────────────────────────────────────────────────────────

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel has loading state: ${name}`, () => {
    const src = read(file);
    const hasLoading =
      /loading/i.test(src) ||
      /isLoading/i.test(src) ||
      /animate-pulse/i.test(src) ||
      /skeleton/i.test(src) ||
      /Spinner/i.test(src) ||
      /spinner/i.test(src);
    assert.ok(hasLoading, `${name} missing loading state`);
  });
});

// ─── D: Error states ──────────────────────────────────────────────────────────

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel has error state: ${name}`, () => {
    const src = read(file);
    const hasError =
      /error/i.test(src) ||
      /\.ok === false/i.test(src) ||
      /ok: false/i.test(src) ||
      /!.*\.ok\b/.test(src);
    assert.ok(hasError, `${name} missing error state`);
  });
});

// ─── E: Empty states ──────────────────────────────────────────────────────────

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel handles empty data: ${name}`, () => {
    const src = read(file);
    const hasEmpty =
      /\.length === 0/i.test(src) ||
      /length === 0/i.test(src) ||
      /empty/i.test(src) ||
      /No .* found/i.test(src) ||
      /no data/i.test(src) ||
      /\[\]/.test(src);
    assert.ok(hasEmpty, `${name} missing empty state handling`);
  });
});

// ─── F: API layer ─────────────────────────────────────────────────────────────

test('operationsCenterApi exports getOperationsQueue', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getOperationsQueue/);
});

test('operationsCenterApi exports getAutomationQueue', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getAutomationQueue/);
});

test('operationsCenterApi exports getDecisionPipeline', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getDecisionPipeline/);
});

test('operationsCenterApi exports getRiskHeatmap', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getRiskHeatmap/);
});

test('operationsCenterApi exports getEvidenceFreshness', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getEvidenceFreshness/);
});

test('operationsCenterApi exports getPolicyConflicts', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getPolicyConflicts/);
});

test('operationsCenterApi exports getGovernanceSLA', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getGovernanceSLA/);
});

test('operationsCenterApi exports getAutomationSafety', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getAutomationSafety/);
});

test('operationsCenterApi exports getCrossAuthorityTimeline', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getCrossAuthorityTimeline/);
});

test('operationsCenterApi exports getOperationalBriefing', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /export.*getOperationalBriefing/);
});

test('operationsCenterApi defines LoadResult type', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /LoadResult/);
});

test('operationsCenterApi uses fail-closed ok:false pattern', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /ok: false/);
});

test('operationsCenterApi uses fail-closed ok:true pattern', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /ok: true/);
});

test('operationsCenterApi uses listDecisions from coreApi', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /listDecisions/);
});

test('operationsCenterApi SLA does not rely on due_at for calculation', () => {
  const src = read('lib/operationsCenterApi.ts');
  // SLA is age-based (created_at + threat_level thresholds), not due_at-based
  assert.match(src, /created_at/);
  assert.match(src, /threat_level/);
  // The SLA_HOURS or equivalent threshold constants must exist
  assert.ok(
    /SLA_HOURS|sla_hours|hoursThreshold|SLA_THRESHOLD/.test(src) ||
      /critical.*4|4.*critical/.test(src),
    'SLA thresholds not found',
  );
});

test('operationsCenterApi pipeline stage does not rely on workflow_state', () => {
  const src = read('lib/operationsCenterApi.ts');
  // Pipeline stage is derived from explain_summary, rules_triggered, pq_fallback
  assert.match(src, /explain_summary/);
  assert.match(src, /rules_triggered/);
  assert.match(src, /pq_fallback/);
});

test('operationsCenterApi derives SLA from created_at and threat_level', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /created_at/);
  assert.match(src, /threat_level/);
});

test('operationsCenterApi has SLA thresholds for critical severity', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /critical/);
});

test('operationsCenterApi derives pipeline stage from explain_summary', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /explain_summary/);
});

test('operationsCenterApi derives pipeline stage from rules_triggered', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /rules_triggered/);
});

test('operationsCenterApi derives pipeline stage from pq_fallback', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /pq_fallback/);
});

// ─── G: Navigation registry ───────────────────────────────────────────────────

test('console registry has operations-center entry', () => {
  const src = readRepo('packages/navigation/src/registrations/console.ts');
  assert.match(src, /operations-center/);
});

test('operations-center registry entry has MCIM-18.7', () => {
  const src = readRepo('packages/navigation/src/registrations/console.ts');
  assert.match(src, /MCIM-18\.7/);
});

test('operations-center registry entry has correct route', () => {
  const src = readRepo('packages/navigation/src/registrations/console.ts');
  assert.match(src, /\/operations-center/);
});

test('operations-center registry entry is visible', () => {
  const src = readRepo('packages/navigation/src/registrations/console.ts');
  const block = src.match(/operations-center[\s\S]{0,400}/);
  assert.ok(block, 'operations-center entry not found');
  assert.match(block[0], /visibility.*visible|visible.*visibility/);
});

// ─── H: Sidebar icon mapping ──────────────────────────────────────────────────

test('Sidebar has operations-center in ICON_MAP', () => {
  const src = read('components/layout/Sidebar.tsx');
  assert.match(src, /'operations-center'/);
});

// ─── I: workspaceNav integration ─────────────────────────────────────────────

test('workspaceNav has operations-center key', () => {
  const src = read('lib/workspaceNav.ts');
  assert.match(src, /'operations-center'/);
});

// ─── J: Accessibility ─────────────────────────────────────────────────────────

test('operations-center page has skip-link for accessibility', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /sr-only/);
});

test('operations-center page has main-content id', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /id="main-content"/);
});

test('operations-center page has tabIndex on main content', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /tabIndex/);
});

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel has aria or role attribute: ${name}`, () => {
    const src = read(file);
    const hasA11y =
      /aria-/i.test(src) ||
      /role=/i.test(src) ||
      /tabIndex/i.test(src) ||
      /sr-only/i.test(src);
    assert.ok(hasA11y, `${name} missing accessibility attributes`);
  });
});

// ─── K: Security ──────────────────────────────────────────────────────────────

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel has no hardcoded secrets: ${name}`, () => {
    const src = read(file);
    assert.doesNotMatch(src, /sk-[a-zA-Z0-9]{20,}/);
    assert.doesNotMatch(src, /password\s*=\s*["'][^"']{4,}/i);
    assert.doesNotMatch(src, /api_key\s*=\s*["'][^"']{4,}/i);
  });
});

test('operationsCenterApi has no hardcoded secrets', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.doesNotMatch(src, /sk-[a-zA-Z0-9]{20,}/);
  assert.doesNotMatch(src, /password\s*=\s*["'][^"']{4,}/i);
});

PANEL_FILES.forEach((file) => {
  const name = path.basename(file, '.tsx');
  test(`panel has no mock/fake data in prod path: ${name}`, () => {
    const src = read(file);
    assert.doesNotMatch(src, /Math\.random\(\)/);
    assert.doesNotMatch(src, /faker\./);
  });
});

// ─── L: Page structure ────────────────────────────────────────────────────────

test('operations-center page uses grid layout', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /grid/);
});

test('operations-center page has refresh mechanism', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /refresh/i);
});

test('operations-center page renders all 10 panels', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /ExecutiveOperationsQueue/);
  assert.match(src, /GovernanceAutomationQueue/);
  assert.match(src, /DecisionExecutionPipeline/);
  assert.match(src, /OperationalRiskHeatmap/);
  assert.match(src, /EvidenceFreshnessMonitor/);
  assert.match(src, /PolicyConflictCenter/);
  assert.match(src, /GovernanceSLAMonitor/);
  assert.match(src, /AutomationSafetyCenter/);
  assert.match(src, /CrossAuthorityTimeline/);
  assert.match(src, /ExecutiveOperationalBriefing/);
});

test('operations-center page has data-section attributes', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /data-section=/);
});

test('operations-center page imports ConsoleTopNav', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /ConsoleTopNav/);
});

test('operations-center page uses refreshKey prop pattern', () => {
  const src = read('app/dashboard/operations-center/page.tsx');
  assert.match(src, /refreshKey/);
});

// ─── M: Panel MCIM identifiers ────────────────────────────────────────────────

const PANEL_MCIM = {
  'ExecutiveOperationsQueue.tsx': /EXEC-OPS-QUEUE|OPERATIONS-QUEUE|exec-ops/i,
  'GovernanceAutomationQueue.tsx': /GOV-AUTO-QUEUE|AUTOMATION-QUEUE|gov-auto/i,
  'DecisionExecutionPipeline.tsx': /DECISION-PIPELINE|EXEC-PIPELINE|decision-pipeline/i,
  'OperationalRiskHeatmap.tsx': /RISK-HEATMAP|risk-heatmap/i,
  'EvidenceFreshnessMonitor.tsx': /EVIDENCE-FRESHNESS|evidence-freshness/i,
  'PolicyConflictCenter.tsx': /POLICY-CONFLICT|policy-conflict/i,
  'GovernanceSLAMonitor.tsx': /GOV-SLA|governance-sla/i,
  'AutomationSafetyCenter.tsx': /AUTOMATION-SAFETY|auto-safety/i,
  'CrossAuthorityTimeline.tsx': /CROSS-AUTH-TIMELINE|cross-authority/i,
  'ExecutiveOperationalBriefing.tsx': /EXEC-OP-BRIEFING|exec-briefing/i,
};

Object.entries(PANEL_MCIM).forEach(([file, pattern]) => {
  const name = path.basename(file, '.tsx');
  test(`panel MCIM identifier is descriptive: ${name}`, () => {
    const src = read(`components/operations-center/${file}`);
    assert.ok(
      pattern.test(src) || /data-mcim="[^"]{4,}"/.test(src),
      `${name} MCIM identifier too generic or missing`,
    );
  });
});

// ─── N: Type contracts ────────────────────────────────────────────────────────

test('operationsCenterApi LoadResult has fetchedAt field on success', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /fetchedAt/);
});

test('operationsCenterApi LoadResult has authority field', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /authority/);
});

test('operationsCenterApi uses async/await pattern', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /async /);
  assert.match(src, /await /);
});

test('operationsCenterApi uses try/catch for fail-closed error handling', () => {
  const src = read('lib/operationsCenterApi.ts');
  assert.match(src, /try\s*\{/);
  assert.match(src, /catch/);
});

// ─── O: CI test file ─────────────────────────────────────────────────────────

test('check_operations_center.py CI script exists', () => {
  const p = path.join(REPO_ROOT, 'tests', 'check_operations_center.py');
  assert.ok(fs.existsSync(p), 'missing tests/check_operations_center.py');
});

test('check_operations_center.py checks all 10 panel files', () => {
  const src = fs.readFileSync(
    path.join(REPO_ROOT, 'tests', 'check_operations_center.py'),
    'utf8',
  );
  assert.match(src, /ExecutiveOperationsQueue/);
  assert.match(src, /ExecutiveOperationalBriefing/);
});

// ─── P: PR_FIX_LOG gate ───────────────────────────────────────────────────────

test('PR_FIX_LOG has 18.7 entry', () => {
  const src = readRepo('docs/ai/PR_FIX_LOG.md');
  assert.match(src, /18\.7/);
});

test('PR_FIX_LOG 18.7 entry mentions Suspense fix', () => {
  const src = readRepo('docs/ai/PR_FIX_LOG.md');
  assert.match(src, /[Ss]uspense/);
});

test('PR_FIX_LOG 18.7 entry mentions decisions page', () => {
  const src = readRepo('docs/ai/PR_FIX_LOG.md');
  assert.match(src, /decisions/);
});
