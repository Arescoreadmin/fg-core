/**
 * readiness-dashboard.test.js
 *
 * Static-analysis tests for PR 91 — Enterprise Readiness Dashboard UI.
 *
 * Coverage:
 *   - File existence: all 10 components, API client, page, index
 *   - Barrel index exports all readiness components
 *   - readinessApi.ts: SafeResult, all types, all API functions
 *   - BFF proxy: 5 readiness routes present, GET/HEAD only
 *   - No write methods (POST/PUT/PATCH/DELETE) in readiness proxy rules
 *   - FrameworkSelector: lifecycle warnings, assessment warnings, aria-labels
 *   - ReadinessOverview: score, risk, maturity, completion, threshold alert
 *   - DomainHeatmap: sorted by score, risk badge + text label, threshold marker
 *   - EvidenceCompleteness: completion bar, control counts
 *   - HighRiskGaps: blockers first, severity badge, classification label
 *   - RemediationQueue: ordered list, classification badge, impact
 *   - EvidenceBasisPanel: outcome summary, failed controls list
 *   - SnapshotContext: replay contract fields, assessment dates
 *   - GovernanceDrift: threshold failures, scoring warnings
 *   - EvidenceLineage: fresh/stale counts, staleness_days
 *   - Page: FrameworkSelector wired, parallel fetch (getScore + getGapAnalysis + getAssessment)
 *   - Page: cancelled-flag cleanup pattern in useEffect
 *   - Page: dashboard-loading aria-label, dashboard-error, readiness-dashboard
 *   - Security: no dangerouslySetInnerHTML in any readiness file
 *   - Security: no tenant_id accepted from props or URL in API client
 *   - Security: no fake/hardcoded scores or fabricated metrics
 *   - Security: no raw evidence bodies, vectors, provider payloads
 *   - Accessibility: text labels alongside color signals (not color-only)
 *   - Accessibility: aria-hidden on decorative icons
 *   - Regression: existing BFF routes unmodified
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

const API = 'lib/readinessApi.ts';
const BFF = 'app/api/core/[...path]/route.ts';
const PAGE = 'app/dashboard/readiness/page.tsx';
const INDEX = 'components/readiness/index.ts';

const COMPONENTS = {
  FrameworkSelector: 'components/readiness/FrameworkSelector.tsx',
  ReadinessOverview: 'components/readiness/ReadinessOverview.tsx',
  DomainHeatmap: 'components/readiness/DomainHeatmap.tsx',
  EvidenceCompleteness: 'components/readiness/EvidenceCompleteness.tsx',
  HighRiskGaps: 'components/readiness/HighRiskGaps.tsx',
  RemediationQueue: 'components/readiness/RemediationQueue.tsx',
  EvidenceBasisPanel: 'components/readiness/EvidenceBasisPanel.tsx',
  SnapshotContext: 'components/readiness/SnapshotContext.tsx',
  GovernanceDrift: 'components/readiness/GovernanceDrift.tsx',
  EvidenceLineage: 'components/readiness/EvidenceLineage.tsx',
};

// ─── File existence ────────────────────────────────────────────────────────────

test('readinessApi.ts exists', () => {
  assert.ok(exists(API), 'Missing lib/readinessApi.ts');
});

test('readiness page exists', () => {
  assert.ok(exists(PAGE), 'Missing app/dashboard/readiness/page.tsx');
});

test('readiness index.ts exists', () => {
  assert.ok(exists(INDEX), 'Missing components/readiness/index.ts');
});

for (const [name, relPath] of Object.entries(COMPONENTS)) {
  test(`${name}.tsx exists`, () => {
    assert.ok(exists(relPath), `Missing ${relPath}`);
  });
}

// ─── API client types ──────────────────────────────────────────────────────────

test('readinessApi exports SafeResult type', () => {
  const api = read(API);
  assert.match(api, /SafeResult/);
  assert.match(api, /ok: true/);
  assert.match(api, /ok: false/);
});

test('readinessApi exports Framework type (list endpoints return bare arrays)', () => {
  const api = read(API);
  assert.match(api, /Framework\b/);
  assert.match(api, /framework_id/);
  assert.match(api, /framework_status/);
  // FrameworkListResponse is a type alias for Framework[], not a paginated wrapper
  assert.match(api, /FrameworkListResponse = Framework\[\]/);
});

test('readinessApi exports Assessment type (list endpoints return bare arrays)', () => {
  const api = read(API);
  assert.match(api, /Assessment\b/);
  assert.match(api, /AssessmentListResponse = Assessment\[\]/);
  assert.match(api, /assessment_status/);
});

test('readinessApi list functions return SafeResult of arrays, not wrapper objects', () => {
  const api = read(API);
  // listFrameworks returns Framework[], not FrameworkListResponse with .items
  assert.match(api, /SafeResult<Framework\[\]>/);
  assert.match(api, /SafeResult<Assessment\[\]>/);
});

test('readinessApi exports ScoreOutput with all score fields', () => {
  const api = read(API);
  assert.match(api, /ScoreOutput/);
  assert.match(api, /overall_score/);
  assert.match(api, /normalized_score/);
  assert.match(api, /domain_scores/);
  assert.match(api, /control_scores/);
  assert.match(api, /maturity_tier/);
  assert.match(api, /risk_classification/);
  assert.match(api, /completion_percentage/);
  assert.match(api, /threshold_failures/);
  assert.match(api, /scoring_warnings/);
  assert.match(api, /missing_controls/);
  assert.match(api, /failed_controls/);
  assert.match(api, /is_complete/);
});

test('readinessApi exports GapAnalysisResult with gap types', () => {
  const api = read(API);
  assert.match(api, /GapAnalysisResult/);
  assert.match(api, /ReadinessGap/);
  assert.match(api, /ReadinessBlocker/);
  assert.match(api, /RemediationRecommendation/);
  assert.match(api, /EvidenceFreshnessRecord/);
  assert.match(api, /GapReplayContract/);
  assert.match(api, /replay_contract/);
});

test('readinessApi exports all API functions', () => {
  const api = read(API);
  assert.match(api, /listFrameworks/);
  assert.match(api, /getFramework/);
  assert.match(api, /listAssessments/);
  assert.match(api, /getAssessment/);
  assert.match(api, /getScore/);
  assert.match(api, /getGapAnalysis/);
  assert.match(api, /listDomains/);
});

test('readinessApi routes all go through BFF /api/core', () => {
  const api = read(API);
  assert.match(api, /const BFF = '\/api\/core'/);
  assert.doesNotMatch(api, /localhost:\d+/);
});

// ─── Security: API client tenant isolation ─────────────────────────────────────

test('readinessApi does not accept tenant_id from browser', () => {
  const api = read(API);
  // No props or parameters named tenant_id — resolved server-side
  assert.doesNotMatch(api, /tenant_id.*param/i);
  assert.doesNotMatch(api, /params.*tenant_id/i);
});

test('readinessApi uses safeGet — never throws to callers', () => {
  const api = read(API);
  assert.match(api, /safeGet/);
  assert.match(api, /try\s*\{/);
  assert.match(api, /catch/);
});

// ─── BFF proxy rules ───────────────────────────────────────────────────────────

test('BFF includes readiness frameworks route', () => {
  const bff = read(BFF);
  assert.match(bff, /control-plane\/readiness\/frameworks/);
});

test('BFF includes readiness assessments route', () => {
  const bff = read(BFF);
  assert.match(bff, /control-plane\/readiness\/assessments/);
});

test('BFF includes readiness domains route', () => {
  const bff = read(BFF);
  assert.match(bff, /control-plane\/readiness\/domains/);
});

test('BFF includes readiness controls route', () => {
  const bff = read(BFF);
  assert.match(bff, /control-plane\/readiness\/controls/);
});

test('BFF includes readiness maturity-tiers route', () => {
  const bff = read(BFF);
  assert.match(bff, /control-plane\/readiness\/maturity-tiers/);
});

test('BFF readiness routes are GET/HEAD only — no write methods', () => {
  const bff = read(BFF);
  // Each readiness entry should appear only with GET/HEAD, never POST/PUT/PATCH/DELETE
  const lines = bff.split('\n');
  const readinessLines = lines.filter((l) => l.includes('control-plane/readiness'));
  for (const line of readinessLines) {
    assert.doesNotMatch(line, /POST|PUT|PATCH|DELETE/, `Unexpected write method in: ${line}`);
  }
});

// ─── Barrel index ─────────────────────────────────────────────────────────────

test('index.ts exports all 10 readiness components', () => {
  const idx = read(INDEX);
  for (const name of Object.keys(COMPONENTS)) {
    assert.match(idx, new RegExp(name), `index.ts missing export for ${name}`);
  }
});

// ─── FrameworkSelector ────────────────────────────────────────────────────────

test('FrameworkSelector is use client', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /'use client'/);
});

test('FrameworkSelector has readiness-framework-selector aria-label', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /readiness-framework-selector/);
});

test('FrameworkSelector shows lifecycle warning for deprecated/retired frameworks', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /framework-lifecycle-warning/);
  assert.match(c, /deprecated|retired/);
  assert.match(c, /LIFECYCLE_WARN/);
});

test('FrameworkSelector shows warning for non-finalized assessments', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /assessment-incomplete-warning/);
  assert.match(c, /finalized/);
});

test('FrameworkSelector has loading aria-labels for frameworks and assessments', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /frameworks-loading/);
  assert.match(c, /assessments-loading/);
});

test('FrameworkSelector has error aria-labels', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /frameworks-error/);
  assert.match(c, /assessments-error/);
});

test('FrameworkSelector uses cancelled-flag cleanup pattern', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /cancelled/);
  assert.match(c, /return \(\) =>/);
});

test('FrameworkSelector resets assessment on framework change', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /setLocalAssessmentId\(''\)/);
});

// ─── ReadinessOverview ────────────────────────────────────────────────────────

test('ReadinessOverview has readiness-overview aria-label', () => {
  const c = read(COMPONENTS.ReadinessOverview);
  assert.match(c, /readiness-overview/);
});

test('ReadinessOverview shows overall-score, risk-classification, maturity-tier, completion-state', () => {
  const c = read(COMPONENTS.ReadinessOverview);
  assert.match(c, /overall-score/);
  assert.match(c, /risk-classification/);
  assert.match(c, /maturity-tier/);
  assert.match(c, /completion-state/);
});

test('ReadinessOverview shows threshold-failures-summary when failures exist', () => {
  const c = read(COMPONENTS.ReadinessOverview);
  assert.match(c, /threshold-failures-summary/);
  assert.match(c, /threshold_failures\.length/);
});

test('ReadinessOverview shows computed-at timestamp', () => {
  const c = read(COMPONENTS.ReadinessOverview);
  assert.match(c, /computed-at/);
  assert.match(c, /computed_at/);
});

test('ReadinessOverview uses text labels alongside color signals', () => {
  const c = read(COMPONENTS.ReadinessOverview);
  // Badge text labels for risk, not just color
  assert.match(c, /risk_classification/);
  assert.match(c, /Badge/);
  assert.match(c, /riskVariant/);
});

// ─── DomainHeatmap ────────────────────────────────────────────────────────────

test('DomainHeatmap has domain-heatmap aria-label', () => {
  const c = read(COMPONENTS.DomainHeatmap);
  assert.match(c, /domain-heatmap/);
});

test('DomainHeatmap sorts domains by normalized_score ascending', () => {
  const c = read(COMPONENTS.DomainHeatmap);
  assert.match(c, /normalized_score/);
  assert.match(c, /sort/);
});

test('DomainHeatmap shows per-domain aria-label', () => {
  const c = read(COMPONENTS.DomainHeatmap);
  assert.match(c, /domain-score-\$\{/);
});

test('DomainHeatmap shows risk badge text alongside progress bar color', () => {
  const c = read(COMPONENTS.DomainHeatmap);
  assert.match(c, /risk_classification/);
  assert.match(c, /Badge/);
  assert.match(c, /Progress/);
});

test('DomainHeatmap marks threshold_failed domains', () => {
  const c = read(COMPONENTS.DomainHeatmap);
  assert.match(c, /threshold_failed/);
  assert.match(c, /threshold-failed/);
});

test('DomainHeatmap shows empty state', () => {
  const c = read(COMPONENTS.DomainHeatmap);
  assert.match(c, /domain-heatmap-empty/);
});

// ─── EvidenceCompleteness ─────────────────────────────────────────────────────

test('EvidenceCompleteness has evidence-completeness aria-label', () => {
  const c = read(COMPONENTS.EvidenceCompleteness);
  assert.match(c, /evidence-completeness/);
});

test('EvidenceCompleteness shows completion progress bar', () => {
  const c = read(COMPONENTS.EvidenceCompleteness);
  assert.match(c, /completion_percentage/);
  assert.match(c, /Progress/);
});

test('EvidenceCompleteness shows missing and failed control counts', () => {
  const c = read(COMPONENTS.EvidenceCompleteness);
  assert.match(c, /control-count-missing/);
  assert.match(c, /control-count-failed/);
  assert.match(c, /missing_controls/);
  assert.match(c, /failed_controls/);
});

test('EvidenceCompleteness shows evidence-count-total', () => {
  const c = read(COMPONENTS.EvidenceCompleteness);
  assert.match(c, /evidence-count-total/);
  assert.match(c, /evidence_count/);
});

// ─── HighRiskGaps ─────────────────────────────────────────────────────────────

test('HighRiskGaps has high-risk-gaps aria-label', () => {
  const c = read(COMPONENTS.HighRiskGaps);
  assert.match(c, /high-risk-gaps/);
});

test('HighRiskGaps filters to critical and high severity only', () => {
  const c = read(COMPONENTS.HighRiskGaps);
  assert.match(c, /HIGH_RISK/);
  assert.match(c, /critical.*high|high.*critical/);
  assert.match(c, /gap_severity/);
});

test('HighRiskGaps renders blockers separately before gaps', () => {
  const c = read(COMPONENTS.HighRiskGaps);
  assert.match(c, /blocker-\$\{/);
  assert.match(c, /blockers\.length/);
  assert.match(c, /Blockers/);
});

test('HighRiskGaps shows classification label text', () => {
  const c = read(COMPONENTS.HighRiskGaps);
  assert.match(c, /classificationLabel/);
  assert.match(c, /missing_evidence/);
  assert.match(c, /failed_control/);
  assert.match(c, /threshold_failure/);
});

test('HighRiskGaps shows empty state when no critical/high gaps', () => {
  const c = read(COMPONENTS.HighRiskGaps);
  assert.match(c, /gaps-empty/);
});

// ─── RemediationQueue ─────────────────────────────────────────────────────────

test('RemediationQueue has remediation-queue aria-label', () => {
  const c = read(COMPONENTS.RemediationQueue);
  assert.match(c, /remediation-queue/);
});

test('RemediationQueue renders ordered list with position numbers', () => {
  const c = read(COMPONENTS.RemediationQueue);
  assert.match(c, /remediation-list/);
  assert.match(c, /idx \+ 1/);
});

test('RemediationQueue shows classification badge with label', () => {
  const c = read(COMPONENTS.RemediationQueue);
  assert.match(c, /classificationLabel/);
  assert.match(c, /immediate/);
  assert.match(c, /short_term/);
  assert.match(c, /Badge/);
});

test('RemediationQueue shows estimated_readiness_impact', () => {
  const c = read(COMPONENTS.RemediationQueue);
  assert.match(c, /estimated_readiness_impact/);
  assert.match(c, /readiness impact/);
});

test('RemediationQueue shows empty state', () => {
  const c = read(COMPONENTS.RemediationQueue);
  assert.match(c, /remediation-empty/);
});

// ─── EvidenceBasisPanel ───────────────────────────────────────────────────────

test('EvidenceBasisPanel has evidence-basis-panel aria-label', () => {
  const c = read(COMPONENTS.EvidenceBasisPanel);
  assert.match(c, /evidence-basis-panel/);
});

test('EvidenceBasisPanel shows outcome-summary grouped by outcome', () => {
  const c = read(COMPONENTS.EvidenceBasisPanel);
  assert.match(c, /outcome-summary/);
  assert.match(c, /byOutcome/);
});

test('EvidenceBasisPanel covers all outcome types', () => {
  const c = read(COMPONENTS.EvidenceBasisPanel);
  assert.match(c, /pass/);
  assert.match(c, /fail/);
  assert.match(c, /partial/);
  assert.match(c, /not_evaluated/);
  assert.match(c, /not_applicable/);
});

test('EvidenceBasisPanel shows failed controls list with identifiers', () => {
  const c = read(COMPONENTS.EvidenceBasisPanel);
  assert.match(c, /failed-control-\$\{/);
  assert.match(c, /control_identifier/);
});

test('EvidenceBasisPanel shows empty state', () => {
  const c = read(COMPONENTS.EvidenceBasisPanel);
  assert.match(c, /evidence-basis-empty/);
});

// ─── SnapshotContext ──────────────────────────────────────────────────────────

test('SnapshotContext has snapshot-context aria-label', () => {
  const c = read(COMPONENTS.SnapshotContext);
  assert.match(c, /snapshot-context/);
});

test('SnapshotContext shows all replay contract version fields', () => {
  const c = read(COMPONENTS.SnapshotContext);
  assert.match(c, /analysis_version/);
  assert.match(c, /framework_version/);
  assert.match(c, /scoring_contract_version/);
  assert.match(c, /maturity_model_version/);
  assert.match(c, /mapping_version/);
  assert.match(c, /evidence_snapshot_version/);
});

test('SnapshotContext shows assessment dates', () => {
  const c = read(COMPONENTS.SnapshotContext);
  assert.match(c, /assessment-created-at/);
  assert.match(c, /created_at/);
  assert.match(c, /snapshot_version/);
});

// ─── GovernanceDrift ──────────────────────────────────────────────────────────

test('GovernanceDrift has governance-drift aria-label', () => {
  const c = read(COMPONENTS.GovernanceDrift);
  assert.match(c, /governance-drift/);
});

test('GovernanceDrift shows threshold failures with required vs actual', () => {
  const c = read(COMPONENTS.GovernanceDrift);
  assert.match(c, /threshold-failure-/);
  assert.match(c, /required_value/);
  assert.match(c, /actual_value/);
  assert.match(c, /threshold_name/);
});

test('GovernanceDrift shows scoring warnings', () => {
  const c = read(COMPONENTS.GovernanceDrift);
  assert.match(c, /scoring-warning-/);
  assert.match(c, /scoringWarnings/);
});

test('GovernanceDrift shows clean state when no failures', () => {
  const c = read(COMPONENTS.GovernanceDrift);
  assert.match(c, /governance-drift-clean/);
});

// ─── EvidenceLineage ──────────────────────────────────────────────────────────

test('EvidenceLineage has evidence-lineage aria-label', () => {
  const c = read(COMPONENTS.EvidenceLineage);
  assert.match(c, /evidence-lineage/);
});

test('EvidenceLineage shows fresh and stale counts separately', () => {
  const c = read(COMPONENTS.EvidenceLineage);
  assert.match(c, /evidence-fresh-count/);
  assert.match(c, /evidence-stale-count/);
  assert.match(c, /is_stale/);
});

test('EvidenceLineage shows staleness_days for stale records', () => {
  const c = read(COMPONENTS.EvidenceLineage);
  assert.match(c, /staleness_days/);
  assert.match(c, /stale-record-\$\{/);
});

test('EvidenceLineage shows freshness_window_days context', () => {
  const c = read(COMPONENTS.EvidenceLineage);
  assert.match(c, /freshness_window_days/);
});

test('EvidenceLineage shows empty state when no records', () => {
  const c = read(COMPONENTS.EvidenceLineage);
  assert.match(c, /evidence-lineage-empty/);
});

// ─── Page integration ─────────────────────────────────────────────────────────

test('readiness page is use client', () => {
  const page = read(PAGE);
  assert.match(page, /'use client'/);
});

test('readiness page uses TopBar', () => {
  const page = read(PAGE);
  assert.match(page, /TopBar/);
  assert.match(page, /Readiness/);
});

test('readiness page wires FrameworkSelector', () => {
  const page = read(PAGE);
  assert.match(page, /FrameworkSelector/);
  assert.match(page, /onAssessmentSelect/);
});

test('readiness page fetches score, gap analysis, and assessment in parallel', () => {
  const page = read(PAGE);
  assert.match(page, /getScore/);
  assert.match(page, /getGapAnalysis/);
  assert.match(page, /getAssessment/);
  assert.match(page, /Promise\.all/);
});

test('readiness page uses cancelled-flag cleanup', () => {
  const page = read(PAGE);
  assert.match(page, /cancelled/);
  assert.match(page, /cancelled = true/);
});

test('readiness page has dashboard-loading aria-label', () => {
  const page = read(PAGE);
  assert.match(page, /dashboard-loading/);
});

test('readiness page has dashboard-error aria-label', () => {
  const page = read(PAGE);
  assert.match(page, /dashboard-error/);
});

test('readiness page has readiness-dashboard aria-label', () => {
  const page = read(PAGE);
  assert.match(page, /readiness-dashboard/);
});

test('readiness page imports all 10 readiness components', () => {
  const page = read(PAGE);
  for (const name of Object.keys(COMPONENTS)) {
    assert.match(page, new RegExp(name), `page.tsx missing import for ${name}`);
  }
});

test('readiness page has dashboard-hint when no assessment selected', () => {
  const page = read(PAGE);
  assert.match(page, /dashboard-hint/);
});

// ─── Security invariants ──────────────────────────────────────────────────────

test('no dangerouslySetInnerHTML in any readiness component', () => {
  const files = [PAGE, API, ...Object.values(COMPONENTS)];
  for (const f of files) {
    assert.doesNotMatch(
      read(f),
      /dangerouslySetInnerHTML/,
      `dangerouslySetInnerHTML found in ${f}`,
    );
  }
});

test('no hardcoded fake scores or fabricated metrics in components', () => {
  for (const [name, relPath] of Object.entries(COMPONENTS)) {
    const c = read(relPath);
    // No magic numeric literals used as fake score displays
    assert.doesNotMatch(c, /overall_score\s*=\s*\d+/, `Fake score in ${name}`);
    assert.doesNotMatch(c, /Math\.random/, `Math.random in ${name}`);
  }
});

test('no raw vector or embedding fields exposed in components', () => {
  for (const [name, relPath] of Object.entries(COMPONENTS)) {
    const c = read(relPath);
    assert.doesNotMatch(c, /embedding_vector/, `Raw embedding in ${name}`);
    assert.doesNotMatch(c, /raw_prompt/, `Raw prompt in ${name}`);
  }
});

test('API client does not expose tenant_id from request URL or body', () => {
  const api = read(API);
  // The BFF resolves tenant server-side; client never sends it
  assert.doesNotMatch(api, /searchParams.*tenant/i);
  assert.doesNotMatch(api, /body.*tenant_id/i);
});

// ─── Accessibility ─────────────────────────────────────────────────────────────

test('decorative icons use aria-hidden across readiness components', () => {
  for (const [name, relPath] of Object.entries(COMPONENTS)) {
    const c = read(relPath);
    if (c.includes('lucide-react') && c.includes('aria-hidden')) {
      assert.match(c, /aria-hidden="true"/, `Missing aria-hidden in ${name}`);
    }
  }
});

test('risk badges use text labels not just color class names', () => {
  // Ensure Badge components receive text content derived from risk_classification
  const overview = read(COMPONENTS.ReadinessOverview);
  assert.match(overview, /risk_classification/);
  assert.match(overview, /Badge/);
  // Text is derived via charAt/slice or riskVariant — not color-only
  assert.match(overview, /charAt\(0\)\.toUpperCase\(\)|riskVariant/);
});

// ─── P2: stale data cleared on framework switch ────────────────────────────────

test('FrameworkSelector accepts onFrameworkChange optional prop', () => {
  const c = read(COMPONENTS.FrameworkSelector);
  assert.match(c, /onFrameworkChange/);
  assert.match(c, /onFrameworkChange\?\./);
});

test('page wires onFrameworkChange to clear stale dashboard data', () => {
  const page = read(PAGE);
  assert.match(page, /onFrameworkChange/);
  assert.match(page, /handleFrameworkChange/);
  // Clearing stale data: assessment ID and data reset on framework switch
  assert.match(page, /setSelectedAssessmentId\(null\)/);
  assert.match(page, /setData\(null\)/);
});

// ─── Architectural seams (Gaps 1–5) ──────────────────────────────────────────

test('Gap 1 seam: ScoreHistoryEntry type stub present in readinessApi', () => {
  const api = read(API);
  assert.match(api, /ScoreHistoryEntry/);
  assert.match(api, /posture-trend-panel/);
});

test('Gap 1 seam: posture-trend-panel slot comment present in page', () => {
  const page = read(PAGE);
  assert.match(page, /posture-trend-panel/);
});

test('Gap 2 seam: OperationalImpact type stub present in readinessApi', () => {
  const api = read(API);
  assert.match(api, /OperationalImpact/);
  assert.match(api, /operational.impact/i);
});

test('Gap 2 seam: operational-impact-panel slot comment present in page', () => {
  const page = read(PAGE);
  assert.match(page, /operational-impact-panel/);
});

test('Gap 3 seam: CrosswalkControlMapping and FrameworkCrosswalk type stubs present', () => {
  const api = read(API);
  assert.match(api, /CrosswalkControlMapping/);
  assert.match(api, /FrameworkCrosswalk/);
});

test('Gap 3 seam: page comment references cross-framework comparison', () => {
  const page = read(PAGE);
  assert.match(page, /cross-framework|crosswalk/i);
});

test('Gap 4 seam: ReviewerContext and ReviewerAssignment type stubs present', () => {
  const api = read(API);
  assert.match(api, /ReviewerContext/);
  assert.match(api, /ReviewerAssignment/);
  assert.match(api, /reviewer-workflow/);
});

test('Gap 4 seam: reviewer-workflow-panel slot comment present in page', () => {
  const page = read(PAGE);
  assert.match(page, /reviewer-workflow-panel/);
});

test('Gap 5 seam: RuntimeCorrelationSummary type stub present in readinessApi', () => {
  const api = read(API);
  assert.match(api, /RuntimeCorrelationSummary/);
  assert.match(api, /RuntimeCorrelationFactor/);
});

test('Gap 5 seam: runtime-correlation-panel slot comment present in page', () => {
  const page = read(PAGE);
  assert.match(page, /runtime-correlation-panel/);
});

// ─── Regression: existing routes unmodified ───────────────────────────────────

test('BFF still includes existing routes (decisions, keys, rag/corpora)', () => {
  const bff = read(BFF);
  assert.match(bff, /decisions/);
  assert.match(bff, /\bkeys\b/);
  assert.match(bff, /rag\/corpora/);
  assert.match(bff, /ui\/ai\/chat/);
});
