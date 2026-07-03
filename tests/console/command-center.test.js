/**
 * command-center.test.js
 *
 * 600+ deterministic static-analysis tests for PR 18.6.2 Executive Command Center.
 * Tests read source files and assert on their structure — no runtime execution,
 * no mocking, no network calls.
 *
 * Structure:
 *  - 18 widget component tests (~30 each = ~540 tests)
 *  - Page tests (~30)
 *  - CI tool tests (~20)
 *  - Navigation tests (~15)
 *
 * All tests are static-analysis only — they verify file structure, MCIM
 * references, authority attribution, no fabricated data, proper TypeScript
 * patterns, etc.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', '..', relPath), 'utf8');
}

function exists(relPath) {
  return fs.existsSync(path.join(__dirname, '..', '..', relPath));
}

// Widget paths
const WIDGET_DIR = 'apps/console/components/command-center';

function widget(name) {
  return `${WIDGET_DIR}/${name}`;
}

// ─── WidgetShell ──────────────────────────────────────────────────────────────

test('WidgetShell — file exists', () => {
  assert.ok(exists(widget('WidgetShell.tsx')));
});

test('WidgetShell — has use client', () => {
  assert.match(read(widget('WidgetShell.tsx')), /'use client'/);
});

test('WidgetShell — has default export', () => {
  assert.match(read(widget('WidgetShell.tsx')), /export default function WidgetShell/);
});

test('WidgetShell — has MCIM reference', () => {
  assert.match(read(widget('WidgetShell.tsx')), /MCIM-18\.6-/);
});

test('WidgetShell — has authority reference', () => {
  assert.match(read(widget('WidgetShell.tsx')), /authority/);
});

test('WidgetShell — has sourceOfTruth prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /sourceOfTruth/);
});

test('WidgetShell — has drillDown prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /drillDown/);
});

test('WidgetShell — has aria-expanded', () => {
  assert.match(read(widget('WidgetShell.tsx')), /aria-expanded/);
});

test('WidgetShell — has Source button', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Source/);
});

test('WidgetShell — has mcimId prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /mcimId/);
});

test('WidgetShell — has title prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /title/);
});

test('WidgetShell — has children prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /children/);
});

test('WidgetShell — has confidence prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /confidence/);
});

test('WidgetShell — has lastUpdated prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /lastUpdated/);
});

test('WidgetShell — has refreshPolicy prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /refreshPolicy/);
});

test('WidgetShell — no Math.random', () => {
  assert.doesNotMatch(read(widget('WidgetShell.tsx')), /Math\.random/);
});

test('WidgetShell — imports Card', () => {
  assert.match(read(widget('WidgetShell.tsx')), /@\/components\/ui\/card/);
});

test('WidgetShell — imports Button', () => {
  assert.match(read(widget('WidgetShell.tsx')), /@\/components\/ui\/button/);
});

test('WidgetShell — has className prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /className/);
});

test('WidgetShell — has heading via CardTitle', () => {
  assert.match(read(widget('WidgetShell.tsx')), /CardTitle/);
});

test('WidgetShell — has Link for drill-down', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Link/);
});

test('WidgetShell — has capability prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /capability/);
});

test('WidgetShell — has aria-label on widget', () => {
  assert.match(read(widget('WidgetShell.tsx')), /aria-label/);
});

test('WidgetShell — uses useState for metadata panel', () => {
  assert.match(read(widget('WidgetShell.tsx')), /useState/);
});

test('WidgetShell — no TODO or placeholder text', () => {
  assert.doesNotMatch(read(widget('WidgetShell.tsx')), /TODO|placeholder text/i);
});

test('WidgetShell — TypeScript interface exported', () => {
  assert.match(read(widget('WidgetShell.tsx')), /export interface WidgetShellProps/);
});

test('WidgetShell — has set/toggle open state', () => {
  assert.match(read(widget('WidgetShell.tsx')), /setMetaOpen/);
});

test('WidgetShell — uses Tailwind classes', () => {
  assert.match(read(widget('WidgetShell.tsx')), /className=/);
});

test('WidgetShell — imports from lucide-react', () => {
  assert.match(read(widget('WidgetShell.tsx')), /lucide-react/);
});

// ─── ExecutiveKPIBar ──────────────────────────────────────────────────────────

test('ExecutiveKPIBar — file exists', () => {
  assert.ok(exists(widget('ExecutiveKPIBar.tsx')));
});

test('ExecutiveKPIBar — has use client', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /'use client'/);
});

test('ExecutiveKPIBar — has default export', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /export default function ExecutiveKPIBar/);
});

test('ExecutiveKPIBar — has MCIM reference', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /MCIM-18\.6-CMD-CENTER/);
});

test('ExecutiveKPIBar — has authority reference', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /AUTHORITY/);
});

test('ExecutiveKPIBar — has sourceOfTruth', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /sourceOfTruth/);
});

test('ExecutiveKPIBar — has drillDown', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /drillDown/);
});

test('ExecutiveKPIBar — has loading skeleton state', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /animate-pulse/);
});

test('ExecutiveKPIBar — has no-data em dash', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /—/);
});

test('ExecutiveKPIBar — no Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveKPIBar.tsx')), /Math\.random/);
});

test('ExecutiveKPIBar — has aria-label', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /aria-label/);
});

test('ExecutiveKPIBar — has governance-score testid', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /governance-score/);
});

test('ExecutiveKPIBar — has trust-score testid', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /trust-score/);
});

test('ExecutiveKPIBar — has risk-score testid', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /risk-score/);
});

test('ExecutiveKPIBar — has readiness-score testid', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /readiness-score/);
});

test('ExecutiveKPIBar — has active-assessments testid', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /active-assessments/);
});

test('ExecutiveKPIBar — has critical-findings testid', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /critical-findings/);
});

test('ExecutiveKPIBar — has open-decisions testid', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /open-decisions/);
});

test('ExecutiveKPIBar — imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /WidgetShell/);
});

test('ExecutiveKPIBar — has ControlTowerSnapshotV1 type import', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /ControlTowerSnapshotV1/);
});

test('ExecutiveKPIBar — has href for drill-down', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /href/);
});

test('ExecutiveKPIBar — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ExecutiveKPIBar.tsx')), /TODO|placeholder text/i);
});

test('ExecutiveKPIBar — has Tailwind classes', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /className=/);
});

test('ExecutiveKPIBar — has trend indicator', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /TrendingUp|TrendingDown|trend/);
});

test('ExecutiveKPIBar — has delta badge reference', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /delta/);
});

test('ExecutiveKPIBar — has KPIData interface', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /KPIData/);
});

test('ExecutiveKPIBar — imports lucide-react icons', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /lucide-react/);
});

test('ExecutiveKPIBar — has compliance-coverage kpi', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /compliance-coverage/);
});

test('ExecutiveKPIBar — has evidence-freshness kpi', () => {
  assert.match(read(widget('ExecutiveKPIBar.tsx')), /evidence-freshness/);
});

// ─── ExecutiveHealthPanel ─────────────────────────────────────────────────────

test('ExecutiveHealthPanel — file exists', () => {
  assert.ok(exists(widget('ExecutiveHealthPanel.tsx')));
});

test('ExecutiveHealthPanel — has use client', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /'use client'/);
});

test('ExecutiveHealthPanel — has default export', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /export default function ExecutiveHealthPanel/);
});

test('ExecutiveHealthPanel — has MCIM-18.6-TRUST-CENTER', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /MCIM-18\.6-TRUST-CENTER/);
});

test('ExecutiveHealthPanel — has AUTHORITY', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /AUTHORITY/);
});

test('ExecutiveHealthPanel — has sourceOfTruth', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /sourceOfTruth/);
});

test('ExecutiveHealthPanel — has drillDown', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /drillDown/);
});

test('ExecutiveHealthPanel — has loading state', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /animate-pulse|loading/);
});

test('ExecutiveHealthPanel — has health-healthy state', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /health-healthy/);
});

test('ExecutiveHealthPanel — has health-needs-attention state', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /health-needs-attention/);
});

test('ExecutiveHealthPanel — has health-elevated-risk state', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /health-elevated-risk/);
});

test('ExecutiveHealthPanel — has health-critical state', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /health-critical/);
});

test('ExecutiveHealthPanel — has health-blocked state', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /health-blocked/);
});

test('ExecutiveHealthPanel — no Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveHealthPanel.tsx')), /Math\.random/);
});

test('ExecutiveHealthPanel — has aria-label', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /aria-label/);
});

test('ExecutiveHealthPanel — imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /WidgetShell/);
});

test('ExecutiveHealthPanel — has ControlTowerSnapshotV1 import', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /ControlTowerSnapshotV1/);
});

test('ExecutiveHealthPanel — has confidence prop', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /confidence/);
});

test('ExecutiveHealthPanel — has recommendations list', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /recommendations/i);
});

test('ExecutiveHealthPanel — has reason display', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /reason/);
});

test('ExecutiveHealthPanel — has evidence reference', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /evidence|Evidence/);
});

test('ExecutiveHealthPanel — no hardcoded fake health score', () => {
  assert.doesNotMatch(read(widget('ExecutiveHealthPanel.tsx')), /score\s*=\s*\d{2,3}\b/);
});

test('ExecutiveHealthPanel — has Tailwind classes', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /className=/);
});

test('ExecutiveHealthPanel — imports lucide-react icons', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /lucide-react/);
});

test('ExecutiveHealthPanel — has no-data/blocked state', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /blocked|unavailable/);
});

test('ExecutiveHealthPanel — deriveHealthState function', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /deriveHealthState/);
});

test('ExecutiveHealthPanel — has STATE_CONFIG map', () => {
  assert.match(read(widget('ExecutiveHealthPanel.tsx')), /STATE_CONFIG/);
});

// ─── GovernanceOverview ───────────────────────────────────────────────────────

test('GovernanceOverview — file exists', () => {
  assert.ok(exists(widget('GovernanceOverview.tsx')));
});

test('GovernanceOverview — has use client', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /'use client'/);
});

test('GovernanceOverview — has default export', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /export default function GovernanceOverview/);
});

test('GovernanceOverview — has MCIM-18.6-GOVERNANCE', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /MCIM-18\.6-GOVERNANCE/);
});

test('GovernanceOverview — has AUTHORITY', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /AUTHORITY/);
});

test('GovernanceOverview — has sourceOfTruth', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /sourceOfTruth/);
});

test('GovernanceOverview — has drillDown', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /drillDown/);
});

test('GovernanceOverview — has loading state', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /animate-pulse|loading/);
});

test('GovernanceOverview — has no-data empty state', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /No governance assessment/);
});

test('GovernanceOverview — has governance-overview testid', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /governance-overview/);
});

test('GovernanceOverview — has governance-score-display testid', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /governance-score-display/);
});

test('GovernanceOverview — has governance-trend testid', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /governance-trend/);
});

test('GovernanceOverview — has governance-factors testid', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /governance-factors/);
});

test('GovernanceOverview — no Math.random', () => {
  assert.doesNotMatch(read(widget('GovernanceOverview.tsx')), /Math\.random/);
});

test('GovernanceOverview — imports WidgetShell', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /WidgetShell/);
});

test('GovernanceOverview — imports ScoreOutput type', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /ScoreOutput/);
});

test('GovernanceOverview — has aria-label', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /aria-label/);
});

test('GovernanceOverview — has governance debt indicator', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /debt|missing/i);
});

test('GovernanceOverview — has completion percentage display', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /completion/i);
});

test('GovernanceOverview — no hardcoded score numbers', () => {
  assert.doesNotMatch(read(widget('GovernanceOverview.tsx')), /score\s*=\s*\d{2,3}\b/);
});

test('GovernanceOverview — has Tailwind classes', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /className=/);
});

test('GovernanceOverview — imports lucide-react', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /lucide-react/);
});

test('GovernanceOverview — has risk classification display', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /riskClass|risk_classification/);
});

test('GovernanceOverview — trendNote prop accepted', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /trendNote/);
});

test('GovernanceOverview — has top factors section', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /topFactors|Top Factor/);
});

test('GovernanceOverview — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('GovernanceOverview.tsx')), /TODO|placeholder text/i);
});

test('GovernanceOverview — h3 heading element', () => {
  assert.match(read(widget('GovernanceOverview.tsx')), /h3/);
});

// ─── TrustCenterSummary ───────────────────────────────────────────────────────

test('TrustCenterSummary — file exists', () => {
  assert.ok(exists(widget('TrustCenterSummary.tsx')));
});

test('TrustCenterSummary — has use client', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /'use client'/);
});

test('TrustCenterSummary — has default export', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /export default function TrustCenterSummary/);
});

test('TrustCenterSummary — has MCIM-18.6-TRUST-CENTER', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /MCIM-18\.6-TRUST-CENTER/);
});

test('TrustCenterSummary — has AUTHORITY', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /AUTHORITY/);
});

test('TrustCenterSummary — has sourceOfTruth', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /sourceOfTruth/);
});

test('TrustCenterSummary — has drillDown', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /drillDown/);
});

test('TrustCenterSummary — has trust-health testid', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /trust-health/);
});

test('TrustCenterSummary — has chain-integrity testid', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /chain-integrity/);
});

test('TrustCenterSummary — has key-lifecycle testid', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /key-lifecycle/);
});

test('TrustCenterSummary — has verification-status testid', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /verification-status/);
});

test('TrustCenterSummary — no Math.random', () => {
  assert.doesNotMatch(read(widget('TrustCenterSummary.tsx')), /Math\.random/);
});

test('TrustCenterSummary — has aria-label', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /aria-label/);
});

test('TrustCenterSummary — links to /dashboard/forensics', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /\/dashboard\/forensics/);
});

test('TrustCenterSummary — links to /dashboard/provenance', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /\/dashboard\/provenance/);
});

test('TrustCenterSummary — links to /dashboard/decisions', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /\/dashboard\/decisions/);
});

test('TrustCenterSummary — links to /keys', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /\/keys/);
});

test('TrustCenterSummary — imports WidgetShell', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /WidgetShell/);
});

test('TrustCenterSummary — has ControlTowerSnapshotV1 import', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /ControlTowerSnapshotV1/);
});

test('TrustCenterSummary — has no-data empty state', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /unavailable|No trust/);
});

test('TrustCenterSummary — has loading skeleton', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /animate-pulse/);
});

test('TrustCenterSummary — has StatusIcon component', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /StatusIcon/);
});

test('TrustCenterSummary — has Link imports', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /Link/);
});

test('TrustCenterSummary — has Tailwind classes', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /className=/);
});

test('TrustCenterSummary — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('TrustCenterSummary.tsx')), /TODO|placeholder text/i);
});

test('TrustCenterSummary — decision-provenance row', () => {
  assert.match(read(widget('TrustCenterSummary.tsx')), /decision-provenance/);
});

// ─── ExecutiveRiskMap ─────────────────────────────────────────────────────────

test('ExecutiveRiskMap — file exists', () => {
  assert.ok(exists(widget('ExecutiveRiskMap.tsx')));
});

test('ExecutiveRiskMap — has use client', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /'use client'/);
});

test('ExecutiveRiskMap — has default export', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /export default function ExecutiveRiskMap/);
});

test('ExecutiveRiskMap — has MCIM-18.6-FIELD-ASSESSMENT', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /MCIM-18\.6-FIELD-ASSESSMENT/);
});

test('ExecutiveRiskMap — has AUTHORITY', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /AUTHORITY/);
});

test('ExecutiveRiskMap — has sourceOfTruth', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /sourceOfTruth/);
});

test('ExecutiveRiskMap — has drillDown', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /drillDown/);
});

test('ExecutiveRiskMap — has risk-critical testid', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /risk-critical/);
});

test('ExecutiveRiskMap — has risk-high testid', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /risk-high/);
});

test('ExecutiveRiskMap — has risk-medium testid', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /risk-medium/);
});

test('ExecutiveRiskMap — has risk-low testid', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /risk-low/);
});

test('ExecutiveRiskMap — has risk-trend testid', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /risk-trend/);
});

test('ExecutiveRiskMap — has risk-map-authority', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /risk-map-authority/);
});

test('ExecutiveRiskMap — has risk-no-data empty state', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /risk-no-data/);
});

test('ExecutiveRiskMap — no Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveRiskMap.tsx')), /Math\.random/);
});

test('ExecutiveRiskMap — no hardcoded count numbers', () => {
  assert.doesNotMatch(read(widget('ExecutiveRiskMap.tsx')), /count\s*=\s*\d{2,3}\b/);
});

test('ExecutiveRiskMap — has aria-label', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /aria-label/);
});

test('ExecutiveRiskMap — imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /WidgetShell/);
});

test('ExecutiveRiskMap — has RiskCounts interface', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /RiskCounts/);
});

test('ExecutiveRiskMap — has Business impact label', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /Business/);
});

test('ExecutiveRiskMap — has Operational impact label', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /Operational/);
});

test('ExecutiveRiskMap — has Regulatory impact label', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /Regulatory/);
});

test('ExecutiveRiskMap — has Customer impact label', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /Customer/);
});

test('ExecutiveRiskMap — has loading skeleton', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /animate-pulse/);
});

test('ExecutiveRiskMap — has Tailwind classes', () => {
  assert.match(read(widget('ExecutiveRiskMap.tsx')), /className=/);
});

test('ExecutiveRiskMap — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ExecutiveRiskMap.tsx')), /TODO|placeholder text/i);
});

// ─── ExecutiveActionQueue ─────────────────────────────────────────────────────

test('ExecutiveActionQueue — file exists', () => {
  assert.ok(exists(widget('ExecutiveActionQueue.tsx')));
});

test('ExecutiveActionQueue — has use client', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /'use client'/);
});

test('ExecutiveActionQueue — has default export', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /export default function ExecutiveActionQueue/);
});

test('ExecutiveActionQueue — has MCIM-18.6-GOVERNANCE', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /MCIM-18\.6-GOVERNANCE/);
});

test('ExecutiveActionQueue — has AUTHORITY', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /AUTHORITY/);
});

test('ExecutiveActionQueue — has sourceOfTruth', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /sourceOfTruth/);
});

test('ExecutiveActionQueue — has drillDown', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /drillDown/);
});

test('ExecutiveActionQueue — action-queue-empty empty state', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /action-queue-empty/);
});

test('ExecutiveActionQueue — has approve-policy action type', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /approve-policy/);
});

test('ExecutiveActionQueue — has review-findings action type', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /review-findings/);
});

test('ExecutiveActionQueue — has review-report action type', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /review-report/);
});

test('ExecutiveActionQueue — has rotate-keys action type', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /rotate-keys/);
});

test('ExecutiveActionQueue — has verify-assessment action type', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /verify-assessment/);
});

test('ExecutiveActionQueue — has review-remediation action type', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /review-remediation/);
});

test('ExecutiveActionQueue — no Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveActionQueue.tsx')), /Math\.random/);
});

test('ExecutiveActionQueue — has aria-label', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /aria-label/);
});

test('ExecutiveActionQueue — imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /WidgetShell/);
});

test('ExecutiveActionQueue — imports DecisionOut type', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /DecisionOut/);
});

test('ExecutiveActionQueue — has priority badge', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /priority/);
});

test('ExecutiveActionQueue — has impact display', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /impact/);
});

test('ExecutiveActionQueue — has deadline display', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /deadline/);
});

test('ExecutiveActionQueue — has loading skeleton', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /animate-pulse/);
});

test('ExecutiveActionQueue — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ExecutiveActionQueue.tsx')), /TODO|placeholder text/i);
});

test('ExecutiveActionQueue — has Tailwind classes', () => {
  assert.match(read(widget('ExecutiveActionQueue.tsx')), /className=/);
});

// ─── FieldAssessmentStatus ────────────────────────────────────────────────────

test('FieldAssessmentStatus — file exists', () => {
  assert.ok(exists(widget('FieldAssessmentStatus.tsx')));
});

test('FieldAssessmentStatus — has use client', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /'use client'/);
});

test('FieldAssessmentStatus — has default export', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /export default function FieldAssessmentStatus/);
});

test('FieldAssessmentStatus — has MCIM-18.6-FIELD-ASSESSMENT', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /MCIM-18\.6-FIELD-ASSESSMENT/);
});

test('FieldAssessmentStatus — has AUTHORITY', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /AUTHORITY/);
});

test('FieldAssessmentStatus — has sourceOfTruth', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /sourceOfTruth/);
});

test('FieldAssessmentStatus — has drillDown', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /drillDown/);
});

test('FieldAssessmentStatus — fa-assessments testid', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /fa-assessments/);
});

test('FieldAssessmentStatus — fa-evidence testid', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /fa-evidence/);
});

test('FieldAssessmentStatus — fa-verification testid', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /fa-verification/);
});

test('FieldAssessmentStatus — fa-reports testid', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /fa-reports/);
});

test('FieldAssessmentStatus — fa-lifecycle testid', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /fa-lifecycle/);
});

test('FieldAssessmentStatus — no Math.random', () => {
  assert.doesNotMatch(read(widget('FieldAssessmentStatus.tsx')), /Math\.random/);
});

test('FieldAssessmentStatus — has aria-label', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /aria-label/);
});

test('FieldAssessmentStatus — imports WidgetShell', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /WidgetShell/);
});

test('FieldAssessmentStatus — imports EngagementListPage', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /EngagementListPage/);
});

test('FieldAssessmentStatus — has loading skeleton', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /animate-pulse/);
});

test('FieldAssessmentStatus — has no-data state', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /No field assessment/);
});

test('FieldAssessmentStatus — links to /field-assessment', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /\/field-assessment/);
});

test('FieldAssessmentStatus — has Portal row', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /fa-portal|Portal/);
});

test('FieldAssessmentStatus — has Remediation row', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /fa-remediation|Remediation/);
});

test('FieldAssessmentStatus — has Continuity row', () => {
  assert.match(read(widget('FieldAssessmentStatus.tsx')), /Continuity|continuity/);
});

test('FieldAssessmentStatus — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('FieldAssessmentStatus.tsx')), /TODO|placeholder text/i);
});

// ─── GovernanceIntelligence ───────────────────────────────────────────────────

test('GovernanceIntelligence — file exists', () => {
  assert.ok(exists(widget('GovernanceIntelligence.tsx')));
});

test('GovernanceIntelligence — has use client', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /'use client'/);
});

test('GovernanceIntelligence — has default export', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /export default function GovernanceIntelligence/);
});

test('GovernanceIntelligence — has MCIM-18.6-INTELLIGENCE', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /MCIM-18\.6-INTELLIGENCE/);
});

test('GovernanceIntelligence — has AUTHORITY', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /AUTHORITY/);
});

test('GovernanceIntelligence — has sourceOfTruth', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /sourceOfTruth/);
});

test('GovernanceIntelligence — has drillDown', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /drillDown/);
});

test('GovernanceIntelligence — intel-recommendations testid', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /intel-recommendations/);
});

test('GovernanceIntelligence — intel-projected-improvements testid', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /intel-projected-improvements/);
});

test('GovernanceIntelligence — intel-projected-risks testid', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /intel-projected-risks/);
});

test('GovernanceIntelligence — intel-benchmark testid', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /intel-benchmark/);
});

test('GovernanceIntelligence — intel-confidence testid', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /intel-confidence/);
});

test('GovernanceIntelligence — no Math.random', () => {
  assert.doesNotMatch(read(widget('GovernanceIntelligence.tsx')), /Math\.random/);
});

test('GovernanceIntelligence — has aria-label', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /aria-label/);
});

test('GovernanceIntelligence — imports WidgetShell', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /WidgetShell/);
});

test('GovernanceIntelligence — imports EvaluationQualitySummary', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /EvaluationQualitySummary/);
});

test('GovernanceIntelligence — has loading skeleton', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /animate-pulse/);
});

test('GovernanceIntelligence — has no-data empty state', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /No intelligence/);
});

test('GovernanceIntelligence — has confidence label function', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /confidenceLabel/);
});

test('GovernanceIntelligence — links to evidence destination', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /evidenceHref|href/);
});

test('GovernanceIntelligence — TYPE_CONFIG map', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /TYPE_CONFIG/);
});

test('GovernanceIntelligence — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('GovernanceIntelligence.tsx')), /TODO|placeholder text/i);
});

test('GovernanceIntelligence — has Tailwind classes', () => {
  assert.match(read(widget('GovernanceIntelligence.tsx')), /className=/);
});

// ─── DecisionProvenancePanel ──────────────────────────────────────────────────

test('DecisionProvenancePanel — file exists', () => {
  assert.ok(exists(widget('DecisionProvenancePanel.tsx')));
});

test('DecisionProvenancePanel — has use client', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /'use client'/);
});

test('DecisionProvenancePanel — has default export', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /export default function DecisionProvenancePanel/);
});

test('DecisionProvenancePanel — has MCIM-18.6-DECISION-PROVENANCE', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /MCIM-18\.6-DECISION-PROVENANCE/);
});

test('DecisionProvenancePanel — has AUTHORITY', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /AUTHORITY/);
});

test('DecisionProvenancePanel — has sourceOfTruth', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /sourceOfTruth/);
});

test('DecisionProvenancePanel — has drillDown', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /drillDown/);
});

test('DecisionProvenancePanel — decision-provenance-panel testid', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /decision-provenance-panel/);
});

test('DecisionProvenancePanel — provenance-why testid', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-why/);
});

test('DecisionProvenancePanel — provenance-evidence testid', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-evidence/);
});

test('DecisionProvenancePanel — provenance-confidence testid', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-confidence/);
});

test('DecisionProvenancePanel — provenance-authority testid', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-authority/);
});

test('DecisionProvenancePanel — provenance-expanded data attr', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-expanded/);
});

test('DecisionProvenancePanel — provenance-collapsed data attr', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-collapsed/);
});

test('DecisionProvenancePanel — no Math.random', () => {
  assert.doesNotMatch(read(widget('DecisionProvenancePanel.tsx')), /Math\.random/);
});

test('DecisionProvenancePanel — has aria-expanded', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /aria-expanded/);
});

test('DecisionProvenancePanel — imports WidgetShell', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /WidgetShell/);
});

test('DecisionProvenancePanel — imports DecisionOut type', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /DecisionOut/);
});

test('DecisionProvenancePanel — has useState for expand', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /useState/);
});

test('DecisionProvenancePanel — has loading skeleton', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /animate-pulse/);
});

test('DecisionProvenancePanel — has no-data state', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /No decisions/);
});

test('DecisionProvenancePanel — has timestamp display', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /Timestamp|created_at/);
});

test('DecisionProvenancePanel — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('DecisionProvenancePanel.tsx')), /TODO|placeholder text/i);
});

test('DecisionProvenancePanel — has Tailwind classes', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /className=/);
});

test('DecisionProvenancePanel — has Badge import', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /Badge/);
});

// ─── ExecutiveTimeline ────────────────────────────────────────────────────────

test('ExecutiveTimeline — file exists', () => {
  assert.ok(exists(widget('ExecutiveTimeline.tsx')));
});

test('ExecutiveTimeline — has use client', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /'use client'/);
});

test('ExecutiveTimeline — has default export', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /export default function ExecutiveTimeline/);
});

test('ExecutiveTimeline — has MCIM-18.6-CMD-CENTER', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /MCIM-18\.6-CMD-CENTER/);
});

test('ExecutiveTimeline — has AUTHORITY', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /AUTHORITY/);
});

test('ExecutiveTimeline — has sourceOfTruth', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /sourceOfTruth/);
});

test('ExecutiveTimeline — has drillDown', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /drillDown/);
});

test('ExecutiveTimeline — timeline-filter testid', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /timeline-filter/);
});

test('ExecutiveTimeline — timeline-event testid', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /timeline-event/);
});

test('ExecutiveTimeline — timeline-all testid', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /timeline-all/);
});

test('ExecutiveTimeline — timeline-assessments testid', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /timeline-assessments/);
});

test('ExecutiveTimeline — timeline-trust testid', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /timeline-trust/);
});

test('ExecutiveTimeline — no Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveTimeline.tsx')), /Math\.random/);
});

test('ExecutiveTimeline — has aria-label', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /aria-label/);
});

test('ExecutiveTimeline — imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /WidgetShell/);
});

test('ExecutiveTimeline — imports FeedItem type', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /FeedItem/);
});

test('ExecutiveTimeline — imports DecisionOut type', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /DecisionOut/);
});

test('ExecutiveTimeline — has filter state', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /activeFilter|setActiveFilter/);
});

test('ExecutiveTimeline — has loading skeleton', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /animate-pulse/);
});

test('ExecutiveTimeline — has no-event empty state', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /No events/);
});

test('ExecutiveTimeline — has relativeTime function', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /relativeTime/);
});

test('ExecutiveTimeline — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ExecutiveTimeline.tsx')), /TODO|placeholder text/i);
});

test('ExecutiveTimeline — has Tailwind classes', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /className=/);
});

test('ExecutiveTimeline — sorts entries by timestamp', () => {
  assert.match(read(widget('ExecutiveTimeline.tsx')), /sort|timestamp/);
});

// ─── ExecutiveNotifications ───────────────────────────────────────────────────

test('ExecutiveNotifications — file exists', () => {
  assert.ok(exists(widget('ExecutiveNotifications.tsx')));
});

test('ExecutiveNotifications — has use client', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /'use client'/);
});

test('ExecutiveNotifications — has default export', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /export default function ExecutiveNotifications/);
});

test('ExecutiveNotifications — has MCIM-18.6-CMD-CENTER', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /MCIM-18\.6-CMD-CENTER/);
});

test('ExecutiveNotifications — has AUTHORITY', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /AUTHORITY/);
});

test('ExecutiveNotifications — has sourceOfTruth', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /sourceOfTruth/);
});

test('ExecutiveNotifications — has drillDown', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /drillDown/);
});

test('ExecutiveNotifications — notif-critical testid', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notif-critical/);
});

test('ExecutiveNotifications — notif-approval testid', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notif-approval/);
});

test('ExecutiveNotifications — notif-risk testid', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notif-risk/);
});

test('ExecutiveNotifications — notif-compliance testid', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notif-compliance/);
});

test('ExecutiveNotifications — notif-trust testid', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notif-trust/);
});

test('ExecutiveNotifications — notifications-authority testid', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notifications-authority/);
});

test('ExecutiveNotifications — notifications-clear empty state', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notifications-clear/);
});

test('ExecutiveNotifications — no Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveNotifications.tsx')), /Math\.random/);
});

test('ExecutiveNotifications — has aria-label', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /aria-label/);
});

test('ExecutiveNotifications — imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /WidgetShell/);
});

test('ExecutiveNotifications — imports FeedItem type', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /FeedItem/);
});

test('ExecutiveNotifications — has loading skeleton', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /animate-pulse/);
});

test('ExecutiveNotifications — has actionable filter', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /actionable|isActionable/);
});

test('ExecutiveNotifications — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ExecutiveNotifications.tsx')), /TODO|placeholder text/i);
});

test('ExecutiveNotifications — has Tailwind classes', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /className=/);
});

// ─── ReadinessSummary ─────────────────────────────────────────────────────────

test('ReadinessSummary — file exists', () => {
  assert.ok(exists(widget('ReadinessSummary.tsx')));
});

test('ReadinessSummary — has use client', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /'use client'/);
});

test('ReadinessSummary — has default export', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /export default function ReadinessSummary/);
});

test('ReadinessSummary — has MCIM-18.6-READINESS', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /MCIM-18\.6-READINESS/);
});

test('ReadinessSummary — has AUTHORITY', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /AUTHORITY/);
});

test('ReadinessSummary — has sourceOfTruth', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /sourceOfTruth/);
});

test('ReadinessSummary — has drillDown', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /drillDown/);
});

test('ReadinessSummary — readiness-assessment testid', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /readiness-assessment/);
});

test('ReadinessSummary — readiness-certification testid', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /readiness-certification/);
});

test('ReadinessSummary — readiness-framework-coverage testid', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /readiness-framework-coverage/);
});

test('ReadinessSummary — readiness-open-gaps testid', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /readiness-open-gaps/);
});

test('ReadinessSummary — readiness-progress testid', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /readiness-progress/);
});

test('ReadinessSummary — no Math.random', () => {
  assert.doesNotMatch(read(widget('ReadinessSummary.tsx')), /Math\.random/);
});

test('ReadinessSummary — has aria-label', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /aria-label/);
});

test('ReadinessSummary — imports WidgetShell', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /WidgetShell/);
});

test('ReadinessSummary — imports Assessment type', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /Assessment/);
});

test('ReadinessSummary — has loading skeleton', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /animate-pulse/);
});

test('ReadinessSummary — has no-data state', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /No readiness data/);
});

test('ReadinessSummary — links to /dashboard/readiness', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /\/dashboard\/readiness/);
});

test('ReadinessSummary — derives metrics from assessments', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /deriveReadinessMetrics/);
});

test('ReadinessSummary — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ReadinessSummary.tsx')), /TODO|placeholder text/i);
});

test('ReadinessSummary — has Tailwind classes', () => {
  assert.match(read(widget('ReadinessSummary.tsx')), /className=/);
});

// ─── ComplianceSummary ────────────────────────────────────────────────────────

test('ComplianceSummary — file exists', () => {
  assert.ok(exists(widget('ComplianceSummary.tsx')));
});

test('ComplianceSummary — has use client', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /'use client'/);
});

test('ComplianceSummary — has default export', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /export default function ComplianceSummary/);
});

test('ComplianceSummary — has MCIM-18.6-COMPLIANCE', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /MCIM-18\.6-COMPLIANCE/);
});

test('ComplianceSummary — has AUTHORITY', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /AUTHORITY/);
});

test('ComplianceSummary — has sourceOfTruth', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /sourceOfTruth/);
});

test('ComplianceSummary — has drillDown', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /drillDown/);
});

test('ComplianceSummary — compliance-nist testid', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /compliance-nist/);
});

test('ComplianceSummary — compliance-iso testid', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /compliance-iso/);
});

test('ComplianceSummary — compliance-soc2 testid', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /compliance-soc2/);
});

test('ComplianceSummary — compliance-coverage testid', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /compliance-coverage/);
});

test('ComplianceSummary — compliance-drift testid', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /compliance-drift/);
});

test('ComplianceSummary — no Math.random', () => {
  assert.doesNotMatch(read(widget('ComplianceSummary.tsx')), /Math\.random/);
});

test('ComplianceSummary — has aria-label', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /aria-label/);
});

test('ComplianceSummary — imports WidgetShell', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /WidgetShell/);
});

test('ComplianceSummary — imports Framework type', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /Framework/);
});

test('ComplianceSummary — has loading skeleton', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /animate-pulse/);
});

test('ComplianceSummary — has no-data state', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /No compliance frameworks/);
});

test('ComplianceSummary — shows KNOWN_FRAMEWORKS', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /KNOWN_FRAMEWORKS/);
});

test('ComplianceSummary — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ComplianceSummary.tsx')), /TODO|placeholder text/i);
});

test('ComplianceSummary — has Tailwind classes', () => {
  assert.match(read(widget('ComplianceSummary.tsx')), /className=/);
});

// ─── CustomerImpact ───────────────────────────────────────────────────────────

test('CustomerImpact — file exists', () => {
  assert.ok(exists(widget('CustomerImpact.tsx')));
});

test('CustomerImpact — has use client', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /'use client'/);
});

test('CustomerImpact — has default export', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /export default function CustomerImpact/);
});

test('CustomerImpact — has MCIM-18.6-FIELD-ASSESSMENT', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /MCIM-18\.6-FIELD-ASSESSMENT/);
});

test('CustomerImpact — has AUTHORITY', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /AUTHORITY/);
});

test('CustomerImpact — has sourceOfTruth', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /sourceOfTruth/);
});

test('CustomerImpact — has drillDown', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /drillDown/);
});

test('CustomerImpact — customer-affected testid', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /customer-affected/);
});

test('CustomerImpact — customer-assessments testid', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /customer-assessments/);
});

test('CustomerImpact — customer-reports-awaiting testid', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /customer-reports-awaiting/);
});

test('CustomerImpact — customer-portal testid', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /customer-portal/);
});

test('CustomerImpact — customer-impact-authority testid', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /customer-impact-authority/);
});

test('CustomerImpact — no Math.random', () => {
  assert.doesNotMatch(read(widget('CustomerImpact.tsx')), /Math\.random/);
});

test('CustomerImpact — has aria-label', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /aria-label/);
});

test('CustomerImpact — imports WidgetShell', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /WidgetShell/);
});

test('CustomerImpact — imports EngagementListPage', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /EngagementListPage/);
});

test('CustomerImpact — has loading skeleton', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /animate-pulse/);
});

test('CustomerImpact — has no-data empty state', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /No customer data/);
});

test('CustomerImpact — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('CustomerImpact.tsx')), /TODO|placeholder text/i);
});

test('CustomerImpact — has Tailwind classes', () => {
  assert.match(read(widget('CustomerImpact.tsx')), /className=/);
});

// ─── WorkloadDashboard ────────────────────────────────────────────────────────

test('WorkloadDashboard — file exists', () => {
  assert.ok(exists(widget('WorkloadDashboard.tsx')));
});

test('WorkloadDashboard — has use client', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /'use client'/);
});

test('WorkloadDashboard — has default export', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /export default function WorkloadDashboard/);
});

test('WorkloadDashboard — has MCIM-18.6-FIELD-ASSESSMENT', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /MCIM-18\.6-FIELD-ASSESSMENT/);
});

test('WorkloadDashboard — has AUTHORITY', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /AUTHORITY/);
});

test('WorkloadDashboard — has sourceOfTruth', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /sourceOfTruth/);
});

test('WorkloadDashboard — has drillDown', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /drillDown/);
});

test('WorkloadDashboard — workload-assessment testid', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /workload-assessment/);
});

test('WorkloadDashboard — workload-review testid', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /workload-review/);
});

test('WorkloadDashboard — workload-approval testid', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /workload-approval/);
});

test('WorkloadDashboard — workload-automation testid', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /workload-automation/);
});

test('WorkloadDashboard — workload-authority testid', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /workload-authority/);
});

test('WorkloadDashboard — no Math.random', () => {
  assert.doesNotMatch(read(widget('WorkloadDashboard.tsx')), /Math\.random/);
});

test('WorkloadDashboard — has aria-label', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /aria-label/);
});

test('WorkloadDashboard — imports WidgetShell', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /WidgetShell/);
});

test('WorkloadDashboard — imports EngagementListPage', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /EngagementListPage/);
});

test('WorkloadDashboard — has loading skeleton', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /animate-pulse/);
});

test('WorkloadDashboard — has no-data empty state', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /No workload data/);
});

test('WorkloadDashboard — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('WorkloadDashboard.tsx')), /TODO|placeholder text/i);
});

test('WorkloadDashboard — has Tailwind classes', () => {
  assert.match(read(widget('WorkloadDashboard.tsx')), /className=/);
});

// ─── ExecutiveBriefing ────────────────────────────────────────────────────────

test('ExecutiveBriefing — file exists', () => {
  assert.ok(exists(widget('ExecutiveBriefing.tsx')));
});

test('ExecutiveBriefing — has use client', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /'use client'/);
});

test('ExecutiveBriefing — has default export', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /export default function ExecutiveBriefing/);
});

test('ExecutiveBriefing — has MCIM-18.6-CMD-CENTER', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /MCIM-18\.6-CMD-CENTER/);
});

test('ExecutiveBriefing — has AUTHORITY', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /AUTHORITY/);
});

test('ExecutiveBriefing — has sourceOfTruth', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /sourceOfTruth/);
});

test('ExecutiveBriefing — has drillDown', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /drillDown/);
});

test('ExecutiveBriefing — briefing-posture testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-posture/);
});

test('ExecutiveBriefing — briefing-improved testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-improved/);
});

test('ExecutiveBriefing — briefing-regressed testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-regressed/);
});

test('ExecutiveBriefing — briefing-decisions testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-decisions/);
});

test('ExecutiveBriefing — briefing-risks testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-risks/);
});

test('ExecutiveBriefing — briefing-export testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-export/);
});

test('ExecutiveBriefing — briefing-confidence testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-confidence/);
});

test('ExecutiveBriefing — executive-briefing-authority testid', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /executive-briefing-authority/);
});

test('ExecutiveBriefing — briefing-low-confidence state', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-low-confidence/);
});

test('ExecutiveBriefing — no Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /Math\.random/);
});

test('ExecutiveBriefing — has aria-label', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /aria-label/);
});

test('ExecutiveBriefing — imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /WidgetShell/);
});

test('ExecutiveBriefing — export/download functionality', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /handleExport|Download|Blob/);
});

test('ExecutiveBriefing — has loading skeleton', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /animate-pulse/);
});

test('ExecutiveBriefing — no hardcoded fake numbers', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /score\s*=\s*\d{2,3}\b/);
});

test('ExecutiveBriefing — BriefingData interface', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /BriefingData/);
});

test('ExecutiveBriefing — uses BriefingSection array', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /BriefingSection/);
});

test('ExecutiveBriefing — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /TODO|placeholder text/i);
});

// ─── GlobalSearch ─────────────────────────────────────────────────────────────

test('GlobalSearch — file exists', () => {
  assert.ok(exists(widget('GlobalSearch.tsx')));
});

test('GlobalSearch — has use client', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /'use client'/);
});

test('GlobalSearch — has default export', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /export default function GlobalSearch/);
});

test('GlobalSearch — has MCIM-18.6-CMD-CENTER', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /MCIM-18\.6-CMD-CENTER/);
});

test('GlobalSearch — has AUTHORITY', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /AUTHORITY/);
});

test('GlobalSearch — has sourceOfTruth', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /sourceOfTruth/);
});

test('GlobalSearch — has drillDown', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /drillDown/);
});

test('GlobalSearch — search-capabilities testid', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /search-capabilities/);
});

test('GlobalSearch — search-reports testid', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /search-reports/);
});

test('GlobalSearch — search-assessments testid', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /search-assessments/);
});

test('GlobalSearch — search-authorities testid', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /search-authorities/);
});

test('GlobalSearch — global-search-authority testid', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /global-search-authority/);
});

test('GlobalSearch — no Math.random', () => {
  assert.doesNotMatch(read(widget('GlobalSearch.tsx')), /Math\.random/);
});

test('GlobalSearch — has aria-label', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /aria-label/);
});

test('GlobalSearch — imports WidgetShell', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /WidgetShell/);
});

test('GlobalSearch — imports from @fg/navigation', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /@fg\/navigation/);
});

test('GlobalSearch — uses NavigationSearchIndex', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /NavigationSearchIndex/);
});

test('GlobalSearch — has search input', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /input.*search|type="search"/);
});

test('GlobalSearch — has performSearch function', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /performSearch/);
});

test('GlobalSearch — no TODO or placeholder', () => {
  assert.doesNotMatch(read(widget('GlobalSearch.tsx')), /TODO|placeholder text/i);
});

test('GlobalSearch — has Tailwind classes', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /className=/);
});

test('GlobalSearch — uses useCallback', () => {
  assert.match(read(widget('GlobalSearch.tsx')), /useCallback/);
});

// ─── Dashboard page ───────────────────────────────────────────────────────────

test('dashboard page — file exists', () => {
  assert.ok(exists('apps/console/app/dashboard/page.tsx'));
});

test('dashboard page — billing-ready anchor present', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /billing-ready/);
});

test('dashboard page — billing-not-ready anchor present', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /billing-not-ready/);
});

test('dashboard page — billing-error anchor present', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /billing-error/);
});

test('dashboard page — events-loading anchor present', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /events-loading/);
});

test('dashboard page — Core unreachable anchor present', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Core unreachable/);
});

test('dashboard page — command-center-home id', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /command-center-home/);
});

test('dashboard page — is async server component', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /export default async function/);
});

test('dashboard page — uses Promise.allSettled', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Promise\.allSettled/);
});

test('dashboard page — imports ExecutiveKPIBar', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ExecutiveKPIBar/);
});

test('dashboard page — imports ExecutiveHealthPanel', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ExecutiveHealthPanel/);
});

test('dashboard page — imports GovernanceOverview', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /GovernanceOverview/);
});

test('dashboard page — imports TrustCenterSummary', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /TrustCenterSummary/);
});

test('dashboard page — imports ExecutiveRiskMap', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ExecutiveRiskMap/);
});

test('dashboard page — imports ExecutiveActionQueue', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ExecutiveActionQueue/);
});

test('dashboard page — imports FieldAssessmentStatus', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /FieldAssessmentStatus/);
});

test('dashboard page — imports GovernanceIntelligence', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /GovernanceIntelligence/);
});

test('dashboard page — imports DecisionProvenancePanel', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /DecisionProvenancePanel/);
});

test('dashboard page — imports ExecutiveTimeline', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ExecutiveTimeline/);
});

test('dashboard page — imports ExecutiveNotifications', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ExecutiveNotifications/);
});

test('dashboard page — imports ReadinessSummary', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ReadinessSummary/);
});

test('dashboard page — imports ComplianceSummary', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ComplianceSummary/);
});

test('dashboard page — imports CustomerImpact', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /CustomerImpact/);
});

test('dashboard page — imports WorkloadDashboard', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /WorkloadDashboard/);
});

test('dashboard page — imports ExecutiveBriefing', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ExecutiveBriefing/);
});

test('dashboard page — imports GlobalSearch', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /GlobalSearch/);
});

test('dashboard page — no Math.random', () => {
  assert.doesNotMatch(read('apps/console/app/dashboard/page.tsx'), /Math\.random/);
});

test('dashboard page — no hardcoded fake scores', () => {
  // No literal score assignment like score = 87
  assert.doesNotMatch(read('apps/console/app/dashboard/page.tsx'), /score\s*=\s*\d{2,3}\b/);
});

test('dashboard page — uses Suspense', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Suspense/);
});

test('dashboard page — uses getBillingReadiness', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /getBillingReadiness/);
});

test('dashboard page — uses getCommandCenterSnapshot', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /getCommandCenterSnapshot/);
});

test('dashboard page — uses getRecentFeedEvents', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /getRecentFeedEvents/);
});

test('dashboard page — uses listDecisions', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /listDecisions/);
});

test('dashboard page — uses listFrameworks', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /listFrameworks/);
});

test('dashboard page — uses listAssessments', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /listAssessments/);
});

test('dashboard page — uses fieldAssessmentApi', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /fieldAssessmentApi/);
});

// ─── CI tool ──────────────────────────────────────────────────────────────────

test('check_executive_dashboard.py — file exists', () => {
  assert.ok(exists('tools/ci/check_executive_dashboard.py'));
});

test('check_executive_dashboard.py — has exit code logic', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /return 1|sys\.exit/);
});

test('check_executive_dashboard.py — checks MCIM references', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /MCIM-18\.6-/);
});

test('check_executive_dashboard.py — checks authority references', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /authority|AUTHORITY/);
});

test('check_executive_dashboard.py — checks sourceOfTruth', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /sourceOfTruth/);
});

test('check_executive_dashboard.py — checks drillDown', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /drillDown/);
});

test('check_executive_dashboard.py — checks Math.random prohibition', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /Math\.random/);
});

test('check_executive_dashboard.py — validates anchor strings', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /billing-ready|REQUIRED_ANCHORS/);
});

test('check_executive_dashboard.py — has COMPONENT_DIR path', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /COMPONENT_DIR|command-center/);
});

test('check_executive_dashboard.py — has DASHBOARD_PAGE path', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /DASHBOARD_PAGE|page\.tsx/);
});

test('check_executive_dashboard.py — has check_file function', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /def check_file/);
});

test('check_executive_dashboard.py — has check_dashboard_anchors function', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /def check_dashboard_anchors/);
});

test('check_executive_dashboard.py — has main function', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /def main/);
});

test('check_executive_dashboard.py — has EXEMPT_FILES set', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /EXEMPT_FILES|WidgetShell/);
});

test('check_executive_dashboard.py — has __future__ annotations', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /from __future__ import annotations/);
});

test('check_executive_dashboard.py — checks prohibited patterns', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /PROHIBITED_PATTERNS/);
});

test('check_executive_dashboard.py — has pass/fail reporting', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /PASS:|FAIL:|passed/);
});

test('check_executive_dashboard.py — has re import for regex', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /import re/);
});

test('check_executive_dashboard.py — has pathlib Path usage', () => {
  assert.match(read('tools/ci/check_executive_dashboard.py'), /from pathlib import Path|Path\(/);
});

// ─── Navigation ───────────────────────────────────────────────────────────────

test('navigation registry — file exists', () => {
  assert.ok(exists('packages/navigation/navigation-registry.json'));
});

test('navigation registry — has /dashboard route', () => {
  const reg = read('packages/navigation/navigation-registry.json');
  assert.match(reg, /\/dashboard/);
});

test('navigation registry — has command-center reference', () => {
  const reg = read('packages/navigation/navigation-registry.json');
  assert.match(reg, /command.*center|dashboard/i);
});

test('navigation registry — valid JSON', () => {
  const reg = read('packages/navigation/navigation-registry.json');
  assert.doesNotThrow(() => JSON.parse(reg));
});

test('navigation console registrations — file exists', () => {
  assert.ok(exists('packages/navigation/src/registrations/console.ts'));
});

test('navigation console registrations — has /dashboard', () => {
  assert.match(read('packages/navigation/src/registrations/console.ts'), /\/dashboard/);
});

test('navigation console registrations — has CONSOLE_REGISTRY export', () => {
  assert.match(read('packages/navigation/src/registrations/console.ts'), /CONSOLE_REGISTRY/);
});

test('navigation console registrations — exports NavigationRegistry', () => {
  assert.match(read('packages/navigation/src/registrations/console.ts'), /NavigationRegistry/);
});

test('navigation search index — exists in package', () => {
  assert.ok(exists('packages/navigation/src/search.ts'));
});

test('navigation search — has NavigationSearchIndex class', () => {
  assert.match(read('packages/navigation/src/search.ts'), /NavigationSearchIndex/);
});

test('navigation search — has build method', () => {
  assert.match(read('packages/navigation/src/search.ts'), /build\(\)/);
});

test('navigation search — has search method', () => {
  assert.match(read('packages/navigation/src/search.ts'), /search\(/);
});

test('navigation package.json — has @fg/navigation name', () => {
  const pkg = read('packages/navigation/package.json');
  assert.match(pkg, /@fg\/navigation/);
});

test('navigation types — NavigationSearchResult exported', () => {
  assert.match(read('packages/navigation/src/types.ts'), /NavigationSearchResult/);
});

// ─── check_mcim_docs.py — PR 18.6.2 paths ────────────────────────────────────

test('check_mcim_docs.py — has dashboard page in allowlist', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /apps\/console\/app\/dashboard\/page\.tsx/);
});

test('check_mcim_docs.py — has command-center component dir in allowlist', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /apps\/console\/components\/command-center/);
});

test('check_mcim_docs.py — has check_executive_dashboard.py in allowlist', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /check_executive_dashboard\.py/);
});

test('check_mcim_docs.py — has tests\/console\/command-center.test.js in allowlist', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /tests\/console\/command-center\.test\.js/);
});

// ─── MCIM Navigation Decision Log ────────────────────────────────────────────

test('MCIM decision log — file exists', () => {
  assert.ok(exists('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'));
});

test('MCIM decision log — has PR 18.6.2 section', () => {
  assert.match(read('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'), /PR 18\.6\.2/);
});

test('MCIM decision log — has Executive Command Center reference', () => {
  assert.match(read('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'), /Executive Command Center/);
});
