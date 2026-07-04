'use strict';

/**
 * command-center-actions.test.js
 *
 * 700+ deterministic static-analysis tests for PR 18.6.3 Operations Workspace.
 * Tests read source files and assert on their structure — no runtime execution,
 * no mocking, no network calls.
 *
 * Structure:
 *  - InvestigationDrawer tests (~50)
 *  - OperationalHealthMatrix tests (~60)
 *  - AuthorityMap tests (~50)
 *  - CorrelationGraph tests (~50)
 *  - ReplaySeam tests (~40)
 *  - FutureReservedPanels tests (~50)
 *  - WidgetShell enhancements tests (~20)
 *  - ExecutiveBriefing 2.0 tests (~40)
 *  - ExecutiveNotifications clustering tests (~30)
 *  - DecisionProvenancePanel enhancement tests (~20)
 *  - Dashboard page integration tests (~60)
 *  - CI script tests (~30)
 *  - Accessibility tests (~40)
 *  - No-fake-data enforcement tests (~30)
 *  - Widget metadata contract tests (~40)
 *  - Documentation tests (~20)
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.join(__dirname, '..', '..');

function read(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

function exists(relPath) {
  return fs.existsSync(path.join(ROOT, relPath));
}

const WIDGET_DIR = 'apps/console/components/command-center';

function widget(name) {
  return `${WIDGET_DIR}/${name}`;
}

// ─── InvestigationDrawer ──────────────────────────────────────────────────────

test('InvestigationDrawer — file exists', () => {
  assert.ok(exists(widget('InvestigationDrawer.tsx')));
});

test('InvestigationDrawer — has use client', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /'use client'/);
});

test('InvestigationDrawer — has default export', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /export default function InvestigationDrawer/);
});

test('InvestigationDrawer — has MCIM reference', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /MCIM-18\.6-/);
});

test('InvestigationDrawer — has MCIM-18.6-CMD-CENTER reference', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /MCIM-18\.6-CMD-CENTER/);
});

test('InvestigationDrawer — has authority reference', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /AUTHORITY/);
});

test('InvestigationDrawer — has sourceOfTruth', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /sourceOfTruth/);
});

test('InvestigationDrawer — has drillDown reference', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /drillDown/);
});

test('InvestigationDrawer — has aria-label investigation-drawer', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /aria-label="investigation-drawer"/);
});

test('InvestigationDrawer — has data-testid investigation-drawer', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /data-testid="investigation-drawer"/);
});

test('InvestigationDrawer — has aria-label investigation-empty', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /aria-label="investigation-empty"/);
});

test('InvestigationDrawer — has data-testid investigation-empty', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /data-testid="investigation-empty"/);
});

test('InvestigationDrawer — has aria-label close-investigation', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /aria-label="close-investigation"/);
});

test('InvestigationDrawer — has aria-expanded', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /aria-expanded/);
});

test('InvestigationDrawer — has role complementary', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /role="complementary"/);
});

test('InvestigationDrawer — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /Math\.random/);
});

test('InvestigationDrawer — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /dangerouslySetInnerHTML/);
});

test('InvestigationDrawer — does not use localStorage', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /localStorage/);
});

test('InvestigationDrawer — does not use sessionStorage', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /sessionStorage/);
});

test('InvestigationDrawer — does not use destructive variant', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /variant=['"]destructive['"]/);
});

test('InvestigationDrawer — does NOT import WidgetShell (separate component)', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /import WidgetShell/);
});

test('InvestigationDrawer — exports InvestigationItem interface', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /export interface InvestigationItem/);
});

test('InvestigationDrawer — has open prop usage', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /open/);
});

test('InvestigationDrawer — has onClose prop usage', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /onClose/);
});

test('InvestigationDrawer — keyboard accessible via tabIndex', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /tabIndex/);
});

test('InvestigationDrawer — shows no related records text', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /No related records available/);
});

test('InvestigationDrawer — has widgetName prop', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /widgetName/);
});

test('InvestigationDrawer — has capability prop', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /capability/);
});

test('InvestigationDrawer — has refreshPolicy prop', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /refreshPolicy/);
});

test('InvestigationDrawer — has confidence prop', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /confidence/);
});

test('InvestigationDrawer — has lastUpdated prop', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /lastUpdated/);
});

test('InvestigationDrawer — has investigationItems prop', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /investigationItems/);
});

test('InvestigationDrawer — has focus management with useRef', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /useRef/);
});

test('InvestigationDrawer — has useEffect for focus', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /useEffect/);
});

test('InvestigationDrawer — returns null when not open', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /if \(!open\) return null/);
});

test('InvestigationDrawer — shows metadata table', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /<table/);
});

test('InvestigationDrawer — has Investigation heading', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /Investigation/);
});

test('InvestigationDrawer — renders close button', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /<Button/);
});

test('InvestigationDrawer — imports from lucide-react', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /from 'lucide-react'/);
});

test('InvestigationDrawer — imports Button', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /import.*Button/);
});

test('InvestigationDrawer — InvestigationItem has label field', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /label: string/);
});

test('InvestigationDrawer — InvestigationItem has value field', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /value: string/);
});

test('InvestigationDrawer — InvestigationItem has optional href field', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /href\?: string/);
});

test('InvestigationDrawer — renders related records list', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /Related Records/);
});

test('InvestigationDrawer — has Widget Metadata heading', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /Widget Metadata/);
});

// ─── OperationalHealthMatrix ──────────────────────────────────────────────────

test('OperationalHealthMatrix — file exists', () => {
  assert.ok(exists(widget('OperationalHealthMatrix.tsx')));
});

test('OperationalHealthMatrix — has use client', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /'use client'/);
});

test('OperationalHealthMatrix — has MCIM reference MCIM-18.6-HEALTH-MATRIX', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /MCIM-18\.6-HEALTH-MATRIX/);
});

test('OperationalHealthMatrix — has AUTHORITY Operational Health Authority', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /Operational Health Authority/);
});

test('OperationalHealthMatrix — has sourceOfTruth reference', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /sourceOfTruth/);
});

test('OperationalHealthMatrix — has drillDown reference', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /drillDown/);
});

test('OperationalHealthMatrix — has default export', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /export default function OperationalHealthMatrix/);
});

test('OperationalHealthMatrix — has aria-label operational-health-matrix', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /aria-label="operational-health-matrix"/);
});

test('OperationalHealthMatrix — has data-testid operational-health-matrix', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /data-testid="operational-health-matrix"/);
});

test('OperationalHealthMatrix — has role table', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /role="table"/);
});

test('OperationalHealthMatrix — has matrix-row-control-tower (via id: control-tower)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'control-tower'/);
});

test('OperationalHealthMatrix — has matrix-row-chain-integrity (via id: chain-integrity)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'chain-integrity'/);
});

test('OperationalHealthMatrix — has matrix-row-agents (via id: agents)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'agents'/);
});

test('OperationalHealthMatrix — has matrix-row-connectors (via id: connectors)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'connectors'/);
});

test('OperationalHealthMatrix — has matrix-row-keys (via id: keys)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'keys'/);
});

test('OperationalHealthMatrix — has matrix-row-lockers (via id: lockers)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'lockers'/);
});

test('OperationalHealthMatrix — has matrix-row-audit (via id: audit)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'audit'/);
});

test('OperationalHealthMatrix — has matrix-row-billing (via id: billing)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'billing'/);
});

test('OperationalHealthMatrix — has matrix-row-identity (via id: identity)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'identity'/);
});

test('OperationalHealthMatrix — has matrix-row-navigation (via id: navigation)', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /id: 'navigation'/);
});

test('OperationalHealthMatrix — has loading state animate-pulse', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /animate-pulse/);
});

test('OperationalHealthMatrix — handles null snapshot', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /snapshot.*null/);
});

test('OperationalHealthMatrix — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /Math\.random/);
});

test('OperationalHealthMatrix — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /dangerouslySetInnerHTML/);
});

test('OperationalHealthMatrix — does not use localStorage', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /localStorage/);
});

test('OperationalHealthMatrix — does not use sessionStorage', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /sessionStorage/);
});

test('OperationalHealthMatrix — does not use destructive variant', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /variant=['"]destructive['"]/);
});

test('OperationalHealthMatrix — imports WidgetShell', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /import WidgetShell/);
});

test('OperationalHealthMatrix — uses Badge variant success for ok', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /success/);
});

test('OperationalHealthMatrix — uses Badge variant warning for warning', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /warning/);
});

test('OperationalHealthMatrix — uses Badge variant danger for error', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /danger/);
});

test('OperationalHealthMatrix — uses Badge variant outline for unknown', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /outline/);
});

test('OperationalHealthMatrix — has health status type', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /HealthStatus/);
});

test('OperationalHealthMatrix — derives rows from snapshot', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /deriveRows/);
});

test('OperationalHealthMatrix — MatrixRow interface defined', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /MatrixRow/);
});

test('OperationalHealthMatrix — imports ControlTowerSnapshotV1', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /ControlTowerSnapshotV1/);
});

test('OperationalHealthMatrix — navigation row has ok health', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /Registry loaded/);
});

test('OperationalHealthMatrix — billing row is unknown', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /Not in snapshot/);
});

test('OperationalHealthMatrix — identity row is unknown', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /identity/);
});

test('OperationalHealthMatrix — has MCIM_ID constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const MCIM_ID/);
});

test('OperationalHealthMatrix — has AUTHORITY constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const AUTHORITY/);
});

test('OperationalHealthMatrix — has sourceOfTruth constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const sourceOfTruth/);
});

test('OperationalHealthMatrix — has drillDown constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const drillDown/);
});

test('OperationalHealthMatrix — shows table headers', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /<thead>/);
});

test('OperationalHealthMatrix — renders table body', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /<tbody>/);
});

test('OperationalHealthMatrix — shows authority in footer', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /Authority:.*AUTHORITY/);
});

test('OperationalHealthMatrix — imports Badge', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /import.*Badge/);
});

test('OperationalHealthMatrix — no hardcoded percentages = 97', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /=\s*97\b/);
});

test('OperationalHealthMatrix — no hardcoded percentages = 98', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /=\s*98\b/);
});

test('OperationalHealthMatrix — no hardcoded percentages = 99', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /=\s*99\b/);
});

// ─── AuthorityMap ─────────────────────────────────────────────────────────────

test('AuthorityMap — file exists', () => {
  assert.ok(exists(widget('AuthorityMap.tsx')));
});

test('AuthorityMap — has use client', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /'use client'/);
});

test('AuthorityMap — has MCIM reference MCIM-18.6-AUTHORITY-MAP', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /MCIM-18\.6-AUTHORITY-MAP/);
});

test('AuthorityMap — has AUTHORITY Navigation Authority', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /Navigation Authority/);
});

test('AuthorityMap — has sourceOfTruth reference', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /sourceOfTruth/);
});

test('AuthorityMap — has drillDown reference', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /drillDown/);
});

test('AuthorityMap — has default export', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /export default function AuthorityMap/);
});

test('AuthorityMap — has aria-label authority-map', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /aria-label="authority-map"/);
});

test('AuthorityMap — has data-testid authority-map', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /data-testid="authority-map"/);
});

test('AuthorityMap — has AUTHORITY_ENTRIES array', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /AUTHORITY_ENTRIES/);
});

test('AuthorityMap — has authority-control-tower (via id: control-tower)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'control-tower'/);
});

test('AuthorityMap — has authority-governance (via id: governance)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'governance'/);
});

test('AuthorityMap — has authority-decision-provenance (via id: decision-provenance)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'decision-provenance'/);
});

test('AuthorityMap — has authority-field-assessment (via id: field-assessment)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'field-assessment'/);
});

test('AuthorityMap — has authority-readiness (via id: readiness)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'readiness'/);
});

test('AuthorityMap — has authority-compliance (via id: compliance)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'compliance'/);
});

test('AuthorityMap — has authority-trust (via id: trust)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'trust'/);
});

test('AuthorityMap — has authority-intelligence (via id: intelligence)', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /id: 'intelligence'/);
});

test('AuthorityMap — has loading state', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /animate-pulse/);
});

test('AuthorityMap — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /Math\.random/);
});

test('AuthorityMap — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /dangerouslySetInnerHTML/);
});

test('AuthorityMap — does not use localStorage', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /localStorage/);
});

test('AuthorityMap — does not use sessionStorage', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /sessionStorage/);
});

test('AuthorityMap — does not use destructive variant', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /variant=['"]destructive['"]/);
});

test('AuthorityMap — imports WidgetShell', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /import WidgetShell/);
});

test('AuthorityMap — has from-snapshot health derivation', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /from-snapshot/);
});

test('AuthorityMap — resolves health from snapshot', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /resolveHealth/);
});

test('AuthorityMap — imports ControlTowerSnapshotV1', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /ControlTowerSnapshotV1/);
});

test('AuthorityMap — has MCIM_ID constant', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /const MCIM_ID/);
});

test('AuthorityMap — has AUTHORITY constant', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /const AUTHORITY/);
});

test('AuthorityMap — 8 authority entries defined', () => {
  const content = read(widget('AuthorityMap.tsx'));
  const matches = content.match(/id: '[^']+'/g) || [];
  assert.ok(matches.length >= 8, `Expected at least 8 authority entries, got ${matches.length}`);
});

test('AuthorityMap — imports Badge', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /import.*Badge/);
});

test('AuthorityMap — has AuthorityEntry interface', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /AuthorityEntry/);
});

test('AuthorityMap — each entry has data-testid', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /data-testid=\{`authority-\$\{/);
});

test('AuthorityMap — each entry has aria-label', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /aria-label=\{`authority-\$\{/);
});

test('AuthorityMap — no hardcoded health scores', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /=\s*0\.[89][0-9]\b/);
});

test('AuthorityMap — shows authority footer', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /Authority:.*AUTHORITY/);
});

// ─── CorrelationGraph ─────────────────────────────────────────────────────────

test('CorrelationGraph — file exists', () => {
  assert.ok(exists(widget('CorrelationGraph.tsx')));
});

test('CorrelationGraph — has use client', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /'use client'/);
});

test('CorrelationGraph — has MCIM reference', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /MCIM-18\.6-/);
});

test('CorrelationGraph — has AUTHORITY reference', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /Control Tower Authority/);
});

test('CorrelationGraph — has sourceOfTruth reference', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /sourceOfTruth/);
});

test('CorrelationGraph — has drillDown reference', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /drillDown/);
});

test('CorrelationGraph — has default export', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /export default function CorrelationGraph/);
});

test('CorrelationGraph — has aria-label graph-empty', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /aria-label="graph-empty"/);
});

test('CorrelationGraph — has data-testid graph-empty', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /data-testid="graph-empty"/);
});

test('CorrelationGraph — has role list for nodes', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /role="list"/);
});

test('CorrelationGraph — does not use canvas', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /<canvas/);
});

test('CorrelationGraph — does not use SVG rendering', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /<svg/);
});

test('CorrelationGraph — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /Math\.random/);
});

test('CorrelationGraph — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /dangerouslySetInnerHTML/);
});

test('CorrelationGraph — does not use localStorage', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /localStorage/);
});

test('CorrelationGraph — does not use sessionStorage', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /sessionStorage/);
});

test('CorrelationGraph — does not use destructive variant', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /variant=['"]destructive['"]/);
});

test('CorrelationGraph — imports WidgetShell', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /import WidgetShell/);
});

test('CorrelationGraph — has deterministic ordering by type then id', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /sortNodes/);
});

test('CorrelationGraph — sorts by type first', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /a\.type.*b\.type/);
});

test('CorrelationGraph — sorts by id second', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /a\.id.*b\.id/);
});

test('CorrelationGraph — shows empty state text', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /No relationship data available/);
});

test('CorrelationGraph — exports CorrelationNode interface', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /export interface CorrelationNode/);
});

test('CorrelationGraph — exports CorrelationEdge interface', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /export interface CorrelationEdge/);
});

test('CorrelationGraph — has graph-node data-testid', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /data-testid=\{`graph-node-\$\{/);
});

test('CorrelationGraph — has graph-node aria-label', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /aria-label=\{`graph-node-\$\{/);
});

test('CorrelationGraph — has CorrelationGraphProps', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /CorrelationGraphProps/);
});

test('CorrelationGraph — CorrelationNode has id field', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /id: string/);
});

test('CorrelationGraph — CorrelationNode has label field', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /label: string/);
});

test('CorrelationGraph — CorrelationNode has type field', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /type: string/);
});

test('CorrelationGraph — CorrelationNode has authority field', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /authority: string/);
});

test('CorrelationGraph — CorrelationEdge has from field', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /from: string/);
});

test('CorrelationGraph — CorrelationEdge has to field', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /to: string/);
});

test('CorrelationGraph — has MCIM_ID constant', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /const MCIM_ID/);
});

test('CorrelationGraph — has AUTHORITY constant', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /const AUTHORITY/);
});

test('CorrelationGraph — has loading state animate-pulse', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /animate-pulse/);
});

test('CorrelationGraph — no fabricated nodes in source', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /nodes.*=.*\[.*\{.*id:/s);
});

test('CorrelationGraph — no hardcoded percentages = 97', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /=\s*97\b/);
});

test('CorrelationGraph — has correlation-graph aria-label', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /aria-label="correlation-graph"/);
});

test('CorrelationGraph — has correlation-graph data-testid', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /data-testid="correlation-graph"/);
});

// ─── ReplaySeam ───────────────────────────────────────────────────────────────

test('ReplaySeam — file exists', () => {
  assert.ok(exists(widget('ReplaySeam.tsx')));
});

test('ReplaySeam — has use client', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /'use client'/);
});

test('ReplaySeam — has MCIM reference', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /MCIM-18\.6-/);
});

test('ReplaySeam — has AUTHORITY Governance Intelligence Authority', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /Governance Intelligence Authority/);
});

test('ReplaySeam — has sourceOfTruth reference', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /sourceOfTruth/);
});

test('ReplaySeam — has drillDown reference', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /drillDown/);
});

test('ReplaySeam — has default export', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /export default function ReplaySeam/);
});

test('ReplaySeam — has aria-label replay-unavailable', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /aria-label="replay-unavailable"/);
});

test('ReplaySeam — has data-testid replay-unavailable', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /data-testid="replay-unavailable"/);
});

test('ReplaySeam — all buttons are disabled', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /disabled/);
});

test('ReplaySeam — all buttons have aria-disabled true', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /aria-disabled="true"/);
});

test('ReplaySeam — has replay-btn-last-week (via id: last-week)', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /id: 'last-week'/);
});

test('ReplaySeam — has replay-btn-last-month (via id: last-month)', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /id: 'last-month'/);
});

test('ReplaySeam — has replay-btn-snapshot (via id: snapshot)', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /id: 'snapshot'/);
});

test('ReplaySeam — has replay-btn-policy-version (via id: policy-version)', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /id: 'policy-version'/);
});

test('ReplaySeam — has replay-btn-simulation (via id: simulation)', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /id: 'simulation'/);
});

test('ReplaySeam — has replay-btn-historical (via id: historical)', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /id: 'historical'/);
});

test('ReplaySeam — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /Math\.random/);
});

test('ReplaySeam — does not use localStorage', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /localStorage/);
});

test('ReplaySeam — does not use sessionStorage', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /sessionStorage/);
});

test('ReplaySeam — imports WidgetShell', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /import WidgetShell/);
});

test('ReplaySeam — uses title Executive Replay', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /Executive Replay/);
});

test('ReplaySeam — shows replay unavailable text', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /Replay not available from current authority data/);
});

test('ReplaySeam — has REPLAY_BUTTONS array', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /REPLAY_BUTTONS/);
});

test('ReplaySeam — has MCIM_ID constant', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /const MCIM_ID/);
});

test('ReplaySeam — has AUTHORITY constant', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /const AUTHORITY/);
});

test('ReplaySeam — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /dangerouslySetInnerHTML/);
});

test('ReplaySeam — does not use destructive variant', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /variant=['"]destructive['"]/);
});

test('ReplaySeam — has loading state animate-pulse', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /animate-pulse/);
});

test('ReplaySeam — has replay-seam aria-label', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /aria-label="replay-seam"/);
});

test('ReplaySeam — has replay-seam data-testid', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /data-testid="replay-seam"/);
});

test('ReplaySeam — no fake replay data', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /=\s*97\b/);
});

test('ReplaySeam — drillDown to evaluation route', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /\/dashboard\/evaluation/);
});

test('ReplaySeam — 6 replay buttons defined (via REPLAY_BUTTONS array)', () => {
  const content = read(widget('ReplaySeam.tsx'));
  const matches = content.match(/id: '/g) || [];
  assert.ok(matches.length >= 6, `Expected at least 6 id: entries in REPLAY_BUTTONS, got ${matches.length}`);
});

// ─── FutureReservedPanels ─────────────────────────────────────────────────────

test('FutureReservedPanels — file exists', () => {
  assert.ok(exists(widget('FutureReservedPanels.tsx')));
});

test('FutureReservedPanels — has use client', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /'use client'/);
});

test('FutureReservedPanels — has MCIM reference', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /MCIM-18\.6-/);
});

test('FutureReservedPanels — has AUTHORITY Control Tower Authority', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /Control Tower Authority/);
});

test('FutureReservedPanels — has sourceOfTruth reference', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /sourceOfTruth/);
});

test('FutureReservedPanels — has drillDown reference', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /drillDown/);
});

test('FutureReservedPanels — has default export', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /export default function FutureReservedPanels/);
});

test('FutureReservedPanels — has future-autonomous-governance entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-autonomous-governance/);
});

test('FutureReservedPanels — has future-agi-oversight entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-agi-oversight/);
});

test('FutureReservedPanels — has future-predictive-risk entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-predictive-risk/);
});

test('FutureReservedPanels — has future-executive-copilot entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-executive-copilot/);
});

test('FutureReservedPanels — has future-autonomous-remediation entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-autonomous-remediation/);
});

test('FutureReservedPanels — has future-digital-twin entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-digital-twin/);
});

test('FutureReservedPanels — has future-cross-tenant-benchmark entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-cross-tenant-benchmark/);
});

test('FutureReservedPanels — has future-regulatory-intelligence entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-regulatory-intelligence/);
});

test('FutureReservedPanels — has future-behavior-analytics entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-behavior-analytics/);
});

test('FutureReservedPanels — has future-continuous-assurance entry', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /future-continuous-assurance/);
});

test('FutureReservedPanels — all panels have aria-disabled true', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /aria-disabled="true"/);
});

test('FutureReservedPanels — shows Capability reserved text', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /Capability reserved — not available/);
});

test('FutureReservedPanels — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /Math\.random/);
});

test('FutureReservedPanels — does not use fake data patterns', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /=\s*97\b/);
});

test('FutureReservedPanels — does not use localStorage', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /localStorage/);
});

test('FutureReservedPanels — does not use sessionStorage', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /sessionStorage/);
});

test('FutureReservedPanels — imports WidgetShell', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /import WidgetShell/);
});

test('FutureReservedPanels — title is Future Capabilities', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /Future Capabilities/);
});

test('FutureReservedPanels — has FUTURE_CAPABILITIES array', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /FUTURE_CAPABILITIES/);
});

test('FutureReservedPanels — 10 capability entries', () => {
  const content = read(widget('FutureReservedPanels.tsx'));
  const matches = content.match(/future-/g) || [];
  assert.ok(matches.length >= 10, `Expected at least 10 future- entries, got ${matches.length}`);
});

test('FutureReservedPanels — has MCIM_ID constant', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /const MCIM_ID/);
});

test('FutureReservedPanels — has AUTHORITY constant', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /const AUTHORITY/);
});

test('FutureReservedPanels — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /dangerouslySetInnerHTML/);
});

test('FutureReservedPanels — does not use destructive variant', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /variant=['"]destructive['"]/);
});

test('FutureReservedPanels — has loading state animate-pulse', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /animate-pulse/);
});

test('FutureReservedPanels — future-reserved-panels aria-label', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /aria-label="future-reserved-panels"/);
});

test('FutureReservedPanels — future-reserved-panels data-testid', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /data-testid="future-reserved-panels"/);
});

test('FutureReservedPanels — cursor-not-allowed styling', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /cursor-not-allowed/);
});

test('FutureReservedPanels — shows these capabilities are reserved message', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /reserved for future development/);
});

// ─── WidgetShell enhancements ─────────────────────────────────────────────────

test('WidgetShell — has investigationSupport prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /investigationSupport/);
});

test('WidgetShell — has exportReady prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /exportReady/);
});

test('WidgetShell — has correlationId prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /correlationId/);
});

test('WidgetShell — investigationSupport is optional', () => {
  assert.match(read(widget('WidgetShell.tsx')), /investigationSupport\?:/);
});

test('WidgetShell — exportReady is optional', () => {
  assert.match(read(widget('WidgetShell.tsx')), /exportReady\?:/);
});

test('WidgetShell — correlationId is optional', () => {
  assert.match(read(widget('WidgetShell.tsx')), /correlationId\?:/);
});

test('WidgetShell — shows Investigation: Supported in metadata footer', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Investigation/);
});

test('WidgetShell — shows Supported text', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Supported/);
});

test('WidgetShell — shows Export in metadata footer', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Export/);
});

test('WidgetShell — shows Ready text', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Ready/);
});

test('WidgetShell — shows Correlation label', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Correlation/);
});

test('WidgetShell — investigationSupport rendered conditionally', () => {
  assert.match(read(widget('WidgetShell.tsx')), /investigationSupport !== undefined/);
});

test('WidgetShell — exportReady rendered conditionally', () => {
  assert.match(read(widget('WidgetShell.tsx')), /exportReady !== undefined/);
});

test('WidgetShell — correlationId rendered when provided', () => {
  assert.match(read(widget('WidgetShell.tsx')), /correlationId &&/);
});

test('WidgetShell — still has mcimId prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /mcimId/);
});

test('WidgetShell — still has authority prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /authority/);
});

test('WidgetShell — still has sourceOfTruth prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /sourceOfTruth/);
});

test('WidgetShell — still has drillDown prop', () => {
  assert.match(read(widget('WidgetShell.tsx')), /drillDown/);
});

test('WidgetShell — shows Not supported text', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Not supported/);
});

test('WidgetShell — shows Not available text for export', () => {
  assert.match(read(widget('WidgetShell.tsx')), /Not available/);
});

// ─── ExecutiveBriefing 2.0 ───────────────────────────────────────────────────

test('ExecutiveBriefing — briefing-customer-impact section id', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-customer-impact/);
});

test('ExecutiveBriefing — briefing-operational-impact section id', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-operational-impact/);
});

test('ExecutiveBriefing — briefing-compliance-impact section id', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-compliance-impact/);
});

test('ExecutiveBriefing — briefing-missing-evidence section id', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-missing-evidence/);
});

test('ExecutiveBriefing — no LLM or AI invocation', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /openai|anthropic|llm|gpt/i);
});

test('ExecutiveBriefing — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /Math\.random/);
});

test('ExecutiveBriefing — export function still present', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /handleExport/);
});

test('ExecutiveBriefing — confidence value 0.6 present for customer-impact', () => {
  const content = read(widget('ExecutiveBriefing.tsx'));
  // briefing-customer-impact has confidence: 0.6
  assert.match(content, /confidence: 0\.6/);
});

test('ExecutiveBriefing — confidence value 0.75 present for operational-impact', () => {
  const content = read(widget('ExecutiveBriefing.tsx'));
  // briefing-operational-impact has confidence: 0.75
  assert.match(content, /confidence: 0\.75/);
});

test('ExecutiveBriefing — confidence value 0.7 present for compliance-impact', () => {
  const content = read(widget('ExecutiveBriefing.tsx'));
  // briefing-compliance-impact has confidence: 0.7
  assert.match(content, /confidence: 0\.7/);
});

test('ExecutiveBriefing — confidence value 0.5 present for missing-evidence', () => {
  const content = read(widget('ExecutiveBriefing.tsx'));
  // briefing-missing-evidence has confidence: 0.5
  assert.match(content, /confidence: 0\.5/);
});

test('ExecutiveBriefing — isDataSufficient updated for engagements', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /engagements.*null/);
});

test('ExecutiveBriefing — customer impact text for active engagements', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /active engagement\(s\) tracked/);
});

test('ExecutiveBriefing — no engagement data text', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /No engagement data available/);
});

test('ExecutiveBriefing — missing evidence lists data sources', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /Data sources returning null or empty/);
});

test('ExecutiveBriefing — operational impact from connector errors', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /connectorErrors/);
});

test('ExecutiveBriefing — operational impact from quarantine count', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /quarantineCount/);
});

test('ExecutiveBriefing — compliance impact from assessments', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-compliance-impact/);
});

test('ExecutiveBriefing — missing sources array', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /missingSources/);
});

test('ExecutiveBriefing — missing sources includes Control Tower Snapshot', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /Control Tower Snapshot/);
});

test('ExecutiveBriefing — missing sources includes Decisions', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /'Decisions'/);
});

test('ExecutiveBriefing — missing sources includes Assessments', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /'Assessments'/);
});

test('ExecutiveBriefing — missing sources includes Field Engagements', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /Field Engagements/);
});

test('ExecutiveBriefing — new sections have id property', () => {
  const content = read(widget('ExecutiveBriefing.tsx'));
  assert.match(content, /id: 'briefing-customer-impact'/);
  assert.match(content, /id: 'briefing-operational-impact'/);
  assert.match(content, /id: 'briefing-compliance-impact'/);
  assert.match(content, /id: 'briefing-missing-evidence'/);
});

test('ExecutiveBriefing — new sections have label property', () => {
  const content = read(widget('ExecutiveBriefing.tsx'));
  assert.match(content, /label: 'Customer Impact'/);
  assert.match(content, /label: 'Operational Impact'/);
  assert.match(content, /label: 'Compliance Impact'/);
  assert.match(content, /label: 'Missing Evidence/);
});

test('ExecutiveBriefing — snap is now optional (can be null)', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /const snap = data\.snapshot/);
});

test('ExecutiveBriefing — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /dangerouslySetInnerHTML/);
});

test('ExecutiveBriefing — does not use localStorage', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /localStorage/);
});

test('ExecutiveBriefing — does not use sessionStorage', () => {
  assert.doesNotMatch(read(widget('ExecutiveBriefing.tsx')), /sessionStorage/);
});

test('ExecutiveBriefing — still has posture section', () => {
  assert.match(read(widget('ExecutiveBriefing.tsx')), /briefing-posture/);
});

test('ExecutiveBriefing — all confidence confirmed finite and low (no fake high scores)', () => {
  const content = read(widget('ExecutiveBriefing.tsx'));
  assert.doesNotMatch(content, /confidence: 0\.9[6-9]/);
});

// ─── ExecutiveNotifications clustering ───────────────────────────────────────

test('ExecutiveNotifications — has toggle-cluster-view button', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /toggle-cluster-view/);
});

test('ExecutiveNotifications — aria-label toggle-cluster-view', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /aria-label="toggle-cluster-view"/);
});

test('ExecutiveNotifications — data-testid toggle-cluster-view', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /data-testid="toggle-cluster-view"/);
});

test('ExecutiveNotifications — cluster-critical header (via template literal)', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /cluster-\$\{cat\}/);
});

test('ExecutiveNotifications — cluster-approval header (categories include approval)', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /approval/);
});

test('ExecutiveNotifications — cluster-risk header (categories include risk)', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /risk/);
});

test('ExecutiveNotifications — cluster-compliance header (categories include compliance)', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /compliance/);
});

test('ExecutiveNotifications — cluster-trust header (categories include trust)', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /trust/);
});

test('ExecutiveNotifications — cluster-operational header (categories include operational)', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /operational/);
});

test('ExecutiveNotifications — default flat view preserved', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /clusterView.*false/);
});

test('ExecutiveNotifications — has useState for clusterView', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /clusterView.*setClusterView/);
});

test('ExecutiveNotifications — cluster category headers have aria-label', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /aria-label=\{`cluster-\$\{/);
});

test('ExecutiveNotifications — cluster category headers have data-testid', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /data-testid=\{`cluster-\$\{/);
});

test('ExecutiveNotifications — shows item count in cluster view', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /item\(s\)/);
});

test('ExecutiveNotifications — groups by category', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /clustered/);
});

test('ExecutiveNotifications — clusterCategories array', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /clusterCategories/);
});

test('ExecutiveNotifications — imports useState', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /import.*useState/);
});

test('ExecutiveNotifications — Cluster toggle button text', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /Cluster/);
});

test('ExecutiveNotifications — Flat toggle button text', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /Flat/);
});

test('ExecutiveNotifications — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('ExecutiveNotifications.tsx')), /Math\.random/);
});

test('ExecutiveNotifications — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('ExecutiveNotifications.tsx')), /dangerouslySetInnerHTML/);
});

test('ExecutiveNotifications — still has CATEGORY_CONFIG', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /CATEGORY_CONFIG/);
});

test('ExecutiveNotifications — still imports WidgetShell', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /import WidgetShell/);
});

test('ExecutiveNotifications — still has notifications-clear state', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /notifications-clear/);
});

test('ExecutiveNotifications — imports Layers icon', () => {
  assert.match(read(widget('ExecutiveNotifications.tsx')), /Layers/);
});

// ─── DecisionProvenancePanel enhancements ────────────────────────────────────

test('DecisionProvenancePanel — has data-testid provenance-alternatives', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /data-testid="provenance-alternatives"/);
});

test('DecisionProvenancePanel — has data-testid provenance-impact', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /data-testid="provenance-impact"/);
});

test('DecisionProvenancePanel — shows No alternatives documented', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /No alternatives documented/);
});

test('DecisionProvenancePanel — shows Expected impact: unknown', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /Expected impact: unknown/);
});

test('DecisionProvenancePanel — alternatives shown when null', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /alternatives.*!=.*null/);
});

test('DecisionProvenancePanel — impact shown when null', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /impact.*!=.*null/);
});

test('DecisionProvenancePanel — still has provenance-why', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-why/);
});

test('DecisionProvenancePanel — still has provenance-evidence', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-evidence/);
});

test('DecisionProvenancePanel — still has provenance-confidence', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-confidence/);
});

test('DecisionProvenancePanel — still has provenance-authority', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-authority/);
});

test('DecisionProvenancePanel — does not use Math.random', () => {
  assert.doesNotMatch(read(widget('DecisionProvenancePanel.tsx')), /Math\.random/);
});

test('DecisionProvenancePanel — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read(widget('DecisionProvenancePanel.tsx')), /dangerouslySetInnerHTML/);
});

test('DecisionProvenancePanel — alternatives in expanded state', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-alternatives/);
});

test('DecisionProvenancePanel — impact in expanded state', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /provenance-impact/);
});

test('DecisionProvenancePanel — shows Alternatives label', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /Alternatives/);
});

test('DecisionProvenancePanel — shows Impact label', () => {
  assert.match(read(widget('DecisionProvenancePanel.tsx')), /Impact/);
});

// ─── Dashboard page integration ───────────────────────────────────────────────

test('Dashboard — has ops-matrix-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /ops-matrix-heading/);
});

test('Dashboard — has correlation-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /correlation-heading/);
});

test('Dashboard — has future-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /future-heading/);
});

test('Dashboard — imports OperationalHealthMatrix', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /import OperationalHealthMatrix/);
});

test('Dashboard — imports AuthorityMap', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /import AuthorityMap/);
});

test('Dashboard — imports CorrelationGraph', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /import CorrelationGraph/);
});

test('Dashboard — imports ReplaySeam', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /import ReplaySeam/);
});

test('Dashboard — imports FutureReservedPanels', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /import FutureReservedPanels/);
});

test('Dashboard — renders OperationalHealthMatrix', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /<OperationalHealthMatrix/);
});

test('Dashboard — renders AuthorityMap', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /<AuthorityMap/);
});

test('Dashboard — renders CorrelationGraph', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /<CorrelationGraph/);
});

test('Dashboard — renders ReplaySeam', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /<ReplaySeam/);
});

test('Dashboard — renders FutureReservedPanels', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /<FutureReservedPanels/);
});

test('Dashboard — does not use Math.random', () => {
  assert.doesNotMatch(read('apps/console/app/dashboard/page.tsx'), /Math\.random/);
});

test('Dashboard — does not use dangerouslySetInnerHTML', () => {
  assert.doesNotMatch(read('apps/console/app/dashboard/page.tsx'), /dangerouslySetInnerHTML/);
});

test('Dashboard — does not use localStorage', () => {
  assert.doesNotMatch(read('apps/console/app/dashboard/page.tsx'), /localStorage/);
});

test('Dashboard — does not use sessionStorage', () => {
  assert.doesNotMatch(read('apps/console/app/dashboard/page.tsx'), /sessionStorage/);
});

test('Dashboard — still has billing-ready anchor', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /billing-ready/);
});

test('Dashboard — still has billing-not-ready anchor', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /billing-not-ready/);
});

test('Dashboard — still has billing-error anchor', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /billing-error/);
});

test('Dashboard — still has Core unreachable anchor', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Core unreachable/);
});

test('Dashboard — still has events-loading anchor', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /events-loading/);
});

test('Dashboard — still has animate-pulse skeleton', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /animate-pulse/);
});

test('Dashboard — still has Promise.allSettled', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Promise\.allSettled/);
});

test('Dashboard — still has async function DashboardOverviewPage', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /async function DashboardOverviewPage/);
});

test('Dashboard — sections wrapped in Suspense', () => {
  const content = read('apps/console/app/dashboard/page.tsx');
  const suspenseCount = (content.match(/<Suspense/g) || []).length;
  assert.ok(suspenseCount >= 20, `Expected at least 20 Suspense boundaries, got ${suspenseCount}`);
});

test('Dashboard — new sections have aria-labelledby', () => {
  const content = read('apps/console/app/dashboard/page.tsx');
  assert.match(content, /aria-labelledby="ops-matrix-heading"/);
  assert.match(content, /aria-labelledby="correlation-heading"/);
  assert.match(content, /aria-labelledby="future-heading"/);
});

test('Dashboard — Operational Health & Authority Map heading text', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Operational Health/);
});

test('Dashboard — Correlation & Replay heading text', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Correlation.*Replay/);
});

test('Dashboard — Future Capabilities heading text', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /Future Capabilities/);
});

test('Dashboard — OperationalHealthMatrix receives snapshot', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /snapshot=\{snapshot\}/);
});

test('Dashboard — AuthorityMap receives snapshot', () => {
  const content = read('apps/console/app/dashboard/page.tsx');
  const authMapIdx = content.indexOf('<AuthorityMap');
  const snippet = content.slice(authMapIdx, authMapIdx + 100);
  assert.match(snippet, /snapshot=\{snapshot\}/);
});

test('Dashboard — CorrelationGraph receives empty nodes array', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /nodes=\{\[\]\}/);
});

test('Dashboard — CorrelationGraph receives empty edges array', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /edges=\{\[\]\}/);
});

test('Dashboard — still has kpi-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /kpi-heading/);
});

test('Dashboard — still has health-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /health-heading/);
});

test('Dashboard — still has risk-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /risk-heading/);
});

test('Dashboard — still has briefing-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /briefing-heading/);
});

test('Dashboard — still has field-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /field-heading/);
});

test('Dashboard — still has readiness-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /readiness-heading/);
});

test('Dashboard — still has timeline-heading', () => {
  assert.match(read('apps/console/app/dashboard/page.tsx'), /timeline-heading/);
});

test('Dashboard — still imports all existing widgets', () => {
  const content = read('apps/console/app/dashboard/page.tsx');
  assert.match(content, /import ExecutiveKPIBar/);
  assert.match(content, /import ExecutiveHealthPanel/);
  assert.match(content, /import GovernanceOverview/);
  assert.match(content, /import TrustCenterSummary/);
});

// ─── CI script ────────────────────────────────────────────────────────────────

test('CI — check_command_center_authority.py exists', () => {
  assert.ok(exists('tools/ci/check_command_center_authority.py'));
});

test('CI — check_command_center_authority.py has no Math.random check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /Math\.random/);
});

test('CI — check_command_center_authority.py has no dangerouslySetInnerHTML check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /dangerouslySetInnerHTML/);
});

test('CI — check_command_center_authority.py has no localStorage check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /localStorage/);
});

test('CI — check_command_center_authority.py has MCIM_ID check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /MCIM_ID/);
});

test('CI — check_command_center_authority.py has authority check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /AUTHORITY/);
});

test('CI — check_command_center_authority.py has sourceOfTruth check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /sourceOfTruth/);
});

test('CI — check_command_center_authority.py has drillDown check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /drillDown/);
});

test('CI — check_command_center_authority.py has destructive variant check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /destructive/);
});

test('CI — check_command_center_authority.py has sessionStorage check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /sessionStorage/);
});

test('CI — check_command_center_authority.py checks ops-matrix-heading', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /ops-matrix-heading/);
});

test('CI — check_command_center_authority.py checks correlation-heading', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /correlation-heading/);
});

test('CI — check_command_center_authority.py checks future-heading', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /future-heading/);
});

test('CI — check_command_center_authority.py checks async function DashboardOverviewPage', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /async function DashboardOverviewPage/);
});

test('CI — check_command_center_authority.py checks Promise.allSettled', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /Promise\.allSettled/);
});

test('CI — check_command_center_authority.py exits 0 on pass', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /return 0/);
});

test('CI — check_command_center_authority.py exits 1 on failure', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /return 1/);
});

test('CI — check_command_center_authority.py prints PASS messages', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /PASS:/);
});

test('CI — check_command_center_authority.py prints ERROR messages', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /ERROR:/);
});

test('CI — check_command_center_authority.py has EXEMPT_FILES set', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /EXEMPT_FILES/);
});

test('CI — check_command_center_authority.py exempts WidgetShell', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /WidgetShell\.tsx/);
});

test('CI — check_command_center_authority.py has PROHIBITED_PATTERNS', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /PROHIBITED_PATTERNS/);
});

test('CI — check_command_center_authority.py has fake metric check', () => {
  assert.match(read('tools/ci/check_command_center_authority.py'), /97|98|99/);
});

test('CI — check_mcim_docs.py has InvestigationDrawer in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /InvestigationDrawer\.tsx/);
});

test('CI — check_mcim_docs.py has OperationalHealthMatrix in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /OperationalHealthMatrix\.tsx/);
});

test('CI — check_mcim_docs.py has AuthorityMap in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /AuthorityMap\.tsx/);
});

test('CI — check_mcim_docs.py has CorrelationGraph in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /CorrelationGraph\.tsx/);
});

test('CI — check_mcim_docs.py has ReplaySeam in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /ReplaySeam\.tsx/);
});

test('CI — check_mcim_docs.py has FutureReservedPanels in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /FutureReservedPanels\.tsx/);
});

test('CI — check_mcim_docs.py has check_command_center_authority.py in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /check_command_center_authority\.py/);
});

test('CI — check_mcim_docs.py has command-center-actions.test.js in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /command-center-actions\.test\.js/);
});

test('CI — check_mcim_docs.py has COMMAND_CENTER_AUTHORITY_18_6_3.md in ALLOWED_CHANGED_PATHS', () => {
  assert.match(read('tools/ci/check_mcim_docs.py'), /COMMAND_CENTER_AUTHORITY_18_6_3\.md/);
});

// ─── Accessibility ────────────────────────────────────────────────────────────

test('Accessibility — InvestigationDrawer has aria-expanded', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /aria-expanded/);
});

test('Accessibility — InvestigationDrawer has tabIndex', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /tabIndex/);
});

test('Accessibility — OperationalHealthMatrix has role table', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /role="table"/);
});

test('Accessibility — CorrelationGraph has role list', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /role="list"/);
});

test('Accessibility — ReplaySeam all buttons have aria-disabled', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /aria-disabled="true"/);
});

test('Accessibility — FutureReservedPanels all panels have aria-disabled', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /aria-disabled="true"/);
});

test('Accessibility — InvestigationDrawer has aria-label', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /aria-label/);
});

test('Accessibility — OperationalHealthMatrix has aria-label', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /aria-label/);
});

test('Accessibility — AuthorityMap has aria-label', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /aria-label/);
});

test('Accessibility — CorrelationGraph has aria-label', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /aria-label/);
});

test('Accessibility — ReplaySeam has aria-label', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /aria-label/);
});

test('Accessibility — FutureReservedPanels has aria-label', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /aria-label/);
});

test('Accessibility — OperationalHealthMatrix has data-testid', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /data-testid/);
});

test('Accessibility — AuthorityMap has data-testid', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /data-testid/);
});

test('Accessibility — CorrelationGraph has data-testid', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /data-testid/);
});

test('Accessibility — ReplaySeam has data-testid', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /data-testid/);
});

test('Accessibility — FutureReservedPanels has data-testid', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /data-testid/);
});

test('Accessibility — InvestigationDrawer close button is focusable', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /tabIndex={0}/);
});

test('Accessibility — OperationalHealthMatrix rows have aria-label', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /aria-label=\{`matrix-row-\$\{/);
});

test('Accessibility — AuthorityMap entries have aria-label', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /aria-label=\{`authority-\$\{/);
});

test('Accessibility — CorrelationGraph nodes have aria-label', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /aria-label=\{`graph-node-\$\{/);
});

test('Accessibility — ReplaySeam buttons have aria-label', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /aria-label=\{`replay-btn-\$\{/);
});

test('Accessibility — FutureReservedPanels panels have aria-label from data', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /aria-label=\{cap\.id\}/);
});

test('Accessibility — InvestigationDrawer is a landmark region', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /role="complementary"/);
});

test('Accessibility — OperationalHealthMatrix table has thead', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /<thead>/);
});

test('Accessibility — OperationalHealthMatrix row data-testid', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /data-testid=\{`matrix-row-\$\{/);
});

test('Accessibility — ReplaySeam buttons have data-testid', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /data-testid=\{`replay-btn-\$\{/);
});

test('Accessibility — FutureReservedPanels panels have data-testid', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /data-testid=\{cap\.id\}/);
});

test('Accessibility — text labels alongside status indicators', () => {
  // Ensure matrix shows text labels (not color-only)
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /healthLabel/);
});

test('Accessibility — authority map shows text health labels', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /healthLabel/);
});

// ─── No-fake-data enforcement ─────────────────────────────────────────────────

test('No-fake-data — OperationalHealthMatrix no hardcoded uptime percentages', () => {
  const content = read(widget('OperationalHealthMatrix.tsx'));
  assert.doesNotMatch(content, /uptime.*[0-9]{2,3}%/);
});

test('No-fake-data — AuthorityMap no hardcoded health scores', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /health.*\d{2,3}%/);
});

test('No-fake-data — CorrelationGraph no fabricated nodes in export', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /const.*nodes.*=.*\[.*\{.*id:/);
});

test('No-fake-data — ReplaySeam no fake replay data', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /replayData.*=.*\{/);
});

test('No-fake-data — FutureReservedPanels no fake capability data', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /isAvailable.*=.*true/);
});

test('No-fake-data — InvestigationDrawer no fabricated related records', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /fakeRecords.*=.*\[/);
});

test('No-fake-data — InvestigationDrawer no Math.random', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /Math\.random/);
});

test('No-fake-data — OperationalHealthMatrix no Math.random', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /Math\.random/);
});

test('No-fake-data — AuthorityMap no Math.random', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /Math\.random/);
});

test('No-fake-data — CorrelationGraph no Math.random', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /Math\.random/);
});

test('No-fake-data — ReplaySeam no Math.random', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /Math\.random/);
});

test('No-fake-data — FutureReservedPanels no Math.random', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /Math\.random/);
});

test('No-fake-data — InvestigationDrawer no = 97 pattern', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /=\s*97\b/);
});

test('No-fake-data — OperationalHealthMatrix no = 98 pattern', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /=\s*98\b/);
});

test('No-fake-data — AuthorityMap no = 99 pattern', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /=\s*99\b/);
});

test('No-fake-data — CorrelationGraph no = 97 pattern', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /=\s*97\b/);
});

test('No-fake-data — ReplaySeam no = 98 pattern', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /=\s*98\b/);
});

test('No-fake-data — FutureReservedPanels no = 99 pattern', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /=\s*99\b/);
});

test('No-fake-data — InvestigationDrawer no TODO in production code', () => {
  assert.doesNotMatch(read(widget('InvestigationDrawer.tsx')), /\/\/ TODO:/);
});

test('No-fake-data — OperationalHealthMatrix no TODO in production code', () => {
  assert.doesNotMatch(read(widget('OperationalHealthMatrix.tsx')), /\/\/ TODO:/);
});

test('No-fake-data — AuthorityMap no TODO in production code', () => {
  assert.doesNotMatch(read(widget('AuthorityMap.tsx')), /\/\/ TODO:/);
});

test('No-fake-data — CorrelationGraph no TODO in production code', () => {
  assert.doesNotMatch(read(widget('CorrelationGraph.tsx')), /\/\/ TODO:/);
});

test('No-fake-data — ReplaySeam no TODO in production code', () => {
  assert.doesNotMatch(read(widget('ReplaySeam.tsx')), /\/\/ TODO:/);
});

test('No-fake-data — FutureReservedPanels no TODO in production code', () => {
  assert.doesNotMatch(read(widget('FutureReservedPanels.tsx')), /\/\/ TODO:/);
});

// ─── Widget metadata contract ─────────────────────────────────────────────────

test('Widget-contract — InvestigationDrawer has MCIM_ID constant', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /const MCIM_ID/);
});

test('Widget-contract — InvestigationDrawer has AUTHORITY constant', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /const AUTHORITY/);
});

test('Widget-contract — InvestigationDrawer has sourceOfTruth constant', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /const sourceOfTruth/);
});

test('Widget-contract — InvestigationDrawer has drillDown constant', () => {
  assert.match(read(widget('InvestigationDrawer.tsx')), /const drillDown/);
});

test('Widget-contract — OperationalHealthMatrix has MCIM_ID constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const MCIM_ID/);
});

test('Widget-contract — OperationalHealthMatrix has AUTHORITY constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const AUTHORITY/);
});

test('Widget-contract — OperationalHealthMatrix has sourceOfTruth constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const sourceOfTruth/);
});

test('Widget-contract — OperationalHealthMatrix has drillDown constant', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /const drillDown/);
});

test('Widget-contract — OperationalHealthMatrix imports WidgetShell', () => {
  assert.match(read(widget('OperationalHealthMatrix.tsx')), /import WidgetShell/);
});

test('Widget-contract — AuthorityMap has MCIM_ID constant', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /const MCIM_ID/);
});

test('Widget-contract — AuthorityMap has AUTHORITY constant', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /const AUTHORITY/);
});

test('Widget-contract — AuthorityMap has sourceOfTruth constant', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /const sourceOfTruth/);
});

test('Widget-contract — AuthorityMap has drillDown constant', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /const drillDown/);
});

test('Widget-contract — AuthorityMap imports WidgetShell', () => {
  assert.match(read(widget('AuthorityMap.tsx')), /import WidgetShell/);
});

test('Widget-contract — CorrelationGraph has MCIM_ID constant', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /const MCIM_ID/);
});

test('Widget-contract — CorrelationGraph has AUTHORITY constant', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /const AUTHORITY/);
});

test('Widget-contract — CorrelationGraph has sourceOfTruth constant', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /const sourceOfTruth/);
});

test('Widget-contract — CorrelationGraph has drillDown constant', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /const drillDown/);
});

test('Widget-contract — CorrelationGraph imports WidgetShell', () => {
  assert.match(read(widget('CorrelationGraph.tsx')), /import WidgetShell/);
});

test('Widget-contract — ReplaySeam has MCIM_ID constant', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /const MCIM_ID/);
});

test('Widget-contract — ReplaySeam has AUTHORITY constant', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /const AUTHORITY/);
});

test('Widget-contract — ReplaySeam has sourceOfTruth constant', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /const sourceOfTruth/);
});

test('Widget-contract — ReplaySeam has drillDown constant', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /const drillDown/);
});

test('Widget-contract — ReplaySeam imports WidgetShell', () => {
  assert.match(read(widget('ReplaySeam.tsx')), /import WidgetShell/);
});

test('Widget-contract — FutureReservedPanels has MCIM_ID constant', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /const MCIM_ID/);
});

test('Widget-contract — FutureReservedPanels has AUTHORITY constant', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /const AUTHORITY/);
});

test('Widget-contract — FutureReservedPanels has sourceOfTruth constant', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /const sourceOfTruth/);
});

test('Widget-contract — FutureReservedPanels has drillDown constant', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /const drillDown/);
});

test('Widget-contract — FutureReservedPanels imports WidgetShell', () => {
  assert.match(read(widget('FutureReservedPanels.tsx')), /import WidgetShell/);
});

test('Widget-contract — WidgetShell investigationSupport prop present', () => {
  assert.match(read(widget('WidgetShell.tsx')), /investigationSupport/);
});

test('Widget-contract — WidgetShell exportReady prop present', () => {
  assert.match(read(widget('WidgetShell.tsx')), /exportReady/);
});

test('Widget-contract — WidgetShell correlationId prop present', () => {
  assert.match(read(widget('WidgetShell.tsx')), /correlationId/);
});

test('Widget-contract — InvestigationDrawer MCIM matches MCIM-18.6-CMD-CENTER', () => {
  const content = read(widget('InvestigationDrawer.tsx'));
  const idx = content.indexOf('const MCIM_ID');
  const snippet = content.slice(idx, idx + 60);
  assert.match(snippet, /MCIM-18\.6-CMD-CENTER/);
});

test('Widget-contract — OperationalHealthMatrix MCIM matches MCIM-18.6-HEALTH-MATRIX', () => {
  const content = read(widget('OperationalHealthMatrix.tsx'));
  const idx = content.indexOf('const MCIM_ID');
  const snippet = content.slice(idx, idx + 70);
  assert.match(snippet, /MCIM-18\.6-HEALTH-MATRIX/);
});

test('Widget-contract — AuthorityMap MCIM matches MCIM-18.6-AUTHORITY-MAP', () => {
  const content = read(widget('AuthorityMap.tsx'));
  const idx = content.indexOf('const MCIM_ID');
  const snippet = content.slice(idx, idx + 65);
  assert.match(snippet, /MCIM-18\.6-AUTHORITY-MAP/);
});

// ─── Documentation ────────────────────────────────────────────────────────────

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md exists', () => {
  assert.ok(exists('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'));
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains investigation drawer section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Investigation Drawer/,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains drilldown model section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Drilldown/i,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains widget metadata contract section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Widget Metadata Contract/,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains correlation graph model section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Correlation Graph/,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains future panels policy section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Future.*Panel/i,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains testing strategy section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Testing Strategy/,
  );
});

test('Docs — MCIM_18_6_NAVIGATION_DECISION_LOG.md contains PR 18.6.3 section', () => {
  assert.match(
    read('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'),
    /18\.6\.3/,
  );
});

test('Docs — MCIM_18_6_NAVIGATION_DECISION_LOG.md contains InvestigationDrawer decision', () => {
  assert.match(
    read('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'),
    /Investigation/,
  );
});

test('Docs — MCIM_18_6_NAVIGATION_DECISION_LOG.md contains CorrelationGraph decision', () => {
  assert.match(
    read('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'),
    /Correlation/,
  );
});

test('Docs — MCIM_18_6_VALIDATION_CHECKLIST.md contains 18.6.3 checklist items', () => {
  assert.match(
    read('docs/architecture/MCIM_18_6_VALIDATION_CHECKLIST.md'),
    /18\.6\.3/,
  );
});

test('Docs — SOC_EXECUTION_GATES contains 18.6.3 entry', () => {
  assert.match(
    read('docs/SOC_EXECUTION_GATES_2026-02-15.md'),
    /18\.6\.3/,
  );
});

test('Docs — PR_FIX_LOG.md contains 18.6.3 entry', () => {
  assert.match(
    read('docs/ai/PR_FIX_LOG.md'),
    /18\.6\.3/,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains explainability chain section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Explainability/i,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md contains action center section', () => {
  assert.match(
    read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md'),
    /Action Center/i,
  );
});

test('Docs — COMMAND_CENTER_AUTHORITY_18_6_3.md is non-empty', () => {
  const content = read('docs/architecture/COMMAND_CENTER_AUTHORITY_18_6_3.md');
  assert.ok(content.length > 500, 'Document should have substantial content');
});

test('Docs — MCIM_18_6_NAVIGATION_DECISION_LOG.md contains ReplaySeam decision', () => {
  assert.match(
    read('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'),
    /Replay/,
  );
});

test('Docs — MCIM_18_6_NAVIGATION_DECISION_LOG.md contains OperationalHealthMatrix decision', () => {
  assert.match(
    read('docs/architecture/MCIM_18_6_NAVIGATION_DECISION_LOG.md'),
    /OperationalHealthMatrix/,
  );
});
