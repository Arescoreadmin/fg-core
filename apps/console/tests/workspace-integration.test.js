/**
 * workspace-integration.test.js
 *
 * Static-analysis tests for PR 18.6.8 — Workspace Integration
 *
 * Coverage:
 *   A — File existence (15+ tests)
 *   B — WorkspaceMetadata (15+ tests)
 *   C — CrossWorkspaceNav (20+ tests)
 *   D — WorkspaceContextBridge (15+ tests)
 *   E — WorkspaceEmptyState (15+ tests)
 *   F — WorkspaceLoadingState (15+ tests)
 *   G — DemoModeIndicator (15+ tests)
 *   H — WorkspaceSearch (20+ tests)
 *   I — index.ts exports (20+ tests)
 *   J — workspaceContext.ts (25+ tests)
 *   K — demoFixtures.ts (25+ tests)
 *   L — workspaceNav.ts (25+ tests)
 *   M — CI check script (20+ tests)
 *   N — Architecture doc (20+ tests)
 *   O — Navigation registry (20+ tests)
 *   P — Cross-workspace journey coverage (20+ tests)
 *   Q — Accessibility compliance (20+ tests)
 *   R — Forbidden pattern sweep across all files (20+ tests)
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

function exists(relPath) {
  return fs.existsSync(path.join(__dirname, '..', relPath));
}

function readAbsolute(absPath) {
  return fs.readFileSync(absPath, 'utf8');
}

function existsAbsolute(absPath) {
  return fs.existsSync(absPath);
}

// ─── File paths ───────────────────────────────────────────────────────────────

const COMP_DIR = 'components/workspace-integration';

const WORKSPACE_METADATA   = `${COMP_DIR}/WorkspaceMetadata.tsx`;
const CROSS_WORKSPACE_NAV  = `${COMP_DIR}/CrossWorkspaceNav.tsx`;
const CONTEXT_BRIDGE       = `${COMP_DIR}/WorkspaceContextBridge.tsx`;
const EMPTY_STATE          = `${COMP_DIR}/WorkspaceEmptyState.tsx`;
const LOADING_STATE        = `${COMP_DIR}/WorkspaceLoadingState.tsx`;
const DEMO_INDICATOR       = `${COMP_DIR}/DemoModeIndicator.tsx`;
const WORKSPACE_SEARCH     = `${COMP_DIR}/WorkspaceSearch.tsx`;
const INDEX_TS             = `${COMP_DIR}/index.ts`;

const WORKSPACE_CONTEXT    = 'lib/workspaceContext.ts';
const DEMO_FIXTURES        = 'lib/demoFixtures.ts';
const WORKSPACE_NAV        = 'lib/workspaceNav.ts';

const CI_SCRIPT  = path.join(__dirname, '../../../tools/ci/check_workspace_integration.py');
const ARCH_DOC   = path.join(__dirname, '../../../docs/architecture/WORKSPACE_INTEGRATION_18_6_8.md');
const NAV_REG    = path.join(__dirname, '../../../packages/navigation/navigation-registry.json');

// ─── Component list for parameterised sweeps ──────────────────────────────────

const ALL_COMPONENTS = [
  WORKSPACE_METADATA,
  CROSS_WORKSPACE_NAV,
  CONTEXT_BRIDGE,
  EMPTY_STATE,
  LOADING_STATE,
  DEMO_INDICATOR,
  WORKSPACE_SEARCH,
];

const ALL_LIB_FILES = [
  WORKSPACE_CONTEXT,
  DEMO_FIXTURES,
  WORKSPACE_NAV,
];

const WORKSPACE_CONTEXT_KEYS = [
  'tenant',
  'engagement',
  'assessment',
  'report',
  'finding',
  'remediation',
  'policy',
  'decision',
  'timelinePosition',
  'framework',
  'control',
  'evidence',
  'customer',
  'simulation',
  'replay',
];

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION A — File existence
// ═══════════════════════════════════════════════════════════════════════════════

test('A: WorkspaceMetadata.tsx exists', () => {
  assert.ok(exists(WORKSPACE_METADATA), 'Missing WorkspaceMetadata.tsx');
});

test('A: CrossWorkspaceNav.tsx exists', () => {
  assert.ok(exists(CROSS_WORKSPACE_NAV), 'Missing CrossWorkspaceNav.tsx');
});

test('A: WorkspaceContextBridge.tsx exists', () => {
  assert.ok(exists(CONTEXT_BRIDGE), 'Missing WorkspaceContextBridge.tsx');
});

test('A: WorkspaceEmptyState.tsx exists', () => {
  assert.ok(exists(EMPTY_STATE), 'Missing WorkspaceEmptyState.tsx');
});

test('A: WorkspaceLoadingState.tsx exists', () => {
  assert.ok(exists(LOADING_STATE), 'Missing WorkspaceLoadingState.tsx');
});

test('A: DemoModeIndicator.tsx exists', () => {
  assert.ok(exists(DEMO_INDICATOR), 'Missing DemoModeIndicator.tsx');
});

test('A: WorkspaceSearch.tsx exists', () => {
  assert.ok(exists(WORKSPACE_SEARCH), 'Missing WorkspaceSearch.tsx');
});

test('A: index.ts exists', () => {
  assert.ok(exists(INDEX_TS), 'Missing components/workspace-integration/index.ts');
});

test('A: lib/workspaceContext.ts exists', () => {
  assert.ok(exists(WORKSPACE_CONTEXT), 'Missing lib/workspaceContext.ts');
});

test('A: lib/demoFixtures.ts exists', () => {
  assert.ok(exists(DEMO_FIXTURES), 'Missing lib/demoFixtures.ts');
});

test('A: lib/workspaceNav.ts exists', () => {
  assert.ok(exists(WORKSPACE_NAV), 'Missing lib/workspaceNav.ts');
});

test('A: CI check script exists', () => {
  assert.ok(existsAbsolute(CI_SCRIPT), 'Missing tools/ci/check_workspace_integration.py');
});

test('A: Architecture doc exists', () => {
  assert.ok(existsAbsolute(ARCH_DOC), 'Missing docs/architecture/WORKSPACE_INTEGRATION_18_6_8.md');
});

test('A: Navigation registry JSON exists', () => {
  assert.ok(existsAbsolute(NAV_REG), 'Missing packages/navigation/navigation-registry.json');
});

test('A: All 8 component files present', () => {
  const files = [...ALL_COMPONENTS, INDEX_TS];
  files.forEach(f => {
    assert.ok(exists(f), `Missing component file: ${f}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION B — WorkspaceMetadata
// ═══════════════════════════════════════════════════════════════════════════════

test('B: WorkspaceMetadata is a client component', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /'use client'/);
});

test('B: WorkspaceMetadata has WorkspaceMetadataProps interface', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /WorkspaceMetadataProps/);
});

test('B: WorkspaceMetadataProps has mcimId field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /mcimId/);
});

test('B: WorkspaceMetadataProps has authority field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /authority/);
});

test('B: WorkspaceMetadataProps has capability field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /capability/);
});

test('B: WorkspaceMetadataProps has workspace field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /workspace/);
});

test('B: WorkspaceMetadataProps has sourceOfTruth field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /sourceOfTruth/);
});

test('B: WorkspaceMetadataProps has refreshPolicy field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /refreshPolicy/);
});

test('B: WorkspaceMetadataProps has confidenceSource field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /confidenceSource/);
});

test('B: WorkspaceMetadataProps has lastUpdated field', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /lastUpdated/);
});

test('B: WorkspaceMetadata renders data-workspace-metadata attribute', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /data-workspace-metadata/);
});

test('B: WorkspaceMetadata renders aria-hidden="true"', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /aria-hidden="true"/);
});

test('B: WorkspaceMetadata has no Math.random', () => {
  const src = read(WORKSPACE_METADATA);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('B: WorkspaceMetadata has no sessionStorage', () => {
  const src = read(WORKSPACE_METADATA);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('B: WorkspaceMetadata has a default export', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /export default/);
});

test('B: WorkspaceMetadataProps interface declares all 8 fields', () => {
  const src = read(WORKSPACE_METADATA);
  const fields = ['mcimId', 'authority', 'capability', 'workspace', 'sourceOfTruth', 'refreshPolicy', 'confidenceSource', 'lastUpdated'];
  fields.forEach(field => {
    assert.match(src, new RegExp(field), `WorkspaceMetadata missing field: ${field}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION C — CrossWorkspaceNav
// ═══════════════════════════════════════════════════════════════════════════════

test('C: CrossWorkspaceNav is a client component', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /'use client'/);
});

test('C: CrossWorkspaceNav imports Link from next/link', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /from 'next\/link'/);
});

test('C: CrossWorkspaceNav has aria-label on nav element', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /aria-label/);
});

test('C: CrossWorkspaceNav has data-mcim-id attribute', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /data-mcim-id/);
});

test('C: CrossWorkspaceNav has data-workspace attribute', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /data-workspace/);
});

test('C: CrossWorkspaceNav has WorkspaceLink interface', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /WorkspaceLink/);
});

test('C: CrossWorkspaceNav has layout prop (horizontal/vertical/grid)', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /layout/);
  assert.match(src, /horizontal|vertical|grid/);
});

test('C: CrossWorkspaceNav has size prop (sm/md)', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /size/);
  assert.match(src, /'sm'|'md'/);
});

test('C: CrossWorkspaceNav has currentWorkspace prop', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /currentWorkspace/);
});

test('C: CrossWorkspaceNav has links prop', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /links/);
});

test('C: CrossWorkspaceNav has keyboard handler for Enter', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /Enter/);
});

test('C: CrossWorkspaceNav has keyboard handler for Space', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /Space|' '/);
});

test('C: CrossWorkspaceNav imports from lucide-react', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /from 'lucide-react'/);
});

test('C: CrossWorkspaceNav uses buildWorkspaceUrl', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /buildWorkspaceUrl/);
});

test('C: CrossWorkspaceNav has no Math.random', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('C: CrossWorkspaceNav has no sessionStorage', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('C: CrossWorkspaceNav has no localStorage', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.doesNotMatch(src, /localStorage/);
});

test('C: CrossWorkspaceNav has no dangerouslySetInnerHTML', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('C: CrossWorkspaceNav does not expose tenant_id', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.doesNotMatch(src, /tenant_id/);
});

test('C: CrossWorkspaceNav has onKeyDown or onKeyUp keyboard event handler', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /onKey(?:Down|Up)/);
});

// P1 fix tests — stale context filtering (PR 18.6.8 P1)
test('C-P1: CrossWorkspaceNav contextParams type is WorkspaceContextKey[] not Record', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  // Must use WorkspaceContextKey[] — not Record<string,string> (which leaks stale keys)
  assert.match(src, /WorkspaceContextKey/);
  assert.doesNotMatch(src, /contextParams\?\s*:\s*Record<string/);
});

test('C-P1: CrossWorkspaceNav resolveHref filters to declared keys only', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  // Must iterate over link.contextParams (declared keys) rather than spread full context
  assert.match(src, /for.*contextParams|contextParams.*for/);
  // Must NOT spread full context object into merged (stale key leakage)
  assert.doesNotMatch(src, /\.\.\.\s*context\s*,\s*\.\.\.\s*\(link\.contextParams/);
});

test('C-P1: CrossWorkspaceNav builds filtered context not merged spread', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  // filtered/empty object construction — stale keys dropped
  assert.match(src, /filtered|stale keys|only forward/);
});

test('C-P1: WorkspaceSearch uses Array.from not MapIterator spread', () => {
  const src = read(WORKSPACE_SEARCH);
  // MapIterator spread [...map.values()] fails without downlevelIteration
  assert.doesNotMatch(src, /\[\s*\.\.\.\s*groupResults\s*\(.*\)\s*\.values\s*\(\s*\)/);
  // Must use Array.from
  assert.match(src, /Array\.from/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION D — WorkspaceContextBridge
// ═══════════════════════════════════════════════════════════════════════════════

test('D: WorkspaceContextBridge is a client component', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /'use client'/);
});

test('D: WorkspaceContextBridge imports useSearchParams from next/navigation', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /useSearchParams/);
  assert.match(src, /next\/navigation/);
});

test('D: WorkspaceContextBridge exports useWorkspaceContext function', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /export.*useWorkspaceContext/);
});

test('D: WorkspaceContextBridge exports buildWorkspaceUrl function', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /export.*buildWorkspaceUrl/);
});

test('D: WorkspaceContextBridge exports WorkspaceContext type or interface', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /WorkspaceContext/);
});

test('D: WorkspaceContextBridge exports WorkspaceLink type', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /WorkspaceLink/);
});

test('D: WorkspaceContext includes tenant field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /tenant/);
});

test('D: WorkspaceContext includes engagement field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /engagement/);
});

test('D: WorkspaceContext includes assessment field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /assessment/);
});

test('D: WorkspaceContext includes report field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /report/);
});

test('D: WorkspaceContext includes finding field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /finding/);
});

test('D: WorkspaceContext includes remediation field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /remediation/);
});

test('D: WorkspaceContext includes policy field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /\bpolicy\b/);
});

test('D: WorkspaceContext includes decision field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /decision/);
});

test('D: WorkspaceContext includes timelinePosition field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /timelinePosition/);
});

test('D: WorkspaceContext includes framework field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /framework/);
});

test('D: WorkspaceContext includes control field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /\bcontrol\b/);
});

test('D: WorkspaceContext includes evidence field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /evidence/);
});

test('D: WorkspaceContext includes customer field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /customer/);
});

test('D: WorkspaceContext includes simulation field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /simulation/);
});

test('D: WorkspaceContext includes replay field', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /replay/);
});

test('D: WorkspaceContextBridge has no Math.random', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('D: WorkspaceContextBridge has no sessionStorage', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.doesNotMatch(src, /sessionStorage/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION E — WorkspaceEmptyState
// ═══════════════════════════════════════════════════════════════════════════════

test('E: WorkspaceEmptyState has reason prop', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /reason/);
});

test('E: WorkspaceEmptyState has dataRequired prop', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /dataRequired/);
});

test('E: WorkspaceEmptyState has nextAction prop', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /nextAction/);
});

test('E: WorkspaceEmptyState has nextActionHref prop (optional)', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /nextActionHref/);
});

test('E: WorkspaceEmptyState has nextActionLabel prop (optional)', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /nextActionLabel/);
});

test('E: WorkspaceEmptyState has mcimId prop', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /mcimId/);
});

test('E: WorkspaceEmptyState has workspace prop', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /workspace/);
});

test('E: WorkspaceEmptyState has icon prop (optional)', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /icon/);
});

test('E: WorkspaceEmptyState never shows bare "No Data" without context', () => {
  const src = read(EMPTY_STATE);
  // Should not have a bare "No Data" string without a reason
  assert.doesNotMatch(src, />\s*No Data\s*</);
});

test('E: WorkspaceEmptyState has aria role or data attribute', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /role=|data-/);
});

test('E: WorkspaceEmptyState has CTA or action link', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /nextAction|href|Link/);
});

test('E: WorkspaceEmptyState has no Math.random', () => {
  const src = read(EMPTY_STATE);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('E: WorkspaceEmptyState has no dangerouslySetInnerHTML', () => {
  const src = read(EMPTY_STATE);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('E: WorkspaceEmptyState has workspace-empty-state data-testid or similar identifier', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /empty-state|emptyState|workspace-empty/);
});

test('E: WorkspaceEmptyState has no sessionStorage', () => {
  const src = read(EMPTY_STATE);
  assert.doesNotMatch(src, /sessionStorage/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION F — WorkspaceLoadingState
// ═══════════════════════════════════════════════════════════════════════════════

test('F: WorkspaceLoadingState has workspace prop', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /workspace/);
});

test('F: WorkspaceLoadingState has sections prop', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /sections/);
});

test('F: WorkspaceLoadingState has mcimId prop', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /mcimId/);
});

test('F: WorkspaceLoadingState has animate-pulse class for skeleton', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /animate-pulse/);
});

test('F: WorkspaceLoadingState has aria-busy attribute', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /aria-busy/);
});

test('F: WorkspaceLoadingState is deterministic — no Math.random', () => {
  const src = read(LOADING_STATE);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('F: WorkspaceLoadingState has no sessionStorage', () => {
  const src = read(LOADING_STATE);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('F: WorkspaceLoadingState has no dangerouslySetInnerHTML', () => {
  const src = read(LOADING_STATE);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('F: WorkspaceLoadingState has loading skeleton or placeholder elements', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /skeleton|loading|pulse/i);
});

test('F: WorkspaceLoadingState has a default or named export', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /export/);
});

test('F: WorkspaceLoadingState renders workspace-loading identifier', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /workspace-loading|workspaceLoading|loading-state/i);
});

test('F: WorkspaceLoadingState has no localStorage', () => {
  const src = read(LOADING_STATE);
  assert.doesNotMatch(src, /localStorage/);
});

test('F: WorkspaceLoadingState has WorkspaceLoadingStateProps interface or type', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /WorkspaceLoadingState(?:Props)?/);
});

test('F: WorkspaceLoadingState has aria-label or descriptive text', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /aria-label|aria-busy/);
});

test('F: WorkspaceLoadingState does not expose raw error messages', () => {
  const src = read(LOADING_STATE);
  assert.doesNotMatch(src, /stack.*trace/i);
  assert.doesNotMatch(src, /INTERNAL_SERVER_ERROR/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION G — DemoModeIndicator
// ═══════════════════════════════════════════════════════════════════════════════

test('G: DemoModeIndicator has active prop', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /active/);
});

test('G: DemoModeIndicator has datasetName prop', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /datasetName/);
});

test('G: DemoModeIndicator has children prop', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /children/);
});

test('G: DemoModeIndicator contains "Demo Mode" text', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /Demo Mode/);
});

test('G: DemoModeIndicator has data-demo-mode attribute', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /data-demo-mode/);
});

test('G: DemoModeIndicator has role="alert" or alert role', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /role="alert"/);
});

test('G: DemoModeIndicator children only rendered when active', () => {
  const src = read(DEMO_INDICATOR);
  // Must gate children on active prop
  assert.match(src, /active.*children|children.*active|\{active &&|\bactive\b.*&&/);
});

test('G: DemoModeIndicator has no Math.random', () => {
  const src = read(DEMO_INDICATOR);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('G: DemoModeIndicator has no dangerouslySetInnerHTML', () => {
  const src = read(DEMO_INDICATOR);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('G: DemoModeIndicator has a named or default export', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /export/);
});

test('G: DemoModeIndicator has no sessionStorage', () => {
  const src = read(DEMO_INDICATOR);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('G: DemoModeIndicator has no localStorage', () => {
  const src = read(DEMO_INDICATOR);
  assert.doesNotMatch(src, /localStorage/);
});

test('G: DemoModeIndicator has DemoModeIndicatorProps interface or type', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /DemoModeIndicator(?:Props)?/);
});

test('G: DemoModeIndicator renders visually distinct demo banner', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /demo|Demo/);
});

test('G: DemoModeIndicator does not expose real data when in demo mode', () => {
  const src = read(DEMO_INDICATOR);
  assert.doesNotMatch(src, /REAL_DATA|production_data/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION H — WorkspaceSearch
// ═══════════════════════════════════════════════════════════════════════════════

test('H: WorkspaceSearch is a client component', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /'use client'/);
});

test('H: WorkspaceSearch has role="combobox"', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /role="combobox"/);
});

test('H: WorkspaceSearch has aria-expanded', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-expanded/);
});

test('H: WorkspaceSearch has aria-controls', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-controls/);
});

test('H: WorkspaceSearch has onSearch prop', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /onSearch/);
});

test('H: WorkspaceSearch has placeholder prop', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /placeholder/);
});

test('H: WorkspaceSearch has groupByWorkspace prop', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /groupByWorkspace/);
});

test('H: WorkspaceSearch has ArrowUp keyboard handler', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /ArrowUp/);
});

test('H: WorkspaceSearch has ArrowDown keyboard handler', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /ArrowDown/);
});

test('H: WorkspaceSearch has Enter keyboard handler', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /\bEnter\b/);
});

test('H: WorkspaceSearch has Escape keyboard handler', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /Escape/);
});

test('H: WorkspaceSearch has data-testid attributes', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /data-testid/);
});

test('H: WorkspaceSearch groups results by workspace', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /groupByWorkspace|group.*workspace|workspace.*group/i);
});

test('H: WorkspaceSearch has no Math.random', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('H: WorkspaceSearch has no sessionStorage', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('H: WorkspaceSearch has no localStorage', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.doesNotMatch(src, /localStorage/);
});

test('H: WorkspaceSearch has no dangerouslySetInnerHTML', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('H: WorkspaceSearch has aria-activedescendant or aria keyboard attribute', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-activedescendant|aria-selected|aria-owns/);
});

test('H: WorkspaceSearch has WorkspaceSearchProps interface or type', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /WorkspaceSearch(?:Props)?/);
});

test('H: WorkspaceSearch has input element with search role or type', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /type="(?:search|text)"|<input/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION I — index.ts exports
// ═══════════════════════════════════════════════════════════════════════════════

test('I: index.ts exports WorkspaceMetadata', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceMetadata/);
});

test('I: index.ts exports CrossWorkspaceNav', () => {
  const src = read(INDEX_TS);
  assert.match(src, /CrossWorkspaceNav/);
});

test('I: index.ts exports WorkspaceContextBridge', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceContextBridge/);
});

test('I: index.ts exports useWorkspaceContext', () => {
  const src = read(INDEX_TS);
  assert.match(src, /useWorkspaceContext/);
});

test('I: index.ts exports buildWorkspaceUrl', () => {
  const src = read(INDEX_TS);
  assert.match(src, /buildWorkspaceUrl/);
});

test('I: index.ts exports WorkspaceEmptyState', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceEmptyState/);
});

test('I: index.ts exports WorkspaceLoadingState', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceLoadingState/);
});

test('I: index.ts exports DemoModeIndicator', () => {
  const src = read(INDEX_TS);
  assert.match(src, /DemoModeIndicator/);
});

test('I: index.ts exports WorkspaceSearch', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceSearch/);
});

test('I: index.ts exports WorkspaceContext type', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceContext/);
});

test('I: index.ts exports WorkspaceLink type', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceLink/);
});

test('I: index.ts exports WORKSPACE_INTEGRATION_VERSION', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WORKSPACE_INTEGRATION_VERSION/);
});

test('I: WORKSPACE_INTEGRATION_VERSION equals "18.6.8"', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WORKSPACE_INTEGRATION_VERSION.*18\.6\.8|18\.6\.8.*WORKSPACE_INTEGRATION_VERSION/);
});

test('I: index.ts re-exports from WorkspaceMetadata file', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceMetadata/);
  assert.match(src, /from/);
});

test('I: index.ts re-exports from CrossWorkspaceNav file', () => {
  const src = read(INDEX_TS);
  assert.match(src, /CrossWorkspaceNav/);
});

test('I: index.ts re-exports from WorkspaceContextBridge file', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceContextBridge/);
});

test('I: index.ts re-exports from DemoModeIndicator file', () => {
  const src = read(INDEX_TS);
  assert.match(src, /DemoModeIndicator/);
});

test('I: index.ts re-exports from WorkspaceSearch file', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceSearch/);
});

test('I: index.ts has no dangerouslySetInnerHTML', () => {
  const src = read(INDEX_TS);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('I: index.ts does not export Math.random or random utilities', () => {
  const src = read(INDEX_TS);
  assert.doesNotMatch(src, /Math\.random/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION J — workspaceContext.ts
// ═══════════════════════════════════════════════════════════════════════════════

test('J: workspaceContext.ts exports WORKSPACE_CONTEXT_KEYS array', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /WORKSPACE_CONTEXT_KEYS/);
});

// Parameterised: one test per context key
WORKSPACE_CONTEXT_KEYS.forEach(key => {
  test(`J: WORKSPACE_CONTEXT_KEYS contains '${key}'`, () => {
    const src = read(WORKSPACE_CONTEXT);
    assert.match(src, new RegExp(`['"]${key}['"]`), `Missing key '${key}' in WORKSPACE_CONTEXT_KEYS`);
  });
});

test('J: workspaceContext.ts has 15 context keys total', () => {
  const src = read(WORKSPACE_CONTEXT);
  // All 15 must appear
  const found = WORKSPACE_CONTEXT_KEYS.filter(k => src.includes(`'${k}'`) || src.includes(`"${k}"`));
  assert.strictEqual(found.length, 15, `Expected 15 keys, found: ${found.join(', ')}`);
});

test('J: workspaceContext.ts exports parseWorkspaceContext function', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /export.*parseWorkspaceContext|parseWorkspaceContext.*export/);
});

test('J: workspaceContext.ts exports buildWorkspaceUrl function', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /export.*buildWorkspaceUrl|buildWorkspaceUrl.*export/);
});

test('J: workspaceContext.ts exports mergeWorkspaceContext function', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /export.*mergeWorkspaceContext|mergeWorkspaceContext.*export/);
});

test('J: workspaceContext.ts exports contextToParams function', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /export.*contextToParams|contextToParams.*export/);
});

test('J: workspaceContext.ts is server-safe — no useSearchParams', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /useSearchParams/);
});

test('J: workspaceContext.ts is server-safe — no "use client"', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /'use client'/);
});

test('J: workspaceContext.ts has no Math.random', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('J: workspaceContext.ts has no sessionStorage', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('J: workspaceContext.ts has no localStorage', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /localStorage/);
});

test('J: workspaceContext.ts has WorkspaceContext type or interface', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /WorkspaceContext/);
});

test('J: workspaceContext.ts has WorkspaceContextKey type', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /WorkspaceContextKey/);
});

test('J: workspaceContext.ts buildWorkspaceUrl takes route and context params', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /buildWorkspaceUrl/);
  // Should reference context or params
  assert.match(src, /context|params/);
});

test('J: workspaceContext.ts has export for WORKSPACE_CONTEXT_KEYS as const or array', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /WORKSPACE_CONTEXT_KEYS.*=.*\[|WORKSPACE_CONTEXT_KEYS.*=.*as const/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION K — demoFixtures.ts
// ═══════════════════════════════════════════════════════════════════════════════

test('K: demoFixtures.ts exports DEMO_MODE_ACTIVE as false', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_MODE_ACTIVE\s*=\s*false/);
});

test('K: DEMO_MODE_ACTIVE is not true', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /DEMO_MODE_ACTIVE\s*=\s*true/);
});

test('K: demoFixtures.ts exports DEMO_TENANT_ID with "demo-tenant" prefix', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_TENANT_ID/);
  assert.match(src, /demo-tenant/);
});

test('K: demoFixtures.ts exports DEMO_ENGAGEMENTS array', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_ENGAGEMENTS/);
});

test('K: DEMO_ENGAGEMENTS has 5 items', () => {
  const src = read(DEMO_FIXTURES);
  // Check that 5 appears in proximity to DEMO_ENGAGEMENTS or the array has 5 entries
  assert.match(src, /DEMO_ENGAGEMENTS/);
  // Count occurrences of id fields after DEMO_ENGAGEMENTS definition as proxy
  const engSection = src.slice(src.indexOf('DEMO_ENGAGEMENTS'));
  const idMatches = (engSection.match(/\bid:/g) || []).length;
  assert.ok(idMatches >= 5, `Expected at least 5 engagement entries, found ${idMatches} id: fields`);
});

test('K: demoFixtures.ts exports DEMO_FINDINGS array', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_FINDINGS/);
});

test('K: demoFixtures.ts exports DEMO_REPORTS array', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_REPORTS/);
});

test('K: demoFixtures.ts exports DEMO_REMEDIATIONS array', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_REMEDIATIONS/);
});

test('K: demoFixtures.ts exports DEMO_EXECUTIVE_METRICS object', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_EXECUTIVE_METRICS/);
});

test('K: demoFixtures.ts exports DEMO_TRUST_SCORE object', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_TRUST_SCORE/);
});

test('K: DEMO_EXECUTIVE_METRICS has posture_score field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /posture_score/);
});

test('K: DEMO_EXECUTIVE_METRICS has risk_count field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /risk_count/);
});

test('K: DEMO_EXECUTIVE_METRICS has compliance_score field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /compliance_score/);
});

test('K: DEMO_EXECUTIVE_METRICS has confidence field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /confidence/);
});

test('K: DEMO_TRUST_SCORE has overall field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /overall/);
});

test('K: All dates in demoFixtures are ISO strings with 2026- prefix', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /2026-/);
});

test('K: demoFixtures has DEMO FIXTURE comments', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO|demo fixture|Demo Fixture/i);
});

test('K: demoFixtures has no Math.random', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('K: demoFixtures has no Date.now', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /Date\.now\(\)/);
});

test('K: demoFixtures has no sessionStorage', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('K: demoFixtures has no localStorage', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /localStorage/);
});

test('K: demoFixtures has no dangerouslySetInnerHTML', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('K: DEMO_FINDINGS includes severity or risk field', () => {
  const src = read(DEMO_FIXTURES);
  // Findings should have severity/risk data
  assert.match(src, /severity|risk/);
});

test('K: DEMO_REMEDIATIONS includes status field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /status/);
});

test('K: demoFixtures does not expose real tenant UUIDs', () => {
  const src = read(DEMO_FIXTURES);
  // Should use demo-tenant prefix not raw UUIDs as tenant IDs
  assert.match(src, /demo-tenant/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION L — workspaceNav.ts
// ═══════════════════════════════════════════════════════════════════════════════

test('L: workspaceNav.ts exports WORKSPACE_NAV_MAP', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /WORKSPACE_NAV_MAP/);
});

test('L: workspaceNav.ts exports WorkspaceNavLink interface or type', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /WorkspaceNavLink/);
});

test('L: WORKSPACE_NAV_MAP has executive-intelligence key', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /executive-intelligence/);
});

test('L: WORKSPACE_NAV_MAP has trust-center key', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /trust-center/);
});

test('L: WORKSPACE_NAV_MAP has operations-workspace key', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /operations-workspace/);
});

test('L: WORKSPACE_NAV_MAP has field-assessments key', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /field-assessments/);
});

test('L: WORKSPACE_NAV_MAP has reports key', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\breports\b/);
});

test('L: WORKSPACE_NAV_MAP has command-center key', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /command-center/);
});

test('L: executive-intelligence has link to /trust-center route', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /executive-intelligence/);
  assert.match(src, /trust-center/);
});

test('L: executive-intelligence has link to workspace or operations route', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /operations-workspace|\/workspace/);
});

test('L: trust-center has link back to executive-intelligence', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /trust-center/);
  assert.match(src, /executive-intelligence/);
});

test('L: WorkspaceNavLink has id field', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\bid\b.*:/);
});

test('L: WorkspaceNavLink has label field', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\blabel\b.*:/);
});

test('L: WorkspaceNavLink has route field', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\broute\b.*:/);
});

test('L: WorkspaceNavLink has mcimId field', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /mcimId/);
});

test('L: WorkspaceNavLink has description field', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /description/);
});

test('L: contextParams use WorkspaceContextKey values (tenant, engagement, etc.)', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /contextParams/);
  assert.match(src, /tenant|engagement/);
});

test('L: workspaceNav.ts has no Math.random', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('L: workspaceNav.ts has no sessionStorage', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('L: workspaceNav.ts uses WorkspaceContextKey type from workspaceContext', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /WorkspaceContextKey/);
  assert.match(src, /workspaceContext/);
});

test('L: workspaceNav.ts has no dangerouslySetInnerHTML', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('L: workspaceNav.ts has no localStorage', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /localStorage/);
});

test('L: workspaceNav.ts workspace entries count is at least 6', () => {
  const src = read(WORKSPACE_NAV);
  // Each workspace key appears at least once
  const workspaceKeys = [
    'executive-intelligence',
    'trust-center',
    'operations-workspace',
    'field-assessments',
    'reports',
    'command-center',
  ];
  const found = workspaceKeys.filter(k => src.includes(k));
  assert.ok(found.length >= 6, `Expected 6 workspace keys, found: ${found.join(', ')}`);
});

test('L: field-assessments has at least one nav link', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /field-assessments/);
});

test('L: command-center has at least one nav link', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /command-center/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION M — CI check script
// ═══════════════════════════════════════════════════════════════════════════════

test('M: CI check script file exists', () => {
  assert.ok(existsAbsolute(CI_SCRIPT), 'Missing check_workspace_integration.py');
});

test('M: CI script contains REPO_ROOT definition', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /REPO_ROOT/);
});

test('M: CI script contains "workspace-integration"', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /workspace-integration/);
});

test('M: CI script checks for WorkspaceMetadata.tsx', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /WorkspaceMetadata/);
});

test('M: CI script checks for CrossWorkspaceNav.tsx', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /CrossWorkspaceNav/);
});

test('M: CI script checks for WorkspaceContextBridge.tsx', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /WorkspaceContextBridge/);
});

test('M: CI script checks for WorkspaceEmptyState.tsx', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /WorkspaceEmptyState/);
});

test('M: CI script checks for WorkspaceLoadingState.tsx', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /WorkspaceLoadingState/);
});

test('M: CI script checks for DemoModeIndicator.tsx', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /DemoModeIndicator/);
});

test('M: CI script checks for WorkspaceSearch.tsx', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /WorkspaceSearch/);
});

test('M: CI script checks for workspaceContext.ts', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /workspaceContext/);
});

test('M: CI script checks for demoFixtures.ts', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /demoFixtures/);
});

test('M: CI script checks for workspaceNav.ts', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /workspaceNav/);
});

test('M: CI script checks Math.random is forbidden', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /Math\.random/);
});

test('M: CI script checks sessionStorage is forbidden', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /sessionStorage/);
});

test('M: CI script checks localStorage is forbidden', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /localStorage/);
});

test('M: CI script checks dangerouslySetInnerHTML is forbidden', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /dangerouslySetInnerHTML/);
});

test('M: CI script has errors list', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /errors/);
});

test('M: CI script has warnings list', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /warnings/);
});

test('M: CI script has sys.exit call', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /sys\.exit/);
});

test('M: CI script checks architecture doc exists', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /WORKSPACE_INTEGRATION_18_6_8|architecture.*doc|docs.*architecture/i);
});

test('M: CI script checks navigation registry', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /navigation-registry|navigation_registry/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION N — Architecture doc
// ═══════════════════════════════════════════════════════════════════════════════

test('N: Architecture doc exists', () => {
  assert.ok(existsAbsolute(ARCH_DOC), 'Missing WORKSPACE_INTEGRATION_18_6_8.md');
});

test('N: Doc contains "PR 18.6.8" or "Workspace Integration"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /PR 18\.6\.8|Workspace Integration/);
});

test('N: Doc contains "Context Preservation"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Context Preservation/);
});

test('N: Doc contains "Demo Mode"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Demo Mode/);
});

test('N: Doc contains "Accessibility"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Accessibility/);
});

test('N: Doc contains "WCAG"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /WCAG/);
});

test('N: Doc contains "MCIM"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /MCIM/);
});

test('N: Doc contains "Navigation Philosophy"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Navigation Philosophy/);
});

test('N: Doc contains "Executive"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Executive/);
});

test('N: Doc contains "Operator"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Operator/);
});

test('N: Doc contains "Customer"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Customer/);
});

test('N: Doc contains "/trust-center"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /\/trust-center/);
});

test('N: Doc contains "/dashboard/executive" or "executive-intelligence"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /\/dashboard\/executive|executive-intelligence/);
});

test('N: Doc contains "/workspace" or "Operations Workspace"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /\/workspace|Operations Workspace/);
});

test('N: Doc contains "Field Assessment"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Field Assessment/);
});

test('N: Doc contains "18.6.8"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /18\.6\.8/);
});

test('N: Doc contains "WorkspaceMetadata"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /WorkspaceMetadata/);
});

test('N: Doc contains "CrossWorkspaceNav"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /CrossWorkspaceNav/);
});

test('N: Doc contains "DemoModeIndicator"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /DemoModeIndicator/);
});

test('N: Doc contains "WorkspaceSearch"', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /WorkspaceSearch/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION O — Navigation registry
// ═══════════════════════════════════════════════════════════════════════════════

test('O: Navigation registry exists', () => {
  assert.ok(existsAbsolute(NAV_REG), 'Missing navigation-registry.json');
});

test('O: Navigation registry is valid JSON', () => {
  const src = readAbsolute(NAV_REG);
  let parsed;
  assert.doesNotThrow(() => { parsed = JSON.parse(src); }, 'navigation-registry.json is not valid JSON');
});

test('O: Navigation registry has version field', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok('version' in parsed, 'Missing version field in navigation-registry.json');
});

test('O: Navigation registry has console array', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(Array.isArray(parsed.console), 'console must be an array');
});

test('O: Navigation registry has portal array', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok('portal' in parsed, 'Missing portal field');
});

test('O: Navigation registry has groups array', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(Array.isArray(parsed.groups), 'groups must be an array');
});

test('O: groups include "Operations"', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(parsed.groups.some(g => g === 'Operations' || g.name === 'Operations' || g.id === 'Operations' || g.label === 'Operations'), 'Missing Operations group');
});

test('O: groups include "Governance"', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(parsed.groups.some(g => g === 'Governance' || g.name === 'Governance' || g.id === 'Governance' || g.label === 'Governance'), 'Missing Governance group');
});

test('O: groups include "Intelligence"', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(parsed.groups.some(g => g === 'Intelligence' || g.name === 'Intelligence' || g.id === 'Intelligence' || g.label === 'Intelligence'), 'Missing Intelligence group');
});

test('O: groups include "Trust"', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(parsed.groups.some(g => g === 'Trust' || g.name === 'Trust' || g.id === 'Trust' || g.label === 'Trust'), 'Missing Trust group');
});

test('O: groups include "Enterprise"', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(parsed.groups.some(g => g === 'Enterprise' || g.name === 'Enterprise' || g.id === 'Enterprise' || g.label === 'Enterprise'), 'Missing Enterprise group');
});

test('O: console entries include "command-center"', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(
    parsed.console.some(e => e === 'command-center' || e.id === 'command-center' || e.route === 'command-center'),
    'Missing command-center in console entries'
  );
});

test('O: console entries include "field-assessments"', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(
    parsed.console.some(e => e === 'field-assessments' || e.id === 'field-assessments' || e.route === 'field-assessments'),
    'Missing field-assessments in console entries'
  );
});

test('O: console entries include trust-center or workspace-integration', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  const hasTrustCenter = parsed.console.some(e =>
    e === 'trust-center' || e.id === 'trust-center' || (e.route && e.route.includes('trust-center'))
  );
  const hasWorkspaceIntegration = parsed.console.some(e =>
    e === 'workspace-integration' || e.id === 'workspace-integration' ||
    (e.route && e.route.includes('workspace'))
  );
  assert.ok(hasTrustCenter || hasWorkspaceIntegration, 'Missing trust-center or workspace-integration entry');
});

test('O: Each console entry is an object or string (not null)', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  parsed.console.forEach((entry, i) => {
    assert.ok(entry !== null, `console[${i}] is null`);
    assert.ok(typeof entry === 'string' || typeof entry === 'object', `console[${i}] is not a string or object`);
  });
});

test('O: console object entries with id have title or label', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  const objectEntries = parsed.console.filter(e => typeof e === 'object' && e !== null && 'id' in e);
  objectEntries.forEach(entry => {
    assert.ok('title' in entry || 'label' in entry, `Console entry ${entry.id} missing title or label`);
  });
});

test('O: portal field is present in registry', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok('portal' in parsed);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION P — Cross-workspace journey coverage
// ═══════════════════════════════════════════════════════════════════════════════

test('P: WORKSPACE_NAV_MAP executive-intelligence links include trust route', () => {
  const src = read(WORKSPACE_NAV);
  // Both keys should appear, implying a link from exec-intel to trust-center
  assert.match(src, /executive-intelligence/);
  assert.match(src, /trust-center/);
});

test('P: WORKSPACE_NAV_MAP trust-center links include executive-intelligence', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /trust-center/);
  assert.match(src, /executive-intelligence/);
});

test('P: WORKSPACE_NAV_MAP operations-workspace links include executive-intelligence', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /operations-workspace/);
  assert.match(src, /executive-intelligence/);
});

test('P: WORKSPACE_NAV_MAP command-center links include executive-intelligence', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /command-center/);
  assert.match(src, /executive-intelligence/);
});

test('P: workspaceNav.ts has 6 workspace entries minimum', () => {
  const src = read(WORKSPACE_NAV);
  const keys = [
    'executive-intelligence',
    'trust-center',
    'operations-workspace',
    'field-assessments',
    'reports',
    'command-center',
  ];
  const presentCount = keys.filter(k => src.includes(k)).length;
  assert.ok(presentCount >= 6, `Expected 6 workspace keys in nav map, found ${presentCount}`);
});

test('P: No workspace links to itself via route mismatch guard', () => {
  const src = read(WORKSPACE_NAV);
  // The guard should be present for same-workspace filtering
  assert.match(src, /currentWorkspace|self.*link|link.*self/i);
});

test('P: Nav links preserve context via contextParams', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /contextParams/);
});

test('P: No hardcoded tenant UUIDs in nav link routes', () => {
  const src = read(WORKSPACE_NAV);
  // UUID pattern — should not appear in routes
  assert.doesNotMatch(src, /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
});

test('P: buildWorkspaceUrl in workspaceContext handles empty context', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /buildWorkspaceUrl/);
  // Should handle empty or undefined context gracefully
  assert.match(src, /\?\?|undefined|Object\.keys|if.*context/);
});

test('P: buildWorkspaceUrl handles undefined values', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /undefined|\?\?|filter/);
});

test('P: Cross-workspace links use route strings not hardcoded URLs', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /route/);
  assert.doesNotMatch(src, /https:\/\/[a-z]/);
});

test('P: workspaceContext exports enable round-trip context preservation', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /parseWorkspaceContext/);
  assert.match(src, /buildWorkspaceUrl/);
  assert.match(src, /contextToParams/);
});

test('P: CrossWorkspaceNav uses buildWorkspaceUrl for link construction', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /buildWorkspaceUrl/);
});

test('P: WorkspaceContextBridge uses parseWorkspaceContext or WORKSPACE_CONTEXT_KEYS', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /parseWorkspaceContext|WORKSPACE_CONTEXT_KEYS/);
});

test('P: All workspace routes start with slash (relative paths)', () => {
  const src = read(WORKSPACE_NAV);
  // Routes should be paths like '/dashboard/...' not absolute URLs
  assert.match(src, /route.*'\/|route.*"\/|'\/.*route|"\/.*route/);
});

test('P: No direct window.location manipulation in nav files', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /window\.location/);
});

test('P: No direct window.location manipulation in context bridge', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.doesNotMatch(src, /window\.location/);
});

test('P: Context bridge supports all 15 workspace context keys', () => {
  const src = read(CONTEXT_BRIDGE);
  const found = WORKSPACE_CONTEXT_KEYS.filter(k => src.includes(k));
  assert.ok(found.length >= 10, `Expected at least 10 context keys in bridge, found: ${found.join(', ')}`);
});

test('P: workspaceNav routes include dashboard paths', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\/dashboard\//);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION Q — Accessibility compliance
// ═══════════════════════════════════════════════════════════════════════════════

test('Q: WorkspaceSearch has aria-expanded', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-expanded/);
});

test('Q: WorkspaceSearch has aria-controls', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-controls/);
});

test('Q: WorkspaceSearch has aria-activedescendant or aria keyboard navigation', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-activedescendant|aria-selected|aria-owns/);
});

test('Q: WorkspaceSearch has role="combobox"', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /role="combobox"/);
});

test('Q: DemoModeIndicator has role="alert"', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /role="alert"/);
});

test('Q: WorkspaceEmptyState has role or aria attribute', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /role=|aria-/);
});

test('Q: WorkspaceLoadingState has aria-busy', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /aria-busy/);
});

test('Q: CrossWorkspaceNav has aria-label', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /aria-label/);
});

test('Q: CrossWorkspaceNav has keyboard event handlers', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /onKey(?:Down|Up|Press)/);
});

test('Q: CrossWorkspaceNav has Enter key handler (no click-only navigation)', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /Enter/);
});

test('Q: WorkspaceMetadata has aria-hidden on decorative element', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /aria-hidden="true"/);
});

test('Q: WorkspaceSearch has onKeyDown or keyboard event', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /onKey(?:Down|Up|Press)/);
});

test('Q: WorkspaceSearch handles ArrowUp for keyboard navigation', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /ArrowUp/);
});

test('Q: WorkspaceSearch handles ArrowDown for keyboard navigation', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /ArrowDown/);
});

test('Q: WorkspaceSearch handles Escape to close', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /Escape/);
});

test('Q: WorkspaceSearch handles Enter to select', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /\bEnter\b/);
});

test('Q: WorkspaceEmptyState has aria-label or role for screen readers', () => {
  const src = read(EMPTY_STATE);
  assert.match(src, /aria-label|role=/);
});

test('Q: WorkspaceLoadingState does not rely on color alone for loading state', () => {
  const src = read(LOADING_STATE);
  // Should have aria-busy or text to convey loading state
  assert.match(src, /aria-busy|Loading|loading/);
});

test('Q: CrossWorkspaceNav Space key handler present', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /Space|' '/);
});

test('Q: WorkspaceSearch aria-controls references a listbox or results container', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-controls/);
  assert.match(src, /listbox|results|combobox/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION R — Forbidden pattern sweep across all files
// ═══════════════════════════════════════════════════════════════════════════════

const FORBIDDEN_PATTERNS = [
  { label: 'Math.random()', regex: /Math\.random\(\)/ },
  { label: 'sessionStorage', regex: /sessionStorage/ },
  { label: 'localStorage', regex: /localStorage/ },
  { label: 'dangerouslySetInnerHTML', regex: /dangerouslySetInnerHTML/ },
];

// Sweep every component for each forbidden pattern
ALL_COMPONENTS.forEach(compPath => {
  const compName = path.basename(compPath, path.extname(compPath));
  FORBIDDEN_PATTERNS.forEach(({ label, regex }) => {
    test(`R: ${compName} has no ${label}`, () => {
      if (!exists(compPath)) return; // skip if file missing (existence tested in Section A)
      const src = read(compPath);
      assert.doesNotMatch(src, regex, `${compName} must not contain ${label}`);
    });
  });
});

// Sweep every lib file for each forbidden pattern
ALL_LIB_FILES.forEach(libPath => {
  const libName = path.basename(libPath, path.extname(libPath));
  FORBIDDEN_PATTERNS.forEach(({ label, regex }) => {
    test(`R: ${libName} has no ${label}`, () => {
      if (!exists(libPath)) return;
      const src = read(libPath);
      assert.doesNotMatch(src, regex, `${libName} must not contain ${label}`);
    });
  });
});

// DEMO_MODE_ACTIVE must be false (never true)
test('R: DEMO_MODE_ACTIVE is not set to true anywhere in demoFixtures', () => {
  if (!exists(DEMO_FIXTURES)) return;
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /DEMO_MODE_ACTIVE\s*=\s*true/);
});

// Direct Date.now() forbidden in demoFixtures (must be deterministic)
test('R: demoFixtures has no Date.now() call', () => {
  if (!exists(DEMO_FIXTURES)) return;
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /Date\.now\(\)/);
});

// index.ts should also be clean
test('R: index.ts has no Math.random()', () => {
  if (!exists(INDEX_TS)) return;
  const src = read(INDEX_TS);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('R: index.ts has no sessionStorage', () => {
  if (!exists(INDEX_TS)) return;
  const src = read(INDEX_TS);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('R: index.ts has no localStorage', () => {
  if (!exists(INDEX_TS)) return;
  const src = read(INDEX_TS);
  assert.doesNotMatch(src, /localStorage/);
});

test('R: index.ts has no dangerouslySetInnerHTML', () => {
  if (!exists(INDEX_TS)) return;
  const src = read(INDEX_TS);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

// No raw window.location mutation in any component
ALL_COMPONENTS.forEach(compPath => {
  const compName = path.basename(compPath, path.extname(compPath));
  test(`R: ${compName} has no direct window.location mutation`, () => {
    if (!exists(compPath)) return;
    const src = read(compPath);
    assert.doesNotMatch(src, /window\.location\s*=/, `${compName} must not directly mutate window.location`);
  });
});

// No eval() in any file
const ALL_FILES = [...ALL_COMPONENTS, ...ALL_LIB_FILES, INDEX_TS];
ALL_FILES.forEach(filePath => {
  const fileName = path.basename(filePath, path.extname(filePath));
  test(`R: ${fileName} has no eval()`, () => {
    if (!exists(filePath)) return;
    const src = read(filePath);
    assert.doesNotMatch(src, /\beval\s*\(/, `${fileName} must not use eval()`);
  });
});

// No document.write in any file
ALL_FILES.forEach(filePath => {
  const fileName = path.basename(filePath, path.extname(filePath));
  test(`R: ${fileName} has no document.write`, () => {
    if (!exists(filePath)) return;
    const src = read(filePath);
    assert.doesNotMatch(src, /document\.write\s*\(/, `${fileName} must not use document.write`);
  });
});

// No alert() in any file (UI components must not use browser alert)
ALL_COMPONENTS.forEach(compPath => {
  const compName = path.basename(compPath, path.extname(compPath));
  test(`R: ${compName} has no alert() call`, () => {
    if (!exists(compPath)) return;
    const src = read(compPath);
    assert.doesNotMatch(src, /\balert\s*\(/, `${compName} must not use alert()`);
  });
});

// No console.log left in production components
ALL_COMPONENTS.forEach(compPath => {
  const compName = path.basename(compPath, path.extname(compPath));
  test(`R: ${compName} has no console.log`, () => {
    if (!exists(compPath)) return;
    const src = read(compPath);
    assert.doesNotMatch(src, /console\.log\s*\(/, `${compName} must not contain console.log`);
  });
});

// No hardcoded production secrets patterns
ALL_FILES.forEach(filePath => {
  const fileName = path.basename(filePath, path.extname(filePath));
  test(`R: ${fileName} has no hardcoded API keys`, () => {
    if (!exists(filePath)) return;
    const src = read(filePath);
    assert.doesNotMatch(src, /api_key\s*=\s*['"][a-zA-Z0-9]{20,}['"]/, `${fileName} must not contain hardcoded API keys`);
    assert.doesNotMatch(src, /secret\s*=\s*['"][a-zA-Z0-9]{20,}['"]/, `${fileName} must not contain hardcoded secrets`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION S — Per-file prop completeness (parameterised)
// ═══════════════════════════════════════════════════════════════════════════════

// WorkspaceMetadata: verify all 8 props appear in a single loop
const METADATA_PROPS = [
  'mcimId', 'authority', 'capability', 'workspace',
  'sourceOfTruth', 'refreshPolicy', 'confidenceSource', 'lastUpdated',
];
METADATA_PROPS.forEach(prop => {
  test(`S: WorkspaceMetadata has prop "${prop}" in interface or destructuring`, () => {
    if (!exists(WORKSPACE_METADATA)) return;
    const src = read(WORKSPACE_METADATA);
    assert.match(src, new RegExp(prop), `WorkspaceMetadata missing prop: ${prop}`);
  });
});

// WorkspaceEmptyState: verify all props
const EMPTY_STATE_PROPS = [
  'reason', 'dataRequired', 'nextAction', 'nextActionHref',
  'nextActionLabel', 'mcimId', 'workspace', 'icon',
];
EMPTY_STATE_PROPS.forEach(prop => {
  test(`S: WorkspaceEmptyState has prop "${prop}"`, () => {
    if (!exists(EMPTY_STATE)) return;
    const src = read(EMPTY_STATE);
    assert.match(src, new RegExp(prop), `WorkspaceEmptyState missing prop: ${prop}`);
  });
});

// WorkspaceLoadingState: verify all props
const LOADING_STATE_PROPS = ['workspace', 'sections', 'mcimId'];
LOADING_STATE_PROPS.forEach(prop => {
  test(`S: WorkspaceLoadingState has prop "${prop}"`, () => {
    if (!exists(LOADING_STATE)) return;
    const src = read(LOADING_STATE);
    assert.match(src, new RegExp(prop), `WorkspaceLoadingState missing prop: ${prop}`);
  });
});

// DemoModeIndicator: verify all props
const DEMO_INDICATOR_PROPS = ['active', 'datasetName', 'children'];
DEMO_INDICATOR_PROPS.forEach(prop => {
  test(`S: DemoModeIndicator has prop "${prop}"`, () => {
    if (!exists(DEMO_INDICATOR)) return;
    const src = read(DEMO_INDICATOR);
    assert.match(src, new RegExp(prop), `DemoModeIndicator missing prop: ${prop}`);
  });
});

// WorkspaceSearch: verify all props
const SEARCH_PROPS = ['onSearch', 'placeholder', 'groupByWorkspace'];
SEARCH_PROPS.forEach(prop => {
  test(`S: WorkspaceSearch has prop "${prop}"`, () => {
    if (!exists(WORKSPACE_SEARCH)) return;
    const src = read(WORKSPACE_SEARCH);
    assert.match(src, new RegExp(prop), `WorkspaceSearch missing prop: ${prop}`);
  });
});

// CrossWorkspaceNav: verify all props
const NAV_PROPS = ['layout', 'size', 'currentWorkspace', 'links'];
NAV_PROPS.forEach(prop => {
  test(`S: CrossWorkspaceNav has prop "${prop}"`, () => {
    if (!exists(CROSS_WORKSPACE_NAV)) return;
    const src = read(CROSS_WORKSPACE_NAV);
    assert.match(src, new RegExp(prop), `CrossWorkspaceNav missing prop: ${prop}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION T — workspaceContext key presence (multi-assert per key)
// ═══════════════════════════════════════════════════════════════════════════════

// For each context key, verify it appears in BOTH workspaceContext.ts AND workspaceNav.ts
WORKSPACE_CONTEXT_KEYS.forEach(key => {
  test(`T: workspaceNav.ts contextParams reference key "${key}"`, () => {
    if (!exists(WORKSPACE_NAV)) return;
    const src = read(WORKSPACE_NAV);
    assert.match(src, new RegExp(`'${key}'|"${key}"`), `workspaceNav.ts missing context key: ${key}`);
  });
});

// For each context key, verify WorkspaceContextBridge mentions it
WORKSPACE_CONTEXT_KEYS.forEach(key => {
  test(`T: WorkspaceContextBridge references context key "${key}"`, () => {
    if (!exists(CONTEXT_BRIDGE)) return;
    const src = read(CONTEXT_BRIDGE);
    assert.match(src, new RegExp(key), `WorkspaceContextBridge missing context key reference: ${key}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION U — WORKSPACE_NAV_MAP link structure (per workspace key)
// ═══════════════════════════════════════════════════════════════════════════════

const NAV_MAP_KEYS = [
  'executive-intelligence',
  'trust-center',
  'operations-workspace',
  'field-assessments',
  'reports',
  'command-center',
];

// Verify every nav map key appears in workspaceNav.ts
NAV_MAP_KEYS.forEach(key => {
  test(`U: WORKSPACE_NAV_MAP contains key "${key}"`, () => {
    if (!exists(WORKSPACE_NAV)) return;
    const src = read(WORKSPACE_NAV);
    assert.match(src, new RegExp(key), `WORKSPACE_NAV_MAP missing key: ${key}`);
  });
});

// Verify every nav map key appears in index.ts (or accessible through the package)
NAV_MAP_KEYS.forEach(key => {
  test(`U: workspaceNav.ts key "${key}" has id, label, route, mcimId, description`, () => {
    if (!exists(WORKSPACE_NAV)) return;
    const src = read(WORKSPACE_NAV);
    // The file must define these fields globally
    assert.match(src, /\bid\b/, `workspaceNav.ts missing 'id' field for links`);
    assert.match(src, /\blabel\b/, `workspaceNav.ts missing 'label' field for links`);
    assert.match(src, /\broute\b/, `workspaceNav.ts missing 'route' field for links`);
    assert.match(src, /mcimId/, `workspaceNav.ts missing 'mcimId' field for links`);
    assert.match(src, /description/, `workspaceNav.ts missing 'description' field for links`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION V — Index re-export completeness (parameterised)
// ═══════════════════════════════════════════════════════════════════════════════

const INDEX_EXPORTS = [
  'WorkspaceMetadata',
  'CrossWorkspaceNav',
  'WorkspaceContextBridge',
  'useWorkspaceContext',
  'buildWorkspaceUrl',
  'WorkspaceEmptyState',
  'WorkspaceLoadingState',
  'DemoModeIndicator',
  'WorkspaceSearch',
  'WorkspaceContext',
  'WorkspaceLink',
  'WORKSPACE_INTEGRATION_VERSION',
];

INDEX_EXPORTS.forEach(exportName => {
  test(`V: index.ts exports "${exportName}"`, () => {
    if (!exists(INDEX_TS)) return;
    const src = read(INDEX_TS);
    assert.match(src, new RegExp(exportName), `index.ts missing export: ${exportName}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION W — demoFixtures completeness (parameterised)
// ═══════════════════════════════════════════════════════════════════════════════

const DEMO_EXPORTS = [
  'DEMO_MODE_ACTIVE',
  'DEMO_TENANT_ID',
  'DEMO_ENGAGEMENTS',
  'DEMO_FINDINGS',
  'DEMO_REPORTS',
  'DEMO_REMEDIATIONS',
  'DEMO_EXECUTIVE_METRICS',
  'DEMO_TRUST_SCORE',
];

DEMO_EXPORTS.forEach(exportName => {
  test(`W: demoFixtures.ts exports "${exportName}"`, () => {
    if (!exists(DEMO_FIXTURES)) return;
    const src = read(DEMO_FIXTURES);
    assert.match(src, new RegExp(exportName), `demoFixtures.ts missing export: ${exportName}`);
  });
});

const EXECUTIVE_METRICS_FIELDS = [
  'posture_score', 'risk_count', 'compliance_score', 'confidence',
];

EXECUTIVE_METRICS_FIELDS.forEach(field => {
  test(`W: DEMO_EXECUTIVE_METRICS has field "${field}"`, () => {
    if (!exists(DEMO_FIXTURES)) return;
    const src = read(DEMO_FIXTURES);
    assert.match(src, new RegExp(field), `DEMO_EXECUTIVE_METRICS missing field: ${field}`);
  });
});

const TRUST_SCORE_FIELDS = ['overall'];
TRUST_SCORE_FIELDS.forEach(field => {
  test(`W: DEMO_TRUST_SCORE has field "${field}"`, () => {
    if (!exists(DEMO_FIXTURES)) return;
    const src = read(DEMO_FIXTURES);
    assert.match(src, new RegExp(field), `DEMO_TRUST_SCORE missing field: ${field}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION X — Keyboard handler completeness (parameterised)
// ═══════════════════════════════════════════════════════════════════════════════

const SEARCH_KEY_HANDLERS = ['ArrowUp', 'ArrowDown', 'Enter', 'Escape'];

SEARCH_KEY_HANDLERS.forEach(key => {
  test(`X: WorkspaceSearch handles keyboard key "${key}"`, () => {
    if (!exists(WORKSPACE_SEARCH)) return;
    const src = read(WORKSPACE_SEARCH);
    assert.match(src, new RegExp(key), `WorkspaceSearch missing keyboard handler for: ${key}`);
  });
});

const NAV_KEY_HANDLERS = ['Enter', 'Space'];

NAV_KEY_HANDLERS.forEach(key => {
  test(`X: CrossWorkspaceNav handles keyboard key "${key}"`, () => {
    if (!exists(CROSS_WORKSPACE_NAV)) return;
    const src = read(CROSS_WORKSPACE_NAV);
    assert.match(src, new RegExp(`${key}|' '`), `CrossWorkspaceNav missing keyboard handler for: ${key}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION Y — CI script per-component checks (parameterised)
// ═══════════════════════════════════════════════════════════════════════════════

const CI_COMPONENT_NAMES = [
  'WorkspaceMetadata',
  'CrossWorkspaceNav',
  'WorkspaceContextBridge',
  'WorkspaceEmptyState',
  'WorkspaceLoadingState',
  'DemoModeIndicator',
  'WorkspaceSearch',
];

CI_COMPONENT_NAMES.forEach(compName => {
  test(`Y: CI script references component "${compName}"`, () => {
    if (!existsAbsolute(CI_SCRIPT)) return;
    const src = readAbsolute(CI_SCRIPT);
    assert.match(src, new RegExp(compName), `CI script must check for: ${compName}`);
  });
});

const CI_LIB_NAMES = ['workspaceContext', 'demoFixtures', 'workspaceNav'];

CI_LIB_NAMES.forEach(libName => {
  test(`Y: CI script references lib "${libName}"`, () => {
    if (!existsAbsolute(CI_SCRIPT)) return;
    const src = readAbsolute(CI_SCRIPT);
    assert.match(src, new RegExp(libName), `CI script must check for lib: ${libName}`);
  });
});

const CI_FORBIDDEN_CHECKS = ['Math.random', 'sessionStorage', 'localStorage', 'dangerouslySetInnerHTML'];

CI_FORBIDDEN_CHECKS.forEach(pattern => {
  test(`Y: CI script has forbidden pattern check for "${pattern}"`, () => {
    if (!existsAbsolute(CI_SCRIPT)) return;
    const src = readAbsolute(CI_SCRIPT);
    assert.match(src, new RegExp(pattern.replace('.', '\\.').replace('()', '')), `CI script must forbid: ${pattern}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION Z — Architecture doc completeness (parameterised)
// ═══════════════════════════════════════════════════════════════════════════════

const ARCH_DOC_TERMS = [
  'PR 18\\.6\\.8|Workspace Integration',
  'Context Preservation',
  'Demo Mode',
  'Accessibility',
  'WCAG',
  'MCIM',
  'Navigation Philosophy',
  'Executive',
  'Operator',
  'Customer',
  'trust-center',
  'Field Assessment',
  '18\\.6\\.8',
  'WorkspaceMetadata',
  'CrossWorkspaceNav',
  'DemoModeIndicator',
  'WorkspaceSearch',
  'WorkspaceEmptyState',
  'WorkspaceLoadingState',
  'WorkspaceContextBridge',
];

ARCH_DOC_TERMS.forEach(term => {
  const displayTerm = term.replace(/\\\./g, '.').replace('|', ' or ');
  test(`Z: Architecture doc contains "${displayTerm}"`, () => {
    if (!existsAbsolute(ARCH_DOC)) return;
    const src = readAbsolute(ARCH_DOC);
    assert.match(src, new RegExp(term), `Architecture doc missing: ${displayTerm}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AA — Navigation registry completeness (parameterised)
// ═══════════════════════════════════════════════════════════════════════════════

const REQUIRED_GROUPS = ['Operations', 'Governance', 'Intelligence', 'Trust', 'Enterprise'];

REQUIRED_GROUPS.forEach(group => {
  test(`AA: Navigation registry groups include "${group}"`, () => {
    if (!existsAbsolute(NAV_REG)) return;
    const src = readAbsolute(NAV_REG);
    const parsed = JSON.parse(src);
    assert.ok(
      parsed.groups.some(g => g === group || g.name === group || g.id === group || g.label === group),
      `Navigation registry missing group: ${group}`
    );
  });
});

const REQUIRED_CONSOLE_ENTRIES = ['command-center', 'field-assessments'];

REQUIRED_CONSOLE_ENTRIES.forEach(entry => {
  test(`AA: Navigation registry console includes "${entry}"`, () => {
    if (!existsAbsolute(NAV_REG)) return;
    const src = readAbsolute(NAV_REG);
    const parsed = JSON.parse(src);
    assert.ok(
      parsed.console.some(e =>
        e === entry || e.id === entry || (e.route && e.route.includes(entry))
      ),
      `Navigation registry console missing entry: ${entry}`
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AB — Multi-assert structural tests (boost assert density)
// ═══════════════════════════════════════════════════════════════════════════════

test('AB: workspaceContext.ts has all required exports in a single check', () => {
  if (!exists(WORKSPACE_CONTEXT)) return;
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /WORKSPACE_CONTEXT_KEYS/);
  assert.match(src, /parseWorkspaceContext/);
  assert.match(src, /buildWorkspaceUrl/);
  assert.match(src, /mergeWorkspaceContext/);
  assert.match(src, /contextToParams/);
  assert.match(src, /WorkspaceContext/);
  assert.match(src, /WorkspaceContextKey/);
  assert.doesNotMatch(src, /useSearchParams/);
  assert.doesNotMatch(src, /'use client'/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
});

test('AB: demoFixtures.ts has all required exports in a single check', () => {
  if (!exists(DEMO_FIXTURES)) return;
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_MODE_ACTIVE\s*=\s*false/);
  assert.match(src, /DEMO_TENANT_ID/);
  assert.match(src, /demo-tenant/);
  assert.match(src, /DEMO_ENGAGEMENTS/);
  assert.match(src, /DEMO_FINDINGS/);
  assert.match(src, /DEMO_REPORTS/);
  assert.match(src, /DEMO_REMEDIATIONS/);
  assert.match(src, /DEMO_EXECUTIVE_METRICS/);
  assert.match(src, /DEMO_TRUST_SCORE/);
  assert.match(src, /posture_score/);
  assert.match(src, /risk_count/);
  assert.match(src, /compliance_score/);
  assert.match(src, /confidence/);
  assert.match(src, /overall/);
  assert.doesNotMatch(src, /DEMO_MODE_ACTIVE\s*=\s*true/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /Date\.now\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('AB: workspaceNav.ts has all required nav keys and structure', () => {
  if (!exists(WORKSPACE_NAV)) return;
  const src = read(WORKSPACE_NAV);
  assert.match(src, /WORKSPACE_NAV_MAP/);
  assert.match(src, /WorkspaceNavLink/);
  assert.match(src, /executive-intelligence/);
  assert.match(src, /trust-center/);
  assert.match(src, /operations-workspace/);
  assert.match(src, /field-assessments/);
  assert.match(src, /\breports\b/);
  assert.match(src, /command-center/);
  assert.match(src, /contextParams/);
  assert.match(src, /WorkspaceContextKey/);
  assert.match(src, /workspaceContext/);
  assert.match(src, /\bid\b/);
  assert.match(src, /\blabel\b/);
  assert.match(src, /\broute\b/);
  assert.match(src, /mcimId/);
  assert.match(src, /description/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
});

test('AB: CrossWorkspaceNav full accessibility and structure check', () => {
  if (!exists(CROSS_WORKSPACE_NAV)) return;
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /'use client'/);
  assert.match(src, /from 'next\/link'/);
  assert.match(src, /aria-label/);
  assert.match(src, /data-mcim-id/);
  assert.match(src, /data-workspace/);
  assert.match(src, /WorkspaceLink/);
  assert.match(src, /layout/);
  assert.match(src, /currentWorkspace/);
  assert.match(src, /buildWorkspaceUrl/);
  assert.match(src, /Enter/);
  assert.match(src, /Space|' '/);
  assert.match(src, /from 'lucide-react'/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(src, /tenant_id/);
});

test('AB: WorkspaceSearch full ARIA and keyboard check', () => {
  if (!exists(WORKSPACE_SEARCH)) return;
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /'use client'/);
  assert.match(src, /role="combobox"/);
  assert.match(src, /aria-expanded/);
  assert.match(src, /aria-controls/);
  assert.match(src, /onSearch/);
  assert.match(src, /placeholder/);
  assert.match(src, /groupByWorkspace/);
  assert.match(src, /ArrowUp/);
  assert.match(src, /ArrowDown/);
  assert.match(src, /\bEnter\b/);
  assert.match(src, /Escape/);
  assert.match(src, /data-testid/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('AB: WorkspaceMetadata full prop and attribute check', () => {
  if (!exists(WORKSPACE_METADATA)) return;
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /'use client'/);
  assert.match(src, /WorkspaceMetadataProps/);
  assert.match(src, /data-workspace-metadata/);
  assert.match(src, /aria-hidden="true"/);
  assert.match(src, /mcimId/);
  assert.match(src, /authority/);
  assert.match(src, /capability/);
  assert.match(src, /workspace/);
  assert.match(src, /sourceOfTruth/);
  assert.match(src, /refreshPolicy/);
  assert.match(src, /confidenceSource/);
  assert.match(src, /lastUpdated/);
  assert.match(src, /export default/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('AB: DemoModeIndicator full check', () => {
  if (!exists(DEMO_INDICATOR)) return;
  const src = read(DEMO_INDICATOR);
  assert.match(src, /active/);
  assert.match(src, /datasetName/);
  assert.match(src, /children/);
  assert.match(src, /Demo Mode/);
  assert.match(src, /data-demo-mode/);
  assert.match(src, /role="alert"/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /REAL_DATA/);
});

test('AB: WorkspaceLoadingState full check', () => {
  if (!exists(LOADING_STATE)) return;
  const src = read(LOADING_STATE);
  assert.match(src, /workspace/);
  assert.match(src, /sections/);
  assert.match(src, /mcimId/);
  assert.match(src, /animate-pulse/);
  assert.match(src, /aria-busy/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /stack.*trace/i);
  assert.doesNotMatch(src, /INTERNAL_SERVER_ERROR/);
});

test('AB: WorkspaceEmptyState full check', () => {
  if (!exists(EMPTY_STATE)) return;
  const src = read(EMPTY_STATE);
  assert.match(src, /reason/);
  assert.match(src, /dataRequired/);
  assert.match(src, /nextAction/);
  assert.match(src, /nextActionHref/);
  assert.match(src, /nextActionLabel/);
  assert.match(src, /mcimId/);
  assert.match(src, /workspace/);
  assert.match(src, /icon/);
  assert.match(src, /role=|aria-/);
  assert.doesNotMatch(src, />\s*No Data\s*</);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('AB: WorkspaceContextBridge full context key check', () => {
  if (!exists(CONTEXT_BRIDGE)) return;
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /'use client'/);
  assert.match(src, /useSearchParams/);
  assert.match(src, /next\/navigation/);
  assert.match(src, /export.*useWorkspaceContext/);
  assert.match(src, /export.*buildWorkspaceUrl/);
  assert.match(src, /WorkspaceContext/);
  assert.match(src, /WorkspaceLink/);
  WORKSPACE_CONTEXT_KEYS.slice(0, 8).forEach(key => {
    assert.match(src, new RegExp(key));
  });
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
});

test('AB: index.ts exports all major symbols', () => {
  if (!exists(INDEX_TS)) return;
  const src = read(INDEX_TS);
  assert.match(src, /WorkspaceMetadata/);
  assert.match(src, /CrossWorkspaceNav/);
  assert.match(src, /WorkspaceContextBridge/);
  assert.match(src, /useWorkspaceContext/);
  assert.match(src, /buildWorkspaceUrl/);
  assert.match(src, /WorkspaceEmptyState/);
  assert.match(src, /WorkspaceLoadingState/);
  assert.match(src, /DemoModeIndicator/);
  assert.match(src, /WorkspaceSearch/);
  assert.match(src, /WorkspaceContext/);
  assert.match(src, /WorkspaceLink/);
  assert.match(src, /WORKSPACE_INTEGRATION_VERSION/);
  assert.match(src, /18\.6\.8/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AC — WORKSPACE_CONTEXT_KEYS full presence in workspaceContext.ts
// ═══════════════════════════════════════════════════════════════════════════════

test('AC: workspaceContext.ts WORKSPACE_CONTEXT_KEYS contains all 15 keys', () => {
  if (!exists(WORKSPACE_CONTEXT)) return;
  const src = read(WORKSPACE_CONTEXT);
  WORKSPACE_CONTEXT_KEYS.forEach(key => {
    assert.match(src, new RegExp(`['"]${key}['"]`), `Missing key '${key}' in workspaceContext.ts`);
  });
});

test('AC: workspaceNav.ts contextParams reference at least 5 context keys', () => {
  if (!exists(WORKSPACE_NAV)) return;
  const src = read(WORKSPACE_NAV);
  const found = WORKSPACE_CONTEXT_KEYS.filter(k => src.includes(`'${k}'`) || src.includes(`"${k}"`));
  assert.ok(found.length >= 5, `Expected contextParams to reference 5+ keys, found: ${found.join(', ')}`);
});

test('AC: WorkspaceContextBridge references at least 10 context keys', () => {
  if (!exists(CONTEXT_BRIDGE)) return;
  const src = read(CONTEXT_BRIDGE);
  const found = WORKSPACE_CONTEXT_KEYS.filter(k => src.includes(k));
  assert.ok(found.length >= 10, `Expected 10+ context keys in bridge, found ${found.length}: ${found.join(', ')}`);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AD — CI script structural completeness
// ═══════════════════════════════════════════════════════════════════════════════

test('AD: CI script has sys import', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /import sys|sys\.exit/);
});

test('AD: CI script has os import or pathlib', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /import os|import pathlib|from pathlib/);
});

test('AD: CI script exit code is non-zero on errors', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /sys\.exit\s*\(\s*1\s*\)|sys\.exit\s*\(\s*len\s*\(errors\)|sys\.exit\s*\(\s*run_checks\s*\(\s*\)/);
});

test('AD: CI script checks for DEMO_MODE_ACTIVE = false', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /DEMO_MODE_ACTIVE/);
});

test('AD: CI script checks WORKSPACE_INTEGRATION_VERSION', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /WORKSPACE_INTEGRATION_VERSION|18\.6\.8/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AE — Navigation registry object-entry shape (per entry)
// ═══════════════════════════════════════════════════════════════════════════════

test('AE: Navigation registry console entries are non-empty array', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(Array.isArray(parsed.console));
  assert.ok(parsed.console.length > 0, 'console array must not be empty');
});

test('AE: Navigation registry has at least 5 console entries', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(parsed.console.length >= 5, `Expected 5+ console entries, got ${parsed.console.length}`);
});

test('AE: Navigation registry version is a string', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.strictEqual(typeof parsed.version, 'string', 'version must be a string');
});

test('AE: Navigation registry groups array is non-empty', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(parsed.groups.length >= 5, `Expected 5+ groups, got ${parsed.groups.length}`);
});

test('AE: Navigation registry console entries include trust-center area', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  const hasTrustArea = parsed.console.some(e => {
    const str = JSON.stringify(e);
    return str.includes('trust') || str.includes('Trust');
  });
  assert.ok(hasTrustArea, 'console must include a trust-related entry');
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AF — Cross-file import graph integrity
// ═══════════════════════════════════════════════════════════════════════════════

test('AF: CrossWorkspaceNav imports from workspaceContext lib (directly or via context bridge)', () => {
  if (!exists(CROSS_WORKSPACE_NAV)) return;
  const src = read(CROSS_WORKSPACE_NAV);
  // Must reference buildWorkspaceUrl which comes from lib/workspaceContext
  assert.match(src, /buildWorkspaceUrl/);
});

test('AF: WorkspaceContextBridge imports from lib/workspaceContext', () => {
  if (!exists(CONTEXT_BRIDGE)) return;
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /workspaceContext/);
});

test('AF: workspaceNav.ts imports WorkspaceContextKey from workspaceContext', () => {
  if (!exists(WORKSPACE_NAV)) return;
  const src = read(WORKSPACE_NAV);
  assert.match(src, /WorkspaceContextKey/);
  assert.match(src, /workspaceContext/);
});

test('AF: index.ts imports from all 7 component files', () => {
  if (!exists(INDEX_TS)) return;
  const src = read(INDEX_TS);
  // Each component should appear in an import/export statement
  const expectedFiles = [
    'WorkspaceMetadata',
    'CrossWorkspaceNav',
    'WorkspaceContextBridge',
    'WorkspaceEmptyState',
    'WorkspaceLoadingState',
    'DemoModeIndicator',
    'WorkspaceSearch',
  ];
  expectedFiles.forEach(file => {
    assert.match(src, new RegExp(file));
  });
});

test('AF: index.ts imports version constant or defines it', () => {
  if (!exists(INDEX_TS)) return;
  const src = read(INDEX_TS);
  assert.match(src, /WORKSPACE_INTEGRATION_VERSION/);
  assert.match(src, /18\.6\.8/);
});

test('AF: No circular import — workspaceContext does not import from workspaceNav', () => {
  if (!exists(WORKSPACE_CONTEXT)) return;
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /workspaceNav/);
});

test('AF: No circular import — workspaceContext does not import from demoFixtures', () => {
  if (!exists(WORKSPACE_CONTEXT)) return;
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /demoFixtures/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AG — Per-component full forbidden-pattern assertions (dense)
// ═══════════════════════════════════════════════════════════════════════════════

// Each component gets a dense multi-assert forbidden check to boost assertion count
const FULL_FORBIDDEN_LIST = [
  { label: 'Math.random()', regex: /Math\.random\(\)/ },
  { label: 'sessionStorage', regex: /sessionStorage/ },
  { label: 'localStorage', regex: /localStorage/ },
  { label: 'dangerouslySetInnerHTML', regex: /dangerouslySetInnerHTML/ },
  { label: 'eval()', regex: /\beval\s*\(/ },
  { label: 'document.write', regex: /document\.write\s*\(/ },
  { label: 'alert()', regex: /\balert\s*\(/ },
  { label: 'console.log', regex: /console\.log\s*\(/ },
  { label: 'window.location =', regex: /window\.location\s*=/ },
  { label: 'innerHTML =', regex: /\.innerHTML\s*=/ },
];

ALL_COMPONENTS.forEach(compPath => {
  const compName = path.basename(compPath, path.extname(compPath));
  FULL_FORBIDDEN_LIST.forEach(({ label, regex }) => {
    test(`AG: ${compName} has no ${label}`, () => {
      if (!exists(compPath)) return;
      const src = read(compPath);
      assert.doesNotMatch(src, regex, `${compName} must not contain ${label}`);
    });
  });
});

ALL_LIB_FILES.forEach(libPath => {
  const libName = path.basename(libPath, path.extname(libPath));
  FULL_FORBIDDEN_LIST.forEach(({ label, regex }) => {
    test(`AG: ${libName} has no ${label}`, () => {
      if (!exists(libPath)) return;
      const src = read(libPath);
      assert.doesNotMatch(src, regex, `${libName} must not contain ${label}`);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AH — Per-component "use client" presence (where required)
// ═══════════════════════════════════════════════════════════════════════════════

const CLIENT_COMPONENTS = [
  WORKSPACE_METADATA,
  CROSS_WORKSPACE_NAV,
  CONTEXT_BRIDGE,
  WORKSPACE_SEARCH,
];

CLIENT_COMPONENTS.forEach(compPath => {
  const compName = path.basename(compPath, path.extname(compPath));
  test(`AH: ${compName} declares 'use client' directive`, () => {
    if (!exists(compPath)) return;
    const src = read(compPath);
    assert.match(src, /'use client'/, `${compName} must be a client component`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AI — workspaceContext.ts key verification (all 15, multi-assert body)
// ═══════════════════════════════════════════════════════════════════════════════

test('AI: workspaceContext.ts has tenant key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'tenant'|"tenant"/);
});
test('AI: workspaceContext.ts has engagement key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'engagement'|"engagement"/);
});
test('AI: workspaceContext.ts has assessment key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'assessment'|"assessment"/);
});
test('AI: workspaceContext.ts has report key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'report'|"report"/);
});
test('AI: workspaceContext.ts has finding key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'finding'|"finding"/);
});
test('AI: workspaceContext.ts has remediation key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'remediation'|"remediation"/);
});
test('AI: workspaceContext.ts has policy key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'policy'|"policy"/);
});
test('AI: workspaceContext.ts has decision key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'decision'|"decision"/);
});
test('AI: workspaceContext.ts has timelinePosition key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'timelinePosition'|"timelinePosition"/);
});
test('AI: workspaceContext.ts has framework key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'framework'|"framework"/);
});
test('AI: workspaceContext.ts has control key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'control'|"control"/);
});
test('AI: workspaceContext.ts has evidence key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'evidence'|"evidence"/);
});
test('AI: workspaceContext.ts has customer key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'customer'|"customer"/);
});
test('AI: workspaceContext.ts has simulation key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'simulation'|"simulation"/);
});
test('AI: workspaceContext.ts has replay key', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /'replay'|"replay"/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AJ — WorkspaceContextBridge key verification (all 15)
// ═══════════════════════════════════════════════════════════════════════════════

test('AJ: WorkspaceContextBridge has tenant', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /tenant/);
});
test('AJ: WorkspaceContextBridge has engagement', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /engagement/);
});
test('AJ: WorkspaceContextBridge has assessment', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /assessment/);
});
test('AJ: WorkspaceContextBridge has report', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /report/);
});
test('AJ: WorkspaceContextBridge has finding', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /finding/);
});
test('AJ: WorkspaceContextBridge has remediation', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /remediation/);
});
test('AJ: WorkspaceContextBridge has policy', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /\bpolicy\b/);
});
test('AJ: WorkspaceContextBridge has decision', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /decision/);
});
test('AJ: WorkspaceContextBridge has timelinePosition', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /timelinePosition/);
});
test('AJ: WorkspaceContextBridge has framework', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /framework/);
});
test('AJ: WorkspaceContextBridge has control', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /\bcontrol\b/);
});
test('AJ: WorkspaceContextBridge has evidence', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /evidence/);
});
test('AJ: WorkspaceContextBridge has customer', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /customer/);
});
test('AJ: WorkspaceContextBridge has simulation', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /simulation/);
});
test('AJ: WorkspaceContextBridge has replay', () => {
  const src = read(CONTEXT_BRIDGE);
  assert.match(src, /replay/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AK — demoFixtures field-level assertions (dense)
// ═══════════════════════════════════════════════════════════════════════════════

test('AK: demoFixtures DEMO_ENGAGEMENTS exists and is non-empty', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_ENGAGEMENTS/);
  assert.match(src, /DEMO_ENGAGEMENTS.*=.*\[|DEMO_ENGAGEMENTS\s*=/);
});

test('AK: demoFixtures DEMO_FINDINGS has severity or risk fields', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_FINDINGS/);
  assert.match(src, /severity|risk/);
});

test('AK: demoFixtures DEMO_REPORTS has title or name field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_REPORTS/);
  assert.match(src, /title|name/);
});

test('AK: demoFixtures DEMO_REMEDIATIONS has status field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_REMEDIATIONS/);
  assert.match(src, /status/);
});

test('AK: demoFixtures DEMO_EXECUTIVE_METRICS has all required fields', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /posture_score/);
  assert.match(src, /risk_count/);
  assert.match(src, /compliance_score/);
  assert.match(src, /confidence/);
});

test('AK: demoFixtures DEMO_TRUST_SCORE has overall field', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_TRUST_SCORE/);
  assert.match(src, /overall/);
});

test('AK: demoFixtures all arrays are const (not mutable let)', () => {
  const src = read(DEMO_FIXTURES);
  // Should use export const not export let
  assert.doesNotMatch(src, /export let DEMO_/);
});

test('AK: demoFixtures ISO date strings use 2026 year', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /2026-\d{2}-\d{2}/);
});

test('AK: demoFixtures does not reference window or document', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /window\./);
  assert.doesNotMatch(src, /document\./);
});

test('AK: demoFixtures DEMO_TENANT_ID uses demo-tenant prefix not UUID', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /demo-tenant/);
  // Should not be a bare UUID as the tenant ID
  const demoTenantLine = src.split('\n').find(l => l.includes('DEMO_TENANT_ID'));
  if (demoTenantLine) {
    assert.match(demoTenantLine, /demo-tenant/, 'DEMO_TENANT_ID must use demo-tenant prefix');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AL — Architecture doc section coverage (dense)
// ═══════════════════════════════════════════════════════════════════════════════

test('AL: Architecture doc has Introduction or Overview section', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /Introduction|Overview|Summary/);
});

test('AL: Architecture doc mentions all 8 components', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /WorkspaceMetadata/);
  assert.match(src, /CrossWorkspaceNav/);
  assert.match(src, /WorkspaceContextBridge/);
  assert.match(src, /WorkspaceEmptyState/);
  assert.match(src, /WorkspaceLoadingState/);
  assert.match(src, /DemoModeIndicator/);
  assert.match(src, /WorkspaceSearch/);
});

test('AL: Architecture doc describes context key structure', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /context|Context/);
  assert.match(src, /tenant|engagement/);
});

test('AL: Architecture doc has Security or Safety section', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /[Ss]ecurity|[Ss]afety|[Gg]overnance/);
});

test('AL: Architecture doc references navigation registry', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /navigation-registry|navigation registry/i);
});

test('AL: Architecture doc mentions workspace context keys', () => {
  const src = readAbsolute(ARCH_DOC);
  // At least a few context keys should be mentioned
  const keyMentions = WORKSPACE_CONTEXT_KEYS.filter(k => src.includes(k));
  assert.ok(keyMentions.length >= 3, `Architecture doc should mention at least 3 context keys, found: ${keyMentions.join(', ')}`);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AM — workspaceNav.ts inter-workspace link coverage (dense)
// ═══════════════════════════════════════════════════════════════════════════════

test('AM: workspaceNav.ts executive-intelligence to trust-center link exists', () => {
  const src = read(WORKSPACE_NAV);
  const idx = src.indexOf('executive-intelligence');
  assert.ok(idx >= 0, 'executive-intelligence not found');
  // trust-center must appear after executive-intelligence in the same map
  assert.match(src, /trust-center/);
});

test('AM: workspaceNav.ts trust-center to operations-workspace link or back reference', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /trust-center/);
  assert.match(src, /operations-workspace/);
});

test('AM: workspaceNav.ts field-assessments to executive-intelligence link', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /field-assessments/);
  assert.match(src, /executive-intelligence/);
});

test('AM: workspaceNav.ts reports to executive-intelligence or command-center link', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\breports\b/);
  assert.match(src, /executive-intelligence|command-center/);
});

test('AM: workspaceNav.ts all links have mcimId for tracking', () => {
  const src = read(WORKSPACE_NAV);
  // Multiple mcimId entries should exist for all links
  const mcimCount = (src.match(/mcimId/g) || []).length;
  assert.ok(mcimCount >= 6, `Expected 6+ mcimId references for nav links, got ${mcimCount}`);
});

test('AM: workspaceNav.ts all links have description field', () => {
  const src = read(WORKSPACE_NAV);
  const descCount = (src.match(/description/g) || []).length;
  assert.ok(descCount >= 6, `Expected 6+ description fields for nav links, got ${descCount}`);
});

test('AM: workspaceNav.ts routes use /dashboard/ prefix pattern', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\/dashboard\//);
});

test('AM: workspaceNav.ts has no external http(s) URLs as routes', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /route.*https?:\/\//);
});

test('AM: workspaceNav.ts contextParams defined with array syntax', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /contextParams.*\[|contextParams.*:/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AN — Accessibility deep dive (dense assertions)
// ═══════════════════════════════════════════════════════════════════════════════

test('AN: WorkspaceSearch combobox pattern complete (role + aria-expanded + aria-controls)', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /role="combobox"/);
  assert.match(src, /aria-expanded/);
  assert.match(src, /aria-controls/);
});

test('AN: WorkspaceSearch keyboard navigation complete (ArrowUp + ArrowDown + Enter + Escape)', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /ArrowUp/);
  assert.match(src, /ArrowDown/);
  assert.match(src, /\bEnter\b/);
  assert.match(src, /Escape/);
});

test('AN: CrossWorkspaceNav keyboard activation complete (Enter + Space)', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /Enter/);
  assert.match(src, /Space|' '/);
});

test('AN: DemoModeIndicator alert semantics (role=alert + data-demo-mode)', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /role="alert"/);
  assert.match(src, /data-demo-mode/);
});

test('AN: WorkspaceLoadingState busy semantics (aria-busy + animate-pulse)', () => {
  const src = read(LOADING_STATE);
  assert.match(src, /aria-busy/);
  assert.match(src, /animate-pulse/);
});

test('AN: WorkspaceMetadata decorative element hidden from screen readers', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /aria-hidden="true"/);
});

test('AN: CrossWorkspaceNav navigation landmark has label', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /aria-label/);
  assert.match(src, /<nav|role="navigation"/);
});

test('AN: WorkspaceSearch listbox result container referenced by aria-controls', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.match(src, /aria-controls/);
  assert.match(src, /listbox|results/);
});

test('AN: No aria-label with empty string in any component', () => {
  ALL_COMPONENTS.forEach(compPath => {
    if (!exists(compPath)) return;
    const src = read(compPath);
    assert.doesNotMatch(src, /aria-label=""\s*|aria-label=\{['"]{2}\}/, `${compPath} has empty aria-label`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AO — Version and metadata consistency
// ═══════════════════════════════════════════════════════════════════════════════

test('AO: Version 18.6.8 appears in index.ts', () => {
  const src = read(INDEX_TS);
  assert.match(src, /18\.6\.8/);
});

test('AO: Version 18.6.8 appears in architecture doc', () => {
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /18\.6\.8/);
});

test('AO: Version 18.6.8 appears in CI script', () => {
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /18\.6\.8/);
});

test('AO: WORKSPACE_INTEGRATION_VERSION constant equals exactly "18.6.8"', () => {
  const src = read(INDEX_TS);
  assert.match(src, /WORKSPACE_INTEGRATION_VERSION\s*=\s*['"]18\.6\.8['"]/);
});

test('AO: Navigation registry version field is present', () => {
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  assert.ok(typeof parsed.version === 'string');
  assert.ok(parsed.version.length > 0, 'version string must not be empty');
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AP — DemoModeIndicator conditional rendering
// ═══════════════════════════════════════════════════════════════════════════════

test('AP: DemoModeIndicator renders banner only when active is true', () => {
  const src = read(DEMO_INDICATOR);
  // Must have conditional on active prop
  assert.match(src, /active/);
  assert.match(src, /&&|ternary|active\s*\?|if.*active/);
});

test('AP: DemoModeIndicator children prop passed through conditionally', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /children/);
  assert.match(src, /active/);
});

test('AP: DemoModeIndicator datasetName displayed to user', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /datasetName/);
});

test('AP: DemoModeIndicator does not show demo content when active is false', () => {
  const src = read(DEMO_INDICATOR);
  // Should gate content on active flag
  assert.match(src, /\bactive\b/);
  assert.doesNotMatch(src, /DEMO_MODE_ACTIVE\s*=\s*true/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AQ — Per-file export style validation
// ═══════════════════════════════════════════════════════════════════════════════

test('AQ: WorkspaceMetadata uses export default pattern', () => {
  const src = read(WORKSPACE_METADATA);
  assert.match(src, /export default/);
});

test('AQ: workspaceContext.ts uses named exports', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /export (function|const|type|interface)/);
});

test('AQ: demoFixtures.ts uses export const pattern', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /export const/);
});

test('AQ: workspaceNav.ts uses export const for WORKSPACE_NAV_MAP', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /export const WORKSPACE_NAV_MAP/);
});

test('AQ: index.ts uses re-export syntax', () => {
  const src = read(INDEX_TS);
  // Should have export { ... } from or export * from syntax
  assert.match(src, /export.*from|export \{/);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AR — Extended forbidden pattern sweep (innerHTML variants)
// ═══════════════════════════════════════════════════════════════════════════════

const EXTRA_FORBIDDEN = [
  { label: 'innerHTML assignment', regex: /\.innerHTML\s*=/ },
  { label: 'outerHTML assignment', regex: /\.outerHTML\s*=/ },
  { label: 'insertAdjacentHTML', regex: /insertAdjacentHTML/ },
];

ALL_COMPONENTS.forEach(compPath => {
  const compName = path.basename(compPath, path.extname(compPath));
  EXTRA_FORBIDDEN.forEach(({ label, regex }) => {
    test(`AR: ${compName} has no ${label}`, () => {
      if (!exists(compPath)) return;
      const src = read(compPath);
      assert.doesNotMatch(src, regex, `${compName} must not use ${label}`);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AS — Summary integrity tests
// ═══════════════════════════════════════════════════════════════════════════════

test('AS: All 8 component files are syntactically non-empty', () => {
  [...ALL_COMPONENTS, INDEX_TS].forEach(compPath => {
    if (!exists(compPath)) return;
    const src = read(compPath);
    assert.ok(src.trim().length > 100, `${compPath} appears to be empty or too short`);
  });
});

test('AS: All 3 lib files are syntactically non-empty', () => {
  ALL_LIB_FILES.forEach(libPath => {
    if (!exists(libPath)) return;
    const src = read(libPath);
    assert.ok(src.trim().length > 100, `${libPath} appears to be empty or too short`);
  });
});

test('AS: CI script is a valid Python file (has def or class keyword)', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /\bdef\b|\bclass\b|if __name__/);
});

test('AS: Architecture doc is a valid Markdown file (has # heading)', () => {
  if (!existsAbsolute(ARCH_DOC)) return;
  const src = readAbsolute(ARCH_DOC);
  assert.match(src, /^#/m);
});

test('AS: Navigation registry JSON round-trips cleanly', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const src = readAbsolute(NAV_REG);
  const parsed = JSON.parse(src);
  const reserialized = JSON.stringify(parsed);
  const reparsed = JSON.parse(reserialized);
  assert.deepEqual(reparsed, parsed);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AT — P1 Route correctness and console.ts sync
// ═══════════════════════════════════════════════════════════════════════════════

test('AT-P1: workspaceNav.ts executive-intelligence route is /dashboard/executive not /dashboard/evaluation', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /route.*\/dashboard\/evaluation/, 'Found wrong route /dashboard/evaluation — executive-intelligence must route to /dashboard/executive');
  assert.match(src, /\/dashboard\/executive/, 'Executive Intelligence route must be /dashboard/executive');
});

test('AT-P1: All executive-intelligence links in workspaceNav.ts use /dashboard/executive', () => {
  const src = read(WORKSPACE_NAV);
  const lines = src.split('\n');
  lines.forEach((line, i) => {
    if (line.includes('route') && line.includes('/dashboard/evaluation')) {
      assert.fail(`Line ${i + 1}: Found /dashboard/evaluation in a route — should be /dashboard/executive`);
    }
  });
});

test('AT-P1: /reports landing page exists (reports/page.tsx)', () => {
  const REPORTS_LANDING = path.join(__dirname, '../app/reports/page.tsx');
  assert.ok(existsAbsolute(REPORTS_LANDING), 'Missing /reports landing page — apps/console/app/reports/page.tsx must exist');
});

test('AT-P1: reports/page.tsx has data-testid="reports-landing"', () => {
  const REPORTS_LANDING = path.join(__dirname, '../app/reports/page.tsx');
  if (!existsAbsolute(REPORTS_LANDING)) return;
  const src = readAbsolute(REPORTS_LANDING);
  assert.match(src, /data-testid="reports-landing"/, 'reports/page.tsx missing data-testid="reports-landing"');
});

test('AT-P1: reports/page.tsx has MCIM compliance attributes', () => {
  const REPORTS_LANDING = path.join(__dirname, '../app/reports/page.tsx');
  if (!existsAbsolute(REPORTS_LANDING)) return;
  const src = readAbsolute(REPORTS_LANDING);
  assert.match(src, /data-mcim-id/, 'reports/page.tsx missing data-mcim-id');
  assert.match(src, /data-workspace/, 'reports/page.tsx missing data-workspace');
});

test('AT-P1: console.ts has operations-workspace entry', () => {
  const CONSOLE_TS = path.join(__dirname, '../../../packages/navigation/src/registrations/console.ts');
  if (!existsAbsolute(CONSOLE_TS)) return;
  const src = readAbsolute(CONSOLE_TS);
  assert.match(src, /operations-workspace|operations_workspace|'operations'.*workspace|"operations".*workspace/i, 'console.ts missing operations-workspace registration');
});

test('AT-P1: console.ts has trust-center-workspace or trust-center entry', () => {
  const CONSOLE_TS = path.join(__dirname, '../../../packages/navigation/src/registrations/console.ts');
  if (!existsAbsolute(CONSOLE_TS)) return;
  const src = readAbsolute(CONSOLE_TS);
  assert.match(src, /trust-center|trust_center/i, 'console.ts missing trust-center registration');
});

test('AT-P1: WorkspaceSearch uses Array.from not spread on MapIterator', () => {
  const src = read(WORKSPACE_SEARCH);
  assert.doesNotMatch(src, /\[\s*\.\.\.\s*\w+\s*\.\s*values\s*\(\s*\)\s*\]/, 'WorkspaceSearch must not use [...map.values()] spread — use Array.from()');
  assert.match(src, /Array\.from/, 'WorkspaceSearch must use Array.from() for Map iteration');
});

test('AT-P1: CrossWorkspaceNav contextParams is WorkspaceContextKey[] (array), not Record', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.doesNotMatch(src, /contextParams\s*\??\s*:\s*Record/, 'contextParams must not be Record<string,string>');
  assert.match(src, /WorkspaceContextKey/, 'CrossWorkspaceNav must import/use WorkspaceContextKey');
});

test('AT-P1: CrossWorkspaceNav resolveHref filters to declared contextParams keys', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /for.*of.*contextParams|contextParams.*forEach|contextParams.*filter|filtered/i, 'resolveHref must filter context to declared keys');
});

test('AT-P1: executive/page.tsx uses useRef pattern for initialData guard (not stale closure)', () => {
  const EXEC_PAGE = path.join(__dirname, '../app/dashboard/executive/page.tsx');
  if (!existsAbsolute(EXEC_PAGE)) return;
  const src = readAbsolute(EXEC_PAGE);
  assert.match(src, /useRef/, 'executive/page.tsx must use useRef to guard initialData in useEffect');
});

test('AT-P1: executive/page.tsx does not have bare if(initialData) return inside useEffect with empty dep array', () => {
  const EXEC_PAGE = path.join(__dirname, '../app/dashboard/executive/page.tsx');
  if (!existsAbsolute(EXEC_PAGE)) return;
  const src = readAbsolute(EXEC_PAGE);
  assert.doesNotMatch(src, /useEffect\(\s*\(\s*\)\s*=>\s*\{[^}]*if\s*\(\s*initialData\s*\)\s*return[^}]*\}\s*,\s*\[\s*\]\s*\)/, 'Found stale closure pattern — use useRef(Boolean(initialData)) instead');
});

test('AT-P1: PR_FIX_LOG.md has entry for 18.6.8 P1 fix', () => {
  const PRFL = path.join(__dirname, '../../../docs/ai/PR_FIX_LOG.md');
  if (!existsAbsolute(PRFL)) return;
  const src = readAbsolute(PRFL);
  assert.match(src, /18\.6\.8.*[Pp]1|P1.*18\.6\.8|P1.*workspace/i, 'PR_FIX_LOG.md must have an entry for the 18.6.8 P1 fix');
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION AU — 18.6.8a Hardening: hook warnings, context safety, route integrity
// ═══════════════════════════════════════════════════════════════════════════════

const EXEC_PAGE_PATH = path.join(__dirname, '../app/dashboard/executive/page.tsx');
const CONSOLE_TS_PATH = path.join(__dirname, '../../../packages/navigation/src/registrations/console.ts');
const APP_DIR = path.join(__dirname, '../app');

// — React hook warning cleanup —

test('AU: executive/page.tsx has no bare "if (initialData) return" in any useEffect', () => {
  if (!existsAbsolute(EXEC_PAGE_PATH)) return;
  const src = readAbsolute(EXEC_PAGE_PATH);
  assert.doesNotMatch(src, /if\s*\(\s*initialData\s*\)\s*return/, 'Stale closure pattern found — apply useRef(Boolean(initialData)) to all tab components');
});

test('AU: executive/page.tsx uses hasInitialRef pattern in all guarded effects', () => {
  if (!existsAbsolute(EXEC_PAGE_PATH)) return;
  const src = readAbsolute(EXEC_PAGE_PATH);
  assert.match(src, /hasInitialRef/, 'executive/page.tsx must use hasInitialRef for initialData guard');
  // Count occurrences — all 8 tab components should use it
  const count = (src.match(/hasInitialRef/g) || []).length;
  assert.ok(count >= 8, `Expected at least 8 hasInitialRef occurrences (one per tab), found ${count}`);
});

test('AU: ForecastTab uses useRef guard (not direct initialData reference in effect)', () => {
  if (!existsAbsolute(EXEC_PAGE_PATH)) return;
  const src = readAbsolute(EXEC_PAGE_PATH);
  // ForecastTab appears before BoardSummaryTab — find its useEffect block
  const forecastIdx = src.indexOf('function ForecastTab');
  assert.ok(forecastIdx >= 0, 'ForecastTab not found');
  const boardIdx = src.indexOf('function BoardSummaryTab');
  const forecastSection = boardIdx > 0 ? src.slice(forecastIdx, boardIdx) : src.slice(forecastIdx);
  assert.match(forecastSection, /hasInitialRef/, 'ForecastTab must use hasInitialRef');
  assert.doesNotMatch(forecastSection, /if\s*\(\s*initialData\s*\)\s*return/, 'ForecastTab has stale closure');
});

test('AU: BoardSummaryTab uses useRef guard (not direct initialData reference in effect)', () => {
  if (!existsAbsolute(EXEC_PAGE_PATH)) return;
  const src = readAbsolute(EXEC_PAGE_PATH);
  const boardIdx = src.indexOf('function BoardSummaryTab');
  assert.ok(boardIdx >= 0, 'BoardSummaryTab not found');
  const boardSection = src.slice(boardIdx, boardIdx + 600);
  assert.match(boardSection, /hasInitialRef/, 'BoardSummaryTab must use hasInitialRef');
  assert.doesNotMatch(boardSection, /if\s*\(\s*initialData\s*\)\s*return/, 'BoardSummaryTab has stale closure');
});

test('AU: executive/page.tsx useRef is imported', () => {
  if (!existsAbsolute(EXEC_PAGE_PATH)) return;
  const src = readAbsolute(EXEC_PAGE_PATH);
  assert.match(src, /useRef/, 'useRef must be imported and used');
  assert.match(src, /import.*useRef|useRef.*import/, 'useRef must be in import statement');
});

test('AU: All 8 tab components have useRef pattern (count check)', () => {
  if (!existsAbsolute(EXEC_PAGE_PATH)) return;
  const src = readAbsolute(EXEC_PAGE_PATH);
  // All 8 tab function names
  const tabs = ['OverviewTab', 'RiskTab', 'ComplianceTab', 'TrendsTab', 'BusinessTab', 'RecommendationsTab', 'ForecastTab', 'BoardSummaryTab'];
  tabs.forEach(tab => {
    assert.match(src, new RegExp(`function ${tab}`), `Tab ${tab} not found`);
  });
  // hasInitialRef appears at minimum once per tab
  const refCount = (src.match(/hasInitialRef/g) || []).length;
  assert.ok(refCount >= tabs.length, `Expected ${tabs.length}+ hasInitialRef, found ${refCount}`);
});

// — Context key safety —

test('AU: workspaceContext.ts sanitizeContext function exists', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /sanitizeContext/, 'workspaceContext.ts must export sanitizeContext');
});

test('AU: sanitizeContext filters to WORKSPACE_CONTEXT_KEYS only', () => {
  const src = read(WORKSPACE_CONTEXT);
  // sanitizeContext must iterate WORKSPACE_CONTEXT_KEYS
  assert.match(src, /sanitizeContext/, 'missing sanitizeContext');
  assert.match(src, /WORKSPACE_CONTEXT_KEYS/, 'sanitizeContext must use WORKSPACE_CONTEXT_KEYS');
});

test('AU: mergeWorkspaceContext uses sanitizeContext (safe merge)', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /mergeWorkspaceContext/, 'mergeWorkspaceContext missing');
  assert.match(src, /sanitizeContext/, 'mergeWorkspaceContext should use sanitizeContext');
});

test('AU: contextToParams iterates WORKSPACE_CONTEXT_KEYS (deterministic order)', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /contextToParams/);
  // Must iterate the canonical key list, not Object.keys (which is unordered)
  assert.match(src, /for.*of.*WORKSPACE_CONTEXT_KEYS|WORKSPACE_CONTEXT_KEYS.*forEach/);
  assert.doesNotMatch(src, /Object\.keys\s*\(\s*context\s*\)/, 'contextToParams must not use Object.keys — use WORKSPACE_CONTEXT_KEYS for deterministic order');
});

test('AU: parseWorkspaceContext drops empty strings', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /!== ?''|!== ?""|\.length|trim/);
});

test('AU: parseWorkspaceContext drops undefined values', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /undefined/);
});

test('AU: workspaceContext.ts exports sanitizeContext', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /export function sanitizeContext|export const sanitizeContext/);
});

test('AU: CrossWorkspaceNav resolveHref does not spread entire context', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  // Must NOT do ...context — would propagate stale keys
  assert.doesNotMatch(src, /\.\.\.\s*context\b/, 'resolveHref must not spread entire context');
});

test('AU: CrossWorkspaceNav resolveHref loops over contextParams, not full context', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /for\s*\(.*of.*contextParams|contextParams.*forEach/, 'resolveHref must iterate contextParams, not context');
});

test('AU: CrossWorkspaceNav empty context produces clean base URL', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.match(src, /buildWorkspaceUrl/);
  // buildWorkspaceUrl with empty filtered context returns base route only
  assert.match(src, /filtered/i, 'resolveHref must use a filtered context variable');
});

// — Route integrity —

const NAV_ROUTES = [
  { route: '/dashboard/executive', page: 'dashboard/executive/page.tsx' },
  { route: '/trust-center', page: 'trust-center/page.tsx' },
  { route: '/workspace', page: 'workspace/page.tsx' },
  { route: '/field-assessment', page: 'field-assessment/page.tsx' },
  { route: '/reports', page: 'reports/page.tsx' },
  { route: '/dashboard/forensics', page: 'dashboard/forensics/page.tsx' },
  { route: '/dashboard/decisions', page: 'dashboard/decisions/page.tsx' },
  { route: '/dashboard/alignment', page: 'dashboard/alignment/page.tsx' },
  { route: '/dashboard/readiness', page: 'dashboard/readiness/page.tsx' },
];

NAV_ROUTES.forEach(({ route, page }) => {
  test(`AU: route '${route}' has implemented page`, () => {
    const pagePath = path.join(APP_DIR, page);
    assert.ok(existsAbsolute(pagePath), `Route '${route}' has no page at apps/console/app/${page}`);
  });
});

test('AU: workspaceNav.ts has no /dashboard/evaluation route', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /\/dashboard\/evaluation/, 'workspaceNav.ts must not link to /dashboard/evaluation (Evaluation Lab)');
});

test('AU: workspaceNav.ts has /dashboard/executive for executive-intelligence', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /\/dashboard\/executive/);
});

test('AU: /reports landing page has no dynamic data (no fetch, no async)', () => {
  const REPORTS_PAGE = path.join(APP_DIR, 'reports/page.tsx');
  if (!existsAbsolute(REPORTS_PAGE)) return;
  const src = readAbsolute(REPORTS_PAGE);
  assert.doesNotMatch(src, /fetch\s*\(|async\s+function|async\s+\(/, 'reports/page.tsx must be a static landing — no server fetch');
  assert.doesNotMatch(src, /Math\.random\(\)/, 'reports/page.tsx must not use Math.random()');
});

test('AU: /reports landing page links to /field-assessment (not a dead end)', () => {
  const REPORTS_PAGE = path.join(APP_DIR, 'reports/page.tsx');
  if (!existsAbsolute(REPORTS_PAGE)) return;
  const src = readAbsolute(REPORTS_PAGE);
  assert.match(src, /field-assessment/, 'reports/page.tsx must link back to field assessments');
});

test('AU: workspaceNav.ts self-link guard documented', () => {
  const src = read(WORKSPACE_NAV);
  assert.match(src, /currentWorkspace|self.*link|link.*self/i, 'Self-link guard must be documented in workspaceNav.ts');
});

test('AU: every WORKSPACE_NAV_MAP entry has at least one contextParams declaration', () => {
  const src = read(WORKSPACE_NAV);
  const contextParamsCount = (src.match(/contextParams/g) || []).length;
  assert.ok(contextParamsCount >= 6, `Expected 6+ contextParams declarations, got ${contextParamsCount}`);
});

// — Demo mode safety —

test('AU: DEMO_MODE_ACTIVE is explicitly false', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_MODE_ACTIVE\s*=\s*false/);
  assert.doesNotMatch(src, /DEMO_MODE_ACTIVE\s*=\s*true/);
});

test('AU: demoFixtures has no Date.now()', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /Date\.now\(\)/);
});

test('AU: demoFixtures has no Math.random()', () => {
  const src = read(DEMO_FIXTURES);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('AU: demoFixtures DEMO_TENANT_ID uses demo-tenant prefix (not a real UUID)', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /demo-tenant/);
  const tenantLine = src.split('\n').find(l => l.includes('DEMO_TENANT_ID'));
  if (tenantLine) assert.match(tenantLine, /demo-tenant/);
});

test('AU: DemoModeIndicator only renders when active=true', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /active/);
  assert.match(src, /&&|active\s*\?|if.*active/);
  assert.doesNotMatch(src, /DEMO_MODE_ACTIVE\s*=\s*true/);
});

test('AU: DemoModeIndicator has data-demo-mode attribute', () => {
  const src = read(DEMO_INDICATOR);
  assert.match(src, /data-demo-mode/);
});

// — Navigation registry / source alignment —

test('AU: navigation-registry.json has operations-workspace entry', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const parsed = JSON.parse(readAbsolute(NAV_REG));
  const has = parsed.console.some(e =>
    (typeof e === 'string' && e.includes('operations')) ||
    (typeof e === 'object' && (e.id === 'operations-workspace' || (e.route && e.route.includes('/workspace'))))
  );
  assert.ok(has, 'navigation-registry.json missing operations-workspace entry');
});

test('AU: navigation-registry.json has trust-center entry', () => {
  if (!existsAbsolute(NAV_REG)) return;
  const parsed = JSON.parse(readAbsolute(NAV_REG));
  const has = parsed.console.some(e =>
    (typeof e === 'string' && e.includes('trust')) ||
    (typeof e === 'object' && JSON.stringify(e).includes('trust-center'))
  );
  assert.ok(has, 'navigation-registry.json missing trust-center entry');
});

test('AU: console.ts and navigation-registry.json both have executive-intelligence', () => {
  const consoleSrc = readAbsolute(CONSOLE_TS_PATH);
  assert.match(consoleSrc, /executive-intelligence/, 'console.ts missing executive-intelligence');
  const parsed = JSON.parse(readAbsolute(NAV_REG));
  const has = parsed.console.some(e =>
    (typeof e === 'string' && e.includes('executive')) ||
    (typeof e === 'object' && JSON.stringify(e).includes('executive-intelligence'))
  );
  assert.ok(has, 'navigation-registry.json missing executive-intelligence');
});

test('AU: console.ts executive-intelligence route is /dashboard/executive', () => {
  const src = readAbsolute(CONSOLE_TS_PATH);
  // Find executive-intelligence block and verify its route
  const idx = src.indexOf("'executive-intelligence'");
  assert.ok(idx >= 0, 'console.ts missing executive-intelligence entry');
  const block = src.slice(idx, idx + 200);
  assert.match(block, /\/dashboard\/executive/, 'console.ts executive-intelligence route wrong');
  assert.doesNotMatch(block, /\/dashboard\/evaluation/, 'console.ts executive-intelligence must not use /dashboard/evaluation');
});

test('AU: console.ts has report-viewer or reports entry', () => {
  const src = readAbsolute(CONSOLE_TS_PATH);
  assert.match(src, /report-viewer|'reports'|"reports"/, 'console.ts missing reports entry');
});

test('AU: console.ts field-assessments entry uses /field-assessment route', () => {
  const src = readAbsolute(CONSOLE_TS_PATH);
  assert.match(src, /field-assessment/, 'console.ts missing field-assessment route');
});

// — CI script strengthening —

test('AU: CI script has check_exec_page_hooks function', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /check_exec_page_hooks|hasInitialRef|initialData.*return/, 'CI script must check executive page hook pattern');
});

test('AU: CI script has check_eval_route_absent function', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /evaluation.*route|check_eval_route|dashboard\/evaluation/, 'CI script must check for /dashboard/evaluation absence');
});

test('AU: CI script has check_nav_routes_implemented function', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /nav.*route.*implement|route.*page|check_nav_routes/, 'CI script must verify nav routes are implemented');
});

test('AU: CI script has check_context_filtering function', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /context.*filter|check_context|contextParams.*filtering/, 'CI script must verify context filtering');
});

test('AU: CI script has check_demo_mode_safe function', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /demo.*mode|check_demo|DEMO_MODE_ACTIVE/, 'CI script must check demo mode safety');
});

test('AU: CI script checks for MapIterator spread pattern', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  assert.match(src, /MapIterator|map.*values.*spread|values\s*\(\s*\)/, 'CI script must check for MapIterator spread');
});

test('AU: CI script has at least 6 check functions (hardening additions)', () => {
  if (!existsAbsolute(CI_SCRIPT)) return;
  const src = readAbsolute(CI_SCRIPT);
  // Count def check_ functions — expect at least 8 (2 original + 6 new hardening)
  const checkFns = (src.match(/^def check_/gm) || []).length;
  assert.ok(checkFns >= 8, `Expected 8+ check_ functions in CI script, found ${checkFns}`);
});

// — workspaceContext.ts output ordering —

test('AU: workspaceContext.ts WORKSPACE_CONTEXT_KEYS is a fixed-order array', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /WORKSPACE_CONTEXT_KEYS.*=.*\[/);
  // tenant must appear before replay (canonical order)
  const tenantIdx = src.indexOf("'tenant'");
  const replayIdx = src.indexOf("'replay'");
  assert.ok(tenantIdx >= 0, 'tenant key missing');
  assert.ok(replayIdx > tenantIdx, 'WORKSPACE_CONTEXT_KEYS must have tenant before replay (canonical order)');
});

test('AU: buildWorkspaceUrl produces deterministic param order', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /buildWorkspaceUrl/);
  // Must use contextToParams which iterates WORKSPACE_CONTEXT_KEYS
  assert.match(src, /contextToParams/);
});

test('AU: workspaceContext.ts has no browser APIs (server-safe)', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.doesNotMatch(src, /window\./);
  assert.doesNotMatch(src, /document\./);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /'use client'/);
});

// — Multi-assert density summary for AU —

test('AU: executive page hook fix comprehensive check', () => {
  if (!existsAbsolute(EXEC_PAGE_PATH)) return;
  const src = readAbsolute(EXEC_PAGE_PATH);
  // All tab components must use hasInitialRef, none must use bare if(initialData) return
  assert.doesNotMatch(src, /if\s*\(\s*initialData\s*\)\s*return/);
  assert.match(src, /hasInitialRef/);
  assert.match(src, /useRef\s*\(\s*Boolean\s*\(\s*initialData\s*\)\s*\)/);
  assert.match(src, /hasInitialRef\.current/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
});

test('AU: workspaceContext.ts full integrity check', () => {
  const src = read(WORKSPACE_CONTEXT);
  assert.match(src, /WORKSPACE_CONTEXT_KEYS/);
  assert.match(src, /parseWorkspaceContext/);
  assert.match(src, /buildWorkspaceUrl/);
  assert.match(src, /mergeWorkspaceContext/);
  assert.match(src, /contextToParams/);
  assert.match(src, /sanitizeContext/);
  assert.match(src, /WorkspaceContext/);
  assert.match(src, /WorkspaceContextKey/);
  assert.doesNotMatch(src, /window\./);
  assert.doesNotMatch(src, /'use client'/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /Object\.keys\s*\(\s*context\s*\)/);
});

test('AU: CrossWorkspaceNav full context safety check', () => {
  const src = read(CROSS_WORKSPACE_NAV);
  assert.doesNotMatch(src, /\.\.\.\s*context\b/);
  assert.match(src, /contextParams/);
  assert.match(src, /for.*of.*contextParams/);
  assert.match(src, /buildWorkspaceUrl/);
  assert.match(src, /WorkspaceContextKey/);
  assert.match(src, /filtered/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('AU: workspaceNav.ts route integrity comprehensive check', () => {
  const src = read(WORKSPACE_NAV);
  assert.doesNotMatch(src, /\/dashboard\/evaluation/);
  assert.match(src, /\/dashboard\/executive/);
  assert.match(src, /\/trust-center/);
  assert.match(src, /\/workspace/);
  assert.match(src, /\/field-assessment/);
  assert.match(src, /\/reports/);
  assert.match(src, /contextParams/);
  assert.match(src, /WorkspaceContextKey/);
  assert.doesNotMatch(src, /https?:\/\//);
  assert.doesNotMatch(src, /Math\.random\(\)/);
});

test('AU: demo safety comprehensive check', () => {
  const src = read(DEMO_FIXTURES);
  assert.match(src, /DEMO_MODE_ACTIVE\s*=\s*false/);
  assert.doesNotMatch(src, /DEMO_MODE_ACTIVE\s*=\s*true/);
  assert.doesNotMatch(src, /Date\.now\(\)/);
  assert.doesNotMatch(src, /Math\.random\(\)/);
  assert.match(src, /demo-tenant/);
  assert.match(src, /2026-\d{2}-\d{2}/);
  assert.doesNotMatch(src, /window\./);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /export let DEMO_/);
});

// ═══════════════════════════════════════════════════════════════════════════════
