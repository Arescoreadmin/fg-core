/**
 * console-shell.test.js
 *
 * Static-analysis tests for the PR 43 unified console shell:
 *   - Shell structure (skip-to-content, main landmark, mobile nav)
 *   - Navigation sections and route paths
 *   - Accessibility attributes (aria-current, aria-label, aria-hidden)
 *   - Placeholder routes exist and are safe (no fake data, no live fetches)
 *   - No secret leakage in shell files
 *   - SSR safety (no browser-only APIs at module level)
 *   - Existing routes preserved
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

// ─── Shell structure ──────────────────────────────────────────────────────────

test('dashboard layout includes skip-to-content link targeting main-content', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.match(layout, /Skip to content/);
  assert.match(layout, /href="#main-content"/);
});

test('skip-to-content link is sr-only until focused', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.match(layout, /sr-only/);
});

test('dashboard layout renders main element with id for skip-to-content target', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.match(layout, /id="main-content"/);
});

test('dashboard layout includes mobile nav toggle button with aria-expanded', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.match(layout, /Open navigation/);
  assert.match(layout, /aria-expanded/);
  assert.match(layout, /aria-controls="sidebar-nav"/);
});

test('mobile backdrop overlay has aria-hidden to exclude from assistive technology', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.match(layout, /aria-hidden="true"/);
});

test('dashboard layout does not introduce random IDs or nondeterministic values', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.doesNotMatch(layout, /Math\.random/);
  assert.doesNotMatch(layout, /randomUUID/);
  assert.doesNotMatch(layout, /Date\.now\(\)/);
});

// ─── Navigation sections ──────────────────────────────────────────────────────

test('sidebar contains all required navigation section labels', () => {
  // Sidebar is registry-driven; titles come from CONSOLE_REGISTRY at runtime.
  // Verify Sidebar imports the registry and ICON_MAP covers all required item IDs.
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /CONSOLE_REGISTRY/);
  assert.match(sidebar, /'command-center'/);
  assert.match(sidebar, /'ai-workspace'/);
  assert.match(sidebar, /'corpus'/);
  assert.match(sidebar, /'retrieval'/);
  assert.match(sidebar, /'provenance'/);
  assert.match(sidebar, /'policies'/);
  assert.match(sidebar, /'audit-forensics'/);
  assert.match(sidebar, /'providers'/);
  assert.match(sidebar, /'readiness'/);
  assert.match(sidebar, /'evaluation-lab'/);
  assert.match(sidebar, /'settings'/);
});

test('sidebar contains all required route paths', () => {
  // Routes are served from CONSOLE_REGISTRY; validate via the checked-in JSON snapshot.
  const reg = JSON.parse(read('../../packages/navigation/navigation-registry.json'));
  const routes = reg.console.map((i) => i.route);
  for (const route of [
    '/dashboard',
    '/dashboard/assistant',
    '/dashboard/corpus',
    '/dashboard/retrieval',
    '/dashboard/provenance',
    '/dashboard/policies',
    '/dashboard/forensics',
    '/dashboard/providers',
    '/dashboard/readiness',
    '/dashboard/evaluation',
    '/dashboard/settings',
  ]) {
    assert.ok(routes.includes(route), `registry missing route: ${route}`);
  }
  assert.match(read('components/layout/Sidebar.tsx'), /CONSOLE_REGISTRY/);
});

test('sidebar preserves existing control-tower route and excludes legacy keys route', () => {
  // Routes live in CONSOLE_REGISTRY; validate via the JSON snapshot.
  const reg = JSON.parse(read('../../packages/navigation/navigation-registry.json'));
  const routes = reg.console.map((i) => i.route);
  assert.ok(routes.includes('/dashboard/control-tower'), 'control-tower must be in registry');
  assert.ok(!routes.includes('/dashboard/keys'), '/dashboard/keys must not exist — keys lives at /keys');
});

test('sidebar nav links call onClose on click so mobile drawer closes after navigation', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /onClick={onClose}/);
});

// ─── Accessibility ────────────────────────────────────────────────────────────

test('sidebar uses semantic nav landmark with aria-label', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /<nav/);
  assert.match(sidebar, /aria-label/);
  assert.match(sidebar, /Main navigation/);
});

test('sidebar renders aria-current="page" on active navigation links', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /aria-current/);
  assert.match(sidebar, /aria-current=\{active \? 'page' : undefined\}/);
});

test('sidebar nav has stable id for aria-controls reference', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /id="sidebar-nav"/);
});

test('sidebar close button has aria-label', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /Close navigation/);
});

test('sidebar icons have aria-hidden to prevent duplicate announcements', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /aria-hidden="true"/);
});

// ─── SSR safety ───────────────────────────────────────────────────────────────

test('sidebar does not access browser-only APIs at module level', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.doesNotMatch(sidebar, /localStorage/);
  assert.doesNotMatch(sidebar, /sessionStorage/);
  assert.doesNotMatch(sidebar, /window\./);
  assert.doesNotMatch(sidebar, /document\./);
});

test('layout does not access browser-only APIs at module level', () => {
  const layout = read('app/dashboard/layout.tsx');
  assert.doesNotMatch(layout, /localStorage/);
  assert.doesNotMatch(layout, /sessionStorage/);
  assert.doesNotMatch(layout, /window\./);
  assert.doesNotMatch(layout, /document\./);
});

// ─── Secret safety ────────────────────────────────────────────────────────────

test('shell components do not expose NEXT_PUBLIC API key or core URL secrets', () => {
  const shellFiles = [
    'app/dashboard/layout.tsx',
    'components/layout/Sidebar.tsx',
    'components/layout/TopBar.tsx',
  ];
  for (const file of shellFiles) {
    const content = read(file);
    assert.doesNotMatch(content, /NEXT_PUBLIC_CORE_API_KEY/, `${file} leaks API key`);
    assert.doesNotMatch(content, /NEXT_PUBLIC_CORE_API_URL/, `${file} leaks core URL`);
  }
});

// ─── Placeholder routes ───────────────────────────────────────────────────────

test('all required placeholder route files exist', () => {
  const routes = [
    'app/dashboard/corpus/page.tsx',
    'app/dashboard/retrieval/page.tsx',
    'app/dashboard/provenance/page.tsx',
    'app/dashboard/policies/page.tsx',
    'app/dashboard/providers/page.tsx',
    'app/dashboard/readiness/page.tsx',
    'app/dashboard/settings/page.tsx',
  ];
  for (const route of routes) {
    assert.ok(exists(route), `Missing placeholder route: ${route}`);
  }
});

test('placeholder pages display not-configured state', () => {
  const placeholders = [
    // corpus graduated to full implementation in PR 50 — no longer a placeholder
    // readiness graduated to full implementation in PR 91 — no longer a placeholder
    // provenance graduated to full implementation in PR 92 — no longer a placeholder
    'app/dashboard/retrieval/page.tsx',
    'app/dashboard/policies/page.tsx',
    'app/dashboard/providers/page.tsx',
    'app/dashboard/settings/page.tsx',
  ];
  for (const file of placeholders) {
    const content = read(file);
    assert.match(content, /not yet configured/, `${file}: missing not-configured state`);
    assert.match(content, /module-not-configured/, `${file}: missing aria-label`);
  }
});

test('placeholder pages do not fetch live data or use client-side effects', () => {
  const placeholders = [
    // corpus graduated to full implementation in PR 50 — no longer a placeholder
    // readiness graduated to full implementation in PR 91 — no longer a placeholder
    // provenance graduated to full implementation in PR 92 — no longer a placeholder
    'app/dashboard/retrieval/page.tsx',
    'app/dashboard/policies/page.tsx',
    'app/dashboard/providers/page.tsx',
    'app/dashboard/settings/page.tsx',
  ];
  for (const file of placeholders) {
    const content = read(file);
    assert.doesNotMatch(content, /useEffect/, `${file}: should not have live data fetch`);
    assert.doesNotMatch(content, /fetch\(/, `${file}: should not fetch real data`);
    assert.doesNotMatch(content, /'use client'/, `${file}: should be server component`);
  }
});

test('evaluation page is implemented and no longer a placeholder', () => {
  const content = read('app/dashboard/evaluation/page.tsx');
  assert.match(content, /EvaluationLabConsole/);
  assert.match(content, /Operator-grade retrieval and grounding evaluation workspace/);
  assert.doesNotMatch(content, /not yet configured/);
  assert.doesNotMatch(content, /module-not-configured/);
});

test('readiness page is implemented and no longer a placeholder', () => {
  const content = read('app/dashboard/readiness/page.tsx');
  assert.match(content, /ReadinessOverview/);
  assert.match(content, /FrameworkSelector/);
  assert.match(content, /getScore/);
  assert.doesNotMatch(content, /not yet configured/);
  assert.doesNotMatch(content, /module-not-configured/);
});

test('provenance page is implemented and no longer a placeholder', () => {
  const content = read('app/dashboard/provenance/page.tsx');
  assert.match(content, /EvidenceTimeline/);
  assert.match(content, /AuditChainPanel/);
  assert.match(content, /listEvidence/);
  assert.doesNotMatch(content, /not yet configured/);
  assert.doesNotMatch(content, /module-not-configured/);
});

test('placeholder pages do not render fake operational data', () => {
  const placeholders = [
    // corpus graduated to full implementation in PR 50 — no longer a placeholder
    // readiness graduated to full implementation in PR 91 — no longer a placeholder
    // provenance graduated to full implementation in PR 92 — no longer a placeholder
    'app/dashboard/retrieval/page.tsx',
    'app/dashboard/policies/page.tsx',
    'app/dashboard/providers/page.tsx',
    'app/dashboard/settings/page.tsx',
  ];
  for (const file of placeholders) {
    const content = read(file);
    assert.doesNotMatch(content, /\d+%/, `${file}: should not render fake percentages`);
    assert.doesNotMatch(content, /score|Score/, `${file}: should not render fake scores`);
    assert.doesNotMatch(content, /chart|Chart/, `${file}: should not render fake charts`);
  }
});

// ─── Existing routes preserved ────────────────────────────────────────────────

test('all existing dashboard route pages are still present', () => {
  const existing = [
    'app/dashboard/page.tsx',
    'app/dashboard/assistant/page.tsx',
    'app/dashboard/control-tower/page.tsx',
    'app/dashboard/forensics/page.tsx',
    'app/dashboard/decisions/page.tsx',
    'app/dashboard/alignment/page.tsx',
  ];
  for (const route of existing) {
    assert.ok(exists(route), `Existing route removed: ${route}`);
  }
});

test('existing forensics page retains chain verify and proof copy fields', () => {
  const page = read('app/dashboard/forensics/page.tsx');
  assert.match(page, /Chain Verify Status/);
  assert.match(page, /Copy proof/);
  assert.match(page, /responseHash/);
});

test('existing dashboard page retains billing and feed states', () => {
  const page = read('app/dashboard/page.tsx');
  assert.match(page, /billing-ready/);
  assert.match(page, /billing-error/);
  assert.match(page, /events-loading/);
  assert.match(page, /Core unreachable/);
});
