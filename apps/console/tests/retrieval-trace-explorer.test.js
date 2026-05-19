/**
 * retrieval-trace-explorer.test.js
 *
 * Static-analysis tests for the PR 47 RetrievalTraceExplorer component.
 * Covers: structure, accessibility, safe rendering, sort/filter controls,
 * score cells, confidence derivation, fallback states, future placeholders,
 * and integration with the AI workspace page.
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

const EXPLORER = 'components/governance/RetrievalTraceExplorer.tsx';
const PAGE = 'app/dashboard/assistant/page.tsx';
const INDEX = 'components/governance/index.ts';

// ─── File existence ───────────────────────────────────────────────────────────

test('RetrievalTraceExplorer.tsx exists', () => {
  assert.ok(exists(EXPLORER), 'Missing RetrievalTraceExplorer.tsx');
});

// ─── Exports ──────────────────────────────────────────────────────────────────

test('index.ts exports RetrievalTraceExplorer', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalTraceExplorer/);
  assert.match(idx, /from '\.\/RetrievalTraceExplorer'/);
});

test('index.ts exports RetrievalTraceExplorerProps type', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalTraceExplorerProps/);
});

// ─── Component signature ──────────────────────────────────────────────────────

test('component exports RetrievalTraceExplorer as named export', () => {
  const src = read(EXPLORER);
  assert.match(src, /export function RetrievalTraceExplorer/);
});

test('component accepts provenance, retrievalSteps, and apiFailure props', () => {
  const src = read(EXPLORER);
  assert.match(src, /provenance/);
  assert.match(src, /retrievalSteps/);
  assert.match(src, /apiFailure/);
});

test('component is a client component', () => {
  const src = read(EXPLORER);
  assert.match(src, /'use client'/);
});

// ─── Fallback states ──────────────────────────────────────────────────────────

test('renders trace-api-failure-state when apiFailure is true', () => {
  const src = read(EXPLORER);
  assert.match(src, /trace-api-failure-state/);
  assert.match(src, /Retrieval trace unavailable/);
});

test('renders no-trace-state when no data is provided', () => {
  const src = read(EXPLORER);
  assert.match(src, /no-trace-state/);
  assert.match(src, /No retrieval trace available/);
});

test('renders no-context-trace-state when RAG was not used', () => {
  const src = read(EXPLORER);
  assert.match(src, /no-context-trace-state/);
  assert.match(src, /No retrieval context/);
});

// ─── Retrieval Path section ───────────────────────────────────────────────────

test('renders retrieval-path-section collapsible', () => {
  const src = read(EXPLORER);
  assert.match(src, /retrieval-path-section/);
  assert.match(src, /Retrieval Path/);
});

test('renders retrieval-path-visualization with stage pills', () => {
  const src = read(EXPLORER);
  assert.match(src, /retrieval-path-visualization/);
  assert.match(src, /retrieval-path-stage/);
});

test('strategy path maps all known strategies', () => {
  const src = read(EXPLORER);
  assert.match(src, /hybrid_rrf/);
  assert.match(src, /RRF Fusion/);
  assert.match(src, /Combined Rank/);
  assert.match(src, /legacy_in_memory/);
  assert.match(src, /In-Memory Lexical/);
});

test('renders lexical-fallback-indicator when fallback is detected', () => {
  const src = read(EXPLORER);
  assert.match(src, /lexical-fallback-indicator/);
  assert.match(src, /Lexical fallback/);
});

test('renders retrieval-path-unavailable when strategy is null', () => {
  const src = read(EXPLORER);
  assert.match(src, /retrieval-path-unavailable/);
  assert.match(src, /Retrieval path not reported/);
});

// ─── Execution Timeline section ───────────────────────────────────────────────

test('renders execution-timeline-section when steps are present', () => {
  const src = read(EXPLORER);
  assert.match(src, /execution-timeline-section/);
  assert.match(src, /Execution Timeline/);
});

test('renders timeline-stages ordered list', () => {
  const src = read(EXPLORER);
  assert.match(src, /timeline-stages/);
  assert.match(src, /<ol/);
});

test('renders stage-timing labels for each step', () => {
  const src = read(EXPLORER);
  assert.match(src, /stage-timing/);
});

test('renders total-timing when steps are present', () => {
  const src = read(EXPLORER);
  assert.match(src, /total-timing/);
  assert.match(src, /Total:/);
});

test('renders timing-unavailable-state when no steps', () => {
  const src = read(EXPLORER);
  assert.match(src, /timing-unavailable-state/);
  assert.match(src, /Timing data not reported/);
});

// ─── Candidate Flow section ───────────────────────────────────────────────────

test('renders candidate-flow section with returned/accepted/rejected counts', () => {
  const src = read(EXPLORER);
  assert.match(src, /candidate-flow/);
  assert.match(src, /returned-count/);
  assert.match(src, /accepted-count/);
  assert.match(src, /rejected-count/);
});

// ─── Chunk Rankings section ───────────────────────────────────────────────────

test('renders chunk-rankings-section collapsible', () => {
  const src = read(EXPLORER);
  assert.match(src, /chunk-rankings-section/);
  assert.match(src, /Chunk Rankings/);
});

test('renders filter-controls fieldset with aria-pressed buttons', () => {
  const src = read(EXPLORER);
  assert.match(src, /filter-controls/);
  assert.match(src, /aria-pressed/);
  assert.match(src, /accepted/);
  assert.match(src, /rejected/);
});

test('renders chunk-rankings-table with chunk-ranking-row entries', () => {
  const src = read(EXPLORER);
  assert.match(src, /chunk-rankings-table/);
  assert.match(src, /chunk-ranking-row/);
});

test('sort header buttons use aria-sort attribute', () => {
  const src = read(EXPLORER);
  assert.match(src, /aria-sort/);
  assert.match(src, /ascending/);
  assert.match(src, /descending/);
});

test('renders chunk-accepted and chunk-filtered status labels', () => {
  const src = read(EXPLORER);
  assert.match(src, /chunk-accepted/);
  assert.match(src, /chunk-filtered/);
  assert.match(src, /chunk-status-unknown/);
});

test('score-unavailable renders dash for null score values', () => {
  const src = read(EXPLORER);
  assert.match(src, /score-unavailable/);
});

test('renders large-result-truncation notice when rows exceed MAX_VISIBLE_CHUNKS', () => {
  const src = read(EXPLORER);
  assert.match(src, /large-result-truncation/);
  assert.match(src, /MAX_VISIBLE_CHUNKS/);
});

test('MAX_VISIBLE_CHUNKS is set to 20', () => {
  const src = read(EXPLORER);
  assert.match(src, /MAX_VISIBLE_CHUNKS\s*=\s*20/);
});

test('sortRows uses stable localeCompare tie-break on chunkId', () => {
  const src = read(EXPLORER);
  assert.match(src, /localeCompare/);
  assert.match(src, /chunkId/);
});

// ─── Confidence Derivation section ───────────────────────────────────────────

test('renders confidence-derivation-section', () => {
  const src = read(EXPLORER);
  assert.match(src, /confidence-derivation-section/);
  assert.match(src, /Confidence Derivation/);
});

test('renders confidence-grounding-label with grounding level text', () => {
  const src = read(EXPLORER);
  assert.match(src, /confidence-grounding-label/);
  assert.match(src, /Grounded/);
  assert.match(src, /Weakly Grounded/);
  assert.match(src, /Ungrounded/);
});

test('renders confidence-value in parentheses when available', () => {
  const src = read(EXPLORER);
  assert.match(src, /confidence-value/);
});

test('renders confidence-reason when present', () => {
  const src = read(EXPLORER);
  assert.match(src, /confidence-reason/);
});

test('renders confidence-unavailable when confidence is null', () => {
  const src = read(EXPLORER);
  assert.match(src, /confidence-unavailable/);
  assert.match(src, /Confidence not reported/);
});

test('grounding thresholds are >= 0.7 for grounded and >= 0.4 for weakly-grounded', () => {
  const src = read(EXPLORER);
  assert.match(src, /0\.7/);
  assert.match(src, /0\.4/);
});

// ─── Future Capabilities section ──────────────────────────────────────────────

test('renders future-trace-capabilities-section collapsed by default', () => {
  const src = read(EXPLORER);
  assert.match(src, /future-trace-capabilities-section/);
  assert.match(src, /Future Capabilities/);
  assert.match(src, /defaultOpen={false}/);
});

test('renders future-trace-placeholder items labeled not yet available', () => {
  const src = read(EXPLORER);
  assert.match(src, /future-trace-placeholder/);
  assert.match(src, /not yet available/);
});

test('future placeholder includes Rerank visualization item', () => {
  const src = read(EXPLORER);
  assert.match(src, /Rerank visualization/);
});

test('future placeholder includes Retrieval replay item', () => {
  const src = read(EXPLORER);
  assert.match(src, /Retrieval replay/);
});

// ─── Accessibility ────────────────────────────────────────────────────────────

test('CollapsibleSection uses aria-expanded and aria-controls', () => {
  const src = read(EXPLORER);
  assert.match(src, /aria-expanded/);
  assert.match(src, /aria-controls/);
});

test('CollapsibleSection uses hidden prop to hide content', () => {
  const src = read(EXPLORER);
  assert.match(src, /hidden=\{!open\}/);
});

test('icons use aria-hidden to prevent duplicate announcements', () => {
  const src = read(EXPLORER);
  assert.match(src, /aria-hidden="true"/);
});

test('sort header buttons have focus-visible ring for keyboard users', () => {
  const src = read(EXPLORER);
  assert.match(src, /focus-visible:ring/);
});

test('filter fieldset has sr-only legend', () => {
  const src = read(EXPLORER);
  assert.match(src, /sr-only/);
  assert.match(src, /Filter by inclusion status/);
});

// ─── Safe rendering ───────────────────────────────────────────────────────────

test('does not use dangerouslySetInnerHTML', () => {
  const src = read(EXPLORER);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('does not expose raw_vector or raw_prompt fields', () => {
  const src = read(EXPLORER);
  assert.doesNotMatch(src, /raw_vector/);
  assert.doesNotMatch(src, /raw_prompt/);
});

test('safeNum guards against non-numeric or non-finite values', () => {
  const src = read(EXPLORER);
  assert.match(src, /safeNum/);
  assert.match(src, /isFinite/);
});

test('fmt uses toFixed(3) for score display', () => {
  const src = read(EXPLORER);
  assert.match(src, /toFixed\(3\)/);
});

test('does not render fake operational data', () => {
  const src = read(EXPLORER);
  // No hard-coded percentages or fabricated values
  assert.doesNotMatch(src, /98%|99%|100%/);
  assert.doesNotMatch(src, /0\.987|0\.999/);
});

// ─── Integration with AI Workspace page ──────────────────────────────────────

test('AI workspace page imports RetrievalTraceExplorer', () => {
  const page = read(PAGE);
  assert.match(page, /RetrievalTraceExplorer/);
});

test('AI workspace page renders RetrievalTraceExplorer with provenance and retrievalSteps', () => {
  const page = read(PAGE);
  assert.match(page, /<RetrievalTraceExplorer/);
  assert.match(page, /provenance=\{prov\}/);
  assert.match(page, /retrievalSteps=\{meta\.retrievalSteps\}/);
});

test('AI workspace page does not use RetrievalTrace directly in MetadataPanel', () => {
  const page = read(PAGE);
  // RetrievalTrace is still imported from governance but should not render inline
  assert.doesNotMatch(page, /<RetrievalTrace /);
});

test('retrieval/page.tsx placeholder is still untouched', () => {
  const placeholder = read('app/dashboard/retrieval/page.tsx');
  assert.match(placeholder, /module-not-configured/);
  assert.match(placeholder, /not yet configured/);
  assert.doesNotMatch(placeholder, /'use client'/);
  assert.doesNotMatch(placeholder, /useEffect/);
  assert.doesNotMatch(placeholder, /fetch\(/);
});
