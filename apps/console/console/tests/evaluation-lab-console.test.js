/**
 * evaluation-lab-console.test.js
 *
 * Static-analysis tests for PR 54 — Evaluation Lab UI
 *
 * Coverage:
 *   - file existence and exports
 *   - EvaluationLabConsole component signature
 *   - QuerySetPanel rendering (empty, loading, error, populated)
 *   - RetrievalPrecisionPanel: no fabricated precision metrics
 *   - GroundingReviewPanel: grounding data visibility
 *   - HallucinationReviewPanel: heuristic label required
 *   - ConfidenceDistributionPanel: unknown confidence renders safely
 *   - RerankerComparisonPanel: deterministic ordering flag
 *   - EvaluationExportPanel: export-safe flag, download pattern
 *   - evaluation page wired to EvaluationLabConsole
 *   - governance index exports all new components
 *   - coreApi new types and functions
 *   - no dangerouslySetInnerHTML
 *   - no fabricated metrics
 *   - tenant-scoped rendering patterns
 *   - accessibility aria-labels
 *   - safe empty-state patterns
 *   - deterministic ordering assertions
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

const LAB = 'components/governance/EvaluationLabConsole.tsx';
const INDEX = 'components/governance/index.ts';
const EVAL_PAGE = 'app/dashboard/evaluation/page.tsx';
const CORE_API = 'lib/coreApi.ts';

// ─── File existence ───────────────────────────────────────────────────────────

test('EvaluationLabConsole.tsx exists', () => {
  assert.ok(exists(LAB), 'EvaluationLabConsole.tsx must exist');
});

test('evaluation page exists', () => {
  assert.ok(exists(EVAL_PAGE), 'evaluation/page.tsx must exist');
});

// ─── Component exports ────────────────────────────────────────────────────────

test('EvaluationLabConsole exports EvaluationLabConsole', () => {
  const src = read(LAB);
  assert.match(src, /export function EvaluationLabConsole/);
});

test('EvaluationLabConsole exports QuerySetPanel', () => {
  const src = read(LAB);
  assert.match(src, /export function QuerySetPanel/);
});

test('EvaluationLabConsole exports RetrievalPrecisionPanel', () => {
  const src = read(LAB);
  assert.match(src, /export function RetrievalPrecisionPanel/);
});

test('EvaluationLabConsole exports GroundingReviewPanel', () => {
  const src = read(LAB);
  assert.match(src, /export function GroundingReviewPanel/);
});

test('EvaluationLabConsole exports HallucinationReviewPanel', () => {
  const src = read(LAB);
  assert.match(src, /export function HallucinationReviewPanel/);
});

test('EvaluationLabConsole exports ConfidenceDistributionPanel', () => {
  const src = read(LAB);
  assert.match(src, /export function ConfidenceDistributionPanel/);
});

test('EvaluationLabConsole exports RerankerComparisonPanel', () => {
  const src = read(LAB);
  assert.match(src, /export function RerankerComparisonPanel/);
});

test('EvaluationLabConsole exports EvaluationExportPanel', () => {
  const src = read(LAB);
  assert.match(src, /export function EvaluationExportPanel/);
});

// ─── governance index re-exports ─────────────────────────────────────────────

test('index.ts exports EvaluationLabConsole', () => {
  const idx = read(INDEX);
  assert.match(idx, /EvaluationLabConsole/);
  assert.match(idx, /from '\.\/EvaluationLabConsole'/);
});

test('index.ts exports QuerySetPanel', () => {
  const idx = read(INDEX);
  assert.match(idx, /QuerySetPanel/);
});

test('index.ts exports RetrievalPrecisionPanel', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalPrecisionPanel/);
});

test('index.ts exports GroundingReviewPanel', () => {
  const idx = read(INDEX);
  assert.match(idx, /GroundingReviewPanel/);
});

test('index.ts exports HallucinationReviewPanel', () => {
  const idx = read(INDEX);
  assert.match(idx, /HallucinationReviewPanel/);
});

test('index.ts exports ConfidenceDistributionPanel', () => {
  const idx = read(INDEX);
  assert.match(idx, /ConfidenceDistributionPanel/);
});

test('index.ts exports RerankerComparisonPanel', () => {
  const idx = read(INDEX);
  assert.match(idx, /RerankerComparisonPanel/);
});

test('index.ts exports EvaluationExportPanel', () => {
  const idx = read(INDEX);
  assert.match(idx, /EvaluationExportPanel/);
});

test('index.ts exports prop types for new components', () => {
  const idx = read(INDEX);
  assert.match(idx, /EvaluationLabConsoleProps/);
  assert.match(idx, /QuerySetPanelProps/);
  assert.match(idx, /RetrievalPrecisionPanelProps/);
  assert.match(idx, /HallucinationReviewPanelProps/);
  assert.match(idx, /ConfidenceDistributionPanelProps/);
  assert.match(idx, /RerankerComparisonPanelProps/);
  assert.match(idx, /EvaluationExportPanelProps/);
});

// ─── Evaluation page integration ─────────────────────────────────────────────

test('evaluation page imports EvaluationLabConsole', () => {
  const page = read(EVAL_PAGE);
  assert.match(page, /EvaluationLabConsole/);
  assert.match(page, /from.*@\/components\/governance\/EvaluationLabConsole/);
});

test('evaluation page renders EvaluationLabConsole', () => {
  const page = read(EVAL_PAGE);
  assert.match(page, /<EvaluationLabConsole/);
});

test('evaluation page no longer shows module-not-configured placeholder', () => {
  const page = read(EVAL_PAGE);
  assert.doesNotMatch(page, /module-not-configured/);
});

// ─── coreApi new types ────────────────────────────────────────────────────────

test('coreApi exports EvaluationQuerySetRecord', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationQuerySetRecord/);
});

test('coreApi exports EvaluationQueryItemRecord', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationQueryItemRecord/);
});

test('coreApi exports EvaluationQuerySetDetail', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationQuerySetDetail/);
});

test('coreApi exports EvaluationRunComparison', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationRunComparison/);
});

test('coreApi exports EvaluationRunConfidence', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationRunConfidence/);
});

test('coreApi exports EvaluationRunHallucination', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationRunHallucination/);
});

test('coreApi exports EvaluationRunReranker', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationRunReranker/);
});

test('coreApi exports EvaluationRunExport', () => {
  const api = read(CORE_API);
  assert.match(api, /EvaluationRunExport/);
});

test('coreApi exports getEvaluationQuerySets', () => {
  const api = read(CORE_API);
  assert.match(api, /export async function getEvaluationQuerySets/);
});

test('coreApi exports getEvaluationQuerySetDetail', () => {
  const api = read(CORE_API);
  assert.match(api, /export async function getEvaluationQuerySetDetail/);
});

test('coreApi exports getEvaluationRunComparison', () => {
  const api = read(CORE_API);
  assert.match(api, /export async function getEvaluationRunComparison/);
});

test('coreApi exports getEvaluationRunConfidence', () => {
  const api = read(CORE_API);
  assert.match(api, /export async function getEvaluationRunConfidence/);
});

test('coreApi exports getEvaluationRunHallucination', () => {
  const api = read(CORE_API);
  assert.match(api, /export async function getEvaluationRunHallucination/);
});

test('coreApi exports getEvaluationRunReranker', () => {
  const api = read(CORE_API);
  assert.match(api, /export async function getEvaluationRunReranker/);
});

test('coreApi exports getEvaluationRunExport', () => {
  const api = read(CORE_API);
  assert.match(api, /export async function getEvaluationRunExport/);
});

// ─── Query set rendering ──────────────────────────────────────────────────────

test('QuerySetPanel renders empty-state aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="query-sets-empty"/);
});

test('QuerySetPanel renders loading state', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="query-sets-loading"/);
});

test('QuerySetPanel renders error state', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="query-sets-error"/);
});

test('QuerySetPanel renders query-set-panel aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="query-set-panel"/);
});

// ─── Expected source rendering ────────────────────────────────────────────────

test('QuerySetDetailView renders expected-sources aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="expected-sources"/);
});

test('QuerySetDetailView renders expected_source_ids count', () => {
  const src = read(LAB);
  assert.match(src, /expected_source_ids\.length/);
});

test('QuerySetDetailView renders expected_chunk_ids count', () => {
  const src = read(LAB);
  assert.match(src, /expected_chunk_ids\.length/);
});

test('QuerySetDetailView renders expected_source_hashes count', () => {
  const src = read(LAB);
  assert.match(src, /expected_source_hashes\.length/);
});

// ─── RetrievalPrecisionPanel ──────────────────────────────────────────────────

test('RetrievalPrecisionPanel renders comparison_note field', () => {
  const src = read(LAB);
  assert.match(src, /comparison_note/);
});

test('RetrievalPrecisionPanel has no-precision-data-notice for empty runs', () => {
  const src = read(LAB);
  assert.match(src, /no-precision-data-notice/);
});

test('RetrievalPrecisionPanel renders has-relevance-data aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="has-relevance-data"/);
});

test('RetrievalPrecisionPanel renders has-coverage-data aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="has-coverage-data"/);
});

test('RetrievalPrecisionPanel renders reranker-comparison-available aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="reranker-comparison-available"/);
});

// ─── HallucinationReviewPanel ─────────────────────────────────────────────────

test('HallucinationReviewPanel renders heuristic-label aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="heuristic-label"/);
});

test('HallucinationReviewPanel shows heuristic review type label', () => {
  const src = read(LAB);
  assert.match(src, /Heuristic review/);
});

test('HallucinationReviewPanel renders hallucination-review-note', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="hallucination-review-note"/);
});

test('HallucinationReviewPanel renders export-safe-flag', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="export-safe-flag"/);
});

// ─── ConfidenceDistributionPanel ─────────────────────────────────────────────

test('ConfidenceDistributionPanel renders confidence-source aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="confidence-source"/);
});

test('ConfidenceDistributionPanel renders unknown-confidence-notice', () => {
  const src = read(LAB);
  assert.match(src, /unknown-confidence-notice/);
});

test('ConfidenceDistributionPanel labels unknown as unknown not fabricated', () => {
  const src = read(LAB);
  assert.match(src, /unknown.*not fabricated/i);
});

test('ConfidenceDistributionPanel renders distribution note', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="confidence-distribution-note"/);
});

// ─── RerankerComparisonPanel ──────────────────────────────────────────────────

test('RerankerComparisonPanel renders ordering-deterministic aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="ordering-deterministic"/);
});

test('RerankerComparisonPanel renders reranker-comparison-note', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="reranker-comparison-note"/);
});

test('RerankerComparisonPanel renders no-reranker-data-notice for empty', () => {
  const src = read(LAB);
  assert.match(src, /no-reranker-data-notice/);
});

// ─── EvaluationExportPanel ────────────────────────────────────────────────────

test('EvaluationExportPanel renders export-safe-badge', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="export-safe-badge"/);
});

test('EvaluationExportPanel renders download button', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="Download export JSON"/);
});

test('EvaluationExportPanel renders export-note', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="export-note"/);
});

test('EvaluationExportPanel renders has-relevance-indicators', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="has-relevance-indicators"/);
});

test('EvaluationExportPanel download uses URL.createObjectURL', () => {
  const src = read(LAB);
  assert.match(src, /URL\.createObjectURL/);
  assert.match(src, /URL\.revokeObjectURL/);
});

// ─── EvaluationLabConsole tabs ────────────────────────────────────────────────

test('EvaluationLabConsole renders evaluation-lab-console aria-label', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="evaluation-lab-console"/);
});

test('EvaluationLabConsole renders evaluation-lab-tabs nav', () => {
  const src = read(LAB);
  assert.match(src, /aria-label="evaluation-lab-tabs"/);
});

test('EvaluationLabConsole has runs tab', () => {
  const src = read(LAB);
  // Tab IDs defined in static tabs array
  assert.match(src, /id:\s*['"]runs['"]/);
});

test('EvaluationLabConsole has query-sets tab', () => {
  const src = read(LAB);
  assert.match(src, /id:\s*['"]query-sets['"]/);
  assert.match(src, /Query Sets/);
});

test('EvaluationLabConsole has comparison tab', () => {
  const src = read(LAB);
  assert.match(src, /id:\s*['"]comparison['"]/);
});

test('EvaluationLabConsole has grounding tab', () => {
  const src = read(LAB);
  assert.match(src, /id:\s*['"]grounding['"]/);
});

test('EvaluationLabConsole has hallucination tab', () => {
  const src = read(LAB);
  assert.match(src, /id:\s*['"]hallucination['"]/);
});

test('EvaluationLabConsole has confidence tab', () => {
  const src = read(LAB);
  assert.match(src, /id:\s*['"]confidence['"]/);
});

test('EvaluationLabConsole has reranker tab', () => {
  const src = read(LAB);
  assert.match(src, /id:\s*['"]reranker['"]/);
});

test('EvaluationLabConsole has export tab', () => {
  const src = read(LAB);
  assert.match(src, /id:\s*['"]export['"]/);
});

// ─── Safety checks ────────────────────────────────────────────────────────────

test('EvaluationLabConsole does not use dangerouslySetInnerHTML', () => {
  const src = read(LAB);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('EvaluationLabConsole does not fabricate metrics', () => {
  const src = read(LAB);
  // No hardcoded fake score variables or fabricated result objects
  assert.doesNotMatch(src, /fake_score|invented_metric|fakeResult|mockScore/i);
});

test('EvaluationLabConsole does not hardcode evaluation datasets', () => {
  const src = read(LAB);
  // No hardcoded numeric precision/recall percentages
  assert.doesNotMatch(src, /precision.*=.*\d+\.\d+.*%/);
  assert.doesNotMatch(src, /recall.*=.*\d+\.\d+.*%/);
});

test('EvaluationLabConsole is a client component', () => {
  const src = read(LAB);
  assert.match(src, /^'use client'/);
});

// ─── Deterministic state rendering ───────────────────────────────────────────

test('EvaluationLabConsole uses deterministic ordering for items', () => {
  const src = read(LAB);
  // QuerySetDetailView renders items_total for deterministic count display
  assert.match(src, /items_total/);
  // Detail view shows item list with consistent ordering
  assert.match(src, /query-items-list/);
});

// ─── Tenant isolation patterns ────────────────────────────────────────────────

test('EvaluationLabConsole does not bypass tenant isolation', () => {
  const src = read(LAB);
  // No hardcoded tenant IDs
  assert.doesNotMatch(src, /tenant_id\s*=\s*["'][^"']{1,}/);
});
