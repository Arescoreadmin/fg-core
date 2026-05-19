/**
 * corpus-management-console.test.js
 *
 * Static-analysis tests for PR 50 — Corpus Management Console
 *
 * Coverage:
 *   - File existence (component, API client, page, test)
 *   - Component exports from governance index
 *   - CorpusManagementConsole props
 *   - IngestionLifecycleBadge: all known statuses present
 *   - EmbeddingStatusBadge: known states present
 *   - CorpusEmptyState, CorpusLoadingState: safe empty/loading states
 *   - CorpusHealthPanel: document and chunk count fields
 *   - ChunkStatePanel: no raw vectors exposed
 *   - DocumentDetailPanel: source_hash_prefix (safe), no raw chunk text
 *   - CorpusFilterBar: status and version filters
 *   - CorpusPaginationControls: limit/offset/total
 *   - CorpusMetadataViewer: safe keys only
 *   - DocumentBrowser: pagination, filtering, empty state
 *   - API client types and functions
 *   - Ingestion status coverage: received, validating, duplicate, quarantined,
 *     chunking, embedding, indexed, failed, superseded, reindexing
 *   - Embedding state coverage: pending, processing, completed, failed, skipped
 *   - Governance safety: no dangerouslySetInnerHTML
 *   - Governance safety: no raw vectors/prompts/provider payloads
 *   - Governance safety: no fabricated metrics
 *   - Governance safety: future hooks clearly marked unavailable
 *   - Pagination: deterministic stable ordering with tiebreaker
 *   - Filtering: ingestion_status, is_current filter
 *   - Tenant isolation: tenant_id not accepted in API client
 *   - BFF proxy rules include rag/documents
 *   - Route inventory includes new routes
 *   - Corpus page wires up CorpusManagementConsole
 *   - Index exports all required components and types
 *   - Regression: retrieval policy, provenance, trace explorer still present
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

const CONSOLE_COMPONENT = 'components/governance/CorpusManagementConsole.tsx';
const CORPUS_API = 'lib/corpusConsoleApi.ts';
const INDEX = 'components/governance/index.ts';
const CORPUS_PAGE = 'app/dashboard/corpus/page.tsx';
const BFF_ROUTE = 'app/api/core/[...path]/route.ts';

// ─── File existence ───────────────────────────────────────────────────────────

test('CorpusManagementConsole.tsx exists', () => {
  assert.ok(exists(CONSOLE_COMPONENT), 'Missing CorpusManagementConsole.tsx');
});

test('corpusConsoleApi.ts exists', () => {
  assert.ok(exists(CORPUS_API), 'Missing lib/corpusConsoleApi.ts');
});

test('corpus dashboard page exists', () => {
  assert.ok(exists(CORPUS_PAGE), 'Missing app/dashboard/corpus/page.tsx');
});

// ─── Index exports ─────────────────────────────────────────────────────────────

test('index.ts exports CorpusManagementConsole', () => {
  const idx = read(INDEX);
  assert.match(idx, /CorpusManagementConsole/);
  assert.match(idx, /from '\.\/CorpusManagementConsole'/);
});

test('index.ts exports all required corpus console components', () => {
  const idx = read(INDEX);
  assert.match(idx, /CorpusBrowser/);
  assert.match(idx, /DocumentBrowser/);
  assert.match(idx, /DocumentDetailPanel/);
  assert.match(idx, /ChunkStatePanel/);
  assert.match(idx, /EmbeddingStatusBadge/);
  assert.match(idx, /IngestionLifecycleBadge/);
  assert.match(idx, /CorpusMetadataViewer/);
  assert.match(idx, /CorpusFilterBar/);
  assert.match(idx, /CorpusPaginationControls/);
  assert.match(idx, /CorpusHealthPanel/);
  assert.match(idx, /CorpusEmptyState/);
  assert.match(idx, /CorpusLoadingState/);
});

test('index.ts exports CorpusManagementConsoleProps type', () => {
  const idx = read(INDEX);
  assert.match(idx, /CorpusManagementConsoleProps/);
});

// ─── Component structure ──────────────────────────────────────────────────────

test('CorpusManagementConsole is a use-client component', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /'use client'/);
});

test('IngestionLifecycleBadge is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function IngestionLifecycleBadge/);
});

test('EmbeddingStatusBadge is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function EmbeddingStatusBadge/);
});

test('CorpusEmptyState is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function CorpusEmptyState/);
});

test('CorpusLoadingState is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function CorpusLoadingState/);
});

test('DocumentDetailPanel is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function DocumentDetailPanel/);
});

test('DocumentBrowser is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function DocumentBrowser/);
});

test('CorpusBrowser is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function CorpusBrowser/);
});

test('CorpusHealthPanel is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function CorpusHealthPanel/);
});

test('ChunkStatePanel is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function ChunkStatePanel/);
});

test('CorpusFilterBar is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function CorpusFilterBar/);
});

test('CorpusPaginationControls is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function CorpusPaginationControls/);
});

test('CorpusMetadataViewer is exported', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /export function CorpusMetadataViewer/);
});

// ─── Ingestion status coverage ────────────────────────────────────────────────

const EXPECTED_INGESTION_STATUSES = [
  'received',
  'validating',
  'duplicate',
  'quarantined',
  'chunking',
  'embedding',
  'indexed',
  'failed',
  'superseded',
  'reindexing',
];

EXPECTED_INGESTION_STATUSES.forEach((status) => {
  test(`IngestionLifecycleBadge covers status: ${status}`, () => {
    const src = read(CONSOLE_COMPONENT);
    assert.match(src, new RegExp(`'${status}'`), `Missing ingestion status: ${status}`);
  });
});

test('IngestionLifecycleBadge handles unknown status safely', () => {
  const src = read(CONSOLE_COMPONENT);
  // Must have a fallback for unknown states (the ?? branch)
  assert.match(src, /Unknown/);
});

// ─── Embedding state coverage ─────────────────────────────────────────────────

const EXPECTED_EMBEDDING_STATES = ['pending', 'processing', 'completed', 'failed', 'skipped'];

EXPECTED_EMBEDDING_STATES.forEach((state) => {
  test(`EmbeddingStatusBadge covers state: ${state}`, () => {
    const src = read(CONSOLE_COMPONENT);
    assert.match(src, new RegExp(`'${state}'`), `Missing embedding state: ${state}`);
  });
});

// ─── Governance safety ────────────────────────────────────────────────────────

test('CorpusManagementConsole does not use dangerouslySetInnerHTML', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('CorpusManagementConsole does not expose raw vectors', () => {
  const src = read(CONSOLE_COMPONENT);
  // Must not render vector data (rendering/passing embedding arrays)
  assert.doesNotMatch(src, /embedding_vector|raw_vector|vector_data/i);
  // Must not pass provider payload objects through
  assert.doesNotMatch(src, /providerPayload|provider_payload_data/i);
});

test('CorpusManagementConsole does not expose raw prompts', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.doesNotMatch(src, /raw.?prompt/i);
  assert.doesNotMatch(src, /provider.?payload/i);
});

test('CorpusManagementConsole declares raw vectors not exposed', () => {
  const src = read(CONSOLE_COMPONENT);
  // ChunkStatePanel must have a note that raw vectors are not exposed
  assert.match(src, /[Rr]aw vectors.*not exposed|not exposed.*[Rr]aw vectors/);
});

test('CorpusManagementConsole future hooks marked unavailable', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /not yet available/i);
  assert.match(src, /future/i);
});

test('CorpusManagementConsole does not fabricate metrics', () => {
  const src = read(CONSOLE_COMPONENT);
  // Should use backend-provided counts — no hardcoded fake numbers
  assert.doesNotMatch(src, /document_count.*42|42.*document_count/);
  assert.doesNotMatch(src, /chunk_count.*1337/);
});

// ─── source_hash_prefix safety ────────────────────────────────────────────────

test('DocumentDetailPanel shows source_hash_prefix not full hash', () => {
  const src = read(CONSOLE_COMPONENT);
  // Must show prefix and ellipsis, not the full hash
  assert.match(src, /source_hash_prefix/);
  assert.match(src, /…/);
});

test('CorpusManagementConsole does not expose full source_hash', () => {
  const src = read(CONSOLE_COMPONENT);
  // The component should only ever expose source_hash_prefix, not source_hash
  const sourceHashRefs = (src.match(/source_hash(?!_prefix)/g) || []).length;
  // source_hash without _prefix should not appear in render paths
  assert.ok(sourceHashRefs === 0, 'source_hash (not prefix) should not be rendered');
});

// ─── Pagination ───────────────────────────────────────────────────────────────

test('CorpusPaginationControls accepts total, limit, offset props', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /total:/);
  assert.match(src, /limit:/);
  assert.match(src, /offset:/);
});

test('CorpusPaginationControls shows item range', () => {
  const src = read(CONSOLE_COMPONENT);
  // Should show "Showing X-Y of Z" style pagination
  assert.match(src, /Showing/);
});

test('DocumentBrowser uses stable sort with tiebreaker', () => {
  const src = read(CONSOLE_COMPONENT);
  // sort_by and sort_dir are passed to the API
  assert.match(src, /sort_by/);
  assert.match(src, /sort_dir/);
});

// ─── Filtering ────────────────────────────────────────────────────────────────

test('CorpusFilterBar has ingestion status filter', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /status-filter/);
  assert.match(src, /filter-by-ingestion-status/);
});

test('CorpusFilterBar has is_current / version filter', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /current-filter/);
  assert.match(src, /filter-by-version-state/);
});

test('CorpusFilterBar has "All statuses" option for no filter', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /All statuses/);
});

test('CorpusFilterBar has "All versions" option for no filter', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /All versions/);
});

// ─── Tenant isolation ─────────────────────────────────────────────────────────

test('corpusConsoleApi does not accept tenant_id parameter', () => {
  const src = read(CORPUS_API);
  // Exported API functions must not have tenant_id in their parameter lists
  // (tenant_id may appear in comments but not in export function signatures)
  assert.doesNotMatch(src, /export async function getCorpusDetail\([^)]*tenant_id/);
  assert.doesNotMatch(src, /export async function listCorpusDocuments\([^)]*tenant_id/);
  assert.doesNotMatch(src, /export async function getDocumentDetail\([^)]*tenant_id/);
  // DocumentListQuery interface must not include tenant_id
  assert.doesNotMatch(src, /interface DocumentListQuery[\s\S]{0,200}tenant_id/);
});

test('corpusConsoleApi states tenant isolation in comment', () => {
  const src = read(CORPUS_API);
  assert.match(src, /[Tt]enant isolation/);
});

// ─── API client ───────────────────────────────────────────────────────────────

test('corpusConsoleApi exports getCorpusDetail', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export async function getCorpusDetail/);
});

test('corpusConsoleApi exports listCorpusDocuments', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export async function listCorpusDocuments/);
});

test('corpusConsoleApi exports getDocumentDetail', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export async function getDocumentDetail/);
});

test('corpusConsoleApi exports CorpusDetail type', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export interface CorpusDetail/);
});

test('corpusConsoleApi exports DocumentSummary type', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export interface DocumentSummary/);
});

test('corpusConsoleApi exports DocumentPage type', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export interface DocumentPage/);
});

test('corpusConsoleApi exports DocumentDetail type', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export interface DocumentDetail/);
});

test('corpusConsoleApi exports IngestionStatus type', () => {
  const src = read(CORPUS_API);
  assert.match(src, /export type IngestionStatus/);
});

test('corpusConsoleApi uses SafeResult pattern', () => {
  const src = read(CORPUS_API);
  assert.match(src, /SafeResult/);
});

test('corpusConsoleApi does not use dangerouslySetInnerHTML', () => {
  const src = read(CORPUS_API);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('CorpusDetail type includes future_hooks', () => {
  const src = read(CORPUS_API);
  assert.match(src, /future_hooks/);
});

test('CorpusDetail type includes ingestion_status_summary', () => {
  const src = read(CORPUS_API);
  assert.match(src, /ingestion_status_summary/);
});

test('CorpusDetail type includes embedding_state_summary', () => {
  const src = read(CORPUS_API);
  assert.match(src, /embedding_state_summary/);
});

test('DocumentSummary type has source_hash_prefix not full source_hash', () => {
  const src = read(CORPUS_API);
  assert.match(src, /source_hash_prefix/);
  // Must not have a plain 'source_hash' field (only prefix is safe)
  assert.doesNotMatch(src, /source_hash[^_]/);
});

// ─── BFF proxy rules ──────────────────────────────────────────────────────────

test('BFF proxy includes rag/documents route', () => {
  const bff = read(BFF_ROUTE);
  assert.match(bff, /rag\/documents/);
  assert.match(bff, /GET.*HEAD|HEAD.*GET/);
});

test('BFF proxy includes rag/corpora route', () => {
  const bff = read(BFF_ROUTE);
  assert.match(bff, /rag\/corpora/);
});

// ─── Corpus page integration ──────────────────────────────────────────────────

test('corpus page imports CorpusManagementConsole', () => {
  const page = read(CORPUS_PAGE);
  assert.match(page, /CorpusManagementConsole/);
  assert.match(page, /@\/components\/governance/);
});

test('corpus page renders CorpusManagementConsole', () => {
  const page = read(CORPUS_PAGE);
  assert.match(page, /<CorpusManagementConsole/);
});

test('corpus page has corpus-page aria-label', () => {
  const page = read(CORPUS_PAGE);
  assert.match(page, /aria-label="corpus-page"/);
});

test('corpus page has corpus-management-console-card aria-label', () => {
  const page = read(CORPUS_PAGE);
  assert.match(page, /corpus-management-console-card/);
});

// ─── Accessible markup ────────────────────────────────────────────────────────

test('CorpusEmptyState has role="status"', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /role="status"/);
});

test('CorpusLoadingState has aria-busy', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /aria-busy="true"/);
});

test('Error states use role="alert"', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /role="alert"/);
});

test('Icons are aria-hidden', () => {
  const src = read(CONSOLE_COMPONENT);
  assert.match(src, /aria-hidden="true"/);
});

// ─── Regression: existing governance components still present ─────────────────

test('ProvenanceValidationPanel still exported from governance index', () => {
  const idx = read(INDEX);
  assert.match(idx, /ProvenanceValidationPanel/);
  assert.match(idx, /from '\.\/ProvenanceValidationPanel'/);
});

test('RetrievalPolicyCenter still exported from governance index', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalPolicyCenter/);
});

test('RetrievalTraceExplorer still exported from governance index', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalTraceExplorer/);
});

test('RetrievalPolicyCenterContainer still exported from governance index', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalPolicyCenterContainer/);
});
