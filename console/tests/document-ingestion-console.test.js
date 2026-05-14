/**
 * document-ingestion-console.test.js
 *
 * Static-analysis tests for PR 51 — Document Ingestion UX
 *
 * Coverage:
 *   - File existence: component, API client, page, test
 *   - Component exports from governance index
 *   - DocumentIngestionConsole props
 *   - UploadDropzone: corpus selector, file input, drop zone
 *   - IngestionUXStatusBadge: all known statuses present
 *   - ChunkingProgressPanel: chunk counts, no raw vectors
 *   - EmbeddingProgressPanel: embedding states, no raw vectors
 *   - IngestionFailurePanel: failure, quarantine, duplicate states
 *   - IngestionLifecycleTimeline: lifecycle steps present
 *   - ConnectorIngestionPlaceholder: clearly marked unavailable
 *   - UploadAuditSummary: export-safe fields
 *   - API client: uploadDocument, listUploads, getDocumentIngestion
 *   - API client types: UploadResult, UploadListPage, DocumentIngestionDetail
 *   - BFF proxy rules: rag/upload POST, rag/uploads GET, rag/documents POST+GET
 *   - Governance safety: no dangerouslySetInnerHTML
 *   - Governance safety: no raw vectors/prompts/provider payloads
 *   - Governance safety: future hooks clearly marked unavailable
 *   - Ingestion status coverage: all lifecycle states handled
 *   - Tenant isolation: tenant_id not accepted in API client
 *   - Dashboard page wires up DocumentIngestionConsole
 *   - Index exports all required components and types
 *   - Regression: CorpusManagementConsole still present and exported
 *   - Regression: provenance, retrieval policy, trace explorer still present
 *   - Route inventory: new routes included
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

const COMPONENT = 'components/governance/DocumentIngestionConsole.tsx';
const INGESTION_API = 'lib/ingestionApi.ts';
const INDEX = 'components/governance/index.ts';
const INGESTION_PAGE = 'app/dashboard/ingestion/page.tsx';
const BFF_ROUTE = 'app/api/core/[...path]/route.ts';
const ROUTE_INVENTORY = '../../tools/ci/route_inventory.json';

// ─── File existence ───────────────────────────────────────────────────────────

test('DocumentIngestionConsole.tsx exists', () => {
  assert.ok(exists(COMPONENT), 'Missing DocumentIngestionConsole.tsx');
});

test('ingestionApi.ts exists', () => {
  assert.ok(exists(INGESTION_API), 'Missing ingestionApi.ts');
});

test('ingestion/page.tsx exists', () => {
  assert.ok(exists(INGESTION_PAGE), 'Missing app/dashboard/ingestion/page.tsx');
});

// ─── Governance index exports ─────────────────────────────────────────────────

test('Index exports DocumentIngestionConsole', () => {
  const src = read(INDEX);
  assert.ok(src.includes('DocumentIngestionConsole'), 'Index must export DocumentIngestionConsole');
});

test('Index exports ChunkingProgressPanel', () => {
  const src = read(INDEX);
  assert.ok(src.includes('ChunkingProgressPanel'));
});

test('Index exports EmbeddingProgressPanel', () => {
  const src = read(INDEX);
  assert.ok(src.includes('EmbeddingProgressPanel'));
});

test('Index exports IngestionFailurePanel', () => {
  const src = read(INDEX);
  assert.ok(src.includes('IngestionFailurePanel'));
});

test('Index exports IngestionLifecycleTimeline', () => {
  const src = read(INDEX);
  assert.ok(src.includes('IngestionLifecycleTimeline'));
});

test('Index exports ConnectorIngestionPlaceholder', () => {
  const src = read(INDEX);
  assert.ok(src.includes('ConnectorIngestionPlaceholder'));
});

test('Index exports UploadAuditSummary', () => {
  const src = read(INDEX);
  assert.ok(src.includes('UploadAuditSummary'));
});

test('Index exports UploadDropzone', () => {
  const src = read(INDEX);
  assert.ok(src.includes('UploadDropzone'));
});

test('Index exports DocumentIngestionConsoleProps type', () => {
  const src = read(INDEX);
  assert.ok(src.includes('DocumentIngestionConsoleProps'));
});

// ─── Ingestion status coverage ────────────────────────────────────────────────

const INGESTION_STATUSES = [
  'indexed', 'duplicate', 'quarantined', 'failed', 'superseded',
  'embedding', 'chunking', 'received', 'validating', 'reindexing',
];

for (const status of INGESTION_STATUSES) {
  test(`Component handles ingestion status: ${status}`, () => {
    const src = read(COMPONENT);
    assert.ok(src.includes(`'${status}'`), `Missing status: ${status}`);
  });
}

// ─── Lifecycle steps ──────────────────────────────────────────────────────────

const LIFECYCLE_STEPS = ['received', 'validating', 'chunking', 'embedding', 'indexed'];

test('IngestionLifecycleTimeline has all lifecycle steps', () => {
  const src = read(COMPONENT);
  for (const step of LIFECYCLE_STEPS) {
    assert.ok(src.includes(`'${step}'`), `Missing lifecycle step: ${step}`);
  }
});

// ─── Chunking panel safety ────────────────────────────────────────────────────

test('ChunkingProgressPanel renders activeChunkCount', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('active_chunk_count') || src.includes('activeChunkCount'), 'Missing activeChunkCount');
});

test('ChunkingProgressPanel renders totalChunkCount', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('total_chunk_count') || src.includes('totalChunkCount'), 'Missing totalChunkCount');
});

test('ChunkingProgressPanel does not expose raw chunk text', () => {
  const src = read(COMPONENT);
  assert.ok(!src.includes('raw_chunk_text') && !src.includes('rawChunkText'), 'Must not expose raw chunk text');
});

// ─── Embedding panel safety ───────────────────────────────────────────────────

const EMBEDDING_STATES = ['pending', 'processing', 'completed', 'failed', 'skipped'];

test('EmbeddingProgressPanel covers embedding states', () => {
  const src = read(COMPONENT);
  for (const state of EMBEDDING_STATES) {
    assert.ok(src.includes(`'${state}'`) || src.includes(`"${state}"`), `Missing embedding state: ${state}`);
  }
});

test('EmbeddingProgressPanel does not expose raw vectors', () => {
  const src = read(COMPONENT);
  assert.ok(!src.includes('rawVector') && !src.includes('raw_vector'), 'Must not expose raw vectors');
});

// ─── Failure panel states ─────────────────────────────────────────────────────

test('IngestionFailurePanel renders quarantine state', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('quarantine') || src.includes('Quarantine'), 'Missing quarantine handling');
});

test('IngestionFailurePanel renders failure state', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('failed') || src.includes('Failed'), 'Missing failure handling');
});

test('IngestionFailurePanel renders duplicate state', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('duplicate') || src.includes('Duplicate'), 'Missing duplicate handling');
});

test('IngestionFailurePanel uses role=alert for failures', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('role="alert"'), 'Must use role=alert for failures/quarantine');
});

// ─── Governance safety ────────────────────────────────────────────────────────

test('DocumentIngestionConsole has no dangerouslySetInnerHTML', () => {
  const src = read(COMPONENT);
  assert.ok(!src.includes('dangerouslySetInnerHTML'), 'Must not use dangerouslySetInnerHTML');
});

test('Ingestion page has no dangerouslySetInnerHTML', () => {
  const src = read(INGESTION_PAGE);
  assert.ok(!src.includes('dangerouslySetInnerHTML'), 'Page must not use dangerouslySetInnerHTML');
});

test('Component has no raw vector exposure', () => {
  const src = read(COMPONENT);
  assert.ok(!src.includes('rawVector') && !src.includes('raw_vector'));
});

test('Component has no raw prompt exposure', () => {
  const src = read(COMPONENT);
  assert.ok(!src.includes('rawPrompt') && !src.includes('raw_prompt'));
});

test('Component has no provider payload exposure', () => {
  const src = read(COMPONENT);
  assert.ok(!src.includes('provider_payload') && !src.includes('providerPayload'));
});

// ─── Connector placeholder ────────────────────────────────────────────────────

test('ConnectorIngestionPlaceholder marks features as not yet available', () => {
  const src = read(COMPONENT);
  assert.ok(
    src.includes('not yet available') || src.includes('Planned'),
    'Connector placeholder must mark features as unavailable'
  );
});

test('ConnectorIngestionPlaceholder does not fabricate connector data', () => {
  const src = read(COMPONENT);
  assert.ok(!src.includes('connector_data') && !src.includes('syncActive'));
});

// ─── Upload audit summary safety ──────────────────────────────────────────────

test('UploadAuditSummary exposes document_id', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('document_id') || src.includes('documentId'));
});

test('UploadAuditSummary exposes source_hash_prefix not full hash', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('source_hash_prefix') || src.includes('sourceHashPrefix'));
  assert.ok(!src.includes('source_hash_full') && !src.includes('fullHash'));
});

test('UploadAuditSummary marks export_safe', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('Export-safe') || src.includes('export_safe') || src.includes('audit_safe'));
});

// ─── API client types ─────────────────────────────────────────────────────────

test('ingestionApi has UploadResult type', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('UploadResult'));
});

test('ingestionApi has UploadListPage type', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('UploadListPage'));
});

test('ingestionApi has DocumentIngestionDetail type', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('DocumentIngestionDetail'));
});

test('ingestionApi has uploadDocument function', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('uploadDocument'));
});

test('ingestionApi has listUploads function', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('listUploads'));
});

test('ingestionApi has getDocumentIngestion function', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('getDocumentIngestion'));
});

test('ingestionApi does not accept tenant_id parameter (tenant isolation)', () => {
  const src = read(INGESTION_API);
  // Functions must not accept tenant_id — BFF injects CORE_TENANT_ID server-side
  const fnDefs = src.match(/export async function \w+\([^)]*\)/g) || [];
  for (const fn of fnDefs) {
    assert.ok(!fn.includes('tenant_id'), `Function ${fn} must not accept tenant_id`);
  }
});

test('ingestionApi uses FormData for upload (multipart)', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('FormData'), 'uploadDocument must use FormData for multipart upload');
});

test('ingestionApi audit_safe field present in UploadResult', () => {
  const src = read(INGESTION_API);
  assert.ok(src.includes('audit_safe'));
});

// ─── BFF proxy rules ──────────────────────────────────────────────────────────

test('BFF proxy allows rag/upload POST', () => {
  const src = read(BFF_ROUTE);
  assert.ok(src.includes("'rag/upload'"), 'BFF must allow rag/upload');
  assert.ok(src.includes("'POST'"), 'BFF must allow POST method for upload');
});

test('BFF proxy allows rag/uploads GET', () => {
  const src = read(BFF_ROUTE);
  assert.ok(src.includes("'rag/uploads'"), 'BFF must allow rag/uploads');
});

test('BFF proxy handles multipart body for upload', () => {
  const src = read(BFF_ROUTE);
  assert.ok(
    src.includes('multipart') || src.includes('form-data') || src.includes('isMultipart'),
    'BFF must handle multipart/form-data for upload route'
  );
});

// ─── Route inventory ──────────────────────────────────────────────────────────

test('Route inventory includes POST /rag/upload', () => {
  const inventoryPath = path.join(__dirname, ROUTE_INVENTORY);
  const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
  const routes = inventory.data || [];
  const found = routes.some(
    (r) => r.path === '/rag/upload' && r.method === 'POST'
  );
  assert.ok(found, 'Route inventory must include POST /rag/upload');
});

test('Route inventory includes GET /rag/uploads', () => {
  const inventoryPath = path.join(__dirname, ROUTE_INVENTORY);
  const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
  const routes = inventory.data || [];
  const found = routes.some(
    (r) => r.path === '/rag/uploads' && r.method === 'GET'
  );
  assert.ok(found, 'Route inventory must include GET /rag/uploads');
});

test('Route inventory includes GET /rag/documents/{document_id}/ingestion', () => {
  const inventoryPath = path.join(__dirname, ROUTE_INVENTORY);
  const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
  const routes = inventory.data || [];
  const found = routes.some(
    (r) => r.path === '/rag/documents/{document_id}/ingestion' && r.method === 'GET'
  );
  assert.ok(found, 'Route inventory must include GET /rag/documents/{document_id}/ingestion');
});

test('Route inventory new ingestion routes are tenant_bound', () => {
  const inventoryPath = path.join(__dirname, ROUTE_INVENTORY);
  const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
  const routes = inventory.data || [];
  const ingestionRoutes = routes.filter(
    (r) => r.file === 'api/rag_corpus_ingestion.py'
  );
  assert.ok(ingestionRoutes.length >= 3, 'Must have at least 3 new ingestion routes');
  for (const r of ingestionRoutes) {
    assert.ok(r.tenant_bound === true, `Route ${r.path} must be tenant_bound`);
    assert.ok(r.scoped === true, `Route ${r.path} must be scoped`);
  }
});

// ─── Ingestion page ───────────────────────────────────────────────────────────

test('Ingestion page imports DocumentIngestionConsole', () => {
  const src = read(INGESTION_PAGE);
  assert.ok(src.includes('DocumentIngestionConsole'), 'Page must render DocumentIngestionConsole');
});

test('Ingestion page has aria-label for main region', () => {
  const src = read(INGESTION_PAGE);
  assert.ok(src.includes('aria-label="ingestion-page"'));
});

test('Ingestion page marks no fabricated metrics', () => {
  const src = read(INGESTION_PAGE);
  assert.ok(
    src.includes('actual backend') || src.includes('backend truth') || src.includes('No fabricated'),
    'Page must clarify no fabricated metrics'
  );
});

// ─── Regression: existing governance components still present ─────────────────

test('Regression: CorpusManagementConsole still exported from index', () => {
  const src = read(INDEX);
  assert.ok(src.includes('CorpusManagementConsole'));
});

test('Regression: ProvenanceValidationPanel still exported from index', () => {
  const src = read(INDEX);
  assert.ok(src.includes('ProvenanceValidationPanel'));
});

test('Regression: RetrievalPolicyCenter still exported from index', () => {
  const src = read(INDEX);
  assert.ok(src.includes('RetrievalPolicyCenter'));
});

test('Regression: RetrievalTraceExplorer still exported from index', () => {
  const src = read(INDEX);
  assert.ok(src.includes('RetrievalTraceExplorer'));
});

// ─── Upload dropzone ──────────────────────────────────────────────────────────

test('UploadDropzone has corpus selector', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('corpus-selector') || src.includes('ingestion-corpus-select'));
});

test('UploadDropzone has file-drop-zone region', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('file-drop-zone'));
});

test('UploadDropzone has file-input element', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('file-input') || src.includes('type="file"'));
});

test('UploadDropzone accepts .txt and .md files', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('.txt') && src.includes('.md'));
});

test('UploadDropzone is disabled when no corpus selected', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('Select a corpus first') || src.includes('selectedCorpusId'));
});

// ─── Upload queue ─────────────────────────────────────────────────────────────

test('Component has upload-queue aria-label', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('upload-queue'));
});

test('Component has upload-queue-list', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('upload-queue-list'));
});

test('Component shows uploading state', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('Uploading') || src.includes("'uploading'"));
});

test('Component shows error state in queue', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('upload-error') || src.includes("state === 'error'"));
});

// ─── Resumable UX ────────────────────────────────────────────────────────────

test('Component has refresh button for reloading ingestion state', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('refresh-ingestion-status') || src.includes('onRefresh'));
});

test('Component uses getDocumentIngestion for refresh (backend truth)', () => {
  const src = read(COMPONENT);
  assert.ok(src.includes('getDocumentIngestion'), 'Refresh must reload from backend via getDocumentIngestion');
});

// ─── Future hooks labeled ─────────────────────────────────────────────────────

test('Component has future_hooks not yet available', () => {
  const src = read(COMPONENT);
  assert.ok(
    src.includes('not yet available') || src.includes('Planned') || src.includes('future_hooks'),
    'Future hooks must be clearly marked'
  );
});
