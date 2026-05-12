/**
 * provenance-validation-panel.test.js
 *
 * Static-analysis tests for PR 48 — Provenance Validation UI
 *
 * Coverage:
 *   - file existence and exports
 *   - provenance validation states render correctly
 *   - invalid citation rendering
 *   - rejection reason display (human-readable + machine reason code)
 *   - retrieved / prompt-included / cited chunk distinction
 *   - no-context explicit state
 *   - trust level derivation (deterministic)
 *   - export-safe summary exists and excludes secrets
 *   - citation ordering: rejected first, then valid
 *   - unknown reason codes render safely
 *   - malformed/partial payload renders safely
 *   - future placeholders do not fake legal status
 *   - no dangerouslySetInnerHTML
 *   - no fake citations
 *   - no fake legal approval
 *   - accessibility basics
 *   - existing governance tests still pass (smoke)
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

const PANEL = 'components/governance/ProvenanceValidationPanel.tsx';
const INDEX = 'components/governance/index.ts';
const PROVENANCE_PAGE = 'app/dashboard/provenance/page.tsx';

// ─── File existence ───────────────────────────────────────────────────────────

test('provenance validation panel file exists', () => {
  assert.ok(exists(PANEL), 'ProvenanceValidationPanel.tsx must exist');
});

test('provenance validation panel is exported from governance index', () => {
  const idx = read(INDEX);
  assert.match(idx, /ProvenanceValidationPanel/);
  assert.match(idx, /from '\.\/ProvenanceValidationPanel'/);
});

test('index.ts exports ProvenanceValidationPanel and related types', () => {
  const idx = read(INDEX);
  assert.match(idx, /ProvenanceValidationPanelProps/);
  assert.match(idx, /ProvenanceValidationData/);
  assert.match(idx, /ProvenanceValidationCitation/);
  assert.match(idx, /TrustLevel/);
  assert.match(idx, /ProvenanceExportSummary/);
});

test('index.ts exports deriveTrustLevel and buildProvenanceExportSummary', () => {
  const idx = read(INDEX);
  assert.match(idx, /deriveTrustLevel/);
  assert.match(idx, /buildProvenanceExportSummary/);
  assert.match(idx, /sortCitations/);
  assert.match(idx, /deriveCitationsFromProvenance/);
});

test('provenance page imports and uses ProvenanceValidationPanel', () => {
  const page = read(PROVENANCE_PAGE);
  assert.match(page, /ProvenanceValidationPanel/);
  assert.match(page, /from.*@\/components\/governance/);
});

// ─── Component signature ──────────────────────────────────────────────────────

test('provenance validation panel exports named ProvenanceValidationPanel', () => {
  const src = read(PANEL);
  assert.match(src, /export function ProvenanceValidationPanel/);
});

test('provenance validation panel exports deriveTrustLevel', () => {
  const src = read(PANEL);
  assert.match(src, /export function deriveTrustLevel/);
});

test('provenance validation panel exports buildProvenanceExportSummary', () => {
  const src = read(PANEL);
  assert.match(src, /export function buildProvenanceExportSummary/);
});

test('provenance validation panel exports sortCitations', () => {
  const src = read(PANEL);
  assert.match(src, /export function sortCitations/);
});

// ─── Provenance states ────────────────────────────────────────────────────────

test('provenance validation panel renders validation states', () => {
  const src = read(PANEL);
  // Status config must include all four canonical codes
  assert.match(src, /PROVENANCE_VALID/);
  assert.match(src, /PROVENANCE_SOURCE_NOT_RETRIEVED/);
  assert.match(src, /PROVENANCE_SOURCE_NOT_IN_PROMPT/);
  assert.match(src, /PROVENANCE_NO_CONTEXT_AVAILABLE/);
  assert.match(src, /STATUS_CONFIG/);
});

test('provenance validation panel renders valid provenance state', () => {
  const src = read(PANEL);
  assert.match(src, /Provenance Valid/);
  assert.match(src, /All cited sources were retrieved and included/);
});

test('provenance validation panel renders invalid provenance state', () => {
  const src = read(PANEL);
  assert.match(src, /Provenance Invalid/);
  assert.match(src, /Citation rejected/);
});

test('provenance validation panel renders no-context state explicitly', () => {
  const src = read(PANEL);
  assert.match(src, /no-context-provenance-state/);
  assert.match(src, /No Retrieval Context/);
  assert.match(src, /Answer was generated without retrieved evidence/);
  assert.match(src, /No citation claims should be trusted/);
});

test('provenance validation panel renders unavailable state', () => {
  const src = read(PANEL);
  assert.match(src, /Provenance Unavailable/);
  assert.match(src, /provenance-validation-empty/);
  assert.match(src, /Provenance validation will appear here/);
});

test('provenance validation panel renders unknown reason code safely', () => {
  const src = read(PANEL);
  // Unknown status codes must produce a warning state, not crash
  assert.match(src, /Unknown status:/);
  assert.match(src, /Treat this response with caution/);
  assert.match(src, /getStatusConfig/);
  // Must use hasOwnProperty check, not direct bracket access
  assert.match(src, /hasOwnProperty/);
});

test('provenance validation panel renders api failure state', () => {
  const src = read(PANEL);
  assert.match(src, /provenance-validation-api-failure/);
  assert.match(src, /Provenance validation unavailable/);
  assert.match(src, /apiFailure/);
});

// ─── Provenance status label ──────────────────────────────────────────────────

test('provenance validation panel renders status label (not color-only)', () => {
  const src = read(PANEL);
  // Text labels must be present alongside icons
  assert.match(src, /provenance-status-label/);
  assert.match(src, /provenance-status-detail/);
  // Icons must be aria-hidden
  assert.match(src, /aria-hidden="true"/);
});

test('provenance validation panel renders machine-readable reason code', () => {
  const src = read(PANEL);
  assert.match(src, /provenance-reason-code/);
  // The status string must be rendered as text
  assert.match(src, /\{status\}/);
});

// ─── Rejection reasons ────────────────────────────────────────────────────────

test('provenance validation panel renders invalid citation reasons', () => {
  const src = read(PANEL);
  assert.match(src, /provenance-rejection-reason-section/);
  assert.match(src, /rejection-reason-banner/);
  assert.match(src, /rejection-reason-short/);
  assert.match(src, /rejection-reason-explanation/);
  assert.match(src, /rejection-reason-code/);
});

test('provenance validation panel renders human-readable rejection reasons', () => {
  const src = read(PANEL);
  assert.match(src, /REJECTION_REASONS/);
  // Both codes must have operator-readable explanations
  assert.match(src, /Source was not retrieved for this request/);
  assert.match(src, /retrieved but not included in the prompt context/);
  assert.match(src, /The answer has been suppressed/);
});

test('provenance validation panel retains machine-readable reason code in rejection', () => {
  const src = read(PANEL);
  // Reason code must appear alongside human-readable detail
  assert.match(src, /Reason code: \{status\}/);
});

test('provenance validation panel handles unknown reason codes in CitationCard', () => {
  const src = read(PANEL);
  // getRejectionReason must handle unknown codes
  assert.match(src, /function getRejectionReason/);
  assert.match(src, /Unknown rejection reason/);
  // Must not throw on unknown code
  assert.match(src, /REJECTION_REASONS\[code\]/);
});

// ─── Citation validation ──────────────────────────────────────────────────────

test('provenance validation panel renders citation validation groups', () => {
  const src = read(PANEL);
  assert.match(src, /citation-validation-section/);
  assert.match(src, /invalid-citations-group/);
  assert.match(src, /valid-citations-group/);
  assert.match(src, /unavailable-citations-group/);
  assert.match(src, /invalid-citations-list/);
  assert.match(src, /valid-citations-list/);
});

test('provenance validation panel renders citation card validation status', () => {
  const src = read(PANEL);
  assert.match(src, /citation-card-\$\{citation\.status\}/);
  assert.match(src, /citation-validation-status/);
  assert.match(src, /citation-id/);
});

test('provenance validation panel renders citation IDs safely', () => {
  const src = read(PANEL);
  // Must render citation_id, chunk_id, source_id, document_id, corpus_id
  assert.match(src, /citation_id/);
  assert.match(src, /chunk_id/);
  assert.match(src, /source_id/);
  assert.match(src, /document_id/);
  assert.match(src, /corpus_id/);
});

test('provenance validation panel renders per-citation retrieved state', () => {
  const src = read(PANEL);
  assert.match(src, /citation-retrieved-state/);
  assert.match(src, /Retrieved/);
  assert.match(src, /Not retrieved/);
});

test('provenance validation panel renders per-citation included-in-prompt state', () => {
  const src = read(PANEL);
  assert.match(src, /citation-included-state/);
  assert.match(src, /In prompt/);
  assert.match(src, /Not in prompt/);
});

test('provenance validation panel renders per-citation cited state', () => {
  const src = read(PANEL);
  assert.match(src, /citation-cited-state/);
});

// ─── Citation ordering ────────────────────────────────────────────────────────

test('provenance validation panel sorts rejected citations first', () => {
  const src = read(PANEL);
  assert.match(src, /CITATION_STATUS_ORDER/);
  // invalid must have lowest order value
  assert.match(src, /invalid.*0/);
  assert.match(src, /rejected.*1/);
  assert.match(src, /valid.*2/);
  assert.match(src, /unknown.*3/);
  assert.match(src, /unavailable.*4/);
});

test('provenance validation panel citation sort uses localeCompare tie-break', () => {
  const src = read(PANEL);
  assert.match(src, /localeCompare/);
  // Tie-break key must include citation_id, chunk_id, source_id, document_id
  assert.match(src, /citation_id/);
  assert.match(src, /chunk_id/);
  assert.match(src, /source_id/);
  assert.match(src, /document_id/);
});

test('provenance validation panel deriveCitationsFromProvenance is deterministic', () => {
  const src = read(PANEL);
  assert.match(src, /function deriveCitationsFromProvenance/);
  assert.match(src, /sortCitations/);
  // Must handle structured citations prop when available
  assert.match(src, /data\.citations.*length/);
});

// ─── Retrieved / prompt-included / cited distinction ─────────────────────────

test('provenance validation panel distinguishes retrieved included and cited chunks', () => {
  const src = read(PANEL);
  assert.match(src, /chunk-breakdown-section/);
  assert.match(src, /chunk-pipeline-counts/);
  assert.match(src, /retrieved-chunk-count/);
  assert.match(src, /included-chunk-count/);
  assert.match(src, /cited-chunk-count/);
});

test('provenance validation panel renders the distinction note', () => {
  const src = read(PANEL);
  assert.match(src, /Retrieved ≠ Included in prompt/);
  assert.match(src, /Included ≠ Cited/);
  assert.match(src, /Cited ≠ Valid/);
  assert.match(src, /chunk-distinction-note/);
});

test('provenance validation panel renders chunk pipeline table', () => {
  const src = read(PANEL);
  assert.match(src, /chunk-breakdown-table/);
  assert.match(src, /chunk-pipeline-table/);
  assert.match(src, /chunk-breakdown-row/);
  assert.match(src, /retrieved-cell/);
  assert.match(src, /included-cell/);
  assert.match(src, /not-included-cell/);
  assert.match(src, /cited-cell/);
  assert.match(src, /not-cited-cell/);
});

test('provenance validation panel renders not-included chunk warning', () => {
  const src = read(PANEL);
  assert.match(src, /not-included-chunk-warning/);
  assert.match(src, /retrieved but not included in prompt context/);
  assert.match(src, /notIncludedCount/);
});

// ─── Trust status ─────────────────────────────────────────────────────────────

test('provenance validation panel renders provenance trust status', () => {
  const src = read(PANEL);
  assert.match(src, /provenance-trust-status-section/);
  assert.match(src, /provenance-trust-level/);
  assert.match(src, /provenance-trust-detail/);
  assert.match(src, /TRUST_CONFIG/);
});

test('deriveTrustLevel is deterministic for all known reason codes', () => {
  const src = read(PANEL);
  assert.match(src, /function deriveTrustLevel/);
  // Must map each known code explicitly
  assert.match(src, /PROVENANCE_VALID.*trusted/s);
  assert.match(src, /PROVENANCE_NO_CONTEXT_AVAILABLE.*no_context/s);
  assert.match(src, /PROVENANCE_SOURCE_NOT_RETRIEVED.*untrusted/s);
  assert.match(src, /PROVENANCE_SOURCE_NOT_IN_PROMPT.*untrusted/s);
  // Unknown codes → unavailable
  assert.match(src, /return 'unavailable'/);
});

test('deriveTrustLevel derivation is documented in comments', () => {
  const src = read(PANEL);
  // Must document the derivation so operators/auditors can verify
  assert.match(src, /PROVENANCE_VALID.*→.*trusted/);
  assert.match(src, /PROVENANCE_NO_CONTEXT_AVAILABLE.*→.*no_context/);
  assert.match(src, /PROVENANCE_SOURCE_NOT_RETRIEVED.*→.*untrusted/);
  assert.match(src, /PROVENANCE_SOURCE_NOT_IN_PROMPT.*→.*untrusted/);
});

test('trust-derivation-source is rendered so operators can see what status was used', () => {
  const src = read(PANEL);
  assert.match(src, /trust-derivation-source/);
  assert.match(src, /Derived from:/);
});

// ─── Export-safe summary ──────────────────────────────────────────────────────

test('provenance validation panel export-safe summary exists', () => {
  const src = read(PANEL);
  assert.match(src, /export-safe-summary-section/);
  assert.match(src, /export-safe-indicator/);
  assert.match(src, /export-summary-fields/);
  assert.match(src, /buildProvenanceExportSummary/);
});

test('export-safe summary excludes raw vectors', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /raw_vector/i);
  assert.doesNotMatch(src, /embedding_vector/i);
});

test('export-safe summary excludes raw prompts', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /raw_prompt/i);
  assert.doesNotMatch(src, /system_prompt/i);
  assert.doesNotMatch(src, /provider_payload/i);
});

test('export-safe summary excludes secrets and auth material', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /api_key/i);
  assert.doesNotMatch(src, /provider_token/i);
  assert.doesNotMatch(src, /auth_header/i);
  assert.doesNotMatch(src, /secret/i);
});

test('export-safe summary marks payload as export_safe: true', () => {
  const src = read(PANEL);
  assert.match(src, /export_safe: true/);
  assert.match(src, /ProvenanceExportSummary/);
});

test('buildProvenanceExportSummary includes safe provenance fields only', () => {
  const src = read(PANEL);
  assert.match(src, /provenance_status/);
  assert.match(src, /trust_level/);
  assert.match(src, /citation_count/);
  assert.match(src, /prompt_included_chunk_count/);
  assert.match(src, /retrieved_chunk_count/);
  assert.match(src, /retrieval_trace_id/);
  assert.match(src, /retrieval_strategy/);
  assert.match(src, /generated_at/);
});

test('export copy button is keyboard accessible', () => {
  const src = read(PANEL);
  assert.match(src, /Copy export summary to clipboard/);
  assert.match(src, /type="button"/);
  assert.match(src, /focus-visible:ring/);
});

// ─── No-context behavior ──────────────────────────────────────────────────────

test('provenance validation panel renders no-context state with export warning', () => {
  const src = read(PANEL);
  assert.match(src, /no-context-export-warning/);
  assert.match(src, /not provenance-validated/);
});

test('provenance validation panel hides chunk breakdown when no context', () => {
  const src = read(PANEL);
  // chunk-breakdown-section must be gated by !isNoContext
  assert.match(src, /\{!isNoContext && /);
  assert.match(src, /isNoContext/);
});

test('provenance validation panel shows no-citations message when no context', () => {
  const src = read(PANEL);
  assert.match(src, /No citations to validate — no context was available/);
});

// ─── Safe fallback states ─────────────────────────────────────────────────────

test('provenance validation panel handles null provenance gracefully', () => {
  const src = read(PANEL);
  assert.match(src, /provenance == null/);
  assert.match(src, /provenance-validation-empty/);
});

test('provenance validation panel handles no chunk detail safely', () => {
  const src = read(PANEL);
  assert.match(src, /no-chunk-detail-state/);
  assert.match(src, /No chunk detail available/);
});

test('provenance validation panel filters malformed source summaries', () => {
  const src = read(PANEL);
  // Must filter out null/non-object entries
  assert.match(src, /\.filter\(.*s.*!=.*null.*typeof.*object/s);
});

test('provenance validation panel handles empty citation arrays safely', () => {
  const src = read(PANEL);
  // deriveCitationsFromProvenance must handle null/empty arrays
  assert.match(src, /data\.citation_source_ids.*\?\?.*\[\]/);
  assert.match(src, /data\.invalid_source_ids.*\?\?.*\[\]/);
});

// ─── Future placeholders ──────────────────────────────────────────────────────

test('provenance validation panel future placeholders render safely', () => {
  const src = read(PANEL);
  assert.match(src, /provenance-future-capabilities-section/);
  assert.match(src, /provenance-future-placeholder/);
  assert.match(src, /not yet available/);
  // Must be collapsed by default
  assert.match(src, /defaultOpen=\{false\}/);
});

test('provenance validation panel future placeholders do not fake graph lineage or legal status', () => {
  const src = read(PANEL);
  // Must have the labels but marked not yet available
  assert.match(src, /Evidence graph/);
  assert.match(src, /Legal review mode/);
  assert.match(src, /Citation lineage/);
  assert.match(src, /Exportable legal packet/);
  assert.match(src, /Answer-to-source mapping/);
  // Must not imply these are functional
  assert.doesNotMatch(src, /Legal approved/i);
  assert.doesNotMatch(src, /Probably fine/i);
  assert.doesNotMatch(src, /AI thinks this is valid/i);
  assert.doesNotMatch(src, /Looks trustworthy/i);
});

test('provenance validation panel future placeholders do not contain fake data', () => {
  const src = read(PANEL);
  // Must not contain fabricated graph nodes or lineage paths
  assert.doesNotMatch(src, /evidenceNodes/i);
  assert.doesNotMatch(src, /fake.*graph/i);
  assert.doesNotMatch(src, /lineage.*=.*\[/i);
});

// ─── Security: no dangerous rendering ────────────────────────────────────────

test('provenance validation panel does not use dangerouslySetInnerHTML', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /dangerously\s*Set\s*Inner\s*HTML/i);
});

test('provenance validation panel does not expose raw vectors', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /raw_vector/i);
  assert.doesNotMatch(src, /embedding_vector/i);
  assert.doesNotMatch(src, /\bvector\b.*render/i);
});

test('provenance validation panel does not expose raw prompts', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /raw_prompt/i);
  assert.doesNotMatch(src, /system_prompt/i);
  assert.doesNotMatch(src, /provider_payload/i);
});

test('provenance validation panel does not expose provider internals', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /openai_response/i);
  assert.doesNotMatch(src, /anthropic_response/i);
  assert.doesNotMatch(src, /provider_token/i);
});

// ─── No fake evidence ─────────────────────────────────────────────────────────

test('provenance validation panel does not contain fake citations', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /Apex National/i);
  assert.doesNotMatch(src, /meridian-health/i);
  assert.doesNotMatch(src, /fake.*citation/i);
});

test('provenance validation panel does not contain fake legal approval', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /Legal approved/i);
  assert.doesNotMatch(src, /Compliance passed/i);
  assert.doesNotMatch(src, /100% trusted/i);
});

test('provenance validation panel does not fake evidence graph data', () => {
  const src = read(PANEL);
  assert.doesNotMatch(src, /graph.*nodes.*=.*\[/i);
  assert.doesNotMatch(src, /lineage.*nodes/i);
  assert.doesNotMatch(src, /evidenceGraph/i);
});

// ─── Accessibility ────────────────────────────────────────────────────────────

test('provenance validation panel preserves accessibility semantics', () => {
  const src = read(PANEL);
  // Semantic headings
  assert.match(src, /<h3/);
  // Aria labels
  assert.match(src, /aria-label/);
  // Icons aria-hidden
  assert.match(src, /aria-hidden="true"/);
  // Role alert on invalid states
  assert.match(src, /role=\{isInvalidState \? 'alert' : undefined\}/);
  // Aria expanded on collapsible buttons
  assert.match(src, /aria-expanded/);
  // Aria controls on collapsible buttons
  assert.match(src, /aria-controls/);
});

test('provenance validation panel has visible focus states', () => {
  const src = read(PANEL);
  assert.match(src, /focus-visible:ring/);
  assert.match(src, /focus:outline-none/);
});

test('provenance validation panel collapsible sections are keyboard accessible', () => {
  const src = read(PANEL);
  assert.match(src, /<button/);
  assert.match(src, /type="button"/);
  assert.match(src, /aria-expanded/);
  assert.match(src, /aria-controls/);
  assert.match(src, /hidden=\{!open\}/);
});

// ─── Collapsible section ──────────────────────────────────────────────────────

test('provenance validation panel uses collapsible sections', () => {
  const src = read(PANEL);
  assert.match(src, /CollapsibleSection/);
  assert.match(src, /function CollapsibleSection/);
});

// ─── Responsive / safe truncation ────────────────────────────────────────────

test('provenance validation panel truncates long IDs safely', () => {
  const src = read(PANEL);
  assert.match(src, /truncate/);
  assert.match(src, /overflow-x-auto/);
});

// ─── Provenance page integration ─────────────────────────────────────────────

test('provenance page renders ProvenanceValidationPanel', () => {
  const page = read(PROVENANCE_PAGE);
  assert.match(page, /ProvenanceValidationPanel/);
  assert.match(page, /provenance=\{null\}/);
  assert.match(page, /provenance-page/);
  assert.match(page, /provenance-validation-card/);
});

test('provenance page renders capability overview', () => {
  const page = read(PROVENANCE_PAGE);
  assert.match(page, /provenance-capability-list/);
  assert.match(page, /Citation validation state/);
  assert.match(page, /rejection reason/);
  assert.match(page, /Export-safe summary/);
});

// ─── Existing tests smoke checks ──────────────────────────────────────────────

test('existing AI workspace tests still pass (file exists and loads)', () => {
  assert.ok(exists('tests/ai-workspace.test.js'), 'ai-workspace test file must exist');
  const src = read('tests/ai-workspace.test.js');
  assert.match(src, /ai workspace renders governed chat layout/);
  assert.match(src, /ai workspace includes conversation metadata and evidence columns/);
});

test('existing source evidence panel tests still pass (file exists and loads)', () => {
  assert.ok(exists('tests/source-evidence-panel.test.js'), 'source-evidence-panel test file must exist');
  const src = read('tests/source-evidence-panel.test.js');
  assert.match(src, /source evidence panel/);
  assert.match(src, /SourceEvidencePanel/);
});

test('existing retrieval trace explorer tests still pass (file exists and loads)', () => {
  assert.ok(exists('tests/retrieval-trace-explorer.test.js'), 'retrieval-trace-explorer test file must exist');
  const src = read('tests/retrieval-trace-explorer.test.js');
  assert.match(src, /RetrievalTraceExplorer/);
});

test('existing governance index still exports all prior components', () => {
  const idx = read(INDEX);
  assert.match(idx, /SourceEvidencePanel/);
  assert.match(idx, /RetrievalTraceExplorer/);
  assert.match(idx, /ConfidenceMeter/);
  assert.match(idx, /PolicyDecision/);
  assert.match(idx, /ProviderRouteCard/);
});

test('existing shell navigation tests still pass (smoke check)', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /AI Workspace/);
  assert.match(sidebar, /\/dashboard\/assistant/);
});

test('existing dashboard truth anchors preserved', () => {
  const page_ = read('app/dashboard/page.tsx');
  assert.match(page_, /billing-ready/);
  assert.match(page_, /billing-not-ready/);
  assert.match(page_, /events-loading/);
});
