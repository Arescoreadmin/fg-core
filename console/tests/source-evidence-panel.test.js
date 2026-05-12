/**
 * source-evidence-panel.test.js
 *
 * Static-analysis tests for PR 46 — Source & Evidence Side Panel
 *
 * Coverage:
 *   - source cards render with rank, chunk ref, scores, metadata
 *   - chunk references render deterministically
 *   - retrieval scores render safely (only real numbers)
 *   - unavailable scores render explicit fallback
 *   - why-this-chunk explanations render safely
 *   - confidence explanations render with grounding levels
 *   - retrieval strategy renders with label
 *   - lexical fallback renders explicitly
 *   - source metadata renders safely
 *   - no-context state renders explicitly
 *   - invalid provenance state renders explicitly
 *   - no-source state renders safely
 *   - collapsible evidence sections present
 *   - evidence ordering deterministic
 *   - evidence ordering tie-break deterministic
 *   - no raw vectors rendered
 *   - no raw prompts rendered
 *   - no provider internals rendered
 *   - no dangerouslySetInnerHTML
 *   - no fake citations
 *   - no fake scores
 *   - future placeholders render safely
 *   - accessibility basics present
 *   - existing AI workspace tests still pass (smoke)
 *   - existing shell/dashboard tests still pass (smoke)
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

const PANEL = 'components/governance/SourceEvidencePanel.tsx';
const PAGE = 'app/dashboard/assistant/page.tsx';
const INDEX = 'components/governance/index.ts';

// ─── File existence ───────────────────────────────────────────────────────────

test('source evidence panel file exists', () => {
  assert.ok(exists(PANEL), 'SourceEvidencePanel.tsx must exist');
});

test('source evidence panel is exported from governance index', () => {
  const idx = read(INDEX);
  assert.match(idx, /SourceEvidencePanel/);
  assert.match(idx, /SourceEvidencePanel.*from.*SourceEvidencePanel/s);
});

test('page imports and uses SourceEvidencePanel', () => {
  const page = read(PAGE);
  assert.match(page, /SourceEvidencePanel/);
  assert.match(page, /from.*@\/components\/governance/);
});

// ─── Source cards ─────────────────────────────────────────────────────────────

test('source evidence panel renders source cards', () => {
  const panel = read(PANEL);
  assert.match(panel, /source-card/);
  assert.match(panel, /SourceCard/);
  assert.match(panel, /source-cards-list/);
  assert.match(panel, /source-cards-section/);
});

test('source evidence panel renders retrieval rank on source card', () => {
  const panel = read(PANEL);
  assert.match(panel, /retrieval-rank/);
  assert.match(panel, /retrievalRank/);
  // JSX renders rank as #{retrievalRank} — # followed by JSX expression
  assert.match(panel, /#\{retrievalRank\}/);
});

test('source evidence panel renders inclusion status on source card', () => {
  const panel = read(PANEL);
  assert.match(panel, /inclusion-status/);
  assert.match(panel, /included_in_prompt/);
  assert.match(panel, /Included/);
  assert.match(panel, /Not in prompt/);
});

// ─── Chunk references ─────────────────────────────────────────────────────────

test('source evidence panel renders chunk references', () => {
  const panel = read(PANEL);
  assert.match(panel, /chunk-reference/);
  assert.match(panel, /chunk-ids-list/);
  assert.match(panel, /chunk-ids-section/);
});

test('source evidence panel renders deterministic ordering', () => {
  const panel = read(PANEL);
  // orderSummaries function must exist
  assert.match(panel, /function orderSummaries/);
  // Must sort by rank first
  assert.match(panel, /rrf_rank/);
  assert.match(panel, /lexical_rank/);
  // Must sort by combined_score second
  assert.match(panel, /combined_score/);
  // Must have tie-break by chunk_id
  assert.match(panel, /localeCompare/);
});

test('source evidence panel renders deterministic ordering tie-break on chunk id', () => {
  const panel = read(PANEL);
  // Tie-break must use chunk_id alphabetical (localeCompare)
  assert.match(panel, /chunk_id.*localeCompare/s);
});

// ─── Retrieval scores ─────────────────────────────────────────────────────────

test('source evidence panel renders retrieval scores', () => {
  const panel = read(PANEL);
  assert.match(panel, /retrieval-score-section/);
  assert.match(panel, /lexical_score/);
  assert.match(panel, /semantic_score/);
  assert.match(panel, /rrf_score/);
  assert.match(panel, /combined_score/);
});

test('source evidence panel renders retrieval scores safely with formatScore', () => {
  const panel = read(PANEL);
  // Must use bounded formatting (toFixed(3))
  assert.match(panel, /formatScore/);
  assert.match(panel, /toFixed\(3\)/);
  // Must not invent percentages
  assert.doesNotMatch(panel, /\* 100/);
});

test('source evidence panel renders unavailable scores with explicit fallback', () => {
  const panel = read(PANEL);
  assert.match(panel, /score-unavailable/);
  assert.match(panel, /Scores unavailable/);
});

test('source evidence panel renders scores only when real finite numbers', () => {
  const panel = read(PANEL);
  // safeNum helper must check typeof and isFinite
  assert.match(panel, /function safeNum/);
  assert.match(panel, /typeof val.*number/);
  assert.match(panel, /isFinite/);
});

// ─── Why-this-chunk ───────────────────────────────────────────────────────────

test('source evidence panel renders why-this-chunk explanations safely', () => {
  const panel = read(PANEL);
  assert.match(panel, /why-this-chunk-section/);
  assert.match(panel, /Why Retrieved/);
  assert.match(panel, /rank-reason/);
  assert.match(panel, /rank_reason/);
});

test('source evidence panel renders matched term count from why-this-chunk', () => {
  const panel = read(PANEL);
  assert.match(panel, /matched_term_count/);
  assert.match(panel, /Matched terms/);
});

test('source evidence panel renders matched categories from why-this-chunk', () => {
  const panel = read(PANEL);
  assert.match(panel, /matched_categories/);
  assert.match(panel, /Categories/);
});

test('source evidence panel does not expose raw prompt fragments in why-this-chunk', () => {
  const panel = read(PANEL);
  // Must not render raw matched terms or provider reasoning
  assert.doesNotMatch(panel, /raw_matched_term/i);
  assert.doesNotMatch(panel, /provider_reasoning/i);
  assert.doesNotMatch(panel, /system_prompt/i);
});

// ─── Confidence explanation ───────────────────────────────────────────────────

test('source evidence panel renders confidence explanations', () => {
  const panel = read(PANEL);
  assert.match(panel, /confidence-explanation/);
  assert.match(panel, /confidence-grounding-level/);
  assert.match(panel, /groundingLevel/);
  assert.match(panel, /GROUNDING_CONFIG/);
});

test('source evidence panel renders all grounding levels', () => {
  const panel = read(PANEL);
  assert.match(panel, /grounded/);
  assert.match(panel, /weakly-grounded/);
  assert.match(panel, /ungrounded/);
  assert.match(panel, /unavailable/);
  // Must have text label for each (non-color-only)
  assert.match(panel, /Grounded/);
  assert.match(panel, /Weakly Grounded/);
  assert.match(panel, /Ungrounded/);
  assert.match(panel, /Unavailable/);
});

test('source evidence panel confidence uses non-color-only indicators', () => {
  const panel = read(PANEL);
  // Each grounding level must have both a text label AND an icon
  assert.match(panel, /GroundingIcon/);
  assert.match(panel, /statusText/);
  // Icons must be aria-hidden
  assert.match(panel, /aria-hidden="true"/);
});

test('source evidence panel does not invent confidence math', () => {
  const panel = read(PANEL);
  // Must not hardcode fake confidence thresholds beyond the defined bounds
  assert.doesNotMatch(panel, /confidence.*0\.95/);
  assert.doesNotMatch(panel, /confidence.*=\s*1\b/);
  // Must not imply 100% certainty
  assert.doesNotMatch(panel, /100% confident/i);
  assert.doesNotMatch(panel, /guaranteed/i);
});

// ─── Retrieval strategy ───────────────────────────────────────────────────────

test('source evidence panel renders retrieval strategy', () => {
  const panel = read(PANEL);
  assert.match(panel, /retrieval-strategy-section/);
  assert.match(panel, /retrieval-strategy/);
  assert.match(panel, /STRATEGY_LABELS/);
  assert.match(panel, /strategyLabel/);
});

test('source evidence panel renders supported strategy labels', () => {
  const panel = read(PANEL);
  assert.match(panel, /lexical.*Lexical/s);
  assert.match(panel, /semantic.*Semantic/s);
  assert.match(panel, /hybrid.*Hybrid/s);
  assert.match(panel, /hybrid_rrf.*Hybrid RRF/s);
});

test('source evidence panel renders lexical fallback explicitly', () => {
  const panel = read(PANEL);
  assert.match(panel, /lexical-fallback-indicator/);
  assert.match(panel, /Lexical fallback/i);
  assert.match(panel, /isLexicalFallback/);
  // Must detect via strategy = 'lexical' or explicit flag
  assert.match(panel, /lexical_fallback/);
});

test('source evidence panel renders retrieval unavailable state', () => {
  const panel = read(PANEL);
  assert.match(panel, /retrieval-unavailable-state/);
  assert.match(panel, /Retrieval strategy not reported/);
});

// ─── Source metadata ──────────────────────────────────────────────────────────

test('source evidence panel renders source metadata safely', () => {
  const panel = read(PANEL);
  assert.match(panel, /source-metadata-section/);
  assert.match(panel, /source_id/);
  assert.match(panel, /chunk_id/);
  assert.match(panel, /corpus_id/);
  assert.match(panel, /document_id/);
  assert.match(panel, /chunk_index/);
});

test('source evidence panel does not expose tenant secrets or raw storage paths', () => {
  const panel = read(PANEL);
  assert.doesNotMatch(panel, /storage_path/i);
  assert.doesNotMatch(panel, /tenant_secret/i);
  assert.doesNotMatch(panel, /api_key/i);
  assert.doesNotMatch(panel, /provider_payload/i);
});

// ─── Safe fallback states ─────────────────────────────────────────────────────

test('source evidence panel handles no-context state safely', () => {
  const panel = read(PANEL);
  assert.match(panel, /no-context-state/);
  assert.match(panel, /No retrieval context available/);
  assert.match(panel, /Answer was generated without retrieved evidence/);
});

test('source evidence panel handles invalid provenance state explicitly', () => {
  const panel = read(PANEL);
  assert.match(panel, /invalid-provenance-state/);
  assert.match(panel, /Provenance validation did not pass/);
  assert.match(panel, /isInvalidProvenance/);
});

test('source evidence panel handles no-source state safely', () => {
  const panel = read(PANEL);
  assert.match(panel, /no-source-state/);
  assert.match(panel, /No source references returned/);
});

test('source evidence panel handles api failure state', () => {
  const panel = read(PANEL);
  assert.match(panel, /api-failure-state/);
  assert.match(panel, /Retrieval data could not be loaded/);
  assert.match(panel, /apiFailure/);
});

test('source evidence panel does not render blank panels', () => {
  const panel = read(PANEL);
  // Every fallback state must have a message
  assert.match(panel, /evidence-empty/);
  // Evidence empty has text
  assert.match(panel, /Sources will appear here/);
});

// ─── Collapsible sections ─────────────────────────────────────────────────────

test('source evidence panel uses collapsible sections', () => {
  const panel = read(PANEL);
  assert.match(panel, /CollapsibleSection/);
  assert.match(panel, /function CollapsibleSection/);
});

test('collapsible sections are keyboard accessible', () => {
  const panel = read(PANEL);
  // Must use button element
  assert.match(panel, /<button/);
  assert.match(panel, /type="button"/);
  // Must have aria-expanded
  assert.match(panel, /aria-expanded/);
  // Must have aria-controls
  assert.match(panel, /aria-controls/);
  // Must have focus-visible style
  assert.match(panel, /focus-visible:ring/);
});

test('collapsible sections have stable hidden attribute', () => {
  const panel = read(PANEL);
  // Must use hidden attribute for content visibility
  assert.match(panel, /hidden=\{!open\}/);
});

// ─── Security: no raw injection ───────────────────────────────────────────────

test('source evidence panel does not use dangerouslySetInnerHTML', () => {
  const panel = read(PANEL);
  assert.doesNotMatch(panel, /dangerously\s*Set\s*Inner\s*HTML/i);
});

test('source evidence panel does not expose raw vectors', () => {
  const panel = read(PANEL);
  assert.doesNotMatch(panel, /raw_vector/i);
  assert.doesNotMatch(panel, /embedding_vector/i);
  assert.doesNotMatch(panel, /\bvector\b.*render/i);
});

test('source evidence panel does not expose raw prompts', () => {
  const panel = read(PANEL);
  assert.doesNotMatch(panel, /raw_prompt/i);
  assert.doesNotMatch(panel, /system_prompt/i);
  assert.doesNotMatch(panel, /provider_payload/i);
});

test('source evidence panel does not expose provider internals', () => {
  const panel = read(PANEL);
  assert.doesNotMatch(panel, /provider_token/i);
  assert.doesNotMatch(panel, /openai_response/i);
  assert.doesNotMatch(panel, /anthropic_response/i);
});

// ─── No fake evidence ─────────────────────────────────────────────────────────

test('source evidence panel does not contain fake citations', () => {
  const panel = read(PANEL);
  // Must not hardcode fake source names
  assert.doesNotMatch(panel, /Apex National/i);
  assert.doesNotMatch(panel, /meridian-health/i);
  assert.doesNotMatch(panel, /fake.*citation/i);
});

test('source evidence panel does not contain fake scores', () => {
  const panel = read(PANEL);
  // Must not hardcode score values
  assert.doesNotMatch(panel, /lexical_score.*0\.9[0-9]/);
  assert.doesNotMatch(panel, /combined_score.*=.*0\.[0-9]/);
});

// ─── Future placeholders ──────────────────────────────────────────────────────

test('source evidence panel future placeholders render safely', () => {
  const panel = read(PANEL);
  assert.match(panel, /future-placeholder/);
  assert.match(panel, /future-capabilities-section/);
  assert.match(panel, /not yet available/);
});

test('source evidence panel future placeholders do not fake metrics', () => {
  const panel = read(PANEL);
  // Placeholder items must be labeled "not yet available", not have numbers
  assert.match(panel, /Rerank visualization/);
  assert.match(panel, /Source freshness/);
  assert.match(panel, /Conflicting evidence/);
  assert.match(panel, /Citation lineage/);
  // Must not show fake rerank scores
  assert.doesNotMatch(panel, /rerank_score.*\d+\.\d+/);
  assert.doesNotMatch(panel, /freshness.*\d+ days/i);
});

// ─── Accessibility ────────────────────────────────────────────────────────────

test('source evidence panel preserves accessibility semantics', () => {
  const panel = read(PANEL);
  // Semantic headings
  assert.match(panel, /<h3/);
  // Aria labels present
  assert.match(panel, /aria-label/);
  // Icons aria-hidden
  assert.match(panel, /aria-hidden="true"/);
  // Role alert on warning banners
  assert.match(panel, /role="alert"/);
  // ARIA expanded on collapsible buttons
  assert.match(panel, /aria-expanded/);
});

test('source evidence panel has visible focus states', () => {
  const panel = read(PANEL);
  assert.match(panel, /focus-visible:ring/);
  assert.match(panel, /focus:outline-none/);
});

// ─── Existing tests smoke check ───────────────────────────────────────────────

test('existing AI workspace tests still pass (file exists and loads)', () => {
  assert.ok(exists('tests/ai-workspace.test.js'), 'ai-workspace test file must exist');
  const test_ = read('tests/ai-workspace.test.js');
  // Key AI workspace test anchors must still be present
  assert.match(test_, /ai workspace renders governed chat layout/);
  assert.match(test_, /ai workspace includes conversation metadata and evidence columns/);
});

test('existing shell navigation tests still pass (smoke check)', () => {
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /AI Workspace/);
  assert.match(sidebar, /\/dashboard\/assistant/);
});

test('existing dashboard truth anchors preserved', () => {
  const page_ = read('app/dashboard/page.tsx');
  // Key anchors from dashboard-truth tests
  assert.match(page_, /billing-ready/);
  assert.match(page_, /billing-not-ready/);
  assert.match(page_, /events-loading/);
});

test('page.tsx still renders evidence column with SourceEvidencePanel', () => {
  const page = read(PAGE);
  assert.match(page, /evidence-column/);
  assert.match(page, /Evidence.*Sources/s);
  assert.match(page, /SourceEvidencePanel/);
  // Must pass provenance data
  assert.match(page, /provenance.*provenance/s);
});

test('page.tsx does not reference removed inline EvidencePanel function', () => {
  const page = read(PAGE);
  // The inline function should have been removed; only the import remains
  assert.doesNotMatch(page, /function EvidencePanel/);
});

// ─── Safe extraction ──────────────────────────────────────────────────────────

test('source evidence panel uses safe extraction helpers', () => {
  const panel = read(PANEL);
  assert.match(panel, /function safeNum/);
  assert.match(panel, /function safeStr/);
  assert.match(panel, /function safeStrArr/);
  assert.match(panel, /function parseWhyEntry/);
});

test('source evidence panel parseWhyEntry does not expose raw unknown fields', () => {
  const panel = read(PANEL);
  // parseWhyEntry must only extract declared safe fields
  assert.match(panel, /function parseWhyEntry/);
  // Must check object type before accessing fields
  assert.match(panel, /typeof raw.*!==.*object/);
  // Must return empty object on invalid input
  assert.match(panel, /return \{\}/);
});
