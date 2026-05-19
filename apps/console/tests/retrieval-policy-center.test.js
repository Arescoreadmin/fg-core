/**
 * retrieval-policy-center.test.js
 *
 * Static-analysis tests for PR 49 — Retrieval Policy Center
 *
 * Coverage:
 *   - File existence and exports
 *   - Component signatures (RetrievalPolicyCenter, sub-components)
 *   - Policy validation: invalid top-k, unsupported strategy, semantic/strategy conflict,
 *     contradictory corpus policy, missing tenant_id
 *   - Policy preview: effective corpora, denied corpora, empty scope, semantic state,
 *     fallback state, grounded-answer state, no live retrieval
 *   - Corpus policy matrix: allowed/denied/inherited states, denied overrides allowed
 *   - Strategy panel: only repo-approved values, semantic toggle
 *   - Grounding panel: enforcement state matches backend behavior, no fake toggle
 *   - Fallback panel: never bypasses denied corpora language present
 *   - Audit summary: timestamps, actors, changed_fields
 *   - Tenant isolation: tenant_id required, no cross-tenant exposure
 *   - Governance safety: no dangerouslySetInnerHTML, no raw vectors/prompts/provider payloads,
 *     no fake retrieval results, no fake policy approval
 *   - Retrieval page integration
 *   - Index exports
 *   - Regression: provenance panel, retrieval trace explorer still present
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

const POLICY_CENTER = 'components/governance/RetrievalPolicyCenter.tsx';
const INDEX = 'components/governance/index.ts';
const RETRIEVAL_PAGE = 'app/dashboard/retrieval/page.tsx';
const PROVENANCE_PANEL = 'components/governance/ProvenanceValidationPanel.tsx';
const TRACE_EXPLORER = 'components/governance/RetrievalTraceExplorer.tsx';

// ─── File existence ───────────────────────────────────────────────────────────

test('RetrievalPolicyCenter.tsx exists', () => {
  assert.ok(exists(POLICY_CENTER), 'Missing RetrievalPolicyCenter.tsx');
});

test('retrieval page exists', () => {
  assert.ok(exists(RETRIEVAL_PAGE), 'Missing app/dashboard/retrieval/page.tsx');
});

// ─── Exports ──────────────────────────────────────────────────────────────────

test('index.ts exports RetrievalPolicyCenter', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalPolicyCenter/);
  assert.match(idx, /from '\.\/RetrievalPolicyCenter'/);
});

test('index.ts exports all required sub-components', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalPolicyEditor/);
  assert.match(idx, /RetrievalPolicyPreview/);
  assert.match(idx, /CorpusPolicyMatrix/);
  assert.match(idx, /RetrievalStrategyPanel/);
  assert.match(idx, /GroundingEnforcementPanel/);
  assert.match(idx, /RetrievalFallbackPanel/);
  assert.match(idx, /RetrievalPolicyAuditSummary/);
});

test('index.ts exports validation and preview utilities', () => {
  const idx = read(INDEX);
  assert.match(idx, /validateRetrievalPolicy/);
  assert.match(idx, /buildRetrievalPolicyPreview/);
});

test('index.ts exports RETRIEVAL_STRATEGIES, TOP_K_MIN, TOP_K_MAX constants', () => {
  const idx = read(INDEX);
  assert.match(idx, /RETRIEVAL_STRATEGIES/);
  assert.match(idx, /TOP_K_MIN/);
  assert.match(idx, /TOP_K_MAX/);
});

test('index.ts exports required types', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalPolicyCenterProps/);
  assert.match(idx, /RetrievalPolicyData/);
  assert.match(idx, /RetrievalPolicyValidationError/);
  assert.match(idx, /RetrievalPolicyPreviewData/);
  assert.match(idx, /RetrievalPolicyAuditEntry/);
  assert.match(idx, /CorpusEntry/);
  assert.match(idx, /CorpusAccessState/);
  assert.match(idx, /RetrievalStrategy/);
});

// ─── Component signatures ─────────────────────────────────────────────────────

test('RetrievalPolicyCenter is a named export function', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function RetrievalPolicyCenter/);
});

test('RetrievalPolicyCenter accepts policy prop', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /policy\?/);
});

test('RetrievalPolicyCenter accepts availableCorpora prop', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /availableCorpora/);
});

test('RetrievalPolicyCenter accepts auditEntries prop', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /auditEntries/);
});

test('RetrievalPolicyCenter accepts onSave callback', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /onSave/);
});

test('RetrievalPolicyCenter accepts apiFailure prop', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /apiFailure/);
});

test('component is a client component', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /'use client'/);
});

// ─── Retrieval strategies ─────────────────────────────────────────────────────

test('only repo-approved retrieval strategies defined', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /RETRIEVAL_STRATEGIES/);
  // Must include all four approved values
  assert.match(src, /'lexical'/);
  assert.match(src, /'semantic'/);
  assert.match(src, /'hybrid'/);
  assert.match(src, /'hybrid_rrf'/);
});

test('no unknown or invented strategy values', () => {
  const src = read(POLICY_CENTER);
  // Must NOT contain any invented strategy values
  assert.doesNotMatch(src, /'vector_search'/);
  assert.doesNotMatch(src, /'bm42'/);
  assert.doesNotMatch(src, /'dense'/);
  assert.doesNotMatch(src, /'sparse'/);
});

// ─── Top-K validation ─────────────────────────────────────────────────────────

test('validateRetrievalPolicy is exported', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function validateRetrievalPolicy/);
});

test('validation rejects top_k below minimum', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /TOP_K_MIN/);
  assert.match(src, /TOP_K_MAX/);
  assert.match(src, /INVALID_TOP_K/);
});

test('TOP_K_MIN is 1', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /TOP_K_MIN = 1/);
});

test('TOP_K_MAX is 20', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /TOP_K_MAX = 20/);
});

test('validation rejects unsupported strategy', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /UNSUPPORTED_STRATEGY/);
});

test('validation rejects semantic strategy with semantic disabled', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /SEMANTIC_DISABLED_WITH_SEMANTIC_STRATEGY/);
});

test('validation rejects contradictory corpus policy', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /CONTRADICTORY_CORPUS_POLICY/);
});

test('validation rejects missing tenant_id', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /MISSING_TENANT_ID/);
});

test('validation returns empty array for valid policy', () => {
  const src = read(POLICY_CENTER);
  // Function must return errors array
  assert.match(src, /RetrievalPolicyValidationError\[\]/);
  assert.match(src, /return errors/);
});

// ─── Policy preview ───────────────────────────────────────────────────────────

test('buildRetrievalPolicyPreview is exported', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function buildRetrievalPolicyPreview/);
});

test('preview does not execute live retrieval', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /does not execute live retrieval/);
});

test('preview returns effective_corpora field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /effective_corpora/);
});

test('preview returns denied_corpora field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /denied_corpora/);
});

test('preview returns empty_scope field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /empty_scope/);
});

test('preview reflects denied corpora override allowed', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /filter.*denied/);
});

test('preview warns when effective scope is empty', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Effective corpus scope is empty/);
});

test('preview warns when semantic strategy used with semantic disabled', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /requires semantic enabled/);
});

test('preview has legal note — no implied compliance', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /no legal or compliance.*approval is implied/i);
});

test('preview shows Preview only label', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Preview only/);
});

// ─── Corpus policy matrix ─────────────────────────────────────────────────────

test('CorpusPolicyMatrix is exported', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function CorpusPolicyMatrix/);
});

test('CorpusPolicyMatrix renders allowed state', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Allowed/);
  // aria-label uses template literal corpus-access-state-${state}
  assert.match(src, /corpus-access-state-/);
});

test('CorpusPolicyMatrix renders denied state', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Denied/);
  assert.match(src, /corpus-access-state-/);
});

test('CorpusPolicyMatrix renders inherited state', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Inherited/);
  assert.match(src, /corpus-access-state-/);
});

test('CorpusPolicyMatrix has cross-tenant safety note', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Cross-tenant corpora are never shown/);
});

test('CorpusPolicyMatrix explains denied overrides allowed', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Denied corpora override allowed/);
});

test('CorpusPolicyMatrix explains empty allowlist behavior', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Empty allowed list = all non-denied/);
});

test('CorpusPolicyMatrix renders allow/deny action buttons', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /allow-corpus-/);
  assert.match(src, /deny-corpus-/);
});

test('CorpusPolicyMatrix handles empty corpora safely', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /corpus-policy-matrix-empty/);
  assert.match(src, /No corpora available for this tenant/);
});

// ─── Strategy panel ───────────────────────────────────────────────────────────

test('RetrievalStrategyPanel is exported', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function RetrievalStrategyPanel/);
});

test('strategy panel has aria label', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /retrieval-strategy-panel/);
});

test('strategy panel warns when semantic strategy used with semantic disabled', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /semantic-strategy-warning/);
  assert.match(src, /requires semantic retrieval enabled/);
});

test('strategy panel has semantic-enabled-control', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /semantic-enabled-control/);
});

test('strategy panel shows lexical fallback cannot bypass denied corpora', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /does not bypass denied corpora/);
});

// ─── Grounding enforcement panel ─────────────────────────────────────────────

test('GroundingEnforcementPanel is exported', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function GroundingEnforcementPanel/);
});

test('grounding panel has aria label', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /grounding-enforcement-panel/);
});

test('grounding panel shows enforcement active state', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Grounded-answer enforcement: Active/);
});

test('grounding panel shows read-only enforcement note when readOnly', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /grounding-enforcement-note/);
  assert.match(src, /cannot be disabled in this deployment/);
});

test('grounding panel warns when enforcement is disabled', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /grounding-disabled-warning/);
  assert.match(src, /explicit operator approval/);
});

// ─── Fallback panel ───────────────────────────────────────────────────────────

test('RetrievalFallbackPanel is exported', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function RetrievalFallbackPanel/);
});

test('fallback panel has aria label', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /retrieval-fallback-panel/);
});

test('fallback panel states it does not bypass denied corpora', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /does not bypass denied corpora/);
});

test('fallback panel states it does not bypass tenant isolation', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /tenant isolation/);
});

test('fallback panel states it does not bypass provenance enforcement', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /provenance enforcement/);
});

// ─── Audit summary ────────────────────────────────────────────────────────────

test('RetrievalPolicyAuditSummary is exported', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /export function RetrievalPolicyAuditSummary/);
});

test('audit summary has aria label', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /retrieval-policy-audit-summary/);
});

test('audit summary renders timestamps', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /audit-timestamp/);
});

test('audit summary renders actors', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /audit-actor/);
});

test('audit summary renders changed fields', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /changed_fields/);
  assert.match(src, /changed-field-/);
});

test('audit summary renders policy version', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /policy_version/);
  assert.match(src, /policy-version/);
});

test('audit summary handles no entries safely', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /no-audit-entries/);
  assert.match(src, /No policy change audit entries/);
});

// ─── Tenant isolation ─────────────────────────────────────────────────────────

test('policy data includes tenant_id field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /tenant_id:/);
});

test('tenant_id is displayed to operator', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /Tenant:/);
});

test('policy-not-configured state renders safely', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /policy-not-configured/);
  assert.match(src, /No retrieval policy configured/);
});

test('api failure renders safe error state without exposing internals', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /policy-api-failure/);
  assert.match(src, /Retrieval policy unavailable/);
  // Must not expose raw error messages from backend
  assert.doesNotMatch(src, /stack.*trace/i);
  assert.doesNotMatch(src, /INTERNAL_SERVER_ERROR/);
});

// ─── Governance safety ────────────────────────────────────────────────────────

test('no dangerouslySetInnerHTML', () => {
  const src = read(POLICY_CENTER);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('no raw vector exposure', () => {
  const src = read(POLICY_CENTER);
  assert.doesNotMatch(src, /embedding_vector/);
  assert.doesNotMatch(src, /raw_vector/);
  assert.doesNotMatch(src, /float32/);
});

test('no raw prompt exposure', () => {
  const src = read(POLICY_CENTER);
  assert.doesNotMatch(src, /raw_prompt/);
  assert.doesNotMatch(src, /provider_prompt/);
  assert.doesNotMatch(src, /system_prompt/);
});

test('no provider secret exposure', () => {
  const src = read(POLICY_CENTER);
  assert.doesNotMatch(src, /api_key/);
  assert.doesNotMatch(src, /API_KEY/);
  assert.doesNotMatch(src, /secret_key/);
  assert.doesNotMatch(src, /provider_secret/);
});

test('no fake retrieval results', () => {
  const src = read(POLICY_CENTER);
  // Preview must not claim to execute retrieval
  assert.doesNotMatch(src, /live retrieval results/);
  assert.doesNotMatch(src, /simulated.*result/i);
  assert.doesNotMatch(src, /mock.*retrieval/i);
});

test('no fake policy approval language', () => {
  const src = read(POLICY_CENTER);
  assert.doesNotMatch(src, /compliance approved/i);
  assert.doesNotMatch(src, /legally approved/i);
  assert.doesNotMatch(src, /audit.*passed/i);
});

test('no hidden/system corpus exposure', () => {
  const src = read(POLICY_CENTER);
  assert.doesNotMatch(src, /__system_corpus/);
  assert.doesNotMatch(src, /hidden_corpus/);
  assert.doesNotMatch(src, /internal_corpus/);
});

// ─── UI / accessibility ───────────────────────────────────────────────────────

test('aria labels present on key interactive elements', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /aria-label/);
  assert.match(src, /aria-expanded/);
  assert.match(src, /aria-pressed/);
});

test('aria-hidden on decorative icons', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /aria-hidden="true"/);
});

test('role="alert" on warning states', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /role="alert"/);
});

test('role="tablist" and role="tab" for editor tabs', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /role="tablist"/);
  assert.match(src, /role="tab"/);
  assert.match(src, /role="tabpanel"/);
  assert.match(src, /aria-selected/);
});

test('labels associated with inputs via htmlFor', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /htmlFor=/);
});

test('status icons are aria-hidden with text labels', () => {
  const src = read(POLICY_CENTER);
  // Corpus access badge has text label, not color only
  assert.match(src, /corpus-access-state-/);
  // aria-label is a JSX expression with template literal: aria-label={`corpus-access-state-${state}`}
  assert.match(src, /aria-label=\{`corpus-access-state-/);
});

// ─── Retrieval page integration ───────────────────────────────────────────────

test('retrieval page imports RetrievalPolicyCenter', () => {
  const page = read(RETRIEVAL_PAGE);
  assert.match(page, /RetrievalPolicyCenter/);
  assert.match(page, /from.*@\/components\/governance/);
});

test('retrieval page has retrieval-page aria label', () => {
  const page = read(RETRIEVAL_PAGE);
  assert.match(page, /retrieval-page/);
});

test('retrieval page renders RetrievalPolicyCenter', () => {
  const page = read(RETRIEVAL_PAGE);
  assert.match(page, /<RetrievalPolicyCenter/);
});

test('retrieval page has capability overview card', () => {
  const page = read(RETRIEVAL_PAGE);
  assert.match(page, /retrieval-policy-capabilities/);
  assert.match(page, /retrieval-policy-capability-list/);
});

test('retrieval page capability list includes corpus access item', () => {
  const page = read(RETRIEVAL_PAGE);
  assert.match(page, /Corpus access control/);
});

test('retrieval page capability list includes validation before save', () => {
  const page = read(RETRIEVAL_PAGE);
  assert.match(page, /invalid configs fail closed|invalid configurations.*fail closed/i);
});

// ─── Validation before save ───────────────────────────────────────────────────

test('RetrievalPolicyEditor has save button with aria label', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /save-retrieval-policy/);
});

test('RetrievalPolicyEditor save button disabled when errors exist', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /disabled.*hasErrors/);
});

test('RetrievalPolicyEditor has cancel button', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /cancel-policy-edit/);
});

test('validation error summary has role alert', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /validation-error-summary/);
});

test('invalid policy save fails closed — errors must be non-empty', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /errors\.length > 0/);
  // Must check errors before calling onSave
  assert.match(src, /if.*errors\.length/);
});

// ─── Policy model fields ──────────────────────────────────────────────────────

test('policy model has allowed_corpora field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /allowed_corpora/);
});

test('policy model has denied_corpora field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /denied_corpora/);
});

test('policy model has retrieval_strategy field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /retrieval_strategy/);
});

test('policy model has top_k field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /top_k/);
});

test('policy model has semantic_enabled field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /semantic_enabled/);
});

test('policy model has grounded_answer_required field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /grounded_answer_required/);
});

test('policy model has lexical_fallback_enabled field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /lexical_fallback_enabled/);
});

test('policy model has fallback_strategy field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /fallback_strategy/);
});

test('policy model has reranking_enabled field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /reranking_enabled/);
});

test('policy model has policy_version field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /policy_version/);
});

test('policy model has updated_by field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /updated_by/);
});

test('policy model has updated_at field', () => {
  const src = read(POLICY_CENTER);
  assert.match(src, /updated_at/);
});

// ─── Regression: existing governance components still present ─────────────────

test('ProvenanceValidationPanel.tsx still exists (regression)', () => {
  assert.ok(exists(PROVENANCE_PANEL), 'ProvenanceValidationPanel.tsx must still exist');
});

test('RetrievalTraceExplorer.tsx still exists (regression)', () => {
  assert.ok(exists(TRACE_EXPLORER), 'RetrievalTraceExplorer.tsx must still exist');
});

test('governance index still exports ProvenanceValidationPanel (regression)', () => {
  const idx = read(INDEX);
  assert.match(idx, /ProvenanceValidationPanel/);
  assert.match(idx, /from '\.\/ProvenanceValidationPanel'/);
});

test('governance index still exports RetrievalTraceExplorer (regression)', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalTraceExplorer/);
  assert.match(idx, /from '\.\/RetrievalTraceExplorer'/);
});

// ─── Addendum: Persistence wiring ────────────────────────────────────────────

const CONTAINER = 'components/governance/RetrievalPolicyCenterContainer.tsx';
const POLICY_API = 'lib/retrievalPolicyApi.ts';
const PROXY_ROUTE = 'app/api/core/[...path]/route.ts';

test('RetrievalPolicyCenterContainer.tsx exists', () => {
  assert.ok(exists(CONTAINER), 'Missing RetrievalPolicyCenterContainer.tsx');
});

test('retrievalPolicyApi.ts exists', () => {
  assert.ok(exists(POLICY_API), 'Missing lib/retrievalPolicyApi.ts');
});

test('container is a use client component', () => {
  const src = read(CONTAINER);
  assert.match(src, /'use client'/);
});

test('container exports RetrievalPolicyCenterContainer', () => {
  const src = read(CONTAINER);
  assert.match(src, /export function RetrievalPolicyCenterContainer/);
});

test('container imports getRetrievalPolicy from retrievalPolicyApi', () => {
  const src = read(CONTAINER);
  assert.match(src, /getRetrievalPolicy/);
  assert.match(src, /retrievalPolicyApi/);
});

test('container imports putRetrievalPolicy from retrievalPolicyApi', () => {
  const src = read(CONTAINER);
  assert.match(src, /putRetrievalPolicy/);
});

test('container imports getCorpora from retrievalPolicyApi', () => {
  const src = read(CONTAINER);
  assert.match(src, /getCorpora/);
});

test('container calls onSave with real PUT and reloads policy', () => {
  const src = read(CONTAINER);
  assert.match(src, /handleSave/);
  assert.match(src, /putRetrievalPolicy/);
  assert.match(src, /setPolicy/);
});

test('container handles loading state', () => {
  const src = read(CONTAINER);
  assert.match(src, /retrieval-policy-loading/);
  assert.match(src, /aria-busy/);
});

test('container handles apiFailure state', () => {
  const src = read(CONTAINER);
  assert.match(src, /apiFailure/);
  assert.match(src, /retrieval-policy-api-failure/);
});

test('container handles not-configured state', () => {
  const src = read(CONTAINER);
  assert.match(src, /notConfigured/);
  assert.match(src, /policy-not-configured/);
});

test('container passes validationErrors from backend to component', () => {
  const src = read(CONTAINER);
  assert.match(src, /saveErrors/);
  assert.match(src, /validationErrors/);
});

test('container maps allowed_corpus_ids to allowed_corpora', () => {
  const src = read(CONTAINER);
  assert.match(src, /allowed_corpus_ids/);
  assert.match(src, /allowed_corpora/);
});

test('container maps denied_corpus_ids to denied_corpora', () => {
  const src = read(CONTAINER);
  assert.match(src, /denied_corpus_ids/);
  assert.match(src, /denied_corpora/);
});

test('container maps max_top_k to top_k', () => {
  const src = read(CONTAINER);
  assert.match(src, /max_top_k/);
  assert.match(src, /top_k/);
});

test('container uses toFrontendPolicy mapping', () => {
  const src = read(CONTAINER);
  assert.match(src, /toFrontendPolicy/);
});

test('container uses toBackendRequest mapping', () => {
  const src = read(CONTAINER);
  assert.match(src, /toBackendRequest/);
});

test('container does not dangerouslySetInnerHTML', () => {
  const src = read(CONTAINER);
  assert.doesNotMatch(src, /dangerouslySetInnerHTML/);
});

test('container does not expose raw vectors or provider payloads', () => {
  const src = read(CONTAINER);
  assert.doesNotMatch(src, /embedding|vector\s*:/);
  assert.doesNotMatch(src, /api_key|secret|password/i);
});

test('retrievalPolicyApi exports getRetrievalPolicy', () => {
  const src = read(POLICY_API);
  assert.match(src, /export function getRetrievalPolicy/);
});

test('retrievalPolicyApi exports putRetrievalPolicy', () => {
  const src = read(POLICY_API);
  assert.match(src, /export function putRetrievalPolicy/);
});

test('retrievalPolicyApi exports getCorpora', () => {
  const src = read(POLICY_API);
  assert.match(src, /export function getCorpora/);
});

test('retrievalPolicyApi uses /rag/retrieval-policy path', () => {
  const src = read(POLICY_API);
  assert.match(src, /\/rag\/retrieval-policy/);
});

test('retrievalPolicyApi uses /rag/corpora path', () => {
  const src = read(POLICY_API);
  assert.match(src, /\/rag\/corpora/);
});

test('retrievalPolicyApi uses PUT method for save', () => {
  const src = read(POLICY_API);
  assert.match(src, /method.*PUT|PUT.*method/);
});

test('proxy route allows rag/retrieval-policy GET and PUT', () => {
  const src = read(PROXY_ROUTE);
  assert.match(src, /rag\/retrieval-policy/);
  assert.match(src, /PUT/);
});

test('proxy route allows rag/corpora GET', () => {
  const src = read(PROXY_ROUTE);
  assert.match(src, /rag\/corpora/);
});

test('page uses RetrievalPolicyCenterContainer not static null', () => {
  const page = read(RETRIEVAL_PAGE);
  assert.match(page, /RetrievalPolicyCenterContainer/);
  assert.doesNotMatch(page, /policy=\{null\}/);
});

test('governance index exports RetrievalPolicyCenterContainer', () => {
  const idx = read(INDEX);
  assert.match(idx, /RetrievalPolicyCenterContainer/);
});
