/**
 * ai-workspace.test.js
 *
 * Static-analysis tests for the PR 45 AI Workspace (Governed Chat UX):
 *   - 3-column layout (conversation | metadata | evidence)
 *   - Provider/model, confidence, provenance, context count, source refs
 *   - Safe markdown (no dangerouslySetInnerHTML, no raw HTML injection)
 *   - No fake citations, no fake confidence, no raw vectors
 *   - Copy/export controls exist and exclude secrets
 *   - Retry/regenerate controls are deterministic
 *   - BFF route preserved (/api/core/ui/ai/chat)
 *   - Accessibility basics
 *   - Deterministic loading state (counter IDs, no Math.random)
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

const PAGE = 'app/dashboard/assistant/page.tsx';
const EVIDENCE_PANEL = 'components/governance/SourceEvidencePanel.tsx';

// ─── Layout ───────────────────────────────────────────────────────────────────

test('ai workspace renders governed chat layout', () => {
  const page = read(PAGE);
  assert.match(page, /ai-workspace/);
  assert.match(page, /AI Workspace/);
  assert.match(page, /TopBar/);
});

test('ai workspace includes conversation metadata and evidence columns', () => {
  const page = read(PAGE);
  assert.match(page, /conversation-panel/);
  assert.match(page, /metadata-column/);
  assert.match(page, /evidence-column/);
  assert.match(page, /answer-metadata-panel/);
  // Evidence panel is now the SourceEvidencePanel component
  assert.match(page, /SourceEvidencePanel/);
  const panel = read(EVIDENCE_PANEL);
  assert.match(panel, /source-evidence-panel/);
});

test('ai workspace has 3-column responsive structure', () => {
  const page = read(PAGE);
  // Desktop 3-col achieved via lg: responsive classes
  assert.match(page, /lg:flex-row/);
  assert.match(page, /lg:w-72/);
  assert.match(page, /lg:w-64/);
});

// ─── Panels ───────────────────────────────────────────────────────────────────

test('ai workspace conversation panel renders', () => {
  const page = read(PAGE);
  assert.match(page, /conversation-panel/);
  assert.match(page, /conversation-empty/);
  assert.match(page, /user-message/);
  assert.match(page, /assistant-message/);
  assert.match(page, /assistant-thinking/);
});

test('ai workspace answer metadata panel renders', () => {
  const page = read(PAGE);
  assert.match(page, /answer-metadata-panel/);
  assert.match(page, /metadata-empty/);
  // Must contain all required metadata fields
  assert.match(page, /Provider/);
  assert.match(page, /Confidence/);
  assert.match(page, /Provenance/);
  assert.match(page, /Context/);
});

test('ai workspace evidence source panel renders', () => {
  const page = read(PAGE);
  // Page uses SourceEvidencePanel component for the right column
  assert.match(page, /SourceEvidencePanel/);
  assert.match(page, /Evidence.*Sources/s);
  // Panel component carries the evidence content
  const panel = read(EVIDENCE_PANEL);
  assert.match(panel, /source-evidence-panel/);
  assert.match(panel, /evidence-empty/);
  assert.match(panel, /no-source-state/);
});

// ─── Provider / model ─────────────────────────────────────────────────────────

test('ai workspace renders provider unavailable state', () => {
  const page = read(PAGE);
  assert.match(page, /provider-unavailable/);
  assert.match(page, /Provider not reported/);
  assert.match(page, /ProviderRouteCard/);
});

// ─── Confidence ───────────────────────────────────────────────────────────────

test('ai workspace renders confidence bounded safe state', () => {
  const page = read(PAGE);
  assert.match(page, /confidence-unavailable/);
  assert.match(page, /Not measured/);
  assert.match(page, /ConfidenceMeter/);
  // Must not hardcode a fake confidence value
  assert.doesNotMatch(page, /confidence=\{0\.9[0-9]\}/);
  assert.doesNotMatch(page, /confidence=\{95\}/);
});

// ─── Provenance status ────────────────────────────────────────────────────────

test('ai workspace renders provenance status', () => {
  const page = read(PAGE);
  assert.match(page, /ProvenanceStatusBadge/);
  assert.match(page, /provenance-status-indicator/);
  assert.match(page, /PROVENANCE_VALID/);
  assert.match(page, /PROVENANCE_NO_CONTEXT_AVAILABLE/);
  assert.match(page, /PROVENANCE_SOURCE_NOT_RETRIEVED/);
  assert.match(page, /PROVENANCE_SOURCE_NOT_IN_PROMPT/);
});

test('ai workspace renders provenance invalid/warning state', () => {
  const page = read(PAGE);
  assert.match(page, /Provenance validation did not pass/);
  // Must not silently hide provenance failure
  assert.doesNotMatch(page, /provenance.*ok.*hide/i);
});

// ─── Context count ────────────────────────────────────────────────────────────

test('ai workspace renders context count', () => {
  const page = read(PAGE);
  assert.match(page, /context-count-display/);
  assert.match(page, /chunk.*used/);
});

test('ai workspace renders no-context state explicitly', () => {
  const page = read(PAGE);
  assert.match(page, /no-context-state/);
  assert.match(page, /No context available/);
  assert.match(page, /Answer generated without retrieval context/);
});

// ─── Source references ────────────────────────────────────────────────────────

test('ai workspace renders source references from safe payload', () => {
  // Source evidence panel renders all source reference patterns
  const panel = read(EVIDENCE_PANEL);
  assert.match(panel, /source-card/);
  assert.match(panel, /chunk-ids-section/);
  assert.match(panel, /chunk-reference/);
  assert.match(panel, /citations-section/);
  assert.match(panel, /citation-item/);
  // Page passes provenance data to the panel
  const page = read(PAGE);
  assert.match(page, /provenance.*provenance/s);
});

test('ai workspace renders why-this-chunk explanations', () => {
  // Why-this-chunk is rendered in SourceEvidencePanel
  const panel = read(EVIDENCE_PANEL);
  assert.match(panel, /why-this-chunk-section/);
  assert.match(panel, /Why Retrieved/);
  assert.match(panel, /rank_reason/);
  assert.match(panel, /rank-reason/);
});

// ─── Missing fields ───────────────────────────────────────────────────────────

test('ai workspace renders deterministic unavailable states for missing fields', () => {
  const page = read(PAGE);
  // Metadata panel empty states remain in page.tsx
  assert.match(page, /metadata-empty/);
  assert.match(page, /provider-unavailable/);
  assert.match(page, /confidence-unavailable/);
  // Evidence panel empty states live in SourceEvidencePanel
  const panel = read(EVIDENCE_PANEL);
  assert.match(panel, /evidence-empty/);
  assert.match(panel, /no-source-state/);
});

// ─── API failure ──────────────────────────────────────────────────────────────

test('ai workspace renders safe error state on API failure', () => {
  const page = read(PAGE);
  assert.match(page, /error-banner/);
  assert.match(page, /aria-live="assertive"/);
  assert.match(page, /Network error/);
  assert.match(page, /Request failed/);
});

// ─── Loading state ────────────────────────────────────────────────────────────

test('ai workspace renders loading state deterministically', () => {
  const page = read(PAGE);
  assert.match(page, /assistant-thinking/);
  assert.match(page, /Generating response/);
  assert.match(page, /animate-pulse/);
  assert.match(page, /aria-live="polite"/);
  // Must not use Math.random for IDs
  assert.doesNotMatch(page, /Math\.random/);
  // Message IDs must be counter-based (msg-N)
  assert.match(page, /msg-\$\{msgIdRef\.current\}/);
});

// ─── Retry / regenerate ───────────────────────────────────────────────────────

test('ai workspace retry controls are deterministic', () => {
  const page = read(PAGE);
  assert.match(page, /handleRetry/);
  assert.match(page, /Retry last message/);
  // Retry must be disabled when loading
  assert.match(page, /!lastUserMessage \|\| loading/);
  // Must not add autonomous loops or background automation
  assert.doesNotMatch(page, /setInterval.*retry/);
  assert.doesNotMatch(page, /while.*retry/i);
});

// ─── Copy / export ────────────────────────────────────────────────────────────

test('ai workspace copy export controls exist', () => {
  const page = read(PAGE);
  assert.match(page, /handleCopyAnswer/);
  assert.match(page, /handleExport/);
  assert.match(page, /Copy answer text/);
  assert.match(page, /Export response metadata/);
  assert.match(page, /copyToClipboard/);
  assert.match(page, /buildExportPayload/);
});

test('ai workspace copy export excludes secrets', () => {
  const page = read(PAGE);
  // buildExportPayload must not include session_id in its return object
  // Extract just the buildExportPayload function body to check
  const exportFn = page.match(/function buildExportPayload[\s\S]+?^\}/m)?.[0] ?? '';
  assert.doesNotMatch(exportFn, /session_id/);
  // Must not export raw vectors
  assert.doesNotMatch(page, /raw_vector.*export/i);
  // why_this_chunk must not appear inside buildExportPayload's return object
  assert.doesNotMatch(page, /why_this_chunk:.*null.*\}/s);
  // Clipboard API must be guarded for SSR safety
  assert.match(page, /typeof navigator/);
  assert.match(page, /navigator\.clipboard/);
});

test('ai workspace export payload documents safe subset', () => {
  const page = read(PAGE);
  // Export must include safe governance fields
  assert.match(page, /provenance_status.*export/s);
  assert.match(page, /source_chunk_ids.*export/s);
  // Must not include phi_types as a key in buildExportPayload's return object
  assert.doesNotMatch(page, /phi_types: /);
});

// ─── Safe markdown ────────────────────────────────────────────────────────────

test('ai workspace does not use dangerouslySetInnerHTML', () => {
  const page = read(PAGE);
  // Must not use innerHTML injection pattern
  assert.doesNotMatch(page, /dangerously\s*Set\s*Inner\s*HTML/i);
  // AnswerText uses plain text rendering (whitespace-pre-wrap)
  assert.match(page, /whitespace-pre-wrap/);
});

test('ai workspace escapes unsafe markdown', () => {
  const page = read(PAGE);
  // AnswerText must render content as text node, not HTML
  assert.match(page, /AnswerText/);
  assert.match(page, /whitespace-pre-wrap/);
  // Must not use innerHTML or insertAdjacentHTML
  assert.doesNotMatch(page, /innerHTML\s*=/);
  assert.doesNotMatch(page, /insertAdjacentHTML/);
  // Must not use eval or Function constructor on answer content
  assert.doesNotMatch(page, /eval\s*\(/);
  // Must not use iframe, object, embed tags
  assert.doesNotMatch(page, /<iframe/i);
  assert.doesNotMatch(page, /<object/i);
  assert.doesNotMatch(page, /<embed/i);
});

test('ai workspace answer text renders as plain text not HTML', () => {
  const page = read(PAGE);
  // AnswerText wraps content in <p> with text children — safe by construction
  assert.match(page, /function AnswerText/);
  assert.match(page, /answer-text/);
  // Must use plain text rendering pattern
  assert.match(page, /whitespace-pre-wrap/);
  // Must not use innerHTML
  assert.doesNotMatch(page, /innerHTML\s*=/);
});

// ─── No fake data ─────────────────────────────────────────────────────────────

test('ai workspace does not render fake sources', () => {
  const page = read(PAGE);
  // No hardcoded fake citations or source names in page
  assert.doesNotMatch(page, /Apex National Bank/);
  assert.doesNotMatch(page, /meridian-health/);
  assert.doesNotMatch(page, /source-1.*fake/i);
  // Sources only rendered when API provides them — check in SourceEvidencePanel
  const panel = read(EVIDENCE_PANEL);
  assert.match(panel, /citations.*length/);
});

test('ai workspace does not expose raw vectors', () => {
  const page = read(PAGE);
  assert.doesNotMatch(page, /raw_vector/i);
  assert.doesNotMatch(page, /embedding_vector/i);
  assert.doesNotMatch(page, /\bvector\b.*render/i);
});

test('ai workspace does not expose raw prompts or provider payloads', () => {
  const page = read(PAGE);
  assert.doesNotMatch(page, /raw_prompt/i);
  assert.doesNotMatch(page, /provider_payload/i);
  assert.doesNotMatch(page, /system_prompt/i);
});

// ─── BFF boundary ─────────────────────────────────────────────────────────────

test('ai workspace preserves BFF route usage', () => {
  const page = read(PAGE);
  assert.match(page, /\/api\/core\/ui\/ai\/chat/);
  assert.doesNotMatch(page, /NEXT_PUBLIC_CORE_API_KEY/);
  assert.doesNotMatch(page, /NEXT_PUBLIC_CORE_API_URL/);
  // Must NOT call core directly
  assert.doesNotMatch(page, /fetch\(['"]http/);
});

// ─── Accessibility ────────────────────────────────────────────────────────────

test('ai workspace has accessibility basics', () => {
  const page = read(PAGE);
  // Labelled input
  assert.match(page, /htmlFor="workspace-input"/);
  assert.match(page, /id="workspace-input"/);
  // Labelled buttons
  assert.match(page, /aria-label="Send message"/);
  assert.match(page, /aria-label="Retry last message"/);
  assert.match(page, /aria-label="Copy answer text"/);
  assert.match(page, /aria-label="Export response metadata"/);
  // Semantic headings for panels
  assert.match(page, /<h2/);
  assert.match(page, /<h3/);
  // Icons marked aria-hidden
  assert.match(page, /aria-hidden="true"/);
});

// ─── Determinism ──────────────────────────────────────────────────────────────

test('ai workspace does not use nondeterministic render IDs', () => {
  const page = read(PAGE);
  // No Math.random
  assert.doesNotMatch(page, /Math\.random/);
  // Message IDs use counter
  assert.match(page, /msgIdRef/);
  assert.match(page, /nextId/);
  // No unbounded polling in workspace
  assert.doesNotMatch(page, /setInterval.*sendPrompt/);
});

// ─── Existing navigation ──────────────────────────────────────────────────────

test('dashboard assistant route still exists at expected path', () => {
  assert.ok(exists('app/dashboard/assistant/page.tsx'), 'assistant page must exist');
});

test('existing shell navigation tests still pass (smoke check)', () => {
  // Verify that the sidebar still has the AI Workspace link (not removed/renamed)
  const sidebar = read('components/layout/Sidebar.tsx');
  assert.match(sidebar, /AI Workspace/);
  assert.match(sidebar, /\/dashboard\/assistant/);
});
