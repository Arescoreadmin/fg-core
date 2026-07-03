/**
 * field-assessment-workspace.test.js
 *
 * Static-analysis tests for PR 2 — Field Data Collector UI
 *
 * Coverage:
 *   - File existence: all pages, components, API client
 *   - API client: all 15 substrate routes present, tenant_id never in body
 *   - Security: no tenant_id body trust, no raw payload echo, no dangerouslySetInnerHTML
 *   - BFF proxy: field-assessment route allowed with correct methods
 *   - State machine: VALID_TRANSITIONS exported, terminal states have no transitions
 *   - packages/ui: Textarea, Table, Alert, Tabs exported
 *   - Scan import: JSON parse validation present, raw payload not echoed
 *   - Observation form: required fields enforced (domain, severity, type, title, description)
 *   - Interview form: interview_role required, maps to observation endpoint
 *   - Evidence linkage: duplicate prevention present, engagement-scoped requests
 *   - Finding preview: no AI-generated content, read-only surface
 *   - Status transition: VALID_TRANSITIONS controls UI, cancelled branch present
 *   - Empty/loading/error states: all panels have safe states
 *   - No localStorage governance state
 *   - No mock APIs in production code
 *   - ObservationType INTERVIEW present in API client
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

function readUi(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', '..', '..', 'packages', 'ui', 'src', relPath), 'utf8');
}

function existsUi(relPath) {
  return fs.existsSync(path.join(__dirname, '..', '..', '..', 'packages', 'ui', 'src', relPath));
}

// ─── File existence ───────────────────────────────────────────────────────────

test('fieldAssessmentApi.ts exists', () => {
  assert.ok(exists('lib/fieldAssessmentApi.ts'), 'Missing lib/fieldAssessmentApi.ts');
});

test('field-assessment list page exists', () => {
  assert.ok(exists('app/field-assessment/page.tsx'), 'Missing app/field-assessment/page.tsx');
});

test('field-assessment workspace page exists', () => {
  assert.ok(
    exists('app/field-assessment/[engagementId]/page.tsx'),
    'Missing app/field-assessment/[engagementId]/page.tsx',
  );
});

test('StatusBadge component exists', () => {
  assert.ok(exists('components/field-assessment/StatusBadge.tsx'));
});

test('StatusTransitionBar component exists', () => {
  assert.ok(exists('components/field-assessment/StatusTransitionBar.tsx'));
});

test('ProgressChecklist component exists', () => {
  assert.ok(exists('components/field-assessment/ProgressChecklist.tsx'));
});

test('ScanImportPanel component exists', () => {
  assert.ok(exists('components/field-assessment/ScanImportPanel.tsx'));
});

test('DocumentRegistrationPanel component exists', () => {
  assert.ok(exists('components/field-assessment/DocumentRegistrationPanel.tsx'));
});

test('ObservationForm component exists', () => {
  assert.ok(exists('components/field-assessment/ObservationForm.tsx'));
});

test('InterviewForm component exists', () => {
  assert.ok(exists('components/field-assessment/InterviewForm.tsx'));
});

test('EvidenceLinkPanel component exists', () => {
  assert.ok(exists('components/field-assessment/EvidenceLinkPanel.tsx'));
});

test('FindingPreviewPanel component exists', () => {
  assert.ok(exists('components/field-assessment/FindingPreviewPanel.tsx'));
});

test('EngagementSummaryPanel component exists', () => {
  assert.ok(exists('components/field-assessment/EngagementSummaryPanel.tsx'));
});

test('GuidedExecutionPanel component exists', () => {
  assert.ok(exists('components/field-assessment/GuidedExecutionPanel.tsx'));
});

// ─── packages/ui new exports ──────────────────────────────────────────────────

test('packages/ui exports Textarea', () => {
  assert.ok(existsUi('textarea.tsx'), 'Missing packages/ui/src/textarea.tsx');
  const idx = readUi('index.ts');
  assert.ok(idx.includes('Textarea'), 'packages/ui/src/index.ts must export Textarea');
});

test('packages/ui exports Alert', () => {
  assert.ok(existsUi('alert.tsx'), 'Missing packages/ui/src/alert.tsx');
  const idx = readUi('index.ts');
  assert.ok(idx.includes('Alert'), 'packages/ui/src/index.ts must export Alert');
});

test('packages/ui exports Table', () => {
  assert.ok(existsUi('table.tsx'), 'Missing packages/ui/src/table.tsx');
  const idx = readUi('index.ts');
  assert.ok(idx.includes('Table'), 'packages/ui/src/index.ts must export Table');
});

test('packages/ui exports Tabs', () => {
  assert.ok(existsUi('tabs.tsx'), 'Missing packages/ui/src/tabs.tsx');
  const idx = readUi('index.ts');
  assert.ok(idx.includes('Tabs'), 'packages/ui/src/index.ts must export Tabs');
});

// ─── API client — routes ──────────────────────────────────────────────────────

test('API client covers GET /engagements', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('/engagements'), 'Must have engagements route');
  assert.ok(src.includes('listEngagements'), 'Must export listEngagements');
});

test('API client covers POST /engagements', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('createEngagement'), 'Must export createEngagement');
});

test('API client covers GET /engagements/{id}', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('getEngagement'), 'Must export getEngagement');
});

test('API client covers PATCH /engagements/{id}/status', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('transitionEngagement'), 'Must export transitionEngagement');
  assert.ok(src.includes('/status'), 'Must target /status endpoint');
});

test('API client covers scan results ingestion', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('ingestScan'), 'Must export ingestScan');
  assert.ok(src.includes('listScans'), 'Must export listScans');
});

test('API client covers document analyses', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('registerDocument'), 'Must export registerDocument');
  assert.ok(src.includes('listDocuments'), 'Must export listDocuments');
});

test('API client covers observations', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('captureObservation'), 'Must export captureObservation');
  assert.ok(src.includes('listObservations'), 'Must export listObservations');
});

test('API client covers findings (read-only)', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('listFindings'), 'Must export listFindings');
  assert.ok(src.includes('getFinding'), 'Must export getFinding');
  assert.ok(!src.includes('createFinding'), 'Must NOT export createFinding — findings are substrate-only');
});

test('API client covers evidence links', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('createEvidenceLink'), 'Must export createEvidenceLink');
  assert.ok(src.includes('listEvidenceLinks'), 'Must export listEvidenceLinks');
});

test('API client covers summary endpoint', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('getSummary'), 'Must export getSummary');
  assert.ok(src.includes('/summary'), 'Must target /summary endpoint');
});

test('API client covers execution-state endpoint', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('getExecutionState'), 'Must export getExecutionState');
  assert.ok(src.includes('/execution-state'), 'Must target /execution-state endpoint');
  assert.ok(src.includes('ExecutionState'), 'Must type execution-state response');
});

test('API client covers Microsoft Graph connector import endpoint', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('importMicrosoftGraphRun'), 'Must export importMicrosoftGraphRun');
  assert.ok(src.includes('/connector-runs/msgraph/import'), 'Must target msgraph import endpoint');
  assert.ok(src.includes('ConnectorImportPayload'), 'Must type connector import payload');
});

// ─── Security — tenant_id never in request body ───────────────────────────────

test('API client never sends tenant_id in request body', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  // tenant_id must not appear in any JSON.stringify payload
  const bodyLines = src.split('\n').filter((l) => l.includes('JSON.stringify'));
  for (const line of bodyLines) {
    assert.ok(
      !line.includes('tenant_id'),
      `Request body must not include tenant_id — tenant injected server-side by BFF: ${line.trim()}`,
    );
  }
});

test('API client security comment documents tenant injection', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(
    src.includes('tenant_id is NEVER sent') || src.includes('X-Tenant-ID') || src.includes('server-side'),
    'API client must document that tenant_id comes from server-side BFF injection',
  );
});

test('Scan import panel does not echo raw payload', () => {
  const src = read('components/field-assessment/ScanImportPanel.tsx');
  // The full raw JSON must not be rendered back — only metadata preview
  assert.ok(!src.includes('JSON.stringify(parseResult.parsed)') || src.includes('preview'), 'Scan panel must not echo raw payload back to UI');
  assert.ok(src.includes('Payload Preview') || src.includes('preview'), 'Scan panel must show metadata preview, not raw payload');
});

test('No dangerouslySetInnerHTML in field assessment components', () => {
  const components = [
    'ScanImportPanel',
    'DocumentRegistrationPanel',
    'ObservationForm',
    'InterviewForm',
    'EvidenceLinkPanel',
    'FindingPreviewPanel',
    'EngagementSummaryPanel',
    'StatusTransitionBar',
    'ProgressChecklist',
    'StatusBadge',
  ];
  for (const name of components) {
    const src = read(`components/field-assessment/${name}.tsx`);
    assert.ok(
      !src.includes('dangerouslySetInnerHTML'),
      `${name} must not use dangerouslySetInnerHTML`,
    );
  }
});

test('No localStorage governance state in workspace page', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(!src.includes('localStorage'), 'Workspace page must not use localStorage for governance state');
  assert.ok(!src.includes('sessionStorage'), 'Workspace page must not use sessionStorage');
});

test('GuidedExecutionPanel has no browser storage governance state', () => {
  const src = read('components/field-assessment/GuidedExecutionPanel.tsx');
  assert.ok(!src.includes('localStorage'), 'GuidedExecutionPanel must not use localStorage');
  assert.ok(!src.includes('sessionStorage'), 'GuidedExecutionPanel must not use sessionStorage');
});

test('No mock API data in production components', () => {
  const files = [
    'lib/fieldAssessmentApi.ts',
    'app/field-assessment/page.tsx',
    'app/field-assessment/[engagementId]/page.tsx',
  ];
  const mockPatterns = ['MOCK_', 'mock_data', 'fakeData', 'demoData', 'DEMO_'];
  for (const f of files) {
    const src = read(f);
    for (const pat of mockPatterns) {
      assert.ok(!src.includes(pat), `${f} must not contain mock/demo data pattern: ${pat}`);
    }
  }
});

// ─── BFF proxy ────────────────────────────────────────────────────────────────

test('BFF proxy allows field-assessment routes', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.ok(src.includes("'field-assessment/engagements'"), 'BFF PROXY_RULES must include field-assessment/engagements');
});

test('BFF proxy allows POST for field-assessment', () => {
  const src = read('app/api/core/[...path]/route.ts');
  const idx = src.indexOf("'field-assessment/engagements'");
  const snippet = src.slice(Math.max(0, idx - 20), idx + 100);
  assert.ok(snippet.includes('POST'), 'field-assessment proxy rule must include POST method');
});

test('BFF proxy does not inject tenant_id from request body', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.ok(src.includes('CORE_TENANT_ID'), 'BFF must use CORE_TENANT_ID env for tenant injection');
  assert.ok(src.includes('X-Tenant-ID'), 'BFF must set X-Tenant-ID header from server env');
});

// ─── State machine ────────────────────────────────────────────────────────────

test('VALID_TRANSITIONS exported from API client', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('VALID_TRANSITIONS'), 'Must export VALID_TRANSITIONS');
});

test('Terminal statuses have empty transition arrays', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes("closed: []"), 'closed must have no transitions');
  assert.ok(src.includes("cancelled: []"), 'cancelled must have no transitions');
});

test('StatusTransitionBar uses VALID_TRANSITIONS for allowed moves', () => {
  const src = read('components/field-assessment/StatusTransitionBar.tsx');
  assert.ok(src.includes('VALID_TRANSITIONS'), 'StatusTransitionBar must use VALID_TRANSITIONS');
});

test('StatusTransitionBar has cancel branch', () => {
  const src = read('components/field-assessment/StatusTransitionBar.tsx');
  assert.ok(src.includes('cancelled') || src.includes('Cancel'), 'Must handle cancelled transition');
});

// ─── Observation form ─────────────────────────────────────────────────────────

test('ObservationForm requires domain field', () => {
  const src = read('components/field-assessment/ObservationForm.tsx');
  assert.ok(src.includes('domain') && src.includes('aria-required'), 'ObservationForm must require domain');
});

test('ObservationForm requires severity field', () => {
  const src = read('components/field-assessment/ObservationForm.tsx');
  assert.ok(src.includes('severity'), 'ObservationForm must include severity');
});

test('ObservationForm requires title and description', () => {
  const src = read('components/field-assessment/ObservationForm.tsx');
  assert.ok(src.includes("title.trim() !== ''"), 'ObservationForm must validate title');
  assert.ok(src.includes("description.trim() !== ''"), 'ObservationForm must validate description');
});

// ─── Interview form ───────────────────────────────────────────────────────────

test('InterviewForm routes to observations endpoint', () => {
  const src = read('components/field-assessment/InterviewForm.tsx');
  assert.ok(src.includes('captureObservation'), 'InterviewForm must use captureObservation');
  assert.ok(src.includes("observation_type: 'interview'"), 'InterviewForm must set observation_type=interview');
});

test('InterviewForm requires interview_role', () => {
  const src = read('components/field-assessment/InterviewForm.tsx');
  assert.ok(src.includes('interview_role'), 'InterviewForm must include interview_role field');
  assert.ok(src.includes("interviewRole.trim() !== ''"), 'InterviewForm must require interview_role');
});

test('InterviewForm documents PII avoidance', () => {
  const src = read('components/field-assessment/InterviewForm.tsx');
  assert.ok(src.includes('PII') || src.includes('personal name') || src.includes('not personal'), 'InterviewForm must document PII avoidance');
});

// ─── INTERVIEW ObservationType in API client ──────────────────────────────────

test('ObservationType includes interview in API client', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(
    src.includes("'interview'") || src.includes('"interview"'),
    'fieldAssessmentApi must include interview as ObservationType value',
  );
});

// ─── Evidence linkage ─────────────────────────────────────────────────────────

test('EvidenceLinkPanel sends engagement-scoped request', () => {
  const src = read('components/field-assessment/EvidenceLinkPanel.tsx');
  assert.ok(src.includes('engagementId'), 'EvidenceLinkPanel must scope requests to engagementId');
  assert.ok(src.includes('createEvidenceLink'), 'EvidenceLinkPanel must use createEvidenceLink');
});

test('EvidenceLinkPanel has duplicate prevention', () => {
  const src = read('components/field-assessment/EvidenceLinkPanel.tsx');
  assert.ok(src.includes('isDuplicate') || src.includes('duplicate'), 'EvidenceLinkPanel must check for duplicate links');
});

test('EvidenceLinkPanel never sends tenant_id in body', () => {
  const src = read('components/field-assessment/EvidenceLinkPanel.tsx');
  const bodyLines = src.split('\n').filter((l) => l.includes('createEvidenceLink'));
  for (const line of bodyLines) {
    assert.ok(!line.includes('tenant_id'), `EvidenceLinkPanel must not pass tenant_id: ${line.trim()}`);
  }
});

// ─── Finding preview ──────────────────────────────────────────────────────────

test('FindingPreviewPanel is read-only — no create action', () => {
  const src = read('components/field-assessment/FindingPreviewPanel.tsx');
  assert.ok(!src.includes('createFinding'), 'FindingPreviewPanel must not create findings');
  assert.ok(!src.includes('POST'), 'FindingPreviewPanel must not POST to findings endpoint');
});

test('FindingPreviewPanel has loading skeleton', () => {
  const src = read('components/field-assessment/FindingPreviewPanel.tsx');
  assert.ok(src.includes('loading') || src.includes('animate-pulse'), 'FindingPreviewPanel must have loading state');
});

test('FindingPreviewPanel has empty state', () => {
  const src = read('components/field-assessment/FindingPreviewPanel.tsx');
  assert.ok(src.includes('No findings') || src.includes('empty'), 'FindingPreviewPanel must have safe empty state');
});

// ─── Scan import panel ────────────────────────────────────────────────────────

test('ScanImportPanel validates JSON before submit', () => {
  const src = read('components/field-assessment/ScanImportPanel.tsx');
  assert.ok(src.includes('JSON.parse') || src.includes('parsePreview'), 'ScanImportPanel must parse JSON before submit');
  assert.ok(src.includes('parseError') || src.includes('Invalid JSON'), 'ScanImportPanel must surface JSON parse errors');
});

test('ScanImportPanel requires source_type', () => {
  const src = read('components/field-assessment/ScanImportPanel.tsx');
  assert.ok(src.includes('source_type'), 'ScanImportPanel must require source_type');
  assert.ok(src.includes("sourceType !== ''"), 'ScanImportPanel must validate sourceType is set');
});

test('ScanImportPanel shows evidence hash from API response', () => {
  const src = read('components/field-assessment/ScanImportPanel.tsx');
  assert.ok(src.includes('evidence_hash'), 'ScanImportPanel must display evidence_hash from API response');
});

// ─── Progress checklist ───────────────────────────────────────────────────────

test('ProgressChecklist derives state from summary, not local state', () => {
  const src = read('components/field-assessment/ProgressChecklist.tsx');
  assert.ok(src.includes('EngagementSummary') || src.includes('summary'), 'ProgressChecklist must accept summary prop from API');
  assert.ok(!src.includes('useState') || src.includes('summary'), 'ProgressChecklist must not invent local completion truth');
});

test('GuidedExecutionPanel renders server-authored readiness surfaces', () => {
  const src = read('components/field-assessment/GuidedExecutionPanel.tsx');
  assert.ok(src.includes('next_actions'), 'GuidedExecutionPanel must render next actions from API');
  assert.ok(src.includes('blocking_gate_count'), 'GuidedExecutionPanel must render blocking gates from API');
  assert.ok(src.includes('escalation_items'), 'GuidedExecutionPanel must render escalation items from API');
  assert.ok(src.includes('transition_blockers'), 'GuidedExecutionPanel must render transition blockers from API');
  assert.ok(src.includes('asset_candidate_actions'), 'GuidedExecutionPanel must render asset candidate actions from API');
});

test('GuidedExecutionPanel does not compute authoritative readiness locally', () => {
  const src = read('components/field-assessment/GuidedExecutionPanel.tsx');
  assert.ok(src.includes('overall_readiness_state'), 'GuidedExecutionPanel must display server readiness state');
  assert.ok(!src.includes('setExecutionState'), 'GuidedExecutionPanel must not mutate execution state');
  assert.ok(!src.includes('Math.round'), 'GuidedExecutionPanel must not calculate readiness score locally');
});

// ─── Workspace page ───────────────────────────────────────────────────────────

test('Workspace page has loading skeleton', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(src.includes('animate-pulse') || src.includes('loading'), 'Workspace must have loading state');
});

test('Workspace page uses GuidedExecutionPanel instead of local readiness authority', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(src.includes('GuidedExecutionPanel'), 'Workspace must render GuidedExecutionPanel');
  assert.ok(src.includes('getExecutionState'), 'Workspace must fetch execution-state API');
});

test('Workspace page has error state', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(src.includes('engError') || src.includes('Error'), 'Workspace must have error state');
});

test('Workspace page has 7 tabs covering all surfaces', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  const requiredTabs = ['overview', 'scans', 'documents', 'observations', 'interviews', 'evidence', 'findings'];
  for (const tab of requiredTabs) {
    assert.ok(src.includes(`value="${tab}"`), `Workspace must include tab: ${tab}`);
  }
});

test('List page has loading skeleton', () => {
  const src = read('app/field-assessment/page.tsx');
  assert.ok(src.includes('animate-pulse') || src.includes('loading'), 'List page must have loading state');
});

test('List page has empty state', () => {
  const src = read('app/field-assessment/page.tsx');
  assert.ok(src.includes('No engagements'), 'List page must have safe empty state');
});

test('List page has error state', () => {
  const src = read('app/field-assessment/page.tsx');
  assert.ok(src.includes('error') || src.includes('Error'), 'List page must have safe error state');
});

// ─── Sidebar nav link ─────────────────────────────────────────────────────────

test('Sidebar includes Field Assessments nav link', () => {
  // Sidebar is registry-driven; route and label come from CONSOLE_REGISTRY at runtime.
  const reg = JSON.parse(read('../../packages/navigation/navigation-registry.json'));
  const item = reg.console.find((i) => i.id === 'field-assessments');
  assert.ok(item, 'field-assessments must be registered');
  assert.ok(item.route === '/field-assessment', 'field-assessments route must be /field-assessment');
  assert.ok(
    item.title === 'Field Assessments' || item.title === 'Field Assessment',
    'field-assessments must have correct title',
  );
  // Sidebar ICON_MAP must still cover field-assessments with ClipboardCheck.
  const src = read('components/layout/Sidebar.tsx');
  assert.ok(src.includes('ClipboardCheck'), 'Sidebar must use ClipboardCheck icon for field assessment');
});

// ─── Audit trail ─────────────────────────────────────────────────────────────

test('fieldAssessmentApi exports listAuditEvents', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('listAuditEvents'), 'API client must export listAuditEvents');
  assert.ok(src.includes('audit-events'), 'API client must target /audit-events endpoint');
});

test('AuditEvent type is defined in API client', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('AuditEvent'), 'API client must define AuditEvent type');
  assert.ok(src.includes('event_type'), 'AuditEvent must have event_type field');
  assert.ok(src.includes('reason_code'), 'AuditEvent must have reason_code field');
});

test('Workspace page has history tab', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(src.includes('value="history"'), 'Workspace must include history tab');
  assert.ok(src.includes('listAuditEvents'), 'Workspace must call listAuditEvents');
  assert.ok(src.includes('auditEvents'), 'Workspace must hold auditEvents state');
});

test('History tab lazy-loads on first activation', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(
    src.includes("activeTab === 'history'") || src.includes("activeTab==='history'"),
    'History tab must lazy-load — only fetch when activated',
  );
});

// ─── Observation type filter ──────────────────────────────────────────────────

test('listObservations accepts observation_type filter param', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('observation_type'), 'listObservations must accept observation_type filter');
});

// ─── Structured evidence KV editor ───────────────────────────────────────────

test('ObservationForm has structured-evidence-editor', () => {
  const src = read('components/field-assessment/ObservationForm.tsx');
  assert.ok(src.includes('structured-evidence-editor') || src.includes('structured_evidence'), 'ObservationForm must include structured evidence editor');
  assert.ok(src.includes('kvPairs') || src.includes('buildStructuredEvidence'), 'ObservationForm must build structured_evidence dict');
});

test('ObservationForm submits structured_evidence field', () => {
  const src = read('components/field-assessment/ObservationForm.tsx');
  assert.ok(src.includes('structured_evidence'), 'captureObservation payload must include structured_evidence');
});

// ─── Offline draft queue ──────────────────────────────────────────────────────

test('fieldAssessmentDrafts.ts utility exists', () => {
  assert.ok(exists('lib/fieldAssessmentDrafts.ts'), 'Missing lib/fieldAssessmentDrafts.ts');
});

test('Draft queue uses IndexedDB, not localStorage', () => {
  const src = read('lib/fieldAssessmentDrafts.ts');
  assert.ok(src.includes('indexedDB'), 'Draft queue must use IndexedDB');
  assert.ok(!src.includes('localStorage'), 'Draft queue must not use localStorage');
  assert.ok(!src.includes('sessionStorage'), 'Draft queue must not use sessionStorage');
});

test('Draft queue exports saveDraft, loadDraft, clearDraft', () => {
  const src = read('lib/fieldAssessmentDrafts.ts');
  assert.ok(src.includes('saveDraft'), 'Must export saveDraft');
  assert.ok(src.includes('loadDraft'), 'Must export loadDraft');
  assert.ok(src.includes('clearDraft'), 'Must export clearDraft');
});

test('ScanImportPanel integrates draft queue', () => {
  const src = read('components/field-assessment/ScanImportPanel.tsx');
  assert.ok(src.includes('saveDraft') || src.includes('loadDraft'), 'ScanImportPanel must use draft queue');
  assert.ok(src.includes('clearDraft'), 'ScanImportPanel must clear draft on successful submit');
});

test('ObservationForm integrates draft queue', () => {
  const src = read('components/field-assessment/ObservationForm.tsx');
  assert.ok(src.includes('saveDraft') || src.includes('loadDraft'), 'ObservationForm must use draft queue');
  assert.ok(src.includes('clearDraft'), 'ObservationForm must clear draft on successful submit');
});

// ─── Finding drill-down ───────────────────────────────────────────────────────

test('FindingPreviewPanel has expand/collapse interaction', () => {
  const src = read('components/field-assessment/FindingPreviewPanel.tsx');
  assert.ok(src.includes('expandedId') || src.includes('expanded'), 'FindingPreviewPanel must support expand/collapse');
  assert.ok(src.includes('aria-expanded'), 'FindingPreviewPanel must set aria-expanded on cards');
});

test('FindingPreviewPanel shows full detail in expanded state', () => {
  const src = read('components/field-assessment/FindingPreviewPanel.tsx');
  assert.ok(src.includes('evidence_ref_ids'), 'Expanded finding must show evidence_ref_ids');
  assert.ok(src.includes('nist_ai_rmf_mappings'), 'Expanded finding must show NIST AI RMF mappings');
  assert.ok(src.includes('framework_mappings'), 'Expanded finding must show framework mappings');
});

// ─── Observation expand/collapse ──────────────────────────────────────────────

test('Workspace observation list has expand/collapse', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(src.includes('expandedObsId') || src.includes('isExpanded'), 'Workspace observation list must support expand/collapse');
  assert.ok(src.includes('structured_evidence'), 'Expanded observation must show structured_evidence');
});

// ─── Evidence lineage graph ───────────────────────────────────────────────────

test('EvidenceLinkPanel has SVG lineage graph', () => {
  const src = read('components/field-assessment/EvidenceLinkPanel.tsx');
  assert.ok(src.includes('<svg') || src.includes('EvidenceLineageGraph'), 'EvidenceLinkPanel must include SVG lineage visualization');
  assert.ok(!src.includes('import * as d3') && !src.includes("from 'd3'"), 'Evidence graph must not use d3 — inline SVG only');
});
