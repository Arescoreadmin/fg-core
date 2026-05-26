/**
 * report-ui.test.js
 *
 * Static-analysis tests for PR 19 — Report UI + Engagement Detail Reports Tab.
 *
 * Coverage:
 *   - File existence: all 5 new components
 *   - API client: report methods, types, no tenant_id in bodies
 *   - Reports tab present in workspace page
 *   - Report type selector: all 4 valid types
 *   - Generate button: calls generateReport, disables during submission
 *   - Version history: renders list, handles empty/error states
 *   - Viewer: safe rendering, no dangerouslySetInnerHTML
 *   - Export: JSON/PDF call exportReport with correct format
 *   - Verify: calls verifyReport, shows verified/failed badge
 *   - ControlGapMatrix: covered/gap states, accessible table
 *   - Security: no raw report JSON in logs, no raw error body
 *   - No localStorage/sessionStorage for report state
 *   - Polling: bounded, cleans up on unmount
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

// ─── File existence ───────────────────────────────────────────────────────────

test('ReportGenerationPanel component exists', () => {
  assert.ok(exists('components/field-assessment/ReportGenerationPanel.tsx'));
});

test('ReportVersionHistory component exists', () => {
  assert.ok(exists('components/field-assessment/ReportVersionHistory.tsx'));
});

test('ReportViewer component exists', () => {
  assert.ok(exists('components/field-assessment/ReportViewer.tsx'));
});

test('ReportExportBar component exists', () => {
  assert.ok(exists('components/field-assessment/ReportExportBar.tsx'));
});

test('ControlGapMatrix component exists', () => {
  assert.ok(exists('components/field-assessment/ControlGapMatrix.tsx'));
});

// ─── API client — report methods ──────────────────────────────────────────────

test('API client exports generateReport', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('generateReport'), 'Must export generateReport');
  assert.ok(src.includes("method: 'POST'"), 'generateReport must use POST');
  assert.ok(src.includes('/reports'), 'Must target /reports endpoint');
});

test('API client exports listReports', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('listReports'), 'Must export listReports');
});

test('API client exports getReport', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('getReport'), 'Must export getReport');
});

test('API client exports exportReport', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('exportReport'), 'Must export exportReport');
  assert.ok(src.includes('requestBlob'), 'exportReport must use requestBlob for binary download');
  assert.ok(src.includes('/export'), 'Must target /export endpoint');
});

test('API client exports verifyReport', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('verifyReport'), 'Must export verifyReport');
  assert.ok(src.includes('/verify'), 'Must target /verify endpoint');
});

test('API client exports ReportDocument type', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('ReportDocument'), 'Must export ReportDocument interface');
  assert.ok(src.includes('manifest_hash'), 'ReportDocument must include manifest_hash');
  assert.ok(src.includes('section_hashes'), 'ReportDocument must include section_hashes');
});

test('API client exports ReportVersionList type', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('ReportVersionList'), 'Must export ReportVersionList');
  assert.ok(src.includes('ReportVersionSummary'), 'Must export ReportVersionSummary');
});

test('API client exports ReportVerifyResult type', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  assert.ok(src.includes('ReportVerifyResult'), 'Must export ReportVerifyResult');
  assert.ok(src.includes('valid: boolean'), 'ReportVerifyResult must have valid field');
});

test('generateReport does not include tenant_id in request body', () => {
  const src = read('lib/fieldAssessmentApi.ts');
  const bodyLines = src.split('\n').filter((l) => l.includes('JSON.stringify'));
  for (const line of bodyLines) {
    assert.ok(
      !line.includes('tenant_id'),
      `Request body must not include tenant_id: ${line.trim()}`,
    );
  }
});

// ─── Reports tab — workspace page ─────────────────────────────────────────────

test('Reports tab trigger present in workspace page', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(src.includes('"reports"'), 'Must have reports tab trigger value');
  assert.ok(src.includes('Reports'), 'Must render Reports label');
});

test('Workspace page imports all report components', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(src.includes('ReportGenerationPanel'), 'Must import ReportGenerationPanel');
  assert.ok(src.includes('ReportVersionHistory'), 'Must import ReportVersionHistory');
  assert.ok(src.includes('ReportViewer'), 'Must import ReportViewer');
  assert.ok(src.includes('ReportExportBar'), 'Must import ReportExportBar');
  assert.ok(src.includes('ControlGapMatrix'), 'Must import ControlGapMatrix');
});

test('Workspace page does not use localStorage for report state', () => {
  const src = read('app/field-assessment/[engagementId]/page.tsx');
  assert.ok(!src.includes('localStorage'), 'Must not use localStorage');
  assert.ok(!src.includes('sessionStorage'), 'Must not use sessionStorage');
});

// ─── ReportGenerationPanel ────────────────────────────────────────────────────

test('Report type selector renders all 4 valid types', () => {
  const src = read('components/field-assessment/ReportGenerationPanel.tsx');
  assert.ok(src.includes('full_assessment'), 'Must include full_assessment');
  assert.ok(src.includes('executive_summary'), 'Must include executive_summary');
  assert.ok(src.includes('findings_register'), 'Must include findings_register');
  assert.ok(src.includes('control_gap'), 'Must include control_gap');
});

test('Generate button calls generateReport', () => {
  const src = read('components/field-assessment/ReportGenerationPanel.tsx');
  assert.ok(src.includes('generateReport'), 'Must call generateReport');
  assert.ok(src.includes('handleGenerate'), 'Must have handleGenerate handler');
});

test('Generate button disabled while submitting', () => {
  const src = read('components/field-assessment/ReportGenerationPanel.tsx');
  assert.ok(src.includes('disabled={submitting}'), 'Generate button must be disabled while submitting');
  assert.ok(src.includes('aria-busy'), 'Must set aria-busy during submission');
});

test('ReportGenerationPanel polling is bounded', () => {
  const src = read('components/field-assessment/ReportGenerationPanel.tsx');
  assert.ok(
    src.includes('MAX_POLL') || src.includes('MAX_ATTEMPTS') || src.includes('maxAttempts') || src.includes('attempts <'),
    'Polling must be bounded — no infinite loops',
  );
  assert.ok(src.includes('mountedRef') || src.includes('mounted'), 'Must guard against unmounted state updates');
});

test('ReportGenerationPanel does not print report JSON to console', () => {
  const src = read('components/field-assessment/ReportGenerationPanel.tsx');
  assert.ok(!src.includes('console.log'), 'Must not console.log report data');
});

// ─── ReportVersionHistory ─────────────────────────────────────────────────────

test('Version history renders versions from listReports', () => {
  const src = read('components/field-assessment/ReportVersionHistory.tsx');
  assert.ok(src.includes('listReports'), 'Must call listReports');
  assert.ok(src.includes('compiled_at') || src.includes('compiled_by'), 'Must display version metadata');
});

test('Version history has empty state', () => {
  const src = read('components/field-assessment/ReportVersionHistory.tsx');
  assert.ok(src.includes('No reports yet') || src.includes('no reports'), 'Must handle empty state');
});

test('Version history has loading state', () => {
  const src = read('components/field-assessment/ReportVersionHistory.tsx');
  assert.ok(src.includes('animate-pulse') || src.includes('loading'), 'Must show loading state');
  assert.ok(src.includes('aria-busy'), 'Must set aria-busy during loading');
});

test('Version history has error state', () => {
  const src = read('components/field-assessment/ReportVersionHistory.tsx');
  assert.ok(src.includes('AlertDescription') || src.includes('error'), 'Must show error state');
});

test('Clicking version row fires onSelectVersion', () => {
  const src = read('components/field-assessment/ReportVersionHistory.tsx');
  assert.ok(src.includes('onSelectVersion'), 'Must call onSelectVersion on row click');
  assert.ok(src.includes("role=\"button\""), 'Version rows must have role=button');
});

test('Version history shows status badges', () => {
  const src = read('components/field-assessment/ReportVersionHistory.tsx');
  assert.ok(src.includes('finalized') || src.includes('STATUS_LABEL'), 'Must render status badges');
});

// ─── ReportViewer ─────────────────────────────────────────────────────────────

test('ReportViewer does not use dangerouslySetInnerHTML', () => {
  const src = read('components/field-assessment/ReportViewer.tsx');
  assert.ok(!src.includes('dangerouslySetInnerHTML'), 'ReportViewer must never use dangerouslySetInnerHTML');
});

test('ReportViewer renders report sections safely', () => {
  const src = read('components/field-assessment/ReportViewer.tsx');
  assert.ok(src.includes('findings'), 'Must render findings section');
  assert.ok(src.includes('evidence_appendix') || src.includes('evidence'), 'Must render evidence section');
  assert.ok(src.includes('framework_summary') || src.includes('Framework'), 'Must render framework section');
});

test('ReportViewer shows manifest_hash', () => {
  const src = read('components/field-assessment/ReportViewer.tsx');
  assert.ok(src.includes('manifest_hash'), 'Must display manifest_hash');
});

test('ReportViewer handles null document gracefully', () => {
  const src = read('components/field-assessment/ReportViewer.tsx');
  assert.ok(src.includes('!doc') || src.includes('doc === null') || src.includes("document: doc"), 'Must handle null document');
});

test('ReportViewer does not print raw report JSON to console', () => {
  const src = read('components/field-assessment/ReportViewer.tsx');
  assert.ok(!src.includes('console.log'), 'Must not console.log report content');
  assert.ok(!src.includes('console.error'), 'Must not console.error');
});

// ─── ReportExportBar ──────────────────────────────────────────────────────────

test('Export JSON calls exportReport with json format', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(src.includes("exportReport"), 'Must call exportReport');
  assert.ok(src.includes("'json'") || src.includes('"json"'), 'Must request json format');
});

test('Export PDF calls exportReport with pdf format', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(src.includes("'pdf'") || src.includes('"pdf"'), 'Must request pdf format');
});

test('Export filename is deterministic', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(
    src.includes('frostgate-report') && src.includes('engagementId') && src.includes('version'),
    'Export filename must include engagementId and version',
  );
});

test('Verify button calls verifyReport', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(src.includes('verifyReport'), 'Must call verifyReport');
  assert.ok(src.includes('handleVerify'), 'Must have handleVerify handler');
});

test('Verify success shows verified badge', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(
    src.includes('Verified') || src.includes('verified'),
    'Must display verified state when valid=true',
  );
  assert.ok(src.includes('verifyResult.valid'), 'Must check valid flag from backend response');
});

test('Verify failure shows failed badge', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(
    src.includes('Invalid') || src.includes('invalid') || src.includes('failed'),
    'Must display invalid/failed state when valid=false',
  );
});

test('ReportExportBar does not compute verification client-side', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(!src.includes('crypto.subtle'), 'Must not use client-side crypto for verification');
  assert.ok(!src.includes('Ed25519'), 'Must not implement Ed25519 client-side');
  assert.ok(!src.includes('createVerify'), 'Must not use client-side signature verification');
});

test('ExportBar does not expose raw error body', () => {
  const src = read('components/field-assessment/ReportExportBar.tsx');
  assert.ok(!src.includes('console.log'), 'Must not console.log error details');
  assert.ok(src.includes('safeExportMsg') || src.includes('safeVerifyMsg') || src.includes('safe'), 'Must use safe error messages');
});

// ─── ControlGapMatrix ─────────────────────────────────────────────────────────

test('ControlGapMatrix renders covered state', () => {
  const src = read('components/field-assessment/ControlGapMatrix.tsx');
  assert.ok(src.includes('covered'), 'Must render covered cell state');
});

test('ControlGapMatrix renders gap state', () => {
  const src = read('components/field-assessment/ControlGapMatrix.tsx');
  assert.ok(src.includes('gap'), 'Must render gap cell state');
});

test('ControlGapMatrix has accessible table', () => {
  const src = read('components/field-assessment/ControlGapMatrix.tsx');
  assert.ok(src.includes('<table') || src.includes('role="table"'), 'Must render as an accessible table');
  assert.ok(src.includes('aria-label'), 'Must have aria-label on table or container');
  assert.ok(src.includes('scope='), 'Must use scope attribute on headers for accessibility');
});

test('ControlGapMatrix handles null data gracefully', () => {
  const src = read('components/field-assessment/ControlGapMatrix.tsx');
  assert.ok(src.includes('!data') || src.includes('data == null') || src.includes('null'), 'Must handle null data');
});

// ─── No dangerouslySetInnerHTML in any new component ─────────────────────────

test('No dangerouslySetInnerHTML in any new report component', () => {
  const components = [
    'ReportGenerationPanel',
    'ReportVersionHistory',
    'ReportViewer',
    'ReportExportBar',
    'ControlGapMatrix',
  ];
  for (const name of components) {
    const src = read(`components/field-assessment/${name}.tsx`);
    assert.ok(
      !src.includes('dangerouslySetInnerHTML'),
      `${name} must not use dangerouslySetInnerHTML`,
    );
  }
});

// ─── No localStorage in new components ───────────────────────────────────────

test('No localStorage or sessionStorage in report components', () => {
  const components = [
    'ReportGenerationPanel',
    'ReportVersionHistory',
    'ReportViewer',
    'ReportExportBar',
    'ControlGapMatrix',
  ];
  for (const name of components) {
    const src = read(`components/field-assessment/${name}.tsx`);
    assert.ok(!src.includes('localStorage'), `${name} must not use localStorage`);
    assert.ok(!src.includes('sessionStorage'), `${name} must not use sessionStorage`);
  }
});
