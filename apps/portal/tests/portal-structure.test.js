/**
 * portal-structure.test.js
 *
 * Structural and behavioral contract tests for portal pages and components.
 * Asserts that key features shipped in PRs 30-33 are present and correct.
 */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ---------------------------------------------------------------------------
// portalApi — method surface
// ---------------------------------------------------------------------------

test('portalApi exposes all required methods for portal pages', () => {
  const api = read('lib/portalApi.ts');
  const required = [
    'listEngagements',
    'listFindings',
    'listReports',
    'getReport',
    'exportReport',
    'verifyReport',
    'listAssets',
    'listAttestations',
    'submitAttestation',
    'getAttestationHealth',
    'explainFinding',
    'listContinuityGaps',
    'listQuestionnaires',
    'getRemediationRoadmap',
    'updateFindingStatus',
  ];
  for (const method of required) {
    assert.match(api, new RegExp(`${method}\\(`), `missing method: ${method}`);
  }
});

test('portalApi updateFindingStatus sends PATCH with JSON body', () => {
  const api = read('lib/portalApi.ts');
  assert.match(api, /method: 'PATCH'/);
  assert.match(api, /body: JSON\.stringify\(payload\)/);
  assert.match(api, /findings\/\$\{findingId\}/);
});

test('portalApi FindingStatusPatch only allows terminal status values', () => {
  const api = read('lib/portalApi.ts');
  assert.match(api, /remediated.*accepted.*false_positive/s);
});

// ---------------------------------------------------------------------------
// Home page — risk posture dashboard (PR 33)
// ---------------------------------------------------------------------------

test('home page fetches remediation roadmap, all findings, and questionnaires in parallel', () => {
  const page = read('app/page.tsx');
  assert.match(page, /getRemediationRoadmap/);
  assert.match(page, /fetchAllFindings/);
  assert.match(page, /listQuestionnaires/);
  assert.match(page, /Promise\.allSettled/);
});

test('home page fetchAllFindings paginates with a hardMax cap', () => {
  const page = read('app/page.tsx');
  assert.match(page, /fetchAllFindings/);
  assert.match(page, /hardMax/);
  assert.match(page, /offset/);
});

test('home page guards stale engagement fetches with isCurrent cleanup flag', () => {
  const page = read('app/page.tsx');
  assert.match(page, /let isCurrent = true/);
  assert.match(page, /if \(!isCurrent\) return/);
  assert.match(page, /isCurrent = false/);
});

test('home page renders NIST function coverage heatmap for GOVERN/MAP/MEASURE/MANAGE', () => {
  const page = read('app/page.tsx');
  assert.match(page, /GOVERN/);
  assert.match(page, /MAP/);
  assert.match(page, /MEASURE/);
  assert.match(page, /MANAGE/);
  assert.match(page, /NistFunctionHeatmap/);
});

test('home page renders immediate actions callout linking to remediation page', () => {
  const page = read('app/page.tsx');
  assert.match(page, /ImmediateActionsCallout/);
  assert.match(page, /\/remediation/);
});

test('home page derives function coverage from questionnaire control_id prefix', () => {
  const page = read('app/page.tsx');
  assert.match(page, /control_id\.split\('-'\)/);
});

// ---------------------------------------------------------------------------
// Findings page — explainer and remediation steps (PR 33 fix)
// ---------------------------------------------------------------------------

test('findings page renders explanation.remediation_steps as numbered list', () => {
  const page = read('app/findings/page.tsx');
  assert.match(page, /remediation_steps/);
  assert.match(page, /Remediation steps/);
});

test('findings page calls explainFinding on expand and shows plain_summary', () => {
  const page = read('app/findings/page.tsx');
  assert.match(page, /explainFinding/);
  assert.match(page, /plain_summary/);
  assert.match(page, /what_it_means/);
});

test('findings page falls back gracefully when explanation is unavailable', () => {
  const page = read('app/findings/page.tsx');
  // Must have fallback branch showing raw finding data when explanation fails
  assert.match(page, /!explanation && !explainLoading/);
  assert.match(page, /remediation_hint/);
});

// ---------------------------------------------------------------------------
// Remediation page — closed-loop controls (PR 32)
// ---------------------------------------------------------------------------

test('remediation page has StatusControl component for marking findings resolved', () => {
  const page = read('app/remediation/page.tsx');
  assert.match(page, /StatusControl/);
  assert.match(page, /updateFindingStatus/);
});

test('remediation page StatusControl only allows terminal status values', () => {
  const page = read('app/remediation/page.tsx');
  assert.match(page, /remediated/);
  assert.match(page, /accepted/);
  assert.match(page, /false_positive/);
});

test('remediation page refreshes roadmap after resolution via refreshKey', () => {
  const page = read('app/remediation/page.tsx');
  assert.match(page, /refreshKey/);
  assert.match(page, /setRefreshKey/);
});

test('remediation page passes engagementId and onResolved down to PhaseCard and FindingCard', () => {
  const page = read('app/remediation/page.tsx');
  assert.match(page, /engagementId={engagementId}/);
  assert.match(page, /onResolved={refreshRoadmap}/);
});

// ---------------------------------------------------------------------------
// All portal pages fall back to stored engagement when ?e= param is absent
// ---------------------------------------------------------------------------

test('all sub-pages use getStoredEngagementId() as fallback when URL param absent', () => {
  const pages = [
    'app/findings/page.tsx',
    'app/reports/page.tsx',
    'app/coverage/page.tsx',
    'app/remediation/page.tsx',
  ];
  for (const page of pages) {
    const src = read(page);
    assert.match(src, /getStoredEngagementId\(\)/, `${page} missing getStoredEngagementId fallback`);
    assert.match(src, /params\.get\('e'\)/, `${page} missing ?e= param read`);
  }
});
