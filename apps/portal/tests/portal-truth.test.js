const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('portal summary adapter consumes canonical backend count names', () => {
  const api = read('lib/portalApi.ts');
  assert.match(api, /total_findings\?: number/);
  assert.match(api, /open_findings_count\?: number/);
  assert.match(api, /critical_findings_count\?: number/);
  assert.match(api, /raw\.open_findings_count \?\? raw\.open_findings/);
});

test('finding API normalizes canonical id for stable portal identity', () => {
  const api = read('lib/portalApi.ts');
  assert.match(api, /finding_id: finding\.finding_id \?\? finding\.id/);
});

test('customer report UI never derives author identity from backend compiled_by', () => {
  const page = read('app/reports/page.tsx');
  assert.match(page, /Compiled by:[\s\S]*Not recorded/);
  assert.doesNotMatch(page, /report\.compiled_by\}</);
  assert.match(page, /release_blocked/);
  assert.match(page, /synthetic_draft/);
});

test('dashboard and engagement never infer all findings resolved from zero open', () => {
  const dashboard = read('app/dashboard/page.tsx');
  const engagement = read('app/engagement/[engagementId]/page.tsx');
  assert.match(dashboard, /resolved_findings !== null/);
  assert.doesNotMatch(engagement, /all resolved/i);
  assert.match(dashboard, /critical_findings > 0 \? 'active'/);
  assert.doesNotMatch(engagement, /Error \$\{e\.status\}: \$\{e\.code\}/);
});

test('remediation view marks missing coverage and effort as unavailable', () => {
  const api = read('lib/portalApi.ts');
  const page = read('app/remediation/page.tsx');
  assert.match(api, /current_coverage_pct: number \| null/);
  assert.match(page, /Effort not estimated/);
  assert.match(page, /Coverage|Unavailable/);
});

test('coverage view displays canonical collection gaps and does not infer a percentage', () => {
  const page = read('app/coverage/page.tsx');
  assert.match(page, /Collection completeness and limitations/);
  assert.match(page, /coverage_determinable === true/);
  assert.match(page, /Coverage percentage unavailable/);
  assert.match(page, /coverage\.limitations\) \? coverage\.limitations\.length/);
  assert.match(page, /listReports\(engagementId/);
});
