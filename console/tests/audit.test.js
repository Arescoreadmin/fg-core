const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('audit page includes search and export copy', () => {
  const pagePath = path.join(__dirname, '../app/audit/page.tsx');
  const contents = fs.readFileSync(pagePath, 'utf8');

  assert.match(contents, /Audit Search/);
  assert.match(contents, /Export CSV/);
  assert.match(contents, /Export JSON/);
});
