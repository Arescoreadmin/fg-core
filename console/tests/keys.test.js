const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('keys page includes key management copy', () => {
  const pagePath = path.join(__dirname, '../app/keys/page.tsx');
  const contents = fs.readFileSync(pagePath, 'utf8');

  assert.match(contents, /API Keys/);
  assert.match(contents, /Create API key/);
  assert.match(contents, /Rotate/);
  assert.match(contents, /Revoke/);
});
