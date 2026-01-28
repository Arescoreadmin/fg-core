const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('health route includes ok status response', () => {
  const routePath = path.join(__dirname, '../app/api/health/route.ts');
  const contents = fs.readFileSync(routePath, 'utf8');

  assert.match(contents, /export\s+async\s+function\s+GET/);
  assert.match(contents, /status:\s*'ok'/);
});
