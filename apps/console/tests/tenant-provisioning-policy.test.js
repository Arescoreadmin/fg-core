'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

test('provisioned console keys can manage tenant workforce users', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  const scopes = src.match(/const PROVISION_SCOPES = \[([\s\S]*?)\];/)?.[1] ?? '';
  assert.match(scopes, /'admin:write'/);
});

test('tenant provisioning authenticates admin core calls with the internal token', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  const headers = src.match(/function adminHeaders\(\): HeadersInit \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(headers, /const token = internalToken\(\)/);
  assert.match(headers, /'X-API-Key': token/);
  assert.match(headers, /'X-FG-Internal-Token': token/);
  assert.match(headers, /'X-Admin-Gateway-Internal': 'true'/);
  assert.doesNotMatch(headers, /'X-API-Key': CORE_API_KEY/);
});
