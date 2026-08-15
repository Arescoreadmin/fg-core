'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

test('Console Users gates invite on canonical identity readiness', () => {
  const src = read('app/admin/tenants/[tenantId]/page.tsx');
  assert.match(src, /getIdentityReadiness/);
  assert.match(src, /identityStatus === 'ready'/);
  assert.match(src, /data-testid="identity-setup-required"/);
  assert.match(src, /Configure this tenant's identity policy before inviting console users/);
  assert.match(src, /onClick=\{onConfigureIdentity\}/);
});

test('tenant detail coreApi maps structured Core errors instead of stringifying objects', () => {
  const src = read('app/admin/tenants/[tenantId]/page.tsx');
  assert.match(src, /mapHttpError\(res\.status, body, \{\}\)/);
  assert.doesNotMatch(src, /throw new Error\(body\?\.detail/);
});

test('Identity Governance setup submits canonical ready identity config', () => {
  const src = read('components/identity/IdentityGovernancePanel.tsx');
  assert.match(src, /upsertIdentityConfig\(tenantId, \{/);
  assert.match(src, /provisioning_status: 'ready'/);
  assert.match(src, /Mark identity ready/);
  assert.match(src, /data-testid="identity-config-setup"/);
});

test('identityApi exposes explicit provisioning status on config upsert payload', () => {
  const src = read('lib/identityApi.ts');
  assert.match(src, /export interface ConfigUpsertPayload/);
  assert.match(src, /provisioning_status\?: string/);
});

test('structured error normalizer extracts code and message from Core detail objects', () => {
  const src = read('lib/errors.ts');
  assert.match(src, /structured\.message === 'string'/);
  assert.match(src, /structured\.code === 'string'/);
  assert.match(src, /`\$\{structured\.code\}: \$\{structured\.message\}`/);
  assert.doesNotMatch(src, /return String\(detail\)/);
});

test('tenant provisioning still does not guess identity policy config', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');
  assert.match(src, /identity-bindings/);
  assert.doesNotMatch(src, /admin\/identity\/tenants\/.*\/config/);
  assert.doesNotMatch(src, /upsertIdentityConfig/);
});
