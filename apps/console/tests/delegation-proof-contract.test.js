'use strict';

const assert = require('node:assert/strict');
const { createHmac } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

// ── Cross-language canonicalization contract ──────────────────────────────────
//
// Pinned golden vector. Both the Python Core implementation and this Node.js
// BFF implementation must produce the exact same digest for the same input.
// If this test diverges from the Python golden test, the two sides will fail
// to interoperate in production.
//
// Python reference: tests/test_core_002_admin_gateway_tenant_binding.py
//   test_delegation_proof_canonical_golden_vector

const GOLDEN_SECRET = 'test-cross-language-vector-secret';
const GOLDEN_REQUEST_ID = 'req-123';
const GOLDEN_TENANT_ID = 'tenant-a';
const GOLDEN_METHOD = 'POST';
const GOLDEN_PATH = '/admin/identity/tenants/tenant-a/config';
const GOLDEN_IAT = 1786992000;
const GOLDEN_EXP = 1786992060;

// Pre-computed digest. Both Python and Node must produce this value.
// If you change the canonical format, update BOTH implementations and this pin.
const GOLDEN_DIGEST = '3a46a692f025f3a8a968c59ea1dc45f90eb155e916235b651260c1c26e0b3b33';

function computeProof(secret, requestId, tenantId, method, canonicalPath, issuedAt, expiresAt) {
  const canonical = `v1\n${requestId}\n${tenantId}\n${method.toUpperCase()}\n${canonicalPath}\n${issuedAt}\n${expiresAt}`;
  return createHmac('sha256', secret).update(canonical, 'utf8').digest('hex');
}

function readRoute() {
  return fs.readFileSync(
    path.join(__dirname, '..', 'app', 'api', 'core', '[...path]', 'route.ts'),
    'utf8',
  );
}

test('delegation proof golden vector matches pinned digest', () => {
  const digest = computeProof(
    GOLDEN_SECRET,
    GOLDEN_REQUEST_ID,
    GOLDEN_TENANT_ID,
    GOLDEN_METHOD,
    GOLDEN_PATH,
    GOLDEN_IAT,
    GOLDEN_EXP,
  );
  assert.strictEqual(
    digest,
    GOLDEN_DIGEST,
    'Node.js digest must match the pinned cross-language golden vector',
  );
});

test('method is uppercased before signing', () => {
  const lower = computeProof(GOLDEN_SECRET, 'r', 't', 'post', '/p', 1000, 1060);
  const upper = computeProof(GOLDEN_SECRET, 'r', 't', 'POST', '/p', 1000, 1060);
  assert.strictEqual(lower, upper, 'method case must not affect the digest');
});

test('changing tenant_id changes the digest', () => {
  const a = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, 'tenant-a', GOLDEN_METHOD, GOLDEN_PATH, GOLDEN_IAT, GOLDEN_EXP);
  const b = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, 'tenant-b', GOLDEN_METHOD, GOLDEN_PATH, GOLDEN_IAT, GOLDEN_EXP);
  assert.notStrictEqual(a, b);
});

test('changing method changes the digest', () => {
  const get = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, GOLDEN_TENANT_ID, 'GET', GOLDEN_PATH, GOLDEN_IAT, GOLDEN_EXP);
  const post = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, GOLDEN_TENANT_ID, 'POST', GOLDEN_PATH, GOLDEN_IAT, GOLDEN_EXP);
  assert.notStrictEqual(get, post);
});

test('changing canonical path changes the digest', () => {
  const users = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, GOLDEN_TENANT_ID, GOLDEN_METHOD, '/admin/identity/tenants/tenant-a/users', GOLDEN_IAT, GOLDEN_EXP);
  const keys = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, GOLDEN_TENANT_ID, GOLDEN_METHOD, '/admin/identity/tenants/tenant-a/keys', GOLDEN_IAT, GOLDEN_EXP);
  assert.notStrictEqual(users, keys);
});

test('changing request_id changes the digest', () => {
  const r1 = computeProof(GOLDEN_SECRET, 'req-aaa', GOLDEN_TENANT_ID, GOLDEN_METHOD, GOLDEN_PATH, GOLDEN_IAT, GOLDEN_EXP);
  const r2 = computeProof(GOLDEN_SECRET, 'req-bbb', GOLDEN_TENANT_ID, GOLDEN_METHOD, GOLDEN_PATH, GOLDEN_IAT, GOLDEN_EXP);
  assert.notStrictEqual(r1, r2);
});

test('changing expiry changes the digest', () => {
  const short = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, GOLDEN_TENANT_ID, GOLDEN_METHOD, GOLDEN_PATH, GOLDEN_IAT, GOLDEN_IAT + 30);
  const long = computeProof(GOLDEN_SECRET, GOLDEN_REQUEST_ID, GOLDEN_TENANT_ID, GOLDEN_METHOD, GOLDEN_PATH, GOLDEN_IAT, GOLDEN_IAT + 60);
  assert.notStrictEqual(short, long);
});

// ── Source contract: route.ts signs after tenant resolution ───────────────────

test('createDelegationProof exists in route.ts', () => {
  const src = readRoute();
  assert.ok(src.includes('function createDelegationProof('), 'createDelegationProof must exist');
});

test('route.ts sets delegation headers only after tenantId is set', () => {
  const src = readRoute();
  const tenantHeaderPos = src.indexOf("headers.set('X-Tenant-ID', tenantId)");
  const delegationPos = src.indexOf("headers.set('X-FG-Delegation-Version'");
  assert.ok(tenantHeaderPos > 0, 'X-Tenant-ID header must be set');
  assert.ok(delegationPos > 0, 'X-FG-Delegation-Version header must be set');
  assert.ok(tenantHeaderPos < delegationPos, 'X-Tenant-ID must be set before delegation headers');
});

test('route.ts uses DELEGATION_SECRET_CURRENT not gateway token for signing', () => {
  const src = readRoute();
  // createDelegationProof must be called with DELEGATION_SECRET_CURRENT
  assert.ok(src.includes('createDelegationProof(\n        DELEGATION_SECRET_CURRENT,') ||
            src.includes('createDelegationProof(DELEGATION_SECRET_CURRENT,') ||
            src.includes('DELEGATION_SECRET_CURRENT,\n        requestId,'),
    'delegation proof must use DELEGATION_SECRET_CURRENT, not ADMIN_GATEWAY_TOKEN');
});

test('delegation headers are never NEXT_PUBLIC prefixed', () => {
  const src = readRoute();
  assert.doesNotMatch(src, /NEXT_PUBLIC.*DELEGATION/);
  assert.doesNotMatch(src, /DELEGATION.*NEXT_PUBLIC/);
});
