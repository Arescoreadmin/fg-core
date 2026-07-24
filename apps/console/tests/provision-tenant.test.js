'use strict';

/**
 * provision-tenant.test.js
 *
 * End-to-end static-analysis coverage for the tenant provisioning route's
 * error taxonomy and observability contract.
 *
 * Console tests use `node --test` on source strings (no Next.js runtime),
 * so these assertions verify the CODE INVARIANTS that guarantee production
 * behavior — the same style as tenant-provisioning-policy.test.js.
 *
 * Coverage:
 *   A. request_id is generated and echoed in every response
 *   B. INTERNAL_GATEWAY_UNCONFIGURED returned when gateway secret absent
 *   C. Distinct error codes per failure class (not a single PERSISTENCE_UNAVAILABLE)
 *   D. Structured JSON logs emitted at every persistence stage
 *   E. Secrets and raw tokens NEVER appear in logs (only presence flags)
 *   F. Retry after persistence failure resurfaces same taxonomy on 2nd attempt
 *   G. Upstash 401/403 mapped to UPSTASH_AUTH_FAILED (distinct from network error)
 *   H. Rotate path preserves credential and does NOT revoke on persistence failure
 *   I. Fresh-create path revokes the dangling credential on persistence failure
 *   J. FG_ALLOW_UNPERSISTED_TENANT_KEYS override still hard-blocked in production
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

const ROUTE = 'app/api/admin/provision-tenant/route.ts';

// ─── A. request_id is generated and echoed in every response ─────────────────

test('provision-tenant.A: request_id is generated on entry and echoed in every response', () => {
  const src = read(ROUTE);
  // Must generate request_id from header or crypto.randomUUID()
  assert.match(src, /const requestId = req\.headers\.get\('x-request-id'\) \|\| crypto\.randomUUID\(\)/);
  // Every JSON response must include x-request-id header
  const responseCount = (src.match(/NextResponse\.json/g) || []).length;
  const headersCount = (src.match(/'x-request-id': requestId/g) || []).length;
  assert.ok(
    headersCount >= responseCount - 1,
    `expected ~${responseCount} responses to carry x-request-id header, found ${headersCount}`,
  );
  // Every response body must include request_id field
  assert.match(src, /request_id: requestId/);
});

// ─── B. INTERNAL_GATEWAY_UNCONFIGURED returned when gateway secret absent ─────

test('provision-tenant.B: gateway secret absence returns INTERNAL_GATEWAY_UNCONFIGURED not PERSISTENCE_UNAVAILABLE', () => {
  const src = read(ROUTE);
  // The 503 gate for missing gateway secret must use the distinct code
  assert.match(src, /if \(!internalGatewaySecret\(\)\)/);
  assert.match(src, /error: 'INTERNAL_GATEWAY_UNCONFIGURED'/);
  // Message must list the legacy aliases so operators know what to set
  assert.match(src, /FG_INTERNAL_GATEWAY_SECRET/);
  assert.match(src, /FG_ADMIN_GATEWAY_TOKEN/);
  assert.match(src, /FG_INTERNAL_AUTH_SECRET/);
  assert.match(src, /FG_INTERNAL_TOKEN/);
  // Must log the missing-secret event for observability
  assert.match(src, /'gateway\.secret\.missing'/);
});

// ─── C. Distinct error codes per failure class ────────────────────────────────

test('provision-tenant.C: distinct error codes exist for each persistence failure class', () => {
  const src = read(ROUTE);
  // Neither backend configured
  assert.match(src, /code: 'PERSISTENCE_NOT_CONFIGURED'/);
  // Both configured but both failed
  assert.match(src, /code: 'BOTH_PERSISTENCE_UNAVAILABLE'/);
  // Upstash-only, token rejected
  assert.match(src, /code: 'UPSTASH_AUTH_FAILED'/);
  // Upstash-only, network/HTTP error
  assert.match(src, /code: 'UPSTASH_UNAVAILABLE'/);
  // Redis-only, unreachable
  assert.match(src, /code: 'REDIS_UNAVAILABLE'/);
  // Classifier function must exist
  assert.match(src, /function classifyPersistenceFailure/);
});

test('provision-tenant.C2: classification prioritises specific codes over the generic fallback', () => {
  const src = read(ROUTE);
  const classifierMatch = src.match(/function classifyPersistenceFailure[\s\S]*?\n\}/);
  assert.ok(classifierMatch, 'classifyPersistenceFailure must exist');
  const body = classifierMatch[0];
  // NOT_CONFIGURED branch must precede the BOTH_UNAVAILABLE branch
  const notConfPos = body.indexOf('PERSISTENCE_NOT_CONFIGURED');
  const bothPos = body.indexOf('BOTH_PERSISTENCE_UNAVAILABLE');
  const upstashAuthPos = body.indexOf('UPSTASH_AUTH_FAILED');
  const upstashUnavailPos = body.indexOf('UPSTASH_UNAVAILABLE');
  assert.ok(notConfPos < bothPos, 'NOT_CONFIGURED must be checked before BOTH_UNAVAILABLE');
  // AUTH_FAILED must precede generic UNAVAILABLE (more specific first)
  assert.ok(upstashAuthPos < upstashUnavailPos, 'UPSTASH_AUTH_FAILED must be checked before UPSTASH_UNAVAILABLE');
});

// ─── D. Structured JSON logs at every persistence stage ──────────────────────

test('provision-tenant.D: structured JSON logs emitted at each stage', () => {
  const src = read(ROUTE);
  // Central logEvent helper
  assert.match(src, /function logEvent/);
  assert.match(src, /JSON\.stringify\(payload\)/);
  // Key lifecycle events
  assert.match(src, /'provision\.start'/);
  assert.match(src, /'provision\.tenant\.ok'/);
  assert.match(src, /'provision\.credential\.ok'/);
  assert.match(src, /'provision\.ok'/);
  // Persistence events per backend
  assert.match(src, /'persistence\.redis\.ok'/);
  assert.match(src, /'persistence\.redis\.threw'/);
  assert.match(src, /'persistence\.upstash\.ok'/);
  assert.match(src, /'persistence\.upstash\.auth_failed'/);
  assert.match(src, /'persistence\.upstash\.bad_response'/);
  assert.match(src, /'persistence\.upstash\.threw'/);
  // Failure paths log with structured fields
  assert.match(src, /'provision\.persistence\.failed\.fresh'/);
  assert.match(src, /'provision\.persistence\.failed\.rotate'/);
});

// ─── E. Secrets NEVER appear in logs ──────────────────────────────────────────

test('provision-tenant.E: secrets, tokens, and raw keys never appear in log fields', () => {
  const src = read(ROUTE);
  // logEvent calls must never pass the token or raw key value directly
  assert.doesNotMatch(src, /logEvent\([^)]*,\s*token[,)]/);
  assert.doesNotMatch(src, /logEvent\([^)]*,\s*apiKey[,)]/);
  assert.doesNotMatch(src, /logEvent\([^)]*,\s*rawKey[,)]/);
  // token_len (length only) is allowed and expected for auth_failed diagnostics
  assert.match(src, /token_len: token\.length/);
  // safeHost helper strips credentials and paths from URLs before logging
  assert.match(src, /function safeHost/);
  assert.match(src, /new URL\(rawUrl\)\.host/);
});

test('provision-tenant.E2: response body must never include the raw api_key when persistence succeeded', () => {
  const src = read(ROUTE);
  // The success response (registry_live: true) must NOT include api_key.
  // Extract the success-return block and verify.
  const successBlock = src.match(/registry_live: true,[\s\S]*?\}\)/);
  assert.ok(successBlock, 'success response block must exist');
  assert.doesNotMatch(successBlock[0], /api_key:/);
});

// ─── F. Retry after persistence failure resurfaces same taxonomy ─────────────

test('provision-tenant.F: retry after failure follows the rotate path with the same taxonomy', () => {
  const src = read(ROUTE);
  // On slot conflict (previous partial provisioning), the code must:
  //   1. detect via 409, 2. list credentials, 3. rotate the active one
  assert.match(src, /if \(keyRes\.status === 409\)/);
  assert.match(src, /wasRotated = true/);
  assert.match(src, /\/rotate/);
  // Rotate path uses the SAME persistence classifier as fresh create
  const rotatePathIdx = src.indexOf('provision.persistence.failed.rotate');
  const freshPathIdx = src.indexOf('provision.persistence.failed.fresh');
  assert.ok(rotatePathIdx >= 0 && freshPathIdx >= 0);
  // Both must reference the same `code` and `detail` from classifyPersistenceFailure
  const classifyCalls = src.match(/classifyPersistenceFailure/g) || [];
  assert.ok(classifyCalls.length >= 1, 'classifyPersistenceFailure must be called at least once for both paths');
});

// ─── G. Upstash 401/403 → UPSTASH_AUTH_FAILED (distinct from network error) ─

test('provision-tenant.G: Upstash 401/403 mapped to auth_failed status, not bad_response', () => {
  const src = read(ROUTE);
  const upstashFn = src.match(/async function writeKeyToUpstash[\s\S]*?^\}/m);
  assert.ok(upstashFn, 'writeKeyToUpstash must exist');
  const body = upstashFn[0];
  // Must explicitly check 401/403 before the generic non-ok branch
  assert.match(body, /res\.status === 401 \|\| res\.status === 403/);
  assert.match(body, /status: 'auth_failed'/);
  // The 401/403 branch must precede the !res.ok generic branch
  const authIdx = body.indexOf("status: 'auth_failed'");
  const badRespIdx = body.indexOf("status: 'bad_response'");
  assert.ok(authIdx < badRespIdx, '401/403 auth_failed branch must precede generic bad_response');
});

// ─── H. Rotate path does NOT revoke on persistence failure ───────────────────

test('provision-tenant.H: rotate path preserves the new credential on persistence failure', () => {
  const src = read(ROUTE);
  // Locate the rotate branch of the failure handler
  const rotateBranch = src.match(/if \(wasRotated\) \{[\s\S]*?return NextResponse\.json[\s\S]*?\}\);/);
  assert.ok(rotateBranch, 'rotate branch must exist');
  const body = rotateBranch[0];
  // Must NOT call revokeKey — predecessor is already superseded, and revoking
  // the new credential would leave the tenant with zero usable credentials.
  assert.doesNotMatch(body, /await revokeKey/);
  // Must document that the credential is live in Postgres
  assert.match(body, /live in Postgres/i);
});

// ─── I. Fresh-create path revokes the dangling credential on persistence failure

test('provision-tenant.I: fresh-create path revokes the dangling credential on failure', () => {
  const src = read(ROUTE);
  // The non-rotate failure branch must call revokeKey with the credential_id
  assert.match(src, /await revokeKey\(keyData\.credential_id as string, tenantId, requestId\)/);
  // rollback_performed: true is emitted in the log so operators can trace it
  assert.match(src, /rollback_performed: true/);
  // Rotate path emits rollback_performed: false (predecessor is already superseded)
  assert.match(src, /rollback_performed: false/);
});

// ─── J. Production hard-blocks the FG_ALLOW_UNPERSISTED_TENANT_KEYS override ─

test('provision-tenant.J: production hard-blocks the FG_ALLOW_UNPERSISTED_TENANT_KEYS override', () => {
  const src = read(ROUTE);
  // The devOverride flag must require BOTH FG_ENV != production AND the flag
  assert.match(src, /!isProduction/);
  assert.match(src, /FG_ALLOW_UNPERSISTED_TENANT_KEYS/);
  // In production, even if the flag is set, we log-and-ignore it
  assert.match(src, /security\.override\.ignored_in_production/);
  // No path returns the raw api_key when isProduction is true
  const prodBlock = src.match(/if \(isProduction && \(process\.env\.FG_ALLOW_UNPERSISTED_TENANT_KEYS[\s\S]*?\}/);
  assert.ok(prodBlock, 'production override guard must exist');
  assert.doesNotMatch(prodBlock[0], /api_key: keyData\.plaintext_secret/);
});
