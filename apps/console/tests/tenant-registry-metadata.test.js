'use strict';

/**
 * tenant-registry-metadata.test.js
 *
 * Verifies that the console tenant registry stores display metadata only —
 * no raw API keys. The key-resolution path (portal:tenant:{id}:key) is kept
 * separate and is preserved until token exchange is operational.
 *
 * Test IDs:
 *   1. tenant_record_type_does_not_require_api_key
 *   2. upsert_to_upstash_excludes_api_key
 *   3. upsert_to_registry_excludes_api_key
 *   4. provision_tenant_writes_display_metadata_only_to_registry
 *   5. provision_tenant_preserves_portal_key_write_path
 *   6. tenants_api_response_never_exposes_api_key
 *   7. get_tenant_api_key_reads_portal_key_first
 *   8. get_tenant_api_key_falls_back_to_legacy_registry
 *   9. logs_and_responses_do_not_expose_api_key_field
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ─── Test 1: tenant_record_type_does_not_require_api_key ─────────────────────

test('tenant_record_type_does_not_require_api_key', () => {
  const src = read('lib/tenant-registry.ts');

  // TenantRecord must exist
  assert.match(src, /export interface TenantRecord/, 'TenantRecord must exist');

  // api_key field must be optional (decorated with ?)
  assert.match(src, /api_key\?\s*:\s*string/, 'api_key must be an optional string field');

  // Must not appear as a required field (required = "api_key: string" without ?)
  // We look for the pattern without a preceding ? to confirm it's not required anywhere
  assert.doesNotMatch(
    src,
    /(?<!\?)api_key:\s*string/,
    'api_key must not be a required string field in TenantRecord',
  );
});

// ─── Test 2: upsert_to_upstash_excludes_api_key ──────────────────────────────

test('upsert_to_upstash_excludes_api_key', () => {
  const src = read('lib/tenant-registry.ts');

  // upsertTenantInUpstash must accept Omit<TenantRecord, 'api_key'>
  const fnSig = src.match(/export async function upsertTenantInUpstash\([\s\S]*?\)\:/)?.[0] ?? '';
  assert.ok(fnSig, 'upsertTenantInUpstash must exist');
  assert.match(fnSig, /Omit<TenantRecord, 'api_key'>/, "must accept Omit<TenantRecord, 'api_key'>");
});

// ─── Test 3: upsert_to_registry_excludes_api_key ─────────────────────────────

test('upsert_to_registry_excludes_api_key', () => {
  const src = read('lib/tenant-registry.ts');

  // upsertTenantInRegistry must accept Omit<TenantRecord, 'api_key'>
  const fnSig = src.match(/export async function upsertTenantInRegistry\([\s\S]*?\): Promise/)?.[0] ?? '';
  assert.ok(fnSig, 'upsertTenantInRegistry must exist');
  assert.match(fnSig, /Omit<TenantRecord, 'api_key'>/, "must accept Omit<TenantRecord, 'api_key'>");
});

// ─── Test 4: provision_tenant_writes_display_metadata_only_to_registry ────────

test('provision_tenant_writes_display_metadata_only_to_registry', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');

  // upsertTenantInRegistry must be called (fire-and-forget — no await) without api_key
  // Regex matches both awaited and fire-and-forget call forms
  const registryCallBlock = src.match(/upsertTenantInRegistry\(tenantId,\s*\{[\s\S]*?\}\)/)?.[0] ?? '';
  assert.ok(registryCallBlock, 'upsertTenantInRegistry call must exist');
  assert.doesNotMatch(registryCallBlock, /api_key/, 'must not write api_key to Edge Config registry');
  // Must be fire-and-forget (display metadata only — not a blocking auth step)
  assert.match(src, /upsertTenantInRegistry\(tenantId[\s\S]*?\)\.catch/, 'upsertTenantInRegistry must be fire-and-forget');

  // upsertTenantInUpstash (console registry) call must not include api_key field
  const upstashCallBlock = src.match(/await upsertTenantInUpstash\(tenantId,\s*\{[\s\S]*?\}\)/)?.[0] ?? '';
  assert.ok(upstashCallBlock, 'upsertTenantInUpstash call must exist');
  assert.doesNotMatch(upstashCallBlock, /api_key/, 'must not write api_key to console registry');
});

// ─── Test 5: provision_tenant_preserves_portal_key_write_path ────────────────

test('provision_tenant_preserves_portal_key_write_path', () => {
  const src = read('app/api/admin/provision-tenant/route.ts');

  // writeKeyToRedis and writeKeyToUpstash (portal key writes) must still exist
  assert.match(src, /async function writeKeyToRedis/, 'writeKeyToRedis must be preserved');
  assert.match(src, /async function writeKeyToUpstash/, 'writeKeyToUpstash must be preserved');

  // Both must still write to portal:tenant:{id}:key
  assert.match(src, /PORTAL_KEY_PREFIX/, 'portal key prefix must still be used');
  assert.match(src, /portal:tenant/, 'portal key format must still be used');

  // registryLive tracking (for exposing key in response on total failure) must be preserved
  assert.match(src, /registryLive/, 'registryLive logic must be preserved');
});

// ─── Test 6: tenants_api_response_never_exposes_api_key ─────────────────────

test('tenants_api_response_never_exposes_api_key', () => {
  const src = read('app/api/tenants/route.ts');

  // Response must map to {tenant_id, label, is_default} — no api_key
  const mapBlock = src.match(/\.map\(\([\[\w,\s\]]+\)\s*=>\s*\(?\{[\s\S]*?\}\)?/)?.[0] ?? '';
  assert.ok(mapBlock || src.includes('.map('), 'tenants route must map registry entries');
  assert.doesNotMatch(src, /api_key/, 'GET /api/tenants must never expose api_key field');
});

// ─── Test 7: get_tenant_api_key_reads_portal_key_only ────────────────────────
// R4.8+: getTenantApiKey is canonical — reads portal:tenant:{id}:key only.
// The legacy TenantRecord.api_key fallback was removed because it stores
// pre-canonical keys that Core's credential authority now rejects with 401.

test('get_tenant_api_key_reads_portal_key_only', () => {
  const src = read('lib/tenant-registry.ts');

  const fn = src.match(/export async function getTenantApiKey[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(fn, 'getTenantApiKey must exist');

  // Must read portal:tenant:{id}:key as the primary (and only) path
  assert.match(fn, /PORTAL_KEY_PREFIX/, 'must read portal key');
  assert.match(fn, /\$\{PORTAL_KEY_PREFIX\}:\$\{tenantId\}:key/, 'must use correct portal key format');

  // Must NOT fall back to the legacy registry api_key field (invariant E)
  assert.doesNotMatch(fn, /getTenantRegistry/, 'must not fall back to legacy registry');
  assert.doesNotMatch(fn, /api_key/, 'must not read legacy api_key field from registry');
});

// ─── Test 8: get_tenant_api_key_returns_structured_result ────────────────────
// R4.8+: returns { key, unavailable? } so callers can distinguish
// "key not found" from "persistence unavailable" without catching exceptions.

test('get_tenant_api_key_returns_structured_result', () => {
  const src = read('lib/tenant-registry.ts');

  const fn = src.match(/export async function getTenantApiKey[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(fn, 'getTenantApiKey must exist');

  // Must return an object with key field, not a bare string | null
  assert.match(fn, /Promise<\{ key: string \| null;/, 'must return structured result');
  // Must distinguish unavailability from absence
  assert.match(fn, /unavailable: true/, 'must signal persistence unavailability');
});

// ─── Test 9: logs_and_responses_do_not_expose_api_key_field ──────────────────

test('logs_and_responses_do_not_expose_api_key_field', () => {
  const registrySrc = read('lib/tenant-registry.ts');
  const provisionSrc = read('app/api/admin/provision-tenant/route.ts');

  // Console registry (display-only) functions must not log api_key values
  assert.doesNotMatch(
    registrySrc,
    /console\.(log|info|warn|error).*api_key/,
    'registry module must not log api_key values',
  );

  // R0 fail-closed: raw key must never appear in any response (not even on failure).
  // When persistence fails, the route returns 503 PERSISTENCE_UNAVAILABLE instead of
  // exposing the key. Operators must fix the Redis/Upstash connection, not copy raw keys.
  assert.doesNotMatch(provisionSrc, /api_key:.*rawKey/, 'raw key must never be in response');
  assert.match(provisionSrc, /PERSISTENCE_UNAVAILABLE/, '503 path required when persistence fails');
  assert.match(provisionSrc, /status: 503/, '503 status required when persistence fails');
});


// ─── Test 10: tenants API fail-closed operator context ───────────────────────

test('tenants_api_does_not_synthesize_default_in_production', () => {
  const src = read('app/api/tenants/route.ts');
  assert.match(src, /function resolveConfiguredOperatorTenant/);
  assert.match(src, /TENANT_CONTEXT_MISSING/);
  assert.match(src, /TENANT_CONTEXT_INVALID/);
  assert.match(src, /CORE_TENANT_ID=default/);
  assert.doesNotMatch(
    src,
    /process\.env\.CORE_TENANT_ID \|\| 'default'/,
    'production tenants route must not silently synthesize default operator tenant',
  );
});


test('tenants_api_does_not_synthesize_operator_tenant_into_customer_selector', () => {
  const src = read('app/api/tenants/route.ts');
  assert.doesNotMatch(src, /Default \(operator\)/);
  assert.doesNotMatch(src, /is_default: true/);
  assert.match(src, /filter\(\(\[id\]\) => id !== operatorTenantId\)/);
});
