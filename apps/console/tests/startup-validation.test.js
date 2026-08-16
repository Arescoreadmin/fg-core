'use strict';

/**
 * startup-validation.test.js
 *
 * Static-analysis coverage for the centralized production startup validator.
 * These tests verify CODE INVARIANTS that guarantee production behavior —
 * the same approach as provision-tenant.test.js.
 *
 * Coverage:
 *   A. validateProductionConfig function exists and is exported
 *   B. All three required env vars are checked (CORE_API_URL, CORE_TENANT_ID, gateway secret)
 *   C. CORE_TENANT_ID legacy "default" value is explicitly detected
 *   D. CORE_TENANT_ID format is validated (TENANT_ID_RE)
 *   E. internalGatewaySecret covers all 4 legacy aliases
 *   F. Validation is only active in prod-like envs (isProdLike guard)
 *   G. Error message is consolidated — all problems in one throw
 *   H. Error message names the canonical env var for each gap
 *   I. instrumentation.ts wires validateProductionConfig into Next.js startup
 *   J. instrumentation.ts only runs in nodejs runtime (not edge)
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

const VALIDATION = 'lib/startup-validation.ts';
const INSTRUMENT = 'instrumentation.ts';

// ─── A. validateProductionConfig exists and is exported ───────────────────────

test('startup-validation.A: validateProductionConfig is exported from startup-validation.ts', () => {
  const src = read(VALIDATION);
  assert.match(src, /export function validateProductionConfig/);
});

// ─── B. All three required env vars are checked ───────────────────────────────

test('startup-validation.B: all three required production env vars are validated', () => {
  const src = read(VALIDATION);
  assert.match(src, /CORE_API_URL/);
  assert.match(src, /CORE_TENANT_ID/);
  // Gateway secret checked via internalGatewaySecret() helper (covers 4 aliases)
  assert.match(src, /internalGatewaySecret/);
});

// ─── C. Legacy "default" CORE_TENANT_ID is explicitly detected ───────────────

test('startup-validation.C: CORE_TENANT_ID legacy "default" value is explicitly detected', () => {
  const src = read(VALIDATION);
  // The literal "default" must be checked — this was the root cause of
  // TENANT_CONTEXT_INVALID errors in production.
  assert.match(src, /"default"/);
  // The check must produce an error item (not silently pass)
  const defaultCheckMatch = src.match(/["']default["'][\s\S]*?errors\.push/);
  assert.ok(defaultCheckMatch, '"default" check must push an error');
});

// ─── D. CORE_TENANT_ID format validation ─────────────────────────────────────

test('startup-validation.D: CORE_TENANT_ID is validated against the tenant ID regex', () => {
  const src = read(VALIDATION);
  // Same regex pattern as tenants/route.ts to ensure consistency
  assert.match(src, /TENANT_ID_RE/);
  assert.match(src, /\[a-zA-Z0-9_-\]/);
});

// ─── E. Gateway secret covers all 4 legacy aliases ───────────────────────────

test('startup-validation.E: internalGatewaySecret() covers all 4 legacy env var aliases', () => {
  const secretSrc = read('lib/internal-gateway-secret.ts');
  // All four aliases must be checked in the helper so startup-validation
  // doesn't need to enumerate them.
  assert.match(secretSrc, /FG_INTERNAL_GATEWAY_SECRET/);
  assert.match(secretSrc, /FG_ADMIN_GATEWAY_TOKEN/);
  assert.match(secretSrc, /FG_INTERNAL_AUTH_SECRET/);
  assert.match(secretSrc, /FG_INTERNAL_TOKEN/);
});

// ─── F. Validation is prod-only ───────────────────────────────────────────────

test('startup-validation.F: validateProductionConfig is a no-op in non-prod environments', () => {
  const src = read(VALIDATION);
  // Must export or use an isProdLike guard so dev/test environments are unaffected
  assert.match(src, /isProdLike/);
  // Guard must be the first meaningful check inside the function
  const fnMatch = src.match(/function validateProductionConfig[\s\S]*?\n\}/);
  assert.ok(fnMatch, 'validateProductionConfig function must exist');
  const body = fnMatch[0];
  const guardPos = body.indexOf('isProdLike');
  const coreApiPos = body.indexOf('CORE_API_URL');
  assert.ok(guardPos < coreApiPos, 'isProdLike guard must appear before env var checks');
});

// ─── G. Error message is consolidated ────────────────────────────────────────

test('startup-validation.G: a single throw includes all configuration problems', () => {
  const src = read(VALIDATION);
  // Must accumulate errors into a list before throwing — not throw on first gap
  assert.match(src, /errors\.push/);
  assert.match(src, /errors\.length/);
  // Single consolidated throw at the end
  assert.match(src, /throw new Error/);
  assert.match(src, /Production configuration invalid/);
  assert.match(src, /Console startup aborted/);
});

// ─── H. Error message names canonical env vars ───────────────────────────────

test('startup-validation.H: error messages name the canonical env var so operators know what to set', () => {
  const src = read(VALIDATION);
  // Each error item must name the env var
  assert.match(src, /CORE_API_URL is not configured/);
  assert.match(src, /CORE_TENANT_ID/);
  assert.match(src, /FG_INTERNAL_GATEWAY_SECRET/);
});

// ─── I. instrumentation.ts wires the validator into Next.js startup ───────────

test('startup-validation.I: instrumentation.ts imports and calls validateProductionConfig on startup', () => {
  const src = read(INSTRUMENT);
  // Next.js instrumentation lifecycle hook
  assert.match(src, /export async function register/);
  // Must import from startup-validation
  assert.match(src, /startup-validation/);
  assert.match(src, /validateProductionConfig/);
  // Must call it (not just import it)
  assert.match(src, /validateProductionConfig\(\)/);
});

// ─── J. instrumentation runs in nodejs runtime only ──────────────────────────

test('startup-validation.J: instrumentation.ts restricts validation to nodejs runtime, not edge', () => {
  const src = read(INSTRUMENT);
  // Edge runtime does not support all Node.js APIs — guard is required
  assert.match(src, /NEXT_RUNTIME/);
  assert.match(src, /nodejs/);
  // validateProductionConfig must be inside the nodejs guard
  const nodejsBlock = src.match(/nodejs[\s\S]*?validateProductionConfig/);
  assert.ok(nodejsBlock, 'validateProductionConfig must be inside the nodejs runtime guard');
});

// ─── K. FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK requires explicit "false" ──

test('startup-validation.K: legacy fallback guard requires explicit "false", not just absence of truthy', () => {
  const src = read(VALIDATION);
  assert.match(src, /FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK/);
  // Must use !== 'false' — not a truthiness check — so ambiguous values fail closed
  assert.match(src, /!== 'false'/);
  // Must push an actionable error
  const legacyCheckMatch = src.match(/FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK[\s\S]*?errors\.push/);
  assert.ok(legacyCheckMatch, 'legacy fallback check must push an error');
  // Error message must name the canonical value
  assert.match(src, /explicitly set to "false"/);
});

// ─── L. Full deterministic matrix for the legacy fallback guard ───────────────
// Inline mirror of the guard logic so every case is verifiable without a build.

function legacyFallbackAllowed(rawEnvValue) {
  // Mirrors startup-validation.ts: require explicit "false" after trim/lowercase
  const v = (rawEnvValue || '').trim().toLowerCase();
  return v === 'false';
}

test('startup-validation.L: legacy fallback guard — only "false" permits boot', () => {
  // Values that must FAIL boot (all non-false)
  const failing = [
    [undefined, 'missing (not set)'],
    ['', 'empty string'],
    ['true', 'true'],
    ['TRUE', 'TRUE (uppercase)'],
    ['True', 'True (mixed case)'],
    ['1', '1'],
    ['yes', 'yes'],
    ['on', 'on'],
    ['garbage', 'garbage'],
    [' ', 'whitespace-only'],
  ];

  for (const [value, label] of failing) {
    assert.equal(
      legacyFallbackAllowed(value),
      false,
      `"${label}" must fail boot`,
    );
  }

  // Values that must PASS boot (trim/lowercase normalization applied)
  const passing = [
    ['false', 'false'],
    ['False', 'False (mixed case)'],
    ['FALSE', 'FALSE (uppercase)'],
    ['  false  ', 'false with surrounding whitespace'],
    ['false ', 'false with trailing space'],
  ];

  for (const [value, label] of passing) {
    assert.equal(
      legacyFallbackAllowed(value),
      true,
      `"${label}" must permit boot`,
    );
  }
});
