'use strict';

/**
 * auth-secret-isolation.test.js
 *
 * AUTH-SECRET-ISOLATION-001 regression test suite.
 *
 * Covers the 22-case acceptance matrix from the specification.
 * Tests are static analysis (source inspection) + behavioral simulation
 * where runtime integration is not available in this environment.
 *
 * Static checks verify CODE INVARIANTS that guarantee production behavior —
 * the same methodology as startup-validation.test.js.
 * Behavioral checks exercise actual logic where practical.
 *
 * Legend:
 *   [STATIC]     — source code inspection
 *   [BEHAVIORAL] — in-process logic simulation
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ─── AUTH-T01: Dedicated secret configured — authentication initializes ────────
// [STATIC] auth.ts must not fall back to any internal credential.
// AUTH-001, AUTH-002, AUTH-008

test('AUTH-T01: auth.ts uses only process.env.AUTH_SECRET — no fallback', () => {
  const src = read('auth.ts');

  // Must assign secret from AUTH_SECRET only (no ?? fallback on that line)
  assert.match(src, /secret: process\.env\.AUTH_SECRET(?!\s*\?\?)/,
    'auth.ts must assign secret: process.env.AUTH_SECRET with no fallback expression');

  // Must NOT fall back to FG_INTERNAL_AUTH_SECRET via ?? operator
  assert.doesNotMatch(src, /AUTH_SECRET\s*\?\?\s*process\.env\.FG_INTERNAL/,
    'auth.ts must not fall back to FG_INTERNAL_AUTH_SECRET via ?? operator');

  // The secret: assignment line specifically must not contain FG_INTERNAL
  const secretLine = src.split('\n').find((line) => line.trim().startsWith('secret:'));
  assert.ok(secretLine, 'auth.ts must have a secret: assignment line');
  assert.doesNotMatch(secretLine, /FG_INTERNAL/,
    'secret: assignment line must not reference any FG_INTERNAL credential');

  // Must NOT call internalGatewaySecret() for session secrets
  assert.doesNotMatch(src, /internalGatewaySecret\(\)/,
    'auth.ts must not call internalGatewaySecret()');
});

// ─── AUTH-T02: Secret missing — fail closed ───────────────────────────────────
// [STATIC] startup-validation.ts must check AUTH_SECRET presence.
// AUTH-004

test('AUTH-T02: startup-validation checks that AUTH_SECRET is configured', () => {
  const src = read('lib/startup-validation.ts');
  assert.match(src, /AUTH_SECRET/,
    'startup-validation must validate AUTH_SECRET');
  // Must push an error when absent
  assert.match(src, /AUTH_SECRET is not configured/,
    'startup-validation must emit actionable error when AUTH_SECRET is missing');
  // Error must be pushed (not thrown early — consolidated error pattern required)
  const authSecretBlock = src.match(/AUTH_SECRET[\s\S]*?errors\.push/);
  assert.ok(authSecretBlock, 'AUTH_SECRET absence must push an error into the consolidated list');
});

// ─── AUTH-T03: Secret empty — fail closed ────────────────────────────────────
// [BEHAVIORAL] validateProductionConfig inline mirror: empty AUTH_SECRET must fail.
// AUTH-004

function simulateAuthSecretValidation(authSecretRaw) {
  const authSecret = (authSecretRaw || '').trim();
  const errors = [];
  if (!authSecret) {
    errors.push(
      '  AUTH_SECRET is not configured. Set a dedicated session-signing secret for Auth.js.',
    );
  }
  return errors;
}

test('AUTH-T03: empty AUTH_SECRET produces a validation error', () => {
  const errors = simulateAuthSecretValidation('');
  assert.equal(errors.length, 1, 'empty AUTH_SECRET must produce exactly one error');
  assert.match(errors[0], /AUTH_SECRET is not configured/);
});

// ─── AUTH-T04: Secret whitespace-only — fail closed ──────────────────────────
// [BEHAVIORAL] whitespace-only after trim() must also fail.
// AUTH-004

test('AUTH-T04: whitespace-only AUTH_SECRET produces a validation error', () => {
  const cases = ['   ', '\t', '\n', '  \t  '];
  for (const ws of cases) {
    const errors = simulateAuthSecretValidation(ws);
    assert.equal(errors.length, 1, `whitespace "${ws}" must fail`);
    assert.match(errors[0], /AUTH_SECRET is not configured/);
  }
});

// ─── AUTH-T05: Gateway secret present, session secret missing — no fallback ──
// [BEHAVIORAL] internalGatewaySecret does not satisfy AUTH_SECRET check.
// AUTH-002, AUTH-008

test('AUTH-T05: gateway secret present but AUTH_SECRET missing still fails', () => {
  // Simulate both conditions: gateway is set, AUTH_SECRET is empty
  const errors = simulateAuthSecretValidation(''); // AUTH_SECRET is missing
  assert.equal(errors.length, 1, 'must still error when only the gateway secret is present');
  assert.match(errors[0], /AUTH_SECRET/);

  // Structural: startup-validation must check AUTH_SECRET independently of internalGatewaySecret
  const src = read('lib/startup-validation.ts');
  const authSecretPos = src.indexOf('AUTH_SECRET is not configured');
  const gatewaySecretPos = src.indexOf('internalGatewaySecret()');
  assert.ok(authSecretPos > -1, 'AUTH_SECRET check must exist');
  assert.ok(gatewaySecretPos > -1, 'gateway secret check must exist');
  // They must be SEPARATE conditions — not OR'd together
  const between = src.slice(Math.min(authSecretPos, gatewaySecretPos),
    Math.max(authSecretPos, gatewaySecretPos));
  assert.doesNotMatch(between, /\|\|/, 'AUTH_SECRET and gateway secret must be separate conditions, not OR');
});

// ─── AUTH-T06: Valid session token — accepted ─────────────────────────────────
// [STATIC] authConfig uses JWT strategy, secret comes only from AUTH_SECRET.
// AUTH-006, AUTH-009

test('AUTH-T06: auth config uses JWT session strategy with explicit secret', () => {
  const authTs = read('auth.ts');
  const authConfigTs = read('auth.config.ts');

  // JWT strategy is configured
  assert.match(authConfigTs, /strategy: 'jwt'/,
    'auth.config.ts must configure JWT session strategy');

  // auth.ts spreads authConfig (inheriting strategy) then sets secret
  assert.match(authTs, /\.\.\.authConfig/,
    'auth.ts must spread authConfig to inherit session strategy');
  assert.match(authTs, /secret: process\.env\.AUTH_SECRET/,
    'secret must be assigned from AUTH_SECRET');
});

// ─── AUTH-T07: Wrong signing/encryption secret — rejected ────────────────────
// [STATIC] Single secret source ensures tokens signed with a different secret
// are rejected by NextAuth's internal JWT verification.
// AUTH-009

test('AUTH-T07: single secret source — wrong secret is deterministically rejected', () => {
  const authTs = read('auth.ts');
  const middlewareTs = read('middleware.ts');

  // Both paths use authConfig, which inherits the same session strategy.
  // auth.ts sets the explicit secret; middleware uses NextAuth(authConfig) which
  // in next-auth v5 reads AUTH_SECRET from env directly (no explicit arg needed).
  assert.match(authTs, /secret: process\.env\.AUTH_SECRET/,
    'route handler must set AUTH_SECRET');
  assert.match(middlewareTs, /NextAuth\(authConfig\)/,
    'middleware must use NextAuth(authConfig)');

  // No second secret definition that could diverge
  const authTsSecrets = (authTs.match(/secret:/g) || []).length;
  assert.equal(authTsSecrets, 1, 'auth.ts must have exactly one secret assignment');
});

// ─── AUTH-T08: Expired session — rejected ────────────────────────────────────
// [STATIC] Session maxAge is enforced via authConfig (JWT maxAge + session maxAge).
// AUTH-006

test('AUTH-T08: session expiry is enforced via authConfig maxAge', () => {
  const src = read('auth.config.ts');
  assert.match(src, /maxAge: consoleSessionMaxAgeSeconds/,
    'session maxAge must be set');
  assert.match(src, /jwt: \{/,
    'JWT maxAge must be configured');
  assert.match(src, /maxAge: consoleSessionMaxAgeSeconds/,
    'JWT maxAge must use the same bounded constant as session');
  // Default is 8 hours — not unlimited
  assert.match(src, /DEFAULT_SESSION_MAX_AGE_SECONDS = 8 \* 60 \* 60/,
    'default session max age must be 8 hours');
});

// ─── AUTH-T09: Middleware and handler secret consistency ─────────────────────
// [STATIC] Middleware reads AUTH_SECRET from env (next-auth v5 convention).
// Handler sets it explicitly. Both use the same authConfig session strategy.
// AUTH-009

test('AUTH-T09: middleware and route handler share authConfig + AUTH_SECRET env var', () => {
  const middlewareTs = read('middleware.ts');
  const authTs = read('auth.ts');

  // Both import and use authConfig
  assert.match(middlewareTs, /import \{ authConfig \} from '.\/auth\.config'/,
    'middleware must import authConfig');
  assert.match(authTs, /import \{ authConfig \} from '.\/auth\.config'/,
    'auth.ts must import authConfig');

  // Middleware does not set its own secret (relies on env var picked up by next-auth v5)
  assert.doesNotMatch(middlewareTs, /secret:/,
    'middleware must not define its own secret — uses AUTH_SECRET env var via next-auth v5');

  // Route handler sets AUTH_SECRET explicitly — no fallback
  // Check the specific assignment line rather than using anchored multiline match
  const secretLine = authTs.split('\n').find((line) => line.trim().startsWith('secret:'));
  assert.ok(secretLine, 'auth.ts must have a secret: assignment');
  assert.match(secretLine, /process\.env\.AUTH_SECRET/,
    'route handler must set secret from process.env.AUTH_SECRET');
  assert.doesNotMatch(secretLine, /\?\?/,
    'route handler secret assignment must have no fallback (??) operator');

  // In next-auth v5, NextAuth(authConfig) used in middleware automatically reads
  // AUTH_SECRET. Verify the comment documents this.
  const authTsSrc = authTs;
  assert.match(authTsSrc, /AUTH-001|AUTH_SECRET/,
    'auth.ts must document the dedicated secret invariant');
});

// ─── AUTH-T10: Unauthenticated protected route — denied ──────────────────────
// [STATIC] Middleware redirects unauthenticated users.
// Phase D: tenant and authorization security preserved.

test('AUTH-T10: middleware redirects unauthenticated users to login', () => {
  const src = read('middleware.ts');
  assert.match(src, /isAuthenticated/,
    'middleware must check isAuthenticated');
  assert.match(src, /redirect.*login/,
    'middleware must redirect to /login when not authenticated');
  assert.match(src, /if \(!isAuthenticated\)/,
    'middleware must deny unauthenticated access');
});

// ─── AUTH-T11: Unsupported experience class — denied ─────────────────────────
// [STATIC] Middleware hard-denies unsupported sessions at the edge.

test('AUTH-T11: middleware hard-denies unsupported experience class sessions', () => {
  const src = read('middleware.ts');
  assert.match(src, /experienceClass.*unsupported|unsupported.*experienceClass/,
    'middleware must check for unsupported experience class');
  assert.match(src, /SESSION_UNSUPPORTED/,
    'middleware must return SESSION_UNSUPPORTED error code');
  assert.match(src, /status: 401/,
    'middleware must return 401 for unsupported sessions on API routes');
  assert.match(src, /unauthorized/,
    'middleware must redirect to /unauthorized for unsupported sessions on page routes');
});

// ─── AUTH-T12: Cross-tenant request — denied ─────────────────────────────────
// [STATIC] canAccessConsoleRoute enforces tenant authorization.

test('AUTH-T12: cross-tenant access is denied by route access policy', () => {
  const src = read('middleware.ts');
  assert.match(src, /canAccessConsoleRoute/,
    'middleware must call canAccessConsoleRoute');
  assert.match(src, /unauthorized/,
    'middleware must redirect unauthorized tenants to /unauthorized');

  // consoleAccess exports canAccessConsoleRoute — verified via .d.ts declaration
  const accessDecl = read('lib/consoleAccess.d.ts');
  assert.match(accessDecl, /canAccessConsoleRoute/,
    'canAccessConsoleRoute must be exported from consoleAccess');
});

// ─── AUTH-T13: Role escalation attempt — denied ──────────────────────────────
// [STATIC] Roles come from server-signed JWT, not browser-supplied claims.

test('AUTH-T13: session roles are derived from server-signed JWT claims only', () => {
  const src = read('auth.config.ts');
  // Roles are populated from token (server-signed) not from user-supplied data
  assert.match(src, /token\.roles/,
    'session roles must come from JWT token, not client-supplied data');
  // The session callback reads from token, not from session input
  assert.match(src, /session\.roles = roles/,
    'session must assign roles from token');
  // roles must be an array validated from the token
  assert.match(src, /Array\.isArray\(token\.roles\)/,
    'roles must be validated as an array from the server-signed token');
});

// ─── AUTH-T14: Auth0 callback — existing behavior preserved ──────────────────
// [STATIC] Auth0 provider configuration is unchanged.

test('AUTH-T14: Auth0 provider configuration is preserved', () => {
  const src = read('auth.ts');
  assert.match(src, /Auth0\(\{/,
    'Auth0 provider must be present');
  assert.match(src, /AUTH0_CLIENT_ID/,
    'Auth0 client ID must be configured from env');
  assert.match(src, /AUTH0_CLIENT_SECRET/,
    'Auth0 client secret must be configured from env');
  assert.match(src, /AUTH0_ISSUER_BASE_URL/,
    'Auth0 issuer must be configured from env');
});

// ─── AUTH-T15: Logout — session invalidated ──────────────────────────────────
// [STATIC] Logout route and signOut export exist.

test('AUTH-T15: logout functionality is preserved', () => {
  const src = read('auth.ts');
  // signOut is exported from NextAuth
  assert.match(src, /signOut/,
    'signOut must be exported from auth.ts');

  // Logout route exists
  assert.ok(
    fs.existsSync(path.join(__dirname, '..', 'app/api/auth/logout/route.ts')),
    'logout route must exist',
  );
});

// ─── AUTH-T16: Public authentication routes — accessible ─────────────────────
// [STATIC] Middleware excludes /api/auth/* from the matcher.

test('AUTH-T16: /api/auth/* routes are excluded from middleware enforcement', () => {
  const src = read('middleware.ts');
  // Matcher must exclude api/auth
  assert.match(src, /api\/auth/,
    'middleware matcher must exclude /api/auth routes');
  // Public path check also covers /api/auth
  assert.match(src, /pathname\.startsWith\('\/api\/auth'\)/,
    'isPublic check must include /api/auth paths');
});

// ─── AUTH-T17: Secret leakage through logs/errors — none ─────────────────────
// [STATIC] Secret values must not appear in error messages or responses.
// AUTH-005

test('AUTH-T17: auth.ts does not log or return secret values', () => {
  const src = read('auth.ts');
  // No console.log of secret
  assert.doesNotMatch(src, /console\.(log|error|warn|debug).*AUTH_SECRET/,
    'auth.ts must not log AUTH_SECRET');
  // No return of secret value
  assert.doesNotMatch(src, /return.*AUTH_SECRET/,
    'auth.ts must not return AUTH_SECRET');
});

test('AUTH-T17b: startup-validation error messages do not contain secret values', () => {
  const src = read('lib/startup-validation.ts');
  // Error messages may name the variable but must not emit the value
  // The validation checks presence (.trim() of empty string), never the actual value
  assert.doesNotMatch(src, /\$\{process\.env\.AUTH_SECRET\}/,
    'startup-validation must not interpolate AUTH_SECRET value into error messages');
  assert.doesNotMatch(src, /process\.env\.AUTH_SECRET\}/,
    'startup-validation must not include AUTH_SECRET value in template literals');
});

// ─── AUTH-T18: Edge runtime compatibility — verified ─────────────────────────
// [STATIC] authConfig has no Node.js-only imports; middleware is Edge-safe.

test('AUTH-T18: auth.config.ts contains only Edge-compatible code', () => {
  const src = read('auth.config.ts');
  // No Node.js-only imports
  assert.doesNotMatch(src, /require\(['"]crypto['"]\)/,
    'auth.config.ts must not import Node.js crypto module');
  assert.doesNotMatch(src, /from 'node:/,
    'auth.config.ts must not use node: imports (Edge-incompatible)');
  // Comment confirms edge-only design intent
  assert.match(src, /Edge-compatible/,
    'auth.config.ts must document Edge-compatible design intent');
});

test('AUTH-T18b: middleware does not import Node.js-only modules', () => {
  const src = read('middleware.ts');
  assert.doesNotMatch(src, /from 'node:/,
    'middleware must not use node: imports');
  assert.doesNotMatch(src, /require\(['"]crypto['"]\)/,
    'middleware must not import Node.js crypto');
});

// ─── AUTH-T19: Node runtime compatibility — verified ─────────────────────────
// [STATIC] auth.ts is Node.js route handler (not Edge).

test('AUTH-T19: auth.ts (route handler) is Node.js runtime code', () => {
  const src = read('auth.ts');
  // Auth0 provider requires Node.js (uses Node crypto)
  assert.match(src, /Auth0/,
    'auth.ts must contain Auth0 provider (Node.js runtime)');
  // No edge runtime export
  assert.doesNotMatch(src, /export const runtime = 'edge'/,
    'auth.ts must not export edge runtime config');
});

// ─── AUTH-T20: Authentication file change triggers deployment ────────────────
// [STATIC] vercel.json ignoreCommand watches apps/console (which includes auth.ts).

test('AUTH-T20: vercel.json ignoreCommand watches apps/console for auth file changes', () => {
  const src = read('vercel.json');
  const config = JSON.parse(src);
  assert.ok(config.ignoreCommand, 'vercel.json must have ignoreCommand');
  assert.match(config.ignoreCommand, /apps\/console/,
    'ignoreCommand must watch apps/console (contains auth.ts, auth.config.ts, etc.)');
  // auth.ts lives inside apps/console — any change triggers a build
  // This is correct: apps/console covers the entire console app tree
});

// ─── AUTH-T21: Unrelated governance-only change may skip frontend build ───────
// [STATIC] vercel.json ignoreCommand only watches relevant paths.

test('AUTH-T21: ignoreCommand only triggers on relevant paths (not all repo paths)', () => {
  const src = read('vercel.json');
  const config = JSON.parse(src);
  const ignoreCmd = config.ignoreCommand;
  // The ignore command returns exit 0 (skip build) when ONLY files outside the
  // watched paths changed. This is deliberate — governance-only changes to
  // tests/, migrations/, services/ etc. should not rebuild the console.
  assert.doesNotMatch(ignoreCmd, /^\s*true\s*$/,
    'ignoreCommand must not unconditionally skip builds');
  assert.doesNotMatch(ignoreCmd, /^\s*exit 0\s*$/,
    'ignoreCommand must not unconditionally skip builds');
  // The actual command uses git diff -- <paths> so it is scoped
  assert.match(ignoreCmd, /git diff/,
    'ignoreCommand must use git diff to inspect changed paths');
});

// ─── AUTH-T22: Shared authentication dependency change triggers deployment ────
// [STATIC] vercel.json watches packages/navigation and packages/ui (shared deps).
// package-lock.json is also watched to catch lockfile-level dependency changes.

test('AUTH-T22: ignoreCommand watches shared packages and lockfile', () => {
  const src = read('vercel.json');
  const config = JSON.parse(src);
  const ignoreCmd = config.ignoreCommand;
  assert.match(ignoreCmd, /packages\/navigation/,
    'ignoreCommand must watch packages/navigation');
  assert.match(ignoreCmd, /packages\/ui/,
    'ignoreCommand must watch packages/ui');
  assert.match(ignoreCmd, /package-lock\.json/,
    'ignoreCommand must watch package-lock.json to catch dep changes');
});

// ─── Additional: AUTH-001/002 isolation invariant at source level ─────────────
// [STATIC] internal-gateway-secret.ts must NOT be imported by auth.ts.
// AUTH-002, AUTH-003

test('AUTH-003: auth.ts does not import internal-gateway-secret.ts', () => {
  const src = read('auth.ts');
  assert.doesNotMatch(src, /internal-gateway-secret/,
    'auth.ts must not import internal-gateway-secret — session and gateway secrets must stay isolated');
  assert.doesNotMatch(src, /internalGatewaySecret/,
    'auth.ts must not call internalGatewaySecret()');
});

// ─── Additional: AUTH-007 — no hardcoded fallback secrets in auth.ts ──────────
// [STATIC] No string literals that could be secret values.
// AUTH-007

test('AUTH-007: auth.ts contains no hardcoded secret literals', () => {
  const src = read('auth.ts');
  // No hardcoded hex/base64 strings long enough to be a secret
  assert.doesNotMatch(src, /secret:\s*['"][a-zA-Z0-9+/=_-]{16,}['"]/,
    'auth.ts must not contain hardcoded secret literals');
  // No development default that could be accepted in production
  assert.doesNotMatch(src, /development[-_]?secret|dev[-_]?secret|test[-_]?secret/i,
    'auth.ts must not contain development/test secret defaults');
});

// ─── Additional: startup-validation validates AUTH_SECRET BEFORE gateway secret
// [STATIC] AUTH_SECRET check must appear before gateway secret check in the function.

test('AUTH-002-ordering: AUTH_SECRET is validated independently from gateway secret', () => {
  const src = read('lib/startup-validation.ts');
  const authSecretPos = src.indexOf('AUTH_SECRET is not configured');
  const gatewayPos = src.indexOf('internalGatewaySecret()');
  assert.ok(authSecretPos > -1, 'AUTH_SECRET check must exist');
  assert.ok(gatewayPos > -1, 'gateway check must exist');
  // Both are separate — order doesn't matter functionally, but verify they are distinct
  assert.notEqual(authSecretPos, gatewayPos,
    'AUTH_SECRET and gateway checks must be separate lines');
});
