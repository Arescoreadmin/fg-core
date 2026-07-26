/**
 * portal-prod-named-user.test.js
 *
 * PR B — Production Portal Named-User Cutover. Static structural tests
 * that assert the production security contracts encoded in the BFF and UI:
 *
 *   - Demo/shared-password login is server-side gated by isProdLikeEnv()
 *   - OIDC callback calls /portal/named-users/enroll (not the legacy
 *     /portal/identity/login path which resolves tenant_users)
 *   - Accept-invite BFF calls /portal/invitations/{token}/accept
 *     (not the legacy /workforce/users/accept-invite path)
 *   - pnu1. cookie is forwarded as X-FG-Portal-Session (no silent fallback
 *     to grant sessions when the token is a pnu1.)
 *   - Session cookie is HttpOnly + SameSite; Core API keys never leak
 *     into the browser (module-scope constants only, no NEXT_PUBLIC_)
 *   - Middleware treats pnu1. cookies as valid without local HMAC
 *     (server-side revalidation happens on every /api/core request)
 */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

// ---------------------------------------------------------------------------
// Demo auth is server-side gated in production
// ---------------------------------------------------------------------------

test('BFF /api/auth/login blocks demo auth server-side when isProdLikeEnv()', () => {
  const src = read('app/api/auth/login/route.ts');
  assert.match(src, /isProdLikeEnv\(\)/);
  assert.match(src, /PORTAL_DEMO_AUTH_DISABLED/);
  // Must return an error status, not fall through silently
  assert.match(src, /status:\s*403/);
});

test('isProdLikeEnv fails closed on missing/unknown FG_ENV', () => {
  const src = read('lib/session.ts');
  assert.match(src, /export function isDevOrTestEnv/);
  assert.match(src, /export function isProdLikeEnv/);
  // Must invert: prod = NOT dev/test (unknown env → prod)
  assert.match(src, /return !isDevOrTestEnv\(\)/);
  assert.match(src, /\['dev', 'development', 'local', 'test'\]/);
});

test('BFF /api/core proxy disables demo tenant steering under isProdLikeEnv()', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.match(src, /isProdLikeEnv/);
  // The demo allowlist branch is guarded
  assert.match(src, /allowDemoTenantSteering/);
});

// ---------------------------------------------------------------------------
// OIDC callback wired to portal_users (PR A), not tenant_users
// ---------------------------------------------------------------------------

test('OIDC callback enrolls via /portal/named-users/enroll (not /portal/identity/login)', () => {
  const src = read('app/api/auth/oidc/callback/route.ts');
  assert.match(src, /\/portal\/named-users\/enroll/);
  // Legacy tenant_users resolution path must NOT be the login target anymore
  assert.doesNotMatch(src, /\/portal\/identity\/login/);
});

test('OIDC callback stores the raw pnu1. session token as the cookie value', () => {
  const src = read('app/api/auth/oidc/callback/route.ts');
  assert.match(src, /session_token/);
  assert.match(src, /startsWith\('pnu1\.'\)/);
  // Cookie must be HttpOnly with SameSite Lax
  assert.match(src, /httpOnly:\s*true/);
  assert.match(src, /sameSite:\s*'lax'/);
});

test('OIDC callback invitation-accept branch does not leak access_token to URL/JS', () => {
  const src = read('app/api/auth/oidc/callback/route.ts');
  assert.match(src, /mode === 'accept'/);
  assert.match(src, /fg_oidc_bootstrap/);
  // The bootstrap cookie carrying the access_token must be HttpOnly
  assert.match(src, /OIDC_BOOTSTRAP_COOKIE[\s\S]*httpOnly:\s*true/);
});

test('OIDC callback accept branch sets from=oidc marker on the redirect (P1-B)', () => {
  // Regression: the /accept-invite page shows "Continue with SSO" until it
  // sees ?from=oidc. Without this marker the page loops back to Auth0
  // forever after invitation acceptance.
  const src = read('app/api/auth/oidc/callback/route.ts');
  assert.match(src, /dest\.searchParams\.set\('from',\s*'oidc'\)/);
});

// ---------------------------------------------------------------------------
// Accept-invite BFF wired to portal named-user acceptance
// ---------------------------------------------------------------------------

test('accept-invite BFF calls /portal/invitations/{token}/accept', () => {
  const src = read('app/api/auth/accept-invite/route.ts');
  assert.match(src, /\/portal\/invitations\/\$\{encoded\}\/accept/);
  // Legacy workforce path must NOT be present
  assert.doesNotMatch(src, /\/workforce\/users\/accept-invite/);
});

test('accept-invite BFF rejects tokens that do not have pni1. prefix', () => {
  const src = read('app/api/auth/accept-invite/route.ts');
  assert.match(src, /startsWith\('pni1\.'\)/);
  assert.match(src, /INVITE_TOKEN_FORMAT/);
});

test('accept-invite BFF consumes and clears the OIDC bootstrap cookie', () => {
  const src = read('app/api/auth/accept-invite/route.ts');
  assert.match(src, /fg_oidc_bootstrap/);
  assert.match(src, /request\.cookies\.get\(OIDC_BOOTSTRAP_COOKIE\)/);
  assert.match(src, /response\.cookies\.delete\(OIDC_BOOTSTRAP_COOKIE\)/);
});

test('accept-invite BFF sets the pnu1. session cookie on success', () => {
  const src = read('app/api/auth/accept-invite/route.ts');
  assert.match(src, /startsWith\('pnu1\.'\)/);
  assert.match(src, /response\.cookies\.set\(COOKIE_NAME/);
  assert.match(src, /httpOnly:\s*true/);
  assert.match(src, /sameSite:\s*'lax'/);
});

// ---------------------------------------------------------------------------
// BFF proxy: no silent grant fallback for pnu1. cookies
// ---------------------------------------------------------------------------

test('BFF proxy prefers pnu1. cookie over grant session — no silent fallback', () => {
  const src = read('app/api/core/[...path]/route.ts');
  assert.match(src, /getPnuSessionToken/);
  // When pnuToken is present, sessionUser + grantSession must be short-circuited
  assert.match(src, /pnuToken \? null : await getSessionUser/);
  assert.match(src, /pnuToken \? null : await getGrantSession/);
});

test('BFF proxy forwards the raw pnu1. token as X-FG-Portal-Session', () => {
  const src = read('app/api/core/[...path]/route.ts');
  // Must set X-FG-Portal-Session to the pnu token (not the legacy sessionId)
  assert.match(src, /headers\.set\('X-FG-Portal-Session', pnuToken\)/);
});

// ---------------------------------------------------------------------------
// Session cookie discipline
// ---------------------------------------------------------------------------

test('verifySessionToken enforces pnu1. token format at the edge (P1-A defense-in-depth)', () => {
  const src = read('lib/session.ts');
  // Format check (64 hex chars) short-circuits verify. Core still owns the
  // authoritative fingerprint validation; this rejects trivially malformed
  // tokens before they reach the /api/core proxy.
  assert.match(src, /export const PNU_TOKEN_RE = \/\^pnu1\\\.\[0-9a-f\]\{64\}\$\//);
  assert.match(src, /if \(isPnuSessionCookie\(token\)\) return isPnuSessionCookieWellFormed\(token\)/);
});

test('lib/session exports pnu1. discriminator helpers', () => {
  const src = read('lib/session.ts');
  assert.match(src, /export const PNU_TOKEN_PREFIX = 'pnu1\.'/);
  assert.match(src, /export function isPnuSessionCookie/);
  assert.match(src, /export function getPnuSessionToken/);
});

// ---------------------------------------------------------------------------
// No Core API key ever ships to the browser
// ---------------------------------------------------------------------------

test('Core API keys are read only via process.env in server routes — no NEXT_PUBLIC_ leakage', () => {
  // Enumerate all BFF and lib files that touch CORE_API_KEY; assert they are
  // not client-side entrypoints and none of them are prefixed NEXT_PUBLIC_.
  const files = [
    'app/api/auth/login/route.ts',
    'app/api/auth/accept-invite/route.ts',
    'app/api/auth/oidc/callback/route.ts',
    'app/api/core/[...path]/route.ts',
    'lib/tenant-registry.ts',
  ];
  for (const rel of files) {
    const src = read(rel);
    assert.doesNotMatch(src, /NEXT_PUBLIC_CORE_API_KEY/, `${rel} exposes core API key to browser`);
    assert.doesNotMatch(src, /NEXT_PUBLIC_.*_KEY/, `${rel} exposes a key env var to browser`);
  }
});

test('Login page renders only the named-user panel when NEXT_PUBLIC_FG_ENV=prod', () => {
  const src = read('app/login/page.tsx');
  assert.match(src, /NEXT_PUBLIC_FG_ENV/);
  assert.match(src, /IS_PROD_UI/);
  // Production branch must NOT include the DemoLoginForm component
  assert.match(src, /if \(IS_PROD_UI\) return <NamedUserLoginPanel \/>/);
  // OIDC entrypoint present
  assert.match(src, /\/api\/auth\/oidc/);
});

test('OIDC init route validates invite token format before Auth0 redirect', () => {
  const src = read('app/api/auth/oidc/route.ts');
  assert.match(src, /pni1\\\.\[0-9a-f\]\{64\}/);
  assert.match(src, /PORTAL_ACCEPT_TOKEN_INVALID/);
  assert.match(src, /PORTAL_ACCEPT_TENANT_INVALID/);
});

test('Accept-invite BFF clears bootstrap cookie on terminal invitation errors', () => {
  const src = read('app/api/auth/accept-invite/route.ts');
  assert.match(src, /\[404,\s*409,\s*410\]\.includes\(upstream\.status\)/);
  assert.match(src, /errRes\.cookies\.delete\(OIDC_BOOTSTRAP_COOKIE\)/);
});

test('Accept-invite page redirects to OIDC before hitting the acceptance endpoint', () => {
  const src = read('app/accept-invite/page.tsx');
  assert.match(src, /\/api\/auth\/oidc/);
  assert.match(src, /mode=accept/);
  // On second hop (from=oidc) it POSTs to the acceptance BFF
  assert.match(src, /\/api\/auth\/accept-invite/);
  assert.match(src, /searchParams\.get\('from'\)\s*===\s*'oidc'/);
});

// ---------------------------------------------------------------------------
// Middleware still gates non-public routes
// ---------------------------------------------------------------------------

test('middleware public prefixes cover both /login, /accept-invite, and /api/auth', () => {
  const src = read('middleware.ts');
  assert.match(src, /'\/login'/);
  assert.match(src, /'\/api\/auth'/);
  assert.match(src, /'\/accept-invite'/);
});
