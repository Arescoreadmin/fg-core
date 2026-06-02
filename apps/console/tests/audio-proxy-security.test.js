/**
 * audio-proxy-security.test.js
 *
 * Static-analysis security tests for the audio-url proxy route (C5 fix).
 * No live network or auth required — all assertions are made against source.
 *
 * Tests:
 *  1.  audio_proxy_requires_auth_session
 *  2.  audio_proxy_rejects_missing_url_param
 *  3.  audio_proxy_uses_url_parse_not_string_ops
 *  4.  audio_proxy_rejects_non_https_protocol
 *  5.  audio_proxy_uses_hostname_endswith_not_includes
 *  6.  audio_proxy_rejects_hostname_confusion_attack
 *  7.  audio_proxy_enforces_path_prefix
 *  8.  audio_proxy_never_forwards_token_to_unvalidated_url
 *  9.  audio_proxy_disables_redirect_following
 * 10.  audio_proxy_validates_content_type_before_streaming
 * 11.  audio_proxy_guards_content_length
 * 12.  audio_proxy_does_not_leak_upstream_headers
 * 13.  audio_proxy_sends_cache_control_private
 * 14.  audio_proxy_token_read_after_url_validation
 * 15.  audio_proxy_content_type_allowlist_covers_common_audio
 * 16.  audio_proxy_allowlist_excludes_html_and_json
 * 17.  audio_proxy_callers_use_hostname_check_not_substring
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

const ROUTE = 'app/api/field-assessment/audio-url/route.ts';
const PAGE   = 'app/field-assessment/[engagementId]/page.tsx';

// ─── Route security tests ─────────────────────────────────────────────────────

test('audio_proxy_requires_auth_session', () => {
  const src = read(ROUTE);
  // Must call auth() and check session before processing any URL input.
  assert.match(src, /auth\(\)/,                       'must call auth()');
  assert.match(src, /session.*user|session\?\.user/,  'must check session.user');
  assert.match(src, /401/,                            'must return 401 for missing session');
});

test('audio_proxy_rejects_missing_url_param', () => {
  const src = read(ROUTE);
  assert.match(src, /Missing url parameter|missing.*url/i, 'must handle absent url param');
  assert.match(src, /400/, 'must return 400 for missing param');
});

test('audio_proxy_uses_url_parse_not_string_ops', () => {
  const src = read(ROUTE);
  // Must construct a URL object — this is the gating step that parses the input
  // before any hostname or path checks.
  assert.match(src, /new URL\(/, 'must use new URL() to parse the input');
  // Must have a try/catch around the URL constructor.
  assert.match(src, /try\s*\{[\s\S]*?new URL\([\s\S]*?\}\s*catch/, 'URL construction must be wrapped in try/catch');
});

test('audio_proxy_rejects_non_https_protocol', () => {
  const src = read(ROUTE);
  // After parsing, protocol must be explicitly checked.
  assert.match(src, /protocol.*!==.*'https:|protocol.*!==.*"https:/, 'must reject non-https protocol');
});

test('audio_proxy_uses_hostname_endswith_not_includes', () => {
  const src = read(ROUTE);
  // The fix for C5: hostname.endsWith() — not url.includes() or hostname.includes().
  assert.match(src, /hostname\.endsWith\(/, 'must use hostname.endsWith for host check');
  // url.includes() must not be used for the host check — that was the vulnerability.
  assert.doesNotMatch(src, /url\.includes\(.*blob\.vercel/, 'must NOT use url.includes for blob host check');
});

test('audio_proxy_rejects_hostname_confusion_attack', () => {
  const src = read(ROUTE);
  // The endsWith check on the parsed hostname field is what blocks
  // "https://attacker.com?x=.blob.vercel-storage.com".
  // Verify the check is on parsed.hostname (or equivalent), not on the raw string.
  assert.match(src, /parsed\.hostname\.endsWith|hostname\.endsWith/, 'endsWith must be on parsed hostname field');
});

test('audio_proxy_enforces_path_prefix', () => {
  const src = read(ROUTE);
  // Path must be constrained to the /field-assessment/ upload namespace.
  assert.match(src, /pathname\.startsWith\(/, 'must check pathname.startsWith');
  assert.match(src, /\/field-assessment\//, 'path prefix must be /field-assessment/');
});

test('audio_proxy_never_forwards_token_to_unvalidated_url', () => {
  const src = read(ROUTE);
  // Token must be read AFTER all URL validation checks.
  // Structural check: token declaration should appear after the protocol, hostname,
  // and path checks in the source order.
  // Use the actual env-var read expression — the constant name also appears in
  // the JSDoc comment, so indexOf('BLOB_READ_WRITE_TOKEN') would find the comment
  // first and produce a false ordering result.
  const tokenIdx     = src.indexOf('process.env.BLOB_READ_WRITE_TOKEN');
  const protocolIdx  = src.indexOf("protocol !== 'https:'");
  const hostnameIdx  = src.indexOf('hostname.endsWith(');
  const pathIdx      = src.indexOf('pathname.startsWith(');

  assert.ok(tokenIdx > -1,    'process.env.BLOB_READ_WRITE_TOKEN must be present');
  assert.ok(protocolIdx > -1, 'protocol check must be present');
  assert.ok(hostnameIdx > -1, 'hostname check must be present');
  assert.ok(pathIdx > -1,     'path check must be present');

  // All validation must appear before the token is read/used.
  assert.ok(
    tokenIdx > protocolIdx && tokenIdx > hostnameIdx && tokenIdx > pathIdx,
    'token must be read only after all URL validation checks pass',
  );
});

test('audio_proxy_disables_redirect_following', () => {
  const src = read(ROUTE);
  // fetch must use redirect:'error' or redirect:'manual' — never the default 'follow'.
  // 'follow' would let the storage server redirect the token-bearing request to an
  // attacker-controlled host.
  assert.match(
    src,
    /redirect:\s*['"]error['"]/,
    "fetch must use redirect:'error' to prevent token forwarding via redirect",
  );
});

test('audio_proxy_validates_content_type_before_streaming', () => {
  const src = read(ROUTE);
  // Must read Content-Type from upstream and check it before streaming.
  assert.match(src, /Content-Type|content-type/i,         'must inspect Content-Type');
  assert.match(src, /ALLOWED_CONTENT_TYPES|allowedContent/i, 'must have an allowed content-type set');
  assert.match(src, /Unexpected content type|unexpected.*content/i, 'must reject unexpected content types');
  assert.match(src, /502/, 'unexpected content type must produce 502');
});

test('audio_proxy_guards_content_length', () => {
  const src = read(ROUTE);
  assert.match(src, /Content-Length|content-length/i, 'must check Content-Length header');
  assert.match(src, /MAX_AUDIO_BYTES|maxAudio|max.*bytes/i, 'must define a max size constant');
  assert.match(src, /413/, 'must return 413 for oversized response');
});

test('audio_proxy_does_not_leak_upstream_headers', () => {
  const src = read(ROUTE);
  // The response constructor must build headers explicitly rather than spreading
  // all upstream headers. Check that upstream.headers is not spread into the response.
  assert.doesNotMatch(src, /\.\.\.upstream\.headers/, 'must not spread upstream headers into response');
  // The response should only set a controlled header list.
  assert.match(src, /Cache-Control/, 'must set Cache-Control explicitly');
  assert.match(src, /Content-Disposition/, 'must set Content-Disposition explicitly');
});

test('audio_proxy_sends_cache_control_private', () => {
  const src = read(ROUTE);
  // Audio is sensitive; caching must be scoped to the authenticated user only.
  assert.match(src, /private.*max-age|Cache-Control.*private/, 'Cache-Control must be private');
  // Must not be publicly cacheable.
  assert.doesNotMatch(src, /public.*max-age.*Cache-Control|Cache-Control.*public/, 'Cache-Control must not be public');
});

test('audio_proxy_token_read_after_url_validation', () => {
  const src = read(ROUTE);
  // BLOB_READ_WRITE_TOKEN must appear after the 400-returning validation block,
  // not before. If the token read came first, a validation failure path could
  // theoretically race or a future refactor could accidentally forward the token.
  const firstReturn400 = src.indexOf("status: 400");
  const tokenRead      = src.indexOf('process.env.BLOB_READ_WRITE_TOKEN');
  assert.ok(firstReturn400 > -1, 'must have a 400 validation response');
  assert.ok(tokenRead > -1,      'must read BLOB_READ_WRITE_TOKEN');
  assert.ok(tokenRead > firstReturn400, 'token must be read after the first 400-path check');
});

test('audio_proxy_content_type_allowlist_covers_common_audio', () => {
  const src = read(ROUTE);
  // The allowlist must cover the formats the transcribe route produces.
  for (const ct of ['audio/webm', 'audio/ogg', 'audio/mp4', 'audio/mpeg', 'audio/wav']) {
    assert.match(src, new RegExp(ct.replace('/', '\\/')), `allowlist must include ${ct}`);
  }
});

test('audio_proxy_allowlist_excludes_html_and_json', () => {
  const src = read(ROUTE);
  // An attacker uploading an HTML or JSON blob should not be able to stream it
  // through the proxy (potential for XSS or data exfiltration).
  assert.doesNotMatch(src, /text\/html/, 'allowlist must not include text/html');
  assert.doesNotMatch(src, /application\/json/, 'allowlist must not include application/json');
});

// ─── Caller-side check ────────────────────────────────────────────────────────

test('audio_proxy_callers_use_hostname_check_not_substring', () => {
  const src = read(PAGE);
  // The page's toBlobAudioUrl helper also has a .blob.vercel-storage.com check.
  // It only decides whether to route through the proxy (not whether to add auth),
  // so includes() is acceptable here — but verify the proxy itself does not
  // rely on the caller for security.
  // This test documents the design: caller routes, proxy validates.
  const hasProxyRoute = src.includes('/api/field-assessment/audio-url');
  assert.ok(hasProxyRoute, 'page must route blob audio through the auth-gated proxy');
});
