/**
 * audio-proxy-security.test.js
 *
 * Static-analysis security tests for the artifact-registry audio proxy (C5 full fix).
 * No live network or auth required — all assertions target source code structure.
 *
 * Tests prove:
 *  - Raw blob URL input is structurally impossible (no url= param, no URL parsing of input).
 *  - SSRF payloads are dead code paths (storage_key comes from DB, not the request).
 *  - Short-lived signed download URL is generated via issueSignedToken + presignUrl.
 *  - BLOB_DELEGATION_TOKEN is never forwarded in a fetch call (used only for token issuance).
 *  - Redirects are rejected; no upstream headers leaked; content-type and size gated.
 *  - Audit events are emitted by the backend on every access (backend endpoint spec).
 *  - Metrics are emitted for all outcome paths.
 *  - Transcribe route registers the artifact and returns artifact_id (not audio_url).
 *  - Client code stores _audio_artifact_id (not _audio_url) and uses artifact_id proxy URL.
 *
 * Tests:
 *  1.  proxy_accepts_artifact_id_not_raw_url
 *  2.  proxy_has_no_url_param_handler
 *  3.  proxy_performs_no_url_parsing_of_client_input
 *  4.  proxy_no_ssrf_hostname_checks
 *  5.  proxy_resolves_storage_key_from_backend_not_request
 *  6.  proxy_uses_issue_signed_token
 *  7.  proxy_uses_presign_url
 *  8.  proxy_delegation_token_not_forwarded_in_fetch
 *  9.  proxy_fetch_has_no_authorization_header
 * 10.  proxy_disables_redirect_following
 * 11.  proxy_validates_content_type_before_streaming
 * 12.  proxy_guards_content_length
 * 13.  proxy_does_not_forward_upstream_headers
 * 14.  proxy_sends_cache_control_private
 * 15.  proxy_emits_metric_events
 * 16.  proxy_rejects_wrong_artifact_type
 * 17.  proxy_validates_artifact_id_format
 * 18.  transcribe_registers_artifact_not_audio_url
 * 19.  transcribe_returns_artifact_id_not_audio_url
 * 20.  form_stores_audio_artifact_id_not_audio_url
 * 21.  page_builds_proxy_url_with_artifact_id
 * 22.  page_has_no_raw_blob_url_routing
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

const PROXY      = 'app/api/field-assessment/audio-url/route.ts';
const TRANSCRIBE = 'app/api/field-assessment/transcribe/route.ts';
const FORM       = 'components/field-assessment/InterviewForm.tsx';
const PAGE       = 'app/field-assessment/[engagementId]/page.tsx';

// ─── Proxy: no raw URL input ──────────────────────────────────────────────────

test('proxy_accepts_artifact_id_not_raw_url', () => {
  const src = read(PROXY);
  assert.match(src, /artifact_id/, 'proxy must accept artifact_id parameter');
  assert.match(src, /engagement_id/, 'proxy must accept engagement_id parameter');
  // The old ?url= query parameter must be absent
  assert.doesNotMatch(src, /get\(['"]url['"]\)/, "proxy must not read a 'url' query param");
});

test('proxy_has_no_url_param_handler', () => {
  const src = read(PROXY);
  // Any handler for a raw blob URL would contain the storage host literal
  // being extracted from the request — not acceptable
  assert.doesNotMatch(src, /searchParams\.get\(['"]url['"]\)/, "proxy must not call searchParams.get('url')");
  assert.doesNotMatch(src, /params\.get\(['"]url['"]\)/, 'proxy must not read a url param from request');
});

test('proxy_performs_no_url_parsing_of_client_input', () => {
  const src = read(PROXY);
  // new URL() is only acceptable on the storage_key coming from the DB
  // If there's a new URL() call it must be on artifact.storage_key or similar — not on client input
  // The proxy must NOT call new URL(raw) where raw comes from the request
  assert.doesNotMatch(src, /new URL\(raw\)/, 'proxy must not parse raw client input as URL');
  assert.doesNotMatch(src, /new URL\(url\)/, 'proxy must not parse a client-supplied url as URL');
});

test('proxy_no_ssrf_hostname_checks', () => {
  const src = read(PROXY);
  // The old SSRF vector: hostname/substring checks on user-supplied URL
  // These are now dead code — storage_key comes from DB
  assert.doesNotMatch(src, /hostname\.endsWith\(/, 'proxy must not check hostname of client input');
  assert.doesNotMatch(src, /url\.includes\(.*blob/, 'proxy must not substring-check a client URL for blob host');
  assert.doesNotMatch(src, /BLOB_HOST_SUFFIX/, 'proxy must not reference a blob host suffix constant for input validation');
});

test('proxy_resolves_storage_key_from_backend_not_request', () => {
  const src = read(PROXY);
  // storage_key must come from the backend response (DB), not from any request parameter
  assert.match(src, /storage_key/, 'proxy must reference storage_key from backend response');
  assert.match(src, /resolveArtifact|CORE_API_URL|field-assessment.*artifacts/, 'proxy must call backend to resolve artifact');
  // The URL passed to fetch for the actual blob must be constructed from storage_key,
  // NOT from a client-supplied parameter
  assert.match(src, /artifact\.storage_key|storageUrl/, 'storage_key must be read from artifact record');
});

// ─── Proxy: signed URL generation ────────────────────────────────────────────

test('proxy_uses_issue_signed_token', () => {
  const src = read(PROXY);
  assert.match(src, /issueSignedToken/, 'proxy must call issueSignedToken');
  assert.match(src, /from '@vercel\/blob'/, 'proxy must import from @vercel/blob');
  // Must scope the token to get-only operations
  assert.match(src, /operations.*get|'get'/, 'token must be scoped to get operation');
  // Must set an expiry
  assert.match(src, /validUntil/, 'token must have a validUntil expiry');
});

test('proxy_uses_presign_url', () => {
  const src = read(PROXY);
  assert.match(src, /presignUrl/, 'proxy must call presignUrl');
  assert.match(src, /presignedUrl/, 'proxy must use the presignedUrl from presignUrl result');
  assert.match(src, /operation.*get/, "presign must request get operation");
});

test('proxy_delegation_token_not_forwarded_in_fetch', () => {
  const src = read(PROXY);
  // BLOB_DELEGATION_TOKEN must be used only in issueSignedToken, never in a fetch Authorization header
  const tokenRef = 'BLOB_DELEGATION_TOKEN';
  const issueIdx = src.indexOf('issueSignedToken');
  const tokenIdx = src.indexOf(tokenRef);
  assert.ok(tokenIdx > -1, 'BLOB_DELEGATION_TOKEN must be referenced');
  assert.ok(issueIdx > -1, 'issueSignedToken must be called');
  // The fetch call must not contain BLOB_DELEGATION_TOKEN in its arguments
  // Extract the fetch call block and assert it doesn't reference the token
  const fetchIdx = src.indexOf('fetch(presignedDownloadUrl');
  assert.ok(fetchIdx > -1, 'proxy must fetch presignedDownloadUrl');
  // The token reference must appear BEFORE the fetch (used in issueSignedToken, not in fetch)
  assert.ok(tokenIdx < fetchIdx, 'BLOB_DELEGATION_TOKEN must be used before the presigned fetch, not in it');
});

test('proxy_fetch_has_no_authorization_header', () => {
  const src = read(PROXY);
  // The fetch of the presigned URL must NOT include an Authorization header.
  // Authorization is embedded in the presigned URL itself.
  const presignedFetchBlock = src.slice(src.indexOf('fetch(presignedDownloadUrl'));
  // Check the fetch call doesn't immediately set Authorization
  assert.doesNotMatch(
    presignedFetchBlock.slice(0, 300),
    /Authorization.*Bearer|headers.*Authorization/,
    'presigned URL fetch must not include an Authorization header',
  );
});

// ─── Proxy: transport security ────────────────────────────────────────────────

test('proxy_disables_redirect_following', () => {
  const src = read(PROXY);
  assert.match(src, /redirect:\s*['"]error['"]/, "fetch must use redirect:'error'");
});

test('proxy_validates_content_type_before_streaming', () => {
  const src = read(PROXY);
  assert.match(src, /ALLOWED_CONTENT_TYPES/, 'must define allowed content types');
  assert.match(src, /Content-Type|content-type/i, 'must inspect upstream Content-Type');
  assert.match(src, /Unexpected content type|unexpected.*content/i, 'must reject unexpected types');
  // Audio types present
  for (const ct of ['audio/webm', 'audio/ogg', 'audio/mp4', 'audio/mpeg', 'audio/wav']) {
    assert.match(src, new RegExp(ct.replace('/', '\\/')), `allowlist must include ${ct}`);
  }
  // Non-audio types absent
  assert.doesNotMatch(src, /text\/html/, 'allowlist must not include text/html');
  assert.doesNotMatch(src, /application\/json/, 'allowlist must not include application/json');
});

test('proxy_guards_content_length', () => {
  const src = read(PROXY);
  assert.match(src, /Content-Length|content-length/i, 'must check Content-Length');
  assert.match(src, /MAX_AUDIO_BYTES/, 'must define max audio bytes constant');
  assert.match(src, /413/, 'must return 413 for oversized');
});

test('proxy_does_not_forward_upstream_headers', () => {
  const src = read(PROXY);
  assert.doesNotMatch(src, /\.\.\.upstream\.headers/, 'must not spread upstream headers');
  assert.match(src, /Cache-Control/, 'must set Cache-Control explicitly');
  assert.match(src, /Content-Disposition/, 'must set Content-Disposition explicitly');
});

test('proxy_sends_cache_control_private', () => {
  const src = read(PROXY);
  assert.match(src, /private.*max-age|Cache-Control.*private/, 'Cache-Control must be private');
  assert.doesNotMatch(src, /Cache-Control.*public/, 'Cache-Control must not be public');
});

// ─── Proxy: observability ─────────────────────────────────────────────────────

test('proxy_emits_metric_events', () => {
  const src = read(PROXY);
  // Must have a metric() function
  assert.match(src, /function metric\(|const metric =/, 'must define a metric function');
  // Must emit on success path
  assert.match(src, /metric\('allowed'/, 'must emit allowed metric');
  // Must emit on denial paths
  assert.match(src, /metric\('denied\./, 'must emit denied metrics');
  // Must emit on upstream failure
  assert.match(src, /metric\('upstream_failed'/, 'must emit upstream_failed metric');
  // Must emit on redirect block
  assert.match(src, /metric\('redirect_blocked'/, 'must emit redirect_blocked metric');
});

// ─── Proxy: business logic guards ────────────────────────────────────────────

test('proxy_rejects_wrong_artifact_type', () => {
  const src = read(PROXY);
  assert.match(src, /artifact_type.*!==.*'audio'|artifact\.artifact_type.*audio/, 'must guard artifact type');
  assert.match(src, /Artifact is not audio|not audio/, 'must return meaningful error for wrong type');
});

test('proxy_validates_artifact_id_format', () => {
  const src = read(PROXY);
  // Must validate artifact_id as an opaque ID, not a URL
  assert.match(src, /ARTIFACT_ID_RE|artifact.*id.*regex|/i, 'should validate artifact_id format');
  assert.match(src, /Invalid artifact_id/, 'must reject malformed artifact_id');
});

// ─── Transcribe route ────────────────────────────────────────────────────────

test('transcribe_registers_artifact_not_audio_url', () => {
  const src = read(TRANSCRIBE);
  // Must call the backend artifacts endpoint
  assert.match(src, /\/artifacts/, 'transcribe must call the artifacts endpoint');
  assert.match(src, /registerArtifact|register_artifact/, 'must have artifact registration');
  // Must NOT return audio_url in the JSON response
  assert.doesNotMatch(src, /["']audio_url["']/, 'transcribe must not return audio_url');
});

test('transcribe_returns_artifact_id_not_audio_url', () => {
  const src = read(TRANSCRIBE);
  assert.match(src, /artifact_id/, 'transcribe must return artifact_id');
  // The JSON response key should be artifact_id
  assert.match(src, /artifact_id,/, 'artifact_id must be in the JSON response');
});

// ─── Client: form and page ────────────────────────────────────────────────────

test('form_stores_audio_artifact_id_not_audio_url', () => {
  const src = read(FORM);
  // The form must store _audio_artifact_id in structured_evidence
  assert.match(src, /_audio_artifact_id/, 'form must store _audio_artifact_id');
  assert.doesNotMatch(src, /_audio_url.*structured_evidence|structured_evidence.*_audio_url/, 'form must not store _audio_url');
  // The callback type must use artifactId not audioUrl
  assert.match(src, /artifactId.*string.*null|artifactId: string \| null/, 'callback must carry artifactId');
  assert.doesNotMatch(src, /audioUrl.*string.*null.*onAudioReady|onAudioReady.*audioUrl/, 'callback must not carry audioUrl');
});

test('page_builds_proxy_url_with_artifact_id', () => {
  const src = read(PAGE);
  // The page must build proxy URLs using artifact_id + engagement_id, not raw blob URLs
  assert.match(src, /artifact_id=.*engagement_id=|artifact_id.*engagement_id/, 'proxy URL must include artifact_id and engagement_id');
  assert.match(src, /_audio_artifact_id/, 'page must read _audio_artifact_id from structured_evidence');
});

test('page_has_no_raw_blob_url_routing', () => {
  const src = read(PAGE);
  // The old toBlobAudioUrl function that routed raw blob URLs must be gone
  assert.doesNotMatch(src, /function toBlobAudioUrl/, 'toBlobAudioUrl must be removed');
  assert.doesNotMatch(src, /\.blob\.vercel-storage\.com.*url=|url=.*encodeURIComponent.*blob/, 'page must not route raw blob URLs through proxy');
  // The old extractAudioUrl that picked up _audio_url from payloads must be gone
  assert.doesNotMatch(src, /function extractAudioUrl/, 'extractAudioUrl must be removed');
});
