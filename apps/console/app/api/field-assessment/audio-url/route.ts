import { NextRequest } from 'next/server';
import { issueSignedToken, presignUrl } from '@vercel/blob';
import { auth } from '@/auth';

// Private blob audio can be large (up to 25 MB); allow enough time to stream.
export const maxDuration = 30;

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.FG_CORE_API_KEY ?? process.env.CORE_API_KEY;
const CORE_TENANT_ID = process.env.CORE_TENANT_ID;

// BLOB_DELEGATION_TOKEN is used only to issue a short-lived, path-scoped signed
// URL via issueSignedToken + presignUrl. The actual blob fetch uses the presigned
// URL and requires no bearer token. Operators should set this to the minimum-
// privilege credential available; set to BLOB_READ_WRITE_TOKEN if no read-only
// credential is available on the current Vercel Blob plan.
const BLOB_DELEGATION_TOKEN = process.env.BLOB_DELEGATION_TOKEN ?? process.env.BLOB_READ_WRITE_TOKEN;

const MAX_AUDIO_BYTES = 25 * 1024 * 1024; // 25 MB — Whisper hard limit

// Content-types we will stream. Anything else is rejected before the body is touched.
const ALLOWED_CONTENT_TYPES = new Set([
  'audio/webm',
  'audio/ogg',
  'audio/mp4',
  'audio/mpeg',
  'audio/wav',
  'audio/x-wav',
  'audio/aac',
  'audio/flac',
  'application/octet-stream',
]);

// Opaque ID characters: UUID-style hex + hyphens, max 64 chars.
const ARTIFACT_ID_RE = /^[0-9a-f-]{1,64}$/i;
const ENGAGEMENT_ID_RE = /^[0-9a-zA-Z_-]{1,64}$/;

// Structured metric event — captured by log aggregator (Vercel Log Drains or similar).
function metric(event: string, props: Record<string, string | number | null>) {
  console.log(JSON.stringify({ _metric: 'audio_proxy', event, ...props, ts: Date.now() }));
}

interface ArtifactRecord {
  id: string;
  artifact_type: string;
  storage_key: string;
  content_type: string | null;
  size_bytes: number | null;
}

/**
 * Resolve artifact metadata from the FA backend.
 *
 * The backend enforces: tenant ownership, engagement ownership, not-deleted.
 * It also emits an immutable FA audit event on every access (success and denial).
 * We do not perform any URL construction from client input here — the storage_key
 * comes entirely from the trusted backend database.
 */
async function resolveArtifact(
  artifactId: string,
  engagementId: string,
): Promise<ArtifactRecord | null> {
  if (!CORE_API_KEY || !CORE_TENANT_ID) return null;

  let res: Response;
  try {
    res = await fetch(
      `${CORE_API_URL}/field-assessment/engagements/${encodeURIComponent(engagementId)}/artifacts/${encodeURIComponent(artifactId)}?tenant_id=${encodeURIComponent(CORE_TENANT_ID)}`,
      {
        headers: { 'X-API-Key': CORE_API_KEY },
      },
    );
  } catch {
    return null;
  }

  if (!res.ok) return null;

  try {
    return (await res.json()) as ArtifactRecord;
  } catch {
    return null;
  }
}

/**
 * GET /api/field-assessment/audio-url?artifact_id=<id>&engagement_id=<id>
 *
 * Artifact-registry-based audio proxy. Clients submit an opaque artifact_id;
 * raw blob URLs are never accepted as input. The storage_key is resolved
 * server-side from the trusted FA backend database, never from the request.
 *
 * Security model:
 *  1. Session required — unauthenticated callers receive 401.
 *  2. artifact_id validated as opaque hex ID (no URL parsing of client input).
 *  3. engagement_id validated as safe identifier string.
 *  4. Backend resolves artifact: enforces tenant_id + engagement_id ownership,
 *     deleted_at guard, and emits an immutable audit event on every access.
 *  5. Proxy validates artifact_type === 'audio' (wrong type rejected).
 *  6. storage_key comes from the backend database — it is never user-supplied.
 *     SSRF via crafted URLs is structurally impossible.
 *  7. issueSignedToken scopes a short-lived delegation (60 s) to the exact
 *     blob pathname. presignUrl generates a self-authenticated URL.
 *  8. The actual blob fetch uses the presigned URL — no bearer token in the
 *     fetch call itself (BLOB_DELEGATION_TOKEN is used only for issueSignedToken).
 *  9. redirect:'error' — any redirect from the storage provider is rejected.
 * 10. Upstream Content-Type validated against audio-only allowlist before streaming.
 * 11. Content-Length validated against MAX_AUDIO_BYTES.
 * 12. Only a minimal, controlled set of headers is set downstream.
 * 13. Metric events emitted for every outcome (allowed / denied / upstream-failed).
 */
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    metric('denied.unauthenticated', {});
    return new Response('Unauthorized', { status: 401 });
  }

  const artifactId = req.nextUrl.searchParams.get('artifact_id');
  const engagementId = req.nextUrl.searchParams.get('engagement_id');

  // Validate ID shapes — no URL parsing of client input at any point.
  if (!artifactId || !ARTIFACT_ID_RE.test(artifactId)) {
    metric('denied.invalid_artifact_id', { artifact_id: artifactId ?? '' });
    return new Response('Invalid artifact_id', { status: 400 });
  }
  if (!engagementId || !ENGAGEMENT_ID_RE.test(engagementId)) {
    metric('denied.invalid_engagement_id', { engagement_id: engagementId ?? '' });
    return new Response('Invalid engagement_id', { status: 400 });
  }

  if (!CORE_API_KEY || !CORE_TENANT_ID) {
    metric('denied.misconfigured', { reason: 'missing_backend_config' });
    return new Response('Backend not configured', { status: 503 });
  }

  // Resolve artifact from trusted backend. Backend enforces tenant/engagement
  // ownership and emits audit events; we trust its response unconditionally.
  const artifact = await resolveArtifact(artifactId, engagementId);
  if (!artifact) {
    metric('denied.artifact_not_found', { artifact_id: artifactId, engagement_id: engagementId });
    return new Response('Artifact not found', { status: 404 });
  }

  // Type guard — only audio artifacts may be streamed through this route.
  if (artifact.artifact_type !== 'audio') {
    metric('denied.wrong_type', { artifact_id: artifactId, artifact_type: artifact.artifact_type });
    return new Response('Artifact is not audio', { status: 400 });
  }

  // Size guard — checked early from DB metadata before any network call.
  if (artifact.size_bytes !== null && artifact.size_bytes > MAX_AUDIO_BYTES) {
    metric('denied.oversized', { artifact_id: artifactId, size_bytes: artifact.size_bytes });
    return new Response('Audio file too large', { status: 413 });
  }

  if (!BLOB_DELEGATION_TOKEN) {
    metric('denied.misconfigured', { reason: 'missing_blob_delegation_token' });
    return new Response('Blob storage not configured', { status: 503 });
  }

  // Extract pathname from the verified storage_key (comes from DB, not client input).
  // issueSignedToken requires the relative pathname without leading slash.
  let blobPathname: string;
  try {
    const storageUrl = new URL(artifact.storage_key);
    blobPathname = storageUrl.pathname.replace(/^\//, '');
  } catch {
    metric('upstream_failed', { artifact_id: artifactId, reason: 'invalid_storage_key' });
    return new Response('Storage configuration error', { status: 502 });
  }

  // Issue a 60-second delegation scoped to this exact blob pathname and get-only.
  // BLOB_DELEGATION_TOKEN is consumed here, server-side, to generate a self-signed URL.
  // The token is never forwarded to the client and never used in the blob fetch below.
  let signedToken: Awaited<ReturnType<typeof issueSignedToken>>;
  try {
    signedToken = await issueSignedToken({
      token: BLOB_DELEGATION_TOKEN,
      pathname: blobPathname,
      operations: ['get'],
      validUntil: Date.now() + 60_000,
    });
  } catch {
    metric('upstream_failed', { artifact_id: artifactId, reason: 'signed_token_issue_failed' });
    return new Response('Could not issue signed download token', { status: 502 });
  }

  let presignedDownloadUrl: string;
  try {
    const result = await presignUrl(signedToken, {
      operation: 'get',
      pathname: blobPathname,
      access: 'private',
      validUntil: Date.now() + 60_000,
    });
    presignedDownloadUrl = result.presignedUrl;
  } catch {
    metric('upstream_failed', { artifact_id: artifactId, reason: 'presign_failed' });
    return new Response('Could not generate signed download URL', { status: 502 });
  }

  // Fetch the presigned URL. No Authorization header — the signature is in the URL.
  // redirect:'error' ensures any storage redirect is rejected rather than followed
  // to an unvalidated host (belt-and-suspenders given the URL is from our own issuance).
  let upstream: Response;
  try {
    upstream = await fetch(presignedDownloadUrl, { redirect: 'error' });
  } catch {
    metric('redirect_blocked', { artifact_id: artifactId });
    return new Response('Audio unavailable', { status: 502 });
  }

  if (!upstream.ok) {
    metric('upstream_failed', { artifact_id: artifactId, upstream_status: upstream.status });
    return new Response('Audio not found', {
      status: upstream.status === 404 ? 404 : 502,
    });
  }

  // Content-type guard — only stream audio. Check upstream value, not DB value,
  // since the DB value is what was declared at upload time; the CDN is authoritative.
  const rawContentType = upstream.headers.get('Content-Type') ?? '';
  const baseContentType = rawContentType.split(';')[0].trim().toLowerCase();
  if (baseContentType && !ALLOWED_CONTENT_TYPES.has(baseContentType)) {
    metric('denied.content_type', { artifact_id: artifactId, content_type: baseContentType });
    return new Response('Unexpected content type', { status: 502 });
  }

  // Size guard from upstream headers — defence in depth against DB metadata staleness.
  const contentLength = upstream.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_AUDIO_BYTES) {
    metric('denied.oversized', { artifact_id: artifactId, content_length: parseInt(contentLength, 10) });
    return new Response('Audio file too large', { status: 413 });
  }

  metric('allowed', { artifact_id: artifactId, engagement_id: engagementId });

  // Build response with explicit, minimal headers. Upstream headers are never
  // forwarded to prevent storage internals (ETags, x-amz-*, etc.) reaching the client.
  return new Response(upstream.body, {
    headers: {
      'Content-Type': baseContentType || 'audio/webm',
      'Cache-Control': 'private, max-age=300',
      'Content-Disposition': 'inline',
    },
  });
}
