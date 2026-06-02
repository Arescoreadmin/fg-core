import { NextRequest } from 'next/server';
import { auth } from '@/auth';

// Private blob audio can be large (up to 25 MB); allow enough time to stream.
export const maxDuration = 30;

const BLOB_HOST_SUFFIX = '.blob.vercel-storage.com';
const REQUIRED_PATH_PREFIX = '/field-assessment/';
const MAX_AUDIO_BYTES = 25 * 1024 * 1024; // 25 MB — Whisper hard limit

// Allowlist of content-types we will stream. Anything else is rejected
// before touching the response body.
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

/**
 * GET /api/field-assessment/audio-url?url=<encoded-blob-url>
 *
 * Auth-gated proxy for field-assessment audio blobs.
 * Blobs are stored private; this route fetches them server-side using
 * BLOB_READ_WRITE_TOKEN and streams the content to the authenticated caller.
 *
 * Security model:
 *  1. Session required — unauthenticated callers receive 401.
 *  2. URL must parse cleanly as https: — rejects malformed inputs.
 *  3. Hostname must *end with* BLOB_HOST_SUFFIX — suffix check, not substring,
 *     so "attacker.com?x=.blob.vercel-storage.com" is rejected.
 *  4. Path must begin with /field-assessment/ — only tenant-namespaced uploads
 *     made by this application are reachable.
 *  5. Redirects are never followed — fetch with redirect:'error' so a redirect
 *     to an attacker host cannot smuggle the token out.
 *  6. BLOB_READ_WRITE_TOKEN is sent only after all URL checks pass.
 *  7. Upstream Content-Type must be in ALLOWED_CONTENT_TYPES — non-audio blobs
 *     are rejected before the body is streamed.
 *  8. Upstream Content-Length is checked against MAX_AUDIO_BYTES.
 *  9. Only a minimal set of headers is forwarded downstream — no upstream
 *     headers are passed through that could leak storage internals.
 */
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return new Response('Unauthorized', { status: 401 });
  }

  const raw = req.nextUrl.searchParams.get('url');
  if (!raw) {
    return new Response('Missing url parameter', { status: 400 });
  }

  // Parse first — reject malformed URLs before any string operations.
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return new Response('Invalid audio URL', { status: 400 });
  }

  // HTTPS only.
  if (parsed.protocol !== 'https:') {
    return new Response('Invalid audio URL', { status: 400 });
  }

  // Hostname suffix check — endsWith, not includes.
  // "attacker.com?x=.blob.vercel-storage.com" has hostname "attacker.com" which
  // does not end with the suffix, so it is rejected here.
  if (!parsed.hostname.endsWith(BLOB_HOST_SUFFIX)) {
    return new Response('Invalid audio URL', { status: 400 });
  }

  // Path must be namespaced under /field-assessment/ — the upload prefix used
  // by the transcribe route. This blocks access to blobs from other paths even
  // if they are on the same storage host.
  if (!parsed.pathname.startsWith(REQUIRED_PATH_PREFIX)) {
    return new Response('Invalid audio URL', { status: 400 });
  }

  const token = process.env.BLOB_READ_WRITE_TOKEN;
  if (!token) {
    return new Response('Blob storage not configured', { status: 503 });
  }

  // fetch with redirect:'error' — if the storage provider issues a redirect,
  // we reject it rather than following it to an unvalidated destination that
  // would also receive the Authorization header.
  let upstream: Response;
  try {
    upstream = await fetch(parsed.href, {
      headers: { Authorization: `Bearer ${token}` },
      redirect: 'error',
    });
  } catch {
    return new Response('Audio unavailable', { status: 502 });
  }

  if (!upstream.ok) {
    return new Response('Audio not found', {
      status: upstream.status === 404 ? 404 : 502,
    });
  }

  // Validate Content-Type before streaming the body.
  const rawContentType = upstream.headers.get('Content-Type') ?? '';
  const baseContentType = rawContentType.split(';')[0].trim().toLowerCase();
  if (baseContentType && !ALLOWED_CONTENT_TYPES.has(baseContentType)) {
    return new Response('Unexpected content type', { status: 502 });
  }

  // Guard against unexpectedly large blobs.
  const contentLength = upstream.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_AUDIO_BYTES) {
    return new Response('Audio file too large', { status: 413 });
  }

  return new Response(upstream.body, {
    headers: {
      'Content-Type': baseContentType || 'audio/webm',
      'Cache-Control': 'private, max-age=300',
      'Content-Disposition': 'inline',
    },
  });
}
