import { NextRequest } from 'next/server';
import { auth } from '@/auth';

// Private blob audio can be large (up to 25 MB); allow enough time to stream.
export const maxDuration = 30;

const BLOB_HOST_SUFFIX = '.blob.vercel-storage.com';

/**
 * GET /api/field-assessment/audio-url?url=<encoded-blob-url>
 *
 * Auth-gated proxy for field-assessment audio blobs.
 * Blobs are stored private; this route fetches them server-side using
 * BLOB_READ_WRITE_TOKEN and streams the content to the authenticated caller.
 * Works for both legacy public blobs and new private blobs.
 */
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return new Response('Unauthorized', { status: 401 });
  }

  const url = req.nextUrl.searchParams.get('url');
  if (!url?.startsWith('https://') || !url.includes(BLOB_HOST_SUFFIX)) {
    return new Response('Invalid audio URL', { status: 400 });
  }

  const token = process.env.BLOB_READ_WRITE_TOKEN;
  if (!token) {
    return new Response('Blob storage not configured', { status: 503 });
  }

  const upstream = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!upstream.ok) {
    return new Response('Audio not found', { status: upstream.status === 404 ? 404 : 502 });
  }

  return new Response(upstream.body, {
    headers: {
      'Content-Type': upstream.headers.get('Content-Type') ?? 'audio/webm',
      'Cache-Control': 'private, max-age=300',
      'Content-Disposition': 'inline',
    },
  });
}
