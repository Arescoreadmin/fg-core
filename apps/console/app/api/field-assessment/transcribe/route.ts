import { NextRequest, NextResponse } from 'next/server';
import OpenAI from 'openai';
import { put } from '@vercel/blob';
import { auth } from '@/auth';

// Whisper on long recordings can take 10-20 s; default is 10 s on Vercel Hobby.
export const maxDuration = 60;

const MAX_BYTES = 25 * 1024 * 1024; // Whisper hard limit is 25 MB

// Opaque 12-char hex derived from a string — used to namespace blob paths
// without exposing raw user identifiers.
async function opaqueHash(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
}

export async function POST(req: NextRequest) {
  if (!process.env.OPENAI_API_KEY) {
    return NextResponse.json({ error: 'OPENAI_API_KEY is not configured' }, { status: 503 });
  }

  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return NextResponse.json({ error: 'Invalid multipart form data' }, { status: 400 });
  }

  const audioFile = form.get('audio');
  const engagementId = form.get('engagement_id');
  const audioHash = form.get('audio_hash');

  if (!(audioFile instanceof File)) {
    return NextResponse.json({ error: 'Missing audio field' }, { status: 400 });
  }

  if (audioFile.size > MAX_BYTES) {
    return NextResponse.json(
      { error: `Audio file is ${(audioFile.size / 1024 / 1024).toFixed(1)} MB — Whisper limit is 25 MB. Split the recording or reduce quality.` },
      { status: 413 },
    );
  }

  const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  // Opaque namespace: hash of user identity so paths are non-guessable
  // and scoped to the authenticated user, even without a DB tenant_id lookup.
  const userIdentity = session.user.email ?? session.user.name ?? 'unknown';
  const tenantNs = await opaqueHash(userIdentity);
  const hashSuffix = typeof audioHash === 'string' ? audioHash.slice(0, 12) : Date.now().toString(36);
  const engSuffix = typeof engagementId === 'string' ? engagementId.slice(0, 12) : 'unknown';
  const blobPath = `field-assessment/${tenantNs}/${engSuffix}/${hashSuffix}.webm`;

  // Transcribe and upload concurrently — transcript doesn't depend on blob URL.
  const [transcription, blobResult] = await Promise.allSettled([
    openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      response_format: 'verbose_json',
    }),
    process.env.BLOB_READ_WRITE_TOKEN
      ? put(blobPath, audioFile, { access: 'public', contentType: audioFile.type || 'audio/webm' })
      : Promise.reject(new Error('BLOB_READ_WRITE_TOKEN not configured')),
  ]);

  if (transcription.status === 'rejected') {
    const msg = transcription.reason instanceof Error ? transcription.reason.message : 'Transcription failed';
    return NextResponse.json({ error: msg }, { status: 500 });
  }

  const audio_url = blobResult.status === 'fulfilled' ? blobResult.value.url : null;
  const blob_error = blobResult.status === 'rejected'
    ? (blobResult.reason instanceof Error ? blobResult.reason.message : 'Upload failed')
    : null;

  return NextResponse.json({
    text: transcription.value.text,
    duration: (transcription.value as { duration?: number }).duration ?? null,
    audio_url,
    // Surfaced so the client can warn the user if blob storage isn't configured
    blob_warning: blob_error && process.env.BLOB_READ_WRITE_TOKEN ? blob_error : null,
  });
}
