import { NextRequest, NextResponse } from 'next/server';
import OpenAI from 'openai';
import { put } from '@vercel/blob';

// Whisper on long recordings can take 10-20 s; default is 10 s on Vercel Hobby.
export const maxDuration = 60;

const MAX_BYTES = 25 * 1024 * 1024; // Whisper hard limit is 25 MB

export async function POST(req: NextRequest) {
  if (!process.env.OPENAI_API_KEY) {
    return NextResponse.json({ error: 'OPENAI_API_KEY is not configured' }, { status: 503 });
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

  // Run transcription and blob upload concurrently — blob upload doesn't
  // depend on the transcript so there's no reason to wait for it first.
  const hashSuffix = typeof audioHash === 'string' ? audioHash.slice(0, 12) : Date.now().toString(36);
  const engSuffix = typeof engagementId === 'string' ? engagementId.slice(0, 12) : 'unknown';
  const blobPath = `field-assessment/interviews/${engSuffix}/${hashSuffix}.webm`;

  const [transcription, blobResult] = await Promise.allSettled([
    openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      response_format: 'verbose_json',
    }),
    // Only attempt blob upload when token is configured; degrade gracefully otherwise.
    process.env.BLOB_READ_WRITE_TOKEN
      ? put(blobPath, audioFile, { access: 'public', contentType: audioFile.type || 'audio/webm' })
      : Promise.reject(new Error('BLOB_READ_WRITE_TOKEN not configured')),
  ]);

  if (transcription.status === 'rejected') {
    const msg = transcription.reason instanceof Error ? transcription.reason.message : 'Transcription failed';
    return NextResponse.json({ error: msg }, { status: 500 });
  }

  const audio_url =
    blobResult.status === 'fulfilled' ? blobResult.value.url : null;

  return NextResponse.json({
    text: transcription.value.text,
    duration: (transcription.value as { duration?: number }).duration ?? null,
    audio_url,
  });
}
