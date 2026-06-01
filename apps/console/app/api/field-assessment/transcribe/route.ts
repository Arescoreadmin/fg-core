import { NextRequest, NextResponse } from 'next/server';
import OpenAI from 'openai';

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

  try {
    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      response_format: 'verbose_json', // includes segments with timestamps
    });

    return NextResponse.json({
      text: transcription.text,
      duration: (transcription as { duration?: number }).duration ?? null,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Transcription failed';
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
