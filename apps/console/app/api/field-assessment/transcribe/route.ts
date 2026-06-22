import { NextRequest, NextResponse } from 'next/server';
import OpenAI from 'openai';
import { put } from '@vercel/blob';
import { auth } from '@/auth';

// Whisper on long recordings can take 10-20 s; default is 10 s on Vercel Hobby.
export const maxDuration = 60;

const MAX_BYTES = 25 * 1024 * 1024; // Whisper hard limit is 25 MB

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.FG_CORE_API_KEY ?? process.env.CORE_API_KEY;
const CORE_TENANT_ID = process.env.CORE_TENANT_ID;

// Opaque 12-char hex derived from a string — used to namespace blob paths
// without exposing raw user identifiers.
async function opaqueHash(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
}

interface ExtractedEntities {
  vendors: string[];
  systems: string[];
  risks: string[];
  suggested_domains: string[];
}

async function extractEntities(openai: OpenAI, transcript: string): Promise<ExtractedEntities | null> {
  try {
    const resp = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content: 'You are a security assessment analyst. Extract structured entities from an interview transcript. Respond ONLY with valid JSON, no explanation.',
        },
        {
          role: 'user',
          content: `Extract entities from this field assessment interview transcript. Return JSON with these keys:
- vendors: array of vendor/third-party names mentioned (strings, deduplicated)
- systems: array of internal system/tool names mentioned (strings, deduplicated)
- risks: array of short risk phrases (1 sentence max) — security gaps, missing controls, or concerns raised
- suggested_domains: array of relevant domain labels from this set only: ["ai_governance","data_security","access_management","operational_security","compliance","vendor_management","incident_response","training"]

Transcript:
"""
${transcript.slice(0, 3000)}
"""`,
        },
      ],
      temperature: 0,
      max_tokens: 512,
      response_format: { type: 'json_object' },
    });
    const content = resp.choices[0]?.message?.content;
    if (!content) return null;
    const parsed = JSON.parse(content) as Partial<ExtractedEntities>;
    return {
      vendors: Array.isArray(parsed.vendors) ? parsed.vendors.slice(0, 10) : [],
      systems: Array.isArray(parsed.systems) ? parsed.systems.slice(0, 10) : [],
      risks: Array.isArray(parsed.risks) ? parsed.risks.slice(0, 5) : [],
      suggested_domains: Array.isArray(parsed.suggested_domains) ? parsed.suggested_domains.slice(0, 4) : [],
    };
  } catch {
    return null;
  }
}

/**
 * Register the uploaded blob as an artifact in the FA backend. Returns the
 * opaque artifact_id that clients use to request the audio through the proxy.
 * The storage_key (blob URL) stays server-side and is never given to the browser.
 */
async function registerArtifact(opts: {
  engagementId: string;
  storageKey: string;
  sha256: string | null;
  sizeBytes: number;
  contentType: string;
}): Promise<string | null> {
  if (!CORE_API_KEY || !CORE_TENANT_ID) return null;

  try {
    const res = await fetch(
      `${CORE_API_URL}/field-assessment/engagements/${encodeURIComponent(opts.engagementId)}/artifacts?tenant_id=${encodeURIComponent(CORE_TENANT_ID)}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': CORE_API_KEY,
        },
        body: JSON.stringify({
          artifact_type: 'audio',
          storage_key: opts.storageKey,
          sha256: opts.sha256,
          size_bytes: opts.sizeBytes,
          content_type: opts.contentType,
          retention_class: 'standard_3y',
        }),
      },
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { id?: string };
    return data.id ?? null;
  } catch {
    return null;
  }
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

  // Transcribe first — entity extraction depends on the transcript text.
  const transcriptionResult = await openai.audio.transcriptions.create({
    file: audioFile,
    model: 'whisper-1',
    response_format: 'verbose_json',
  }).then(
    (v) => ({ status: 'fulfilled' as const, value: v }),
    (e: unknown) => ({ status: 'rejected' as const, reason: e }),
  );

  if (transcriptionResult.status === 'rejected') {
    const msg = transcriptionResult.reason instanceof Error ? transcriptionResult.reason.message : 'Transcription failed';
    return NextResponse.json({ error: msg }, { status: 500 });
  }

  const transcriptText = transcriptionResult.value.text;

  // Run blob upload + entity extraction concurrently — both can proceed with transcript ready.
  const [blobResult, entitiesResult] = await Promise.allSettled([
    process.env.BLOB_READ_WRITE_TOKEN
      ? put(blobPath, audioFile, { access: 'private', contentType: audioFile.type || 'audio/webm' })
      : Promise.reject(new Error('BLOB_READ_WRITE_TOKEN not configured')),
    extractEntities(openai, transcriptText),
  ]);

  const blobUrl = blobResult.status === 'fulfilled' ? blobResult.value.url : null;
  const blob_error = blobResult.status === 'rejected'
    ? (blobResult.reason instanceof Error ? blobResult.reason.message : 'Upload failed')
    : null;

  const entities = entitiesResult.status === 'fulfilled' ? entitiesResult.value : null;

  // Register the artifact so the audio proxy can resolve it by opaque ID.
  // artifact_id replaces audio_url — the storage_key never reaches the browser.
  let artifact_id: string | null = null;
  if (blobUrl && typeof engagementId === 'string' && engagementId !== 'unknown') {
    artifact_id = await registerArtifact({
      engagementId,
      storageKey: blobUrl,
      sha256: typeof audioHash === 'string' ? audioHash : null,
      sizeBytes: audioFile.size,
      contentType: audioFile.type || 'audio/webm',
    });
  }

  return NextResponse.json({
    text: transcriptText,
    duration: (transcriptionResult.value as { duration?: number }).duration ?? null,
    artifact_id,
    // Surfaced so the client can warn the user if blob storage isn't configured
    blob_warning: blob_error && process.env.BLOB_READ_WRITE_TOKEN ? blob_error : null,
    // DIFF-2: extracted entities for auto-linking suggestions
    entities,
  });
}
