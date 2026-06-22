'use client';

/**
 * InterviewForm — captures structured interview records as field observations.
 *
 * Backend mapping: POSTs to POST /observations with observation_type="interview"
 * and interview_role required. Interviews are NOT a separate entity — they are
 * FaFieldObservation records with interview_role populated. This is intentional:
 * interviews produce structured governance evidence in the same lineage as
 * technical observations. See docs/ai/PR_FIX_LOG.md PR 2 entry.
 */

import { useEffect, useRef, useState } from 'react';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Textarea } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type ObservationDomain, type ObservationSeverity, type Observation } from '@/lib/fieldAssessmentApi';
import { getInterviewGuide, ASSESSMENT_TYPE_TO_SECTOR, type InterviewGuide, type InterviewQuestion, type SectorKey } from '@/lib/interviewGuides';

const DOMAINS: { value: ObservationDomain; label: string }[] = [
  { value: 'ai_governance', label: 'AI Governance' },
  { value: 'data_security', label: 'Data Security' },
  { value: 'access_management', label: 'Access Management' },
  { value: 'operational_security', label: 'Operational Security' },
  { value: 'compliance', label: 'Compliance' },
  { value: 'vendor_management', label: 'Vendor Management' },
  { value: 'incident_response', label: 'Incident Response' },
  { value: 'training', label: 'Training' },
];

const CONFIDENCE_OPTIONS = [
  { value: 'high', label: 'High — subject was direct, evidence corroborated' },
  { value: 'medium', label: 'Medium — subject was uncertain or partial evidence' },
  { value: 'low', label: 'Low — anecdotal, unverified, or contradicted' },
];


function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60).toString().padStart(2, '0');
  const s = (seconds % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

async function hashBlob(blob: Blob): Promise<string> {
  const buf = await blob.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

type RecordingState = 'idle' | 'recording' | 'paused' | 'stopped';

function RecordingWidget({
  engagementId,
  onAudioReady,
  onUseTranscript,
}: {
  engagementId: string;
  onAudioReady: (info: { hash: string; sizeKb: number; durationSec: number; blobUrl: string; blob: Blob; artifactId: string | null }) => void;
  onUseTranscript: (text: string) => void;
}) {
  const [recState, setRecState] = useState<RecordingState>('idle');
  const [displayTime, setDisplayTime] = useState(0);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [audioInfo, setAudioInfo] = useState<{ hash: string; sizeKb: number; durationSec: number } | null>(null);
  const [recError, setRecError] = useState<string | null>(null);
  const [transcript, setTranscript] = useState<string | null>(null);
  const [transcribing, setTranscribing] = useState(false);
  const [transcriptError, setTranscriptError] = useState<string | null>(null);
  const [blobWarning, setBlobWarning] = useState<string | null>(null);
  const [entities, setEntities] = useState<{ vendors: string[]; systems: string[]; risks: string[]; suggested_domains: string[] } | null>(null);
  const blobRef = useRef<Blob | null>(null);

  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const elapsedRef = useRef(0);     // total elapsed seconds at last pause
  const startedAtRef = useRef(0);   // Date.now() when last resumed

  function tick() {
    const total = elapsedRef.current + Math.floor((Date.now() - startedAtRef.current) / 1000);
    setDisplayTime(total);
  }

  function startTimer() {
    startedAtRef.current = Date.now();
    timerRef.current = setInterval(tick, 1000);
  }

  function stopTimer() {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    elapsedRef.current += Math.floor((Date.now() - startedAtRef.current) / 1000);
  }

  async function start() {
    setRecError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      chunksRef.current = [];
      elapsedRef.current = 0;
      setDisplayTime(0);

      const recorder = new MediaRecorder(stream);
      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunksRef.current.push(e.data);
      };
      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(chunksRef.current, { type: recorder.mimeType || 'audio/webm' });
        const url = URL.createObjectURL(blob);
        const hash = await hashBlob(blob);
        const info = {
          hash,
          sizeKb: Math.round(blob.size / 1024),
          durationSec: elapsedRef.current,
          blobUrl: url,
          blob,
          artifactId: null as string | null,
        };
        blobRef.current = blob;
        setBlobUrl(url);
        setTranscript(null);
        setTranscriptError(null);
        setAudioInfo({ hash, sizeKb: info.sizeKb, durationSec: info.durationSec });
        onAudioReady(info);
        setRecState('stopped');
      };

      recorder.start(500);
      mediaRecorderRef.current = recorder;
      setRecState('recording');
      startTimer();
    } catch {
      setRecError('Microphone access denied — check browser permissions.');
    }
  }

  function pause() {
    mediaRecorderRef.current?.pause();
    stopTimer();
    setRecState('paused');
  }

  function resume() {
    mediaRecorderRef.current?.resume();
    startTimer();
    setRecState('recording');
  }

  function stop() {
    stopTimer();
    mediaRecorderRef.current?.stop();
    // onstop handler fires async and sets state to 'stopped'
  }

  async function transcribe() {
    if (!blobRef.current || !audioInfo) return;
    setTranscribing(true);
    setTranscriptError(null);
    setTranscript(null);
    try {
      const form = new FormData();
      form.append('audio', blobRef.current, 'interview.webm');
      form.append('engagement_id', engagementId);
      form.append('audio_hash', audioInfo.hash);
      const res = await fetch('/api/field-assessment/transcribe', { method: 'POST', body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Transcription failed');
      const artifactId = (data.artifact_id as string | null) ?? null;
      setTranscript(data.text as string);
      setBlobWarning((data.blob_warning as string | null) ?? null);
      setEntities((data.entities as typeof entities) ?? null);
      // Propagate the opaque artifact_id back to the parent form.
      // The storage URL is never returned to the client — the proxy resolves it.
      onAudioReady({ ...audioInfo, blobUrl: blobUrl ?? '', blob: blobRef.current, artifactId });
    } catch (e) {
      setTranscriptError(e instanceof Error ? e.message : 'Transcription failed');
    } finally {
      setTranscribing(false);
    }
  }

  function discard() {
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    blobRef.current = null;
    setBlobUrl(null);
    setAudioInfo(null);
    setDisplayTime(0);
    setTranscript(null);
    setTranscriptError(null);
    elapsedRef.current = 0;
    setRecState('idle');
    onAudioReady({ hash: '', sizeKb: 0, durationSec: 0, blobUrl: '', blob: new Blob(), artifactId: null });
  }

  function download() {
    if (!blobUrl) return;
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `interview-recording-${Date.now()}.webm`;
    a.click();
  }

  // Cleanup blob URL on unmount
  useEffect(() => {
    return () => {
      if (blobUrl) URL.revokeObjectURL(blobUrl);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [blobUrl]);

  return (
    <div className="rounded border border-border bg-surface-2 p-3 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-foreground">Audio recording</p>
        <div className="flex items-center gap-2">
          {recState === 'recording' && (
            <span className="flex items-center gap-1 text-[11px] text-red-300">
              <span className="inline-block h-2 w-2 rounded-full bg-red-400 animate-pulse" />
              REC
            </span>
          )}
          {recState === 'paused' && (
            <span className="text-[11px] text-amber-300">PAUSED</span>
          )}
          <span className="font-mono text-xs text-foreground tabular-nums">
            {formatDuration(displayTime)}
          </span>
        </div>
      </div>

      {recState === 'idle' && (
        <button
          type="button"
          onClick={start}
          className="flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-200 transition hover:bg-red-500/20 focus:outline-none focus:ring-2 focus:ring-red-500/40"
        >
          <span className="inline-block h-2 w-2 rounded-full bg-red-400" />
          Start recording
        </button>
      )}

      {(recState === 'recording' || recState === 'paused') && (
        <div className="flex items-center gap-2">
          {recState === 'recording' ? (
            <button
              type="button"
              onClick={pause}
              className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-200 transition hover:bg-amber-500/20 focus:outline-none focus:ring-2 focus:ring-amber-500/40"
            >
              ⏸ Pause
            </button>
          ) : (
            <button
              type="button"
              onClick={resume}
              className="flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-200 transition hover:bg-red-500/20 focus:outline-none focus:ring-2 focus:ring-red-500/40"
            >
              <span className="inline-block h-2 w-2 rounded-full bg-red-400" />
              Resume
            </button>
          )}
          <button
            type="button"
            onClick={stop}
            className="rounded border border-border bg-surface-1 px-3 py-1.5 text-xs font-medium text-foreground transition hover:border-primary/50 focus:outline-none focus:ring-2 focus:ring-primary/40"
          >
            ⏹ Stop
          </button>
        </div>
      )}

      {recState === 'stopped' && blobUrl && audioInfo && (
        <div className="space-y-2">
          <audio controls src={blobUrl} className="w-full h-8" />
          <div className="flex items-center justify-between text-[11px] text-muted">
            <span>{formatDuration(audioInfo.durationSec)} · {audioInfo.sizeKb} KB</span>
            <span className="font-mono truncate max-w-[160px]" title={audioInfo.hash}>
              SHA-256: {audioInfo.hash.slice(0, 12)}…
            </span>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={download}
              className="rounded border border-border bg-surface-1 px-2 py-1 text-[11px] text-foreground transition hover:border-primary/50 focus:outline-none"
            >
              Download
            </button>
            <button
              type="button"
              onClick={discard}
              disabled={transcribing}
              className="rounded border border-border px-2 py-1 text-[11px] text-muted transition hover:text-foreground focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Discard
            </button>
          </div>

          {/* Transcription panel */}
          {!transcript && !transcribing && (
            <button
              type="button"
              onClick={transcribe}
              className="w-full rounded border border-primary/30 bg-primary/10 px-3 py-2 text-xs font-medium text-primary transition hover:bg-primary/20 focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              Transcribe with Whisper (~$0.006 / min)
            </button>
          )}

          {transcribing && (
            <div className="flex items-center gap-2 rounded border border-border bg-surface-1 px-3 py-2">
              <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              <span className="text-xs text-muted">Transcribing — this may take a moment…</span>
            </div>
          )}

          {transcript && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-[11px] font-medium text-muted uppercase tracking-wide">Transcript</p>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => onUseTranscript(transcript)}
                    className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-200 transition hover:bg-emerald-500/20 focus:outline-none"
                  >
                    Use as notes
                  </button>
                  <button
                    type="button"
                    onClick={transcribe}
                    className="rounded border border-border px-2 py-0.5 text-[11px] text-muted transition hover:text-foreground focus:outline-none"
                  >
                    Re-transcribe
                  </button>
                </div>
              </div>
              <div className="max-h-48 overflow-y-auto rounded border border-border bg-surface-1 p-2 text-xs text-foreground whitespace-pre-wrap leading-relaxed">
                {transcript}
              </div>
              {entities && (entities.risks.length > 0 || entities.vendors.length > 0 || entities.systems.length > 0) && (
                <div className="rounded border border-primary/20 bg-primary/5 p-2 space-y-1.5">
                  <p className="text-[10px] font-semibold text-primary uppercase tracking-wider">AI-extracted signals</p>
                  {entities.risks.length > 0 && (
                    <div>
                      <p className="text-[10px] text-muted font-medium mb-0.5">Risk signals</p>
                      <ul className="space-y-0.5">
                        {entities.risks.map((r, i) => (
                          <li key={i} className="flex items-start gap-1 text-[11px] text-foreground">
                            <span className="text-red-400 shrink-0 mt-0.5">⚠</span>
                            <span>{r}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {(entities.vendors.length > 0 || entities.systems.length > 0) && (
                    <div className="flex flex-wrap gap-1">
                      {entities.vendors.map((v) => (
                        <span key={v} className="inline-flex items-center rounded px-1 py-0.5 text-[10px] border border-amber-500/30 bg-amber-500/10 text-amber-300">vendor: {v}</span>
                      ))}
                      {entities.systems.map((s) => (
                        <span key={s} className="inline-flex items-center rounded px-1 py-0.5 text-[10px] border border-blue-500/30 bg-blue-500/10 text-blue-300">sys: {s}</span>
                      ))}
                    </div>
                  )}
                  {entities.suggested_domains.length > 0 && (
                    <p className="text-[10px] text-muted">
                      Suggested domains:{' '}
                      <span className="font-mono text-foreground">{entities.suggested_domains.join(', ')}</span>
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          {transcriptError && (
            <p className="text-[11px] text-red-300">{transcriptError}</p>
          )}
          {blobWarning && (
            <p className="text-[11px] text-amber-300">
              Transcript saved, but audio could not be stored: {blobWarning}. Download the recording locally to keep a copy.
            </p>
          )}
        </div>
      )}

      {recError && (
        <p className="text-[11px] text-red-300">{recError}</p>
      )}
      <p className="text-[11px] text-muted">
        Recording stays in your browser — download to keep a local copy. The SHA-256 hash is attached to the observation as a tamper-evident artifact reference.
      </p>
    </div>
  );
}

interface InterviewPrefill {
  role?: string;
  title?: string;
  instruction?: string;
}

interface Props {
  engagementId: string;
  prefill?: InterviewPrefill | null;
  assessmentType?: string;
  onSuccess: (obs: Observation) => void;
}

export function InterviewForm({ engagementId, prefill, assessmentType, onSuccess }: Props) {
  const [interviewRole, setInterviewRole] = useState('');
  const [businessFunction, setBusinessFunction] = useState('');
  const [domain, setDomain] = useState<ObservationDomain | ''>('');
  const [severity, setSeverity] = useState<ObservationSeverity | ''>('');
  const [title, setTitle] = useState('');
  const [aiUsageAsserted, setAiUsageAsserted] = useState('');
  const [policyAwareness, setPolicyAwareness] = useState('');
  const [structuredNotes, setStructuredNotes] = useState('');
  const [confidence, setConfidence] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastObs, setLastObs] = useState<Observation | null>(null);
  const [guideOpen, setGuideOpen] = useState(true);
  const [audioArtifact, setAudioArtifact] = useState<{ hash: string; sizeKb: number; durationSec: number; artifactId: string | null } | null>(null);
  const [templateOpen, setTemplateOpen] = useState(false);
  const [templates, setTemplates] = useState<Observation[] | null>(null);
  const [templatesLoading, setTemplatesLoading] = useState(false);

  const guide = getInterviewGuide(prefill?.role, assessmentType);

  // Unique NIST AI RMF refs across all questions in the guide, sorted.
  const nistRefs = guide
    ? Array.from(new Set(guide.questions.flatMap((q) => q.nist))).sort()
    : [];

  useEffect(() => {
    if (!prefill) return;
    if (guide) {
      setInterviewRole(guide.roleLabel);
      setDomain(guide.domain);
      setTitle(guide.suggestedTitle);
    } else if (prefill.role) {
      setInterviewRole(prefill.role.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()));
    }
    setGuideOpen(true);
  }, [prefill]); // eslint-disable-line react-hooks/exhaustive-deps

  const canSubmit =
    interviewRole.trim() !== '' &&
    domain !== '' &&
    severity !== '' &&
    title.trim() !== '' &&
    structuredNotes.trim() !== '' &&
    !submitting;

  async function handleSubmit() {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);

    const audioLine = audioArtifact?.hash
      ? `\n\n[Audio artifact: ${audioArtifact.durationSec}s, ${audioArtifact.sizeKb} KB, SHA-256: ${audioArtifact.hash}]`
      : '';
    const regsRefs = guide
      ? Array.from(new Set(guide.questions.flatMap((q) => q.regs ?? []))).sort()
      : [];
    const nistLine = nistRefs.length > 0
      ? `\n\n[NIST AI RMF: ${nistRefs.join(', ')}${regsRefs.length > 0 ? ` | Regs: ${regsRefs.join(', ')}` : ''}]`
      : '';

    const description = [
      businessFunction.trim() && `Business function: ${businessFunction.trim()}`,
      aiUsageAsserted.trim() && `AI usage asserted: ${aiUsageAsserted.trim()}`,
      policyAwareness.trim() && `Policy awareness: ${policyAwareness.trim()}`,
      confidence && `Confidence: ${confidence}`,
      structuredNotes.trim(),
    ]
      .filter(Boolean)
      .join('\n\n') + nistLine + audioLine;

    try {
      const structured_evidence: Record<string, string> = {};
      if (audioArtifact?.hash) {
        structured_evidence['_audio_hash'] = audioArtifact.hash;
        structured_evidence['_audio_duration_sec'] = String(audioArtifact.durationSec);
        structured_evidence['_audio_size_kb'] = String(audioArtifact.sizeKb);
      }
      if (audioArtifact?.artifactId) {
        structured_evidence['_audio_artifact_id'] = audioArtifact.artifactId;
      }

      const obs = await fieldAssessmentApi.captureObservation(engagementId, {
        domain: domain as ObservationDomain,
        observation_type: 'interview',
        severity: severity as ObservationSeverity,
        title: title.trim(),
        description,
        interview_role: interviewRole.trim(),
        structured_evidence,
      });
      setLastObs(obs);
      setInterviewRole('');
      setBusinessFunction('');
      setDomain('');
      setSeverity('');
      setTitle('');
      setAiUsageAsserted('');
      setPolicyAwareness('');
      setStructuredNotes('');
      setConfidence('');
      setAudioArtifact(null);
      onSuccess(obs);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Capture failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="interview-form">
      {/* Interview guide — shown when a prefill is active */}
      {prefill && (
        <div className="rounded border border-primary/30 bg-primary/5">
          <button
            type="button"
            className="flex w-full items-center justify-between px-3 py-2 text-left focus:outline-none"
            onClick={() => setGuideOpen((v) => !v)}
            aria-expanded={guideOpen}
          >
            <div className="space-y-0.5">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-xs font-semibold text-foreground">
                  Interview guide — {guide?.roleLabel ?? prefill.role?.replace(/_/g, ' ')}
                </p>
                {(() => {
                  const sector: SectorKey = (assessmentType ? ASSESSMENT_TYPE_TO_SECTOR[assessmentType] : undefined) ?? 'default';
                  const SECTOR_LABEL: Record<SectorKey, string> = {
                    default: 'General AI',
                    healthcare: 'Healthcare / HIPAA',
                    pci_dss: 'PCI DSS',
                    dora: 'DORA',
                    government: 'Gov / CMMC',
                  };
                  const isNonDefault = sector !== 'default';
                  return (
                    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] border font-medium ${isNonDefault ? 'border-amber-500/30 bg-amber-500/5 text-amber-300' : 'border-info/20 bg-info/5 text-info'}`}>
                      {SECTOR_LABEL[sector]}
                    </span>
                  );
                })()}
              </div>
              {prefill.instruction && (
                <p className="text-[11px] text-muted mt-0.5">{prefill.instruction}</p>
              )}
            </div>
            <span className="text-xs text-muted shrink-0 ml-2">{guideOpen ? '▲ collapse' : '▼ expand'}</span>
          </button>

          {guideOpen && guide && (
            <div className="border-t border-primary/20 px-3 pb-3 pt-2 space-y-3">
              <div>
                <p className="text-[11px] font-medium text-muted uppercase tracking-wide mb-1">Key topics to cover</p>
                <ul className="space-y-0.5">
                  {guide.topics.map((topic) => (
                    <li key={topic} className="flex items-start gap-1.5 text-xs text-foreground">
                      <span className="mt-0.5 shrink-0 text-primary">•</span>
                      {topic}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <p className="text-[11px] font-medium text-muted uppercase tracking-wide mb-1">Suggested questions</p>
                <ol className="space-y-2 list-none">
                  {guide.questions.map((q, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-foreground">
                      <span className="shrink-0 text-[10px] text-muted font-mono mt-0.5 w-4 text-right">{i + 1}.</span>
                      <div className="space-y-0.5">
                        <span>{q.text}</span>
                        {(q.nist.length > 0 || (q.regs && q.regs.length > 0)) && (
                          <div className="flex flex-wrap gap-1">
                            {q.nist.map((ref) => (
                              <span key={ref} className="inline-flex items-center rounded px-1 py-0.5 text-[10px] font-mono border border-primary/20 bg-primary/10 text-primary">
                                {ref}
                              </span>
                            ))}
                            {q.regs && q.regs.map((reg) => (
                              <span key={reg} title={`Regulatory clause: ${reg}`} className="inline-flex items-center rounded px-1 py-0.5 text-[10px] font-mono border border-amber-500/40 bg-amber-500/10 text-amber-300 font-semibold">
                                {reg}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recording widget */}
      <RecordingWidget
        engagementId={engagementId}
        onAudioReady={(info) => {
          if (info.hash) {
            setAudioArtifact({ hash: info.hash, sizeKb: info.sizeKb, durationSec: info.durationSec, artifactId: info.artifactId });
          } else {
            setAudioArtifact(null);
          }
        }}
        onUseTranscript={(text) =>
          setStructuredNotes((prev) => (prev.trim() ? `${prev.trim()}\n\n${text}` : text))
        }
      />

      <div className="rounded border border-info/20 bg-info/5 px-3 py-2 text-xs text-info">
        Interview records are stored as structured field observations (type: interview) anchored to this engagement.
        Capture role — not personal name. Avoid PII beyond what governance evidence requires.
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="int-role">Interviewee Role / Title *</Label>
          <Input
            id="int-role"
            aria-required="true"
            placeholder="e.g., CTO, CISO, Data Steward"
            value={interviewRole}
            onChange={(e) => setInterviewRole(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-function">Business Function</Label>
          <Input
            id="int-function"
            placeholder="e.g., Engineering, Legal, Operations"
            value={businessFunction}
            onChange={(e) => setBusinessFunction(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-domain">Domain *</Label>
          <Select value={domain} onValueChange={(v) => setDomain(v as ObservationDomain)}>
            <SelectTrigger id="int-domain" aria-required="true">
              <SelectValue placeholder="Select domain…" />
            </SelectTrigger>
            <SelectContent>
              {DOMAINS.map((d) => (
                <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-severity">Governance Severity *</Label>
          <Select value={severity} onValueChange={(v) => setSeverity(v as ObservationSeverity)}>
            <SelectTrigger id="int-severity" aria-required="true">
              <SelectValue placeholder="Select severity…" />
            </SelectTrigger>
            <SelectContent>
              {(['critical', 'high', 'medium', 'low', 'info'] as ObservationSeverity[]).map((s) => (
                <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-title">Interview Summary Title *</Label>
        <Input
          id="int-title"
          aria-required="true"
          placeholder="e.g., CTO interview — AI adoption awareness"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="int-ai-usage">AI Usage Asserted</Label>
          <Input
            id="int-ai-usage"
            placeholder="e.g., Uses ChatGPT for draft communications"
            value={aiUsageAsserted}
            onChange={(e) => setAiUsageAsserted(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-policy">Policy Awareness</Label>
          <Input
            id="int-policy"
            placeholder="e.g., Aware of AI policy, did not read it"
            value={policyAwareness}
            onChange={(e) => setPolicyAwareness(e.target.value)}
          />
        </div>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <Label htmlFor="int-notes">Structured Notes *</Label>
          <button
            type="button"
            onClick={async () => {
              if (!templateOpen) {
                setTemplateOpen(true);
                if (templates === null) {
                  setTemplatesLoading(true);
                  try {
                    const role = prefill?.role || interviewRole.toLowerCase().replace(/\s+/g, '_');
                    const rows = await fieldAssessmentApi.listInterviewTemplates({
                      interview_role: role || undefined,
                      assessment_type: assessmentType || undefined,
                    });
                    setTemplates(rows);
                  } catch {
                    setTemplates([]);
                  } finally {
                    setTemplatesLoading(false);
                  }
                }
              } else {
                setTemplateOpen(false);
              }
            }}
            className="text-[11px] text-primary hover:underline focus:outline-none"
          >
            {templateOpen ? 'Hide' : 'Load from prior interviews'}
          </button>
        </div>
        {templateOpen && (
          <div className="rounded border border-border bg-surface-1 p-2 space-y-1.5 max-h-48 overflow-y-auto">
            {templatesLoading ? (
              <p className="text-xs text-muted">Loading…</p>
            ) : !templates || templates.length === 0 ? (
              <p className="text-xs text-muted">No prior interview notes found for this role/type.</p>
            ) : (
              templates.map((t) => (
                <div key={t.id} className="rounded border border-border bg-surface-2 p-2 space-y-0.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-foreground truncate">{t.title}</span>
                    <button
                      type="button"
                      onClick={() => { setStructuredNotes(t.description); setTemplateOpen(false); }}
                      className="text-[11px] text-primary hover:underline focus:outline-none shrink-0"
                    >
                      Use
                    </button>
                  </div>
                  <p className="text-[11px] text-muted line-clamp-2">{t.description}</p>
                </div>
              ))
            )}
          </div>
        )}
        <Textarea
          id="int-notes"
          aria-required="true"
          placeholder="Key responses, evidence references, governance observations from this interview"
          className="min-h-[120px]"
          value={structuredNotes}
          onChange={(e) => setStructuredNotes(e.target.value)}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-confidence">Confidence Level</Label>
        <Select value={confidence} onValueChange={setConfidence}>
          <SelectTrigger id="int-confidence">
            <SelectValue placeholder="Select confidence…" />
          </SelectTrigger>
          <SelectContent>
            {CONFIDENCE_OPTIONS.map((c) => (
              <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {audioArtifact && (
        <div className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-100">
          Audio artifact will be attached — {formatDuration(audioArtifact.durationSec)}, {audioArtifact.sizeKb} KB, hash {audioArtifact.hash.slice(0, 12)}…
        </div>
      )}

      {lastObs && (
        <Alert variant="success">
          <AlertDescription>Interview captured: <span className="font-medium">{lastObs.title}</span></AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Button onClick={handleSubmit} disabled={!canSubmit} aria-label="Record interview">
        {submitting ? 'Recording…' : 'Record Interview'}
      </Button>
    </div>
  );
}
