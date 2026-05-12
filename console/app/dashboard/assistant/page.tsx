'use client';

import { useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  BookOpen,
  CheckCircle2,
  Clipboard,
  Download,
  HelpCircle,
  Layers,
  RefreshCw,
  Send,
  ShieldCheck,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/button';
import {
  CitationViewer,
  ConfidenceMeter,
  PolicyDecision,
  ProviderRouteCard,
  RetrievalTrace,
} from '@/components/governance';
import type { Citation, TraceStep } from '@/components/governance';

// ─── Types ────────────────────────────────────────────────────────────────────

interface SourceSummary {
  source_id?: string | null;
  chunk_id?: string | null;
  chunk_index?: number | null;
  included_in_prompt?: boolean;
  phi_sensitivity_level?: string | null;
  phi_types?: string[] | null;
}

interface ProvenanceData {
  retrieval_trace_id?: string | null;
  used_rag?: boolean;
  context_count?: number | null;
  source_chunk_ids?: string[] | null;
  source_summaries?: SourceSummary[] | null;
  confidence?: number | null;
  why_this_chunk?: Record<string, unknown> | null;
  retrieval_strategy?: string | null;
  provenance_status?: string | null;
}

interface ApiResponse {
  answer?: string;
  provider?: string;
  model?: string;
  latency_ms?: number;
  request_id?: string | null;
  policy_decision?: { action: string; reason?: string; policy?: string };
  confidence?: number | null;
  citations?: Array<{ index: number; source: string; excerpt?: string; url?: string }>;
  retrieval_steps?: Array<{ step: string; latency_ms?: number; detail?: string }>;
  correlation_id?: string | null;
  session_id?: string | null;
  provenance?: ProvenanceData;
  error?: string;
}

interface MessageMeta {
  provider?: string;
  model?: string;
  latencyMs?: number;
  requestId?: string | null;
  policyDecision?: { action: string; reason?: string; policy?: string };
  confidence?: number | null;
  citations?: Citation[];
  retrievalSteps?: TraceStep[];
  provenance?: ProvenanceData;
  correlationId?: string | null;
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  meta?: MessageMeta;
}

// ─── Provenance status ────────────────────────────────────────────────────────

type ProvCfg = {
  label: string;
  className: string;
  Icon: React.ComponentType<{ className?: string }>;
};

const PROVENANCE_CONFIG: Record<string, ProvCfg> = {
  PROVENANCE_VALID:                { label: 'Sources verified',     className: 'text-success', Icon: CheckCircle2 },
  PROVENANCE_SOURCE_NOT_RETRIEVED: { label: 'Source not retrieved', className: 'text-warning', Icon: AlertCircle },
  PROVENANCE_SOURCE_NOT_IN_PROMPT: { label: 'Source not in prompt', className: 'text-warning', Icon: AlertCircle },
  PROVENANCE_NO_CONTEXT_AVAILABLE: { label: 'No context available', className: 'text-muted',   Icon: HelpCircle },
};

function ProvenanceStatusBadge({ status }: { status: string | null | undefined }) {
  const cfg: ProvCfg = (status != null && PROVENANCE_CONFIG[status]) || {
    label: status ?? 'Unknown',
    className: 'text-muted',
    Icon: HelpCircle,
  };
  const Icon = cfg.Icon;
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-medium ${cfg.className}`}
      aria-label="provenance-status-indicator"
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      {cfg.label}
    </span>
  );
}

// ─── Answer text ──────────────────────────────────────────────────────────────

// Plain text only. No innerHTML, no raw HTML rendering.
// Markdown rendering is intentionally conservative: safe by construction.
function AnswerText({ content }: { content: string }) {
  return (
    <p
      className="whitespace-pre-wrap break-words text-sm leading-relaxed text-foreground"
      aria-label="answer-text"
    >
      {content}
    </p>
  );
}

// ─── Metadata Panel (center column) ──────────────────────────────────────────

function MetadataPanel({ meta }: { meta: MessageMeta | undefined }) {
  if (!meta) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="metadata-empty"
      >
        <ShieldCheck className="h-7 w-7 text-muted/20" aria-hidden="true" />
        <p className="text-xs text-muted">Response metadata will appear here</p>
      </div>
    );
  }

  const prov = meta.provenance;
  const contextCount = prov?.context_count ?? 0;
  const noContext = prov?.used_rag === false || contextCount === 0;
  const effectiveConfidence = meta.confidence ?? prov?.confidence;

  return (
    <div className="space-y-5" aria-label="answer-metadata-panel">

      {/* Provider / model */}
      <section>
        <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
          Provider
        </h3>
        {meta.provider ? (
          <ProviderRouteCard
            provider={meta.provider}
            model={meta.model}
            latencyMs={meta.latencyMs}
            decision={meta.policyDecision?.action}
          />
        ) : (
          <p className="text-xs text-muted" aria-label="provider-unavailable">
            Provider not reported
          </p>
        )}
      </section>

      {/* Policy decision (when no ProviderRouteCard) */}
      {meta.policyDecision && !meta.provider && (
        <section>
          <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Policy Decision
          </h3>
          <PolicyDecision
            action={meta.policyDecision.action}
            reason={meta.policyDecision.reason}
            policy={meta.policyDecision.policy}
          />
        </section>
      )}

      {/* Confidence */}
      <section>
        <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
          Confidence
        </h3>
        {effectiveConfidence != null ? (
          <ConfidenceMeter value={effectiveConfidence} />
        ) : (
          <p className="text-xs text-muted" aria-label="confidence-unavailable">
            Not measured
          </p>
        )}
      </section>

      {/* Provenance */}
      <section>
        <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
          Provenance
        </h3>
        <ProvenanceStatusBadge status={prov?.provenance_status} />
        {prov?.provenance_status &&
          prov.provenance_status !== 'PROVENANCE_VALID' &&
          prov.provenance_status !== 'PROVENANCE_NO_CONTEXT_AVAILABLE' && (
            <p className="mt-1 text-[10px] text-warning">
              Provenance validation did not pass.
            </p>
          )}
      </section>

      {/* Context */}
      <section>
        <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
          Context
        </h3>
        {noContext ? (
          <div aria-label="no-context-state">
            <p className="text-xs text-muted">No context available</p>
            <p className="mt-0.5 text-[10px] text-muted/50">
              Answer generated without retrieval context.
            </p>
          </div>
        ) : (
          <p className="text-xs text-muted" aria-label="context-count-display">
            {contextCount} chunk{contextCount !== 1 ? 's' : ''} used
          </p>
        )}
      </section>

      {/* Retrieval strategy */}
      {prov?.retrieval_strategy && (
        <section>
          <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Retrieval Strategy
          </h3>
          <p className="font-mono text-xs text-foreground" aria-label="retrieval-strategy">
            {prov.retrieval_strategy}
          </p>
        </section>
      )}

      {/* Retrieval trace steps */}
      {meta.retrievalSteps && meta.retrievalSteps.length > 0 && (
        <section>
          <RetrievalTrace steps={meta.retrievalSteps} defaultCollapsed />
        </section>
      )}

      {/* Trace IDs */}
      {(meta.requestId || meta.correlationId || prov?.retrieval_trace_id) && (
        <section>
          <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Trace
          </h3>
          <div className="space-y-0.5">
            {meta.requestId && (
              <p className="truncate font-mono text-[10px] text-muted/60" aria-label="request-id">
                req: {meta.requestId}
              </p>
            )}
            {meta.correlationId && (
              <p className="truncate font-mono text-[10px] text-muted/60" aria-label="correlation-id">
                corr: {meta.correlationId}
              </p>
            )}
            {prov?.retrieval_trace_id && (
              <p
                className="truncate font-mono text-[10px] text-muted/60"
                aria-label="retrieval-trace-id"
              >
                trace: {prov.retrieval_trace_id}
              </p>
            )}
          </div>
        </section>
      )}
    </div>
  );
}

// ─── Evidence Panel (right column) ───────────────────────────────────────────

function EvidencePanel({ meta }: { meta: MessageMeta | undefined }) {
  if (!meta) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="evidence-empty"
      >
        <BookOpen className="h-7 w-7 text-muted/20" aria-hidden="true" />
        <p className="text-xs text-muted">Sources will appear here</p>
      </div>
    );
  }

  const prov = meta.provenance;
  const chunkIds = prov?.source_chunk_ids ?? [];
  const summaries = prov?.source_summaries ?? [];
  const whyChunk = prov?.why_this_chunk ?? null;
  const hasSources =
    chunkIds.length > 0 ||
    summaries.length > 0 ||
    (meta.citations != null && meta.citations.length > 0);

  if (!hasSources) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="no-sources-state"
      >
        <BookOpen className="h-7 w-7 text-muted/20" aria-hidden="true" />
        <p className="text-xs text-muted">No sources for this response</p>
        <p className="max-w-[200px] text-[10px] text-muted/50">
          {prov?.provenance_status === 'PROVENANCE_NO_CONTEXT_AVAILABLE'
            ? 'No retrieval context was available for this request.'
            : 'No source references were returned.'}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-5" aria-label="evidence-sources-panel">

      {/* Source validity */}
      <section>
        <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
          Source Validity
        </h3>
        <ProvenanceStatusBadge status={prov?.provenance_status} />
      </section>

      {/* API-provided citations */}
      {meta.citations && meta.citations.length > 0 && (
        <section aria-label="source-citations">
          <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Citations
          </h3>
          <CitationViewer citations={meta.citations} />
        </section>
      )}

      {/* Provenance source summaries */}
      {summaries.length > 0 && (
        <section aria-label="source-summaries">
          <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Source Summaries ({summaries.length})
          </h3>
          <ul className="space-y-2">
            {summaries.map((s, i) => (
              <li
                key={s.chunk_id ?? i}
                className="rounded-lg border border-border bg-surface-2 p-2.5"
                aria-label="source-summary-item"
              >
                {s.chunk_id && (
                  <p className="truncate font-mono text-[10px] text-muted/70">
                    chunk: {s.chunk_id}
                  </p>
                )}
                {s.source_id && (
                  <p className="truncate font-mono text-[10px] text-muted/70">
                    src: {s.source_id}
                  </p>
                )}
                {s.chunk_index != null && (
                  <p className="font-mono text-[10px] text-muted/50">idx: {s.chunk_index}</p>
                )}
                {s.included_in_prompt !== undefined && (
                  <p
                    className={`mt-0.5 text-[10px] ${
                      s.included_in_prompt ? 'text-success' : 'text-muted/50'
                    }`}
                  >
                    {s.included_in_prompt ? 'Included in prompt' : 'Not in prompt'}
                  </p>
                )}
                {s.phi_sensitivity_level && s.phi_sensitivity_level !== 'NONE' && (
                  <p className="mt-0.5 text-[10px] text-warning">
                    PHI: {s.phi_sensitivity_level}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Chunk IDs (fallback when no summaries) */}
      {chunkIds.length > 0 && summaries.length === 0 && (
        <section aria-label="source-chunk-ids">
          <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Chunk IDs
          </h3>
          <ul className="space-y-1">
            {chunkIds.slice(0, 10).map((id) => (
              <li key={id} className="truncate font-mono text-[10px] text-muted/70">
                {id}
              </li>
            ))}
            {chunkIds.length > 10 && (
              <li className="text-[10px] text-muted/50">+{chunkIds.length - 10} more</li>
            )}
          </ul>
        </section>
      )}

      {/* Why-this-chunk explanations */}
      {whyChunk != null && Object.keys(whyChunk).length > 0 && (
        <section aria-label="why-this-chunk">
          <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Retrieval Explanation
          </h3>
          <ul className="space-y-1.5">
            {Object.entries(whyChunk)
              .slice(0, 5)
              .map(([chunkId, reason]) => (
                <li
                  key={chunkId}
                  className="rounded border border-border bg-surface-2 p-2 text-[10px]"
                >
                  <p className="truncate font-mono text-muted/70">{chunkId}</p>
                  {reason != null && typeof reason === 'object' && (
                    <p className="mt-0.5 text-muted">
                      {(reason as { rank_reason?: string }).rank_reason ?? 'Retrieved'}
                    </p>
                  )}
                </li>
              ))}
          </ul>
        </section>
      )}
    </div>
  );
}

// ─── Copy / export helpers ────────────────────────────────────────────────────

async function copyToClipboard(text: string): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function buildExportPayload(msg: Message): string {
  const prov = msg.meta?.provenance;
  // Safe subset: no raw vectors, no provider internals, no secrets, no raw prompts.
  return JSON.stringify(
    {
      answer: msg.content,
      provider: msg.meta?.provider ?? null,
      model: msg.meta?.model ?? null,
      request_id: msg.meta?.requestId ?? null,
      correlation_id: msg.meta?.correlationId ?? null,
      provenance_status: prov?.provenance_status ?? null,
      context_count: prov?.context_count ?? null,
      retrieval_strategy: prov?.retrieval_strategy ?? null,
      used_rag: prov?.used_rag ?? null,
      source_chunk_ids: prov?.source_chunk_ids ?? null,
      confidence: msg.meta?.confidence ?? prov?.confidence ?? null,
    },
    null,
    2,
  );
}

// ─── Main workspace page ──────────────────────────────────────────────────────

export default function WorkspacePage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copyStatus, setCopyStatus] = useState<'idle' | 'ok' | 'fail'>('idle');

  // Deterministic message IDs via counter — no crypto.randomUUID() for render IDs
  const msgIdRef = useRef(0);
  // Session ID is a one-time backend correlation identifier, not a render ID
  const sessionRef = useRef<string>(
    typeof crypto !== 'undefined' ? crypto.randomUUID() : 'sess-0',
  );
  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const latestAssistant = [...messages].reverse().find((m) => m.role === 'assistant');
  const lastUserMessage = [...messages].reverse().find((m) => m.role === 'user');

  function nextId(): string {
    msgIdRef.current += 1;
    return `msg-${msgIdRef.current}`;
  }

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function sendPrompt(prompt: string) {
    setLoading(true);
    setError('');
    setCopyStatus('idle');

    try {
      const res = await fetch('/api/core/ui/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: prompt, session_id: sessionRef.current }),
        cache: 'no-store',
      });

      const data: ApiResponse = await res.json();

      if (!res.ok || data.error) {
        setError(data.error ?? `Request failed (${res.status})`);
        return;
      }

      const citations: Citation[] = (data.citations ?? []).map((c) => ({
        index: c.index,
        source: c.source,
        excerpt: c.excerpt,
        url: c.url,
      }));

      const retrievalSteps: TraceStep[] = (data.retrieval_steps ?? []).map((s) => ({
        step: s.step,
        latencyMs: s.latency_ms,
        detail: s.detail,
      }));

      const meta: MessageMeta = {
        provider: data.provider,
        model: data.model,
        latencyMs: data.latency_ms,
        requestId: data.request_id,
        policyDecision: data.policy_decision,
        confidence: data.confidence,
        citations: citations.length > 0 ? citations : undefined,
        retrievalSteps: retrievalSteps.length > 0 ? retrievalSteps : undefined,
        provenance: data.provenance,
        correlationId: data.correlation_id,
      };

      const content = data.answer ?? 'No response received.';
      setMessages((prev) => [
        ...prev,
        { id: nextId(), role: 'assistant', content, meta },
      ]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Network error');
    } finally {
      setLoading(false);
      setTimeout(() => textareaRef.current?.focus(), 50);
    }
  }

  function handleSend() {
    const prompt = input.trim();
    if (!prompt || loading) return;
    setMessages((prev) => [
      ...prev,
      { id: nextId(), role: 'user', content: prompt },
    ]);
    setInput('');
    sendPrompt(prompt);
  }

  function handleRetry() {
    if (!lastUserMessage || loading) return;
    setMessages((prev) => [
      ...prev,
      { id: nextId(), role: 'user', content: lastUserMessage.content },
    ]);
    sendPrompt(lastUserMessage.content);
  }

  async function handleCopyAnswer() {
    if (!latestAssistant) return;
    const ok = await copyToClipboard(latestAssistant.content);
    setCopyStatus(ok ? 'ok' : 'fail');
    setTimeout(() => setCopyStatus('idle'), 2000);
  }

  async function handleExport() {
    if (!latestAssistant) return;
    const payload = buildExportPayload(latestAssistant);
    const copied = await copyToClipboard(payload);
    if (!copied && typeof document !== 'undefined') {
      const blob = new Blob([payload], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'workspace-response.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  return (
    <div className="flex h-full flex-col" aria-label="ai-workspace">
      <TopBar
        title="AI Workspace"
        subtitle="Governed AI interaction with provenance, confidence, and source tracing"
      />

      {/* 3-column workspace: conversation | metadata | evidence */}
      <div className="flex min-h-0 flex-1 flex-col divide-y divide-border lg:flex-row lg:divide-x lg:divide-y-0">

        {/* ── LEFT: Conversation ─────────────────────────────────────────────── */}
        <div
          className="flex min-h-0 flex-1 flex-col"
          aria-label="conversation-panel"
        >
          {/* Message thread */}
          <div className="min-h-[40vh] flex-1 overflow-y-auto space-y-3 px-4 py-4 lg:min-h-0">
            {messages.length === 0 && (
              <div
                className="flex flex-col items-center justify-center gap-3 py-16 text-center"
                aria-label="conversation-empty"
              >
                <ShieldCheck className="h-10 w-10 text-muted/20" aria-hidden="true" />
                <p className="text-sm font-medium text-foreground">AI Workspace</p>
                <p className="max-w-xs text-xs text-muted">
                  Every response shows provider route, provenance status, confidence, and source
                  references.
                </p>
              </div>
            )}

            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                aria-label={msg.role === 'user' ? 'user-message' : 'assistant-message'}
              >
                <div
                  className={`max-w-[80%] rounded-xl px-4 py-3 text-sm ${
                    msg.role === 'user'
                      ? 'bg-primary text-white'
                      : 'border border-border bg-surface-2'
                  }`}
                >
                  {msg.role === 'assistant' ? (
                    <AnswerText content={msg.content} />
                  ) : (
                    <p className="text-sm leading-relaxed">{msg.content}</p>
                  )}
                </div>
              </div>
            ))}

            {loading && (
              <div
                className="flex justify-start"
                aria-label="assistant-thinking"
                aria-live="polite"
              >
                <div className="animate-pulse rounded-xl border border-border bg-surface-2 px-4 py-3 text-xs text-muted">
                  Generating response…
                </div>
              </div>
            )}

            <div ref={bottomRef} />
          </div>

          {/* Error banner */}
          {error && (
            <div
              className="mx-4 mb-2 flex items-center gap-2 rounded border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger"
              aria-live="assertive"
              aria-label="error-banner"
            >
              <AlertCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              {error}
            </div>
          )}

          {/* Input bar */}
          <div className="border-t border-border px-4 py-3 space-y-2">
            <div className="flex gap-2">
              <label htmlFor="workspace-input" className="sr-only">
                Message
              </label>
              <textarea
                ref={textareaRef}
                id="workspace-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSend();
                  }
                }}
                placeholder="Ask a governed question… (Enter to send, Shift+Enter for newline)"
                disabled={loading}
                rows={2}
                className="flex-1 resize-none rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-foreground placeholder:text-muted/40 focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
              />
              <Button
                onClick={handleSend}
                disabled={!input.trim() || loading}
                size="sm"
                className="self-end gap-1.5"
                aria-label="Send message"
              >
                <Send className="h-3.5 w-3.5" aria-hidden="true" />
                Send
              </Button>
            </div>

            {/* Secondary controls */}
            <div className="flex items-center justify-between">
              <Button
                onClick={handleRetry}
                disabled={!lastUserMessage || loading}
                size="sm"
                variant="outline"
                className="gap-1.5"
                aria-label="Retry last message"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                Retry
              </Button>
              <div className="flex gap-1.5">
                <Button
                  onClick={handleCopyAnswer}
                  disabled={!latestAssistant}
                  size="sm"
                  variant="outline"
                  className="gap-1"
                  aria-label="Copy answer text"
                >
                  <Clipboard className="h-3 w-3" aria-hidden="true" />
                  {copyStatus === 'ok' ? 'Copied' : copyStatus === 'fail' ? 'Failed' : 'Copy'}
                </Button>
                <Button
                  onClick={handleExport}
                  disabled={!latestAssistant}
                  size="sm"
                  variant="outline"
                  className="gap-1"
                  aria-label="Export response metadata"
                >
                  <Download className="h-3 w-3" aria-hidden="true" />
                  Export
                </Button>
              </div>
            </div>

            <p className="text-center text-[10px] text-muted/40">
              All requests routed through FrostGate policy enforcement
            </p>
          </div>
        </div>

        {/* ── CENTER: Answer Metadata ────────────────────────────────────────── */}
        <div
          className="flex flex-col lg:w-72 lg:shrink-0"
          aria-label="metadata-column"
        >
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <Layers className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
            <h2 className="text-xs font-semibold text-foreground">Response Metadata</h2>
          </div>
          <div className="flex-1 overflow-y-auto p-4">
            <MetadataPanel meta={latestAssistant?.meta} />
          </div>
        </div>

        {/* ── RIGHT: Evidence & Sources ──────────────────────────────────────── */}
        <div
          className="flex flex-col lg:w-64 lg:shrink-0"
          aria-label="evidence-column"
        >
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <BookOpen className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
            <h2 className="text-xs font-semibold text-foreground">Evidence &amp; Sources</h2>
          </div>
          <div className="flex-1 overflow-y-auto p-4">
            <EvidencePanel meta={latestAssistant?.meta} />
          </div>
        </div>

      </div>
    </div>
  );
}
