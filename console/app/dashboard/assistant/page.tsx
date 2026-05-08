'use client';

import { useEffect, useRef, useState } from 'react';
import { Send, ShieldCheck } from 'lucide-react';
import { AssistantMessage } from '@/components/ai/AssistantMessage';
import type { MessageMeta } from '@/components/ai/AssistantMessage';
import type { Citation, TraceStep } from '@/components/governance';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  meta?: MessageMeta;
}

interface ApiResponse {
  answer?: string;
  provider?: string;
  model?: string;
  latency_ms?: number;
  policy_decision?: { action: string; reason?: string; policy?: string };
  confidence?: number;
  citations?: Array<{ index: number; source: string; excerpt?: string; url?: string }>;
  retrieval_steps?: Array<{ step: string; latency_ms?: number; detail?: string }>;
  correlation_id?: string;
  session_id?: string;
  error?: string;
}

function metaFromResponse(res: ApiResponse): MessageMeta {
  const citations: Citation[] = (res.citations ?? []).map((c) => ({
    index: c.index,
    source: c.source,
    excerpt: c.excerpt,
    url: c.url,
  }));
  const retrievalSteps: TraceStep[] = (res.retrieval_steps ?? []).map((s) => ({
    step: s.step,
    latencyMs: s.latency_ms,
    detail: s.detail,
  }));
  return {
    provider: res.provider,
    model: res.model,
    latencyMs: res.latency_ms,
    policyDecision: res.policy_decision,
    confidence: res.confidence,
    citations: citations.length ? citations : undefined,
    retrievalSteps: retrievalSteps.length ? retrievalSteps : undefined,
    correlationId: res.correlation_id,
    sessionId: res.session_id,
  };
}

export default function AssistantPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const sessionId = useRef<string>(
    typeof crypto !== 'undefined' ? crypto.randomUUID() : `sess-${Date.now()}`,
  );
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function send() {
    const text = input.trim();
    if (!text || loading) return;

    const userMsg: Message = { id: crypto.randomUUID(), role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);
    setError('');

    try {
      const res = await fetch('/api/core/ui/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, session_id: sessionId.current }),
        cache: 'no-store',
      });

      const data: ApiResponse = await res.json();

      if (!res.ok || data.error) {
        setError(data.error ?? `Request failed (${res.status})`);
        return;
      }

      const action = data.policy_decision?.action?.toLowerCase() ?? '';
      if (action === 'deny' || action === 'blocked' || action === 'block') {
        // Policy denial — show inline PolicyDecision notice, not a chat bubble
        const denyMsg: Message = {
          id: crypto.randomUUID(),
          role: 'assistant',
          content: data.policy_decision?.reason ?? 'This request was denied by policy.',
          meta: metaFromResponse(data),
        };
        setMessages((prev) => [...prev, denyMsg]);
        return;
      }

      const assistantMsg: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: data.answer ?? 'No response received.',
        meta: metaFromResponse(data),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Network error');
    } finally {
      setLoading(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-border px-6 py-4">
        <ShieldCheck className="h-4 w-4 text-primary" />
        <div>
          <h1 className="text-base font-semibold text-foreground">AI Assistant</h1>
          <p className="text-xs text-muted">Every request policy-checked, classified, and audited</p>
        </div>
      </div>

      {/* Message thread */}
      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-center py-16">
            <ShieldCheck className="h-10 w-10 text-muted/20" />
            <p className="text-sm text-muted">
              Ask anything — every response shows provider route,<br />
              policy decision, confidence, and sources.
            </p>
          </div>
        )}
        {messages.map((msg) => (
          <AssistantMessage
            key={msg.id}
            role={msg.role}
            content={msg.content}
            meta={msg.meta}
          />
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="rounded-xl bg-surface-2 border border-border px-4 py-3 text-xs text-muted animate-pulse">
              Thinking…
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Error */}
      {error && (
        <div className="mx-6 mb-2 rounded border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger">
          {error}
        </div>
      )}

      {/* Input bar */}
      <div className="border-t border-border px-6 py-4">
        <div className="flex gap-2">
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && send()}
            placeholder="Ask a question…"
            disabled={loading}
            className="flex-1 rounded-lg border border-border bg-surface-2 px-4 py-2.5 text-sm text-foreground placeholder:text-muted/40 focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
          />
          <button
            onClick={send}
            disabled={!input.trim() || loading}
            className="flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-40"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
        <p className="mt-2 text-center text-[10px] text-muted/40">
          All requests routed through FrostGate policy enforcement · Session: {sessionId.current.slice(0, 8)}
        </p>
      </div>
    </div>
  );
}
