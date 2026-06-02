'use client';

import { useEffect, useRef, useState } from 'react';
import { getStoredEngagementId } from '@/lib/engagementStore';
import { portalApi } from '@/lib/portalApi';

interface Message {
  role: 'user' | 'assistant';
  text: string;
  provider?: string;
  model?: string;
  tokens?: number;
  policy?: string;
  error?: boolean;
}

const DEVICE_ID_KEY = 'fg_portal_device_id';

function getDeviceId(): string {
  if (typeof window === 'undefined') return 'portal-device';
  let id = localStorage.getItem(DEVICE_ID_KEY);
  if (!id) {
    id = `portal-${crypto.randomUUID()}`;
    localStorage.setItem(DEVICE_ID_KEY, id);
  }
  return id;
}

function MessageBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === 'user';
  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} gap-2`}>
      <div
        className={`max-w-[80%] rounded-lg px-4 py-3 text-sm leading-relaxed ${
          isUser
            ? 'bg-primary/20 border border-primary/30 text-foreground'
            : msg.error
            ? 'bg-red-500/10 border border-red-500/30 text-red-300'
            : 'bg-surface-2 border border-border text-foreground'
        }`}
      >
        <p className="whitespace-pre-wrap">{msg.text}</p>
        {!isUser && !msg.error && msg.model && (
          <p className="mt-1.5 text-[10px] text-muted">
            {msg.provider} · {msg.model} · {msg.tokens ?? 0} tokens · policy: {msg.policy ?? 'allow'}
          </p>
        )}
      </div>
    </div>
  );
}

export default function AssistantPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId] = useState(() => crypto.randomUUID());
  const [engagementId, setEngagementId] = useState<string>('');
  const [aiEnabled, setAiEnabled] = useState<boolean | null>(null); // null = still loading
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const eid = getStoredEngagementId();
    if (!eid) {
      setAiEnabled(false);
      return;
    }
    setEngagementId(eid);
    portalApi
      .getEngagement(eid)
      .then((eng) => {
        const enabled = !!(eng.engagement_metadata as Record<string, unknown> | null)?.portal_ai_enabled;
        setAiEnabled(enabled);
      })
      .catch(() => setAiEnabled(false));
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function sendMessage() {
    const text = input.trim();
    if (!text || loading) return;

    setInput('');
    setMessages((prev) => [...prev, { role: 'user', text }]);
    setLoading(true);

    try {
      const res = await fetch('/api/core/ui/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          session_id: sessionId,
          device_id: getDeviceId(),
          persona: 'default',
          engagement_id: engagementId || undefined,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        const code = data?.detail?.error_code ?? data?.code ?? `HTTP_${res.status}`;
        const friendly =
          code === 'AI_INPUT_POLICY_BLOCKED'
            ? 'That query was blocked by the governance policy for this workspace.'
            : code === 'AI_PROVIDER_DENIED_BY_TENANT_POLICY'
            ? 'No AI provider is configured for your account. Contact your operator.'
            : `Request was not processed (${code}).`;
        setMessages((prev) => [...prev, { role: 'assistant', text: friendly, error: true }]);
        return;
      }

      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: data.answer ?? data.response ?? '(no response)',
          provider: data.provider,
          model: data.model,
          tokens: data.usage?.total_tokens,
          policy: data.policy?.decision,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', text: 'Network error. Please try again.', error: true },
      ]);
    } finally {
      setLoading(false);
    }
  }

  function handleKey(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  // Loading state
  if (aiEnabled === null) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-sm text-muted">Loading…</p>
      </div>
    );
  }

  // Not enabled for this engagement
  if (!aiEnabled) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-lg font-semibold text-foreground">AI Assistant</h1>
          <p className="text-xs text-muted mt-0.5">Remediation guidance · assessment-aware</p>
        </div>
        <div className="rounded border border-border bg-surface p-8 text-center space-y-3">
          <p className="text-sm font-medium text-foreground">
            AI Assistant is not enabled for this engagement
          </p>
          <p className="text-xs text-muted max-w-sm mx-auto">
            The remediation AI assistant is available as part of the monthly tracking plan.
            Contact your FrostGate assessor to enable it for your account.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-foreground">AI Assistant</h1>
          <p className="text-xs text-muted mt-0.5">
            Governed AI workspace · every query is policy-enforced and audit-logged
          </p>
        </div>
        {engagementId && (
          <span className="text-xs text-muted border border-border rounded px-2 py-1">
            Assessment context active
          </span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto space-y-3 rounded border border-border bg-surface p-4">
        {messages.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-2">
              <p className="text-sm font-medium text-foreground">How can I help?</p>
              <p className="text-xs text-muted max-w-xs">
                Ask about your findings, compliance gaps, or what to fix first.
              </p>
              <div className="flex flex-wrap justify-center gap-2 mt-3">
                {[
                  'Summarize my critical findings',
                  'What should I fix first?',
                  'Explain my compliance gaps',
                  'What documents am I missing?',
                ].map((prompt) => (
                  <button
                    key={prompt}
                    onClick={() => setInput(prompt)}
                    className="rounded border border-border bg-surface-2 px-2.5 py-1 text-xs text-muted hover:text-foreground hover:border-primary/40 transition-colors"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
        {messages.map((msg, i) => (
          <MessageBubble key={i} msg={msg} />
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="rounded-lg border border-border bg-surface-2 px-4 py-3 text-sm text-muted">
              Thinking…
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="mt-3 flex gap-2">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          disabled={loading}
          rows={2}
          placeholder="Ask about your assessment… (Enter to send, Shift+Enter for newline)"
          className="flex-1 resize-none rounded border border-border bg-surface px-3 py-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:border-primary/60 disabled:opacity-50"
        />
        <button
          onClick={sendMessage}
          disabled={loading || !input.trim()}
          className="shrink-0 rounded border border-primary bg-primary/10 px-4 text-sm font-medium text-primary hover:bg-primary/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Send
        </button>
      </div>

      <p className="mt-2 text-[10px] text-muted text-center">
        All queries are governed by your organization&apos;s AI policy and retained for compliance review.
      </p>
    </div>
  );
}
