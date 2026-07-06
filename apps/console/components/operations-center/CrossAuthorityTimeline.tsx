'use client';

import { useEffect, useState } from 'react';
import {
  getCrossAuthorityTimeline,
  type CrossAuthorityTimelineResult,
  type TimelineEvent,
} from '@/lib/operationsCenterApi';

function severityDot(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500';
    case 'high': return 'bg-orange-500';
    case 'medium': return 'bg-yellow-500';
    case 'low': return 'bg-blue-500';
    default: return 'bg-muted/50';
  }
}

function relativeTime(ts: string): string {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function CrossAuthorityTimeline() {
  const [result, setResult] = useState<CrossAuthorityTimelineResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeAuthority, setActiveAuthority] = useState<string>('All');

  useEffect(() => {
    getCrossAuthorityTimeline().then((res) => {
      if (res.ok) {
        setResult(res.data);
      } else {
        setError(res.error);
      }
      setLoading(false);
    });
  }, []);

  const filters = result ? ['All', ...result.authorities] : ['All'];
  const filtered: TimelineEvent[] = result
    ? activeAuthority === 'All'
      ? result.events
      : result.events.filter((e) => e.authority === activeAuthority)
    : [];

  return (
    <div
      data-mcim="MCIM-18.7-TIMELINE"
      className="rounded-lg border border-border bg-surface-2 p-4"
    >
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-muted/70">
          Cross Authority Timeline
        </h2>
        {result && (
          <span className="text-xs text-muted" aria-label={`Total events: ${result.total}`}>
            {result.total} event{result.total !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {loading && (
        <p className="text-sm text-muted" aria-live="polite">Loading…</p>
      )}

      {!loading && error && (
        <p className="text-sm text-danger" role="alert" aria-label="Error loading timeline">
          {error}
        </p>
      )}

      {!loading && !error && result && (
        <>
          <div className="mb-4 flex flex-wrap gap-2" role="toolbar" aria-label="Authority filter">
            {filters.map((auth) => (
              <button
                key={auth}
                tabIndex={0}
                onClick={() => setActiveAuthority(auth)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setActiveAuthority(auth); }}
                aria-pressed={activeAuthority === auth}
                aria-label={`Filter by ${auth}`}
                className={
                  activeAuthority === auth
                    ? 'rounded border border-primary/40 bg-primary/10 px-2 py-1 text-xs font-medium text-primary'
                    : 'rounded border border-border bg-surface px-2 py-1 text-xs text-muted hover:text-foreground hover:border-primary/40'
                }
              >
                {auth}
              </button>
            ))}
          </div>

          {filtered.length === 0 ? (
            <p className="text-sm text-muted">No timeline events available.</p>
          ) : (
            <ol className="space-y-2" role="list" aria-label="Timeline events">
              {filtered.map((event) => (
                <li
                  key={event.id}
                  role="listitem"
                  aria-label={`${event.eventType} from ${event.authority}, severity ${event.severity}`}
                  className="flex gap-3 rounded border border-border bg-surface px-3 py-2"
                >
                  <span
                    className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${severityDot(event.severity)}`}
                    aria-hidden="true"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className="text-xs text-muted"
                        title={event.ts}
                        aria-label={`Timestamp: ${event.ts}`}
                      >
                        {relativeTime(event.ts)}
                      </span>
                      <span className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-muted" aria-label={`Authority: ${event.authority}`}>
                        {event.authority}
                      </span>
                      <span className="text-xs text-muted" aria-label={`Category: ${event.category}`}>{event.category}</span>
                      <span className="text-xs font-medium text-foreground">{event.eventType}</span>
                    </div>
                    {event.summary && (
                      <p className="mt-0.5 text-xs text-muted">{event.summary}</p>
                    )}
                    <div className="mt-1 flex flex-wrap gap-2">
                      {event.immutable && (
                        <span className="text-xs text-muted" aria-label="Immutable record">&#x1F512; immutable</span>
                      )}
                      {event.auditable && (
                        <span className="text-xs text-muted" aria-label="Auditable record">auditable</span>
                      )}
                      {event.requestId && (
                        <a
                          href={`/dashboard/forensics?request_id=${event.requestId}`}
                          className="text-xs text-primary hover:underline"
                          aria-label={`View forensics for request ${event.requestId}`}
                          tabIndex={0}
                        >
                          {event.requestId}
                        </a>
                      )}
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </div>
  );
}
