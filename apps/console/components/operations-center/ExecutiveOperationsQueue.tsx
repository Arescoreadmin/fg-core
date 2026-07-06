'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  getOperationsQueue,
  type OperationsQueueItem,
  type OperationsQueueResult,
  type Severity,
} from '@/lib/operationsCenterApi';

type SeverityFilter = 'all' | Severity;

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const FILTERS: { id: SeverityFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'medium', label: 'Medium' },
  { id: 'low', label: 'Low' },
];

function severityBadgeClass(sev: Severity): string {
  switch (sev) {
    case 'critical': return 'bg-red-500/10 text-red-400 border border-red-500/20';
    case 'high':     return 'bg-orange-500/10 text-orange-400 border border-orange-500/20';
    case 'medium':   return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
    case 'low':      return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
    default:         return 'bg-surface text-muted border border-border';
  }
}

function sortItems(items: OperationsQueueItem[]): OperationsQueueItem[] {
  return [...items].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
}

export default function ExecutiveOperationsQueue() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<OperationsQueueResult | null>(null);
  const [filter, setFilter] = useState<SeverityFilter>('all');

  useEffect(() => {
    let cancelled = false;
    getOperationsQueue().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  const visible = data
    ? sortItems(filter === 'all' ? data.items : data.items.filter((i) => i.severity === filter))
    : [];

  return (
    <div
      data-mcim="MCIM-18.7-OPS-QUEUE"
      className="rounded-lg border border-border bg-surface-2 p-4"
      aria-label="Executive Operations Queue"
    >
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Executive Operations Queue
      </h3>

      <div className="mb-3 flex flex-wrap gap-1" role="tablist" aria-label="Severity filter">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            role="tab"
            aria-selected={filter === f.id}
            tabIndex={filter === f.id ? 0 : -1}
            onClick={() => setFilter(f.id)}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setFilter(f.id); }}
            className={`rounded border px-2.5 py-1 text-xs font-medium transition-colors ${
              filter === f.id
                ? 'border-primary bg-primary/10 text-foreground'
                : 'border-border bg-surface text-muted hover:text-foreground'
            }`}
          >
            {f.label}
            {data && f.id !== 'all' && (
              <span className="ml-1.5 tabular-nums">{data.bySeverity[f.id as Severity] ?? 0}</span>
            )}
            {data && f.id === 'all' && (
              <span className="ml-1.5 tabular-nums">{data.total}</span>
            )}
          </button>
        ))}
      </div>

      {loading && (
        <div className="flex items-center gap-2 py-4 text-sm text-muted" aria-live="polite" aria-label="Loading operations queue">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      )}

      {error && (
        <p className="py-4 text-sm text-red-400" role="alert" aria-label="Operations queue error">
          {error}
        </p>
      )}

      {!loading && !error && visible.length === 0 && (
        <p className="py-4 text-sm text-muted" aria-label="No items in queue">
          No governance work items in queue.
        </p>
      )}

      {!loading && !error && visible.length > 0 && (
        <ul className="flex flex-col gap-2" aria-label="Queue items">
          {visible.map((item) => (
            <li
              key={item.id}
              className="rounded border border-border bg-surface p-3 text-xs"
              aria-label={`Queue item: ${item.title}, severity ${item.severity}`}
            >
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <span className={`rounded px-1.5 py-0.5 text-xs font-medium capitalize ${severityBadgeClass(item.severity)}`} aria-label={`Severity: ${item.severity}`}>
                  {item.severity}
                </span>
                <span className="font-medium text-foreground">{item.title}</span>
                <span className="ml-auto rounded border border-border bg-surface px-1.5 py-0.5 text-muted" aria-label={`Workflow state: ${item.workflowState}`}>
                  {item.workflowState}
                </span>
              </div>
              <div className="flex flex-wrap gap-3 text-muted mb-1.5">
                <span aria-label={`Authority: ${item.authority}`}>Auth: {item.authority}</span>
                {item.confidence && <span aria-label={`Confidence: ${item.confidence}`}>Conf: {item.confidence}</span>}
                {item.owner && <span aria-label={`Owner: ${item.owner}`}>Owner: {item.owner}</span>}
              </div>
              {item.summary && (
                <p className="text-muted line-clamp-2" aria-label="Summary">{item.summary}</p>
              )}
              <div className="mt-2">
                <a
                  href={`/dashboard/decisions?decision=${item.id}`}
                  className="rounded border border-border bg-surface px-2.5 py-1 text-xs text-muted hover:text-foreground hover:border-primary/40 focus:outline-none focus:ring-1 focus:ring-primary"
                  tabIndex={0}
                  aria-label={`View decision ${item.id}`}
                >
                  View
                </a>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
