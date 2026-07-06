'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  getAutomationQueue,
  type AutomationQueueItem,
  type AutomationQueueResult,
  type AutomationStatus,
} from '@/lib/operationsCenterApi';

type StatusFilter = 'all' | AutomationStatus;

const STATUS_FILTERS: { id: StatusFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'pending', label: 'Pending' },
  { id: 'running', label: 'Running' },
  { id: 'completed', label: 'Completed' },
  { id: 'failed', label: 'Failed' },
  { id: 'blocked', label: 'Blocked' },
  { id: 'approval_required', label: 'Approval Required' },
];

function statusBadgeClass(status: AutomationStatus): string {
  switch (status) {
    case 'pending':          return 'bg-surface text-muted border border-border';
    case 'running':          return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
    case 'completed':        return 'bg-green-500/10 text-green-400 border border-green-500/20';
    case 'failed':           return 'bg-red-500/10 text-red-400 border border-red-500/20';
    case 'blocked':          return 'bg-orange-500/10 text-orange-400 border border-orange-500/20';
    case 'approval_required': return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
    case 'scheduled':        return 'bg-surface text-muted border border-border';
    default:                 return 'bg-surface text-muted border border-border';
  }
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

export default function GovernanceAutomationQueue() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<AutomationQueueResult | null>(null);
  const [filter, setFilter] = useState<StatusFilter>('all');

  useEffect(() => {
    let cancelled = false;
    getAutomationQueue().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  const visible: AutomationQueueItem[] = data
    ? (filter === 'all' ? data.items : data.items.filter((i) => i.status === filter))
    : [];

  return (
    <div
      data-mcim="MCIM-18.7-AUTO-QUEUE"
      className="rounded-lg border border-border bg-surface-2 p-4"
      aria-label="Governance Automation Queue"
    >
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Governance Automation Queue
      </h3>

      <div className="mb-3 flex flex-wrap gap-1" role="tablist" aria-label="Status filter">
        {STATUS_FILTERS.map((f) => (
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
              <span className="ml-1.5 tabular-nums">{data.byStatus[f.id as AutomationStatus] ?? 0}</span>
            )}
            {data && f.id === 'all' && (
              <span className="ml-1.5 tabular-nums">{data.items.length}</span>
            )}
          </button>
        ))}
      </div>

      {loading && (
        <div className="flex items-center gap-2 py-4 text-sm text-muted" aria-live="polite" aria-label="Loading automation queue">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      )}

      {error && (
        <p className="py-4 text-sm text-red-400" role="alert" aria-label="Automation queue error">
          {error}
        </p>
      )}

      {!loading && !error && visible.length === 0 && (
        <p className="py-4 text-sm text-muted" aria-label="No automation items">
          No automation items.
        </p>
      )}

      {!loading && !error && visible.length > 0 && (
        <ul className="flex flex-col gap-2" aria-label="Automation items">
          {visible.map((item) => (
            <li
              key={item.id}
              className="rounded border border-border bg-surface p-3 text-xs"
              aria-label={`Automation item: ${item.title}, status ${item.status}`}
            >
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <span className={`rounded px-1.5 py-0.5 text-xs font-medium capitalize ${statusBadgeClass(item.status)}`} aria-label={`Status: ${item.status}`}>
                  {item.status.replace('_', ' ')}
                </span>
                <span className="font-medium text-foreground">{item.title}</span>
                {item.rollbackAvailable && (
                  <span className="ml-auto rounded border border-border px-1.5 py-0.5 text-muted" aria-label="Rollback available">
                    Rollback available
                  </span>
                )}
              </div>
              <div className="flex flex-wrap gap-3 text-muted mb-1">
                {item.origin && <span aria-label={`Origin: ${item.origin}`}>Path: {item.origin}</span>}
                {item.reason && <span aria-label={`Reason: ${item.reason}`}>Reason: {item.reason}</span>}
                {item.evidence && <span aria-label={`Evidence request ID: ${item.evidence}`}>Req: {item.evidence}</span>}
              </div>
              <span className="text-muted" aria-label={`Created at: ${fmtDate(item.createdAt)}`}>
                {fmtDate(item.createdAt)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
