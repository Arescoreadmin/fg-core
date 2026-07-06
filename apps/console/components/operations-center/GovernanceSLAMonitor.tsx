'use client';

import { useEffect, useState } from 'react';
import {
  getGovernanceSLA,
  type SLAResult,
  type SLAItem,
} from '@/lib/operationsCenterApi';

function sortItems(items: SLAItem[]): SLAItem[] {
  return [...items].sort((a, b) => {
    if (a.slaBreached && !b.slaBreached) return -1;
    if (!a.slaBreached && b.slaBreached) return 1;
    const aUpcoming = !a.slaBreached && a.dueAt !== null;
    const bUpcoming = !b.slaBreached && b.dueAt !== null;
    if (aUpcoming && !bUpcoming) return -1;
    if (!aUpcoming && bUpcoming) return 1;
    return 0;
  });
}

function rowClasses(item: SLAItem): string {
  if (item.slaBreached) return 'border-l-2 border-l-red-500 bg-red-500/5';
  if (!item.slaBreached && item.dueAt !== null) return 'border-l-2 border-l-yellow-500 bg-yellow-500/5';
  return '';
}

export default function GovernanceSLAMonitor() {
  const [result, setResult] = useState<SLAResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getGovernanceSLA().then((res) => {
      if (res.ok) {
        setResult(res.data);
      } else {
        setError(res.error);
      }
      setLoading(false);
    });
  }, []);

  return (
    <div
      data-mcim="MCIM-18.7-SLA-MONITOR"
      className="rounded-lg border border-border bg-surface-2 p-4"
    >
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Governance SLA Monitor
      </h2>

      {loading && (
        <p className="text-sm text-muted" aria-live="polite">Loading…</p>
      )}

      {!loading && error && (
        <p className="text-sm text-danger" role="alert" aria-label="Error loading SLA data">
          {error}
        </p>
      )}

      {!loading && !error && result && (
        <>
          <div className="mb-4 flex gap-4" aria-label="SLA statistics">
            <div className="rounded border border-border bg-surface px-3 py-2 text-center" role="status" aria-label="Breached SLA items">
              <p className="text-lg font-semibold text-danger">{result.breached}</p>
              <p className="text-xs text-muted">Breached</p>
            </div>
            <div className="rounded border border-border bg-surface px-3 py-2 text-center" role="status" aria-label="Upcoming SLA items">
              <p className="text-lg font-semibold text-yellow-400">{result.upcoming}</p>
              <p className="text-xs text-muted">Upcoming</p>
            </div>
            <div className="rounded border border-border bg-surface px-3 py-2 text-center" role="status" aria-label="Average age in hours">
              <p className="text-lg font-semibold text-foreground">
                {result.averageAgeHours !== null ? Math.round(result.averageAgeHours) : '—'}
              </p>
              <p className="text-xs text-muted">Avg Age (hrs)</p>
            </div>
          </div>

          {result.items.length === 0 ? (
            <p className="text-sm text-muted">No SLA items.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs" role="table" aria-label="Governance SLA items">
                <thead>
                  <tr className="border-b border-border text-left text-muted">
                    <th className="pb-2 pr-3 font-medium">Title</th>
                    <th className="pb-2 pr-3 font-medium">Severity</th>
                    <th className="pb-2 pr-3 font-medium">Age (hrs)</th>
                    <th className="pb-2 pr-3 font-medium">Due</th>
                    <th className="pb-2 pr-3 font-medium">Owner</th>
                    <th className="pb-2 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {sortItems(result.items).map((item) => (
                    <tr
                      key={item.id}
                      className={`border-b border-border/50 ${rowClasses(item)}`}
                      aria-label={`SLA item: ${item.title}${item.slaBreached ? ', breached' : ''}`}
                    >
                      <td className="py-2 pr-3 text-foreground">{item.title}</td>
                      <td className="py-2 pr-3 text-muted">{item.severity}</td>
                      <td className="py-2 pr-3 text-muted">{item.ageHours ?? '—'}</td>
                      <td className="py-2 pr-3 text-muted">{item.dueAt ?? '—'}</td>
                      <td className="py-2 pr-3 text-muted">{item.owner ?? '—'}</td>
                      <td className="py-2">
                        {item.slaBreached ? (
                          <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-red-400" aria-label="SLA breached">breached</span>
                        ) : item.dueAt !== null ? (
                          <span className="rounded border border-yellow-500/30 bg-yellow-500/10 px-1.5 py-0.5 text-yellow-400" aria-label="SLA upcoming">upcoming</span>
                        ) : (
                          <span className="text-muted">open</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
