'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  getEvidenceFreshness,
  type EvidenceRecord,
  type EvidenceFreshnessResult,
  type EvidenceStatus,
} from '@/lib/operationsCenterApi';

const STATUS_SUMMARY: { id: EvidenceStatus; label: string }[] = [
  { id: 'current',    label: 'Current' },
  { id: 'stale',      label: 'Stale' },
  { id: 'expiring',   label: 'Expiring' },
  { id: 'unverified', label: 'Unverified' },
  { id: 'missing',    label: 'Missing' },
];

function statusBadgeClass(status: EvidenceStatus): string {
  switch (status) {
    case 'current':    return 'bg-green-500/10 text-green-400 border border-green-500/20';
    case 'stale':      return 'bg-orange-500/10 text-orange-400 border border-orange-500/20';
    case 'expiring':   return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
    case 'unverified': return 'bg-surface text-muted border border-border';
    case 'missing':    return 'bg-red-500/10 text-red-400 border border-red-500/20';
    default:           return 'bg-surface text-muted border border-border';
  }
}

function trustBarClass(score: number): string {
  if (score >= 0.8) return 'bg-green-500';
  if (score >= 0.5) return 'bg-yellow-500';
  if (score >= 0.3) return 'bg-orange-500';
  return 'bg-red-500';
}

function fmtAge(hours: number | null): string {
  if (hours === null) return '—';
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

export default function EvidenceFreshnessMonitor() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<EvidenceFreshnessResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    getEvidenceFreshness().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  return (
    <div
      data-mcim="MCIM-18.7-EVIDENCE-FRESH"
      className="rounded-lg border border-border bg-surface-2 p-4"
      aria-label="Evidence Freshness Monitor"
    >
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Evidence Freshness Monitor
      </h3>

      {loading && (
        <div className="flex items-center gap-2 py-4 text-sm text-muted" aria-live="polite" aria-label="Loading evidence freshness">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      )}

      {error && (
        <p className="py-4 text-sm text-red-400" role="alert" aria-label="Evidence freshness error">
          {error}
        </p>
      )}

      {!loading && !error && data && (
        <>
          <div className="mb-3 flex flex-wrap gap-3 text-xs" aria-label="Evidence status summary">
            {STATUS_SUMMARY.map(({ id, label }) => (
              <span key={id} className="text-muted" aria-label={`${label}: ${data.byStatus[id]}`}>
                {label}: <span className="font-semibold text-foreground tabular-nums">{data.byStatus[id]}</span>
              </span>
            ))}
            {data.averageTrustScore !== null && (
              <span className="ml-auto text-muted" aria-label={`Average trust score: ${Math.round(data.averageTrustScore * 100)}%`}>
                Avg Trust: <span className="font-semibold text-foreground">{Math.round(data.averageTrustScore * 100)}%</span>
              </span>
            )}
          </div>

          {data.records.length === 0 ? (
            <p className="py-4 text-sm text-muted" aria-label="No evidence records">
              No evidence records. Governance graph may not be populated.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs" aria-label="Evidence records">
                <thead>
                  <tr className="border-b border-border text-muted">
                    <th className="pb-1.5 text-left font-medium" scope="col">Node</th>
                    <th className="pb-1.5 text-left font-medium" scope="col">Type</th>
                    <th className="pb-1.5 text-left font-medium" scope="col">Age</th>
                    <th className="pb-1.5 text-left font-medium" scope="col">Status</th>
                    <th className="pb-1.5 text-left font-medium w-24" scope="col">Trust</th>
                  </tr>
                </thead>
                <tbody>
                  {data.records.map((rec: EvidenceRecord) => (
                    <tr
                      key={rec.nodeId}
                      className="border-b border-border/50 hover:bg-surface/50"
                      aria-label={`Node: ${rec.label}, type ${rec.nodeType}, status ${rec.status}`}
                    >
                      <td className="py-1.5 pr-3 font-medium text-foreground max-w-[120px] truncate" title={rec.label}>
                        {rec.label}
                      </td>
                      <td className="py-1.5 pr-3 text-muted capitalize">{rec.nodeType}</td>
                      <td className="py-1.5 pr-3 text-muted tabular-nums" aria-label={`Age: ${fmtAge(rec.ageHours)}`}>{fmtAge(rec.ageHours)}</td>
                      <td className="py-1.5 pr-3">
                        <span className={`rounded px-1.5 py-0.5 text-xs capitalize ${statusBadgeClass(rec.status)}`} aria-label={`Status: ${rec.status}`}>
                          {rec.status}
                        </span>
                      </td>
                      <td className="py-1.5 w-24" aria-label={`Trust score: ${Math.round(rec.trustScore * 100)}%`}>
                        <div className="flex items-center gap-1.5">
                          <div className="flex-1 rounded-full bg-border h-1.5">
                            <div
                              className={`h-1.5 rounded-full ${trustBarClass(rec.trustScore)}`}
                              style={{ width: `${Math.min(100, Math.round(rec.trustScore * 100))}%` }}
                              role="progressbar"
                              aria-valuenow={Math.round(rec.trustScore * 100)}
                              aria-valuemin={0}
                              aria-valuemax={100}
                            />
                          </div>
                          <span className="text-muted tabular-nums w-7 text-right shrink-0">
                            {Math.round(rec.trustScore * 100)}%
                          </span>
                        </div>
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
