'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  getRiskHeatmap,
  type RiskCell,
  type RiskHeatmapResult,
  type Severity,
} from '@/lib/operationsCenterApi';

function cellBgClass(sev: Severity): string {
  switch (sev) {
    case 'critical': return 'bg-red-500/10 border-red-500/20';
    case 'high':     return 'bg-orange-500/10 border-orange-500/20';
    case 'medium':   return 'bg-yellow-500/10 border-yellow-500/20';
    case 'low':      return 'bg-blue-500/10 border-blue-500/20';
    default:         return 'bg-surface border-border';
  }
}

function cellTextClass(sev: Severity): string {
  switch (sev) {
    case 'critical': return 'text-red-400';
    case 'high':     return 'text-orange-400';
    case 'medium':   return 'text-yellow-400';
    case 'low':      return 'text-blue-400';
    default:         return 'text-muted';
  }
}

export default function OperationalRiskHeatmap() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<RiskHeatmapResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    getRiskHeatmap().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  return (
    <div
      data-mcim="MCIM-18.7-RISK-HEATMAP"
      className="rounded-lg border border-border bg-surface-2 p-4"
      aria-label="Operational Risk Heatmap"
    >
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Operational Risk Heatmap
      </h3>

      {loading && (
        <div className="flex items-center gap-2 py-4 text-sm text-muted" aria-live="polite" aria-label="Loading risk heatmap">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      )}

      {error && (
        <p className="py-4 text-sm text-red-400" role="alert" aria-label="Risk heatmap error">
          {error}
        </p>
      )}

      {!loading && !error && data && (
        <>
          <div className="mb-3 flex flex-wrap gap-4 text-xs" aria-label="Risk summary statistics">
            <span className="text-muted" aria-label={`Total anomalies: ${data.totalAnomalies}`}>
              Anomalies: <span className="font-semibold text-foreground">{data.totalAnomalies}</span>
            </span>
            <span className="text-muted" aria-label={`Node count: ${data.nodeCount}`}>
              Nodes: <span className="font-semibold text-foreground">{data.nodeCount}</span>
            </span>
            <span className="text-muted" aria-label={`Edge count: ${data.edgeCount}`}>
              Edges: <span className="font-semibold text-foreground">{data.edgeCount}</span>
            </span>
          </div>

          {data.cells.length === 0 ? (
            <div className="py-4">
              <p className="text-sm text-muted" aria-label="No risk data available">
                No risk data available. Governance graph may not be populated.
              </p>
            </div>
          ) : (
            <>
              <div
                className="grid gap-2"
                style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))' }}
                role="list"
                aria-label="Risk cells"
              >
                {data.cells.map((cell: RiskCell, i: number) => (
                  <div
                    key={`${cell.dimension}-${cell.category}-${i}`}
                    role="listitem"
                    className={`rounded border p-2.5 ${cellBgClass(cell.severity)}`}
                    aria-label={`Risk: ${cell.dimension} / ${cell.category}, count ${cell.count}, severity ${cell.severity}`}
                    tabIndex={0}
                  >
                    <div className="text-muted text-xs mb-0.5">{cell.dimension}</div>
                    <div className="font-medium text-foreground text-xs truncate mb-1" title={cell.category}>
                      {cell.category}
                    </div>
                    <div className={`text-lg font-semibold tabular-nums ${cellTextClass(cell.severity)}`}>
                      {cell.count}
                    </div>
                    <div className={`text-xs capitalize ${cellTextClass(cell.severity)}`} aria-label={`Severity: ${cell.severity}`}>
                      {cell.severity}
                    </div>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-xs text-muted" aria-label="Data source note">
                Derived from authoritative governance graph state only.
              </p>
            </>
          )}
        </>
      )}
    </div>
  );
}
