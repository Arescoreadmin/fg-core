'use client';

import { Loader2 } from 'lucide-react';
import { RiskBadge } from '@/components/governance/RiskBadge';
import type { AnomalyResponse } from '@/lib/governanceApi';

const PATTERN_LABELS: Record<string, string> = {
  ungoverned_high_centrality:       'Ungoverned High-Centrality Asset',
  privileged_identity_to_shadow_ai: 'Privileged Identity → Shadow AI',
  orphaned_finding:                 'Orphaned Finding',
  zero_trust_score_node:            'Stale/Deleted Node',
  promoted_candidate_no_owner:      'Auto-Promoted Asset Without Owner',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

interface AnomalyQueryPanelProps {
  anomalies: AnomalyResponse[];
  loading: boolean;
  onHighlight: (nodeIds: Set<string>) => void;
  onResolve: (anomalyId: string) => void;
  resolving: string | null;
}

export function AnomalyQueryPanel({ anomalies, loading, onHighlight, onResolve, resolving }: AnomalyQueryPanelProps) {
  if (loading) {
    return <p className="text-xs text-muted">Loading anomalies…</p>;
  }

  const activeAnomalies = anomalies.filter(a => a.is_active);

  if (activeAnomalies.length === 0 && anomalies.length === 0) {
    return <p className="text-xs text-muted">No active anomalies detected.</p>;
  }

  const grouped = SEVERITY_ORDER.reduce<Record<string, AnomalyResponse[]>>((acc, sev) => {
    const group = anomalies.filter(a => a.severity.toLowerCase() === sev);
    if (group.length > 0) acc[sev] = group;
    return acc;
  }, {});

  const ungrouped = anomalies.filter(
    a => !SEVERITY_ORDER.includes(a.severity.toLowerCase()),
  );
  if (ungrouped.length > 0) grouped['other'] = ungrouped;

  return (
    <div className="space-y-4">
      {activeAnomalies.length === 0 && (
        <p className="text-xs text-muted">No active anomalies detected.</p>
      )}
      {Object.entries(grouped).map(([severity, group]) => (
        <div key={severity} className="space-y-2">
          <div className="flex items-center gap-2">
            <RiskBadge level={severity} />
            <span className="text-[10px] text-muted">{group.length}</span>
          </div>
          {group.map(anomaly => (
            <div
              key={anomaly.anomaly_id}
              className="rounded border border-border bg-surface-3 p-2 space-y-1.5"
            >
              <div className="flex items-start justify-between gap-1">
                <p className="text-xs font-medium text-foreground leading-tight">
                  {PATTERN_LABELS[anomaly.pattern_id] ?? anomaly.pattern_id}
                </p>
                {!anomaly.is_active && (
                  <span className="shrink-0 rounded bg-surface-2 border border-border px-1 py-0.5 text-[10px] text-muted uppercase tracking-wider">
                    Resolved
                  </span>
                )}
              </div>
              <p className="text-[10px] text-muted/80 leading-relaxed">
                {truncate(anomaly.description, 80)}
              </p>
              <p className="text-[10px] text-muted/60">{formatDate(anomaly.detected_at)}</p>
              <div className="flex gap-1.5 pt-0.5">
                <button
                  onClick={() => onHighlight(new Set(anomaly.node_ids))}
                  className="rounded border border-border bg-surface-2 px-2 py-0.5 text-[10px] font-medium text-foreground hover:bg-surface-3 transition"
                >
                  Highlight
                </button>
                {anomaly.is_active && (
                  <button
                    onClick={() => onResolve(anomaly.anomaly_id)}
                    disabled={resolving === anomaly.anomaly_id}
                    className="flex items-center gap-1 rounded border border-risk-high/40 bg-risk-high/10 px-2 py-0.5 text-[10px] font-medium text-risk-high hover:bg-risk-high/20 transition disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {resolving === anomaly.anomaly_id && (
                      <Loader2 className="h-2.5 w-2.5 animate-spin" />
                    )}
                    Resolve
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
