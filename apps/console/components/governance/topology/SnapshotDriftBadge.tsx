'use client';

import { Loader2, RefreshCw } from 'lucide-react';
import type { GraphStats } from '@/lib/governanceApi';
import { cn } from '@/lib/cn';

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMin = Math.floor(diffMs / 60_000);
  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDays = Math.floor(diffHr / 24);
  return `${diffDays}d ago`;
}

interface SnapshotDriftBadgeProps {
  stats: GraphStats | null;
  loading: boolean;
  onRebuild: () => void;
  rebuilding: boolean;
}

export function SnapshotDriftBadge({ stats, loading, onRebuild, rebuilding }: SnapshotDriftBadgeProps) {
  const snap = stats?.last_snapshot ?? null;

  return (
    <div className="flex items-center gap-3 text-xs text-muted">
      {snap ? (
        <>
          <span className="font-mono text-foreground">Snapshot #{snap.snapshot_seq}</span>
          <span>{relativeTime(snap.built_at)}</span>
          <span className="text-muted/60">
            +{snap.nodes_upserted} nodes · +{snap.edges_upserted} edges
          </span>
          {(stats?.anomaly_count ?? 0) > 0 && (
            <span className="inline-flex items-center rounded border border-risk-critical/30 bg-risk-critical/10 px-1.5 py-0.5 font-semibold uppercase tracking-wider text-risk-critical">
              {stats!.anomaly_count} anomalies
            </span>
          )}
        </>
      ) : (
        !loading && (
          <span className="text-muted/60">No snapshot — run rebuild</span>
        )
      )}
      <button
        onClick={onRebuild}
        disabled={rebuilding}
        className={cn(
          'flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2 py-1 text-xs font-medium text-foreground transition hover:bg-surface-3 disabled:cursor-not-allowed disabled:opacity-50',
        )}
      >
        {rebuilding ? (
          <Loader2 className="h-3 w-3 animate-spin" />
        ) : (
          <RefreshCw className="h-3 w-3" />
        )}
        Rebuild
      </button>
    </div>
  );
}
