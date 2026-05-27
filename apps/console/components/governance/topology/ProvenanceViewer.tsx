'use client';

import { useEffect, useState } from 'react';
import { getLineage, type LineageResponse } from '@/lib/governanceApi';

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

interface ProvenanceViewerProps {
  nodeId: string | null;
}

export function ProvenanceViewer({ nodeId }: ProvenanceViewerProps) {
  const [lineage, setLineage] = useState<LineageResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!nodeId) {
      setLineage(null);
      return;
    }
    setLoading(true);
    setError(null);
    getLineage(nodeId)
      .then(setLineage)
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load lineage'))
      .finally(() => setLoading(false));
  }, [nodeId]);

  if (!nodeId) return null;

  if (loading) {
    return <p className="text-xs text-muted">Loading lineage…</p>;
  }

  if (error) {
    return <p className="text-xs text-risk-critical">{error}</p>;
  }

  if (!lineage || lineage.chain.length === 0) {
    return <p className="text-xs text-muted">No lineage chain found.</p>;
  }

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-foreground">Lineage depth: {lineage.depth}</p>
      <ol className="space-y-3">
        {lineage.chain.map((entry, idx) => (
          <li key={entry.node.node_id} className="flex flex-col gap-1">
            {idx > 0 && entry.edge && (
              <div className="flex items-center gap-1 pl-2">
                <span className="h-3 w-px bg-border" />
                <span className="rounded bg-surface-3 px-1 py-0.5 font-mono text-[10px] text-muted">
                  {entry.edge.edge_type}
                </span>
              </div>
            )}
            <div className="rounded border border-border bg-surface-2 p-2 space-y-1">
              <p className="text-xs font-medium text-foreground">{entry.node.label}</p>
              <p className="font-mono text-[10px] text-muted">{truncate(entry.node.source_ref, 40)}</p>
              <p className="text-[10px] text-muted/70">{formatDate(entry.node.derived_at)}</p>
              {entry.node.engagement_id && (
                <p className="font-mono text-[10px] text-muted/60">eng: {entry.node.engagement_id}</p>
              )}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
