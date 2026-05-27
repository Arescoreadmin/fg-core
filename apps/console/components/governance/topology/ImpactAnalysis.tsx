'use client';

import { useEffect, useState } from 'react';
import { X, AlertTriangle } from 'lucide-react';
import { traverse, type TraversalResponse } from '@/lib/governanceApi';

interface ImpactAnalysisProps {
  nodeId: string | null;
  nodeLabel: string;
  onClose: () => void;
}

export function ImpactAnalysis({ nodeId, nodeLabel, onClose }: ImpactAnalysisProps) {
  const [result, setResult] = useState<TraversalResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!nodeId) return;
    setLoading(true);
    setError(null);
    setResult(null);
    traverse(nodeId, { max_depth: 5, direction: 'outbound' })
      .then(setResult)
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to analyze impact'))
      .finally(() => setLoading(false));
  }, [nodeId]);

  if (!nodeId) return null;

  const typeCounts: Record<string, number> = {};
  if (result) {
    for (const n of result.nodes) {
      typeCounts[n.node_type] = (typeCounts[n.node_type] ?? 0) + 1;
    }
  }

  const sortedTypes = Object.entries(typeCounts).sort(([, a], [, b]) => b - a);

  return (
    <div className="p-3 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-0.5">
          <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">Blast Radius</h3>
          <p className="text-xs text-muted">from: <span className="text-foreground">{nodeLabel}</span></p>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 rounded p-0.5 text-muted hover:text-foreground hover:bg-surface-3"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {loading && (
        <p className="text-xs text-muted">Traversing graph…</p>
      )}

      {error && (
        <p className="text-xs text-risk-critical">{error}</p>
      )}

      {result && (
        <div className="space-y-3">
          {result.truncated && (
            <div className="flex items-start gap-1.5 rounded border border-risk-medium/40 bg-risk-medium/10 p-2">
              <AlertTriangle className="h-3 w-3 shrink-0 mt-0.5 text-risk-medium" />
              <p className="text-[10px] text-risk-medium leading-relaxed">
                Graph truncated at 500 nodes — actual blast radius may be larger
              </p>
            </div>
          )}

          <div className="flex items-center justify-between text-xs">
            <span className="text-muted">Total affected</span>
            <span className="font-semibold text-foreground">{result.nodes.length} nodes</span>
          </div>

          <div className="flex items-center justify-between text-xs">
            <span className="text-muted">Max traversal depth</span>
            <span className="font-mono text-foreground">{result.max_depth_reached} / 5</span>
          </div>

          {sortedTypes.length > 0 && (
            <div className="rounded border border-border bg-surface-3">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-2 py-1.5 text-left text-[10px] text-muted font-medium uppercase tracking-wider">Node type</th>
                    <th className="px-2 py-1.5 text-right text-[10px] text-muted font-medium uppercase tracking-wider">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedTypes.map(([type, count]) => (
                    <tr key={type} className="border-b border-border last:border-0">
                      <td className="px-2 py-1.5 text-foreground font-mono">{type}</td>
                      <td className="px-2 py-1.5 text-right text-foreground font-semibold">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.nodes.length === 0 && (
            <p className="text-xs text-muted">No downstream nodes found within depth 5.</p>
          )}
        </div>
      )}
    </div>
  );
}
