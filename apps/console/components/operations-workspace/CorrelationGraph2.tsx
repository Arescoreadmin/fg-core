'use client';

import { Badge } from '@/components/ui/badge';
import { ArrowRight } from 'lucide-react';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-CORRELATION-GRAPH-2';
const AUTHORITY = 'Correlation Authority';
const sourceOfTruth = '/api/core/forensics/events';
const drillDown = '/dashboard/forensics';

export interface GraphNode2 {
  id: string;
  label: string;
  authority: string;
  confidence: number | null;
  freshness: string | null;
  owner: string | null;
  lifecycle: string | null;
  trustStatus: string | null;
  verificationState: string | null;
  nodeType: string;
}

export interface GraphEdge2 {
  from: string;
  to: string;
  relationship: string;
}

interface CorrelationGraph2Props {
  nodes: GraphNode2[];
  edges: GraphEdge2[];
  loading?: boolean;
  lastUpdated?: string;
}

export default function CorrelationGraph2({
  nodes,
  edges,
  loading,
  lastUpdated,
}: CorrelationGraph2Props) {
  // Build a lookup map for node labels
  const nodeMap = new Map<string, GraphNode2>(nodes.map((n) => [n.id, n]));

  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Correlation Graph"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Correlation Graph"
    >
      <section aria-label="correlation-graph-2-panel">
        {loading && (
          <div className="space-y-2" aria-label="Loading correlation graph">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-14 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && nodes.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No correlation data.</p>
        )}

        {!loading && nodes.length > 0 && (
          <div className="space-y-4">
            {/* Nodes */}
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted/70 mb-2">
                Nodes ({nodes.length})
              </p>
              <ul className="space-y-1.5" aria-label="Graph nodes">
                {nodes.map((node) => {
                  const confidencePct =
                    node.confidence !== null
                      ? `${Math.round(node.confidence * 100)}%`
                      : null;
                  return (
                    <li
                      key={node.id}
                      className="flex flex-wrap items-start gap-2 rounded border border-border bg-surface-2 px-3 py-2 text-xs"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium text-foreground">{node.label}</span>
                          <Badge variant="secondary" className="text-[10px]">
                            {node.nodeType}
                          </Badge>
                        </div>
                        <div className="mt-1 flex flex-wrap gap-x-3 text-[10px] text-muted">
                          <span className="font-mono">ID: {node.id}</span>
                          <span>Authority: {node.authority}</span>
                          {confidencePct && <span>Confidence: {confidencePct}</span>}
                          {node.freshness && (
                            <span>
                              Freshness: {new Date(node.freshness).toLocaleString()}
                            </span>
                          )}
                          {node.owner && <span>Owner: {node.owner}</span>}
                          {node.lifecycle && <span>Lifecycle: {node.lifecycle}</span>}
                          {node.trustStatus && <span>Trust: {node.trustStatus}</span>}
                          {node.verificationState && (
                            <span>Verification: {node.verificationState}</span>
                          )}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>

            {/* Edges */}
            {edges.length > 0 && (
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-muted/70 mb-2">
                  Relationships ({edges.length})
                </p>
                <ul className="space-y-1" aria-label="Graph relationships">
                  {edges.map((edge, idx) => {
                    const fromNode = nodeMap.get(edge.from);
                    const toNode = nodeMap.get(edge.to);
                    return (
                      <li
                        key={`${edge.from}-${edge.to}-${idx}`}
                        className="flex items-center gap-2 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs"
                      >
                        <span className="font-medium text-foreground truncate">
                          {fromNode?.label ?? edge.from}
                        </span>
                        <div className="flex items-center gap-1 shrink-0">
                          <ArrowRight className="h-3 w-3 text-muted" aria-hidden="true" />
                          <Badge variant="outline" className="text-[10px]">
                            {edge.relationship}
                          </Badge>
                          <ArrowRight className="h-3 w-3 text-muted" aria-hidden="true" />
                        </div>
                        <span className="font-medium text-foreground truncate">
                          {toNode?.label ?? edge.to}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        )}
      </section>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
