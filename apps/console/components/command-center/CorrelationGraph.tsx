'use client';

import WidgetShell from './WidgetShell';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Control Tower Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

export interface CorrelationNode {
  id: string;
  label: string;
  type: string;
  authority: string;
  href?: string;
}

export interface CorrelationEdge {
  from: string;
  to: string;
  label: string;
}

interface CorrelationGraphProps {
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
  loading?: boolean;
  lastUpdated?: string;
}

function sortNodes(nodes: CorrelationNode[]): CorrelationNode[] {
  return [...nodes].sort((a, b) => {
    if (a.type < b.type) return -1;
    if (a.type > b.type) return 1;
    if (a.id < b.id) return -1;
    if (a.id > b.id) return 1;
    return 0;
  });
}

function findEdgesForNode(nodeId: string, edges: CorrelationEdge[]): CorrelationEdge[] {
  return edges.filter((e) => e.from === nodeId || e.to === nodeId);
}

export default function CorrelationGraph({
  nodes,
  edges,
  loading = false,
  lastUpdated,
}: CorrelationGraphProps) {
  const sortedNodes = sortNodes(nodes);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Correlation Graph"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Correlation Graph"
    >
      <div aria-label="correlation-graph" data-testid="correlation-graph">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : sortedNodes.length === 0 ? (
          <div
            aria-label="graph-empty"
            data-testid="graph-empty"
            className="py-6 text-center text-sm text-muted"
          >
            <p>No relationship data available</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <ul role="list" className="space-y-1.5">
            {sortedNodes.map((node) => {
              const nodeEdges = findEdgesForNode(node.id, edges);
              return (
                <li
                  key={node.id}
                  data-testid={`graph-node-${node.id}`}
                  aria-label={`graph-node-${node.id}`}
                  className="rounded-md border border-border px-3 py-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      {node.href ? (
                        <a
                          href={node.href}
                          className="text-[11px] font-medium text-primary hover:underline truncate"
                        >
                          {node.label}
                        </a>
                      ) : (
                        <p className="text-[11px] font-medium text-foreground truncate">{node.label}</p>
                      )}
                      <p className="text-[9px] text-muted">
                        Type: {node.type} · Authority: {node.authority}
                      </p>
                    </div>
                  </div>
                  {nodeEdges.length > 0 && (
                    <ul className="mt-1.5 space-y-0.5 pl-3 border-l border-border/50">
                      {nodeEdges.map((edge, idx) => (
                        <li key={idx} className="text-[9px] text-muted">
                          {edge.from === node.id ? '→' : '←'} {edge.label}{' '}
                          {edge.from === node.id ? edge.to : edge.from}
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        <p className="mt-2 text-[9px] text-muted/50">
          Authority: {AUTHORITY} · {MCIM_ID}
        </p>
      </div>
    </WidgetShell>
  );
}
