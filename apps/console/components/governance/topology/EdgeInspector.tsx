'use client';

import { useState } from 'react';
import { X, ArrowRight, ChevronDown, ChevronRight } from 'lucide-react';
import { ConfidenceMeter } from '@/components/governance/ConfidenceMeter';
import type { GraphEdge, GraphNode } from '@/lib/governanceApi';

const NODE_TYPE_COLOR: Record<string, string> = {
  governance_asset:       '#3B82F6',
  ai_system:              '#8B5CF6',
  oauth_application:      '#F59E0B',
  enterprise_application: '#06B6D4',
  identity:               '#10B981',
  finding:                '#EF4444',
  control:                '#22C55E',
  scan:                   '#A855F7',
  engagement:             '#60A5FA',
  evidence:               '#14B8A6',
  vendor:                 '#F97316',
  department:             '#64748B',
};

const EDGE_TYPE_COLOR: Record<string, string> = {
  OWNS:           '#3B82F6',
  GOVERNED_BY:    '#22C55E',
  USES:           '#F59E0B',
  ACCESSES:       '#EF4444',
  CONNECTED_TO:   '#94A3B8',
  GENERATED:      '#A855F7',
  DETECTED_BY:    '#F97316',
  IMPACTS:        '#DC2626',
  ATTESTED_BY:    '#10B981',
  SUPPORTS:       '#06B6D4',
  RELATED_TO:     '#94A3B8',
  PROMOTED_FROM:  '#8B5CF6',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

interface EdgeInspectorProps {
  edge: GraphEdge | null;
  sourceNode: GraphNode | null;
  targetNode: GraphNode | null;
  onClose: () => void;
}

export function EdgeInspector({ edge, sourceNode, targetNode, onClose }: EdgeInspectorProps) {
  const [propsExpanded, setPropsExpanded] = useState(false);

  if (!edge) return null;

  const edgeColor = EDGE_TYPE_COLOR[edge.edge_type] ?? '#94A3B8';
  const propEntries = Object.entries(edge.properties);

  return (
    <div className="p-3 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <span
          className="inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wider"
          style={{ color: edgeColor, borderColor: `${edgeColor}40`, backgroundColor: `${edgeColor}18` }}
        >
          {edge.edge_type}
        </span>
        <button
          onClick={onClose}
          className="shrink-0 rounded p-0.5 text-muted hover:text-foreground hover:bg-surface-3"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex items-center gap-2 rounded border border-border bg-surface-3 p-2">
        <div className="flex flex-col min-w-0 flex-1">
          <span className="text-[10px] text-muted">Source</span>
          <span className="text-xs font-medium text-foreground truncate">
            {sourceNode?.label ?? truncate(edge.source_node_id, 20)}
          </span>
          {sourceNode && (
            <span
              className="inline-flex w-fit items-center rounded px-1 py-0.5 text-[10px] font-semibold uppercase"
              style={{ color: NODE_TYPE_COLOR[sourceNode.node_type] ?? '#94A3B8' }}
            >
              {sourceNode.node_type}
            </span>
          )}
        </div>
        <ArrowRight className="h-4 w-4 shrink-0 text-muted" />
        <div className="flex flex-col min-w-0 flex-1 items-end text-right">
          <span className="text-[10px] text-muted">Target</span>
          <span className="text-xs font-medium text-foreground truncate">
            {targetNode?.label ?? truncate(edge.target_node_id, 20)}
          </span>
          {targetNode && (
            <span
              className="inline-flex w-fit items-center rounded px-1 py-0.5 text-[10px] font-semibold uppercase"
              style={{ color: NODE_TYPE_COLOR[targetNode.node_type] ?? '#94A3B8' }}
            >
              {targetNode.node_type}
            </span>
          )}
        </div>
      </div>

      <ConfidenceMeter value={edge.confidence} />

      <div className="space-y-1.5 text-xs">
        <div className="flex items-center justify-between">
          <span className="text-muted">Weight</span>
          <span className="text-foreground font-mono">{edge.weight}</span>
        </div>

        <div className="flex items-start justify-between gap-2">
          <span className="text-muted shrink-0">Source ref</span>
          <span className="font-mono text-[10px] text-muted/80 text-right break-all">
            {truncate(edge.source_ref, 36)}
          </span>
        </div>

        {edge.engagement_id && (
          <div className="flex items-start justify-between gap-2">
            <span className="text-muted shrink-0">Engagement</span>
            <span className="font-mono text-[10px] text-muted/80 text-right break-all">
              {truncate(edge.engagement_id, 28)}
            </span>
          </div>
        )}

        <div className="flex items-center justify-between">
          <span className="text-muted">Derived at</span>
          <span className="text-[10px] text-muted/80">{formatDate(edge.derived_at)}</span>
        </div>
      </div>

      {propEntries.length > 0 && (
        <div className="rounded border border-border bg-surface-3">
          <button
            onClick={() => setPropsExpanded(p => !p)}
            className="flex w-full items-center justify-between px-2 py-1.5 text-xs text-muted hover:text-foreground"
          >
            <span>Properties ({propEntries.length})</span>
            {propsExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          </button>
          {propsExpanded && (
            <div className="border-t border-border px-2 py-1.5 space-y-0.5">
              {propEntries.map(([k, v]) => (
                <div key={k} className="flex items-start justify-between gap-2">
                  <span className="font-mono text-[10px] text-muted shrink-0">{k}</span>
                  <span className="font-mono text-[10px] text-foreground/80 text-right break-all">
                    {String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
