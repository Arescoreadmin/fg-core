'use client';

import { useState } from 'react';
import { X, ChevronDown, ChevronRight } from 'lucide-react';
import { ConfidenceMeter } from '@/components/governance/ConfidenceMeter';
import { cn } from '@/lib/cn';
import type { GraphNode } from '@/lib/governanceApi';

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

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

interface NodeInspectorProps {
  node: GraphNode | null;
  onClose: () => void;
  onShowLineage: () => void;
  onAnalyzeImpact: (nodeId: string) => void;
}

export function NodeInspector({ node, onClose, onShowLineage, onAnalyzeImpact }: NodeInspectorProps) {
  const [propsExpanded, setPropsExpanded] = useState(false);

  if (!node) return null;

  const typeColor = NODE_TYPE_COLOR[node.node_type] ?? '#94A3B8';
  const propEntries = Object.entries(node.properties);

  return (
    <div className="p-3 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-col gap-1 min-w-0">
          <h3 className="text-sm font-semibold text-foreground leading-tight">{node.label}</h3>
          <span
            className="inline-flex w-fit items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: typeColor, borderColor: `${typeColor}40`, backgroundColor: `${typeColor}18` }}
          >
            {node.node_type}
          </span>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 rounded p-0.5 text-muted hover:text-foreground hover:bg-surface-3"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex items-center gap-2">
        {node.trust_score === 100 ? (
          <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider">Live</span>
        ) : (
          <span className="text-[10px] font-semibold text-muted uppercase tracking-wider">Stale (source deleted)</span>
        )}
      </div>

      <ConfidenceMeter value={node.confidence} />

      <div className="space-y-1.5 text-xs">
        <div className="flex items-center justify-between">
          <span className="text-muted">Centrality</span>
          <span className="text-foreground font-mono">
            {node.degree_centrality}
            {node.centrality_rank !== null && (
              <span className="text-muted"> (rank #{node.centrality_rank})</span>
            )}
          </span>
        </div>

        <div className="flex items-start justify-between gap-2">
          <span className="text-muted shrink-0">Entity</span>
          <span className="font-mono text-[10px] text-foreground text-right break-all">
            {node.entity_type} / {truncate(node.entity_id, 24)}
          </span>
        </div>

        <div className="flex items-start justify-between gap-2">
          <span className="text-muted shrink-0">Source ref</span>
          <span className="font-mono text-[10px] text-muted/80 text-right break-all">
            {truncate(node.source_ref, 36)}
          </span>
        </div>

        {node.engagement_id && (
          <div className="flex items-start justify-between gap-2">
            <span className="text-muted shrink-0">Engagement</span>
            <span className="font-mono text-[10px] text-muted/80 text-right break-all">
              {truncate(node.engagement_id, 28)}
            </span>
          </div>
        )}

        <div className="flex items-center justify-between">
          <span className="text-muted">Derived at</span>
          <span className="text-[10px] text-muted/80">{formatDate(node.derived_at)}</span>
        </div>
      </div>

      {node.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {node.tags.map(tag => (
            <span key={tag} className="rounded bg-surface-3 px-1.5 py-0.5 text-[10px] text-muted">
              {tag}
            </span>
          ))}
        </div>
      )}

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

      <div className="flex gap-2 pt-1">
        <button
          onClick={onShowLineage}
          className="flex-1 rounded border border-border bg-surface-2 px-2 py-1.5 text-xs font-medium text-foreground hover:bg-surface-3 transition"
        >
          View Lineage
        </button>
        <button
          onClick={() => onAnalyzeImpact(node.node_id)}
          className={cn(
            'flex-1 rounded border px-2 py-1.5 text-xs font-medium transition',
            'border-risk-high/40 bg-risk-high/10 text-risk-high hover:bg-risk-high/20',
          )}
        >
          Analyze Impact
        </button>
      </div>
    </div>
  );
}
