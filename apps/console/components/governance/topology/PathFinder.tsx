'use client';

import { useState, useId } from 'react';
import { ArrowRight } from 'lucide-react';
import { findPath, type GraphNode } from '@/lib/governanceApi';

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

interface NodeSelectProps {
  id: string;
  label: string;
  nodes: GraphNode[];
  query: string;
  selected: GraphNode | null;
  onQueryChange: (q: string) => void;
  onSelect: (node: GraphNode) => void;
}

function NodeSelect({ id, label, nodes, query, selected, onQueryChange, onSelect }: NodeSelectProps) {
  const [open, setOpen] = useState(false);

  const filtered = query.length >= 1
    ? nodes.filter(n => n.label.toLowerCase().includes(query.toLowerCase())).slice(0, 12)
    : [];

  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-[10px] text-muted uppercase tracking-wider">{label}</label>
      <div className="relative">
        <input
          id={id}
          type="text"
          value={selected ? selected.label : query}
          onChange={e => {
            onQueryChange(e.target.value);
            if (selected) onSelect(null as unknown as GraphNode);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 150)}
          placeholder="Search nodes…"
          className="w-full rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-border"
        />
        {open && filtered.length > 0 && (
          <ul className="absolute z-20 top-full left-0 right-0 mt-0.5 max-h-40 overflow-y-auto rounded border border-border bg-surface-2 shadow-lg">
            {filtered.map(n => (
              <li key={n.node_id}>
                <button
                  type="button"
                  onMouseDown={() => {
                    onSelect(n);
                    onQueryChange('');
                    setOpen(false);
                  }}
                  className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-xs hover:bg-surface-3"
                >
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: NODE_TYPE_COLOR[n.node_type] ?? '#94A3B8' }}
                  />
                  <span className="truncate text-foreground">{n.label}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-muted">{n.node_type}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

interface PathResult {
  found: boolean;
  nodes: GraphNode[];
}

interface PathFinderProps {
  nodes: GraphNode[];
  onHighlightPath: (nodeIds: Set<string>) => void;
}

export function PathFinder({ nodes, onHighlightPath }: PathFinderProps) {
  const uid = useId();
  const [fromQuery, setFromQuery] = useState('');
  const [toQuery, setToQuery] = useState('');
  const [fromNode, setFromNode] = useState<GraphNode | null>(null);
  const [toNode, setToNode] = useState<GraphNode | null>(null);
  const [result, setResult] = useState<PathResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleFind() {
    if (!fromNode || !toNode) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await findPath(fromNode.node_id, toNode.node_id, 8);
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Path query failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-3">
      <NodeSelect
        id={`${uid}-from`}
        label="From node"
        nodes={nodes}
        query={fromQuery}
        selected={fromNode}
        onQueryChange={setFromQuery}
        onSelect={n => { setFromNode(n); setResult(null); }}
      />
      <NodeSelect
        id={`${uid}-to`}
        label="To node"
        nodes={nodes}
        query={toQuery}
        selected={toNode}
        onQueryChange={setToQuery}
        onSelect={n => { setToNode(n); setResult(null); }}
      />

      <button
        onClick={handleFind}
        disabled={!fromNode || !toNode || loading}
        className="w-full rounded border border-border bg-surface-2 px-2 py-1.5 text-xs font-medium text-foreground hover:bg-surface-3 transition disabled:cursor-not-allowed disabled:opacity-50"
      >
        {loading ? 'Searching…' : 'Find path'}
      </button>

      {error && (
        <p className="text-xs text-risk-critical">{error}</p>
      )}

      {result && (
        <div className="space-y-2">
          {result.found ? (
            <>
              <p className="text-xs font-semibold text-foreground">
                Path found: {result.nodes.length} nodes
              </p>
              <div className="space-y-1">
                {result.nodes.map((n, idx) => (
                  <div key={n.node_id} className="flex items-center gap-1.5">
                    {idx > 0 && <ArrowRight className="h-3 w-3 shrink-0 text-muted" />}
                    <div className="flex items-center gap-1.5 rounded border border-border bg-surface-3 px-2 py-1 min-w-0">
                      <span
                        className="h-2 w-2 shrink-0 rounded-full"
                        style={{ backgroundColor: NODE_TYPE_COLOR[n.node_type] ?? '#94A3B8' }}
                      />
                      <span className="truncate text-xs text-foreground">{n.label}</span>
                      <span className="ml-auto shrink-0 text-[10px] text-muted">{n.node_type}</span>
                    </div>
                  </div>
                ))}
              </div>
              <button
                onClick={() => onHighlightPath(new Set(result.nodes.map(n => n.node_id)))}
                className="w-full rounded border border-border bg-surface-2 px-2 py-1 text-xs font-medium text-foreground hover:bg-surface-3 transition"
              >
                Highlight path
              </button>
            </>
          ) : (
            <p className="text-xs text-muted">
              No governance path exists between these nodes within depth 8.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
