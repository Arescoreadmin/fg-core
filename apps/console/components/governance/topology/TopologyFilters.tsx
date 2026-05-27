'use client';

export interface TopologyFilters {
  nodeType: string;
  edgeType: string;
  minConfidence: number;
  showDeadNodes: boolean;
}

interface TopologyFiltersProps {
  nodeTypes: string[];
  edgeTypes: string[];
  filters: TopologyFilters;
  onChange: (f: TopologyFilters) => void;
}

export function TopologyFilters({ nodeTypes, edgeTypes, filters, onChange }: TopologyFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-4 text-xs">
      <label className="flex items-center gap-1.5">
        <span className="text-muted">Node type</span>
        <select
          value={filters.nodeType}
          onChange={e => onChange({ ...filters, nodeType: e.target.value })}
          className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-border"
        >
          <option value="">All</option>
          {nodeTypes.map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-1.5">
        <span className="text-muted">Edge type</span>
        <select
          value={filters.edgeType}
          onChange={e => onChange({ ...filters, edgeType: e.target.value })}
          className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-border"
        >
          <option value="">All</option>
          {edgeTypes.map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-1.5">
        <span className="text-muted">Min confidence</span>
        <input
          type="range"
          min={0}
          max={100}
          step={10}
          value={filters.minConfidence}
          onChange={e => onChange({ ...filters, minConfidence: Number(e.target.value) })}
          className="w-24 accent-blue-500"
        />
        <span className="w-8 text-foreground">{filters.minConfidence}%</span>
      </label>

      <label className="flex items-center gap-1.5 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={filters.showDeadNodes}
          onChange={e => onChange({ ...filters, showDeadNodes: e.target.checked })}
          className="rounded border-border accent-blue-500"
        />
        <span className="text-muted">Show dead nodes</span>
      </label>
    </div>
  );
}
