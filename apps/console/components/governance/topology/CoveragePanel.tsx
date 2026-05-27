'use client';

import { useState } from 'react';
import type { CoverageResponse } from '@/lib/governanceApi';

const FRAMEWORKS = ['NIST-AI-RMF'];

interface CoveragePanelProps {
  coverage: CoverageResponse | null;
  loading: boolean;
  onFrameworkChange: (f: string) => void;
  framework: string;
}

export function CoveragePanel({ coverage, loading, onFrameworkChange, framework }: CoveragePanelProps) {
  const [activeTab, setActiveTab] = useState<'covered' | 'missing'>('covered');

  const pct = coverage?.coverage_pct ?? 0;
  const barColor = pct >= 70 ? 'bg-success' : pct >= 40 ? 'bg-warning' : 'bg-danger';

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-1">
        <label className="text-[10px] text-muted uppercase tracking-wider">Framework</label>
        <select
          value={framework}
          onChange={e => onFrameworkChange(e.target.value)}
          className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-border"
        >
          {FRAMEWORKS.map(f => (
            <option key={f} value={f}>{f}</option>
          ))}
        </select>
      </div>

      {loading && <p className="text-xs text-muted">Loading coverage…</p>}

      {!loading && !coverage && (
        <p className="text-xs text-muted">No coverage data.</p>
      )}

      {coverage && (
        <div className="space-y-3">
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted">Coverage</span>
              <span className="font-semibold text-foreground">{Math.round(pct)}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
              <div
                className={`h-full rounded-full transition-all ${barColor}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <p className="text-[10px] text-muted">
              {coverage.covered_controls} / {coverage.total_controls} controls covered
            </p>
          </div>

          <div className="flex border-b border-border">
            <button
              onClick={() => setActiveTab('covered')}
              className={`flex-1 px-2 py-1.5 text-xs font-medium transition ${
                activeTab === 'covered'
                  ? 'border-b-2 border-foreground text-foreground'
                  : 'text-muted hover:text-foreground'
              }`}
            >
              Covered ({coverage.covered.length})
            </button>
            <button
              onClick={() => setActiveTab('missing')}
              className={`flex-1 px-2 py-1.5 text-xs font-medium transition ${
                activeTab === 'missing'
                  ? 'border-b-2 border-foreground text-foreground'
                  : 'text-muted hover:text-foreground'
              }`}
            >
              Missing ({coverage.missing.length})
            </button>
          </div>

          <div className="flex flex-wrap gap-1 pt-1">
            {activeTab === 'covered' && coverage.covered.map(ctrl => (
              <span
                key={ctrl}
                className="inline-flex items-center rounded border border-risk-low/40 bg-risk-low/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-risk-low"
              >
                {ctrl}
              </span>
            ))}
            {activeTab === 'missing' && coverage.missing.map(ctrl => (
              <span
                key={ctrl}
                className="inline-flex items-center rounded border border-risk-critical/30 bg-risk-critical/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-risk-critical"
              >
                {ctrl}
              </span>
            ))}
            {activeTab === 'covered' && coverage.covered.length === 0 && (
              <p className="text-xs text-muted">No controls covered.</p>
            )}
            {activeTab === 'missing' && coverage.missing.length === 0 && (
              <p className="text-xs text-muted">All controls covered.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
