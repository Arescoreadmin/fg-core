'use client';

import { cn } from '@/lib/cn';

interface RiskHighlighterProps {
  active: boolean;
  onChange: (active: boolean) => void;
  anomalyCount: number;
}

export function RiskHighlighter({ active, onChange, anomalyCount }: RiskHighlighterProps) {
  return (
    <button
      onClick={() => onChange(!active)}
      disabled={anomalyCount === 0}
      className={cn(
        'flex items-center gap-1.5 rounded border px-2 py-1 text-xs font-medium transition',
        active
          ? 'border-risk-critical/40 bg-risk-critical/10 text-risk-critical'
          : anomalyCount === 0
            ? 'border-border bg-surface-2 text-muted opacity-50 cursor-not-allowed'
            : 'border-border bg-surface-2 text-foreground hover:bg-surface-3',
      )}
    >
      <span>Highlight anomalies</span>
      <span
        className={cn(
          'inline-flex items-center rounded px-1 py-0.5 text-[10px] font-semibold',
          anomalyCount > 0 ? 'bg-risk-critical/20 text-risk-critical' : 'bg-surface-3 text-muted',
        )}
      >
        {anomalyCount}
      </span>
    </button>
  );
}
