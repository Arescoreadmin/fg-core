'use client';

import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/cn';

export interface TraceStep {
  step: string;
  latencyMs?: number;
  status?: string;
  detail?: string;
}

export function RetrievalTrace({
  steps,
  defaultCollapsed = true,
  className,
}: {
  steps: TraceStep[];
  defaultCollapsed?: boolean;
  className?: string;
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  if (!steps.length) return null;

  const totalMs = steps.reduce((acc, s) => acc + (s.latencyMs ?? 0), 0);

  return (
    <div className={cn('rounded-lg border bg-surface-2', className)}>
      <button
        onClick={() => setCollapsed((v) => !v)}
        className="flex w-full items-center justify-between px-3 py-2.5 text-left"
      >
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted/70">
          Retrieval Trace ({steps.length} step{steps.length !== 1 ? 's' : ''})
        </span>
        <div className="flex items-center gap-2">
          {totalMs > 0 && (
            <span className="font-mono text-[10px] text-muted/60">{totalMs}ms</span>
          )}
          {collapsed ? (
            <ChevronRight className="h-3.5 w-3.5 text-muted" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-muted" />
          )}
        </div>
      </button>

      {!collapsed && (
        <ol className="border-t border-border px-3 py-2 space-y-2">
          {steps.map((s, i) => (
            <li key={i} className="flex items-start gap-2 text-xs">
              <span className="mt-0.5 font-mono text-[10px] text-muted/50 w-4 shrink-0">{i + 1}.</span>
              <div className="flex-1">
                <span className="text-foreground">{s.step}</span>
                {s.detail && (
                  <p className="text-[10px] text-muted mt-0.5">{s.detail}</p>
                )}
              </div>
              {s.latencyMs !== undefined && (
                <span className="font-mono text-[10px] text-muted/60 shrink-0">{s.latencyMs}ms</span>
              )}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
