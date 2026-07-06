'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  getDecisionPipeline,
  type PipelineItem,
  type PipelineResult,
  type PipelineStage,
} from '@/lib/operationsCenterApi';

const STAGES: PipelineStage[] = [
  'detected',
  'evaluated',
  'policy_matched',
  'simulation_completed',
  'approval_required',
  'approved',
  'executing',
  'executed',
  'verified',
  'archived',
];

const STAGE_LABELS: Record<PipelineStage, string> = {
  detected: 'Detected',
  evaluated: 'Evaluated',
  policy_matched: 'Policy Matched',
  simulation_completed: 'Simulation Completed',
  approval_required: 'Approval Required',
  approved: 'Approved',
  executing: 'Executing',
  executed: 'Executed',
  verified: 'Verified',
  archived: 'Archived',
};

function severityClass(sev: string): string {
  switch (sev) {
    case 'critical': return 'text-red-400';
    case 'high':     return 'text-orange-400';
    case 'medium':   return 'text-yellow-400';
    default:         return 'text-blue-400';
  }
}

function fmtTs(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

function truncId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

export default function DecisionExecutionPipeline() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<PipelineResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    getDecisionPipeline().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  const activeStages = new Set(data ? Object.keys(data.byStage) : []);

  return (
    <div
      data-mcim="MCIM-18.7-PIPELINE"
      className="rounded-lg border border-border bg-surface-2 p-4"
      aria-label="Decision Execution Pipeline"
    >
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Decision Execution Pipeline
      </h3>

      {loading && (
        <div className="flex items-center gap-2 py-4 text-sm text-muted" aria-live="polite" aria-label="Loading pipeline">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      )}

      {error && (
        <p className="py-4 text-sm text-red-400" role="alert" aria-label="Pipeline error">
          {error}
        </p>
      )}

      {!loading && !error && data && data.items.length === 0 && (
        <p className="py-4 text-sm text-muted" aria-label="No decisions in pipeline">
          No decisions in pipeline.
        </p>
      )}

      {!loading && !error && data && data.items.length > 0 && (
        <>
          <div
            className="mb-4 overflow-x-auto"
            role="list"
            aria-label="Pipeline stages"
          >
            <div className="flex min-w-max items-center gap-0">
              {STAGES.map((stage, i) => {
                const count = data.byStage[stage] ?? 0;
                const isActive = activeStages.has(stage);
                return (
                  <div key={stage} className="flex items-center" role="listitem" aria-label={`Stage: ${STAGE_LABELS[stage]}, count ${count}`}>
                    <div className={`flex flex-col items-center px-2 py-1.5 rounded ${isActive ? 'bg-primary/10 border border-primary/30' : 'border border-border bg-surface'}`}>
                      <span className={`text-xs font-medium whitespace-nowrap ${isActive ? 'text-foreground' : 'text-muted'}`}>
                        {STAGE_LABELS[stage]}
                      </span>
                      <span className={`mt-0.5 text-sm font-semibold tabular-nums ${isActive ? 'text-primary' : 'text-muted'}`} aria-label={`${count} items`}>
                        {count}
                      </span>
                    </div>
                    {i < STAGES.length - 1 && (
                      <span className="px-1 text-muted text-xs" aria-hidden="true">→</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs" aria-label="Recent pipeline items">
              <thead>
                <tr className="border-b border-border text-muted">
                  <th className="pb-1.5 text-left font-medium" scope="col">ID</th>
                  <th className="pb-1.5 text-left font-medium" scope="col">Stage</th>
                  <th className="pb-1.5 text-left font-medium" scope="col">Event Type</th>
                  <th className="pb-1.5 text-left font-medium" scope="col">Severity</th>
                  <th className="pb-1.5 text-left font-medium" scope="col">Confidence</th>
                  <th className="pb-1.5 text-left font-medium" scope="col">Det.</th>
                  <th className="pb-1.5 text-left font-medium" scope="col">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((item: PipelineItem) => (
                  <tr key={item.id} className="border-b border-border/50 hover:bg-surface/50">
                    <td className="py-1.5 pr-3 font-mono text-muted" aria-label={`ID: ${item.id}`}>{truncId(item.id)}</td>
                    <td className="py-1.5 pr-3 text-muted capitalize">{STAGE_LABELS[item.stage]}</td>
                    <td className="py-1.5 pr-3 text-foreground">{item.eventType}</td>
                    <td className={`py-1.5 pr-3 capitalize font-medium ${severityClass(item.severity)}`} aria-label={`Severity: ${item.severity}`}>{item.severity}</td>
                    <td className="py-1.5 pr-3 text-muted" aria-label={`Confidence: ${item.confidence ?? 'none'}`}>{item.confidence ?? '—'}</td>
                    <td className="py-1.5 pr-3" aria-label={item.deterministic ? 'Deterministic' : 'Non-deterministic'}>
                      {item.deterministic
                        ? <span className="text-green-400">✓</span>
                        : <span className="text-muted">—</span>}
                    </td>
                    <td className="py-1.5 text-muted whitespace-nowrap">{fmtTs(item.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
