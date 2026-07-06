'use client';

import { useEffect, useState } from 'react';
import {
  getAutomationSafety,
  type AutomationSafetyState,
} from '@/lib/operationsCenterApi';

function riskScoreClasses(score: number): string {
  if (score <= 30) return 'text-green-400 border-green-500/40 bg-green-500/10';
  if (score <= 69) return 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10';
  return 'text-red-400 border-red-500/40 bg-red-500/10';
}

function boolBadge(val: boolean, trueLabel = 'Yes', falseLabel = 'No'): React.ReactNode {
  return val ? (
    <span className="rounded border border-green-500/30 bg-green-500/10 px-1.5 py-0.5 text-xs text-green-400">{trueLabel}</span>
  ) : (
    <span className="rounded border border-border bg-surface px-1.5 py-0.5 text-xs text-muted">{falseLabel}</span>
  );
}

export default function AutomationSafetyCenter() {
  const [data, setData] = useState<AutomationSafetyState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAutomationSafety().then((res) => {
      if (res.ok) {
        setData(res.data);
      } else {
        setError(res.error);
      }
      setLoading(false);
    });
  }, []);

  return (
    <div
      data-mcim="MCIM-18.7-AUTO-SAFETY"
      className="rounded-lg border border-border bg-surface-2 p-4"
    >
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Automation Safety Center
      </h2>

      {loading && (
        <p className="text-sm text-muted" aria-live="polite">Loading…</p>
      )}

      {!loading && error && (
        <p className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger" role="alert" aria-label="Safety data unavailable">
          Safety data unavailable — automation actions blocked.
        </p>
      )}

      {!loading && !error && data && (
        <>
          <div className="mb-5 flex items-center gap-4">
            <div
              className={`flex h-20 w-20 flex-col items-center justify-center rounded-full border-2 ${riskScoreClasses(data.riskScore)}`}
              role="status"
              aria-label={`Risk score: ${data.riskScore} out of 100`}
            >
              <span className="text-2xl font-bold leading-none">{data.riskScore}</span>
              <span className="text-xs">/ 100</span>
            </div>
            <div>
              <p className="text-sm font-medium text-foreground">Risk Score</p>
              <p className="text-xs text-muted">
                {data.riskScore <= 30 ? 'Low risk' : data.riskScore <= 69 ? 'Elevated risk' : 'High risk'}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2" aria-label="Safety checklist">
            <div className="rounded border border-border bg-surface px-3 py-2" role="status" aria-label="Simulation required">
              <p className="mb-1 text-xs text-muted">Simulation Required</p>
              {boolBadge(data.simulationRequired)}
            </div>

            <div className="rounded border border-border bg-surface px-3 py-2" role="status" aria-label="Rollback available">
              <p className="mb-1 text-xs text-muted">Rollback Available</p>
              {boolBadge(data.rollbackAvailable)}
            </div>

            <div className="rounded border border-border bg-surface px-3 py-2" role="status" aria-label="Human approval required">
              <p className="mb-1 text-xs text-muted">Human Approval Required</p>
              {boolBadge(data.humanApprovalRequired)}
            </div>

            <div className={`rounded border px-3 py-2 ${data.killSwitchActive ? 'border-red-500/40 bg-red-500/10' : 'border-border bg-surface'}`} role="status" aria-label="Kill switch active">
              <p className="mb-1 text-xs text-muted">Kill Switch Active</p>
              {data.killSwitchActive ? (
                <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-xs text-red-400">Active</span>
              ) : (
                <span className="rounded border border-border bg-surface px-1.5 py-0.5 text-xs text-muted">Inactive</span>
              )}
            </div>

            <div className="rounded border border-border bg-surface px-3 py-2" role="status" aria-label="Chain integrity status">
              <p className="mb-1 text-xs text-muted">Chain Integrity</p>
              <span className="text-xs font-medium text-foreground">{data.chainIntegrity}</span>
            </div>

            <div className="rounded border border-border bg-surface px-3 py-2" role="status" aria-label="Blast radius">
              <p className="mb-1 text-xs text-muted">Blast Radius</p>
              <span className="text-xs font-medium text-foreground">{data.blastRadius}</span>
            </div>

            <div className="rounded border border-border bg-surface px-3 py-2" role="status" aria-label="Execution confidence percentage">
              <p className="mb-1 text-xs text-muted">Execution Confidence</p>
              <span className="text-xs font-medium text-foreground">{data.executionConfidence}%</span>
            </div>

            <div className="rounded border border-border bg-surface px-3 py-2" role="status" aria-label="Agent count">
              <p className="mb-1 text-xs text-muted">Agents</p>
              <span className="text-xs font-medium text-foreground">{data.agentCount}</span>
            </div>

            <div className={`rounded border px-3 py-2 col-span-2 ${data.quarantineCount > 0 ? 'border-red-500/40 bg-red-500/10' : 'border-border bg-surface'}`} role="status" aria-label="Quarantined agent count">
              <p className="mb-1 text-xs text-muted">Quarantined</p>
              <span className={`text-xs font-medium ${data.quarantineCount > 0 ? 'text-red-400' : 'text-foreground'}`}>{data.quarantineCount}</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
