'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-EFFECTIVENESS';
const AUTHORITY = 'Decision Effectiveness Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/decisions';

export type OutcomeWindow = '30d' | '60d' | '90d';

export interface DecisionOutcome {
  decisionId: string;
  decisionLabel: string;
  window: OutcomeWindow;
  madeAt: string;
  outcomeStatus: 'positive' | 'negative' | 'neutral' | 'unknown';
  relatedRemediations: number;
  relatedFindings: number;
  effectivenessScore: number | null;
  notes: string | null;
}

interface DecisionEffectivenessProps {
  outcomes: DecisionOutcome[];
  activeWindow: OutcomeWindow;
  onWindowChange?: (w: OutcomeWindow) => void;
  loading?: boolean;
  lastUpdated?: string;
}

const WINDOWS: OutcomeWindow[] = ['30d', '60d', '90d'];

function outcomeBadge(status: DecisionOutcome['outcomeStatus']): 'success' | 'danger' | 'secondary' {
  switch (status) {
    case 'positive': return 'success';
    case 'negative': return 'danger';
    case 'neutral': return 'secondary';
    case 'unknown': return 'secondary';
  }
}

function effectivenessBadge(score: number | null): { variant: 'success' | 'warning' | 'danger' | 'secondary'; label: string } {
  if (score === null) return { variant: 'secondary', label: 'Insufficient data' };
  if (score >= 80) return { variant: 'success', label: `${score}` };
  if (score >= 60) return { variant: 'warning', label: `${score}` };
  return { variant: 'danger', label: `${score}` };
}

export default function DecisionEffectiveness({ outcomes, activeWindow, onWindowChange, loading, lastUpdated }: DecisionEffectivenessProps) {
  const filtered = outcomes.filter((o) => o.window === activeWindow);

  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Decision outcome effectiveness measurement"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Decision Effectiveness"
    >
      <section aria-label="decision-effectiveness" data-testid="decision-effectiveness">
      <div className="mb-3 flex gap-1">
        {WINDOWS.map((w) => (
          <button
            key={w}
            type="button"
            onClick={() => onWindowChange?.(w)}
            className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
              activeWindow === w
                ? 'bg-primary text-primary-foreground'
                : 'bg-muted/30 text-muted hover:bg-muted/50'
            }`}
          >
            {w}
          </button>
        ))}
      </div>
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <p className="text-sm text-muted">No decision outcome data for this window.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="pb-2 pr-3 font-medium">Decision</th>
                <th className="pb-2 pr-3 font-medium">Made At</th>
                <th className="pb-2 pr-3 font-medium">Outcome</th>
                <th className="pb-2 pr-3 font-medium">Effectiveness</th>
                <th className="pb-2 pr-3 font-medium">Remediations</th>
                <th className="pb-2 pr-3 font-medium">Findings</th>
                <th className="pb-2 font-medium">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((o) => {
                const eff = effectivenessBadge(o.effectivenessScore);
                return (
                  <tr key={o.decisionId} className="text-foreground">
                    <td className="py-2 pr-3 font-medium">{o.decisionLabel}</td>
                    <td className="py-2 pr-3">{new Date(o.madeAt).toLocaleDateString()}</td>
                    <td className="py-2 pr-3">
                      <Badge variant={outcomeBadge(o.outcomeStatus)}>{o.outcomeStatus}</Badge>
                    </td>
                    <td className="py-2 pr-3">
                      <Badge variant={eff.variant}>{eff.label}</Badge>
                    </td>
                    <td className="py-2 pr-3">{o.relatedRemediations}</td>
                    <td className="py-2 pr-3">{o.relatedFindings}</td>
                    <td className="py-2 text-muted">{o.notes ?? '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      </section>
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
