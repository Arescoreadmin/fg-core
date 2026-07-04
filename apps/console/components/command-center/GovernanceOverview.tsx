'use client';

import { TrendingUp, TrendingDown, Minus, AlertTriangle } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { ScoreOutput } from '@/lib/readinessApi';

// MCIM reference: MCIM-18.6-GOVERNANCE
const MCIM_ID = 'MCIM-18.6-GOVERNANCE';
const AUTHORITY = 'Governance Authority';
const sourceOfTruth = '/api/core/control-plane/readiness/assessments/{id}/score';
const drillDown = '/dashboard/readiness';

interface GovernanceOverviewProps {
  score: ScoreOutput | null;
  loading?: boolean;
  trendNote?: string;
  lastUpdated?: string;
}

export default function GovernanceOverview({
  score,
  loading = false,
  trendNote,
  lastUpdated,
}: GovernanceOverviewProps) {
  const overallScore = score?.overall_score ?? null;
  const riskClass = score?.risk_classification ?? null;
  const missingControls = score?.missing_controls?.length ?? null;
  const incompleteControls = score?.incomplete_controls?.length ?? null;
  const completionPct = score?.completion_percentage ?? null;
  const remediationFactors = score?.remediation_factors ?? [];

  const topFactors = remediationFactors.slice(0, 3);

  const trendDisplay = trendNote ?? score?.completion_state ?? null;

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Governance Overview"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Governance Overview"
    >
      <div aria-label="governance-overview" data-testid="governance-overview">
        {loading ? (
          <div className="space-y-2">
            <div className="h-10 w-24 animate-pulse rounded bg-muted" />
            <div className="h-4 w-40 animate-pulse rounded bg-muted" />
            <div className="h-4 w-32 animate-pulse rounded bg-muted" />
          </div>
        ) : score === null ? (
          <div className="py-4 text-center text-sm text-muted">
            <AlertTriangle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No governance assessment available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <div className="space-y-3">
            {/* Score display */}
            <div
              className="flex items-end gap-3"
              aria-label="governance-score-display"
              data-testid="governance-score-display"
            >
              <span className="text-4xl font-bold text-foreground">
                {overallScore !== null ? Math.round(overallScore) : '—'}
              </span>
              <span className="mb-1 text-sm text-muted">/ 100</span>
              {riskClass && (
                <span
                  className={`mb-1 text-sm font-semibold ${
                    riskClass === 'critical'
                      ? 'text-danger'
                      : riskClass === 'high'
                        ? 'text-warning'
                        : riskClass === 'medium'
                          ? 'text-yellow-600'
                          : 'text-success'
                  }`}
                >
                  {riskClass.toUpperCase()}
                </span>
              )}
            </div>

            {/* Trend */}
            {trendDisplay && (
              <div
                className="flex items-center gap-1.5 text-xs text-muted"
                aria-label="governance-trend"
                data-testid="governance-trend"
              >
                <TrendingUp className="h-3.5 w-3.5 text-muted" aria-hidden="true" />
                <span>trend: {trendDisplay}</span>
              </div>
            )}

            {/* Completion */}
            {completionPct !== null && (
              <div className="text-xs text-muted">
                Completion:{' '}
                <span className="font-semibold text-foreground">
                  {Math.round(completionPct)}%
                </span>
              </div>
            )}

            {/* Governance debt */}
            {(missingControls !== null || incompleteControls !== null) && (
              <div className="rounded-md border border-border bg-muted/20 p-2 text-xs text-muted">
                <span className="font-semibold text-foreground">Governance debt: </span>
                {missingControls !== null && (
                  <span className="mr-2">
                    {missingControls} missing control{missingControls !== 1 ? 's' : ''}
                  </span>
                )}
                {incompleteControls !== null && (
                  <span>
                    {incompleteControls} incomplete control{incompleteControls !== 1 ? 's' : ''}
                  </span>
                )}
              </div>
            )}

            {/* Top contributing factors */}
            {topFactors.length > 0 && (
              <div
                aria-label="governance-factors"
                data-testid="governance-factors"
              >
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted mb-1">
                  Top Factors
                </h3>
                <ul className="space-y-1">
                  {topFactors.map((f, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-muted">
                      {f.severity === 'critical' ? (
                        <TrendingDown className="h-3.5 w-3.5 shrink-0 text-danger mt-0.5" aria-hidden="true" />
                      ) : f.severity === 'high' ? (
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-warning mt-0.5" aria-hidden="true" />
                      ) : (
                        <Minus className="h-3.5 w-3.5 shrink-0 text-muted mt-0.5" aria-hidden="true" />
                      )}
                      <span>{f.description}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </WidgetShell>
  );
}
