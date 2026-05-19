'use client';

import { AlertTriangle, ShieldX } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { ReadinessGap, ReadinessBlocker } from '@/lib/readinessApi';

interface HighRiskGapsProps {
  gaps: ReadinessGap[];
  blockers: ReadinessBlocker[];
}

const HIGH_RISK = new Set(['critical', 'high']);

function severityVariant(s: string): 'critical' | 'high' | 'medium' | 'low' | 'outline' {
  const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'outline'> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
  };
  return map[s] ?? 'outline';
}

function classificationLabel(c: string): string {
  const labels: Record<string, string> = {
    missing_evidence: 'Missing Evidence',
    stale_evidence: 'Stale Evidence',
    failed_control: 'Failed Control',
    threshold_failure: 'Threshold Failure',
    maturity_gap: 'Maturity Gap',
  };
  return labels[c] ?? c;
}

export function HighRiskGaps({ gaps, blockers }: HighRiskGapsProps) {
  const highRiskGaps = gaps.filter((g) => HIGH_RISK.has(g.gap_severity));
  const blockerGapIds = new Set(blockers.map((b) => b.gap_id));

  if (highRiskGaps.length === 0 && blockers.length === 0) {
    return (
      <Card aria-label="high-risk-gaps">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">High-Risk Gaps &amp; Blockers</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="gaps-empty">
            No critical or high severity gaps detected.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card aria-label="high-risk-gaps">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">
          High-Risk Gaps &amp; Blockers
          <span className="ml-2 text-xs font-normal text-muted-foreground">
            ({highRiskGaps.length} gap{highRiskGaps.length !== 1 ? 's' : ''},{' '}
            {blockers.length} blocker{blockers.length !== 1 ? 's' : ''})
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {blockers.length > 0 && (
          <div className="mb-4 flex flex-col gap-2">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Blockers
            </p>
            {blockers.map((b) => (
              <div
                key={b.blocker_id}
                className="rounded border border-risk-critical/30 bg-risk-critical/5 px-3 py-2"
                aria-label={`blocker-${b.blocker_id}`}
              >
                <div className="flex items-start gap-2">
                  <ShieldX
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 text-risk-critical"
                    aria-hidden="true"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="mb-1 flex flex-wrap items-center gap-1.5">
                      <Badge variant={severityVariant(b.severity)}>{b.severity}</Badge>
                    </div>
                    <p className="text-xs text-foreground">{b.blocker_rationale}</p>
                    {b.affected_control_ids.length > 0 && (
                      <p className="mt-1 text-xs text-muted-foreground">
                        Controls: {b.affected_control_ids.slice(0, 5).join(', ')}
                        {b.affected_control_ids.length > 5 &&
                          ` +${b.affected_control_ids.length - 5} more`}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="flex flex-col gap-2">
          {blockers.length > 0 && (
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Gaps
            </p>
          )}
          {highRiskGaps.map((g) => (
            <div
              key={g.gap_id}
              className="rounded border border-border px-3 py-2"
              aria-label={`gap-${g.gap_id}`}
            >
              <div className="flex items-start gap-2">
                <AlertTriangle
                  className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${
                    g.gap_severity === 'critical' ? 'text-risk-critical' : 'text-risk-high'
                  }`}
                  aria-hidden="true"
                />
                <div className="min-w-0 flex-1">
                  <div className="mb-1 flex flex-wrap items-center gap-1.5">
                    <Badge variant={severityVariant(g.gap_severity)}>{g.gap_severity}</Badge>
                    <span className="text-xs text-muted-foreground">
                      {classificationLabel(g.gap_classification)}
                    </span>
                    {blockerGapIds.has(g.gap_id) && (
                      <span className="text-xs font-medium text-risk-critical">blocker</span>
                    )}
                    {g.is_maturity_blocker && (
                      <span className="text-xs font-medium text-amber-600">maturity blocker</span>
                    )}
                  </div>
                  <p className="text-xs text-foreground">{g.gap_rationale}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
