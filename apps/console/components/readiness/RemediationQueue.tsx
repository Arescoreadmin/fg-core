'use client';

import { ArrowRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { RemediationRecommendation } from '@/lib/readinessApi';

interface RemediationQueueProps {
  recommendations: RemediationRecommendation[];
}

function classificationLabel(c: string): string {
  const labels: Record<string, string> = {
    immediate: 'Immediate',
    short_term: 'Short Term',
    medium_term: 'Medium Term',
    long_term: 'Long Term',
    accepted_risk: 'Accepted Risk',
    compensating_control: 'Compensating Control',
  };
  return labels[c] ?? c;
}

function classificationVariant(
  c: string,
): 'critical' | 'high' | 'medium' | 'low' | 'outline' | 'secondary' {
  const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'outline' | 'secondary'> = {
    immediate: 'critical',
    short_term: 'high',
    medium_term: 'medium',
    long_term: 'low',
    accepted_risk: 'outline',
    compensating_control: 'secondary',
  };
  return map[c] ?? 'outline';
}

export function RemediationQueue({ recommendations }: RemediationQueueProps) {
  if (recommendations.length === 0) {
    return (
      <Card aria-label="remediation-queue">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Remediation Queue</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="remediation-empty">
            No remediation recommendations.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card aria-label="remediation-queue">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">
          Remediation Queue
          <span className="ml-2 text-xs font-normal text-muted-foreground">
            ({recommendations.length} item{recommendations.length !== 1 ? 's' : ''})
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="flex flex-col gap-2" aria-label="remediation-list">
          {recommendations.map((rec, idx) => (
            <li
              key={rec.recommendation_id}
              className="flex items-start gap-3 rounded border border-border px-3 py-2"
              aria-label={`remediation-item-${rec.recommendation_id}`}
            >
              <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-surface-3 text-xs font-medium tabular-nums text-muted-foreground">
                {idx + 1}
              </span>
              <div className="min-w-0 flex-1">
                <div className="mb-1 flex flex-wrap items-center gap-1.5">
                  <Badge variant={classificationVariant(rec.remediation_classification)}>
                    {classificationLabel(rec.remediation_classification)}
                  </Badge>
                  {rec.estimated_readiness_impact > 0 && (
                    <span className="text-xs text-muted-foreground">
                      +{rec.estimated_readiness_impact.toFixed(1)} readiness impact
                    </span>
                  )}
                </div>
                <p className="text-xs text-foreground">{rec.remediation_rationale}</p>
                {rec.governance_rationale && (
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {rec.governance_rationale}
                  </p>
                )}
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
                  {rec.affected_domain_ids.length > 0 && (
                    <span>
                      {rec.affected_domain_ids.length} domain
                      {rec.affected_domain_ids.length !== 1 ? 's' : ''}
                    </span>
                  )}
                  {rec.dependency_ids.length > 0 && (
                    <span className="flex items-center gap-0.5">
                      <ArrowRight className="h-3 w-3" aria-hidden="true" />
                      {rec.dependency_ids.length} dependenc
                      {rec.dependency_ids.length !== 1 ? 'ies' : 'y'}
                    </span>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
