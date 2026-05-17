'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import type { DomainScore } from '@/lib/readinessApi';

interface DomainHeatmapProps {
  domainScores: Record<string, DomainScore>;
}

function riskVariant(r: string): 'critical' | 'high' | 'medium' | 'low' | 'outline' {
  const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'outline'> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
  };
  return map[r] ?? 'outline';
}

function scoreBarColor(r: string): string {
  const map: Record<string, string> = {
    critical: 'bg-risk-critical',
    high: 'bg-risk-high',
    medium: 'bg-risk-medium',
    low: 'bg-risk-low',
  };
  return map[r] ?? 'bg-muted';
}

export function DomainHeatmap({ domainScores }: DomainHeatmapProps) {
  const domains = Object.values(domainScores).sort(
    (a, b) => a.normalized_score - b.normalized_score,
  );

  if (domains.length === 0) {
    return (
      <Card aria-label="domain-heatmap">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Domain Scores</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="domain-heatmap-empty">
            No domain scores available.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card aria-label="domain-heatmap">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">
          Domain Scores{' '}
          <span className="ml-1 font-normal text-muted-foreground">({domains.length})</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-3">
          {domains.map((d) => (
            <div
              key={d.domain_id}
              className="flex flex-col gap-1"
              aria-label={`domain-score-${d.domain_id}`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-xs font-medium" title={d.domain_name}>
                  {d.domain_name}
                </span>
                <div className="flex shrink-0 items-center gap-1.5">
                  <Badge variant={riskVariant(d.risk_classification)} className="text-xs">
                    {d.risk_classification}
                  </Badge>
                  {d.threshold_failed && (
                    <span className="text-xs text-amber-600" aria-label="threshold-failed">
                      ⚠ threshold
                    </span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Progress
                  value={d.normalized_score * 100}
                  indicatorClassName={scoreBarColor(d.risk_classification)}
                  className="h-1.5 flex-1"
                  aria-label={`${d.domain_name} score ${(d.normalized_score * 100).toFixed(0)}%`}
                />
                <span className="w-8 text-right text-xs tabular-nums text-muted-foreground">
                  {(d.normalized_score * 100).toFixed(0)}%
                </span>
              </div>
              {(d.missing_control_count > 0 || d.failed_control_count > 0) && (
                <p className="text-xs text-muted-foreground">
                  {d.missing_control_count > 0 && `${d.missing_control_count} missing`}
                  {d.missing_control_count > 0 && d.failed_control_count > 0 && ' · '}
                  {d.failed_control_count > 0 && `${d.failed_control_count} failed`}
                </p>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
