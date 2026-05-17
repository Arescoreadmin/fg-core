'use client';

import { AlertTriangle, CheckCircle2, Clock, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import type { ScoreOutput } from '@/lib/readinessApi';

interface ReadinessOverviewProps {
  score: ScoreOutput;
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

function scoreBarColor(score: number): string {
  if (score < 40) return 'bg-risk-critical';
  if (score < 60) return 'bg-risk-high';
  if (score < 80) return 'bg-risk-medium';
  return 'bg-risk-low';
}

export function ReadinessOverview({ score }: ReadinessOverviewProps) {
  return (
    <Card aria-label="readiness-overview">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Readiness Overview</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {/* Overall score */}
          <div className="flex flex-col gap-1" aria-label="overall-score">
            <span className="text-xs text-muted-foreground">Overall Score</span>
            <span className="text-3xl font-bold tabular-nums">
              {score.overall_score.toFixed(1)}
              <span className="text-sm font-normal text-muted-foreground">/100</span>
            </span>
            <Progress
              value={score.overall_score}
              indicatorClassName={scoreBarColor(score.overall_score)}
              aria-label={`Score progress: ${score.overall_score.toFixed(1)} out of 100`}
            />
          </div>

          {/* Risk classification */}
          <div className="flex flex-col gap-1" aria-label="risk-classification">
            <span className="text-xs text-muted-foreground">Risk Classification</span>
            <div className="flex items-center gap-2 pt-1">
              <ShieldAlert className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              <Badge variant={riskVariant(score.risk_classification)}>
                {score.risk_classification.charAt(0).toUpperCase() +
                  score.risk_classification.slice(1)}
              </Badge>
            </div>
            <span className="text-xs text-muted-foreground">
              Priority: {score.remediation_priority}
            </span>
          </div>

          {/* Maturity tier */}
          <div className="flex flex-col gap-1" aria-label="maturity-tier">
            <span className="text-xs text-muted-foreground">Maturity Tier</span>
            <span className="pt-1 text-sm font-medium">
              {score.maturity_tier ?? (
                <span className="italic text-muted-foreground">Not determined</span>
              )}
            </span>
            <span className="text-xs text-muted-foreground">{score.completion_state}</span>
          </div>

          {/* Completion */}
          <div className="flex flex-col gap-1" aria-label="completion-state">
            <span className="text-xs text-muted-foreground">Completion</span>
            <span className="pt-1 text-2xl font-semibold tabular-nums">
              {score.completion_percentage.toFixed(0)}%
            </span>
            <div className="flex items-center gap-1 text-xs">
              {score.is_complete ? (
                <>
                  <CheckCircle2 className="h-3 w-3 text-success" aria-hidden="true" />
                  <span className="text-success">Complete</span>
                </>
              ) : (
                <>
                  <Clock className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                  <span className="text-muted-foreground">Incomplete</span>
                </>
              )}
            </div>
          </div>
        </div>

        {score.threshold_failures.length > 0 && (
          <div
            className="mt-4 flex items-center gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400"
            aria-label="threshold-failures-summary"
          >
            <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden="true" />
            {score.threshold_failures.length} threshold failure
            {score.threshold_failures.length !== 1 ? 's' : ''} detected — see Governance Drift
            panel.
          </div>
        )}

        <p className="mt-3 text-xs text-muted-foreground" aria-label="computed-at">
          Computed: {new Date(score.computed_at).toLocaleString()} · Version:{' '}
          {score.score_version}
        </p>
      </CardContent>
    </Card>
  );
}
