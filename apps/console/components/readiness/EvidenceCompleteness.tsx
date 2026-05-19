'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import type { ScoreOutput } from '@/lib/readinessApi';

interface EvidenceCompletenessProps {
  score: ScoreOutput;
}

export function EvidenceCompleteness({ score }: EvidenceCompletenessProps) {
  const controls = Object.values(score.control_scores);
  const totalControls = controls.length;
  const totalEvidence = controls.reduce((sum, c) => sum + c.evidence_count, 0);

  return (
    <Card aria-label="evidence-completeness">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Evidence Completeness</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mb-4 flex flex-col gap-1">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Assessment completion</span>
            <span className="font-medium tabular-nums">
              {score.completion_percentage.toFixed(0)}%
            </span>
          </div>
          <Progress
            value={score.completion_percentage}
            aria-label={`Completion: ${score.completion_percentage.toFixed(0)}%`}
          />
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
          <div className="flex flex-col gap-0.5" aria-label="control-count-total">
            <span className="text-2xl font-bold tabular-nums">{totalControls}</span>
            <span className="text-muted-foreground">Total Controls</span>
          </div>
          <div className="flex flex-col gap-0.5" aria-label="control-count-evaluated">
            <span className="text-2xl font-bold tabular-nums">
              {controls.filter((c) => c.is_evaluated).length}
            </span>
            <span className="text-muted-foreground">Evaluated</span>
          </div>
          <div className="flex flex-col gap-0.5" aria-label="control-count-missing">
            <span className="text-2xl font-bold tabular-nums text-risk-high">
              {score.missing_controls.length}
            </span>
            <span className="text-muted-foreground">Missing</span>
          </div>
          <div className="flex flex-col gap-0.5" aria-label="control-count-failed">
            <span className="text-2xl font-bold tabular-nums text-risk-critical">
              {score.failed_controls.length}
            </span>
            <span className="text-muted-foreground">Failed</span>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 gap-3 text-xs sm:grid-cols-3">
          <div className="flex flex-col gap-0.5" aria-label="control-count-incomplete">
            <span className="font-semibold tabular-nums">{score.incomplete_controls.length}</span>
            <span className="text-muted-foreground">Incomplete</span>
          </div>
          <div className="flex flex-col gap-0.5" aria-label="control-count-not-applicable">
            <span className="font-semibold tabular-nums">
              {score.not_applicable_controls.length}
            </span>
            <span className="text-muted-foreground">Not Applicable</span>
          </div>
          <div className="flex flex-col gap-0.5" aria-label="evidence-count-total">
            <span className="font-semibold tabular-nums">{totalEvidence}</span>
            <span className="text-muted-foreground">Evidence Items</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
