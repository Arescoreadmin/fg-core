'use client';

import { AlertTriangle, Info } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { ThresholdFailure } from '@/lib/readinessApi';

interface GovernanceDriftProps {
  thresholdFailures: ThresholdFailure[];
  scoringWarnings: string[];
}

export function GovernanceDrift({ thresholdFailures, scoringWarnings }: GovernanceDriftProps) {
  if (thresholdFailures.length === 0 && scoringWarnings.length === 0) {
    return (
      <Card aria-label="governance-drift">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Governance Drift</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="governance-drift-clean">
            No threshold failures or scoring warnings detected.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card aria-label="governance-drift">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Governance Drift</CardTitle>
      </CardHeader>
      <CardContent>
        {thresholdFailures.length > 0 && (
          <div className="mb-4">
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Threshold Failures ({thresholdFailures.length})
            </p>
            <div className="flex flex-col gap-2">
              {thresholdFailures.map((f, i) => (
                <div
                  key={i}
                  className="rounded border border-risk-critical/30 bg-risk-critical/5 px-3 py-2"
                  aria-label={`threshold-failure-${i}`}
                >
                  <div className="flex items-start gap-2">
                    <AlertTriangle
                      className="mt-0.5 h-3.5 w-3.5 shrink-0 text-risk-critical"
                      aria-hidden="true"
                    />
                    <div>
                      <p className="text-xs font-medium text-foreground">{f.threshold_name}</p>
                      <p className="text-xs text-muted-foreground">
                        Type: {f.threshold_type} · Required:{' '}
                        <span className="font-medium">{f.required_value}</span> · Actual:{' '}
                        <span className="font-medium text-risk-critical">{f.actual_value}</span>
                      </p>
                      <p className="mt-0.5 text-xs text-foreground">{f.message}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {scoringWarnings.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Scoring Warnings ({scoringWarnings.length})
            </p>
            <div className="flex flex-col gap-1.5">
              {scoringWarnings.map((w, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2 text-xs"
                  aria-label={`scoring-warning-${i}`}
                >
                  <Info
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600"
                    aria-hidden="true"
                  />
                  <span className="text-foreground">{w}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
