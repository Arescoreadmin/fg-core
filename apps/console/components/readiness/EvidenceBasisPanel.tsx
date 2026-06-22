'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { ControlScore } from '@/lib/readinessApi';

interface EvidenceBasisPanelProps {
  controlScores: Record<string, ControlScore>;
}

function outcomeVariant(
  o: string,
): 'success' | 'critical' | 'medium' | 'outline' | 'secondary' {
  const map: Record<string, 'success' | 'critical' | 'medium' | 'outline' | 'secondary'> = {
    pass: 'success',
    fail: 'critical',
    partial: 'medium',
    not_evaluated: 'outline',
    not_applicable: 'secondary',
  };
  return map[o] ?? 'outline';
}

function outcomeLabel(o: string): string {
  const labels: Record<string, string> = {
    pass: 'Pass',
    fail: 'Fail',
    partial: 'Partial',
    not_evaluated: 'Not Evaluated',
    not_applicable: 'N/A',
  };
  return labels[o] ?? o;
}

const OUTCOME_ORDER = ['fail', 'partial', 'pass', 'not_evaluated', 'not_applicable'];

export function EvidenceBasisPanel({ controlScores }: EvidenceBasisPanelProps) {
  const controls = Object.values(controlScores);

  if (controls.length === 0) {
    return (
      <Card aria-label="evidence-basis-panel">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Control Evidence Basis</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="evidence-basis-empty">
            No control scores available.
          </p>
        </CardContent>
      </Card>
    );
  }

  const byOutcome = controls.reduce<Record<string, ControlScore[]>>((acc, c) => {
    (acc[c.outcome] ??= []).push(c);
    return acc;
  }, {});

  const outcomeSummary = Object.entries(byOutcome).sort(
    ([a], [b]) => OUTCOME_ORDER.indexOf(a) - OUTCOME_ORDER.indexOf(b),
  );

  const failed = byOutcome['fail'] ?? [];

  return (
    <Card aria-label="evidence-basis-panel">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Control Evidence Basis</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mb-4 flex flex-wrap gap-2" aria-label="outcome-summary">
          {outcomeSummary.map(([outcome, items]) => (
            <div
              key={outcome}
              className="flex items-center gap-1.5 rounded border border-border px-2 py-1"
              aria-label={`outcome-${outcome}-count`}
            >
              <Badge variant={outcomeVariant(outcome)}>{outcomeLabel(outcome)}</Badge>
              <span className="text-xs font-medium tabular-nums">{items.length}</span>
            </div>
          ))}
        </div>

        {failed.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Failed Controls (top {Math.min(failed.length, 10)})
            </p>
            <div className="flex flex-col gap-1">
              {failed.slice(0, 10).map((c) => (
                <div
                  key={c.control_id}
                  className="flex items-center justify-between gap-2 text-xs"
                  aria-label={`failed-control-${c.control_id}`}
                >
                  <span className="font-mono text-foreground">{c.control_identifier}</span>
                  <span className="shrink-0 text-muted-foreground">
                    w:{c.weight.toFixed(2)} · ev:{c.evidence_count}
                  </span>
                </div>
              ))}
              {failed.length > 10 && (
                <p className="text-xs text-muted-foreground">
                  +{failed.length - 10} more failed controls
                </p>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
