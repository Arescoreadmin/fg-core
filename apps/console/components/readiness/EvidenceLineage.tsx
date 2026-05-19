'use client';

import { AlertTriangle, CheckCircle2, Clock } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { EvidenceFreshnessRecord } from '@/lib/readinessApi';

interface EvidenceLineageProps {
  freshnessRecords: EvidenceFreshnessRecord[];
}

export function EvidenceLineage({ freshnessRecords }: EvidenceLineageProps) {
  if (freshnessRecords.length === 0) {
    return (
      <Card aria-label="evidence-lineage">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">
            Evidence Lineage &amp; Freshness
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="evidence-lineage-empty">
            No evidence freshness records available.
          </p>
        </CardContent>
      </Card>
    );
  }

  const stale = freshnessRecords.filter((r) => r.is_stale);
  const fresh = freshnessRecords.filter((r) => !r.is_stale);

  return (
    <Card aria-label="evidence-lineage">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">
          Evidence Lineage &amp; Freshness
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mb-4 flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5" aria-label="evidence-fresh-count">
            <CheckCircle2 className="h-3.5 w-3.5 text-success" aria-hidden="true" />
            <span className="font-medium">{fresh.length}</span>
            <span className="text-muted-foreground">fresh</span>
          </div>
          <div className="flex items-center gap-1.5" aria-label="evidence-stale-count">
            <AlertTriangle className="h-3.5 w-3.5 text-risk-high" aria-hidden="true" />
            <span className="font-medium text-risk-high">{stale.length}</span>
            <span className="text-muted-foreground">stale</span>
          </div>
          <span className="text-muted-foreground" aria-label="evidence-total-count">
            {freshnessRecords.length} total
          </span>
        </div>

        {stale.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Stale Evidence (top {Math.min(stale.length, 10)})
            </p>
            <div className="flex flex-col gap-2">
              {stale.slice(0, 10).map((r) => (
                <div
                  key={r.freshness_id}
                  className="rounded border border-risk-high/20 bg-risk-high/5 px-3 py-2"
                  aria-label={`stale-record-${r.freshness_id}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs text-foreground">
                        {r.evidence_id}
                      </p>
                      {r.control_id && (
                        <p className="text-xs text-muted-foreground">Control: {r.control_id}</p>
                      )}
                    </div>
                    <div className="flex shrink-0 items-center gap-1 text-xs text-risk-high">
                      <Clock className="h-3 w-3" aria-hidden="true" />
                      {r.staleness_days !== null ? `${r.staleness_days}d stale` : 'stale'}
                    </div>
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Submitted: {new Date(r.submitted_at).toLocaleDateString()} · Window:{' '}
                    {r.freshness_window_days}d
                  </p>
                </div>
              ))}
              {stale.length > 10 && (
                <p className="text-xs text-muted-foreground">
                  +{stale.length - 10} more stale records
                </p>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
