'use client';

import { Alert, AlertDescription } from '@fg/ui';
import type { EngagementSummary } from '@/lib/fieldAssessmentApi';

interface StatCardProps {
  label: string;
  value: number;
  accent?: boolean;
}

function StatCard({ label, value, accent }: StatCardProps) {
  return (
    <div className="flex flex-col rounded border border-border bg-surface-2 p-3 gap-1">
      <span className={`text-2xl font-bold tabular-nums ${accent ? 'text-danger' : 'text-foreground'}`}>
        {value}
      </span>
      <span className="text-xs text-muted">{label}</span>
    </div>
  );
}

interface Props {
  summary: EngagementSummary;
  loading?: boolean;
  error?: string | null;
}

export function EngagementSummaryPanel({ summary, loading, error }: Props) {
  if (loading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3" aria-busy="true">
        {[1, 2, 3, 4, 5, 6].map((i) => (
          <div key={i} className="h-20 rounded border border-border bg-surface-2 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-4" aria-label="engagement-summary-panel">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <StatCard label="Scans Imported" value={summary.scan_results_count} />
        <StatCard label="Documents Registered" value={summary.document_analyses_count} />
        <StatCard label="Observations" value={summary.observations_count} />
        <StatCard label="Findings" value={summary.findings_count} />
        <StatCard label="Evidence Links" value={summary.evidence_links_count} />
        <StatCard label="Open Findings" value={summary.open_findings_count} accent={summary.open_findings_count > 0} />
      </div>
      {summary.critical_findings_count > 0 && (
        <Alert variant="destructive">
          <AlertDescription>
            {summary.critical_findings_count} critical finding{summary.critical_findings_count !== 1 ? 's' : ''} require attention before report generation
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}
