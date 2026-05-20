'use client';

import { CheckCircle2, Circle, Clock } from 'lucide-react';
import { Progress } from '@fg/ui';
import type { EngagementSummary } from '@/lib/fieldAssessmentApi';

type NumericSummaryKey = {
  [K in keyof EngagementSummary]: EngagementSummary[K] extends number ? K : never;
}[keyof EngagementSummary];

interface ChecklistItem {
  key: NumericSummaryKey;
  label: string;
  description: string;
}

const ITEMS: ChecklistItem[] = [
  { key: 'total_scan_results', label: 'Scans Imported', description: 'Structured scan data ingested' },
  { key: 'total_document_analyses', label: 'Documents Registered', description: 'Governance documents catalogued' },
  { key: 'total_observations', label: 'Observations Captured', description: 'Field observations recorded' },
  { key: 'total_evidence_links', label: 'Evidence Linked', description: 'Evidence edges created' },
  { key: 'total_findings', label: 'Findings Present', description: 'Normalized findings from substrate' },
];

interface Props {
  summary: EngagementSummary;
  onSectionClick?: (section: string) => void;
}

export function ProgressChecklist({ summary, onSectionClick }: Props) {
  const completed = ITEMS.filter((i) => (summary[i.key] as number) > 0).length;
  const pct = Math.round((completed / ITEMS.length) * 100);

  return (
    <div className="space-y-4" aria-label="assessor-progress-checklist">
      <div className="space-y-1">
        <div className="flex items-center justify-between text-sm">
          <span className="font-medium text-foreground">Pre-Report Readiness</span>
          <span className="text-muted">{completed}/{ITEMS.length} complete</span>
        </div>
        <Progress value={pct} className="h-2" aria-label={`${pct}% complete`} />
      </div>

      <ul className="space-y-2" role="list">
        {ITEMS.map((item) => {
          const count = summary[item.key] as number;
          const done = count > 0;
          return (
            <li key={item.key}>
              <button
                className="w-full flex items-center gap-3 p-2 rounded hover:bg-surface-2 transition-colors text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                onClick={() => onSectionClick?.(item.key)}
                aria-label={`${item.label}: ${done ? `${count} recorded` : 'none yet'}`}
              >
                {done ? (
                  <CheckCircle2 className="h-4 w-4 text-success shrink-0" />
                ) : (
                  <Circle className="h-4 w-4 text-muted shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium ${done ? 'text-foreground' : 'text-muted'}`}>
                    {item.label}
                  </p>
                  <p className="text-xs text-muted truncate">{item.description}</p>
                </div>
                <span className={`text-xs font-mono tabular-nums shrink-0 ${done ? 'text-foreground' : 'text-muted'}`}>
                  {count}
                </span>
              </button>
            </li>
          );
        })}
      </ul>

      {summary.open_findings_count > 0 && (
        <div className="flex items-center gap-2 text-xs text-warning p-2 rounded border border-warning/30 bg-warning/10">
          <Clock className="h-3 w-3 shrink-0" />
          <span>{summary.open_findings_count} open finding{summary.open_findings_count !== 1 ? 's' : ''} require review before report generation</span>
        </div>
      )}
    </div>
  );
}
