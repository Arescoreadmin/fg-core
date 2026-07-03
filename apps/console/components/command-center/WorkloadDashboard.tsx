'use client';

import { HelpCircle } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { EngagementListPage } from '@/lib/fieldAssessmentApi';

// MCIM reference: MCIM-18.6-FIELD-ASSESSMENT
const MCIM_ID = 'MCIM-18.6-FIELD-ASSESSMENT';
const AUTHORITY = 'Field Assessment Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/field-assessment';

export interface WorkloadData {
  assessmentLoad: number;
  reviewLoad: number;
  approvalQueue: number;
  remediationWorkload: number;
  analystCount: number;
  automationPct: number | null;
}

function deriveFromEngagements(engagements: EngagementListPage | null): WorkloadData {
  if (!engagements) {
    return { assessmentLoad: 0, reviewLoad: 0, approvalQueue: 0, remediationWorkload: 0, analystCount: 0, automationPct: null };
  }

  const items = engagements.items;
  return {
    assessmentLoad: items.filter((e) => e.status === 'in_progress').length,
    reviewLoad: items.filter((e) => e.status === 'delivered').length,
    approvalQueue: items.filter((e) => e.status === 'delivered').length,
    remediationWorkload: items.filter((e) => e.status === 'remediation').length,
    analystCount: new Set(items.map((e) => e.assessor_id)).size,
    automationPct: null,
  };
}

interface WorkloadBarProps {
  id: string;
  label: string;
  value: number | null;
  max?: number;
  unit?: string;
}

function WorkloadBar({ id, label, value, max, unit = '' }: WorkloadBarProps) {
  const pct = max && max > 0 && value !== null ? Math.min(100, Math.round((value / max) * 100)) : 0;
  const display = value !== null ? `${value}${unit}` : '—';

  return (
    <div data-testid={id} aria-label={id} className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted">{label}</span>
        <span className="font-semibold text-foreground">{display}</span>
      </div>
      {max !== undefined && value !== null && (
        <div className="h-1.5 rounded-full bg-muted/30">
          <div
            className="h-1.5 rounded-full bg-primary transition-all"
            style={{ width: `${pct}%` }}
            role="progressbar"
            aria-valuenow={value}
            aria-valuemax={max}
          />
        </div>
      )}
    </div>
  );
}

interface WorkloadDashboardProps {
  engagements: EngagementListPage | null;
  agentData: Record<string, unknown> | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function WorkloadDashboard({
  engagements,
  agentData,
  loading = false,
  lastUpdated,
}: WorkloadDashboardProps) {
  const data = loading ? null : deriveFromEngagements(engagements);

  const totalLoad =
    data !== null
      ? data.assessmentLoad + data.reviewLoad + data.approvalQueue + data.remediationWorkload
      : 1;

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Workload Dashboard"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Workload"
    >
      <div aria-label="workload-dashboard">
        <p
          className="text-[10px] uppercase tracking-wide text-muted mb-3"
          data-testid="workload-authority"
          aria-label="workload-authority"
        >
          Authority: {AUTHORITY}
        </p>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-8 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : data === null ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No workload data available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <div className="space-y-3">
            <WorkloadBar
              id="workload-assessment"
              label="Assessment Load"
              value={data.assessmentLoad}
              max={totalLoad}
            />
            <WorkloadBar
              id="workload-review"
              label="Review Load"
              value={data.reviewLoad}
              max={totalLoad}
            />
            <WorkloadBar
              id="workload-approval"
              label="Approval Queue"
              value={data.approvalQueue}
              max={totalLoad}
            />
            <WorkloadBar
              id="workload-remediation"
              label="Remediation Workload"
              value={data.remediationWorkload}
              max={totalLoad}
            />
            <WorkloadBar
              id="workload-analysts"
              label="Analyst Count"
              value={data.analystCount}
            />
            <WorkloadBar
              id="workload-automation"
              label="Automation %"
              value={data.automationPct}
              unit="%"
            />
          </div>
        )}
      </div>
    </WidgetShell>
  );
}
