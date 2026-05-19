'use client';

import { Badge } from '@fg/ui';
import type { EngagementStatus } from '@/lib/fieldAssessmentApi';

const STATUS_LABELS: Record<EngagementStatus, string> = {
  scheduled: 'Scheduled',
  pre_visit: 'Pre-Visit',
  in_progress: 'In Progress',
  evidence_collected: 'Evidence Collected',
  report_generation: 'Report Generation',
  delivered: 'Delivered',
  remediation: 'Remediation',
  monitoring: 'Monitoring',
  closed: 'Closed',
  cancelled: 'Cancelled',
};

const STATUS_VARIANT: Record<EngagementStatus, 'default' | 'outline' | 'secondary'> = {
  scheduled: 'outline',
  pre_visit: 'secondary',
  in_progress: 'default',
  evidence_collected: 'default',
  report_generation: 'secondary',
  delivered: 'secondary',
  remediation: 'secondary',
  monitoring: 'outline',
  closed: 'outline',
  cancelled: 'outline',
};

const STATUS_COLOR: Record<EngagementStatus, string> = {
  scheduled: 'text-muted border-border',
  pre_visit: 'text-info border-info/30 bg-info/10',
  in_progress: 'text-primary border-primary/30 bg-primary/10',
  evidence_collected: 'text-success border-success/30 bg-success/10',
  report_generation: 'text-warning border-warning/30 bg-warning/10',
  delivered: 'text-success border-success/30 bg-success/10',
  remediation: 'text-warning border-warning/30 bg-warning/10',
  monitoring: 'text-info border-info/30 bg-info/10',
  closed: 'text-muted border-border',
  cancelled: 'text-danger border-danger/30 bg-danger/10',
};

export function StatusBadge({ status }: { status: EngagementStatus }) {
  return (
    <Badge
      variant={STATUS_VARIANT[status]}
      className={`text-xs font-semibold ${STATUS_COLOR[status]}`}
    >
      {STATUS_LABELS[status]}
    </Badge>
  );
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-danger border-danger/30 bg-danger/10',
  high: 'text-warning border-warning/30 bg-warning/10',
  medium: 'text-yellow-400 border-yellow-400/30 bg-yellow-400/10',
  low: 'text-info border-info/30 bg-info/10',
  info: 'text-muted border-border',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge variant="outline" className={`text-xs font-semibold capitalize ${SEVERITY_COLOR[severity] ?? 'text-muted border-border'}`}>
      {severity}
    </Badge>
  );
}
