'use client';

import Link from 'next/link';
import { ArrowRight, HelpCircle } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { Assessment } from '@/lib/readinessApi';

// MCIM reference: MCIM-18.6-READINESS
const MCIM_ID = 'MCIM-18.6-READINESS';
const AUTHORITY = 'Readiness Authority';
const sourceOfTruth = '/api/core/control-plane/readiness/assessments';
const drillDown = '/dashboard/readiness';

export interface ReadinessSummaryData {
  assessments: Assessment[];
  frameworkCount: number;
  openGaps: number | null;
  projectedCompletion: string | null;
}

function deriveReadinessMetrics(data: ReadinessSummaryData | null): {
  assessmentReadinessPct: number | null;
  certificationReadiness: string;
  frameworkCoverage: number | null;
  openGaps: number | null;
  progress: number | null;
  projectedCompletion: string | null;
} {
  if (!data) {
    return {
      assessmentReadinessPct: null,
      certificationReadiness: 'unknown',
      frameworkCoverage: null,
      openGaps: null,
      progress: null,
      projectedCompletion: null,
    };
  }

  const assessments = data.assessments;
  const total = assessments.length;
  const finalized = assessments.filter(
    (a) => a.assessment_status === 'finalized',
  ).length;
  const inProgress = assessments.filter(
    (a) => a.assessment_status === 'collecting' || a.assessment_status === 'partially_evaluated',
  ).length;

  const pct = total > 0 ? Math.round((finalized / total) * 100) : null;
  const progress = total > 0 ? Math.round(((finalized + inProgress * 0.5) / total) * 100) : null;

  const certReady = finalized > 0 ? 'ready' : inProgress > 0 ? 'in-progress' : 'not-started';

  return {
    assessmentReadinessPct: pct,
    certificationReadiness: certReady,
    frameworkCoverage: data.frameworkCount,
    openGaps: data.openGaps,
    progress,
    projectedCompletion: data.projectedCompletion,
  };
}

interface MetricRow {
  id: string;
  label: string;
  value: string | number | null;
  href: string;
}

interface ReadinessSummaryProps {
  data: ReadinessSummaryData | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function ReadinessSummary({
  data,
  loading = false,
  lastUpdated,
}: ReadinessSummaryProps) {
  const metrics = loading ? null : deriveReadinessMetrics(data);

  const rows: MetricRow[] = metrics
    ? [
        {
          id: 'readiness-assessment',
          label: 'Assessment Readiness',
          value: metrics.assessmentReadinessPct !== null ? `${metrics.assessmentReadinessPct}%` : '—',
          href: '/dashboard/readiness',
        },
        {
          id: 'readiness-certification',
          label: 'Certification Readiness',
          value: metrics.certificationReadiness,
          href: '/dashboard/readiness',
        },
        {
          id: 'readiness-framework-coverage',
          label: 'Framework Coverage',
          value: metrics.frameworkCoverage !== null ? `${metrics.frameworkCoverage} frameworks` : '—',
          href: '/dashboard/readiness',
        },
        {
          id: 'readiness-open-gaps',
          label: 'Open Gaps',
          value: metrics.openGaps !== null ? metrics.openGaps : '—',
          href: '/dashboard/readiness',
        },
        {
          id: 'readiness-progress',
          label: 'Progress',
          value: metrics.progress !== null ? `${metrics.progress}%` : '—',
          href: '/dashboard/readiness',
        },
        {
          id: 'readiness-projected-completion',
          label: 'Projected Completion',
          value: metrics.projectedCompletion ?? '—',
          href: '/dashboard/readiness',
        },
      ]
    : [];

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Readiness Summary"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Readiness"
    >
      <div aria-label="readiness-summary">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-8 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : data === null ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No readiness data available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <div className="space-y-1.5">
            {rows.map((row) => (
              <Link
                key={row.id}
                href={row.href}
                className="flex items-center justify-between rounded-md border border-border px-3 py-2 hover:border-primary/40 transition-colors"
                data-testid={row.id}
                aria-label={row.id}
              >
                <span className="text-xs text-muted">{row.label}</span>
                <div className="flex items-center gap-1.5">
                  <span className="text-sm font-semibold text-foreground">
                    {row.value ?? '—'}
                  </span>
                  <ArrowRight className="h-3 w-3 text-muted" aria-hidden="true" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </WidgetShell>
  );
}
