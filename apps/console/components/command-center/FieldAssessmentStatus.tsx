'use client';

import Link from 'next/link';
import { ArrowRight, FileCheck, HelpCircle } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { EngagementListPage } from '@/lib/fieldAssessmentApi';

// MCIM reference: MCIM-18.6-FIELD-ASSESSMENT
const MCIM_ID = 'MCIM-18.6-FIELD-ASSESSMENT';
const AUTHORITY = 'Field Assessment Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/field-assessment';

export interface FieldAssessmentCounts {
  assessments: number;
  evidence: number;
  verification: number;
  reports: number;
  portal: number;
  remediation: number;
  continuity: number;
}

function countFromEngagements(engagements: EngagementListPage | null): FieldAssessmentCounts {
  if (!engagements) {
    return { assessments: 0, evidence: 0, verification: 0, reports: 0, portal: 0, remediation: 0, continuity: 0 };
  }

  const items = engagements.items;
  return {
    assessments: items.length,
    evidence: items.filter((e) => e.status === 'in_progress').length,
    verification: items.filter((e) => e.status === 'delivered').length,
    reports: items.filter((e) => e.status === 'delivered' || e.status === 'monitoring').length,
    portal: items.filter((e) => e.client_access_code !== null).length,
    remediation: items.filter((e) => e.status === 'remediation').length,
    continuity: items.filter((e) => e.status === 'monitoring').length,
  };
}

interface LifecycleItem {
  id: string;
  label: string;
  count: number;
  href: string;
  description: string;
}

interface FieldAssessmentStatusProps {
  engagements: EngagementListPage | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function FieldAssessmentStatus({
  engagements,
  loading = false,
  lastUpdated,
}: FieldAssessmentStatusProps) {
  const counts = loading ? null : countFromEngagements(engagements);

  const items: LifecycleItem[] = counts
    ? [
        { id: 'fa-assessments', label: 'Assessments', count: counts.assessments, href: '/field-assessment', description: 'Total active engagements' },
        { id: 'fa-evidence', label: 'Evidence', count: counts.evidence, href: '/field-assessment', description: 'In-progress evidence collection' },
        { id: 'fa-verification', label: 'Verification', count: counts.verification, href: '/field-assessment', description: 'Awaiting delivery verification' },
        { id: 'fa-reports', label: 'Reports', count: counts.reports, href: '/field-assessment', description: 'Reports generated' },
        { id: 'fa-portal', label: 'Portal', count: counts.portal, href: '/field-assessment', description: 'Client portal active' },
        { id: 'fa-remediation', label: 'Remediation', count: counts.remediation, href: '/field-assessment', description: 'In remediation phase' },
        { id: 'fa-continuity', label: 'Continuity', count: counts.continuity, href: '/field-assessment', description: 'Ongoing monitoring' },
      ]
    : [];

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Field Assessment Status"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Field Assessment"
    >
      <div aria-label="fa-lifecycle" data-testid="fa-lifecycle">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : engagements === null ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No field assessment data available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <div className="space-y-1">
            {items.map((item) => (
              <Link
                key={item.id}
                href={item.href}
                className="flex items-center justify-between rounded-md border border-border px-3 py-2 hover:border-primary/40 transition-colors"
                data-testid={item.id}
                aria-label={item.id}
              >
                <div className="flex items-center gap-2">
                  <FileCheck className="h-3.5 w-3.5 text-primary shrink-0" aria-hidden="true" />
                  <div>
                    <p className="text-xs font-medium text-foreground">{item.label}</p>
                    <p className="text-[10px] text-muted">{item.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-foreground">{item.count}</span>
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
