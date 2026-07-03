'use client';

import Link from 'next/link';
import { ArrowRight, HelpCircle } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { EngagementListPage } from '@/lib/fieldAssessmentApi';

// MCIM reference: MCIM-18.6-FIELD-ASSESSMENT
const MCIM_ID = 'MCIM-18.6-FIELD-ASSESSMENT';
const AUTHORITY = 'Field Assessment Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/field-assessment';

export interface CustomerImpactData {
  customersAffected: number;
  assessmentsDelivered: number;
  reportsAwaiting: number;
  portalActivity: number;
  openRequests: number;
  upcomingRenewals: number;
}

function deriveFromEngagements(engagements: EngagementListPage | null): CustomerImpactData {
  if (!engagements) {
    return {
      customersAffected: 0,
      assessmentsDelivered: 0,
      reportsAwaiting: 0,
      portalActivity: 0,
      openRequests: 0,
      upcomingRenewals: 0,
    };
  }

  const items = engagements.items;
  return {
    customersAffected: items.length,
    assessmentsDelivered: items.filter((e) => e.status === 'delivered').length,
    reportsAwaiting: items.filter((e) => e.status === 'delivered').length,
    portalActivity: items.filter((e) => e.client_access_code !== null).length,
    openRequests: items.filter((e) => e.status === 'in_progress').length,
    upcomingRenewals: items.filter((e) => e.status === 'monitoring').length,
  };
}

interface ImpactRow {
  id: string;
  label: string;
  value: number;
  href: string;
  description: string;
}

interface CustomerImpactProps {
  engagements: EngagementListPage | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function CustomerImpact({
  engagements,
  loading = false,
  lastUpdated,
}: CustomerImpactProps) {
  const data = loading ? null : deriveFromEngagements(engagements);

  const rows: ImpactRow[] = data
    ? [
        { id: 'customer-affected', label: 'Customers Affected', value: data.customersAffected, href: '/field-assessment', description: 'Total active client engagements' },
        { id: 'customer-assessments', label: 'Assessments Delivered', value: data.assessmentsDelivered, href: '/field-assessment', description: 'Engagements in delivered state' },
        { id: 'customer-reports-awaiting', label: 'Reports Awaiting', value: data.reportsAwaiting, href: '/field-assessment', description: 'Awaiting QA or approval' },
        { id: 'customer-portal', label: 'Portal Activity', value: data.portalActivity, href: '/field-assessment', description: 'Clients with portal access code' },
        { id: 'customer-open-requests', label: 'Open Requests', value: data.openRequests, href: '/field-assessment', description: 'In-progress engagements' },
        { id: 'customer-renewals', label: 'Upcoming Renewals', value: data.upcomingRenewals, href: '/field-assessment', description: 'Engagements in monitoring phase' },
      ]
    : [];

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Impact"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Customer Impact"
    >
      <div aria-label="customer-impact">
        <p
          className="text-[10px] uppercase tracking-wide text-muted mb-2"
          data-testid="customer-impact-authority"
          aria-label="customer-impact-authority"
        >
          Authority: {AUTHORITY}
        </p>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : engagements === null ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No customer data available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-2">
            {rows.map((row) => (
              <Link
                key={row.id}
                href={row.href}
                className="flex flex-col gap-0.5 rounded-md border border-border p-2 hover:border-primary/40 transition-colors"
                data-testid={row.id}
                aria-label={row.id}
              >
                <span className="text-[10px] text-muted">{row.label}</span>
                <span className="text-lg font-bold text-foreground">{row.value}</span>
                <span className="text-[9px] text-muted/60 leading-tight">{row.description}</span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </WidgetShell>
  );
}
