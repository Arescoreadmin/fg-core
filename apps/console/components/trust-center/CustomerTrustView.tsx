'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-CUSTOMER-VIEW';
const AUTHORITY = 'Customer Trust Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/products';

export interface CustomerTrustSummary {
  customerId: string;
  customerName: string;
  overallTrustScore: number | null;
  lastAssessmentAt: string | null;
  activeRisks: number;
  openFindings: number;
  portalPublications: number;
  verificationState: 'verified' | 'partial' | 'unverified';
}

interface CustomerTrustViewProps {
  customers: CustomerTrustSummary[];
  loading?: boolean;
  lastUpdated?: string;
}

function scoreBadge(score: number | null): 'success' | 'warning' | 'danger' | 'secondary' {
  if (score === null) return 'secondary';
  if (score >= 80) return 'success';
  if (score >= 60) return 'warning';
  return 'danger';
}

function verificationBadge(state: 'verified' | 'partial' | 'unverified'): 'success' | 'warning' | 'secondary' {
  switch (state) {
    case 'verified': return 'success';
    case 'partial': return 'warning';
    case 'unverified': return 'secondary';
  }
}

export default function CustomerTrustView({ customers, loading, lastUpdated }: CustomerTrustViewProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer trust state operator preview"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Customer Trust View"
    >
      <section aria-label="customer-trust-view" data-testid="customer-trust-view">
      <div className="mb-3 rounded-md border border-border bg-muted/20 px-3 py-2 text-xs text-muted">
        Operator preview only. This view reflects internal trust state and is not directly exposed to customers.
      </div>
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : customers.length === 0 ? (
        <p className="text-sm text-muted">No customer trust data available.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="pb-2 pr-3 font-medium">Customer Name</th>
                <th className="pb-2 pr-3 font-medium">Trust Score</th>
                <th className="pb-2 pr-3 font-medium">Verification</th>
                <th className="pb-2 pr-3 font-medium">Active Risks</th>
                <th className="pb-2 pr-3 font-medium">Open Findings</th>
                <th className="pb-2 pr-3 font-medium">Portal Publications</th>
                <th className="pb-2 font-medium">Last Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {customers.map((c) => (
                <tr key={c.customerId} className="text-foreground">
                  <td className="py-2 pr-3 font-medium">{c.customerName}</td>
                  <td className="py-2 pr-3">
                    <Badge variant={scoreBadge(c.overallTrustScore)}>
                      {c.overallTrustScore !== null ? c.overallTrustScore : '—'}
                    </Badge>
                  </td>
                  <td className="py-2 pr-3">
                    <Badge variant={verificationBadge(c.verificationState)}>{c.verificationState}</Badge>
                  </td>
                  <td className="py-2 pr-3">{c.activeRisks}</td>
                  <td className="py-2 pr-3">{c.openFindings}</td>
                  <td className="py-2 pr-3">{c.portalPublications}</td>
                  <td className="py-2">
                    {c.lastAssessmentAt ? new Date(c.lastAssessmentAt).toLocaleDateString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      </section>
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
