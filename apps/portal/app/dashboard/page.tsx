'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError, type EngagementCounts } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import CustomerDashboard, { type DashboardCard } from '@/components/portal/CustomerDashboard';

function buildDashboardCards(counts: EngagementCounts): DashboardCard[] {
  return [
    {
      id: 'open-findings',
      title: 'Open Findings',
      status: counts.open_findings > 0 ? 'active' : 'completed',
      value: counts.open_findings,
      lastUpdated: null,
      confidence: null,
      drillDown: '/findings',
      authority: 'Finding Authority',
    },
    {
      id: 'critical-findings',
      title: 'Critical Findings',
      status: counts.critical_findings > 0 ? 'error' : 'completed',
      value: counts.critical_findings,
      lastUpdated: null,
      confidence: null,
      drillDown: '/findings?severity=critical',
      authority: 'Finding Authority',
    },
    {
      id: 'scan-results',
      title: 'Scan Results',
      status: counts.scan_results > 0 ? 'active' : 'draft',
      value: counts.scan_results,
      lastUpdated: null,
      confidence: null,
      drillDown: '/findings',
      authority: 'Scan Authority',
    },
    {
      id: 'evidence-links',
      title: 'Evidence Links',
      status: counts.evidence_links > 0 ? 'active' : 'pending',
      value: counts.evidence_links,
      lastUpdated: null,
      confidence: null,
      drillDown: '/reports',
      authority: 'Evidence Authority',
    },
    {
      id: 'normalized-findings',
      title: 'Total Findings',
      status: 'active',
      value: counts.normalized_findings,
      lastUpdated: null,
      confidence: null,
      drillDown: '/findings',
      authority: 'Assessment Authority',
    },
    {
      id: 'document-analyses',
      title: 'Documents Analysed',
      status: counts.document_analyses > 0 ? 'completed' : 'pending',
      value: counts.document_analyses,
      lastUpdated: null,
      confidence: null,
      drillDown: '/reports',
      authority: 'Document Authority',
    },
  ];
}

function DashboardPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') || getStoredEngagementId();
  const [cards, setCards] = useState<DashboardCard[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    setError(null);
    portalApi
      .getEngagementSummary(engagementId)
      .then((counts) => {
        setCards(buildDashboardCards(counts));
        setLastUpdated(new Date().toISOString());
      })
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setError('Engagement not found.');
        } else {
          setError('Failed to load dashboard data.');
        }
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  return (
    <div data-testid="dashboard-page" aria-label="customer-dashboard-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Dashboard</h1>
        <p className="text-xs text-muted mt-0.5">Engagement summary and key metrics.</p>
      </div>

      {error && !loading && (
        <div className="mb-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      <CustomerDashboard
        cards={cards}
        engagementId={engagementId}
        loading={loading}
        lastUpdated={lastUpdated}
      />
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <DashboardPageInner />
    </Suspense>
  );
}
