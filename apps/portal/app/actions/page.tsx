'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError, type FindingSummary } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import CustomerActionQueue, { type CustomerAction } from '@/components/portal/CustomerActionQueue';

function findingToAction(f: FindingSummary): CustomerAction {
  const priorityMap: Record<string, 'critical' | 'high' | 'medium' | 'low'> = {
    critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'low',
  };
  return {
    id: f.finding_id,
    actionType: 'acknowledge-finding',
    label: f.title,
    description: f.remediation_hint ?? 'Review and acknowledge this finding.',
    priority: priorityMap[f.severity] ?? 'medium',
    dueDate: null,
    owner: null,
    sourceAuthority: 'Finding Authority',
    linkedEntityId: f.finding_id,
    linkedEntityType: 'finding',
    actionRoute: '/findings',
  };
}

function ActionsPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') || getStoredEngagementId();
  const [actions, setActions] = useState<CustomerAction[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    setError(null);
    portalApi
      .listFindings(engagementId, { status: 'open', limit: 50 })
      .then((res) => {
        setActions(res.items.map(findingToAction));
        setLastUpdated(new Date().toISOString());
      })
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setActions([]);
        } else {
          setError('Failed to load action queue.');
        }
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  return (
    <div data-testid="actions-page" aria-label="customer-actions-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Action Queue</h1>
        <p className="text-xs text-muted mt-0.5">Remediation tasks and required actions for this engagement.</p>
      </div>

      {error && !loading && (
        <div className="mb-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      <CustomerActionQueue actions={actions} loading={loading} lastUpdated={lastUpdated} />
    </div>
  );
}

export default function ActionsPage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <ActionsPageInner />
    </Suspense>
  );
}
