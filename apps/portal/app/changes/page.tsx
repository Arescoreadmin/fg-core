'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { getStoredEngagementId } from '@/lib/engagementStore';
import ChangeSummary, { type ChangeGroup } from '@/components/portal/ChangeSummary';

const CHANGE_STORAGE_KEY = 'fg-portal-change-baseline';

function ChangesPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') || getStoredEngagementId();
  const [groups] = useState<ChangeGroup[]>([]);
  const [sinceTimestamp, setSinceTimestamp] = useState<string | null>(null);
  const [hasHistoricalState, setHasHistoricalState] = useState(false);
  const [lastUpdated] = useState<string | undefined>(new Date().toISOString());

  useEffect(() => {
    if (!engagementId) return;
    const baseline = localStorage.getItem(`${CHANGE_STORAGE_KEY}-${engagementId}`);
    if (baseline) {
      setHasHistoricalState(true);
      setSinceTimestamp(baseline);
    }
  }, [engagementId]);

  return (
    <div data-testid="changes-page" aria-label="changes-summary-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Change Summary</h1>
        <p className="text-xs text-muted mt-0.5">What has changed since your last portal visit.</p>
      </div>

      <ChangeSummary
        groups={groups}
        sinceTimestamp={sinceTimestamp}
        hasHistoricalState={hasHistoricalState}
        loading={false}
        lastUpdated={lastUpdated}
      />
    </div>
  );
}

export default function ChangesPage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <ChangesPageInner />
    </Suspense>
  );
}
