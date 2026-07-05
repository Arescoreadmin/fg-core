'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError, type AuditEvent } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import CustomerTrustTimeline, { type CustomerTimelineEvent, type CustomerTimelineEventType } from '@/components/portal/CustomerTrustTimeline';

const PORTAL_SAFE_EVENT_TYPES = new Set([
  'report_compiled', 'report_published', 'evidence_verified', 'engagement_created',
  'engagement_updated', 'attestation_submitted', 'remediation_updated', 'portal_update',
]);

function auditEventToTimeline(event: AuditEvent): CustomerTimelineEvent | null {
  if (!PORTAL_SAFE_EVENT_TYPES.has(event.event_type)) return null;
  const TYPE_MAP: Record<string, CustomerTimelineEventType> = {
    report_compiled: 'report-generated',
    report_published: 'report-published',
    evidence_verified: 'evidence-verified',
    engagement_created: 'assessment-started',
    engagement_updated: 'portal-update',
    attestation_submitted: 'attestation-submitted',
    remediation_updated: 'remediation-opened',
    portal_update: 'portal-update',
  };
  return {
    id: event.id,
    eventType: TYPE_MAP[event.event_type] ?? 'portal-update',
    label: event.event_type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
    timestamp: event.created_at,
    sourceAuthority: event.reason_code ?? 'Engagement Authority',
    drillDown: null,
    isPortalSafe: true,
  };
}

function TimelinePageInner() {
  const params = useSearchParams();
  // UX hint — URL param takes priority; localStorage is session-continuity fallback only.
  // Authorization is enforced server-side: invalid IDs fail closed at the BFF.
  const engagementId = params.get('e') || getStoredEngagementId();
  const [events, setEvents] = useState<CustomerTimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    setError(null);
    portalApi
      .listAuditEvents(engagementId)
      .then((events) => {
        const safe = events
          .map(auditEventToTimeline)
          .filter((e): e is CustomerTimelineEvent => e !== null);
        setEvents(safe);
        setLastUpdated(new Date().toISOString());
      })
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setEvents([]);
        } else {
          setError('Failed to load timeline data.');
        }
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  return (
    <div data-testid="timeline-page" aria-label="trust-timeline-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Trust Timeline</h1>
        <p className="text-xs text-muted mt-0.5">Portal-visible engagement events in chronological order.</p>
      </div>

      {error && !loading && (
        <div className="mb-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      <CustomerTrustTimeline events={events} loading={loading} lastUpdated={lastUpdated} />
    </div>
  );
}

export default function TimelinePage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <TimelinePageInner />
    </Suspense>
  );
}
