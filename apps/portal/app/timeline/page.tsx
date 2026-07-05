'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError, type AuditEvent } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import CustomerTrustTimeline, { type CustomerTimelineEvent, type CustomerTimelineEventType } from '@/components/portal/CustomerTrustTimeline';

// Actual backend event_type values emitted by field_assessment API routes.
// Must match the dot/underscore names the backend writes to fa_engagement_audit_events.
const PORTAL_SAFE_EVENT_TYPES = new Set([
  'engagement.created',
  'engagement.metadata_updated',
  'engagement.status_transitioned',
  'engagement_report_created',
  'report.qa_approved',
  'verification_bundle.generated',
  'attestation.submitted',
  'questionnaire.submitted',
  'evidence_link.created',
  'scan_result.ingested',
]);

const TIMELINE_TYPE_MAP: Record<string, CustomerTimelineEventType> = {
  'engagement.created': 'assessment-started',
  'engagement.metadata_updated': 'portal-update',
  'engagement.status_transitioned': 'portal-update',
  'engagement_report_created': 'report-generated',
  'report.qa_approved': 'report-published',
  'verification_bundle.generated': 'verification-completed',
  'attestation.submitted': 'attestation-submitted',
  'questionnaire.submitted': 'portal-update',
  'evidence_link.created': 'evidence-collected',
  'scan_result.ingested': 'evidence-collected',
};

function auditEventToTimeline(event: AuditEvent): CustomerTimelineEvent | null {
  if (!PORTAL_SAFE_EVENT_TYPES.has(event.event_type)) return null;
  const label = event.event_type
    .replace(/[._]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
  return {
    id: event.id,
    eventType: TIMELINE_TYPE_MAP[event.event_type] ?? 'portal-update',
    label,
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
