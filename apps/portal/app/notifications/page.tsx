'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import NotificationCenter, { type PortalNotification, type NotificationType } from '@/components/portal/NotificationCenter';

const NOTIF_READ_KEY = 'fg-portal-notifications-read';

function getReadIds(engagementId: string): Set<string> {
  try {
    const raw = localStorage.getItem(`${NOTIF_READ_KEY}-${engagementId}`);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch {
    return new Set();
  }
}

function saveReadIds(engagementId: string, ids: Set<string>) {
  try {
    localStorage.setItem(`${NOTIF_READ_KEY}-${engagementId}`, JSON.stringify(Array.from(ids)));
  } catch {
    // ignore storage errors
  }
}

const EVENT_TYPE_MAP: Record<string, NotificationType> = {
  report_compiled: 'report-published',
  report_published: 'report-published',
  finding_created: 'finding-updated',
  finding_updated: 'finding-updated',
  attestation_submitted: 'attestation-due',
  engagement_updated: 'engagement-update',
  remediation_updated: 'remediation-update',
};

function NotificationsPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') || getStoredEngagementId();
  const [notifications, setNotifications] = useState<PortalNotification[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    setError(null);
    const readIds = getReadIds(engagementId);
    portalApi
      .listAuditEvents(engagementId)
      .then((events) => {
        const mapped: PortalNotification[] = events
          .filter((e) => EVENT_TYPE_MAP[e.event_type])
          .slice(0, 20)
          .map((e) => ({
            id: e.id,
            type: EVENT_TYPE_MAP[e.event_type],
            title: e.event_type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
            message: `Event recorded by ${e.actor}${e.reason_code ? ` (${e.reason_code})` : ''}.`,
            severity: 'info' as const,
            isRead: readIds.has(e.id),
            createdAt: e.created_at,
          }));
        setNotifications(mapped);
        setLastUpdated(new Date().toISOString());
      })
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setNotifications([]);
        } else {
          setError('Failed to load notifications.');
        }
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  function handleMarkRead(id: string) {
    if (!engagementId) return;
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, isRead: true } : n)),
    );
    const readIds = getReadIds(engagementId);
    readIds.add(id);
    saveReadIds(engagementId, readIds);
  }

  return (
    <div data-testid="notifications-page" aria-label="notifications-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Notifications</h1>
        <p className="text-xs text-muted mt-0.5">Recent portal events and updates for this engagement.</p>
      </div>

      {error && !loading && (
        <div className="mb-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      <NotificationCenter
        notifications={notifications}
        onMarkRead={handleMarkRead}
        loading={loading}
        lastUpdated={lastUpdated}
      />
    </div>
  );
}

export default function NotificationsPage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <NotificationsPageInner />
    </Suspense>
  );
}
