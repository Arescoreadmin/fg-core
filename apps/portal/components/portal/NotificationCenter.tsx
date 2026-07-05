'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-NOTIFICATIONS';
const AUTHORITY = 'Notification Center Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/notifications';
const customerSafe = true;

export type NotificationType =
  | 'report-published' | 'finding-updated' | 'attestation-due'
  | 'engagement-update' | 'remediation-update';

export interface PortalNotification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical';
  isRead: boolean;
  createdAt: string;
}

interface Props {
  notifications: PortalNotification[];
  onMarkRead?: (id: string) => void;
  loading: boolean;
  lastUpdated?: string;
}

const SEVERITY_CLASS: Record<PortalNotification['severity'], string> = {
  info: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  warning: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
};

const TYPE_LABEL: Record<NotificationType, string> = {
  'report-published': 'Report',
  'finding-updated': 'Finding',
  'attestation-due': 'Attestation',
  'engagement-update': 'Engagement',
  'remediation-update': 'Remediation',
};

export default function NotificationCenter({ notifications, onMarkRead, loading, lastUpdated }: Props) {
  const unread = notifications.filter((n) => !n.isRead).length;

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Notifications"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title={unread > 0 ? `Notifications (${unread} unread)` : 'Notifications'}
      lastUpdated={lastUpdated}
    >
      <section aria-label="notification-center" data-testid="notification-center">
        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && notifications.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No notifications.</p>
        )}

        {!loading && notifications.length > 0 && (
          <div className="space-y-2">
            {notifications.map((n) => (
              <div
                key={n.id}
                className={`rounded border p-3 space-y-1.5 transition-colors ${n.isRead ? 'border-border bg-surface opacity-70' : 'border-border bg-surface-2'}`}
              >
                <div className="flex flex-wrap items-start gap-2 justify-between">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${SEVERITY_CLASS[n.severity]}`}>
                      {n.severity.charAt(0).toUpperCase() + n.severity.slice(1)}
                    </span>
                    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-border bg-surface text-muted font-medium">
                      {TYPE_LABEL[n.type]}
                    </span>
                    {!n.isRead && (
                      <span className="inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] border border-primary/40 bg-primary/10 text-primary font-medium">
                        New
                      </span>
                    )}
                  </div>
                  {!n.isRead && onMarkRead && (
                    <button
                      type="button"
                      className="text-xs text-muted hover:text-foreground transition-colors"
                      onClick={() => onMarkRead(n.id)}
                      aria-label={`Mark notification "${n.title}" as read`}
                    >
                      Mark read
                    </button>
                  )}
                </div>
                <p className="text-sm font-medium text-foreground">{n.title}</p>
                <p className="text-xs text-muted">{n.message}</p>
                <p className="text-[10px] text-muted">{new Date(n.createdAt).toLocaleString()}</p>
              </div>
            ))}
          </div>
        )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
