'use client';
import Link from 'next/link';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-NOTIFICATIONS';
const AUTHORITY = 'Customer Notifications Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/notifications';
const customerSafe = true;

export type NotificationCategory =
  | 'report-ready' | 'remediation-due' | 'attestation-required'
  | 'trust-verification-update' | 'finding-updated' | 'evidence-requested'
  | 'delivery-milestone';

export interface PortalNotification {
  id: string;
  category: NotificationCategory;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  actionRoute: string | null;
}

interface Props {
  notifications: PortalNotification[];
  loading: boolean;
  lastUpdated?: string;
}

const CATEGORY_CLASS: Record<NotificationCategory, string> = {
  'report-ready': 'border-green-500/40 bg-green-500/10 text-green-300',
  'remediation-due': 'border-red-500/40 bg-red-500/10 text-red-300',
  'attestation-required': 'border-purple-500/40 bg-purple-500/10 text-purple-300',
  'trust-verification-update': 'border-teal-500/40 bg-teal-500/10 text-teal-300',
  'finding-updated': 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  'evidence-requested': 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  'delivery-milestone': 'border-primary/40 bg-primary/10 text-primary',
};

const CATEGORY_LABEL: Record<NotificationCategory, string> = {
  'report-ready': 'Report Ready',
  'remediation-due': 'Remediation Due',
  'attestation-required': 'Attestation Required',
  'trust-verification-update': 'Trust Verification',
  'finding-updated': 'Finding Updated',
  'evidence-requested': 'Evidence Requested',
  'delivery-milestone': 'Delivery Milestone',
};

function CategoryBadge({ category }: { category: NotificationCategory }) {
  const cls = CATEGORY_CLASS[category];
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {CATEGORY_LABEL[category]}
    </span>
  );
}

export default function CustomerNotifications({ notifications, loading, lastUpdated }: Props) {
  const sorted = [...notifications].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Notifications"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Notifications"
      lastUpdated={lastUpdated}
    >
      <p className="text-[11px] text-muted mb-3">
        Internal operator alerts are not shown in this view.
      </p>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && sorted.length === 0 && (
        <p className="text-sm text-muted text-center py-8">
          No portal notifications at this time.
        </p>
      )}

      {!loading && sorted.length > 0 && (
        <div className="space-y-2">
          {sorted.map((n) => (
            <div
              key={n.id}
              className={`rounded border bg-surface-2 p-3 space-y-1.5 ${
                !n.read ? 'border-primary/30 border-l-2' : 'border-border'
              }`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <CategoryBadge category={n.category} />
                <span className="text-sm font-medium text-foreground">{n.title}</span>
                <span className="ml-auto text-xs text-muted">
                  {new Date(n.timestamp).toLocaleString()}
                </span>
              </div>
              <p className="text-xs text-muted truncate">{n.message}</p>
              {n.actionRoute && (
                <Link
                  href={n.actionRoute}
                  className="text-xs text-primary hover:underline transition-colors"
                >
                  Go to →
                </Link>
              )}
            </div>
          ))}
        </div>
      )}
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
