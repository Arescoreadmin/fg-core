'use client';

import { AlertCircle, Bell, CheckCircle2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WidgetShell from './WidgetShell';
import type { FeedItem } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Control Tower Authority';
const sourceOfTruth = '/api/core/feed/live';
const drillDown = '/dashboard/forensics';

type NotifCategory =
  | 'critical'
  | 'approval'
  | 'risk'
  | 'compliance'
  | 'trust'
  | 'operational'
  | 'customer';

interface Notification {
  id: string;
  category: NotifCategory;
  title: string;
  timestamp: string | null;
  severity: string | null;
  actionable: boolean;
}

function categorize(item: FeedItem): NotifCategory {
  const et = (item.event_type ?? '').toLowerCase();
  const sev = (item.severity ?? '').toLowerCase();
  const action = (item.action_taken ?? '').toLowerCase();

  if (sev === 'critical' || action === 'blocked') return 'critical';
  if (et.includes('approval') || et.includes('policy')) return 'approval';
  if (et.includes('risk') || sev === 'high') return 'risk';
  if (et.includes('compliance') || et.includes('audit')) return 'compliance';
  if (et.includes('trust') || et.includes('chain') || et.includes('verify')) return 'trust';
  if (et.includes('customer') || et.includes('portal')) return 'customer';
  return 'operational';
}

function isActionable(item: FeedItem): boolean {
  const sev = (item.severity ?? '').toLowerCase();
  const action = (item.action_taken ?? '').toLowerCase();
  return sev === 'critical' || sev === 'high' || action === 'blocked' || action === 'block';
}

function buildNotifications(items: FeedItem[]): Notification[] {
  return items
    .map((item) => ({
      id: String(item.id),
      category: categorize(item),
      title: item.title ?? item.event_type ?? `Event ${item.id}`,
      timestamp: item.timestamp ?? null,
      severity: item.severity ?? null,
      actionable: isActionable(item),
    }))
    .filter((n) => n.actionable);
}

const CATEGORY_CONFIG: Record<
  NotifCategory,
  { id: string; label: string; variant: 'critical' | 'secondary' | 'outline' | 'default' }
> = {
  critical: { id: 'notif-critical', label: 'Critical', variant: 'critical' },
  approval: { id: 'notif-approval', label: 'Approval', variant: 'secondary' },
  risk: { id: 'notif-risk', label: 'Risk', variant: 'secondary' },
  compliance: { id: 'notif-compliance', label: 'Compliance', variant: 'outline' },
  trust: { id: 'notif-trust', label: 'Trust', variant: 'outline' },
  operational: { id: 'notif-operational', label: 'Operational', variant: 'default' },
  customer: { id: 'notif-customer', label: 'Customer', variant: 'default' },
};

function relativeTime(ts: string | null): string {
  if (!ts) return '';
  try {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch {
    return '';
  }
}

interface ExecutiveNotificationsProps {
  feedItems: FeedItem[];
  loading?: boolean;
  lastUpdated?: string;
}

export default function ExecutiveNotifications({
  feedItems,
  loading = false,
  lastUpdated,
}: ExecutiveNotificationsProps) {
  const notifications = loading ? [] : buildNotifications(feedItems);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Executive Notifications"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Notifications"
    >
      <div aria-label="executive-notifications">
        <p
          className="text-[10px] uppercase tracking-wide text-muted mb-2"
          data-testid="notifications-authority"
          aria-label="notifications-authority"
        >
          Authority: {AUTHORITY}
        </p>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : notifications.length === 0 ? (
          <div
            className="py-6 text-center text-sm text-muted"
            data-testid="notifications-clear"
            aria-label="notifications-clear"
          >
            <CheckCircle2 className="mx-auto mb-2 h-6 w-6 text-success" aria-hidden="true" />
            <p>No actionable notifications.</p>
            <p className="mt-1 text-[10px]">All items are below actionable threshold.</p>
          </div>
        ) : (
          <ul className="space-y-1.5" role="list">
            {notifications.map((n) => {
              const config = CATEGORY_CONFIG[n.category];
              return (
                <li
                  key={n.id}
                  className="flex items-start gap-2 border-b border-border py-2 last:border-0"
                  data-testid={config.id}
                  aria-label={config.id}
                >
                  <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-danger" aria-hidden="true" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <Badge variant={config.variant} className="text-[9px]">
                        {config.label}
                      </Badge>
                      {n.severity && (
                        <span className="text-[10px] text-muted">{n.severity}</span>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-foreground truncate">{n.title}</p>
                  </div>
                  <span className="shrink-0 text-[10px] text-muted/60">
                    {relativeTime(n.timestamp)}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </WidgetShell>
  );
}
