'use client';
import Link from 'next/link';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-DASHBOARD';
const AUTHORITY = 'Customer Dashboard Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/dashboard';
const customerSafe = true;

export interface DashboardCard {
  id: string;
  title: string;
  status: string;
  value: string | number | null;
  lastUpdated: string | null;
  confidence: number | null;
  drillDown: string;
  authority: string;
}

interface Props {
  cards: DashboardCard[];
  engagementId: string | null;
  loading: boolean;
  lastUpdated?: string;
}

const STATUS_CLASS: Record<string, string> = {
  active: 'border-green-500/40 bg-green-500/10 text-green-300',
  completed: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  draft: 'border-border bg-surface-2 text-muted',
  pending: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  error: 'border-red-500/40 bg-red-500/10 text-red-300',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? STATUS_CLASS.draft;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, ' ')}
    </span>
  );
}

export default function CustomerDashboard({ cards, engagementId, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Dashboard"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Dashboard"
      lastUpdated={lastUpdated}
    >
      <section aria-label="customer-dashboard" data-testid="customer-dashboard">
      {loading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3" aria-busy="true">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && !engagementId && (
        <p className="text-sm text-muted text-center py-8">
          No engagement selected. Select an engagement to view dashboard.
        </p>
      )}

      {!loading && engagementId && cards.length === 0 && (
        <p className="text-sm text-muted text-center py-8">No dashboard data available.</p>
      )}

      {!loading && cards.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {cards.map((card) => (
            <div
              key={card.id}
              className="rounded border border-border bg-surface-2 p-3 space-y-2"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-muted">{card.title}</span>
                <StatusBadge status={card.status} />
              </div>
              <div className="text-2xl font-semibold text-foreground">
                {card.value ?? '—'}
              </div>
              <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] text-muted">
                <span>{card.authority}</span>
                {card.confidence != null && (
                  <span>{Math.round(card.confidence * 100)}% confidence</span>
                )}
              </div>
              {card.lastUpdated && (
                <p className="text-[10px] text-muted">
                  Updated: {new Date(card.lastUpdated).toLocaleString()}
                </p>
              )}
              <Link
                href={card.drillDown}
                className="block text-xs text-primary hover:underline transition-colors"
              >
                View details →
              </Link>
            </div>
          ))}
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
