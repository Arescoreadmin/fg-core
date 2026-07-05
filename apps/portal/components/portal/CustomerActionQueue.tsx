'use client';
import Link from 'next/link';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-ACTIONS';
const AUTHORITY = 'Customer Action Queue Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/actions';
const customerSafe = true;

export type ActionType =
  | 'review-report' | 'acknowledge-finding' | 'submit-attestation'
  | 'respond-remediation' | 'upload-evidence' | 'review-trust-verification'
  | 'accept-delivery' | 'request-clarification';

export type ActionPriority = 'critical' | 'high' | 'medium' | 'low';

export interface CustomerAction {
  id: string;
  actionType: ActionType;
  label: string;
  description: string;
  priority: ActionPriority;
  dueDate: string | null;
  owner: string | null;
  sourceAuthority: string;
  linkedEntityId: string | null;
  linkedEntityType: string | null;
  actionRoute: string;
}

interface Props {
  actions: CustomerAction[];
  loading: boolean;
  lastUpdated?: string;
}

const PRIORITY_ORDER: Record<ActionPriority, number> = {
  critical: 0, high: 1, medium: 2, low: 3,
};

const PRIORITY_CLASS: Record<ActionPriority, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
};

function PriorityBadge({ priority }: { priority: ActionPriority }) {
  const cls: Record<string, string> = {
    critical: 'border-red-500/40 bg-red-500/10 text-red-300',
    high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
    low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
    info: 'border-border bg-surface-2 text-muted',
  };
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls[priority] ?? cls.info}`}>
      {priority.charAt(0).toUpperCase() + priority.slice(1)}
    </span>
  );
}

export default function CustomerActionQueue({ actions, loading, lastUpdated }: Props) {
  const sorted = [...actions].sort((a, b) => {
    const pd = (PRIORITY_ORDER[a.priority] ?? 9) - (PRIORITY_ORDER[b.priority] ?? 9);
    if (pd !== 0) return pd;
    if (!a.dueDate && !b.dueDate) return 0;
    if (!a.dueDate) return 1;
    if (!b.dueDate) return -1;
    return new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime();
  });

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Action Queue"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Action Queue"
      lastUpdated={lastUpdated}
    >
      <section aria-label="customer-action-queue" data-testid="customer-action-queue">
      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && sorted.length === 0 && (
        <p className="text-sm text-muted text-center py-8">
          No actions required at this time.
        </p>
      )}

      {!loading && sorted.length > 0 && (
        <div className="space-y-3">
          {sorted.map((action) => (
            <div
              key={action.id}
              className="rounded border border-border bg-surface-2 p-3 space-y-2"
            >
              <div className="flex flex-wrap items-center gap-2">
                <PriorityBadge priority={action.priority} />
                <span className="text-sm font-medium text-foreground">{action.label}</span>
              </div>
              <p className="text-xs text-muted">{action.description}</p>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
                {action.dueDate && (
                  <span>Due: {new Date(action.dueDate).toLocaleDateString()}</span>
                )}
                {action.owner && <span>Owner: {action.owner}</span>}
                <span className="text-[11px]">{action.sourceAuthority}</span>
              </div>
              <Link
                href={action.actionRoute}
                className="inline-flex items-center rounded border border-primary/30 bg-primary/5 px-2.5 py-1 text-xs text-primary hover:bg-primary/10 transition-colors"
              >
                Go to action →
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
