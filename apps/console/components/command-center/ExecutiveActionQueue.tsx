'use client';

import Link from 'next/link';
import { AlertCircle, ArrowRight, CheckCircle2, Clock, HelpCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WidgetShell from './WidgetShell';
import type { DecisionOut } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-GOVERNANCE
const MCIM_ID = 'MCIM-18.6-GOVERNANCE';
const AUTHORITY = 'Governance Authority';
const sourceOfTruth = '/api/core/decisions';
const drillDown = '/dashboard/decisions';

export type ActionType =
  | 'approve-policy'
  | 'review-findings'
  | 'review-report'
  | 'rotate-keys'
  | 'verify-assessment'
  | 'review-remediation';

export interface ActionItem {
  id: string;
  type: ActionType;
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  authority: string;
  owner: string | null;
  deadline: string | null;
  impact: string;
  estimatedEffort: string;
  href: string;
}

function priorityToVariant(
  p: ActionItem['priority'],
): 'critical' | 'high' | 'warning' | 'default' {
  if (p === 'critical') return 'critical';
  if (p === 'high') return 'high';
  if (p === 'medium') return 'warning';
  return 'default';
}

function actionTypeToLabel(type: ActionType): string {
  const map: Record<ActionType, string> = {
    'approve-policy': 'Approve Policy',
    'review-findings': 'Review Findings',
    'review-report': 'Review Report',
    'rotate-keys': 'Rotate Keys',
    'verify-assessment': 'Verify Assessment',
    'review-remediation': 'Review Remediation',
  };
  return map[type];
}

function decisionsToActions(decisions: DecisionOut[]): ActionItem[] {
  return decisions.slice(0, 5).map((d) => ({
    id: d.id,
    type: d.event_type?.includes('policy')
      ? 'approve-policy'
      : d.event_type?.includes('finding')
        ? 'review-findings'
        : 'review-remediation',
    priority:
      d.threat_level === 'critical'
        ? 'critical'
        : d.threat_level === 'high'
          ? 'high'
          : d.threat_level === 'medium'
            ? 'medium'
            : 'low',
    title: d.explain_summary ?? d.event_type ?? `Decision ${d.id.slice(0, 8)}`,
    authority: AUTHORITY,
    owner: null,
    deadline: null,
    impact: d.threat_level ?? 'unknown',
    estimatedEffort: 'Varies',
    href: `/dashboard/decisions`,
  }));
}

interface ExecutiveActionQueueProps {
  decisions: DecisionOut[];
  extraActions?: ActionItem[];
  loading?: boolean;
  lastUpdated?: string;
}

export default function ExecutiveActionQueue({
  decisions,
  extraActions = [],
  loading = false,
  lastUpdated,
}: ExecutiveActionQueueProps) {
  const derivedActions = decisionsToActions(decisions);
  const allActions = [...derivedActions, ...extraActions].slice(0, 8);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Executive Action Queue"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Action Queue"
    >
      <div aria-label="executive-action-queue">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-14 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : allActions.length === 0 ? (
          <div
            className="py-6 text-center text-sm text-muted"
            data-testid="action-queue-empty"
            aria-label="action-queue-empty"
          >
            <CheckCircle2 className="mx-auto mb-2 h-6 w-6 text-success" aria-hidden="true" />
            <p>No pending actions.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <ul className="space-y-2" role="list">
            {allActions.map((action) => (
              <li
                key={action.id}
                data-testid={`action-${action.id}`}
                className="rounded-md border border-border p-3"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant={priorityToVariant(action.priority)} className="text-[10px]">
                        {action.priority.toUpperCase()}
                      </Badge>
                      <span className="text-[10px] text-muted">{actionTypeToLabel(action.type)}</span>
                    </div>
                    <p className="mt-1 text-sm font-medium text-foreground truncate">{action.title}</p>
                    <div className="mt-1 flex items-center gap-3 text-[10px] text-muted flex-wrap">
                      {action.owner && (
                        <span>Owner: {action.owner}</span>
                      )}
                      {action.deadline && (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" aria-hidden="true" />
                          {action.deadline}
                        </span>
                      )}
                      <span>Impact: {action.impact}</span>
                      <span>Effort: {action.estimatedEffort}</span>
                    </div>
                  </div>
                  <Link
                    href={action.href}
                    className="shrink-0 text-primary hover:text-primary/80"
                    aria-label={`Go to ${action.title}`}
                  >
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </Link>
                </div>
              </li>
            ))}
          </ul>
        )}

        {!loading && allActions.length > 0 && (
          <div className="mt-3 text-right">
            <Link
              href={drillDown}
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
            >
              View all decisions <ArrowRight className="h-3 w-3" aria-hidden="true" />
            </Link>
          </div>
        )}
      </div>
    </WidgetShell>
  );
}
