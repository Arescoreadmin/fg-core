'use client';

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-DELEGATION-PANEL';
const AUTHORITY = 'Delegation Authority';
const sourceOfTruth = '/api/core/decisions';
const drillDown = '/dashboard/decisions';

export type DelegationActionType =
  | 'approve'
  | 'reject'
  | 'assign'
  | 'delegate'
  | 'escalate'
  | 'review'
  | 'verify'
  | 'generate-report'
  | 'publish'
  | 'archive'
  | 'close';

export interface DelegationAction {
  id: string;
  actionType: DelegationActionType;
  title: string;
  authority: string;
  mcimId: string;
  sourceObject: string;
  drillDown: string;
  delegatedTo: string | null;
}

interface DelegationPanelProps {
  actions: DelegationAction[];
  onDelegate?: (action: DelegationAction, target: string) => void;
  loading?: boolean;
}

const ACTION_BADGE_VARIANT: Record<
  DelegationActionType,
  'default' | 'secondary' | 'success' | 'warning' | 'danger' | 'outline'
> = {
  approve: 'success',
  reject: 'danger',
  assign: 'default',
  delegate: 'default',
  escalate: 'warning',
  review: 'secondary',
  verify: 'success',
  'generate-report': 'secondary',
  publish: 'default',
  archive: 'outline',
  close: 'outline',
};

function ActionRow({
  action,
  onDelegate,
}: {
  action: DelegationAction;
  onDelegate?: (action: DelegationAction, target: string) => void;
}) {
  const [target, setTarget] = useState(action.delegatedTo ?? '');
  const [submitted, setSubmitted] = useState(false);

  const handleDelegate = () => {
    if (!target.trim()) return;
    onDelegate?.(action, target.trim());
    setSubmitted(true);
  };

  return (
    <li className="rounded border border-border bg-surface-2 px-3 py-2 text-xs space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 flex-wrap">
            <Badge
              variant={ACTION_BADGE_VARIANT[action.actionType]}
              className="text-[10px] shrink-0"
            >
              {action.actionType}
            </Badge>
            <Link
              href={action.drillDown}
              className="font-medium text-foreground hover:underline truncate"
            >
              {action.title}
            </Link>
          </div>
          <div className="mt-1 flex flex-wrap gap-x-3 text-[10px] text-muted">
            <span>Authority: {action.authority}</span>
            <span className="font-mono">MCIM: {action.mcimId}</span>
            <span>Source: {action.sourceObject}</span>
          </div>
          {action.delegatedTo && !submitted && (
            <div className="mt-1 text-[10px] text-muted">
              Currently delegated to:{' '}
              <span className="font-semibold text-foreground">{action.delegatedTo}</span>
            </div>
          )}
        </div>
      </div>

      {submitted ? (
        <p className="text-[10px] text-success">
          Delegated to <span className="font-semibold">{target}</span> — pending authority
          confirmation.
        </p>
      ) : (
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Delegate to authority or owner…"
            aria-label={`Delegate target for ${action.title}`}
            className="flex-1 rounded border border-border bg-surface px-2 py-1 text-xs text-foreground placeholder:text-muted outline-none focus:ring-1 focus:ring-primary"
          />
          <Button
            variant="outline"
            size="sm"
            className="h-7 px-2 text-xs shrink-0"
            onClick={handleDelegate}
            disabled={!target.trim()}
          >
            Delegate
          </Button>
        </div>
      )}
    </li>
  );
}

export default function DelegationPanel({
  actions,
  onDelegate,
  loading,
}: DelegationPanelProps) {
  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Delegation Panel"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      title="Delegation Panel"
      delegationSupported
    >
      <section aria-label="delegation-panel">
        {loading && (
          <div className="space-y-2" aria-label="Loading delegation actions">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-16 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && actions.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No pending delegation actions.</p>
        )}

        {!loading && actions.length > 0 && (
          <ul className="space-y-2" aria-label="Delegation actions">
            {actions.map((action) => (
              <ActionRow key={action.id} action={action} onDelegate={onDelegate} />
            ))}
          </ul>
        )}
      </section>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
