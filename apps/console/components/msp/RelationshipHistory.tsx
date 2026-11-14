'use client';

import { useEffect, useState } from 'react';
import { getRelationshipHistory, type RelationshipHistory as History } from '@/lib/mspApi';
import { capabilityLabel, safeErrorMessage } from '@/lib/mspConsole';

const OPERATION_LABELS: Record<string, string> = {
  'relationship.propose': 'Access requested by the MSP',
  'relationship.approve': 'Approved by the customer',
  'relationship.suspend': 'Suspended by the customer',
  'relationship.resume': 'Resumed by the customer',
  'relationship.revoke.customer': 'Revoked by the customer',
  'relationship.revoke.msp': 'Ended by the MSP',
  'context.resolve': 'MSP opened this customer',
  'portfolio.summary': 'MSP viewed portfolio summaries',
};

const PARTY_LABELS: Record<string, string> = {
  customer: 'Customer',
  msp: 'MSP',
  platform: 'FrostGate platform',
};

/** Events for one relationship, read from the viewer's own audit chain. */
export function RelationshipHistory({ relationshipId }: { relationshipId: string }) {
  const [history, setHistory] = useState<History | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    getRelationshipHistory(relationshipId).then((res) => {
      if (cancelled) return;
      if (res.ok) setHistory(res.data);
      else setError(safeErrorMessage(res));
    });
    return () => {
      cancelled = true;
    };
  }, [relationshipId]);

  if (error) {
    return (
      <p role="alert" className="text-xs text-danger">
        {error}
      </p>
    );
  }
  if (!history) {
    return (
      <p aria-live="polite" className="text-xs text-muted">
        Loading history…
      </p>
    );
  }
  return (
    <div className="space-y-2" data-testid="msp-relationship-history">
      <p className="text-xs text-muted">
        Audit chain:{' '}
        <span className={history.chain_verified ? 'text-success' : 'text-danger'}>
          {history.chain_verified ? 'verified intact' : 'verification failed — contact support'}
        </span>
      </p>
      {history.items.length === 0 ? (
        <p className="text-xs text-muted">No recorded events.</p>
      ) : (
        <ol className="space-y-1 text-xs">
          {history.items.map((ev) => (
            <li key={ev.event_hash} className="flex flex-wrap gap-x-2">
              <time dateTime={ev.occurred_at ?? undefined} className="text-muted">
                {ev.occurred_at ? new Date(ev.occurred_at).toLocaleString() : 'Unknown time'}
              </time>
              <span className="font-medium text-foreground">
                {OPERATION_LABELS[ev.operation] ?? 'Recorded event'}
              </span>
              <span className="text-muted">by {PARTY_LABELS[ev.actor_party] ?? 'Unknown party'}</span>
              {ev.capabilities.length > 0 ? (
                <span className="text-muted">({ev.capabilities.map(capabilityLabel).join(', ')})</span>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
