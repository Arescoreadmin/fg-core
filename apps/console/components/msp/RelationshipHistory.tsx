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
  'assessment_grant.request': 'Assessment requested by the MSP',
  'assessment_grant.approve': 'Assessment request approved by the customer',
  'assessment_grant.reject': 'Assessment request declined by the customer',
  'assessment_grant.withdraw': 'Assessment request withdrawn by the MSP',
  'assessment_grant.revoke': 'Assessment authority revoked by the customer',
  'assessment.initiate': 'Assessment started by the MSP',
  'report_share.request': 'Report requested by the MSP',
  'report_share.approve': 'Report shared by the customer',
  'report_share.reject': 'Report request declined by the customer',
  'report_share.withdraw': 'Report request withdrawn by the MSP',
  'report_share.revoke': 'Report access revoked by the customer',
  'report_share.expire': 'Expired report share retired by the customer',
  'report.verify': 'Shared report verified by the MSP',
  'report.download': 'Shared report downloaded by the MSP',
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
  const [loadingMore, setLoadingMore] = useState(false);

  // Older events are fetched page by page from the server's next_offset, so
  // a long-lived relationship's earliest records stay reachable.
  const loadOlder = async () => {
    if (!history || history.next_offset === null || loadingMore) return;
    setLoadingMore(true);
    const res = await getRelationshipHistory(relationshipId, history.next_offset);
    setLoadingMore(false);
    if (!res.ok) {
      setError(safeErrorMessage(res));
      return;
    }
    // New events shift offsets between pages; drop any event already shown.
    const seen = new Set(history.items.map((ev) => ev.event_hash));
    setHistory({
      ...res.data,
      items: [...history.items, ...res.data.items.filter((ev) => !seen.has(ev.event_hash))],
    });
  };

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
      {history.next_offset !== null ? (
        <button
          type="button"
          className="text-xs font-medium text-primary underline disabled:opacity-50"
          disabled={loadingMore}
          onClick={() => void loadOlder()}
        >
          {loadingMore ? 'Loading…' : `Show older events (${history.items.length} of ${history.total})`}
        </button>
      ) : null}
    </div>
  );
}
