'use client';

/**
 * MSP-007 — one report share's history, including every read and every
 * refused read, from the viewer's own verified audit chain. It survives
 * revocation. The customer sees which partner account read its evidence;
 * the MSP never sees the customer's people.
 */

import { useEffect, useState } from 'react';
import { getShareHistory, type ShareHistory as History } from '@/lib/mspApi';
import { blockerLabel, safeReportingError, shortHash } from '@/lib/mspReporting';

const OPERATION_LABELS: Record<string, string> = {
  'report_share.request': 'Report requested by the MSP',
  'report_share.approve': 'Shared by the customer',
  'report_share.reject': 'Request declined by the customer',
  'report_share.withdraw': 'Request withdrawn by the MSP',
  'report_share.revoke': 'Access revoked by the customer',
  'report_share.expire': 'Expired share retired when the customer shared again',
  'report.verify': 'Verified by the MSP',
  'report.download': 'Downloaded by the MSP',
};

export function ShareHistory({ shareId }: { shareId: string }) {
  const [history, setHistory] = useState<History | null>(null);
  const [error, setError] = useState('');
  const [loadingMore, setLoadingMore] = useState(false);

  const loadOlder = async () => {
    if (!history || history.next_offset === null || loadingMore) return;
    setLoadingMore(true);
    const res = await getShareHistory(shareId, history.next_offset);
    setLoadingMore(false);
    if (!res.ok) {
      setError(safeReportingError(res));
      return;
    }
    const seen = new Set(history.items.map((ev) => ev.event_hash));
    setHistory({
      ...res.data,
      items: [...history.items, ...res.data.items.filter((ev) => !seen.has(ev.event_hash))],
    });
  };

  useEffect(() => {
    let cancelled = false;
    getShareHistory(shareId).then((res) => {
      if (cancelled) return;
      if (res.ok) setHistory(res.data);
      else setError(safeReportingError(res));
    });
    return () => {
      cancelled = true;
    };
  }, [shareId]);

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
    <div className="space-y-2" data-testid="msp-share-history">
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
                {ev.decision === 'denied' ? ' — refused' : ''}
              </span>
              {ev.actor_subject ? <span className="text-muted">({ev.actor_subject})</span> : null}
              {ev.report_version !== null ? (
                <span className="text-muted">
                  v{ev.report_version} · {shortHash(ev.manifest_hash)}
                </span>
              ) : null}
              {ev.blockers.length > 0 ? (
                <span className="text-muted">{ev.blockers.map(blockerLabel).join(' ')}</span>
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
