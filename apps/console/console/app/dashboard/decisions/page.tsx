'use client';

import { useCallback, useEffect, useState } from 'react';
import { DecisionsTable } from '@/components/tables/DecisionsTable';
import { getDecision, listDecisions, type DecisionOut } from '@/lib/coreApi';
import { toUserMessage } from '@/lib/errors';
import { DecisionPanel } from '@/components/decisions/DecisionPanel';

const PAGE_SIZE = 10;

export default function DecisionsPage() {
  const [items, setItems] = useState<DecisionOut[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);

  const [eventType, setEventType] = useState('');
  const [threatLevel, setThreatLevel] = useState('');
  const [appliedEventType, setAppliedEventType] = useState('');
  const [appliedThreatLevel, setAppliedThreatLevel] = useState('');

  const [detail, setDetail] = useState<DecisionOut | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      setError('');
      const page = await listDecisions({
        limit: PAGE_SIZE,
        offset,
        event_type: appliedEventType,
        threat_level: appliedThreatLevel,
      });
      setItems(page.items || []);
      setTotal(page.total || 0);
    } catch (e) {
      setError(toUserMessage(e));
    }
  }, [offset, appliedEventType, appliedThreatLevel]);

  useEffect(() => { void load(); }, [load]);

  const applyFilters = useCallback(() => {
    setAppliedEventType(eventType.trim());
    setAppliedThreatLevel(threatLevel.trim());
    setOffset(0);
    setDetail(null);
  }, [eventType, threatLevel]);

  return (
    <div className="flex flex-col">
      <div className="border-b border-border px-6 py-4">
        <h1 className="text-base font-semibold text-foreground">Decisions</h1>
        <p className="text-xs text-muted mt-0.5">Policy outcomes for every classified request</p>
      </div>

      <div className="p-6 space-y-4">
        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          <input
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
            placeholder="Event type"
            className="rounded border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground placeholder:text-muted/50 focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <input
            value={threatLevel}
            onChange={(e) => setThreatLevel(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
            placeholder="Threat level"
            className="rounded border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground placeholder:text-muted/50 focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <button
            onClick={applyFilters}
            className="rounded bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
          >
            Filter
          </button>
        </div>

        {error && (
          <p className="rounded border border-danger/30 bg-danger/5 px-3 py-2 text-sm text-danger">{error}</p>
        )}

        <DecisionsTable
          decisions={items}
          onSelect={async (id) => {
            try {
              setError('');
              setDetail(await getDecision(id));
            } catch (e) {
              setError(toUserMessage(e));
            }
          }}
        />

        {/* Pagination */}
        <div className="flex items-center gap-3">
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}
            className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Previous
          </button>
          <span className="text-xs text-muted">
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <button
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
            className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Next
          </button>
        </div>

        {/* Decision detail */}
        {detail && <DecisionPanel decision={detail} />}
      </div>
    </div>
  );
}
