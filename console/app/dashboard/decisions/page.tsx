'use client';

import { useCallback, useEffect, useState } from 'react';
import { DecisionsTable } from '@/components/tables/DecisionsTable';
import { getDecision, listDecisions, type DecisionOut } from '@/lib/coreApi';
import { toUserMessage } from '@/lib/errors';

const PAGE_SIZE = 10;

export default function DecisionsPage() {
  const [items, setItems] = useState<DecisionOut[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);

  // Draft inputs (what the user is typing)
  const [eventType, setEventType] = useState('');
  const [threatLevel, setThreatLevel] = useState('');

  // Applied filters (what the query actually uses)
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

  useEffect(() => {
    void load();
  }, [load]);

  const applyFilters = useCallback(() => {
    setAppliedEventType(eventType.trim());
    setAppliedThreatLevel(threatLevel.trim());
    setOffset(0); // triggers reload via useEffect/load dependency
    setDetail(null);
  }, [eventType, threatLevel]);

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <h2>Decisions</h2>

      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <input
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          placeholder="event_type"
        />
        <input
          value={threatLevel}
          onChange={(e) => setThreatLevel(e.target.value)}
          placeholder="threat_level"
        />
        <button onClick={applyFilters}>Apply Filters</button>
      </div>

      {error ? <p>{error}</p> : null}

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

      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button disabled={offset === 0} onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}>
          Previous
        </button>
        <button disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
          Next
        </button>
        <span>
          offset={offset} total={total}
        </span>
      </div>

      {detail ? (
        <section style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '1rem' }}>
          <h3>Decision detail</h3>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(detail, null, 2)}</pre>
        </section>
      ) : null}
    </div>
  );
}
