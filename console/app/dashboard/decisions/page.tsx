'use client';

import { useEffect, useState } from 'react';
import { DecisionsTable } from '@/components/tables/DecisionsTable';
import { getDecision, listDecisions, type DecisionOut } from '@/lib/coreApi';
import { toUserMessage } from '@/lib/errors';

const PAGE_SIZE = 10;

export default function DecisionsPage() {
  const [items, setItems] = useState<DecisionOut[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [eventType, setEventType] = useState('');
  const [threatLevel, setThreatLevel] = useState('');
  const [detail, setDetail] = useState<DecisionOut | null>(null);
  const [error, setError] = useState('');

  async function load() {
    try {
      setError('');
      const page = await listDecisions({ limit: PAGE_SIZE, offset, event_type: eventType, threat_level: threatLevel });
      setItems(page.items || []);
      setTotal(page.total || 0);
    } catch (e) {
      setError(toUserMessage(e));
    }
  }

  useEffect(() => {
    load();
  }, [offset]);

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <h2>Decisions</h2>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <input value={eventType} onChange={(e) => setEventType(e.target.value)} placeholder="event_type" />
        <input value={threatLevel} onChange={(e) => setThreatLevel(e.target.value)} placeholder="threat_level" />
        <button onClick={() => { setOffset(0); load(); }}>Apply Filters</button>
      </div>
      {error ? <p>{error}</p> : null}
      <DecisionsTable decisions={items} onSelect={async (id) => {
        try {
          setDetail(await getDecision(id));
        } catch (e) {
          setError(toUserMessage(e));
        }
      }} />
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button disabled={offset === 0} onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}>Previous</button>
        <button disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</button>
        <span>offset={offset} total={total}</span>
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
