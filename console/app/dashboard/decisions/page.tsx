'use client';

import { useCallback, useEffect, useState } from 'react';
import { DecisionsTable } from '@/components/tables/DecisionsTable';
import { getDecision, listDecisionsWithMeta, type ApiMeta, type DecisionOut } from '@/lib/coreApi';
import { toErrorDisplay } from '@/lib/errors';

const PAGE_SIZE = 10;

export default function DecisionsPage() {
  const [items, setItems] = useState<DecisionOut[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [eventType, setEventType] = useState('');
  const [threatLevel, setThreatLevel] = useState('');
  const [decisionType, setDecisionType] = useState('');
  const [severity, setSeverity] = useState('');
  const [search, setSearch] = useState('');
  const [detail, setDetail] = useState<DecisionOut | null>(null);
  const [meta, setMeta] = useState<ApiMeta | null>(null);
  const [error, setError] = useState<{ message: string; code: string; requestId: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const page = await listDecisionsWithMeta({ limit: PAGE_SIZE, offset, event_type: eventType, threat_level: threatLevel, decision_type: decisionType, severity, search });
      setItems(page.data.items || []);
      setTotal(page.data.total || 0);
      setMeta(page.meta);
    } catch (e) {
      setError(toErrorDisplay(e));
    }
  }, [decisionType, eventType, offset, search, severity, threatLevel]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <h2>Decisions</h2>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <input value={eventType} onChange={(e) => setEventType(e.target.value)} placeholder="event_type" />
        <input value={threatLevel} onChange={(e) => setThreatLevel(e.target.value)} placeholder="threat_level" />
        <input value={decisionType} onChange={(e) => setDecisionType(e.target.value)} placeholder="decision_type" />
        <input value={severity} onChange={(e) => setSeverity(e.target.value)} placeholder="severity" />
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="search id/event_id" />
        <button onClick={() => { setOffset(0); load(); }}>Apply Filters</button>
      </div>
      {error ? <p>{error.message} ({error.code}) request_id={error.requestId}</p> : null}
      {meta ? <small style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '0.2rem 0.4rem', width: 'fit-content' }}>debug request_id={meta.requestId || 'n/a'} idempotent-replay={meta.idempotentReplay || 'none'}</small> : null}
      <DecisionsTable decisions={items} onSelect={async (id) => {
        try {
          setDetail(await getDecision(id));
        } catch (e) {
          setError(toErrorDisplay(e));
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
