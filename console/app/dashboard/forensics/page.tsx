'use client';

import { useState } from 'react';
import { getChainVerify, getForensicsAuditTrail, getForensicsSnapshot } from '@/lib/coreApi';
import { toUserMessage } from '@/lib/errors';

export default function ForensicsPage() {
  const [eventId, setEventId] = useState('');
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState('');

  async function run(kind: 'snapshot' | 'audit' | 'chain') {
    try {
      setError('');
      if (kind === 'snapshot') setResult(await getForensicsSnapshot(eventId));
      if (kind === 'audit') setResult(await getForensicsAuditTrail(eventId));
      if (kind === 'chain') setResult(await getChainVerify());
    } catch (e) {
      const msg = toUserMessage(e);
      setError(msg.includes('Not found or forbidden') ? 'Not found or forbidden for current tenant context.' : msg);
    }
  }

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <h2>Forensics</h2>
      <input value={eventId} onChange={(e) => setEventId(e.target.value)} placeholder="event_id" />
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button disabled={!eventId} onClick={() => run('snapshot')}>Snapshot</button>
        <button disabled={!eventId} onClick={() => run('audit')}>Audit trail</button>
        <button onClick={() => run('chain')}>Chain verify</button>
      </div>
      {error ? <p>{error}</p> : null}
      <pre style={{ whiteSpace: 'pre-wrap' }}>{result ? JSON.stringify(result, null, 2) : 'No data yet.'}</pre>
    </div>
  );
}
