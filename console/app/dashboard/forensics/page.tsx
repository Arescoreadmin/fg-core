'use client';

import { useState } from 'react';
import { getChainVerifyWithMeta, getForensicsAuditTrailWithMeta, getForensicsSnapshotWithMeta } from '@/lib/coreApi';
import { toErrorDisplay } from '@/lib/errors';

export default function ForensicsPage() {
  const [eventId, setEventId] = useState('');
  const [result, setResult] = useState<unknown>(null);
  const [chainStatus, setChainStatus] = useState<'Verified' | 'Not Verified' | 'Error'>('Error');
  const [proof, setProof] = useState<{ requestId: string; timestamp: string; responseHash: string }>({ requestId: 'n/a', timestamp: 'n/a', responseHash: 'n/a' });
  const [error, setError] = useState<{ message: string; code: string; requestId: string } | null>(null);

  async function run(kind: 'snapshot' | 'audit' | 'chain') {
    try {
      setError(null);
      const response = kind === 'snapshot'
        ? await getForensicsSnapshotWithMeta(eventId)
        : kind === 'audit'
          ? await getForensicsAuditTrailWithMeta(eventId)
          : await getChainVerifyWithMeta();
      setResult(response.data);
      setProof({
        requestId: response.meta.requestId || 'n/a',
        timestamp: response.meta.receivedAt,
        responseHash: response.meta.responseHash || 'n/a',
      });
      if (kind === 'chain') {
        const verified = Boolean((response.data as { verified?: unknown }).verified ?? (response.data as { pass?: unknown }).pass);
        setChainStatus(verified ? 'Verified' : 'Not Verified');
      }
    } catch (e) {
      const err = toErrorDisplay(e);
      setError(err);
      if (kind === 'chain') setChainStatus('Error');
    }
  }

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <h2>Forensics</h2>
      <div style={{ border: '2px solid var(--border)', borderRadius: 8, padding: '0.8rem' }}>
        Chain Verify Status: <strong>{chainStatus}</strong>
      </div>
      <input value={eventId} onChange={(e) => setEventId(e.target.value)} placeholder="event_id" />
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button disabled={!eventId} onClick={() => run('snapshot')}>Snapshot</button>
        <button disabled={!eventId} onClick={() => run('audit')}>Audit trail</button>
        <button onClick={() => run('chain')}>Chain verify</button>
      </div>
      {error ? <p>{error.message} ({error.code}) request_id={error.requestId}</p> : null}
      <section style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '0.8rem' }}>
        <h4>Copy proof</h4>
        <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(proof, null, 2)}</pre>
      </section>
      <pre style={{ whiteSpace: 'pre-wrap' }}>{result ? JSON.stringify(result, null, 2) : 'No data yet.'}</pre>
    </div>
  );
}
