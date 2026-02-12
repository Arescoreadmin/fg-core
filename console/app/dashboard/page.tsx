'use client';

import { useEffect, useState } from 'react';

type BlockState = { data?: unknown; error?: { message: string; code: string; requestId: string } };

async function fetchBlock(path: string): Promise<BlockState> {
  try {
    const response = await fetch(`/api/core${path}`, { cache: 'no-store' });
    const requestId = response.headers.get('x-request-id') || 'n/a';
    const text = await response.text();
    const payload = text ? JSON.parse(text) : {};
    if (!response.ok) {
      return {
        error: {
          message: response.status >= 500 ? 'Core unreachable' : 'Request failed',
          code: `HTTP_${response.status}`,
          requestId,
        },
      };
    }
    return { data: payload };
  } catch {
    return { error: { message: 'Core unreachable', code: 'CORE_UNREACHABLE', requestId: 'n/a' } };
  }
}

export default function DashboardOverviewPage() {
  const [live, setLive] = useState<BlockState>({});
  const [ready, setReady] = useState<BlockState>({});
  const [stats, setStats] = useState<BlockState>({});
  const [feed, setFeed] = useState<BlockState>({});

  useEffect(() => {
    fetchBlock('/health/live').then(setLive);
    fetchBlock('/health/ready').then(setReady);
    fetchBlock('/stats/summary').then(setStats);
    fetchBlock('/feed/live?limit=1').then(setFeed);
  }, []);

  const card = (title: string, state: BlockState) => (
    <section style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '1rem' }}>
      <h3>{title}</h3>
      {state.error ? <p>{state.error.message} ({state.error.code}) request_id={state.error.requestId}</p> : <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(state.data ?? {}, null, 2)}</pre>}
    </section>
  );

  return (
    <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))' }}>
      {card('Core Health: live', live)}
      {card('Core Health: ready', ready)}
      {card('Summary stats', stats)}
      {card('Latest feed event', feed)}
    </div>
  );
}
