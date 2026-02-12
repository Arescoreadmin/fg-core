'use client';

import { useEffect, useState } from 'react';
import { getChainVerify, getFeedLive, getHealthLive, getHealthReady, getStatsSummary } from '@/lib/coreApi';
import { toUserMessage } from '@/lib/errors';

export default function DashboardOverviewPage() {
  const [data, setData] = useState<Record<string, unknown>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    async function load() {
      const tasks: Array<[string, () => Promise<unknown>]> = [
        ['live', () => getHealthLive()],
        ['ready', () => getHealthReady()],
        ['stats', () => getStatsSummary()],
        ['chain', () => getChainVerify()],
        ['feed', () => getFeedLive(1)],
      ];
      const nextData: Record<string, unknown> = {};
      const nextErrors: Record<string, string> = {};
      for (const [key, fn] of tasks) {
        try {
          nextData[key] = await fn();
        } catch (error) {
          nextErrors[key] = toUserMessage(error);
        }
      }
      setData(nextData);
      setErrors(nextErrors);
    }
    load();
  }, []);

  const card = (title: string, key: string) => (
    <section style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '1rem' }}>
      <h3>{title}</h3>
      {errors[key] ? <p>{errors[key]}</p> : <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(data[key] ?? {}, null, 2)}</pre>}
    </section>
  );

  return (
    <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))' }}>
      {card('System Health (live/ready)', 'live')}
      {card('Stats Summary', 'stats')}
      {card('Chain Verify', 'chain')}
      {card('Latest Feed Event', 'feed')}
    </div>
  );
}
