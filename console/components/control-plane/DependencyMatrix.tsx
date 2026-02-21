'use client';

/**
 * DependencyMatrix — Grid of modules vs dependency statuses.
 * Red/yellow/green indicators per cell.
 */

import React, { useCallback, useEffect, useState } from 'react';
import type { DepStatus, DependencyMatrixResponse } from '@/lib/controlPlaneApi';
import { getDependencyMatrix } from '@/lib/controlPlaneApi';

const STATUS_BG: Record<DepStatus | string, string> = {
  ok: '#166534',
  degraded: '#92400e',
  failed: '#7f1d1d',
  unknown: '#1e293b',
};

const STATUS_FG: Record<DepStatus | string, string> = {
  ok: '#86efac',
  degraded: '#fcd34d',
  failed: '#fca5a5',
  unknown: '#475569',
};

const STATUS_EMOJI: Record<DepStatus | string, string> = {
  ok: '●',
  degraded: '◐',
  failed: '●',
  unknown: '○',
};

function StatusCell({ status }: { status: string }) {
  const bg = STATUS_BG[status] ?? STATUS_BG.unknown;
  const fg = STATUS_FG[status] ?? STATUS_FG.unknown;
  const icon = STATUS_EMOJI[status] ?? '○';
  return (
    <td
      style={{
        padding: '6px 10px',
        background: bg,
        color: fg,
        textAlign: 'center',
        fontSize: '0.8rem',
        border: '1px solid #0f172a',
      }}
      title={status}
    >
      {icon}
    </td>
  );
}

export default function DependencyMatrix() {
  const [data, setData] = useState<DependencyMatrixResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    try {
      const resp = await getDependencyMatrix();
      setData(resp);
      setError(null);
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
    const interval = setInterval(fetch, 20_000);
    return () => clearInterval(interval);
  }, [fetch]);

  if (loading) return <div style={{ color: '#94a3b8', padding: 24 }}>Loading dependency matrix…</div>;
  if (error) return <div style={{ color: '#ef4444', padding: 24 }}>Error: {error}</div>;
  if (!data || data.matrix.length === 0) {
    return <div style={{ color: '#64748b', textAlign: 'center', padding: 32 }}>No modules to display.</div>;
  }

  // Collect all unique dependency names
  const allDeps = new Set<string>();
  const SKIP_KEYS = new Set(['module_id', 'module_name', 'state', 'tenant_id']);
  for (const row of data.matrix) {
    for (const key of Object.keys(row)) {
      if (!SKIP_KEYS.has(key)) allDeps.add(key);
    }
  }
  const depNames = Array.from(allDeps).sort();

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h2 style={{ color: '#f1f5f9', margin: 0 }}>Dependency Matrix</h2>
        <div style={{ display: 'flex', gap: 16, fontSize: '0.75rem', color: '#94a3b8' }}>
          <span style={{ color: STATUS_FG.ok }}>● ok</span>
          <span style={{ color: STATUS_FG.degraded }}>◐ degraded</span>
          <span style={{ color: STATUS_FG.failed }}>● failed</span>
          <span style={{ color: STATUS_FG.unknown }}>○ unknown</span>
        </div>
        <button onClick={fetch} style={{ padding: '6px 14px', background: '#334155', border: '1px solid #475569', borderRadius: 4, color: '#e2e8f0', cursor: 'pointer', fontSize: '0.875rem' }}>
          Refresh
        </button>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ borderCollapse: 'collapse', fontSize: '0.85rem', minWidth: '100%' }}>
          <thead>
            <tr style={{ background: '#0f172a' }}>
              <th style={{ padding: '8px 14px', textAlign: 'left', color: '#64748b', fontWeight: 600, border: '1px solid #1e293b', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                Module
              </th>
              <th style={{ padding: '8px 10px', textAlign: 'center', color: '#64748b', fontWeight: 600, border: '1px solid #1e293b', fontSize: '0.75rem', textTransform: 'uppercase', minWidth: 70 }}>
                State
              </th>
              {depNames.map((dep) => (
                <th key={dep} style={{ padding: '8px 10px', textAlign: 'center', color: '#64748b', fontWeight: 600, border: '1px solid #1e293b', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                  {dep}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.matrix.map((row) => (
              <tr key={row.module_id as string}>
                <td style={{
                  padding: '6px 14px', fontFamily: 'monospace', color: '#7dd3fc',
                  border: '1px solid #1e293b', fontSize: '0.8rem', whiteSpace: 'nowrap',
                }}>
                  {row.module_name as string || row.module_id as string}
                </td>
                <td style={{ padding: '6px 10px', textAlign: 'center', border: '1px solid #1e293b' }}>
                  <span style={{
                    display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: '0.7rem', fontWeight: 600,
                    background: row.state === 'ready' ? '#166534' : row.state === 'failed' ? '#7f1d1d' : '#334155',
                    color: row.state === 'ready' ? '#86efac' : row.state === 'failed' ? '#fca5a5' : '#94a3b8',
                  }}>
                    {row.state}
                  </span>
                </td>
                {depNames.map((dep) => (
                  <StatusCell key={dep} status={(row[dep] as string) ?? 'unknown'} />
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: 12, color: '#475569', fontSize: '0.75rem' }}>
        {data.module_count} module(s) · scope: {data.tenant_scope}
      </div>
    </div>
  );
}
