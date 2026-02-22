'use client';

/**
 * BootTimeline — Visual boot stage progression with duration breakdown
 * and error markers.
 */

import React, { useEffect, useState } from 'react';
import type { BootStage, BootTraceResponse } from '@/lib/controlPlaneApi';
import { getBootTrace } from '@/lib/controlPlaneApi';

const STATUS_COLORS: Record<string, string> = {
  ok: '#22c55e',
  in_progress: '#3b82f6',
  failed: '#ef4444',
  skipped: '#6b7280',
  pending: '#334155',
};

const STATUS_LABELS: Record<string, string> = {
  ok: '✓',
  in_progress: '⟳',
  failed: '✗',
  skipped: '—',
  pending: '·',
};

interface StageRowProps {
  stage: BootStage;
  maxDuration: number;
}

function StageRow({ stage, maxDuration }: StageRowProps) {
  const color = STATUS_COLORS[stage.status] ?? '#6b7280';
  const barWidth =
    stage.duration_ms != null && maxDuration > 0
      ? Math.min(100, (stage.duration_ms / maxDuration) * 100)
      : 0;

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '24px 220px 1fr 90px',
        alignItems: 'center',
        gap: 12,
        padding: '6px 0',
        borderBottom: '1px solid #1e293b',
      }}
    >
      {/* Status icon */}
      <div style={{ color, fontWeight: 700, fontSize: '1rem', textAlign: 'center' }}>
        {STATUS_LABELS[stage.status] ?? '·'}
      </div>

      {/* Stage name */}
      <div style={{ color: '#e2e8f0', fontSize: '0.875rem', fontFamily: 'monospace' }}>
        {stage.stage_name}
        {stage.error_code && (
          <div style={{ color: '#fca5a5', fontSize: '0.7rem', marginTop: 2 }}>
            {stage.error_code}
            {stage.error_detail_redacted && (
              <span style={{ color: '#94a3b8' }}> — {stage.error_detail_redacted}</span>
            )}
          </div>
        )}
      </div>

      {/* Duration bar */}
      <div style={{ height: 8, background: '#0f172a', borderRadius: 4, overflow: 'hidden' }}>
        {barWidth > 0 && (
          <div
            style={{
              height: '100%',
              width: `${barWidth}%`,
              background: color,
              borderRadius: 4,
              transition: 'width 0.4s ease',
            }}
          />
        )}
      </div>

      {/* Duration label */}
      <div style={{ color: '#64748b', fontSize: '0.75rem', textAlign: 'right', fontFamily: 'monospace' }}>
        {stage.duration_ms != null ? `${stage.duration_ms.toFixed(1)}ms` : '—'}
      </div>
    </div>
  );
}

interface Props {
  moduleId: string;
}

export default function BootTimeline({ moduleId }: Props) {
  const [trace, setTrace] = useState<BootTraceResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getBootTrace(moduleId)
      .then(setTrace)
      .catch((e: unknown) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [moduleId]);

  if (loading) return <div style={{ color: '#94a3b8', padding: 12 }}>Loading boot trace…</div>;
  if (error) return <div style={{ color: '#ef4444', padding: 12 }}>Error: {error}</div>;
  if (!trace) return null;

  const maxDuration = Math.max(
    1,
    ...trace.stages
      .map((s) => s.duration_ms ?? 0)
      .filter((d) => d > 0),
  );

  const { summary } = trace;

  return (
    <div>
      <div style={{ display: 'flex', gap: 24, marginBottom: 16 }}>
        <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
          Module: <span style={{ color: '#e2e8f0', fontFamily: 'monospace' }}>{moduleId}</span>
        </div>
        <div
          style={{
            padding: '3px 10px',
            borderRadius: 999,
            background: summary.is_ready ? '#166534' : '#7f1d1d',
            color: summary.is_ready ? '#86efac' : '#fca5a5',
            fontSize: '0.75rem',
            fontWeight: 600,
          }}
        >
          {summary.is_ready ? 'READY' : 'NOT READY'}
        </div>
        <div style={{ color: '#64748b', fontSize: '0.8rem' }}>
          {summary.completed_stages} / {summary.total_stages} stages complete
        </div>
      </div>

      {summary.failed_stages.length > 0 && (
        <div
          style={{
            background: '#3b0c0c', border: '1px solid #7f1d1d',
            borderRadius: 4, padding: '8px 12px', marginBottom: 12,
            color: '#fca5a5', fontSize: '0.8rem',
          }}
        >
          Failed stages: {summary.failed_stages.join(', ')}
        </div>
      )}

      <div style={{ background: '#0f172a', borderRadius: 6, padding: '8px 12px' }}>
        {/* Header */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '24px 220px 1fr 90px',
            gap: 12,
            padding: '4px 0 8px',
            borderBottom: '1px solid #334155',
            color: '#64748b',
            fontSize: '0.7rem',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
          }}
        >
          <div />
          <div>Stage</div>
          <div>Duration</div>
          <div style={{ textAlign: 'right' }}>ms</div>
        </div>

        {trace.stages.map((stage) => (
          <StageRow key={stage.stage_name} stage={stage} maxDuration={maxDuration} />
        ))}
      </div>
    </div>
  );
}
