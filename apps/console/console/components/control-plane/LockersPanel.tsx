'use client';

/**
 * LockersPanel — Table of lockers with heartbeat, version, and action buttons.
 * All actions require reason confirmation before dispatch.
 */

import React, { useCallback, useEffect, useState } from 'react';
import type { LockerRecord } from '@/lib/controlPlaneApi';
import { listLockers, lockerCommand } from '@/lib/controlPlaneApi';

const STATE_COLORS: Record<string, string> = {
  active: '#22c55e',
  paused: '#f59e0b',
  quarantined: '#ef4444',
  restarting: '#3b82f6',
  stopped: '#6b7280',
  unknown: '#a78bfa',
};

function ReasonDialog({
  open, lockerId, command, onConfirm, onCancel,
}: {
  open: boolean;
  lockerId: string;
  command: string;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (open) { setReason(''); setError(''); }
  }, [open]);

  if (!open) return null;

  const submit = () => {
    const trimmed = reason.trim();
    if (trimmed.length < 4) { setError('Reason must be at least 4 characters'); return; }
    if (trimmed.length > 512) { setError('Max 512 characters'); return; }
    onConfirm(trimmed);
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.65)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }}>
      <div style={{
        background: '#1e293b', borderRadius: 8, padding: 24, minWidth: 420,
        border: '1px solid #334155',
      }}>
        <h3 style={{ color: '#f1f5f9', margin: '0 0 6px' }}>
          {command.toUpperCase()}: <code style={{ fontSize: '0.9rem', color: '#7dd3fc' }}>{lockerId}</code>
        </h3>
        <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 14px' }}>
          This action is audited and irreversible without another command. Provide a reason.
        </p>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. Security incident containment"
          rows={3}
          style={{
            width: '100%', boxSizing: 'border-box', background: '#0f172a',
            border: '1px solid #334155', borderRadius: 4, color: '#f1f5f9',
            padding: '8px 12px', fontSize: '0.875rem', resize: 'vertical',
          }}
        />
        {error && <div style={{ color: '#ef4444', fontSize: '0.78rem', marginTop: 4 }}>{error}</div>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onCancel} style={{ padding: '6px 14px', background: 'transparent', border: '1px solid #475569', borderRadius: 4, color: '#94a3b8', cursor: 'pointer', fontSize: '0.875rem' }}>
            Cancel
          </button>
          <button
            onClick={submit}
            style={{
              padding: '6px 14px',
              background: command === 'quarantine' ? '#991b1b' : '#1d4ed8',
              border: 'none', borderRadius: 4, color: '#fff',
              cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}
          >
            Confirm {command}
          </button>
        </div>
      </div>
    </div>
  );
}

function timeSince(ts: string): string {
  try {
    const d = (Date.now() - new Date(ts).getTime()) / 1000;
    if (d < 60) return `${Math.round(d)}s ago`;
    if (d < 3600) return `${Math.round(d / 60)}m ago`;
    return `${Math.round(d / 3600)}h ago`;
  } catch {
    return ts;
  }
}

function ActionButtons({
  locker, onAction,
}: {
  locker: LockerRecord;
  onAction: (lockerId: string, cmd: string) => void;
}) {
  const { state } = locker;
  const isQuarantined = state === 'quarantined';

  return (
    <div style={{ display: 'flex', gap: 6 }}>
      <button
        onClick={() => onAction(locker.locker_id, 'restart')}
        disabled={isQuarantined || state === 'restarting'}
        title={isQuarantined ? 'Quarantined — resume first' : 'Restart'}
        style={{
          padding: '3px 10px', borderRadius: 4, border: '1px solid #475569',
          background: isQuarantined ? '#1e293b' : '#334155', color: isQuarantined ? '#475569' : '#e2e8f0',
          cursor: isQuarantined ? 'not-allowed' : 'pointer', fontSize: '0.78rem',
        }}
      >
        Restart
      </button>
      {state === 'active' && (
        <button
          onClick={() => onAction(locker.locker_id, 'pause')}
          style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #92400e', background: '#451a03', color: '#fcd34d', cursor: 'pointer', fontSize: '0.78rem' }}
        >
          Pause
        </button>
      )}
      {(state === 'paused') && (
        <button
          onClick={() => onAction(locker.locker_id, 'resume')}
          style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #166534', background: '#052e16', color: '#86efac', cursor: 'pointer', fontSize: '0.78rem' }}
        >
          Resume
        </button>
      )}
      {isQuarantined && (
        <button
          onClick={() => onAction(locker.locker_id, 'resume')}
          style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #166534', background: '#052e16', color: '#86efac', cursor: 'pointer', fontSize: '0.78rem', fontWeight: 600 }}
        >
          Resume (Un-quarantine)
        </button>
      )}
      {state !== 'quarantined' && (
        <button
          onClick={() => onAction(locker.locker_id, 'quarantine')}
          style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #7f1d1d', background: '#2d0f0f', color: '#fca5a5', cursor: 'pointer', fontSize: '0.78rem' }}
        >
          Quarantine
        </button>
      )}
    </div>
  );
}

export default function LockersPanel() {
  const [lockers, setLockers] = useState<LockerRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<{ open: boolean; lockerId: string; command: string }>({
    open: false, lockerId: '', command: '',
  });
  const [feedback, setFeedback] = useState<Record<string, string>>({});

  const fetchLockers = useCallback(async () => {
    try {
      const resp = await listLockers();
      setLockers(resp.lockers);
      setError(null);
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLockers();
    const interval = setInterval(fetchLockers, 10_000);
    return () => clearInterval(interval);
  }, [fetchLockers]);

  const handleAction = (lockerId: string, command: string) => {
    setDialog({ open: true, lockerId, command });
  };

  const confirmAction = async (reason: string) => {
    const { lockerId, command } = dialog;
    setDialog({ ...dialog, open: false });
    const idKey = `${command}-${lockerId}-${Date.now()}`;
    try {
      const res = await lockerCommand(lockerId, command as 'restart' | 'pause' | 'resume' | 'quarantine', reason, idKey);
      setFeedback((p) => ({ ...p, [lockerId]: res.ok ? `${command} OK` : (res.error_message ?? 'error') }));
    } catch (e: unknown) {
      setFeedback((p) => ({ ...p, [lockerId]: (e as Error).message }));
    }
    setTimeout(() => {
      setFeedback((p) => { const n = { ...p }; delete n[lockerId]; return n; });
      fetchLockers();
    }, 4000);
  };

  if (loading) return <div style={{ color: '#94a3b8', padding: 24 }}>Loading lockers…</div>;
  if (error) return <div style={{ color: '#ef4444', padding: 24 }}>Error: {error}</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ color: '#f1f5f9', margin: 0 }}>Lockers</h2>
        <button onClick={fetchLockers} style={{ padding: '6px 14px', background: '#334155', border: '1px solid #475569', borderRadius: 4, color: '#e2e8f0', cursor: 'pointer', fontSize: '0.875rem' }}>
          Refresh
        </button>
      </div>

      {lockers.length === 0 ? (
        <div style={{ color: '#64748b', textAlign: 'center', padding: 32 }}>No lockers registered.</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #334155', color: '#64748b', textAlign: 'left', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                <th style={{ padding: '8px 12px' }}>Locker ID</th>
                <th style={{ padding: '8px 12px' }}>State</th>
                <th style={{ padding: '8px 12px' }}>Version</th>
                <th style={{ padding: '8px 12px' }}>Heartbeat</th>
                <th style={{ padding: '8px 12px' }}>Last Error</th>
                <th style={{ padding: '8px 12px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {lockers.map((l) => (
                <tr key={l.locker_id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#7dd3fc' }}>{l.locker_id}</td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{
                      display: 'inline-block', padding: '2px 8px', borderRadius: 999,
                      background: STATE_COLORS[l.state] ?? '#6b7280',
                      color: '#fff', fontSize: '0.72rem', fontWeight: 600,
                    }}>
                      {l.state}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', color: '#94a3b8', fontFamily: 'monospace' }}>{l.version}</td>
                  <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{timeSince(l.last_heartbeat_ts)}</td>
                  <td style={{ padding: '8px 12px', color: '#fca5a5', fontFamily: 'monospace', fontSize: '0.78rem' }}>
                    {l.last_error_code ?? '—'}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <ActionButtons locker={l} onAction={handleAction} />
                    {feedback[l.locker_id] && (
                      <div style={{ fontSize: '0.72rem', color: '#86efac', marginTop: 4 }}>
                        {feedback[l.locker_id]}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ReasonDialog
        open={dialog.open}
        lockerId={dialog.lockerId}
        command={dialog.command}
        onConfirm={confirmAction}
        onCancel={() => setDialog({ ...dialog, open: false })}
      />
    </div>
  );
}
