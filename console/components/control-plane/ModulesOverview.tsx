'use client';

/**
 * ModulesOverview — Card grid of all registered runtime modules.
 *
 * Shows per-module:
 * - State (color-coded)
 * - Dependency quick-view (ok/degraded/failed counts)
 * - Last error code
 * - Restart button (admin only — triggers reason prompt before sending)
 */

import React, { useCallback, useEffect, useState } from 'react';
import type { ModuleSummary, DepStatus } from '@/lib/controlPlaneApi';
import { listModules, lockerCommand } from '@/lib/controlPlaneApi';

// ---------------------------------------------------------------------------
// State color helpers
// ---------------------------------------------------------------------------

const STATE_COLORS: Record<string, string> = {
  ready: '#22c55e',       // green
  starting: '#3b82f6',    // blue
  degraded: '#f59e0b',    // amber
  failed: '#ef4444',      // red
  stopped: '#6b7280',     // gray
  stale: '#a78bfa',       // purple
};

const DEP_COLORS: Record<DepStatus, string> = {
  ok: '#22c55e',
  degraded: '#f59e0b',
  failed: '#ef4444',
  unknown: '#6b7280',
};

function StateChip({ state }: { state: string }) {
  const color = STATE_COLORS[state] ?? '#6b7280';
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 10px',
        borderRadius: '999px',
        background: color,
        color: '#fff',
        fontSize: '0.75rem',
        fontWeight: 600,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
      }}
    >
      {state}
    </span>
  );
}

function DepDot({ status }: { status: DepStatus }) {
  const color = DEP_COLORS[status] ?? '#6b7280';
  return (
    <span
      title={status}
      style={{
        display: 'inline-block',
        width: 10,
        height: 10,
        borderRadius: '50%',
        background: color,
        marginRight: 3,
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// Reason prompt dialog
// ---------------------------------------------------------------------------

interface ReasonDialogProps {
  open: boolean;
  locker: string;
  command: string;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}

function ReasonDialog({ open, locker, command, onConfirm, onCancel }: ReasonDialogProps) {
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (open) {
      setReason('');
      setError('');
    }
  }, [open]);

  if (!open) return null;

  const submit = () => {
    if (!reason.trim() || reason.trim().length < 4) {
      setError('Reason must be at least 4 characters');
      return;
    }
    if (reason.length > 512) {
      setError('Reason must be 512 characters or less');
      return;
    }
    onConfirm(reason.trim());
  };

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        style={{
          background: '#1e293b', borderRadius: 8, padding: 24, minWidth: 400,
          border: '1px solid #334155',
        }}
      >
        <h3 style={{ color: '#f1f5f9', margin: '0 0 8px' }}>
          {command.toUpperCase()} — {locker}
        </h3>
        <p style={{ color: '#94a3b8', fontSize: '0.875rem', margin: '0 0 16px' }}>
          This action is audited. Provide a reason for the change.
        </p>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. Scheduled maintenance window"
          rows={3}
          style={{
            width: '100%', background: '#0f172a', border: '1px solid #334155',
            borderRadius: 4, color: '#f1f5f9', padding: '8px 12px', fontSize: '0.875rem',
            resize: 'vertical', boxSizing: 'border-box',
          }}
        />
        {error && <p style={{ color: '#ef4444', fontSize: '0.8rem', margin: '4px 0 0' }}>{error}</p>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button
            onClick={onCancel}
            style={{
              padding: '6px 16px', background: 'transparent',
              border: '1px solid #475569', borderRadius: 4,
              color: '#94a3b8', cursor: 'pointer', fontSize: '0.875rem',
            }}
          >
            Cancel
          </button>
          <button
            onClick={submit}
            style={{
              padding: '6px 16px', background: '#3b82f6',
              border: 'none', borderRadius: 4,
              color: '#fff', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600,
            }}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Module card
// ---------------------------------------------------------------------------

interface ModuleCardProps {
  module: ModuleSummary;
  isAdmin: boolean;
  onCommand: (lockerId: string, command: string) => void;
}

function ModuleCard({ module: m, isAdmin, onCommand }: ModuleCardProps) {
  const depEntries = Object.entries(m.dependency_summary);
  const failedDeps = depEntries.filter(([, s]) => s === 'failed').length;
  const degradedDeps = depEntries.filter(([, s]) => s === 'degraded').length;

  return (
    <div
      style={{
        background: '#1e293b', borderRadius: 8, padding: 20,
        border: `1px solid ${m.state === 'failed' ? '#ef4444' : m.state === 'degraded' ? '#f59e0b' : '#334155'}`,
        display: 'flex', flexDirection: 'column', gap: 12,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ color: '#f1f5f9', fontWeight: 600, fontSize: '1rem' }}>{m.name}</div>
          <div style={{ color: '#64748b', fontSize: '0.75rem', fontFamily: 'monospace' }}>
            {m.module_id}
          </div>
        </div>
        <StateChip state={m.state} />
      </div>

      <div style={{ display: 'flex', gap: 16, fontSize: '0.8rem', color: '#94a3b8' }}>
        <span>v{m.version}</span>
        <span title={m.commit_hash}>{m.commit_hash.substring(0, 8)}</span>
        <span>↑{Math.round(m.uptime_seconds)}s</span>
      </div>

      {/* Dependencies quick-view */}
      {depEntries.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {depEntries.map(([name, status]) => (
            <span key={name} style={{ display: 'flex', alignItems: 'center', fontSize: '0.75rem', color: '#94a3b8' }}>
              <DepDot status={status as DepStatus} />
              {name}
            </span>
          ))}
        </div>
      )}

      {/* Alerts */}
      {(failedDeps > 0 || degradedDeps > 0) && (
        <div style={{ fontSize: '0.75rem', color: failedDeps > 0 ? '#ef4444' : '#f59e0b' }}>
          {failedDeps > 0 && `${failedDeps} dep(s) failed`}
          {failedDeps > 0 && degradedDeps > 0 && ' · '}
          {degradedDeps > 0 && `${degradedDeps} dep(s) degraded`}
        </div>
      )}

      {/* Last error */}
      {m.last_error_code && (
        <div
          style={{
            background: '#1a1a2e', borderRadius: 4, padding: '4px 8px',
            fontSize: '0.75rem', color: '#fca5a5', fontFamily: 'monospace',
          }}
        >
          {m.last_error_code}
        </div>
      )}

      {/* Admin action */}
      {isAdmin && (
        <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
          <button
            onClick={() => onCommand(m.module_id, 'restart')}
            disabled={m.state === 'restarting'}
            style={{
              padding: '4px 12px', background: m.state === 'restarting' ? '#475569' : '#334155',
              border: '1px solid #475569', borderRadius: 4, color: '#e2e8f0',
              cursor: m.state === 'restarting' ? 'not-allowed' : 'pointer', fontSize: '0.8rem',
            }}
          >
            {m.state === 'restarting' ? '⟳ Restarting…' : 'Restart'}
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function ModulesOverview() {
  const [modules, setModules] = useState<ModuleSummary[]>([]);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [dialog, setDialog] = useState<{
    open: boolean;
    locker: string;
    command: string;
  }>({ open: false, locker: '', command: '' });

  const [cmdFeedback, setCmdFeedback] = useState<Record<string, string>>({});

  const fetchModules = useCallback(async () => {
    try {
      const resp = await listModules();
      setModules(resp.modules);
      setIsAdmin(resp.is_global_admin);
      setError(null);
    } catch (e: unknown) {
      const err = e as Error;
      setError(err.message ?? 'Failed to load modules');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchModules();
    const interval = setInterval(fetchModules, 15_000);
    return () => clearInterval(interval);
  }, [fetchModules]);

  const handleCommand = (lockerId: string, command: string) => {
    setDialog({ open: true, locker: lockerId, command });
  };

  const confirmCommand = async (reason: string) => {
    const { locker, command } = dialog;
    setDialog({ ...dialog, open: false });

    const idempotencyKey = `${command}-${locker}-${Date.now()}`;
    try {
      const result = await lockerCommand(
        locker,
        command as 'restart' | 'pause' | 'resume' | 'quarantine',
        reason,
        idempotencyKey,
      );
      setCmdFeedback((prev) => ({
        ...prev,
        [locker]: result.ok ? `${command} dispatched` : (result.error_message ?? 'error'),
      }));
      setTimeout(() => {
        setCmdFeedback((prev) => { const n = { ...prev }; delete n[locker]; return n; });
        fetchModules();
      }, 3000);
    } catch (e: unknown) {
      const err = e as Error;
      setCmdFeedback((prev) => ({ ...prev, [locker]: err.message ?? 'command failed' }));
    }
  };

  if (loading) {
    return (
      <div style={{ color: '#94a3b8', padding: 24 }}>Loading modules…</div>
    );
  }

  if (error) {
    return (
      <div style={{ color: '#ef4444', padding: 24 }}>Error: {error}</div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h2 style={{ color: '#f1f5f9', margin: 0 }}>Runtime Modules</h2>
        <button
          onClick={fetchModules}
          style={{
            padding: '6px 14px', background: '#334155', border: '1px solid #475569',
            borderRadius: 4, color: '#e2e8f0', cursor: 'pointer', fontSize: '0.875rem',
          }}
        >
          Refresh
        </button>
      </div>

      {modules.length === 0 ? (
        <div style={{ color: '#64748b', padding: 24, textAlign: 'center' }}>
          No modules registered yet.
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
            gap: 16,
          }}
        >
          {modules.map((m) => (
            <div key={m.module_id}>
              <ModuleCard module={m} isAdmin={isAdmin} onCommand={handleCommand} />
              {cmdFeedback[m.module_id] && (
                <div style={{ fontSize: '0.75rem', color: '#86efac', marginTop: 4, paddingLeft: 4 }}>
                  {cmdFeedback[m.module_id]}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <ReasonDialog
        open={dialog.open}
        locker={dialog.locker}
        command={dialog.command}
        onConfirm={confirmCommand}
        onCancel={() => setDialog({ ...dialog, open: false })}
      />
    </div>
  );
}
