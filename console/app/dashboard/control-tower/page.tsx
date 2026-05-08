'use client';

import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import {
  createKey,
  exportEvidenceBundle,
  getChainVerify,
  getControlTowerSnapshot,
  listAgents,
  listLockers,
  lockerRestart,
  lockerResume,
  quarantineAgent,
  restoreAgent,
  revokeKey,
  rotateKey,
  toggleConnector,
  type ControlTowerSnapshotV1,
} from '@/lib/coreApi';
import { EvidenceCard, TrustIndicator, AuditTimeline } from '@/components/governance';
import type { TimelineEvent } from '@/components/governance';
import { ActionModal } from '@/components/control-tower/ActionModal';
import type { ModalField } from '@/components/control-tower/ActionModal';

// ─── Modal config ─────────────────────────────────────────────────────────────

interface ModalConfig {
  title: string;
  description: string;
  fields?: ModalField[];
  destructive?: boolean;
  onConfirm: (values: Record<string, string>) => Promise<unknown>;
}

// ─── Section card ─────────────────────────────────────────────────────────────

function SectionCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface-2 p-4">
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">{title}</h3>
      {children}
    </div>
  );
}

// ─── Action button ────────────────────────────────────────────────────────────

function ActionBtn({
  label,
  destructive,
  onClick,
}: {
  label: string;
  destructive?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={
        destructive
          ? 'rounded border border-danger/30 bg-danger/5 px-3 py-1.5 text-xs font-medium text-danger hover:bg-danger/10'
          : 'rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-muted hover:text-foreground hover:border-primary/40'
      }
    >
      {label}
    </button>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

type State = { snapshot?: ControlTowerSnapshotV1; error?: string; requestId?: string };

export default function ControlTowerPage() {
  const [state, setState] = useState<State>({});
  const [auditReason, setAuditReason] = useState('control-tower-action');
  const [modal, setModal] = useState<ModalConfig | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [lastResult, setLastResult] = useState('');

  async function refresh() {
    try {
      const payload = await getControlTowerSnapshot();
      setState({ snapshot: payload.data, requestId: payload.meta.requestId });
    } catch (e) {
      setState({ error: e instanceof Error ? e.message : 'Failed to load snapshot' });
    }
  }

  useEffect(() => { refresh(); }, []);

  function openModal(config: ModalConfig) {
    setLastResult('');
    setModal(config);
  }

  async function handleConfirm(values: Record<string, string>) {
    if (!modal) return;
    setActionLoading(true);
    try {
      const result = await modal.onConfirm(values);
      setLastResult(result ? JSON.stringify(result, null, 2) : 'Done.');
      await refresh();
    } catch (e) {
      setLastResult(`Error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setActionLoading(false);
    }
  }

  const s = state.snapshot;

  // Build timeline events from audit incidents
  const timelineEvents: TimelineEvent[] = (s?.audit_incidents?.recent_events ?? []).map(
    (ev: Record<string, unknown>, i: number) => ({
      id: String(ev.id ?? ev.event_id ?? i),
      ts: String(ev.ts ?? ev.timestamp ?? ev.created_at ?? ''),
      actor: ev.actor ? String(ev.actor) : undefined,
      action: String(ev.action ?? ev.event_type ?? 'event'),
      status: String(ev.status ?? ev.action ?? 'info'),
      summary: ev.summary ? String(ev.summary) : undefined,
      requestId: ev.request_id ? String(ev.request_id) : undefined,
    }),
  );

  return (
    <div className="flex flex-col">
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <div>
          <h1 className="text-base font-semibold text-foreground">Control Tower</h1>
          <p className="text-xs text-muted mt-0.5">Tenant controls, key lifecycle, agent management</p>
        </div>
        <button
          onClick={refresh}
          className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      <div className="p-6 space-y-4">
        {!s && (
          <p className="text-sm text-muted">{state.error || 'Loading snapshot…'}</p>
        )}

        {s && (
          <>
            {/* Trust proof */}
            <TrustIndicator
              status={s.chain_integrity.status === 'ok' ? 'verified' : 'degraded'}
              label={`Chain: ${s.chain_integrity.status}`}
              requestId={state.requestId}
              hash={s.chain_integrity.chain_head_hash ?? undefined}
            />

            {/* Planes overview */}
            <EvidenceCard
              title="System planes"
              fields={Object.entries(s.planes).map(([k, v]) => ({ label: k, value: String(v) }))}
            />

            {/* Keys */}
            <SectionCard title="API Keys">
              <p className="mb-3 text-xs text-muted">
                Active keys: {s.key_lifecycle.active_key_count} · Last rotation:{' '}
                {s.key_lifecycle.last_rotation ?? 'never'}
              </p>
              <div className="flex flex-wrap gap-2">
                <ActionBtn
                  label="Create key"
                  onClick={() =>
                    openModal({
                      title: 'Create API Key',
                      description: 'Issue a new scoped API key for this tenant.',
                      fields: [
                        { name: 'scopes', label: 'Scopes (comma-separated)', placeholder: 'admin:read,ingest:write', required: true },
                        { name: 'ttl_seconds', label: 'TTL (seconds)', placeholder: '3600', type: 'number', required: true },
                      ],
                      onConfirm: (v) =>
                        createKey({
                          scopes: v.scopes.split(',').map((s) => s.trim()),
                          ttl_seconds: Number(v.ttl_seconds),
                        }),
                    })
                  }
                />
                <ActionBtn
                  label="Revoke key"
                  destructive
                  onClick={() =>
                    openModal({
                      title: 'Revoke API Key',
                      description: 'Permanently revokes the key. Active requests using this key will fail immediately.',
                      fields: [{ name: 'prefix', label: 'Key prefix', placeholder: 'fgk_...', required: true }],
                      destructive: true,
                      onConfirm: (v) => revokeKey(v.prefix),
                    })
                  }
                />
                <ActionBtn
                  label="Rotate key"
                  destructive
                  onClick={() =>
                    openModal({
                      title: 'Rotate API Key',
                      description: 'Issues a new key and revokes the current one after a grace window.',
                      fields: [
                        { name: 'current_key', label: 'Current key material', placeholder: 'fgk_...', required: true },
                        { name: 'ttl_seconds', label: 'New TTL (seconds)', placeholder: '3600', type: 'number', required: true },
                      ],
                      destructive: true,
                      onConfirm: (v) => rotateKey(v.current_key, Number(v.ttl_seconds)),
                    })
                  }
                />
              </div>
            </SectionCard>

            {/* Evidence */}
            <SectionCard title="Evidence & Chain">
              <div className="flex flex-wrap gap-2">
                <ActionBtn
                  label="Replay verify"
                  onClick={() =>
                    openModal({
                      title: 'Replay Chain Verify',
                      description: 'Re-runs HMAC chain verification from the last known good state.',
                      onConfirm: () => getChainVerify(),
                    })
                  }
                />
                <ActionBtn
                  label="Export evidence bundle"
                  onClick={() =>
                    openModal({
                      title: 'Export Evidence Bundle',
                      description: 'Exports a tamper-evident JSON bundle of all audit records for this tenant.',
                      onConfirm: () => exportEvidenceBundle(),
                    })
                  }
                />
              </div>
            </SectionCard>

            {/* Connectors */}
            <SectionCard title="Connectors">
              <p className="mb-3 text-xs text-muted">
                Enabled: {s.connectors.enabled} · Last sync: {s.connectors.last_sync ?? 'never'}
              </p>
              <ActionBtn
                label="Disable connector"
                destructive
                onClick={() =>
                  openModal({
                    title: 'Disable Connector',
                    description: 'Revokes the connector and stops all inbound events from it.',
                    fields: [{ name: 'connector_id', label: 'Connector ID', placeholder: 'conn_...', required: true }],
                    destructive: true,
                    onConfirm: (v) => toggleConnector(v.connector_id),
                  })
                }
              />
            </SectionCard>

            {/* Agents */}
            <SectionCard title="Agent Devices">
              <p className="mb-3 text-xs text-muted">
                Total: {s.agents.total} · Quarantined: {s.agents.quarantine_count} · Channel:{' '}
                {s.agents.update_channel_status}
              </p>
              <div className="flex flex-wrap gap-2">
                <ActionBtn
                  label="List agents"
                  onClick={() =>
                    openModal({
                      title: 'List Agent Devices',
                      description: 'Fetches the current list of registered agent devices for this tenant.',
                      onConfirm: () => listAgents(),
                    })
                  }
                />
                <ActionBtn
                  label="Quarantine device"
                  destructive
                  onClick={() =>
                    openModal({
                      title: 'Quarantine Agent Device',
                      description: 'Isolates the device from the tenant network. All requests from this device will be blocked.',
                      fields: [{ name: 'device_id', label: 'Device ID', placeholder: 'dev_...', required: true }],
                      destructive: true,
                      onConfirm: (v) => quarantineAgent(v.device_id, v.audit_reason || auditReason),
                    })
                  }
                />
                <ActionBtn
                  label="Restore device"
                  onClick={() =>
                    openModal({
                      title: 'Restore Agent Device',
                      description: 'Lifts quarantine and restores the device to normal operation.',
                      fields: [{ name: 'device_id', label: 'Device ID', placeholder: 'dev_...', required: true }],
                      onConfirm: (v) => restoreAgent(v.device_id, v.audit_reason || auditReason),
                    })
                  }
                />
              </div>
            </SectionCard>

            {/* Lockers */}
            <SectionCard title="Lockers">
              <p className="mb-3 text-xs text-muted">
                Status: {s.lockers.status} · Count: {s.lockers.count} · Last restart:{' '}
                {s.lockers.last_restart ?? 'never'}
              </p>
              <div className="flex flex-wrap gap-2">
                <ActionBtn
                  label="List lockers"
                  onClick={() =>
                    openModal({
                      title: 'List Lockers',
                      description: 'Fetches the current locker inventory for this tenant.',
                      onConfirm: () => listLockers(),
                    })
                  }
                />
                <ActionBtn
                  label="Restart locker"
                  destructive
                  onClick={() =>
                    openModal({
                      title: 'Restart Locker',
                      description: 'Restarts the locker process. In-flight requests will be dropped.',
                      fields: [{ name: 'locker_id', label: 'Locker ID', placeholder: 'lck_...', required: true }],
                      destructive: true,
                      onConfirm: (v) => lockerRestart(v.locker_id, v.audit_reason || auditReason),
                    })
                  }
                />
                <ActionBtn
                  label="Resume locker"
                  onClick={() =>
                    openModal({
                      title: 'Resume Locker',
                      description: 'Resumes a paused locker and re-enables request processing.',
                      fields: [{ name: 'locker_id', label: 'Locker ID', placeholder: 'lck_...', required: true }],
                      onConfirm: (v) => lockerResume(v.locker_id, v.audit_reason || auditReason),
                    })
                  }
                />
              </div>
            </SectionCard>

            {/* Audit incidents */}
            <SectionCard title="Recent Incidents">
              {timelineEvents.length > 0 ? (
                <AuditTimeline events={timelineEvents} />
              ) : (
                <p className="text-xs text-muted">No recent incidents.</p>
              )}
            </SectionCard>
          </>
        )}
      </div>

      {/* Modal */}
      {modal && (
        <ActionModal
          open={!!modal}
          title={modal.title}
          description={modal.description}
          fields={modal.fields}
          destructive={modal.destructive}
          loading={actionLoading}
          lastResult={lastResult}
          auditReason={auditReason}
          onAuditReasonChange={setAuditReason}
          onConfirm={handleConfirm}
          onClose={() => { setModal(null); setLastResult(''); }}
        />
      )}
    </div>
  );
}
