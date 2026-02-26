'use client';

import { useEffect, useState } from 'react';
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
import { brandTokens } from '@/styles/tokens';

type State = { snapshot?: ControlTowerSnapshotV1; error?: string; requestId?: string };

export default function ControlTowerPage() {
  const [state, setState] = useState<State>({});
  const [reason, setReason] = useState('control-tower-action');

  async function refresh() {
    try {
      const payload = await getControlTowerSnapshot();
      setState({ snapshot: payload.data, requestId: payload.meta.requestId });
    } catch (e) {
      setState({ error: e instanceof Error ? e.message : 'Failed to load snapshot' });
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function runAction(fn: () => Promise<unknown>) {
    const auditReason = window.prompt('Provide audit reason', reason) || reason;
    setReason(auditReason);
    await fn();
    await refresh();
  }

  const s = state.snapshot;
  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <h2>Control Tower</h2>
      {!s ? <p>{state.error || 'Loading...'}</p> : null}
      {s ? (
        <>
          <section style={{ border: `1px solid ${brandTokens.colors.secondary}`, padding: 12, borderRadius: 12 }}>
            <h3>Overview / Trust Proof</h3>
            <p>request_id={state.requestId || 'n/a'} | tenant={s.tenant.tenant_id} | chain={s.chain_integrity.status}</p>
            <pre>{JSON.stringify(s.planes, null, 2)}</pre>
          </section>

          <section style={{ border: `1px solid ${brandTokens.colors.secondary}`, padding: 12, borderRadius: 12 }}>
            <h3>Admin: keys + tenant clamp</h3>
            <p>Clamp: {JSON.stringify(s.tenant.clamp)}</p>
            <button onClick={() => runAction(() => createKey({ scopes: ['admin:read'], ttl_seconds: 3600 }))}>Create key</button>{' '}
            <button onClick={() => runAction(() => revokeKey(window.prompt('Key prefix to revoke') || ''))}>Revoke key</button>{' '}
            <button onClick={() => runAction(() => rotateKey(window.prompt('Current key material') || '', 3600))}>Rotate key</button>
          </section>

          <section style={{ border: `1px solid ${brandTokens.colors.secondary}`, padding: 12, borderRadius: 12 }}>
            <h3>Evidence</h3>
            <button onClick={() => runAction(() => getChainVerify())}>Replay verify</button>{' '}
            <button onClick={() => runAction(() => exportEvidenceBundle())}>Export evidence bundle</button>
          </section>

          <section style={{ border: `1px solid ${brandTokens.colors.secondary}`, padding: 12, borderRadius: 12 }}>
            <h3>Connectors</h3>
            <button onClick={() => runAction(() => toggleConnector(window.prompt('Connector ID') || ''))}>Disable connector (revoke)</button>
          </section>

          <section style={{ border: `1px solid ${brandTokens.colors.secondary}`, padding: 12, borderRadius: 12 }}>
            <h3>Agents</h3>
            <p>Quarantined: {s.agents.quarantine_count}</p>
            <button onClick={() => runAction(() => listAgents())}>Refresh agent list</button>{' '}
            <button onClick={() => runAction(() => quarantineAgent(window.prompt('Device ID') || '', reason))}>Quarantine</button>{' '}
            <button onClick={() => runAction(() => restoreAgent(window.prompt('Device ID') || '', reason))}>Restore</button>
          </section>

          <section style={{ border: `1px solid ${brandTokens.colors.secondary}`, padding: 12, borderRadius: 12 }}>
            <h3>Lockers</h3>
            <button onClick={() => runAction(() => listLockers())}>List lockers</button>{' '}
            <button onClick={() => runAction(() => lockerRestart(window.prompt('Locker ID') || '', reason))}>Restart</button>{' '}
            <button onClick={() => runAction(() => lockerResume(window.prompt('Locker ID') || '', reason))}>Resume</button>
          </section>

          <section style={{ border: `1px solid ${brandTokens.colors.secondary}`, padding: 12, borderRadius: 12 }}>
            <h3>Incidents / Audit Trail</h3>
            <pre>{JSON.stringify(s.audit_incidents, null, 2)}</pre>
          </section>
        </>
      ) : null}
    </div>
  );
}
