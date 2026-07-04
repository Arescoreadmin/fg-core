'use client';

import { Badge } from '@/components/ui/badge';
import { type ControlTowerSnapshotV1 } from '@/lib/coreApi';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-AUTHORITY-HEALTH-MAP';
const AUTHORITY = 'Authority Health Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

interface AuthorityHealthMapProps {
  snapshot: ControlTowerSnapshotV1 | null;
  loading?: boolean;
  lastUpdated?: string;
}

interface AuthorityRow {
  name: string;
  health: 'healthy' | 'degraded' | 'unknown' | 'error';
  freshness: string | null;
  confidence: string | null;
  coverage: string | null;
  drift: string | null;
  errors: number;
  warnings: number;
  dependencies: string[];
  lastRefresh: string | null;
}

const HEALTH_VARIANT: Record<AuthorityRow['health'], 'success' | 'warning' | 'secondary' | 'danger'> = {
  healthy: 'success',
  degraded: 'warning',
  unknown: 'secondary',
  error: 'danger',
};

function deriveAuthorities(snapshot: ControlTowerSnapshotV1): AuthorityRow[] {
  const rows: AuthorityRow[] = [];

  // Chain Integrity
  const chainOk = snapshot.chain_integrity.status === 'ok' || snapshot.chain_integrity.status === 'healthy';
  rows.push({
    name: 'Chain Integrity',
    health: snapshot.chain_integrity.first_bad ? 'error' : chainOk ? 'healthy' : 'degraded',
    freshness: null,
    confidence: snapshot.chain_integrity.chain_head_hash ? 'chain-verified' : null,
    coverage: snapshot.chain_integrity.chain_head_hash
      ? `head:${snapshot.chain_integrity.chain_head_hash.slice(0, 8)}`
      : null,
    drift: snapshot.chain_integrity.status,
    errors: snapshot.chain_integrity.first_bad ? 1 : 0,
    warnings: 0,
    dependencies: ['Audit Incidents', 'Replay'],
    lastRefresh: null,
  });

  // Key Lifecycle
  const keyHealthy = snapshot.key_lifecycle.active_key_count > 0;
  rows.push({
    name: 'Key Lifecycle',
    health: keyHealthy ? 'healthy' : 'error',
    freshness: snapshot.key_lifecycle.last_rotation,
    confidence: `${snapshot.key_lifecycle.active_key_count} active key(s)`,
    coverage: snapshot.key_lifecycle.grace_window_seconds !== null
      ? `grace:${snapshot.key_lifecycle.grace_window_seconds}s`
      : null,
    drift: null,
    errors: keyHealthy ? 0 : 1,
    warnings: snapshot.key_lifecycle.recent_actions.length > 0 ? snapshot.key_lifecycle.recent_actions.length : 0,
    dependencies: ['Chain Integrity'],
    lastRefresh: snapshot.key_lifecycle.last_rotation,
  });

  // Connectors
  const connectorErrorCount = snapshot.connectors.errors.length;
  rows.push({
    name: 'Connectors',
    health: connectorErrorCount > 0 ? 'degraded' : snapshot.connectors.enabled === 0 ? 'unknown' : 'healthy',
    freshness: snapshot.connectors.last_sync,
    confidence: `${snapshot.connectors.enabled} enabled`,
    coverage: null,
    drift: null,
    errors: connectorErrorCount,
    warnings: 0,
    dependencies: ['Agents'],
    lastRefresh: snapshot.connectors.last_sync,
  });

  // Agents
  const agentQuarantine = snapshot.agents.quarantine_count;
  rows.push({
    name: 'Agents',
    health: agentQuarantine > 0 ? 'degraded' : snapshot.agents.total === 0 ? 'unknown' : 'healthy',
    freshness: null,
    confidence: `${snapshot.agents.total} total`,
    coverage: `channel:${snapshot.agents.update_channel_status}`,
    drift: snapshot.agents.update_channel_status,
    errors: agentQuarantine,
    warnings: 0,
    dependencies: ['Connectors'],
    lastRefresh: null,
  });

  // Lockers
  const lockerOk = snapshot.lockers.status === 'ok' || snapshot.lockers.status === 'healthy';
  rows.push({
    name: 'Lockers',
    health: lockerOk ? 'healthy' : 'degraded',
    freshness: snapshot.lockers.last_restart,
    confidence: `${snapshot.lockers.count} locker(s)`,
    coverage: null,
    drift: snapshot.lockers.status,
    errors: lockerOk ? 0 : 1,
    warnings: 0,
    dependencies: ['Key Lifecycle'],
    lastRefresh: snapshot.lockers.last_restart,
  });

  // Audit Incidents
  const recentIncidents = snapshot.audit_incidents.recent_events.length;
  rows.push({
    name: 'Audit Incidents',
    health: recentIncidents > 0 ? 'degraded' : 'healthy',
    freshness: null,
    confidence: `${recentIncidents} recent event(s)`,
    coverage: Object.keys(snapshot.audit_incidents.facets).join(', ') || null,
    drift: null,
    errors: recentIncidents,
    warnings: 0,
    dependencies: ['Chain Integrity'],
    lastRefresh: null,
  });

  // Replay
  const replayOk = snapshot.last_replay.result === 'ok' || snapshot.last_replay.result === 'pass';
  rows.push({
    name: 'Replay',
    health: replayOk ? 'healthy' : snapshot.last_replay.result ? 'degraded' : 'unknown',
    freshness: snapshot.last_replay.timestamp,
    confidence: snapshot.last_replay.event_id ? `event:${snapshot.last_replay.event_id}` : null,
    coverage: snapshot.last_replay.result,
    drift: null,
    errors: replayOk || !snapshot.last_replay.result ? 0 : 1,
    warnings: 0,
    dependencies: ['Chain Integrity', 'Audit Incidents'],
    lastRefresh: snapshot.last_replay.timestamp,
  });

  // Control Tower
  const planeCount = Object.keys(snapshot.planes).length;
  rows.push({
    name: 'Control Tower',
    health: planeCount > 0 ? 'healthy' : 'unknown',
    freshness: null,
    confidence: `${planeCount} plane(s)`,
    coverage: Object.entries(snapshot.planes)
      .map(([k, v]) => `${k}:${v}`)
      .join(', ') || null,
    drift: null,
    errors: 0,
    warnings: 0,
    dependencies: ['Chain Integrity', 'Key Lifecycle', 'Agents', 'Lockers'],
    lastRefresh: null,
  });

  return rows;
}

export default function AuthorityHealthMap({
  snapshot,
  loading,
  lastUpdated,
}: AuthorityHealthMapProps) {
  const rows = snapshot ? deriveAuthorities(snapshot) : [];

  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Authority Health Map"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Authority Health Map"
    >
      <section aria-label="authority-health-map">
        {loading && (
          <div className="space-y-2" aria-label="Loading authority health">
            {[0, 1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-12 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && snapshot === null && (
          <p className="py-6 text-center text-sm text-muted">
            Snapshot unavailable — authority health cannot be derived.
          </p>
        )}

        {!loading && rows.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse" aria-label="Authority health table">
              <thead>
                <tr className="border-b border-border text-[10px] text-muted/70 uppercase tracking-wide">
                  <th className="pb-1.5 text-left font-semibold pr-3">Authority</th>
                  <th className="pb-1.5 text-left font-semibold pr-3">Health</th>
                  <th className="pb-1.5 text-left font-semibold pr-3">Freshness</th>
                  <th className="pb-1.5 text-left font-semibold pr-3">Confidence</th>
                  <th className="pb-1.5 text-left font-semibold pr-3">Coverage</th>
                  <th className="pb-1.5 text-left font-semibold pr-3">Drift</th>
                  <th className="pb-1.5 text-right font-semibold pr-3">Err</th>
                  <th className="pb-1.5 text-right font-semibold">Warn</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((row) => (
                  <tr key={row.name} className="hover:bg-muted/10">
                    <td className="py-1.5 pr-3">
                      <span className="font-medium text-foreground">{row.name}</span>
                      {row.dependencies.length > 0 && (
                        <div className="text-[10px] text-muted/60">
                          Deps: {row.dependencies.join(', ')}
                        </div>
                      )}
                    </td>
                    <td className="py-1.5 pr-3">
                      <Badge variant={HEALTH_VARIANT[row.health]} className="text-[10px]">
                        {row.health}
                      </Badge>
                    </td>
                    <td className="py-1.5 pr-3 text-muted font-mono text-[10px]">
                      {row.freshness
                        ? new Date(row.freshness).toLocaleString()
                        : '—'}
                    </td>
                    <td className="py-1.5 pr-3 text-muted">{row.confidence ?? '—'}</td>
                    <td className="py-1.5 pr-3 text-muted truncate max-w-[120px]">
                      {row.coverage ?? '—'}
                    </td>
                    <td className="py-1.5 pr-3 text-muted">{row.drift ?? '—'}</td>
                    <td className="py-1.5 pr-3 text-right">
                      {row.errors > 0 ? (
                        <span className="text-danger font-semibold">{row.errors}</span>
                      ) : (
                        <span className="text-muted">0</span>
                      )}
                    </td>
                    <td className="py-1.5 text-right">
                      {row.warnings > 0 ? (
                        <span className="text-warning font-semibold">{row.warnings}</span>
                      ) : (
                        <span className="text-muted">0</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
