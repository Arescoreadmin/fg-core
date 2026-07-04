'use client';

import { Badge } from '@/components/ui/badge';
import WidgetShell from './WidgetShell';
import type { ControlTowerSnapshotV1 } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-HEALTH-MATRIX
const MCIM_ID = 'MCIM-18.6-HEALTH-MATRIX';
const AUTHORITY = 'Operational Health Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

type HealthStatus = 'ok' | 'warning' | 'error' | 'unknown';

interface MatrixRow {
  id: string;
  label: string;
  health: HealthStatus;
  detail: string;
  authority: string;
  drillDown: string;
}

function healthVariant(
  health: HealthStatus,
): 'success' | 'warning' | 'danger' | 'outline' {
  switch (health) {
    case 'ok':
      return 'success';
    case 'warning':
      return 'warning';
    case 'error':
      return 'danger';
    default:
      return 'outline';
  }
}

function healthLabel(health: HealthStatus): string {
  switch (health) {
    case 'ok':
      return 'OK';
    case 'warning':
      return 'Warning';
    case 'error':
      return 'Error';
    default:
      return 'Unknown';
  }
}

function deriveRows(snapshot: ControlTowerSnapshotV1 | null): MatrixRow[] {
  const snap = snapshot;

  const chainHealth: HealthStatus = snap
    ? snap.chain_integrity.status === 'pass'
      ? 'ok'
      : 'error'
    : 'unknown';

  const agentsHealth: HealthStatus = snap
    ? snap.agents.quarantine_count === 0
      ? 'ok'
      : 'warning'
    : 'unknown';

  const connectorHealth: HealthStatus = snap
    ? snap.connectors.errors.length === 0
      ? 'ok'
      : 'warning'
    : 'unknown';

  const keysHealth: HealthStatus = snap
    ? snap.key_lifecycle
      ? snap.key_lifecycle.active_key_count > 0
        ? 'ok'
        : 'warning'
      : 'unknown'
    : 'unknown';

  const lockersHealth: HealthStatus = snap
    ? snap.lockers.status === 'running'
      ? 'ok'
      : 'warning'
    : 'unknown';

  const auditHealth: HealthStatus = snap ? 'ok' : 'unknown';

  const controlTowerHealth: HealthStatus = snap
    ? chainHealth === 'ok' && agentsHealth === 'ok' && connectorHealth === 'ok'
      ? 'ok'
      : 'warning'
    : 'unknown';

  return [
    {
      id: 'control-tower',
      label: 'Control Tower',
      health: controlTowerHealth,
      detail: snap
        ? `Chain: ${snap.chain_integrity.status}, Agents: ${snap.agents.total}`
        : 'No snapshot data',
      authority: AUTHORITY,
      drillDown: '/dashboard/control-tower',
    },
    {
      id: 'chain-integrity',
      label: 'Chain Integrity',
      health: chainHealth,
      detail: snap ? `Status: ${snap.chain_integrity.status}` : 'No data',
      authority: 'Trust Center Authority',
      drillDown: '/dashboard/forensics',
    },
    {
      id: 'agents',
      label: 'Agents',
      health: agentsHealth,
      detail: snap
        ? `Total: ${snap.agents.total}, Quarantined: ${snap.agents.quarantine_count}`
        : 'No data',
      authority: AUTHORITY,
      drillDown: '/dashboard/control-tower',
    },
    {
      id: 'connectors',
      label: 'Connectors',
      health: connectorHealth,
      detail: snap
        ? `Enabled: ${snap.connectors.enabled}, Errors: ${snap.connectors.errors.length}`
        : 'No data',
      authority: AUTHORITY,
      drillDown: '/dashboard/control-tower',
    },
    {
      id: 'keys',
      label: 'Keys',
      health: keysHealth,
      detail: snap
        ? `Active: ${snap.key_lifecycle.active_key_count}`
        : 'No data',
      authority: AUTHORITY,
      drillDown: '/dashboard/control-tower',
    },
    {
      id: 'lockers',
      label: 'Lockers',
      health: lockersHealth,
      detail: snap ? `Status: ${snap.lockers.status}, Count: ${snap.lockers.count}` : 'No data',
      authority: AUTHORITY,
      drillDown: '/dashboard/control-tower',
    },
    {
      id: 'audit',
      label: 'Audit',
      health: auditHealth,
      detail: snap ? 'Audit system active' : 'No data',
      authority: 'Governance Authority',
      drillDown: '/dashboard/forensics',
    },
    {
      id: 'billing',
      label: 'Billing',
      health: 'unknown',
      detail: 'Not in snapshot',
      authority: 'Billing Authority',
      drillDown: '/dashboard',
    },
    {
      id: 'identity',
      label: 'Identity',
      health: 'unknown',
      detail: 'Not in snapshot',
      authority: 'Identity Authority',
      drillDown: '/dashboard',
    },
    {
      id: 'navigation',
      label: 'Navigation',
      health: 'ok',
      detail: 'Registry loaded',
      authority: 'Navigation Authority',
      drillDown: '/dashboard',
    },
  ];
}

interface OperationalHealthMatrixProps {
  snapshot: ControlTowerSnapshotV1 | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function OperationalHealthMatrix({
  snapshot,
  loading = false,
  lastUpdated,
}: OperationalHealthMatrixProps) {
  const rows = loading ? [] : deriveRows(snapshot);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Operational Health Matrix"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Operational Health Matrix"
    >
      <div
        aria-label="operational-health-matrix"
        data-testid="operational-health-matrix"
      >
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-8 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : (
          <table role="table" className="w-full text-[11px]">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="pb-1.5 font-semibold text-muted/70 uppercase tracking-wide">System</th>
                <th className="pb-1.5 font-semibold text-muted/70 uppercase tracking-wide text-center">Status</th>
                <th className="pb-1.5 font-semibold text-muted/70 uppercase tracking-wide hidden sm:table-cell">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  aria-label={`matrix-row-${row.id}`}
                  data-testid={`matrix-row-${row.id}`}
                  className="border-b border-border/50 last:border-0"
                >
                  <td className="py-1.5 font-medium text-foreground">{row.label}</td>
                  <td className="py-1.5 text-center">
                    <Badge variant={healthVariant(row.health)} className="text-[9px]">
                      {healthLabel(row.health)}
                    </Badge>
                  </td>
                  <td className="py-1.5 text-muted hidden sm:table-cell truncate max-w-[160px]">
                    {row.detail}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="mt-2 text-[9px] text-muted/50">
          Authority: {AUTHORITY} · {MCIM_ID}
        </p>
      </div>
    </WidgetShell>
  );
}
