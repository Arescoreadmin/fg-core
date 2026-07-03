'use client';

import { AlertCircle, AlertTriangle, CheckCircle2, HelpCircle, XCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WidgetShell from './WidgetShell';
import type { ControlTowerSnapshotV1 } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-TRUST-CENTER
const MCIM_ID = 'MCIM-18.6-TRUST-CENTER';
const AUTHORITY = 'Trust Center Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/forensics';

export type HealthState =
  | 'healthy'
  | 'needs-attention'
  | 'elevated-risk'
  | 'critical'
  | 'blocked';

function deriveHealthState(snapshot: ControlTowerSnapshotV1 | null): {
  state: HealthState;
  reason: string;
  recommendations: string[];
} {
  if (!snapshot) {
    return {
      state: 'blocked',
      reason: 'Control tower snapshot unavailable — cannot assess health.',
      recommendations: ['Restore connectivity to admin-gateway.'],
    };
  }

  const chainFail = snapshot.chain_integrity.status !== 'pass';
  const quarantineCount = snapshot.agents.quarantine_count;
  const connectorErrors = snapshot.connectors.errors.length;
  const incidentCount = snapshot.audit_incidents.recent_events.length;
  const lockerStatus = snapshot.lockers.status;

  const recommendations: string[] = [];

  if (lockerStatus !== 'ok' && lockerStatus !== 'healthy') {
    recommendations.push(`Investigate locker status: ${lockerStatus}`);
  }
  if (chainFail) {
    recommendations.push('Review chain integrity failures in Forensics.');
  }
  if (quarantineCount > 0) {
    recommendations.push(`Review ${quarantineCount} quarantined agent(s).`);
  }
  if (connectorErrors > 0) {
    recommendations.push(`Resolve ${connectorErrors} connector error(s).`);
  }
  if (incidentCount > 0) {
    recommendations.push(`Review ${incidentCount} recent audit incident(s).`);
  }

  if (chainFail && quarantineCount > 0) {
    return {
      state: 'critical',
      reason: 'Chain integrity failure with quarantined agents detected.',
      recommendations,
    };
  }
  if (chainFail) {
    return {
      state: 'elevated-risk',
      reason: 'Chain integrity failure detected.',
      recommendations,
    };
  }
  if (quarantineCount > 0 || connectorErrors > 0) {
    return {
      state: 'needs-attention',
      reason: `${quarantineCount} quarantined agent(s) and ${connectorErrors} connector error(s).`,
      recommendations,
    };
  }
  if (incidentCount > 0) {
    return {
      state: 'needs-attention',
      reason: `${incidentCount} recent audit incident(s) require review.`,
      recommendations,
    };
  }

  return {
    state: 'healthy',
    reason: 'All monitored systems operational.',
    recommendations: [],
  };
}

const STATE_CONFIG: Record<
  HealthState,
  {
    label: string;
    id: string;
    badgeVariant: 'default' | 'secondary' | 'destructive' | 'outline';
    Icon: React.ComponentType<{ className?: string }>;
    textClass: string;
  }
> = {
  healthy: {
    label: 'Healthy',
    id: 'health-healthy',
    badgeVariant: 'default',
    Icon: CheckCircle2,
    textClass: 'text-success',
  },
  'needs-attention': {
    label: 'Needs Attention',
    id: 'health-needs-attention',
    badgeVariant: 'secondary',
    Icon: AlertTriangle,
    textClass: 'text-warning',
  },
  'elevated-risk': {
    label: 'Elevated Risk',
    id: 'health-elevated-risk',
    badgeVariant: 'secondary',
    Icon: AlertCircle,
    textClass: 'text-warning',
  },
  critical: {
    label: 'Critical',
    id: 'health-critical',
    badgeVariant: 'destructive',
    Icon: XCircle,
    textClass: 'text-danger',
  },
  blocked: {
    label: 'Blocked',
    id: 'health-blocked',
    badgeVariant: 'destructive',
    Icon: HelpCircle,
    textClass: 'text-danger',
  },
};

interface ExecutiveHealthPanelProps {
  snapshot: ControlTowerSnapshotV1 | null;
  loading?: boolean;
  confidence?: number;
  lastUpdated?: string;
}

export default function ExecutiveHealthPanel({
  snapshot,
  loading = false,
  confidence,
  lastUpdated,
}: ExecutiveHealthPanelProps) {
  const { state, reason, recommendations } = deriveHealthState(
    loading ? null : snapshot,
  );
  const config = STATE_CONFIG[state];
  const Icon = config.Icon;

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Operational Health Panel"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      confidence={confidence}
      lastUpdated={lastUpdated}
      title="Platform Health"
    >
      <div aria-label="executive-health-panel">
        {loading ? (
          <div className="space-y-2">
            <div className="h-6 w-32 animate-pulse rounded bg-muted" />
            <div className="h-4 w-48 animate-pulse rounded bg-muted" />
          </div>
        ) : (
          <>
            <div
              className={`flex items-center gap-2 ${config.textClass}`}
              data-health-state={config.id}
              aria-label={config.id}
            >
              <Icon className="h-5 w-5 shrink-0" aria-hidden="true" />
              <span className="text-lg font-bold">{config.label}</span>
              <Badge variant={config.badgeVariant} className="ml-1 text-[10px]">
                {MCIM_ID}
              </Badge>
            </div>

            <p className="mt-2 text-sm text-muted">{reason}</p>

            {snapshot && (
              <div className="mt-3 text-xs text-muted space-y-1">
                <p>
                  <span className="font-semibold">Evidence:</span>{' '}
                  Control tower snapshot — chain:{' '}
                  <span className="font-mono">
                    {snapshot.chain_integrity.status}
                  </span>
                  , agents: {snapshot.agents.total}, connectors:{' '}
                  {snapshot.connectors.enabled}
                </p>
                <p>
                  <span className="font-semibold">Authority:</span> {AUTHORITY}
                </p>
              </div>
            )}

            {recommendations.length > 0 && (
              <div className="mt-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted mb-1">
                  Recommendations
                </h3>
                <ul className="space-y-1 text-xs text-muted list-disc ml-4">
                  {recommendations.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </WidgetShell>
  );
}
