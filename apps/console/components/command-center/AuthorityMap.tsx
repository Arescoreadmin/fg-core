'use client';

import { Badge } from '@/components/ui/badge';
import WidgetShell from './WidgetShell';
import type { ControlTowerSnapshotV1 } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-AUTHORITY-MAP
const MCIM_ID = 'MCIM-18.6-AUTHORITY-MAP';
const AUTHORITY = 'Navigation Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

type AuthorityHealth = 'ok' | 'warning' | 'error' | 'unknown' | 'from-snapshot';

interface AuthorityEntry {
  id: string;
  name: string;
  mcim: string;
  route: string;
  surface: string;
  health: AuthorityHealth;
}

const AUTHORITY_ENTRIES: AuthorityEntry[] = [
  {
    id: 'control-tower',
    name: 'Control Tower Authority',
    mcim: 'MCIM-18.6-TRUST-CENTER',
    route: '/dashboard/control-tower',
    surface: 'console',
    health: 'from-snapshot',
  },
  {
    id: 'governance',
    name: 'Governance Authority',
    mcim: 'MCIM-18.6-GOVERNANCE',
    route: '/dashboard/readiness',
    surface: 'console',
    health: 'unknown',
  },
  {
    id: 'decision-provenance',
    name: 'Decision Provenance Authority',
    mcim: 'MCIM-18.6-DECISION-PROVENANCE',
    route: '/dashboard/decisions',
    surface: 'console',
    health: 'unknown',
  },
  {
    id: 'field-assessment',
    name: 'Field Assessment Authority',
    mcim: 'MCIM-18.6-FIELD-ASSESSMENT',
    route: '/field-assessment',
    surface: 'console',
    health: 'unknown',
  },
  {
    id: 'readiness',
    name: 'Readiness Authority',
    mcim: 'MCIM-18.6-READINESS',
    route: '/dashboard/readiness',
    surface: 'console',
    health: 'unknown',
  },
  {
    id: 'compliance',
    name: 'Compliance Authority',
    mcim: 'MCIM-18.6-COMPLIANCE',
    route: '/dashboard/readiness',
    surface: 'console',
    health: 'unknown',
  },
  {
    id: 'trust',
    name: 'Trust Center Authority',
    mcim: 'MCIM-18.6-TRUST-CENTER',
    route: '/dashboard/forensics',
    surface: 'console',
    health: 'from-snapshot',
  },
  {
    id: 'intelligence',
    name: 'Governance Intelligence Authority',
    mcim: 'MCIM-18.6-INTELLIGENCE',
    route: '/dashboard/evaluation',
    surface: 'console',
    health: 'unknown',
  },
];

function resolveHealth(
  entry: AuthorityEntry,
  snapshot: ControlTowerSnapshotV1 | null,
): 'ok' | 'warning' | 'error' | 'unknown' {
  if (entry.health !== 'from-snapshot') {
    return entry.health as 'ok' | 'warning' | 'error' | 'unknown';
  }
  if (!snapshot) return 'unknown';
  const chainOk = snapshot.chain_integrity.status === 'pass';
  return chainOk ? 'ok' : 'warning';
}

function healthVariant(
  health: 'ok' | 'warning' | 'error' | 'unknown',
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

function healthLabel(health: 'ok' | 'warning' | 'error' | 'unknown'): string {
  switch (health) {
    case 'ok':
      return 'Active';
    case 'warning':
      return 'Degraded';
    case 'error':
      return 'Error';
    default:
      return 'Unknown';
  }
}

interface AuthorityMapProps {
  snapshot: ControlTowerSnapshotV1 | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function AuthorityMap({
  snapshot,
  loading = false,
  lastUpdated,
}: AuthorityMapProps) {
  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Authority Map"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="static"
      lastUpdated={lastUpdated}
      title="Authority Map"
    >
      <div aria-label="authority-map" data-testid="authority-map">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-8 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : (
          <ul className="space-y-1.5" role="list">
            {AUTHORITY_ENTRIES.map((entry) => {
              const resolvedHealth = resolveHealth(entry, snapshot);
              return (
                <li
                  key={entry.id}
                  data-testid={`authority-${entry.id}`}
                  aria-label={`authority-${entry.id}`}
                  className="flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="text-[11px] font-medium text-foreground truncate">{entry.name}</p>
                    <p className="text-[9px] text-muted font-mono">{entry.mcim}</p>
                  </div>
                  <Badge variant={healthVariant(resolvedHealth)} className="text-[9px] shrink-0">
                    {healthLabel(resolvedHealth)}
                  </Badge>
                </li>
              );
            })}
          </ul>
        )}
        <p className="mt-2 text-[9px] text-muted/50">
          Authority: {AUTHORITY} · {MCIM_ID}
        </p>
      </div>
    </WidgetShell>
  );
}
