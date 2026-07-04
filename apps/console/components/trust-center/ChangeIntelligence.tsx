'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-CHANGE-INTEL';
const AUTHORITY = 'Change Intelligence Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/forensics';

export type ChangeCategory =
  | 'policy' | 'evidence' | 'control' | 'decision' | 'attestation'
  | 'governance' | 'remediation' | 'simulation' | 'replay';

export interface ChangeEvent {
  id: string;
  category: ChangeCategory;
  description: string;
  who: string | null;
  when: string;
  why: string | null;
  linkedEntityId: string | null;
}

interface ChangeIntelligenceProps {
  events: ChangeEvent[];
  loading?: boolean;
  lastUpdated?: string;
}

function categoryBadge(category: ChangeCategory): 'default' | 'secondary' | 'warning' | 'success' {
  switch (category) {
    case 'policy': return 'default';
    case 'evidence': return 'secondary';
    case 'control': return 'warning';
    case 'decision': return 'success';
    case 'attestation': return 'default';
    case 'governance': return 'secondary';
    case 'remediation': return 'warning';
    case 'simulation': return 'secondary';
    case 'replay': return 'secondary';
  }
}

export default function ChangeIntelligence({ events, loading, lastUpdated }: ChangeIntelligenceProps) {
  const sorted = [...events].sort((a, b) => new Date(b.when).getTime() - new Date(a.when).getTime());

  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Chronological change event intelligence"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="polling"
      lastUpdated={lastUpdated}
      title="Change Intelligence"
    >
      <section aria-label="change-intelligence" data-testid="change-intelligence">
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <p className="text-sm text-muted">No change events recorded.</p>
      ) : (
        <div className="space-y-2">
          {sorted.map((e) => (
            <div key={e.id} className="rounded-md border border-border bg-surface-2 p-3 text-xs space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="text-muted">{new Date(e.when).toLocaleString()}</span>
                <Badge variant={categoryBadge(e.category)}>{e.category}</Badge>
              </div>
              <p className="text-foreground">{e.description}</p>
              <p className="text-muted">Who: {e.who ?? 'System'}</p>
              {e.why && <p className="text-muted italic">{e.why}</p>}
              {e.linkedEntityId && (
                <p className="font-mono text-muted">{e.linkedEntityId}</p>
              )}
            </div>
          ))}
        </div>
      )}
      </section>
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
