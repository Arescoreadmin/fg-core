'use client';

import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-WORKSPACE-INTEL';
const AUTHORITY = 'Workspace Intelligence Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

// Prioritization is deterministic — no randomness or ML inference.

export type PrioritySignal =
  | 'critical-finding' | 'overdue-review' | 'policy-drift' | 'attestation-due'
  | 'sla-risk' | 'evidence-gap' | 'governance-block' | 'replay-needed';

export interface IntelligenceItem {
  id: string;
  signal: PrioritySignal;
  description: string;
  affectedEntityId: string | null;
  affectedAuthority: string;
  priorityScore: number;
  suggestedAction: string;
  drillDownPath: string;
}

interface WorkspaceIntelligenceProps {
  items: IntelligenceItem[];
  loading?: boolean;
  lastUpdated?: string;
}

function priorityBadge(score: number): 'danger' | 'warning' | 'secondary' {
  if (score >= 70) return 'danger';
  if (score >= 40) return 'warning';
  return 'secondary';
}

export default function WorkspaceIntelligence({ items, loading, lastUpdated }: WorkspaceIntelligenceProps) {
  const sorted = [...items].sort((a, b) => b.priorityScore - a.priorityScore);

  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Deterministic priority intelligence signals"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="polling"
      lastUpdated={lastUpdated}
      title="Workspace Intelligence"
    >
      <section aria-label="workspace-intelligence" data-testid="workspace-intelligence">
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <p className="text-sm text-muted">No actionable intelligence signals.</p>
      ) : (
        <div className="space-y-2">
          {sorted.map((item) => (
            <div key={item.id} className="rounded-md border border-border bg-surface-2 p-3 text-xs space-y-1">
              <div className="flex items-center gap-2">
                <Badge variant={priorityBadge(item.priorityScore)}>{item.priorityScore}</Badge>
                <span className="font-medium text-foreground">{item.signal}</span>
                <span className="text-muted">{item.affectedAuthority}</span>
              </div>
              <p className="text-foreground">{item.description}</p>
              <p className="text-muted italic">{item.suggestedAction}</p>
              <Link
                href={item.drillDownPath}
                className="text-primary hover:underline"
              >
                View details
              </Link>
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
