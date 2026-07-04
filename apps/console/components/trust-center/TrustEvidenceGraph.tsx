'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-EVIDENCE-GRAPH';
const AUTHORITY = 'Trust Evidence Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/provenance';

export type TrustState = 'verified' | 'pending' | 'disputed' | 'expired';

export interface EvidenceNode {
  id: string;
  authority: string;
  mcimId: string;
  evidenceCount: number;
  verificationState: 'verified' | 'unverified' | 'partial';
  trustState: TrustState;
  confidence: number | null;
  freshness: string | null;
}

interface TrustEvidenceGraphProps {
  nodes: EvidenceNode[];
  loading?: boolean;
  lastUpdated?: string;
}

function trustStateBadge(state: TrustState): 'success' | 'warning' | 'danger' | 'secondary' {
  switch (state) {
    case 'verified': return 'success';
    case 'pending': return 'warning';
    case 'disputed': return 'danger';
    case 'expired': return 'secondary';
  }
}

function verificationBadge(state: 'verified' | 'unverified' | 'partial'): 'success' | 'warning' | 'secondary' {
  switch (state) {
    case 'verified': return 'success';
    case 'partial': return 'warning';
    case 'unverified': return 'secondary';
  }
}

export default function TrustEvidenceGraph({ nodes, loading, lastUpdated }: TrustEvidenceGraphProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Evidence node trust state and verification tracking"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Trust Evidence Graph"
    >
      <section aria-label="trust-evidence-graph" data-testid="trust-evidence-graph">
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : nodes.length === 0 ? (
        <p className="text-sm text-muted">No evidence nodes available.</p>
      ) : (
        <div className="space-y-2">
          {nodes.map((n) => (
            <div key={n.id} className="rounded-md border border-border bg-surface-2 p-3 text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-medium text-foreground">{n.authority}</span>
                <div className="flex items-center gap-1.5">
                  <Badge variant={trustStateBadge(n.trustState)}>{n.trustState}</Badge>
                  <Badge variant={verificationBadge(n.verificationState)}>{n.verificationState}</Badge>
                </div>
              </div>
              <div className="flex items-center gap-3 text-muted">
                <span className="font-mono">{n.mcimId}</span>
                <span>Evidence: {n.evidenceCount}</span>
                <span>Confidence: {n.confidence !== null ? `${Math.round(n.confidence * 100)}%` : '—'}</span>
                {n.freshness && <span>{new Date(n.freshness).toLocaleString()}</span>}
              </div>
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
