'use client';

import { Badge } from '@/components/ui/badge';
import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { Button } from '@/components/ui/button';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-PROVENANCE';
const AUTHORITY = 'Decision Provenance Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/decisions';

export type ProvenanceStage =
  | 'assessment' | 'evidence' | 'verification' | 'remediation'
  | 'policy' | 'simulation' | 'replay' | 'decision' | 'customer-impact';

export interface ProvenanceLink {
  stage: ProvenanceStage;
  entityId: string | null;
  label: string;
  completedAt: string | null;
  actor: string | null;
  notes: string | null;
}

export interface DecisionProvenance {
  decisionId: string;
  chain: ProvenanceLink[];
}

interface DecisionProvenanceExplorerProps {
  provenances: DecisionProvenance[];
  loading?: boolean;
  lastUpdated?: string;
}

function ProvenanceItem({ provenance }: { provenance: DecisionProvenance }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-md border border-border bg-surface-2">
      <div className="flex items-center justify-between px-3 py-2">
        <div className="flex items-center gap-3 text-xs">
          <span className="font-mono font-medium text-foreground">{provenance.decisionId}</span>
          <span className="text-muted">{provenance.chain.length} stages</span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs text-muted"
          aria-expanded={expanded}
          aria-controls={`provenance-chain-${provenance.decisionId}`}
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? <ChevronUp className="h-3 w-3" aria-hidden="true" /> : <ChevronDown className="h-3 w-3" aria-hidden="true" />}
        </Button>
      </div>
      {expanded && (
        <div
          id={`provenance-chain-${provenance.decisionId}`}
          className="border-t border-border px-3 py-2"
        >
          <div className="flex flex-wrap gap-2">
            {provenance.chain.map((link, idx) => (
              <div key={idx} className="flex flex-col rounded-md border border-border bg-muted/20 p-2 text-[10px] min-w-[120px]">
                <span className="font-semibold text-foreground">{link.label}</span>
                <span className="text-muted mt-0.5">Actor: {link.actor ?? '—'}</span>
                <span className="text-muted">
                  {link.completedAt ? new Date(link.completedAt).toLocaleString() : 'Pending'}
                </span>
                {link.notes && <span className="text-muted mt-0.5 italic">{link.notes}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function DecisionProvenanceExplorer({ provenances, loading, lastUpdated }: DecisionProvenanceExplorerProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Decision provenance chain exploration"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Decision Provenance Explorer"
    >
      <section aria-label="decision-provenance-explorer" data-testid="decision-provenance">
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : provenances.length === 0 ? (
        <p className="text-sm text-muted">No provenance chains available.</p>
      ) : (
        <div className="space-y-2">
          {provenances.map((p) => (
            <ProvenanceItem key={p.decisionId} provenance={p} />
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
