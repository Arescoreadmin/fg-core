'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-AUDIT-READY';
const AUTHORITY = 'Audit Readiness Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/alignment';

export type ReadinessStatus = 'ready' | 'partial' | 'not-ready' | 'unknown';

export interface AuditDomain {
  id: string;
  name: string;
  status: ReadinessStatus;
  requiredItems: number;
  completedItems: number;
  blockers: string[];
  lastReviewed: string | null;
}

interface AuditReadinessWorkspaceProps {
  domains: AuditDomain[];
  loading?: boolean;
  lastUpdated?: string;
}

function statusVariant(status: ReadinessStatus): 'success' | 'warning' | 'danger' | 'secondary' {
  switch (status) {
    case 'ready': return 'success';
    case 'partial': return 'warning';
    case 'not-ready': return 'danger';
    case 'unknown': return 'secondary';
  }
}

function DomainRow({ domain }: { domain: AuditDomain }) {
  const [blockersOpen, setBlockersOpen] = useState(false);

  return (
    <div className="rounded-md border border-border bg-surface-2">
      <div className="flex items-center gap-3 px-3 py-2 text-xs">
        <span className="flex-1 font-medium text-foreground">{domain.name}</span>
        <Badge variant={statusVariant(domain.status)}>{domain.status}</Badge>
        <span className="text-muted">{domain.completedItems}/{domain.requiredItems}</span>
        <span className="text-muted">{domain.lastReviewed ? new Date(domain.lastReviewed).toLocaleDateString() : 'Never'}</span>
        {domain.blockers.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs text-muted"
            aria-expanded={blockersOpen}
            aria-controls={`blockers-${domain.id}`}
            onClick={() => setBlockersOpen((v) => !v)}
          >
            {domain.blockers.length} blocker{domain.blockers.length !== 1 ? 's' : ''}
            {blockersOpen ? <ChevronUp className="ml-1 h-3 w-3" aria-hidden="true" /> : <ChevronDown className="ml-1 h-3 w-3" aria-hidden="true" />}
          </Button>
        )}
      </div>
      {blockersOpen && domain.blockers.length > 0 && (
        <div id={`blockers-${domain.id}`} className="border-t border-border px-3 py-2">
          <ul className="list-disc list-inside space-y-0.5 text-[10px] text-danger">
            {domain.blockers.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function AuditReadinessWorkspace({ domains, loading, lastUpdated }: AuditReadinessWorkspaceProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Audit readiness assessment across domains"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Audit Readiness Workspace"
    >
      <section aria-label="audit-readiness-workspace" data-testid="audit-readiness">
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : domains.length === 0 ? (
        <p className="text-sm text-muted">No audit domains configured.</p>
      ) : (
        <div className="space-y-2">
          {domains.map((d) => (
            <DomainRow key={d.id} domain={d} />
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
