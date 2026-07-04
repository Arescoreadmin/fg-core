'use client';

import Link from 'next/link';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-CMD-CENTER';
const AUTHORITY = 'Command Center Integration Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

export interface IntegrationLink {
  label: string;
  description: string;
  path: string;
  authority: string;
  mcimId: string;
}

const INTEGRATION_LINKS: IntegrationLink[] = [
  { label: 'Control Tower', description: 'Snapshot authority and chain integrity', path: '/dashboard/control-tower', authority: 'Control Tower Authority', mcimId: 'MCIM-18.6-CONTROL-TOWER' },
  { label: 'Forensics', description: 'Investigation and evidence timeline', path: '/dashboard/forensics', authority: 'Forensics Authority', mcimId: 'MCIM-18.6-FORENSICS' },
  { label: 'Decision Hub', description: 'Governance decisions and approvals', path: '/dashboard/decisions', authority: 'Decision Authority', mcimId: 'MCIM-18.6-DECISIONS' },
  { label: 'Provenance', description: 'Evidence lineage and sourcing', path: '/dashboard/provenance', authority: 'Provenance Authority', mcimId: 'MCIM-18.6-PROVENANCE' },
  { label: 'Alignment', description: 'Reports and portal alignment', path: '/dashboard/alignment', authority: 'Alignment Authority', mcimId: 'MCIM-18.6-ALIGNMENT' },
  { label: 'Policies', description: 'Policy enforcement and drift', path: '/dashboard/policies', authority: 'Policy Authority', mcimId: 'MCIM-18.6-POLICIES' },
  { label: 'Readiness', description: 'Verification and readiness state', path: '/dashboard/readiness', authority: 'Readiness Authority', mcimId: 'MCIM-18.6-READINESS' },
  { label: 'Evaluation', description: 'Simulation and scenario evaluation', path: '/dashboard/evaluation', authority: 'Evaluation Authority', mcimId: 'MCIM-18.6-EVALUATION' },
  { label: 'Assessment', description: 'Assessment intake and workflow', path: '/assessment', authority: 'Assessment Authority', mcimId: 'MCIM-18.6-ASSESSMENT' },
  { label: 'Governance Topology', description: 'Governance structure and hierarchy', path: '/governance/topology', authority: 'Governance Authority', mcimId: 'MCIM-18.6-GOVERNANCE' },
];

interface CommandCenterIntegrationProps {
  loading?: boolean;
}

export default function CommandCenterIntegration({ loading }: CommandCenterIntegrationProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Cross-dashboard command center navigation"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="static"
      title="Command Center Integration"
    >
      <section aria-label="command-center-integration" data-testid="command-center-integration">
      {loading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-20 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {INTEGRATION_LINKS.map((link) => (
            <Link
              key={link.mcimId}
              href={link.path}
              className="rounded-md border border-border bg-surface-2 p-3 hover:bg-muted/30 transition-colors block"
            >
              <p className="text-xs font-bold text-foreground">{link.label}</p>
              <p className="mt-0.5 text-[11px] text-muted">{link.description}</p>
              <p className="mt-1 font-mono text-[10px] text-muted">{link.authority}</p>
              <p className="font-mono text-[10px] text-muted">{link.mcimId}</p>
            </Link>
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
