'use client';

import { AlertTriangle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-ASSURANCE';
const AUTHORITY = 'Continuous Assurance Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/policies';

export type ControlStatus = 'passing' | 'failing' | 'drifted' | 'unknown';

export interface AssuranceControl {
  id: string;
  name: string;
  status: ControlStatus;
  coverage: number | null;
  lastAttestation: string | null;
  driftDetected: boolean;
  policyRef: string;
}

interface ContinuousAssurancePanelProps {
  controls: AssuranceControl[];
  loading?: boolean;
  lastUpdated?: string;
}

function statusVariant(status: ControlStatus): 'success' | 'danger' | 'warning' | 'secondary' {
  switch (status) {
    case 'passing': return 'success';
    case 'failing': return 'danger';
    case 'drifted': return 'warning';
    case 'unknown': return 'secondary';
  }
}

export default function ContinuousAssurancePanel({ controls, loading, lastUpdated }: ContinuousAssurancePanelProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Continuous control assurance and drift detection"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Continuous Assurance Panel"
    >
      <section aria-label="continuous-assurance-panel" data-testid="continuous-assurance">
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : controls.length === 0 ? (
        <p className="text-sm text-muted">No controls registered.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="pb-2 pr-3 font-medium">Control Name</th>
                <th className="pb-2 pr-3 font-medium">Status</th>
                <th className="pb-2 pr-3 font-medium">Coverage</th>
                <th className="pb-2 pr-3 font-medium">Last Attestation</th>
                <th className="pb-2 font-medium">Drift</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {controls.map((c) => (
                <tr key={c.id} className="text-foreground">
                  <td className="py-2 pr-3 font-medium">{c.name}</td>
                  <td className="py-2 pr-3">
                    <Badge variant={statusVariant(c.status)}>{c.status}</Badge>
                  </td>
                  <td className="py-2 pr-3">
                    {c.coverage !== null ? `${c.coverage}%` : '—'}
                  </td>
                  <td className="py-2 pr-3">
                    {c.lastAttestation ? new Date(c.lastAttestation).toLocaleString() : '—'}
                  </td>
                  <td className="py-2">
                    {c.driftDetected ? (
                      <span className="inline-flex items-center gap-1 text-warning">
                        <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                        Detected
                      </span>
                    ) : (
                      <span className="text-success">Clean</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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
