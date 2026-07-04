'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-CASE-REL';
const AUTHORITY = 'Case Relationships Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/forensics';

export type RelationshipType =
  | 'spawned-by' | 'linked-to' | 'evidence-for' | 'resolved-by'
  | 'escalated-to' | 'depends-on';

export interface CaseRelationship {
  fromCaseId: string;
  toCaseId: string;
  relationshipType: RelationshipType;
  authoritySource: string;
  establishedAt: string;
  notes: string | null;
}

interface CaseRelationshipsProps {
  relationships: CaseRelationship[];
  loading?: boolean;
  lastUpdated?: string;
}

export default function CaseRelationships({ relationships, loading, lastUpdated }: CaseRelationshipsProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Authoritative case relationship mapping"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Case Relationships"
    >
      <section aria-label="case-relationships" data-testid="case-relationships">
      <div className="mb-3 rounded-md border border-border bg-muted/20 px-3 py-2 text-xs text-muted">
        Only authoritative relationships are displayed. All links are established by authoritative sources.
      </div>
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : relationships.length === 0 ? (
        <p className="text-sm text-muted">No case relationships recorded.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="pb-2 pr-3 font-medium">From Case</th>
                <th className="pb-2 pr-3 font-medium">To Case</th>
                <th className="pb-2 pr-3 font-medium">Relationship</th>
                <th className="pb-2 pr-3 font-medium">Authority Source</th>
                <th className="pb-2 pr-3 font-medium">Established At</th>
                <th className="pb-2 font-medium">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {relationships.map((r, idx) => (
                <tr key={idx} className="text-foreground">
                  <td className="py-2 pr-3 font-mono">{r.fromCaseId}</td>
                  <td className="py-2 pr-3 font-mono">{r.toCaseId}</td>
                  <td className="py-2 pr-3">
                    <Badge variant="secondary">{r.relationshipType}</Badge>
                  </td>
                  <td className="py-2 pr-3">{r.authoritySource}</td>
                  <td className="py-2 pr-3">{new Date(r.establishedAt).toLocaleString()}</td>
                  <td className="py-2 text-muted">{r.notes ?? '—'}</td>
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
