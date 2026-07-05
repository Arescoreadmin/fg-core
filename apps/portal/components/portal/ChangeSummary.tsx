'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-CHANGES';
const AUTHORITY = 'Change Summary Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/changes';
const customerSafe = true;

export interface ChangeGroup {
  category: 'findings' | 'reports' | 'remediation' | 'trust' | 'evidence' | 'attestations';
  newCount: number;
  changedCount: number;
  closedCount: number;
  summary: string | null;
}

interface Props {
  groups: ChangeGroup[];
  sinceTimestamp: string | null;
  hasHistoricalState: boolean;
  loading: boolean;
  lastUpdated?: string;
}

const CATEGORY_LABEL: Record<ChangeGroup['category'], string> = {
  findings: 'Findings',
  reports: 'Reports',
  remediation: 'Remediation',
  trust: 'Trust',
  evidence: 'Evidence',
  attestations: 'Attestations',
};

export default function ChangeSummary({
  groups,
  sinceTimestamp,
  hasHistoricalState,
  loading,
  lastUpdated,
}: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Change Summary"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Change Summary"
      lastUpdated={lastUpdated}
    >
      <section aria-label="change-summary" data-testid="change-summary">
      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && !hasHistoricalState && (
        <p className="text-sm text-muted text-center py-8">
          No prior portal visit state available. Change summary requires a baseline snapshot.
        </p>
      )}

      {!loading && hasHistoricalState && (
        <>
          {sinceTimestamp && (
            <p className="text-xs text-muted mb-3">
              Changes since: {new Date(sinceTimestamp).toLocaleString()}
            </p>
          )}

          {groups.length === 0 ? (
            <p className="text-sm text-muted text-center py-8">
              No changes detected since last snapshot.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border text-muted">
                    <th className="text-left py-2 pr-4 font-medium">Category</th>
                    <th className="text-right py-2 pr-4 font-medium">New</th>
                    <th className="text-right py-2 pr-4 font-medium">Changed</th>
                    <th className="text-right py-2 pr-4 font-medium">Closed</th>
                    <th className="text-left py-2 font-medium">Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {groups.map((group) => (
                    <tr key={group.category} className="text-foreground">
                      <td className="py-2 pr-4 font-medium">
                        {CATEGORY_LABEL[group.category]}
                      </td>
                      <td className={`py-2 pr-4 text-right font-mono ${group.newCount > 0 ? 'text-green-300' : 'text-muted'}`}>
                        {group.newCount}
                      </td>
                      <td className={`py-2 pr-4 text-right font-mono ${group.changedCount > 0 ? 'text-amber-200' : 'text-muted'}`}>
                        {group.changedCount}
                      </td>
                      <td className="py-2 pr-4 text-right font-mono text-muted">
                        {group.closedCount}
                      </td>
                      <td className="py-2 text-muted">
                        {group.summary ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
