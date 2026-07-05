'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-SCANS';
const AUTHORITY = 'Scan History Panel Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/findings';
const customerSafe = true;

export interface PortalScan {
  id: string;
  sourceType: string;
  collectedAt: string;
  objectCount: number;
  findingCount: number | null;
  evidenceHash: string;
}

interface Props {
  scans: PortalScan[];
  loading: boolean;
  lastUpdated?: string;
}

export default function ScanHistoryPanel({ scans, loading, lastUpdated }: Props) {
  const sorted = [...scans].sort(
    (a, b) => new Date(b.collectedAt).getTime() - new Date(a.collectedAt).getTime(),
  );

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Scan History"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Scan History"
      lastUpdated={lastUpdated}
    >
      <section aria-label="scan-history-panel" data-testid="scan-history-panel">
        <div className="mb-3 rounded border border-border bg-muted/10 px-3 py-2 text-xs text-muted">
          Scan records show evidence collection events. No raw scan payloads are displayed.
        </div>

        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && sorted.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No scan records available for this engagement.</p>
        )}

        {!loading && sorted.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted text-left">
                  <th className="pb-2 pr-4 font-medium">Source Type</th>
                  <th className="pb-2 pr-4 font-medium">Collected At</th>
                  <th className="pb-2 pr-4 font-medium text-right">Objects</th>
                  <th className="pb-2 pr-4 font-medium text-right">Findings</th>
                  <th className="pb-2 font-medium">Evidence Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {sorted.map((scan) => (
                  <tr key={scan.id} className="text-foreground">
                    <td className="py-2 pr-4 font-mono text-sm">{scan.sourceType}</td>
                    <td className="py-2 pr-4 text-muted">{new Date(scan.collectedAt).toLocaleString()}</td>
                    <td className="py-2 pr-4 text-right font-mono">{scan.objectCount}</td>
                    <td className="py-2 pr-4 text-right font-mono">{scan.findingCount ?? '—'}</td>
                    <td className="py-2 font-mono text-[10px] text-muted" title={scan.evidenceHash}>
                      {scan.evidenceHash.slice(0, 12)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
