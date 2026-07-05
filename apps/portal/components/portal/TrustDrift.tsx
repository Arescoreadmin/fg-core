'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-TRUST-DRIFT';
const AUTHORITY = 'Trust Drift Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/trust';
const customerSafe = true;

export interface TrustSnapshot {
  snapshotId: string;
  takenAt: string;
  domain: string;
  score: number | null;
  status: string;
}

export interface TrustDriftData {
  lastSnapshot: TrustSnapshot | null;
  currentSnapshot: TrustSnapshot | null;
  delta: {
    domain: string;
    change: number | null;
    direction: 'improved' | 'regressed' | 'stable' | 'unavailable';
  }[];
  hasAuthorativeData: boolean;
}

interface Props {
  data: TrustDriftData | null;
  loading: boolean;
  lastUpdated?: string;
}

const DIRECTION_CLASS: Record<string, string> = {
  improved: 'border-green-500/40 bg-green-500/10 text-green-300',
  regressed: 'border-red-500/40 bg-red-500/10 text-red-300',
  stable: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  unavailable: 'border-border bg-surface-2 text-muted',
};

function DirectionBadge({ direction }: { direction: string }) {
  const cls = DIRECTION_CLASS[direction] ?? DIRECTION_CLASS.unavailable;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {direction.charAt(0).toUpperCase() + direction.slice(1)}
    </span>
  );
}

function SnapshotCard({ label, snapshot }: { label: string; snapshot: TrustSnapshot | null }) {
  return (
    <div className="rounded border border-border bg-surface-2 p-3 flex-1 min-w-[160px] space-y-1">
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">{label}</p>
      {snapshot ? (
        <>
          <p className="text-2xl font-semibold text-foreground">
            {snapshot.score != null ? snapshot.score : '—'}
          </p>
          <p className="text-xs text-muted">{snapshot.domain}</p>
          <p className="text-xs text-muted">{snapshot.status}</p>
          <p className="text-[10px] text-muted">{new Date(snapshot.takenAt).toLocaleDateString()}</p>
        </>
      ) : (
        <p className="text-sm text-muted">Not available</p>
      )}
    </div>
  );
}

export default function TrustDrift({ data, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Trust Drift"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Trust Drift"
      lastUpdated={lastUpdated}
    >
      {loading && (
        <div className="space-y-3" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && (!data || !data.hasAuthorativeData) && (
        <p className="text-sm text-muted text-center py-8">
          No authoritative drift data available. Drift analysis requires two or more snapshots.
        </p>
      )}

      {!loading && data && data.hasAuthorativeData && (
        <div className="space-y-5">
          {/* Snapshots comparison */}
          <div className="flex flex-wrap gap-3">
            <SnapshotCard label="Last Snapshot" snapshot={data.lastSnapshot} />
            <div className="flex items-center text-muted text-xl select-none self-center" aria-hidden="true">
              →
            </div>
            <SnapshotCard label="Current Snapshot" snapshot={data.currentSnapshot} />
          </div>

          {/* Delta table */}
          {data.delta.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border text-muted">
                    <th className="text-left py-2 pr-4 font-medium">Domain</th>
                    <th className="text-right py-2 pr-4 font-medium">Change</th>
                    <th className="text-left py-2 font-medium">Direction</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data.delta.map((row, i) => (
                    <tr key={i} className="text-foreground">
                      <td className="py-2 pr-4">{row.domain}</td>
                      <td className={`py-2 pr-4 text-right font-mono ${
                        row.direction === 'improved'
                          ? 'text-green-300'
                          : row.direction === 'regressed'
                          ? 'text-red-300'
                          : 'text-muted'
                      }`}>
                        {row.change != null
                          ? `${row.change > 0 ? '+' : ''}${row.change}`
                          : '—'}
                      </td>
                      <td className="py-2">
                        <DirectionBadge direction={row.direction} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
