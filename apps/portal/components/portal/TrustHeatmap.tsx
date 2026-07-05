'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-TRUST-HEATMAP';
const AUTHORITY = 'Trust Heatmap Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/trust';
const customerSafe = true;

export type HeatmapDimension =
  | 'freshness' | 'integrity' | 'verification' | 'coverage' | 'confidence' | 'replayability';

export interface HeatmapCell {
  dimension: HeatmapDimension;
  label: string;
  score: number | null;
  status: 'good' | 'moderate' | 'weak' | 'unavailable';
  lastUpdated: string | null;
}

interface Props {
  cells: HeatmapCell[];
  loading: boolean;
  lastUpdated?: string;
}

const STATUS_BG: Record<string, string> = {
  good: 'border-green-500/40 bg-green-500/10',
  moderate: 'border-amber-500/40 bg-amber-500/10',
  weak: 'border-red-500/40 bg-red-500/10',
  unavailable: 'border-border bg-surface-2',
};

const STATUS_SCORE_CLASS: Record<string, string> = {
  good: 'text-green-300',
  moderate: 'text-amber-200',
  weak: 'text-red-300',
  unavailable: 'text-muted',
};

const STATUS_LABEL_CLASS: Record<string, string> = {
  good: 'text-green-300',
  moderate: 'text-amber-200',
  weak: 'text-red-300',
  unavailable: 'text-muted',
};

export default function TrustHeatmap({ cells, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Trust Heatmap"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Trust Heatmap"
      lastUpdated={lastUpdated}
    >
      {loading && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3" aria-busy="true">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && cells.length === 0 && (
        <p className="text-sm text-muted text-center py-8">No heatmap data available.</p>
      )}

      {!loading && cells.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {cells.map((cell) => (
            <div
              key={cell.dimension}
              className={`rounded border p-3 space-y-1 ${STATUS_BG[cell.status] ?? STATUS_BG.unavailable}`}
            >
              <p className="text-xs font-medium text-foreground">{cell.label}</p>
              <p className={`text-2xl font-semibold ${STATUS_SCORE_CLASS[cell.status]}`}>
                {cell.score != null ? cell.score : '—'}
              </p>
              <p className={`text-xs font-medium ${STATUS_LABEL_CLASS[cell.status]}`}>
                {cell.status.charAt(0).toUpperCase() + cell.status.slice(1)}
              </p>
              {cell.lastUpdated && (
                <p className="text-[10px] text-muted">
                  {new Date(cell.lastUpdated).toLocaleDateString()}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
