'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-BOTTLENECK';
const AUTHORITY = 'Bottleneck Analysis Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/workforce';

export type BottleneckStage =
  | 'approval' | 'review' | 'verification' | 'report' | 'portal' | 'remediation';

export interface BottleneckEntry {
  stage: BottleneckStage;
  label: string;
  queueDepth: number;
  avgWaitHours: number | null;
  blockedItems: number;
  criticalItems: number;
  trend: 'improving' | 'stable' | 'worsening' | null;
}

interface BottleneckAnalysisProps {
  entries: BottleneckEntry[];
  loading?: boolean;
  lastUpdated?: string;
}

function trendBadge(trend: BottleneckEntry['trend']): 'success' | 'secondary' | 'danger' {
  switch (trend) {
    case 'improving': return 'success';
    case 'stable': return 'secondary';
    case 'worsening': return 'danger';
    default: return 'secondary';
  }
}

export default function BottleneckAnalysis({ entries, loading, lastUpdated }: BottleneckAnalysisProps) {
  const sorted = [...entries].sort((a, b) => b.criticalItems - a.criticalItems);

  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Workflow bottleneck detection and queue analysis"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="polling"
      lastUpdated={lastUpdated}
      title="Bottleneck Analysis"
    >
      <section aria-label="bottleneck-analysis" data-testid="bottleneck-analysis">
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <p className="text-sm text-muted">No bottleneck data available.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="pb-2 pr-3 font-medium">Stage</th>
                <th className="pb-2 pr-3 font-medium">Queue Depth</th>
                <th className="pb-2 pr-3 font-medium">Avg Wait</th>
                <th className="pb-2 pr-3 font-medium">Blocked</th>
                <th className="pb-2 pr-3 font-medium">Critical</th>
                <th className="pb-2 font-medium">Trend</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sorted.map((e) => (
                <tr key={e.stage} className="text-foreground">
                  <td className="py-2 pr-3 font-medium">{e.label}</td>
                  <td className="py-2 pr-3">{e.queueDepth}</td>
                  <td className="py-2 pr-3">
                    {e.avgWaitHours !== null ? `${e.avgWaitHours}h` : 'N/A'}
                  </td>
                  <td className="py-2 pr-3">{e.blockedItems}</td>
                  <td className="py-2 pr-3">
                    {e.criticalItems > 0 ? (
                      <Badge variant="danger">{e.criticalItems}</Badge>
                    ) : (
                      <span>{e.criticalItems}</span>
                    )}
                  </td>
                  <td className="py-2">
                    <Badge variant={trendBadge(e.trend)}>{e.trend ?? 'unknown'}</Badge>
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
