'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-SLA';
const AUTHORITY = 'SLA Forecasting Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/workforce';

export type SLARisk = 'on-track' | 'at-risk' | 'breached' | 'unknown';

export interface SLAForecast {
  id: string;
  workType: string;
  currentQueueDepth: number;
  historicalAvgHours: number;
  forecastedCompletionHours: number;
  slaLimitHours: number;
  risk: SLARisk;
  dataPointCount: number;
  lastUpdated: string;
}

interface SLAForecastingProps {
  forecasts: SLAForecast[];
  hasHistoricalData: boolean;
  loading?: boolean;
  lastUpdated?: string;
}

function riskBadge(risk: SLARisk): 'success' | 'warning' | 'danger' | 'secondary' {
  switch (risk) {
    case 'on-track': return 'success';
    case 'at-risk': return 'warning';
    case 'breached': return 'danger';
    case 'unknown': return 'secondary';
  }
}

export default function SLAForecasting({ forecasts, hasHistoricalData, loading, lastUpdated }: SLAForecastingProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Historical-data SLA forecasting"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="SLA Forecasting"
    >
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : !hasHistoricalData ? (
        <div className="rounded-md border border-border bg-muted/20 px-3 py-3 text-xs text-muted">
          Insufficient historical data for SLA forecasting.
        </div>
      ) : forecasts.length === 0 ? (
        <div className="rounded-md border border-border bg-muted/20 px-3 py-3 text-xs text-muted">
          Insufficient historical data for SLA forecasting.
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted text-left">
                  <th className="pb-2 pr-3 font-medium">Work Type</th>
                  <th className="pb-2 pr-3 font-medium">Queue Depth</th>
                  <th className="pb-2 pr-3 font-medium">Avg Hours</th>
                  <th className="pb-2 pr-3 font-medium">Forecasted Hours</th>
                  <th className="pb-2 pr-3 font-medium">SLA Limit</th>
                  <th className="pb-2 pr-3 font-medium">Risk</th>
                  <th className="pb-2 font-medium">Data Points</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {forecasts.map((f) => (
                  <tr key={f.id} className="text-foreground">
                    <td className="py-2 pr-3 font-medium">{f.workType}</td>
                    <td className="py-2 pr-3">{f.currentQueueDepth}</td>
                    <td className="py-2 pr-3">{f.historicalAvgHours}h</td>
                    <td className="py-2 pr-3">{f.forecastedCompletionHours}h</td>
                    <td className="py-2 pr-3">{f.slaLimitHours}h</td>
                    <td className="py-2 pr-3">
                      <Badge variant={riskBadge(f.risk)}>{f.risk}</Badge>
                    </td>
                    <td className="py-2">{f.dataPointCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[10px] text-muted">
            Forecasts are based on historical data only. Not a guarantee.
          </p>
        </>
      )}
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
