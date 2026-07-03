'use client';

import { AlertCircle, AlertTriangle, Info, TrendingDown, TrendingUp } from 'lucide-react';
import WidgetShell from './WidgetShell';

// MCIM reference: MCIM-18.6-FIELD-ASSESSMENT
const MCIM_ID = 'MCIM-18.6-FIELD-ASSESSMENT';
const AUTHORITY = 'Field Assessment Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements/{id}/findings';
const drillDown = '/field-assessment';

export interface RiskCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  trendDirection?: 'up' | 'down' | 'flat';
  trendNote?: string;
}

interface RiskBarProps {
  id: string;
  label: string;
  count: number;
  max: number;
  colorClass: string;
  textClass: string;
}

function RiskBar({ id, label, count, max, colorClass, textClass }: RiskBarProps) {
  const pct = max > 0 ? Math.min(100, Math.round((count / max) * 100)) : 0;

  return (
    <div aria-label={id} data-testid={id} className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className={`font-semibold ${textClass}`}>{label}</span>
        <span className="font-bold text-foreground">{count}</span>
      </div>
      <div className="h-2 rounded-full bg-muted/30">
        <div
          className={`h-2 rounded-full ${colorClass} transition-all`}
          style={{ width: `${pct}%` }}
          aria-valuenow={count}
          aria-valuemax={max}
          role="progressbar"
          aria-label={`${label} risk count`}
        />
      </div>
    </div>
  );
}

const IMPACT_LABELS: Array<{ label: string; description: string }> = [
  { label: 'Business', description: 'Revenue, brand, partnerships' },
  { label: 'Operational', description: 'Availability, continuity' },
  { label: 'Regulatory', description: 'Compliance, penalties, fines' },
  { label: 'Customer', description: 'Data, trust, SLAs' },
];

interface ExecutiveRiskMapProps {
  counts: RiskCounts | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function ExecutiveRiskMap({
  counts,
  loading = false,
  lastUpdated,
}: ExecutiveRiskMapProps) {
  const total =
    counts !== null
      ? counts.critical + counts.high + counts.medium + counts.low
      : 0;

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Executive Risk Map"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Risk Map"
    >
      <div aria-label="executive-risk-map">
        <p className="text-[10px] uppercase tracking-wide text-muted mb-2" data-testid="risk-map-authority">
          Authority: {AUTHORITY}
        </p>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-8 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : counts === null ? (
          <div
            className="py-6 text-center text-sm text-muted"
            data-testid="risk-no-data"
            aria-label="risk-no-data"
          >
            <AlertCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No risk data available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Risk bars */}
            <div className="space-y-2">
              <RiskBar
                id="risk-critical"
                label="Critical"
                count={counts.critical}
                max={total}
                colorClass="bg-danger"
                textClass="text-danger"
              />
              <RiskBar
                id="risk-high"
                label="High"
                count={counts.high}
                max={total}
                colorClass="bg-warning"
                textClass="text-warning"
              />
              <RiskBar
                id="risk-medium"
                label="Medium"
                count={counts.medium}
                max={total}
                colorClass="bg-yellow-500"
                textClass="text-yellow-600"
              />
              <RiskBar
                id="risk-low"
                label="Low"
                count={counts.low}
                max={total}
                colorClass="bg-success"
                textClass="text-success"
              />
            </div>

            {/* Trend */}
            {counts.trendDirection && (
              <div
                className="flex items-center gap-1.5 text-xs text-muted"
                data-testid="risk-trend"
                aria-label="risk-trend"
              >
                {counts.trendDirection === 'up' ? (
                  <TrendingDown className="h-3.5 w-3.5 text-danger" aria-hidden="true" />
                ) : counts.trendDirection === 'down' ? (
                  <TrendingUp className="h-3.5 w-3.5 text-success" aria-hidden="true" />
                ) : (
                  <Info className="h-3.5 w-3.5 text-muted" aria-hidden="true" />
                )}
                <span>{counts.trendNote ?? `${total} total findings`}</span>
              </div>
            )}

            {/* Impact labels */}
            <div className="border-t border-border pt-3">
              <h3 className="text-[10px] font-semibold uppercase tracking-wide text-muted mb-2">
                Impact Dimensions
              </h3>
              <div className="grid grid-cols-2 gap-1.5">
                {IMPACT_LABELS.map(({ label, description }) => (
                  <div key={label} className="rounded-md bg-muted/20 px-2 py-1.5">
                    <p className="text-[10px] font-semibold text-foreground">{label}</p>
                    <p className="text-[9px] text-muted leading-tight">{description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </WidgetShell>
  );
}
