'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  portalApi,
  type AttestationHealthSummary,
  type ContinuityGap,
} from '@/lib/portalApi';

const RISK_CLASS: Record<string, string> = {
  critical: 'text-red-300',
  high: 'text-orange-300',
  medium: 'text-amber-200',
  low: 'text-blue-300',
};

const RISK_BORDER: Record<string, string> = {
  critical: 'border-red-500/30 bg-red-500/5',
  high: 'border-orange-500/30 bg-orange-500/5',
  medium: 'border-amber-500/30 bg-amber-500/5',
  low: 'border-blue-500/30 bg-blue-500/5',
};

function HealthMeter({ health }: { health: AttestationHealthSummary }) {
  const pct = Math.round(health.health_pct * 100) / 100;
  const barColor =
    pct >= 80 ? 'bg-green-400' : pct >= 60 ? 'bg-amber-400' : 'bg-red-400';

  return (
    <div className="rounded border border-border bg-surface-2 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold text-muted uppercase tracking-wider">
          Attestation Health
        </p>
        <span className={`text-lg font-semibold ${pct >= 80 ? 'text-green-300' : pct >= 60 ? 'text-amber-200' : 'text-red-300'}`}>
          {pct.toFixed(1)}%
        </span>
      </div>

      <div className="w-full h-2 rounded-full bg-surface-3 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${barColor}`}
          style={{ width: `${Math.min(100, pct)}%` }}
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Attestation health percentage"
        />
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
        <div>
          <dt className="text-muted">Compliant</dt>
          <dd className="font-semibold text-green-300">{health.compliant}</dd>
        </div>
        <div>
          <dt className="text-muted">Due Soon</dt>
          <dd className="font-semibold text-amber-200">{health.due_soon}</dd>
        </div>
        <div>
          <dt className="text-muted">Overdue</dt>
          <dd className="font-semibold text-red-300">{health.overdue}</dd>
        </div>
        <div>
          <dt className="text-muted">Never Attested</dt>
          <dd className="font-semibold text-muted">{health.never_attested}</dd>
        </div>
      </dl>
    </div>
  );
}

function GapCard({ gap }: { gap: ContinuityGap }) {
  const riskCls = RISK_CLASS[gap.risk_tier] ?? 'text-muted';
  const borderCls = RISK_BORDER[gap.risk_tier] ?? 'border-border bg-surface-2';

  return (
    <div className={`rounded border p-3 space-y-1.5 ${borderCls}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium text-foreground">{gap.asset_name}</p>
        <span className={`text-xs font-medium capitalize ${riskCls}`}>
          {gap.risk_tier.replace(/_/g, ' ')} risk
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-4 text-xs text-muted">
        <span className="capitalize">{gap.asset_type.replace(/_/g, ' ')}</span>
        <span className={gap.days_overdue > 0 ? 'text-red-300 font-medium' : 'text-amber-200'}>
          {gap.days_overdue > 0
            ? `${gap.days_overdue} day${gap.days_overdue !== 1 ? 's' : ''} overdue`
            : 'Due soon'}
        </span>
        {gap.staleness_index > 0 && (
          <span>Staleness: {gap.staleness_index}</span>
        )}
      </div>
    </div>
  );
}

type RiskFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

export default function ContinuityPage() {
  const [health, setHealth] = useState<AttestationHealthSummary | null>(null);
  const [gaps, setGaps] = useState<ContinuityGap[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [overdueOnly, setOverdueOnly] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [healthResult, gapsResult] = await Promise.all([
        portalApi.getAttestationHealth(),
        portalApi.listContinuityGaps(),
      ]);
      setHealth(healthResult);
      setGaps(gapsResult.items);
    } catch {
      setError('Failed to load continuity data. Please try again.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const filteredGaps = gaps
    .filter((g) => riskFilter === 'all' || g.risk_tier === riskFilter)
    .filter((g) => !overdueOnly || g.days_overdue > 0)
    .sort((a, b) => (riskOrder[a.risk_tier] ?? 9) - (riskOrder[b.risk_tier] ?? 9));

  const overdueCount = gaps.filter((g) => g.days_overdue > 0).length;
  const dueSoonCount = gaps.filter((g) => g.days_overdue <= 0).length;

  return (
    <div className="space-y-5" aria-label="continuity-page">
      <div>
        <h2 className="text-base font-semibold text-foreground">Continuity Compliance</h2>
        {!loading && (overdueCount > 0 || dueSoonCount > 0) && (
          <p className="text-xs text-muted mt-0.5">
            {overdueCount > 0 && (
              <span className="text-red-300">{overdueCount} overdue</span>
            )}
            {overdueCount > 0 && dueSoonCount > 0 && <span> · </span>}
            {dueSoonCount > 0 && (
              <span className="text-amber-200">{dueSoonCount} due soon</span>
            )}
          </p>
        )}
      </div>

      {loading && (
        <div className="space-y-3" aria-busy="true">
          <div className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
          <div className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
          <div className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
        </div>
      )}

      {error && !loading && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {!loading && !error && (
        <>
          {health && <HealthMeter health={health} />}

          {gaps.length > 0 && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs font-semibold text-muted uppercase tracking-wider">
                  Continuity Gaps ({gaps.length})
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <label className="flex items-center gap-1.5 text-xs text-muted cursor-pointer">
                    <input
                      type="checkbox"
                      checked={overdueOnly}
                      onChange={(e) => setOverdueOnly(e.target.checked)}
                      className="rounded"
                    />
                    Overdue only
                  </label>
                  <select
                    className="rounded border border-border bg-surface-2 text-xs px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
                    value={riskFilter}
                    onChange={(e) => setRiskFilter(e.target.value as RiskFilter)}
                    aria-label="Filter by risk tier"
                  >
                    <option value="all">All risk tiers</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              {filteredGaps.length === 0 ? (
                <p className="text-xs text-muted text-center py-8">
                  No gaps match the selected filters.
                </p>
              ) : (
                <div className="space-y-2">
                  {filteredGaps.map((gap) => (
                    <GapCard key={gap.asset_id} gap={gap} />
                  ))}
                </div>
              )}
            </div>
          )}

          {gaps.length === 0 && health && (
            <div className="flex flex-col items-center justify-center py-16 text-center text-muted">
              <p className="text-sm font-medium text-green-300">All assets are compliant</p>
              <p className="text-xs mt-1">No continuity gaps detected.</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
