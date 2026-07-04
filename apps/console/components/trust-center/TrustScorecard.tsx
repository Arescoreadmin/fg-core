'use client';

import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-SCORECARD';
const AUTHORITY = 'Trust Scorecard Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

export type TrustDomain =
  | 'assessment' | 'evidence' | 'verification' | 'governance' | 'decision'
  | 'replay' | 'remediation' | 'portal' | 'customer' | 'simulation'
  | 'audit' | 'key-management';

export interface TrustScore {
  domain: TrustDomain;
  label: string;
  score: number | null;
  confidence: number | null;
  freshness: string | null;
  source: string;
  drillDown: string;
  trend: 'improving' | 'stable' | 'degrading' | null;
}

interface TrustScorecardProps {
  scores: TrustScore[];
  loading?: boolean;
  lastUpdated?: string;
}

function scoreBadgeVariant(score: number | null): 'success' | 'warning' | 'danger' | 'secondary' {
  if (score === null) return 'secondary';
  if (score >= 80) return 'success';
  if (score >= 60) return 'warning';
  return 'danger';
}

export default function TrustScorecard({ scores, loading, lastUpdated }: TrustScorecardProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Trust domain score aggregation"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Trust Scorecard"
    >
      {loading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-24 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : scores.length === 0 ? (
        <p className="text-sm text-muted">No trust scores available.</p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {scores.map((s) => (
            <div key={s.domain} className="rounded-md border border-border bg-surface-2 p-3 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">{s.label}</span>
                <Badge variant={scoreBadgeVariant(s.score)}>
                  {s.score !== null ? s.score : '—'}
                </Badge>
              </div>
              <div className="flex items-center gap-1 text-[10px] text-muted">
                {s.trend === 'improving' && <TrendingUp className="h-3 w-3 text-success" aria-hidden="true" />}
                {s.trend === 'degrading' && <TrendingDown className="h-3 w-3 text-danger" aria-hidden="true" />}
                {(s.trend === 'stable' || s.trend === null) && <Minus className="h-3 w-3" aria-hidden="true" />}
                <span>{s.trend ?? 'unknown'}</span>
              </div>
              <div className="text-[10px] text-muted">
                Confidence: {s.confidence !== null ? `${Math.round(s.confidence * 100)}%` : '—'}
              </div>
              {s.freshness && (
                <div className="text-[10px] text-muted truncate">
                  {new Date(s.freshness).toLocaleString()}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
