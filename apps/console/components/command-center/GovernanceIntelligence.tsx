'use client';

import Link from 'next/link';
import { ArrowRight, HelpCircle, TrendingDown, TrendingUp } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WidgetShell from './WidgetShell';
import type { EvaluationQualitySummary } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-INTELLIGENCE
const MCIM_ID = 'MCIM-18.6-INTELLIGENCE';
const AUTHORITY = 'Governance Intelligence Authority';
const sourceOfTruth = '/api/core/ui/evaluation/quality';
const drillDown = '/dashboard/readiness';

export interface IntelInsight {
  type: 'recommendation' | 'improvement' | 'risk' | 'benchmark';
  title: string;
  description: string;
  confidence: number;
  evidenceHref: string;
}

function buildInsightsFromQuality(quality: EvaluationQualitySummary | null): IntelInsight[] {
  if (!quality) return [];

  const insights: IntelInsight[] = [];

  if (quality.completed_run_count > 0) {
    insights.push({
      type: 'benchmark',
      title: 'Evaluation coverage active',
      description: `${quality.completed_run_count} completed evaluation run(s) across ${quality.total_queries_evaluated} queries.`,
      confidence: 0.9,
      evidenceHref: '/dashboard/readiness',
    });
  }

  if (quality.runs_with_relevance_indicators > 0) {
    insights.push({
      type: 'improvement',
      title: 'Relevance data available',
      description: `${quality.runs_with_relevance_indicators} run(s) have relevance indicators for review.`,
      confidence: 0.8,
      evidenceHref: '/dashboard/readiness',
    });
  }

  if (quality.runs_with_correctness_indicators > 0) {
    insights.push({
      type: 'recommendation',
      title: 'Correctness indicators present',
      description: `${quality.runs_with_correctness_indicators} run(s) contain correctness indicators.`,
      confidence: 0.75,
      evidenceHref: '/dashboard/readiness',
    });
  }

  if (quality.quality_note) {
    insights.push({
      type: 'risk',
      title: 'Quality note',
      description: quality.quality_note,
      confidence: 0.7,
      evidenceHref: '/dashboard/readiness',
    });
  }

  return insights;
}

function confidenceLabel(c: number): string {
  if (c >= 0.9) return 'High';
  if (c >= 0.7) return 'Medium';
  return 'Low';
}

function confidenceBadgeVariant(c: number): 'default' | 'secondary' | 'outline' {
  if (c >= 0.9) return 'default';
  if (c >= 0.7) return 'secondary';
  return 'outline';
}

const TYPE_CONFIG: Record<
  IntelInsight['type'],
  { id: string; label: string; icon: React.ComponentType<{ className?: string }> }
> = {
  recommendation: { id: 'intel-recommendations', label: 'Recommendation', icon: TrendingUp },
  improvement: { id: 'intel-projected-improvements', label: 'Improvement', icon: TrendingUp },
  risk: { id: 'intel-projected-risks', label: 'Risk', icon: TrendingDown },
  benchmark: { id: 'intel-benchmark', label: 'Benchmark', icon: TrendingUp },
};

interface GovernanceIntelligenceProps {
  quality: EvaluationQualitySummary | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function GovernanceIntelligence({
  quality,
  loading = false,
  lastUpdated,
}: GovernanceIntelligenceProps) {
  const insights = loading ? [] : buildInsightsFromQuality(quality);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Governance Intelligence"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Governance Intelligence"
    >
      <div aria-label="governance-intelligence">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-14 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : insights.length === 0 ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No intelligence data available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <ul className="space-y-2" role="list">
            {insights.map((insight, i) => {
              const config = TYPE_CONFIG[insight.type];
              const Icon = config.icon;

              return (
                <li
                  key={i}
                  data-testid={config.id}
                  aria-label={config.id}
                  className="rounded-md border border-border p-3"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Icon className="h-3.5 w-3.5 text-primary shrink-0" aria-hidden="true" />
                        <span className="text-[10px] font-semibold text-muted uppercase">{config.label}</span>
                        <Badge
                          variant={confidenceBadgeVariant(insight.confidence)}
                          className="text-[9px]"
                          data-testid="intel-confidence"
                          aria-label="intel-confidence"
                        >
                          {confidenceLabel(insight.confidence)} confidence
                        </Badge>
                      </div>
                      <p className="mt-1 text-sm font-medium text-foreground">{insight.title}</p>
                      <p className="mt-0.5 text-xs text-muted">{insight.description}</p>
                    </div>
                    <Link
                      href={insight.evidenceHref}
                      className="shrink-0 text-primary hover:text-primary/80"
                      aria-label={`View evidence for ${insight.title}`}
                    >
                      <ArrowRight className="h-4 w-4" aria-hidden="true" />
                    </Link>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </WidgetShell>
  );
}
