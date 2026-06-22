'use client';

import { useCallback, useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import {
  DomainHeatmap,
  EvidenceBasisPanel,
  EvidenceCompleteness,
  EvidenceLineage,
  FrameworkSelector,
  GovernanceDrift,
  HighRiskGaps,
  ReadinessOverview,
  RemediationQueue,
  SnapshotContext,
} from '@/components/readiness';
import {
  getAssessment,
  getGapAnalysis,
  getScore,
  type Assessment,
  type GapAnalysisResult,
  type ScoreOutput,
} from '@/lib/readinessApi';

interface DashboardData {
  score: ScoreOutput;
  gap: GapAnalysisResult;
  assessment: Assessment;
}

export default function ReadinessPage() {
  const [selectedFrameworkId, setSelectedFrameworkId] = useState<string | null>(null);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAssessmentSelect = useCallback((frameworkId: string, assessmentId: string) => {
    setSelectedFrameworkId(frameworkId);
    setSelectedAssessmentId(assessmentId);
    setData(null);
    setError(null);
  }, []);

  // P2: clear stale dashboard data when the framework changes so operators
  // never see a prior assessment's scores under a newly-selected framework.
  const handleFrameworkChange = useCallback((_frameworkId: string) => {
    setSelectedAssessmentId(null);
    setData(null);
    setError(null);
  }, []);

  useEffect(() => {
    if (!selectedAssessmentId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      getScore(selectedAssessmentId),
      getGapAnalysis(selectedAssessmentId),
      getAssessment(selectedAssessmentId),
    ]).then(([scoreResult, gapResult, assessmentResult]) => {
      if (cancelled) return;
      setLoading(false);
      if (!scoreResult.ok) { setError(scoreResult.error); return; }
      if (!gapResult.ok) { setError(gapResult.error); return; }
      if (!assessmentResult.ok) { setError(assessmentResult.error); return; }
      setData({ score: scoreResult.data, gap: gapResult.data, assessment: assessmentResult.data });
    });

    return () => { cancelled = true; };
  }, [selectedAssessmentId]);

  return (
    <div className="flex flex-col">
      <TopBar title="Readiness" subtitle="Compliance readiness assessment and gap analysis" />
      <div className="flex flex-col gap-4 p-6">
        {/*
          Gap 3 seam: cross-framework comparison mode.
          FrameworkSelector will grow a multi-select / "Compare" toggle here.
          onFrameworkChange gives the page a stable clear-data hook regardless of
          how the selector evolves internally.
        */}
        <FrameworkSelector
          onAssessmentSelect={handleAssessmentSelect}
          onFrameworkChange={handleFrameworkChange}
          selectedFrameworkId={selectedFrameworkId}
          selectedAssessmentId={selectedAssessmentId}
        />

        {loading && (
          <div
            className="flex items-center gap-2 text-sm text-muted-foreground"
            aria-label="dashboard-loading"
          >
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            Loading readiness data…
          </div>
        )}

        {error && (
          <p className="text-sm text-risk-critical" aria-label="dashboard-error">
            {error}
          </p>
        )}

        {data && (
          <div className="flex flex-col gap-4" aria-label="readiness-dashboard">
            <ReadinessOverview score={data.score} />

            {/*
              Gap 1 seam: temporal trend visualization.
              A ScoreHistoryChart / posture-trend-panel component slots here once
              getScoreHistory() is wired to the backend history endpoint.
              aria-label="posture-trend-panel" reserved for future DOM assertions.
            */}

            <div className="grid gap-4 lg:grid-cols-2">
              <EvidenceCompleteness score={data.score} />
              <GovernanceDrift
                thresholdFailures={data.score.threshold_failures}
                scoringWarnings={data.score.scoring_warnings}
              />
            </div>

            <DomainHeatmap domainScores={data.score.domain_scores} />

            <div className="grid gap-4 lg:grid-cols-2">
              {/*
                Gap 2 seam: "Why This Matters" operational impact layer.
                HighRiskGaps will accept an optional operationalImpacts prop once
                GapAnalysisResult grows the operational_impacts field.
                aria-label="operational-impact-panel" reserved.
              */}
              <HighRiskGaps gaps={data.gap.gaps} blockers={data.gap.readiness_blockers} />
              <RemediationQueue recommendations={data.gap.remediation_recommendations} />
            </div>

            <EvidenceBasisPanel controlScores={data.score.control_scores} />

            {/*
              Gap 5 seam: runtime governance correlation.
              A RuntimeCorrelationPanel slots here, fed by getRuntimeCorrelation(),
              connecting live retrieval drift and provenance failures to this posture.
              aria-label="runtime-correlation-panel" reserved.
            */}

            <div className="grid gap-4 lg:grid-cols-2">
              {/*
                Gap 4 seam: reviewer workflow context.
                SnapshotContext will grow a ReviewerContext section once
                getReviewerContext() is wired — signoff state, approval lineage,
                governance acknowledgment for regulated industries.
                aria-label="reviewer-workflow-panel" reserved.
              */}
              <SnapshotContext contract={data.gap.replay_contract} assessment={data.assessment} />
              <EvidenceLineage freshnessRecords={data.gap.evidence_freshness_records} />
            </div>
          </div>
        )}

        {!selectedAssessmentId && !loading && !data && (
          <p className="text-xs text-muted-foreground" aria-label="dashboard-hint">
            Select a framework and assessment above to load the readiness dashboard.
          </p>
        )}
      </div>
    </div>
  );
}
