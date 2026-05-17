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
        <FrameworkSelector
          onAssessmentSelect={handleAssessmentSelect}
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

            <div className="grid gap-4 lg:grid-cols-2">
              <EvidenceCompleteness score={data.score} />
              <GovernanceDrift
                thresholdFailures={data.score.threshold_failures}
                scoringWarnings={data.score.scoring_warnings}
              />
            </div>

            <DomainHeatmap domainScores={data.score.domain_scores} />

            <div className="grid gap-4 lg:grid-cols-2">
              <HighRiskGaps gaps={data.gap.gaps} blockers={data.gap.readiness_blockers} />
              <RemediationQueue recommendations={data.gap.remediation_recommendations} />
            </div>

            <EvidenceBasisPanel controlScores={data.score.control_scores} />

            <div className="grid gap-4 lg:grid-cols-2">
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
