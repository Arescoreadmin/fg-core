'use client';

import { useEffect, useCallback, Suspense, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { CheckCircle2, ChevronLeft, ChevronRight, Clock, Zap, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { useAssessmentStore, type AssessmentQuestion } from '@/lib/store';
import { assessmentApi } from '@/lib/assessmentApi';
import { reportApi } from '@/lib/reportApi';

// ─── Question renderer ────────────────────────────────────────────────────────

function QuestionCard({
  question,
  value,
  onChange,
}: {
  question: AssessmentQuestion;
  value: boolean | number | string | undefined;
  onChange: (v: boolean | number | string) => void;
}) {
  const DOMAIN_COLORS: Record<string, string> = {
    data_governance: 'text-info border-info/20 bg-info/5',
    security_posture: 'text-danger border-danger/20 bg-danger/5',
    ai_maturity: 'text-primary border-primary/20 bg-primary/5',
    infra_readiness: 'text-warning border-warning/20 bg-warning/5',
    compliance_awareness: 'text-success border-success/20 bg-success/5',
    automation_potential: 'text-muted border-border bg-surface-2',
  };

  const domainStyle = DOMAIN_COLORS[question.domain] ?? 'text-muted border-border bg-surface-2';

  return (
    <Card className="animate-slide-up">
      <CardHeader>
        <div className="flex items-center gap-2 mb-2">
          <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${domainStyle}`}>
            {question.domain.replace(/_/g, ' ')}
          </span>
        </div>
        <CardTitle className="text-base leading-snug">{question.text}</CardTitle>
      </CardHeader>
      <CardContent>
        {question.type === 'boolean' && (
          <div className="flex gap-3">
            {[true, false].map((opt) => (
              <button
                key={String(opt)}
                onClick={() => onChange(opt)}
                className={`flex-1 rounded-lg border py-3 text-sm font-medium transition-all ${
                  value === opt
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border bg-surface-2 text-muted hover:border-primary/40 hover:text-foreground'
                }`}
              >
                {opt ? 'Yes' : 'No'}
              </button>
            ))}
          </div>
        )}

        {question.type === 'scale' && (
          <div className="space-y-3">
            <div className="flex gap-2">
              {[1, 2, 3, 4, 5].map((n) => (
                <button
                  key={n}
                  onClick={() => onChange(n)}
                  className={`flex-1 rounded-lg border py-3 text-sm font-medium transition-all ${
                    value === n
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border bg-surface-2 text-muted hover:border-primary/40 hover:text-foreground'
                  }`}
                >
                  {n}
                </button>
              ))}
            </div>
            <div className="flex justify-between text-xs text-muted">
              <span>1 — None / Not started</span>
              <span>5 — Fully implemented</span>
            </div>
          </div>
        )}

        {question.type === 'select' && question.options && (
          <div className="space-y-2">
            {question.options.map((opt) => (
              <button
                key={opt}
                onClick={() => onChange(opt)}
                className={`w-full rounded-lg border px-4 py-3 text-left text-sm transition-all ${
                  value === opt
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border bg-surface-2 text-muted hover:border-primary/40 hover:text-foreground'
                }`}
              >
                {opt}
              </button>
            ))}
          </div>
        )}

        {question.type === 'text' && (
          <textarea
            className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary resize-none"
            rows={3}
            placeholder="Describe your current approach…"
            value={typeof value === 'string' ? value : ''}
            onChange={(e) => onChange(e.target.value)}
          />
        )}
      </CardContent>
    </Card>
  );
}

// ─── Completion screen ────────────────────────────────────────────────────────

function CompletionScreen({
  assessmentId,
  score,
  riskBand,
}: {
  assessmentId: string;
  score: number;
  riskBand: string;
}) {
  const router = useRouter();
  const [, setReportId] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState('');

  const handleGenerateReport = async () => {
    setGenerating(true);
    setError('');
    try {
      const result = await reportApi.generate(assessmentId, 'executive');
      setReportId(() => result.report_id);
      router.push(`/reports/${result.report_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
      setGenerating(false);
    }
  };

  const riskColor = {
    critical: 'text-risk-critical',
    high: 'text-risk-high',
    medium: 'text-risk-medium',
    low: 'text-risk-low',
  }[riskBand] ?? 'text-foreground';

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-success/10 border border-success/30 mb-6">
        <CheckCircle2 className="h-8 w-8 text-success" />
      </div>
      <h1 className="text-2xl font-bold text-foreground mb-2">Assessment Complete</h1>
      <p className="text-muted text-sm mb-8 text-center max-w-sm">
        Your AI governance risk score has been calculated. Generate your full advisory report to see
        your detailed findings and remediation roadmap.
      </p>

      <Card className="w-full max-w-sm text-center mb-6">
        <CardContent className="pt-6">
          <p className="text-xs text-muted uppercase tracking-wide mb-1">Overall Risk Score</p>
          <p className={`text-5xl font-bold ${riskColor}`}>{score}</p>
          <p className="text-sm text-muted mt-1">out of 100</p>
          <Badge
            variant={riskBand as 'critical' | 'high' | 'medium' | 'low'}
            className="mt-3 capitalize"
          >
            {riskBand} Risk
          </Badge>
        </CardContent>
      </Card>

      {error && (
        <div className="mb-4 rounded-lg border border-danger/30 bg-danger/5 px-4 py-3 w-full max-w-sm">
          <p className="text-sm text-danger">{error}</p>
        </div>
      )}

      <Button size="lg" onClick={handleGenerateReport} loading={generating} className="gap-2">
        <Zap className="h-4 w-4" />
        Generate AI Advisory Report
      </Button>
      <p className="mt-3 text-xs text-muted">
        Powered by Claude · Executive, Technical, and Compliance variants available
      </p>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

function AssessmentContent() {
  const searchParams = useSearchParams();
  const assessmentId = searchParams.get('id') ?? '';
  const paymentSuccess = searchParams.get('payment') === 'success';
  const {
    questions,
    responses,
    currentIndex,
    lastSaved,
    setQuestions,
    setResponse,
    setCurrentIndex,
    setLastSaved,
  } = useAssessmentStore();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [finalScore, setFinalScore] = useState(0);
  const [finalRiskBand, setFinalRiskBand] = useState('high');
  const [showPaymentBanner, setShowPaymentBanner] = useState(paymentSuccess);

  // Load questions on mount
  useEffect(() => {
    if (!assessmentId) {
      setError('No assessment ID. Please start from onboarding.');
      setLoading(false);
      return;
    }
    assessmentApi
      .getQuestions(assessmentId)
      .then((qs) => {
        setQuestions(qs);
        setLoading(false);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to load questions');
        setLoading(false);
      });
  }, [assessmentId, setQuestions]);

  // Autosave every 30 seconds
  const saveNow = useCallback(() => {
    if (!assessmentId || Object.keys(responses).length === 0) return;
    assessmentApi
      .saveResponses(assessmentId, responses)
      .then(() => setLastSaved(new Date()))
      .catch(() => {});
  }, [assessmentId, responses, setLastSaved]);

  useEffect(() => {
    const interval = setInterval(saveNow, 30_000);
    return () => clearInterval(interval);
  }, [saveNow]);

  const handleSubmit = async () => {
    setSubmitting(true);
    setError('');
    try {
      await assessmentApi.saveResponses(assessmentId, responses);
      const result = await assessmentApi.submitAssessment(assessmentId);
      setFinalScore(result.overall_score);
      setFinalRiskBand(result.risk_band);
      setSubmitted(true);
      // Persist domain scores so dashboard can display them without a list endpoint.
      try {
        sessionStorage.setItem('fg_last_assessment_scores', JSON.stringify(result.domain_scores));
      } catch {
        // sessionStorage unavailable — dashboard will show empty state
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Submission failed';
      // 402 = payment not yet confirmed (webhook race condition)
      if (msg.includes('402')) {
        setError(
          'Payment confirmation is still processing. Please wait a moment and try again.'
        );
      } else {
        setError(msg);
      }
      setSubmitting(false);
    }
  };

  if (submitted) {
    return (
      <CompletionScreen
        assessmentId={assessmentId}
        score={finalScore}
        riskBand={finalRiskBand}
      />
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent mx-auto mb-4" />
          <p className="text-muted text-sm">Loading your assessment…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center px-4">
        <Card className="w-full max-w-sm text-center border-danger/30">
          <CardContent className="pt-6">
            <AlertTriangle className="h-8 w-8 text-danger mx-auto mb-3" />
            <p className="text-sm text-danger">{error}</p>
            <Button variant="outline" className="mt-4" onClick={() => window.location.href = '/onboarding'}>
              Back to Onboarding
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const total = questions.length;
  const answered = Object.keys(responses).length;
  const pct = total > 0 ? Math.round((answered / total) * 100) : 0;
  const current = questions[currentIndex];
  const isLast = currentIndex === total - 1;
  const canSubmit = answered >= Math.ceil(total * 0.8);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Payment confirmed banner */}
      {showPaymentBanner && (
        <div className="bg-success/10 border-b border-success/30 px-4 py-2 flex items-center justify-between">
          <p className="text-xs text-success font-medium">
            ✓ Payment confirmed — your assessment is unlocked. Complete all questions below.
          </p>
          <button
            onClick={() => setShowPaymentBanner(false)}
            className="text-success/60 hover:text-success text-xs ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {/* Header */}
      <header className="sticky top-0 z-10 border-b border-border bg-background/80 backdrop-blur-md">
        <div className="mx-auto max-w-2xl px-4 py-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className="flex h-6 w-6 items-center justify-center rounded bg-primary">
                <Zap className="h-3.5 w-3.5 text-white" />
              </div>
              <span className="text-sm font-medium text-foreground">AI Governance Assessment</span>
            </div>
            <div className="flex items-center gap-3">
              {lastSaved && (
                <span className="hidden sm:flex items-center gap-1 text-xs text-muted">
                  <Clock className="h-3 w-3" />
                  Saved {lastSaved.toLocaleTimeString()}
                </span>
              )}
              <span className="text-xs text-muted">
                {answered}/{total} answered
              </span>
            </div>
          </div>
          <Progress value={pct} />
        </div>
      </header>

      {/* Question */}
      <main className="flex-1 mx-auto w-full max-w-2xl px-4 py-8">
        {current ? (
          <>
            <div className="mb-2 flex items-center justify-between text-xs text-muted">
              <span>Question {currentIndex + 1} of {total}</span>
              <span>{pct}% complete</span>
            </div>

            <QuestionCard
              question={current}
              value={responses[current.id]}
              onChange={(v) => setResponse(current.id, v)}
            />

            {/* Navigation */}
            <div className="flex items-center justify-between mt-6 gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCurrentIndex(Math.max(0, currentIndex - 1))}
                disabled={currentIndex === 0}
                className="gap-1"
              >
                <ChevronLeft className="h-4 w-4" /> Previous
              </Button>

              <div className="flex gap-2">
                {isLast ? (
                  <Button
                    onClick={handleSubmit}
                    loading={submitting}
                    disabled={!canSubmit}
                    size="sm"
                    className="gap-1"
                  >
                    Submit & Score <CheckCircle2 className="h-4 w-4" />
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    onClick={() => setCurrentIndex(Math.min(total - 1, currentIndex + 1))}
                    className="gap-1"
                  >
                    Next <ChevronRight className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>

            {error && (
              <div className="mt-3 rounded-lg border border-danger/30 bg-danger/5 px-4 py-3">
                <p className="text-sm text-danger">{error}</p>
              </div>
            )}

            {!canSubmit && isLast && (
              <p className="mt-3 text-center text-xs text-muted">
                Answer at least {Math.ceil(total * 0.8)} questions ({answered} of {Math.ceil(total * 0.8)} required) to submit.
              </p>
            )}
          </>
        ) : (
          <div className="text-center py-16 text-muted">No questions available.</div>
        )}

        {/* Question navigation dots (for shorter assessments) */}
        {total <= 50 && (
          <div className="mt-8 flex flex-wrap gap-1.5 justify-center">
            {questions.map((q, i) => (
              <button
                key={q.id}
                onClick={() => setCurrentIndex(i)}
                className={`h-2.5 w-2.5 rounded-full transition-all ${
                  i === currentIndex
                    ? 'bg-primary scale-125'
                    : responses[q.id] !== undefined
                    ? 'bg-success'
                    : 'bg-surface-3'
                }`}
                title={`Question ${i + 1}`}
              />
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

export default function AssessmentPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-background flex items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      }
    >
      <AssessmentContent />
    </Suspense>
  );
}
