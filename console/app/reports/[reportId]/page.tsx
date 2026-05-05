'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  Download,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ArrowLeft,
  Zap,
  FileText,
  ChevronRight,
  Shield,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { reportApi, type Report, type RoadmapItem, type FrameworkAlignment } from '@/lib/reportApi';

// ─── Risk helpers ─────────────────────────────────────────────────────────────

function riskBadgeVariant(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score < 25) return 'critical';
  if (score < 50) return 'high';
  if (score < 75) return 'medium';
  return 'low';
}

function riskLabel(score: number) {
  if (score < 25) return 'Critical Risk';
  if (score < 50) return 'High Risk';
  if (score < 75) return 'Medium Risk';
  return 'Low Risk';
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function RoadmapPhase({ phase, items }: { phase: string; items: RoadmapItem[] }) {
  if (!items?.length) return null;
  return (
    <div>
      <h4 className="text-xs font-semibold text-muted uppercase tracking-wider mb-3">{phase}</h4>
      <div className="space-y-3">
        {items.map((item, i) => (
          <div key={i} className="rounded-lg border border-border bg-surface-2 p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1">
                <p className="text-sm font-medium text-foreground">{item.title}</p>
                <p className="text-xs text-muted mt-1 leading-relaxed">{item.description}</p>
              </div>
            </div>
            <div className="flex gap-2 mt-3">
              <span className="inline-flex items-center rounded-full border border-border px-2 py-0.5 text-[10px] text-muted">
                Effort: {item.effort}
              </span>
              <span className="inline-flex items-center rounded-full border border-primary/20 bg-primary/5 px-2 py-0.5 text-[10px] text-primary">
                Impact: {item.impact}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function FrameworkRow({ fw }: { fw: FrameworkAlignment }) {
  const color =
    fw.alignment_pct >= 75 ? 'bg-success' : fw.alignment_pct >= 50 ? 'bg-warning' : 'bg-danger';
  return (
    <div className="flex items-center gap-4 py-3 border-b border-border last:border-0">
      <div className="w-32 text-xs font-medium text-foreground shrink-0">{fw.framework}</div>
      <div className="flex-1">
        <Progress
          value={fw.alignment_pct}
          indicatorClassName={color}
          className="h-1.5"
        />
      </div>
      <div className="w-12 text-xs text-right text-muted shrink-0">{fw.alignment_pct}%</div>
      {fw.gap_count > 0 && (
        <Badge variant="danger" className="shrink-0 text-[10px]">
          {fw.gap_count} gaps
        </Badge>
      )}
    </div>
  );
}

// ─── Generating screen ────────────────────────────────────────────────────────

function GeneratingScreen() {
  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-primary/10 border border-primary/30 mb-6">
        <Zap className="h-8 w-8 text-primary animate-pulse" />
      </div>
      <h1 className="text-xl font-bold text-foreground mb-2">Generating Your Report</h1>
      <p className="text-muted text-sm mb-6 text-center max-w-sm">
        Claude is analyzing your assessment responses across all 6 risk domains and generating
        your personalized advisory report.
      </p>
      <div className="w-full max-w-xs space-y-2">
        {[
          'Scoring domain responses…',
          'Mapping compliance frameworks…',
          'Generating executive summary…',
          'Building 30/60/90 day roadmap…',
        ].map((step, i) => (
          <div key={step} className="flex items-center gap-2 text-xs text-muted">
            <div
              className={`h-1.5 w-1.5 rounded-full ${
                i === 0 ? 'bg-primary animate-pulse' : 'bg-surface-3'
              }`}
            />
            {step}
          </div>
        ))}
      </div>
      <p className="mt-6 text-xs text-muted/60">Usually takes 15–45 seconds</p>
    </div>
  );
}

// ─── Main report view ─────────────────────────────────────────────────────────

function ReportView({ report }: { report: Report }) {
  const content = report.content!;

  // Derive score from first framework or default
  const overallScore = 47; // This would come from assessment scores in a real integration

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-10 border-b border-border bg-background/90 backdrop-blur-md">
        <div className="mx-auto max-w-4xl px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" onClick={() => window.history.back()}>
              <ArrowLeft className="h-4 w-4" />
            </Button>
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium text-foreground">Advisory Report</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="text-xs">
              {report.prompt_type}
            </Badge>
            <Button
              size="sm"
              variant="outline"
              className="gap-1"
              onClick={async () => {
                try {
                  const { url } = await reportApi.getDownloadUrl(report.id);
                  window.open(url, '_blank');
                } catch {
                  alert('PDF not yet available. Try again shortly.');
                }
              }}
            >
              <Download className="h-3.5 w-3.5" /> Download PDF
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-4 py-8 space-y-8">
        {/* Risk score hero */}
        <div className="rounded-xl border border-border bg-surface p-6 flex flex-col sm:flex-row items-start sm:items-center gap-6">
          <div className="text-center min-w-[80px]">
            <p className="text-5xl font-bold text-risk-high">{overallScore}</p>
            <p className="text-xs text-muted mt-1">out of 100</p>
            <Badge variant={riskBadgeVariant(overallScore)} className="mt-2">
              {riskLabel(overallScore)}
            </Badge>
          </div>
          <div className="flex-1">
            <p className="text-sm text-muted leading-relaxed">{content.executive_summary}</p>
          </div>
        </div>

        {/* Key strengths + Critical gaps */}
        <div className="grid gap-6 sm:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <CheckCircle2 className="h-4 w-4 text-success" />
                Key Strengths
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {content.key_strengths.map((s, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-muted">
                    <ChevronRight className="h-4 w-4 text-success shrink-0 mt-0.5" />
                    {s}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <AlertTriangle className="h-4 w-4 text-danger" />
                Critical Gaps
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {content.critical_gaps.map((g, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-muted">
                    <ChevronRight className="h-4 w-4 text-danger shrink-0 mt-0.5" />
                    {g}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* Domain findings */}
        {content.domain_findings && Object.keys(content.domain_findings).length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Domain Findings</CardTitle>
              <CardDescription>Risk assessment across all 6 governance domains</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(content.domain_findings).map(([domain, finding]) => (
                  <div key={domain}>
                    <p className="text-xs font-semibold text-foreground uppercase tracking-wide mb-1">
                      {domain.replace(/_/g, ' ')}
                    </p>
                    <p className="text-sm text-muted leading-relaxed">{finding}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Roadmap */}
        {content.roadmap && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <Clock className="h-4 w-4 text-primary" />
                Remediation Roadmap
              </CardTitle>
              <CardDescription>Prioritized actions across 30, 60, and 90 day horizons</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-6 sm:grid-cols-3">
                <RoadmapPhase phase="30 Days — Quick wins" items={content.roadmap.days_30} />
                <RoadmapPhase phase="60 Days — Core improvements" items={content.roadmap.days_60} />
                <RoadmapPhase phase="90 Days — Strategic" items={content.roadmap.days_90} />
              </div>
            </CardContent>
          </Card>
        )}

        {/* Framework alignments */}
        {content.framework_alignments?.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <Shield className="h-4 w-4 text-primary" />
                Compliance Framework Alignment
              </CardTitle>
              <CardDescription>
                Alignment scores — designed to support compliance with, not certified to, these frameworks
              </CardDescription>
            </CardHeader>
            <CardContent>
              {content.framework_alignments.map((fw, i) => (
                <FrameworkRow key={i} fw={fw} />
              ))}
            </CardContent>
          </Card>
        )}

        {/* Disclaimer */}
        {content.disclaimer && (
          <div className="rounded-lg border border-border bg-surface-2 px-5 py-4">
            <p className="text-xs text-muted leading-relaxed">{content.disclaimer}</p>
          </div>
        )}
      </main>
    </div>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

export default function ReportPage() {
  const params = useParams();
  const reportId = params.reportId as string;
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState('');

  const poll = useCallback(() => {
    reportApi
      .getReport(reportId)
      .then((r) => {
        setReport(r);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to load report');
      });
  }, [reportId]);

  useEffect(() => {
    poll();
  }, [poll]);

  // Poll every 3 seconds while generating
  useEffect(() => {
    if (report?.status === 'pending' || report?.status === 'generating') {
      const interval = setInterval(poll, 3_000);
      return () => clearInterval(interval);
    }
  }, [report?.status, poll]);

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center px-4">
        <Card className="w-full max-w-sm text-center border-danger/30">
          <CardContent className="pt-6">
            <AlertTriangle className="h-8 w-8 text-danger mx-auto mb-3" />
            <p className="text-sm text-danger">{error}</p>
            <Button variant="outline" className="mt-4" onClick={() => window.location.href = '/dashboard'}>
              Go to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!report || report.status === 'pending' || report.status === 'generating') {
    return <GeneratingScreen />;
  }

  if (report.status === 'failed') {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center px-4">
        <Card className="w-full max-w-sm text-center border-danger/30">
          <CardContent className="pt-6">
            <AlertTriangle className="h-8 w-8 text-danger mx-auto mb-3" />
            <CardTitle className="text-sm mb-2">Report Generation Failed</CardTitle>
            <CardDescription>{report.error_message ?? 'An unexpected error occurred.'}</CardDescription>
            <Button className="mt-4" onClick={() => window.location.href = '/dashboard'}>
              Return to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return <ReportView report={report} />;
}
