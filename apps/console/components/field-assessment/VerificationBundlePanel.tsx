'use client';

import { useCallback, useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import {
  fieldAssessmentApi,
  FieldAssessmentApiError,
  type VerificationBundle,
} from '@/lib/fieldAssessmentApi';

const STATUS_CLASS: Record<string, string> = {
  verified: 'border-green-500/30 bg-green-500/5 text-green-300',
  incomplete: 'border-amber-500/30 bg-amber-500/5 text-amber-200',
  tamper_detected: 'border-red-500/30 bg-red-500/5 text-red-300',
};

const STATUS_LABEL: Record<string, string> = {
  verified: 'Verified',
  incomplete: 'Incomplete (no approved report)',
  tamper_detected: 'Tamper Detected',
};

const COVERAGE_CLASS: Record<string, string> = {
  complete: 'border-green-500/20 bg-green-500/5 text-green-300',
  partial: 'border-amber-500/20 bg-amber-500/5 text-amber-200',
  missing_report: 'border-amber-500/20 bg-amber-500/5 text-amber-200',
  missing_evidence: 'border-amber-500/20 bg-amber-500/5 text-amber-200',
  missing_decisions: 'border-amber-500/20 bg-amber-500/5 text-amber-200',
  tampered: 'border-red-500/20 bg-red-500/5 text-red-300',
};

const COVERAGE_LABEL: Record<string, string> = {
  complete: 'Coverage: Complete',
  partial: 'Coverage: Partial',
  missing_report: 'Coverage: Missing Report',
  missing_evidence: 'Coverage: Missing Evidence',
  missing_decisions: 'Coverage: Missing Decisions',
  tampered: 'Coverage: Tampered',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-3 text-muted';
  const label = STATUS_LABEL[status] ?? status;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {label}
    </span>
  );
}

function CoverageBadge({ status }: { status: string }) {
  const cls = COVERAGE_CLASS[status] ?? 'border-border bg-surface-3 text-muted';
  const label = COVERAGE_LABEL[status] ?? `Coverage: ${status}`;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border ${cls}`}>
      {label}
    </span>
  );
}

function safeMsg(e: unknown): string {
  if (e instanceof FieldAssessmentApiError) {
    if (e.status === 403) return 'Access denied.';
    if (e.status === 404) return 'Engagement not found.';
  }
  return 'Failed to generate bundle. Please try again.';
}

interface Props {
  engagementId: string;
}

export function VerificationBundlePanel({ engagementId }: Props) {
  const [bundle, setBundle] = useState<VerificationBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadBundle = useCallback(async () => {
    try {
      const b = await fieldAssessmentApi.getVerificationBundle(engagementId);
      setBundle(b);
    } catch (e) {
      if (e instanceof FieldAssessmentApiError && e.status === 404) {
        setBundle(null);
      }
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    loadBundle();
  }, [loadBundle]);

  async function handleGenerate() {
    setGenerating(true);
    setError(null);
    try {
      const b = await fieldAssessmentApi.generateVerificationBundle(engagementId);
      setBundle(b);
    } catch (e) {
      setError(safeMsg(e));
    } finally {
      setGenerating(false);
    }
  }

  async function handleDownload() {
    setDownloading(true);
    try {
      const blob = await fieldAssessmentApi.downloadVerificationBundle(engagementId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `verification_bundle_${engagementId.slice(0, 12)}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError('Download failed. Please try again.');
    } finally {
      setDownloading(false);
    }
  }

  return (
    <Card className="border-border" aria-label="verification-bundle-panel">
      <CardHeader className="pb-2 pt-4 px-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle className="text-sm">Verification Bundle</CardTitle>
            <p className="text-xs text-muted mt-0.5">
              Regulatory-grade SHA-256 hashed snapshot of all engagement components
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            {bundle && (
              <button
                type="button"
                onClick={handleDownload}
                disabled={downloading}
                className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-foreground hover:bg-surface-3 disabled:opacity-50 transition-colors"
              >
                {downloading ? 'Preparing…' : 'Download ZIP'}
              </button>
            )}
            <button
              type="button"
              onClick={handleGenerate}
              disabled={generating}
              className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-foreground hover:bg-surface-3 disabled:opacity-50 transition-colors"
            >
              {generating ? 'Generating…' : 'Generate Bundle'}
            </button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="px-4 pb-4 space-y-3">
        {error && (
          <Alert variant="destructive">
            <AlertDescription className="text-xs">{error}</AlertDescription>
          </Alert>
        )}

        {loading && (
          <div className="space-y-2" aria-busy="true">
            <div className="h-8 rounded border border-border bg-surface-2 animate-pulse" />
            <div className="h-8 rounded border border-border bg-surface-2 animate-pulse" />
          </div>
        )}

        {!loading && !bundle && !error && (
          <p className="text-xs text-muted">
            No bundle generated yet. Click "Generate Bundle" to create a verifiable
            snapshot of all engagement components.
          </p>
        )}

        {bundle && (
          <div className="space-y-3">
            {/* Status + coverage badges */}
            <div className="rounded border border-border bg-surface-2 p-3 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge status={bundle.verification_status} />
                {bundle.coverage_status && (
                  <CoverageBadge status={bundle.coverage_status} />
                )}
                <span className="text-xs text-muted">
                  Generated {new Date(bundle.generated_at).toLocaleString()} by{' '}
                  <span className="font-mono text-foreground">{bundle.generated_by}</span>
                </span>
              </div>
              <dl className="grid grid-cols-1 gap-y-1 text-xs sm:grid-cols-2">
                <dt className="text-muted">Bundle ID</dt>
                <dd className="font-mono text-foreground truncate">{bundle.bundle_id}</dd>
                <dt className="text-muted">Bundle Hash</dt>
                <dd className="font-mono text-foreground truncate">{bundle.bundle_hash}</dd>
                <dt className="text-muted">Manifest Hash</dt>
                <dd className="font-mono text-foreground truncate">{bundle.manifest_hash}</dd>
                {bundle.report_artifact_hash && (
                  <>
                    <dt className="text-muted">Report Artifact Hash</dt>
                    <dd className="font-mono text-foreground truncate">{bundle.report_artifact_hash}</dd>
                  </>
                )}
              </dl>
            </div>

            {/* Component counts */}
            <div className="space-y-1">
              <p className="text-xs font-medium text-foreground">Components</p>
              <div className="grid grid-cols-2 gap-1 sm:grid-cols-4">
                {[
                  { label: 'Findings', value: bundle.finding_count },
                  { label: 'Evidence', value: bundle.evidence_count },
                  { label: 'Interviews', value: bundle.interview_count },
                  { label: 'Decisions', value: bundle.decision_count },
                  { label: 'Risk Accepts.', value: bundle.risk_acceptance_count },
                  { label: 'Exceptions', value: bundle.exception_count },
                  { label: 'Scan Audit', value: bundle.audit_event_count },
                  { label: 'Eng. Audit', value: bundle.engagement_audit_event_count ?? 0 },
                  { label: 'Custody', value: bundle.chain_of_custody_count ?? 0 },
                  { label: 'Report', value: bundle.has_report ? 1 : 0 },
                ].map(({ label, value }) => (
                  <div key={label} className="rounded border border-border bg-surface-2 px-2.5 py-2">
                    <p className="text-[11px] text-muted">{label}</p>
                    <p className="text-base font-semibold text-foreground">{value}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Tamper details */}
            {bundle.tamper_details && bundle.tamper_details.length > 0 && (
              <div className="rounded border border-red-500/30 bg-red-500/5 p-3 space-y-1.5">
                <p className="text-xs font-semibold text-red-300">
                  {bundle.tamper_details.length} integrity issue{bundle.tamper_details.length !== 1 ? 's' : ''} detected
                </p>
                <ul className="space-y-0.5">
                  {bundle.tamper_details.map((issue, i) => (
                    <li key={i} className="text-xs text-red-300/80 font-mono">{issue}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Component hash table */}
            <details className="text-xs">
              <summary className="cursor-pointer text-muted hover:text-foreground select-none">
                Component hashes ({bundle.component_summary.length})
              </summary>
              <div className="mt-2 space-y-1">
                {bundle.component_summary.map((c) => (
                  <div key={c.name} className="flex gap-3 items-baseline">
                    <span className="w-36 shrink-0 text-muted">{c.name.replace(/_/g, ' ')}</span>
                    <span className="text-muted mr-2">{c.count}</span>
                    <span className="font-mono text-foreground truncate">{c.hash}</span>
                  </div>
                ))}
              </div>
            </details>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
