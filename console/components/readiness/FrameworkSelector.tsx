'use client';

/**
 * FrameworkSelector — tenant-safe framework + assessment selector.
 *
 * Uses only API-provided data. No tenant_id accepted from props or URL.
 * Deprecated/retired frameworks shown with explicit warnings.
 * Selection resets downstream assessment context on framework change.
 */

import { useEffect, useState } from 'react';
import { AlertTriangle, ChevronDown, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  listFrameworks,
  listAssessments,
  type Framework,
  type Assessment,
  type SafeResult,
  type FrameworkListResponse,
  type AssessmentListResponse,
} from '@/lib/readinessApi';

interface FrameworkSelectorProps {
  onAssessmentSelect: (frameworkId: string, assessmentId: string) => void;
  selectedFrameworkId: string | null;
  selectedAssessmentId: string | null;
}

const LIFECYCLE_WARN = new Set(['deprecated', 'retired']);

function lifecycleLabel(status: string): string {
  const labels: Record<string, string> = {
    draft: 'Draft',
    active: 'Active',
    deprecated: 'Deprecated',
    retired: 'Retired',
  };
  return labels[status] ?? status;
}

function assessmentStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    draft: 'Draft',
    collecting: 'Collecting Evidence',
    partially_evaluated: 'Partially Evaluated',
    finalized: 'Finalized',
    stale: 'Stale',
    deprecated: 'Deprecated',
    superseded: 'Superseded',
    invalidated: 'Invalidated',
  };
  return labels[status] ?? status;
}

export function FrameworkSelector({
  onAssessmentSelect,
  selectedFrameworkId,
  selectedAssessmentId,
}: FrameworkSelectorProps) {
  const [frameworksResult, setFrameworksResult] = useState<SafeResult<FrameworkListResponse> | null>(null);
  const [assessmentsResult, setAssessmentsResult] = useState<SafeResult<AssessmentListResponse> | null>(null);
  const [loadingFrameworks, setLoadingFrameworks] = useState(true);
  const [loadingAssessments, setLoadingAssessments] = useState(false);
  const [localFrameworkId, setLocalFrameworkId] = useState<string>(selectedFrameworkId ?? '');
  const [localAssessmentId, setLocalAssessmentId] = useState<string>(selectedAssessmentId ?? '');

  // Load frameworks on mount
  useEffect(() => {
    let cancelled = false;
    setLoadingFrameworks(true);
    listFrameworks().then((r) => {
      if (!cancelled) {
        setFrameworksResult(r);
        setLoadingFrameworks(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Load assessments when framework changes
  useEffect(() => {
    if (!localFrameworkId) {
      setAssessmentsResult(null);
      return;
    }
    let cancelled = false;
    setLoadingAssessments(true);
    setLocalAssessmentId('');
    listAssessments(localFrameworkId).then((r) => {
      if (!cancelled) {
        setAssessmentsResult(r);
        setLoadingAssessments(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [localFrameworkId]);

  function handleFrameworkChange(e: React.ChangeEvent<HTMLSelectElement>) {
    setLocalFrameworkId(e.target.value);
    setLocalAssessmentId('');
  }

  function handleAssessmentChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const id = e.target.value;
    setLocalAssessmentId(id);
    if (id && localFrameworkId) {
      onAssessmentSelect(localFrameworkId, id);
    }
  }

  const frameworks =
    frameworksResult?.ok ? frameworksResult.data.items : [];
  const assessments =
    assessmentsResult?.ok ? assessmentsResult.data.items : [];

  const selectedFramework = frameworks.find((f) => f.framework_id === localFrameworkId);
  const selectedAssessment = assessments.find((a) => a.assessment_id === localAssessmentId);

  const frameworkIsWarn = selectedFramework && LIFECYCLE_WARN.has(selectedFramework.framework_status);

  return (
    <Card aria-label="readiness-framework-selector">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Framework &amp; Assessment</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4 sm:grid-cols-2">
          {/* Framework select */}
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="readiness-framework-select"
              className="text-xs font-medium text-muted-foreground"
            >
              Framework
            </label>
            {loadingFrameworks ? (
              <div
                className="flex items-center gap-2 text-xs text-muted"
                aria-label="frameworks-loading"
              >
                <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
                Loading frameworks…
              </div>
            ) : !frameworksResult?.ok ? (
              <p className="text-xs text-risk-critical" aria-label="frameworks-error">
                Failed to load frameworks
              </p>
            ) : (
              <div className="relative">
                <select
                  id="readiness-framework-select"
                  value={localFrameworkId}
                  onChange={handleFrameworkChange}
                  className="w-full appearance-none rounded border border-border bg-background px-3 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  aria-label="Select framework"
                >
                  <option value="">— Select a framework —</option>
                  {frameworks.map((fw) => (
                    <option key={fw.framework_id} value={fw.framework_id}>
                      {fw.framework_name} v{fw.framework_version}
                      {LIFECYCLE_WARN.has(fw.framework_status)
                        ? ` [${lifecycleLabel(fw.framework_status)}]`
                        : ''}
                    </option>
                  ))}
                </select>
                <ChevronDown
                  className="pointer-events-none absolute right-2 top-2.5 h-4 w-4 text-muted"
                  aria-hidden="true"
                />
              </div>
            )}
            {frameworkIsWarn && (
              <p
                className="flex items-center gap-1 text-xs text-amber-600"
                aria-label="framework-lifecycle-warning"
              >
                <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                Framework is {lifecycleLabel(selectedFramework.framework_status).toLowerCase()} —
                results may not reflect current governance requirements.
              </p>
            )}
          </div>

          {/* Assessment select */}
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="readiness-assessment-select"
              className="text-xs font-medium text-muted-foreground"
            >
              Assessment
            </label>
            {!localFrameworkId ? (
              <p className="text-xs text-muted" aria-label="assessment-select-hint">
                Select a framework first
              </p>
            ) : loadingAssessments ? (
              <div
                className="flex items-center gap-2 text-xs text-muted"
                aria-label="assessments-loading"
              >
                <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
                Loading assessments…
              </div>
            ) : !assessmentsResult?.ok ? (
              <p className="text-xs text-risk-critical" aria-label="assessments-error">
                Failed to load assessments
              </p>
            ) : assessments.length === 0 ? (
              <p className="text-xs text-muted" aria-label="assessments-empty">
                No assessments for this framework
              </p>
            ) : (
              <div className="relative">
                <select
                  id="readiness-assessment-select"
                  value={localAssessmentId}
                  onChange={handleAssessmentChange}
                  className="w-full appearance-none rounded border border-border bg-background px-3 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  aria-label="Select assessment"
                >
                  <option value="">— Select an assessment —</option>
                  {assessments.map((a) => (
                    <option key={a.assessment_id} value={a.assessment_id}>
                      {a.assessment_name ?? a.assessment_id.slice(0, 12)}
                      {' '}({assessmentStatusLabel(a.assessment_status)})
                    </option>
                  ))}
                </select>
                <ChevronDown
                  className="pointer-events-none absolute right-2 top-2.5 h-4 w-4 text-muted"
                  aria-hidden="true"
                />
              </div>
            )}
            {selectedAssessment && selectedAssessment.assessment_status !== 'finalized' && (
              <p
                className="flex items-center gap-1 text-xs text-amber-600"
                aria-label="assessment-incomplete-warning"
              >
                <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                Assessment status:{' '}
                <strong>{assessmentStatusLabel(selectedAssessment.assessment_status)}</strong> —
                results are not final.
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
