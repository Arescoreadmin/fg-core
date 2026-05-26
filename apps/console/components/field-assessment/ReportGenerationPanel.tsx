'use client';

import { useEffect, useRef, useState } from 'react';
import { Button, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import {
  fieldAssessmentApi,
  FieldAssessmentApiError,
  type ReportType,
} from '@/lib/fieldAssessmentApi';

const REPORT_TYPES: { value: ReportType; label: string }[] = [
  { value: 'full_assessment', label: 'Full Assessment' },
  { value: 'executive_summary', label: 'Executive Summary' },
  { value: 'findings_register', label: 'Findings Register' },
  { value: 'control_gap', label: 'Control Gap' },
];

const MAX_POLL = 10;
const POLL_MS = 2000;

function safeMsg(e: unknown, version?: number): string {
  if (e instanceof FieldAssessmentApiError) {
    if (e.status === 403) return 'Access denied. Insufficient permissions to generate reports.';
    if (e.status === 404) return 'Engagement not found.';
    if (e.status === 409) return 'Version conflict. Another report was being generated simultaneously. Please try again.';
    if (e.status === 422) return 'Invalid report type.';
    if (e.status === 503) return 'Report signing key unavailable. Contact your administrator.';
  }
  return 'Failed to generate report. Please try again.';
}

interface Props {
  engagementId: string;
  onGenerated?: () => void;
}

export function ReportGenerationPanel({ engagementId, onGenerated }: Props) {
  const [reportType, setReportType] = useState<ReportType>('full_assessment');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successVersion, setSuccessVersion] = useState<number | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    return () => { mountedRef.current = false; };
  }, []);

  async function handleGenerate() {
    setSubmitting(true);
    setError(null);
    setSuccessVersion(null);
    try {
      const result = await fieldAssessmentApi.generateReport(engagementId, { report_type: reportType });

      if (result.status !== 'generating') {
        if (mountedRef.current) {
          setSuccessVersion(result.version);
          onGenerated?.();
        }
        return;
      }

      // Bounded poll for async generation (defensive — backend is currently synchronous)
      let attempts = 0;
      while (attempts < MAX_POLL) {
        await new Promise<void>((r) => setTimeout(r, POLL_MS));
        if (!mountedRef.current) return;
        const list = await fieldAssessmentApi.listReports(engagementId, { limit: 10 });
        const item = list.items.find((r) => r.version === result.version);
        if (item && item.status !== 'generating') {
          if (mountedRef.current) {
            setSuccessVersion(result.version);
            onGenerated?.();
          }
          return;
        }
        attempts++;
      }
      if (mountedRef.current) {
        setError('Report generation timed out. Refresh the version list to check status.');
      }
    } catch (e) {
      if (mountedRef.current) setError(safeMsg(e));
    } finally {
      if (mountedRef.current) setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="report-generation-panel">
      <div className="space-y-1">
        <Label htmlFor="report-type-select" className="text-xs">Report Type</Label>
        <Select
          value={reportType}
          onValueChange={(v) => setReportType(v as ReportType)}
          disabled={submitting}
        >
          <SelectTrigger id="report-type-select" className="text-xs h-8">
            <SelectValue placeholder="Select report type" />
          </SelectTrigger>
          <SelectContent>
            {REPORT_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value} className="text-xs">
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Button
        size="sm"
        onClick={handleGenerate}
        disabled={submitting}
        aria-busy={submitting}
        className="text-xs"
      >
        {submitting ? 'Generating…' : 'Generate Report'}
      </Button>

      {error && (
        <Alert variant="destructive">
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
      )}

      {successVersion !== null && !submitting && (
        <p className="text-xs text-success">
          Report v{successVersion} generated successfully.
        </p>
      )}
    </div>
  );
}
