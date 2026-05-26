'use client';

import { useState } from 'react';
import { Button } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, FieldAssessmentApiError, type ReportVerifyResult } from '@/lib/fieldAssessmentApi';

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = window.document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function safeExportMsg(e: unknown): string {
  if (e instanceof FieldAssessmentApiError) {
    if (e.status === 403) return 'Access denied.';
    if (e.status === 404) return 'Report version not found.';
    if (e.status === 422) return 'Report cannot be exported (deserialization error).';
    if (e.status === 501) return 'PDF export is not available on this server.';
  }
  return 'Export failed. Please try again.';
}

function safeVerifyMsg(e: unknown): string {
  if (e instanceof FieldAssessmentApiError) {
    if (e.status === 403) return 'Access denied.';
    if (e.status === 404) return 'Report version not found.';
    if (e.status === 503) return 'Signing key unavailable for verification.';
  }
  return 'Verification failed. Please try again.';
}

interface Props {
  engagementId: string;
  version: number | null;
  reportType: string | null;
}

export function ReportExportBar({ engagementId, version, reportType }: Props) {
  const [exportingJson, setExportingJson] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<ReportVerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (version === null) return null;

  const filename = (fmt: string) =>
    `frostgate-report-${engagementId}-v${version}.${fmt}`;

  async function handleExportJson() {
    setExportingJson(true);
    setError(null);
    try {
      const blob = await fieldAssessmentApi.exportReport(engagementId, version!, 'json');
      downloadBlob(blob, filename('json'));
    } catch (e) {
      setError(safeExportMsg(e));
    } finally {
      setExportingJson(false);
    }
  }

  async function handleExportPdf() {
    setExportingPdf(true);
    setError(null);
    try {
      const blob = await fieldAssessmentApi.exportReport(engagementId, version!, 'pdf');
      downloadBlob(blob, filename('pdf'));
    } catch (e) {
      setError(safeExportMsg(e));
    } finally {
      setExportingPdf(false);
    }
  }

  async function handleVerify() {
    setVerifying(true);
    setError(null);
    setVerifyResult(null);
    try {
      const result = await fieldAssessmentApi.verifyReport(engagementId, version!);
      setVerifyResult(result);
    } catch (e) {
      setError(safeVerifyMsg(e));
    } finally {
      setVerifying(false);
    }
  }

  return (
    <div className="space-y-3" aria-label="report-export-bar">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-muted uppercase tracking-wider mr-1">
          v{version}{reportType ? ` — ${reportType.replace(/_/g, ' ')}` : ''}
        </span>

        <Button
          size="sm"
          variant="outline"
          onClick={handleExportJson}
          disabled={exportingJson || exportingPdf || verifying}
          aria-busy={exportingJson}
          className="text-xs h-7"
        >
          {exportingJson ? 'Downloading…' : 'Export JSON'}
        </Button>

        <Button
          size="sm"
          variant="outline"
          onClick={handleExportPdf}
          disabled={exportingJson || exportingPdf || verifying}
          aria-busy={exportingPdf}
          className="text-xs h-7"
        >
          {exportingPdf ? 'Downloading…' : 'Export PDF'}
        </Button>

        <Button
          size="sm"
          variant="outline"
          onClick={handleVerify}
          disabled={exportingJson || exportingPdf || verifying}
          aria-busy={verifying}
          className="text-xs h-7"
        >
          {verifying ? 'Verifying…' : 'Verify Signature'}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
      )}

      {verifyResult && (
        <div className="flex flex-wrap gap-3 text-xs p-3 rounded border border-border bg-surface-2">
          {verifyResult.valid ? (
            <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-success/30 bg-success/5 text-success font-medium">
              ✓ Signature Verified
            </span>
          ) : (
            <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-danger/30 bg-danger/5 text-danger font-medium">
              ✗ Signature Invalid
            </span>
          )}
          <span className="text-muted">
            Hash: <span className="font-mono text-foreground truncate max-w-[160px] inline-block align-bottom">
              {verifyResult.manifest_hash}
            </span>
          </span>
          {verifyResult.verified_at && (
            <span className="text-muted ml-auto">
              {new Date(verifyResult.verified_at).toLocaleString()}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
