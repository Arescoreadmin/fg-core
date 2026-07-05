'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import CustomerExportCenter, { type ExportOption } from '@/components/portal/CustomerExportCenter';

const DEFAULT_OPTIONS: ExportOption[] = [
  {
    type: 'report',
    label: 'Assessment Report',
    description: 'Latest compiled assessment report with manifest hash.',
    available: false,
    formats: ['json', 'pdf'],
  },
  {
    type: 'evidence-summary',
    label: 'Evidence Summary',
    description: 'Summary of collected evidence and verification status.',
    available: false,
    formats: ['json', 'csv'],
  },
  {
    type: 'remediation',
    label: 'Remediation Roadmap',
    description: 'Phased remediation plan with finding details.',
    available: false,
    formats: ['json', 'csv'],
  },
  {
    type: 'trust-verification',
    label: 'Trust Verification',
    description: 'Integrity hashes and chain of custody artifacts.',
    available: false,
    formats: ['json'],
  },
  {
    type: 'attestation',
    label: 'Attestation Records',
    description: 'All submitted attestations for this engagement.',
    available: false,
    formats: ['json', 'csv'],
  },
  {
    type: 'portal-snapshot',
    label: 'Portal Snapshot',
    description: 'Full portal-visible snapshot of engagement state.',
    available: false,
    formats: ['json'],
  },
];

function handleExport(type: string, format: string, engagementId: string) {
  if (type === 'report' && (format === 'json' || format === 'pdf')) {
    portalApi
      .listReports(engagementId, { limit: 1 })
      .then((res) => {
        if (!res.items.length) return;
        return portalApi.exportReport(engagementId, res.items[0].version, format as 'json' | 'pdf');
      })
      .then((blob) => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${engagementId}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch(() => {});
  }
}

function ExportPageInner() {
  const params = useSearchParams();
  // UX hint — URL param takes priority; localStorage is session-continuity fallback only.
  // Authorization is enforced server-side: invalid IDs fail closed at the BFF.
  const engagementId = params.get('e') || getStoredEngagementId();
  const [options, setOptions] = useState<ExportOption[]>(DEFAULT_OPTIONS);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    portalApi
      .listReports(engagementId, { limit: 1 })
      .then((res) => {
        const hasReport = res.items.length > 0;
        setOptions((prev) =>
          prev.map((opt) =>
            opt.type === 'report' || opt.type === 'trust-verification'
              ? { ...opt, available: hasReport }
              : { ...opt, available: true },
          ),
        );
        setLastUpdated(new Date().toISOString());
      })
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setOptions(DEFAULT_OPTIONS);
        }
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  return (
    <div data-testid="export-page" aria-label="customer-export-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Export Center</h1>
        <p className="text-xs text-muted mt-0.5">Download engagement artifacts and reports.</p>
      </div>

      <CustomerExportCenter
        options={options}
        onExport={engagementId ? (type, fmt) => handleExport(type, fmt, engagementId) : undefined}
        loading={loading}
        lastUpdated={lastUpdated}
      />
    </div>
  );
}

export default function ExportPage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <ExportPageInner />
    </Suspense>
  );
}
