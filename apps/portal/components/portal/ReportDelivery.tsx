'use client';
import PortalShell from './PortalShell';
import type { ReportVersionSummary } from '@/lib/portalApi';

const MCIM_ID = 'MCIM-18.6-PORTAL-REPORTS';
const AUTHORITY = 'Report Delivery Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/reports';
const customerSafe = true;

interface Props {
  reports: ReportVersionSummary[];
  onExport?: (reportId: string, version: number, format: 'json' | 'pdf') => void;
  onVerify?: (reportId: string, version: number) => void;
  loading: boolean;
  lastUpdated?: string;
}

const STATUS_CLASS: Record<string, string> = {
  finalized: 'border-green-500/30 bg-green-500/5 text-green-300',
  ready: 'border-green-500/30 bg-green-500/5 text-green-300',
  generating: 'border-amber-500/30 bg-amber-500/5 text-amber-200',
  draft: 'border-border bg-surface-3 text-muted',
  failed: 'border-red-500/30 bg-red-500/5 text-red-300',
  superseded: 'border-border bg-surface-3 text-muted',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-3 text-muted';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, ' ')}
    </span>
  );
}

export default function ReportDelivery({ reports, onExport, onVerify, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Report Delivery"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Reports"
      lastUpdated={lastUpdated}
    >
      <section aria-label="report-delivery" data-testid="report-delivery">
      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && reports.length === 0 && (
        <p className="text-sm text-muted text-center py-8">
          No reports available for this engagement.
        </p>
      )}

      {!loading && reports.length > 0 && (
        <div className="space-y-3">
          {reports.map((r) => (
            <div
              key={`${r.report_id}-v${r.version}`}
              className="rounded border border-border bg-surface-2 p-3 space-y-2.5"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-muted truncate max-w-[160px]" title={r.report_id}>
                  {r.report_id.slice(0, 16)}…
                </span>
                <span className="font-mono text-sm font-semibold text-foreground">v{r.version}</span>
                <StatusBadge status={r.status} />
                {r.report_type && (
                  <span className="text-xs text-muted capitalize">
                    {r.report_type.replace(/_/g, ' ')}
                  </span>
                )}
                <span className="ml-auto text-xs text-muted">
                  {new Date(r.compiled_at).toLocaleString()}
                </span>
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
                  onClick={() => onExport?.(r.report_id, r.version, 'json')}
                  disabled={!onExport}
                >
                  Export JSON
                </button>
                <button
                  type="button"
                  className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
                  onClick={() => onExport?.(r.report_id, r.version, 'pdf')}
                  disabled={!onExport}
                >
                  Export PDF
                </button>
                <button
                  type="button"
                  className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
                  onClick={() => onVerify?.(r.report_id, r.version)}
                  disabled={!onVerify}
                >
                  Verify
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
