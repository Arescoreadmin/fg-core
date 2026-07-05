'use client';
import PortalShell from './PortalShell';
import type { FindingSummary } from '@/lib/portalApi';

const MCIM_ID = 'MCIM-18.6-PORTAL-FINDINGS';
const AUTHORITY = 'Customer Findings Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/findings';
const customerSafe = true;

export type FindingFilter = {
  severity?: string;
  status?: string;
};

interface Props {
  findings: FindingSummary[];
  filter: FindingFilter;
  onFilterChange?: (f: FindingFilter) => void;
  loading: boolean;
  lastUpdated?: string;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  info: 'border-border bg-surface-2 text-muted',
};

const STATUS_CLASS: Record<string, string> = {
  open: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  resolved: 'border-green-500/40 bg-green-500/10 text-green-300',
  accepted: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  in_progress: 'border-primary/40 bg-primary/10 text-primary',
  deferred: 'border-border bg-surface-2 text-muted',
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    critical: 'border-red-500/40 bg-red-500/10 text-red-300',
    high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
    low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
    info: 'border-border bg-surface-2 text-muted',
  };
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls[severity] ?? cls.info}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-2 text-muted';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, ' ')}
    </span>
  );
}

export default function FindingsView({ findings, filter, onFilterChange, loading, lastUpdated }: Props) {
  const sorted = [...findings].sort((a, b) => {
    const sd = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (sd !== 0) return sd;
    return a.status.localeCompare(b.status);
  });

  const hasFilter = !!(filter.severity || filter.status);

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Findings"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Findings"
      lastUpdated={lastUpdated}
    >
      <section aria-label="findings-view" data-testid="findings-view">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex items-center gap-2">
          <label className="text-xs text-muted" htmlFor="fv-severity-filter">Severity</label>
          <select
            id="fv-severity-filter"
            className="rounded border border-border bg-surface-2 text-xs px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
            value={filter.severity ?? ''}
            onChange={(e) =>
              onFilterChange?.({ ...filter, severity: e.target.value || undefined })
            }
          >
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-muted" htmlFor="fv-status-filter">Status</label>
          <select
            id="fv-status-filter"
            className="rounded border border-border bg-surface-2 text-xs px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
            value={filter.status ?? ''}
            onChange={(e) =>
              onFilterChange?.({ ...filter, status: e.target.value || undefined })
            }
          >
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="accepted">Accepted</option>
            <option value="deferred">Deferred</option>
          </select>
        </div>
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && sorted.length === 0 && (
        <p className="text-sm text-muted text-center py-8">
          {hasFilter
            ? 'No findings match the current filters.'
            : 'No findings available.'}
        </p>
      )}

      {!loading && sorted.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="border-b border-border text-muted">
                <th className="text-left py-2 pr-3 font-medium">Title</th>
                <th className="text-left py-2 pr-3 font-medium">Severity</th>
                <th className="text-left py-2 pr-3 font-medium">Status</th>
                <th className="text-left py-2 pr-3 font-medium">Frameworks</th>
                <th className="text-left py-2 pr-3 font-medium">Guidance</th>
                <th className="text-left py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sorted.map((f) => (
                <tr key={f.finding_id} className="text-foreground">
                  <td className="py-2 pr-3 max-w-[200px]">
                    <span className="font-medium">{f.title}</span>
                  </td>
                  <td className="py-2 pr-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="py-2 pr-3">
                    <StatusBadge status={f.status} />
                  </td>
                  <td className="py-2 pr-3 text-muted max-w-[140px] truncate">
                    {f.framework_mappings.join(', ') || '—'}
                  </td>
                  <td className="py-2 pr-3 text-muted max-w-[160px] truncate">
                    {f.remediation_hint
                      ? f.remediation_hint.slice(0, 60) + (f.remediation_hint.length > 60 ? '…' : '')
                      : '—'}
                  </td>
                  <td className="py-2 text-muted whitespace-nowrap">
                    {new Date(f.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-[11px] text-muted mt-4 border-t border-border pt-3">
        Business impact and internal confidence details are reviewed with your engagement team.
      </p>
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
