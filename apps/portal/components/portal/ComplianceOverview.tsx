'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-COMPLIANCE';
const AUTHORITY = 'Compliance Overview Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/reports';
const customerSafe = true;

export type ComplianceStatus = 'compliant' | 'partial' | 'non-compliant' | 'not-assessed';

export interface ComplianceDomain {
  id: string;
  name: string;
  framework: string;
  coveragePct: number;
  controlsAssessed: number;
  controlsTotal: number;
  status: ComplianceStatus;
  lastAssessedAt: string | null;
}

interface Props {
  domains: ComplianceDomain[];
  overallCoveragePct: number | null;
  loading: boolean;
  lastUpdated?: string;
}

const STATUS_CLASS: Record<ComplianceStatus, string> = {
  compliant: 'border-green-500/40 bg-green-500/10 text-green-300',
  partial: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  'non-compliant': 'border-red-500/40 bg-red-500/10 text-red-300',
  'not-assessed': 'border-border bg-surface-2 text-muted',
};

const COVERAGE_BAR_CLASS: Record<ComplianceStatus, string> = {
  compliant: 'bg-green-500/60',
  partial: 'bg-amber-500/60',
  'non-compliant': 'bg-red-500/60',
  'not-assessed': 'bg-muted/40',
};

export default function ComplianceOverview({ domains, overallCoveragePct, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Compliance Coverage Overview"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Compliance Overview"
      lastUpdated={lastUpdated}
    >
      <section aria-label="compliance-overview" data-testid="compliance-overview">
        <div className="mb-4 rounded border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">
          Coverage percentages are derived from assessment findings and do not constitute legal certification.
        </div>

        {loading && (
          <div className="space-y-3" aria-busy="true">
            <div className="h-8 rounded border border-border bg-surface-2 animate-pulse" />
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && domains.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No compliance data available for this engagement.</p>
        )}

        {!loading && domains.length > 0 && (
          <>
            {overallCoveragePct != null && (
              <div className="mb-4 rounded border border-border bg-surface-2 p-3 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-foreground">Overall Coverage</span>
                  <span className="font-mono text-foreground">{overallCoveragePct.toFixed(1)}%</span>
                </div>
                <div className="h-2 rounded-full bg-surface overflow-hidden" role="progressbar" aria-valuenow={overallCoveragePct} aria-valuemin={0} aria-valuemax={100}>
                  <div
                    className="h-full rounded-full bg-primary/60 transition-all"
                    style={{ width: `${Math.min(100, overallCoveragePct)}%` }}
                  />
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {domains.map((domain) => {
                const statusCls = STATUS_CLASS[domain.status];
                const barCls = COVERAGE_BAR_CLASS[domain.status];
                return (
                  <div key={domain.id} className="rounded border border-border bg-surface-2 p-3 space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="text-sm font-medium text-foreground">{domain.name}</p>
                        <p className="text-[11px] text-muted">{domain.framework}</p>
                      </div>
                      <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium shrink-0 ${statusCls}`}>
                        {domain.status.replace(/-/g, ' ').charAt(0).toUpperCase() + domain.status.replace(/-/g, ' ').slice(1)}
                      </span>
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px] text-muted">
                        <span>{domain.controlsAssessed}/{domain.controlsTotal} controls</span>
                        <span className="font-mono">{domain.coveragePct.toFixed(1)}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-surface overflow-hidden" role="progressbar" aria-valuenow={domain.coveragePct} aria-valuemin={0} aria-valuemax={100}>
                        <div
                          className={`h-full rounded-full transition-all ${barCls}`}
                          style={{ width: `${Math.min(100, domain.coveragePct)}%` }}
                        />
                      </div>
                    </div>

                    {domain.lastAssessedAt && (
                      <p className="text-[10px] text-muted">Last assessed: {new Date(domain.lastAssessedAt).toLocaleDateString()}</p>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
