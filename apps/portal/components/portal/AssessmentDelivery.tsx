'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-ASSESSMENT';
const AUTHORITY = 'Assessment Delivery Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/coverage';
const customerSafe = true;

export interface AssessmentDeliveryData {
  assessedDomains: string[];
  frameworkCoverage: { framework: string; coverage: number | null }[];
  readinessSummary: string | null;
  evidenceCompleteness: number | null;
  highLevelRiskPosture: 'critical' | 'high' | 'medium' | 'low' | null;
  assessmentTimeline: { label: string; completedAt: string | null }[];
  reviewedAreas: string[];
  excludedAreas: string[];
  limitations: string[];
  confidence: number | null;
}

interface Props {
  data: AssessmentDeliveryData | null;
  loading: boolean;
  lastUpdated?: string;
}

const RISK_CLASS: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
};

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">{children}</h3>
  );
}

export default function AssessmentDelivery({ data, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Assessment Delivery"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Assessment Delivery"
      lastUpdated={lastUpdated}
    >
      <section aria-label="assessment-delivery" data-testid="assessment-delivery">
      {loading && (
        <div className="space-y-3" aria-busy="true">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="h-5 rounded bg-surface-2 animate-pulse w-4/5" />
          ))}
        </div>
      )}

      {!loading && !data && (
        <p className="text-sm text-muted text-center py-8">No assessment data available.</p>
      )}

      {!loading && data && (
        <div className="space-y-5">
          {/* What Was Assessed */}
          <section className="space-y-2">
            <SectionTitle>What Was Assessed</SectionTitle>
            {data.assessedDomains.length > 0 ? (
              <ul className="space-y-1">
                {data.assessedDomains.map((d, i) => (
                  <li key={i} className="text-sm text-foreground">• {d}</li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No domains listed.</p>
            )}

            {data.frameworkCoverage.length > 0 && (
              <div className="mt-2 space-y-1">
                {data.frameworkCoverage.map((fc, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs">
                    <span className="text-foreground w-32 shrink-0">{fc.framework}</span>
                    <span className="text-muted">
                      {fc.coverage != null ? `${Math.round(fc.coverage)}% coverage` : 'Coverage unavailable'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Readiness Summary */}
          <section className="space-y-1">
            <SectionTitle>Readiness Summary</SectionTitle>
            <p className="text-sm text-foreground">
              {data.readinessSummary ?? <span className="text-muted">Not yet available</span>}
            </p>
          </section>

          {/* Risk Posture */}
          <section className="space-y-1">
            <SectionTitle>Risk Posture</SectionTitle>
            {data.highLevelRiskPosture ? (
              <span
                className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${RISK_CLASS[data.highLevelRiskPosture]}`}
              >
                {data.highLevelRiskPosture.charAt(0).toUpperCase() + data.highLevelRiskPosture.slice(1)}
              </span>
            ) : (
              <p className="text-sm text-muted">Not yet available</p>
            )}
          </section>

          {/* Evidence Completeness */}
          <section className="space-y-1">
            <SectionTitle>Evidence Completeness</SectionTitle>
            <p className="text-sm text-foreground">
              {data.evidenceCompleteness != null
                ? `${data.evidenceCompleteness}%`
                : <span className="text-muted">Not yet available</span>}
            </p>
          </section>

          {/* Not Assessed / Limitations */}
          {(data.excludedAreas.length > 0 || data.limitations.length > 0) && (
            <section className="space-y-2">
              <SectionTitle>Not Assessed / Limitations</SectionTitle>
              {data.excludedAreas.length > 0 && (
                <div>
                  <p className="text-xs text-muted mb-1">Excluded areas:</p>
                  <ul className="space-y-1">
                    {data.excludedAreas.map((a, i) => (
                      <li key={i} className="text-sm text-foreground">• {a}</li>
                    ))}
                  </ul>
                </div>
              )}
              {data.limitations.length > 0 && (
                <div>
                  <p className="text-xs text-muted mb-1">Limitations:</p>
                  <ul className="space-y-1">
                    {data.limitations.map((l, i) => (
                      <li key={i} className="text-sm text-foreground">• {l}</li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          )}

          {/* Confidence */}
          <section className="space-y-1">
            <SectionTitle>Confidence</SectionTitle>
            <p className="text-sm text-foreground">
              {data.confidence != null
                ? `${Math.round(data.confidence * 100)}%`
                : <span className="text-muted">Unavailable</span>}
            </p>
          </section>

          {/* Timeline */}
          {data.assessmentTimeline.length > 0 && (
            <section className="space-y-2">
              <SectionTitle>Assessment Timeline</SectionTitle>
              <div className="space-y-2">
                {data.assessmentTimeline.map((step, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <div
                      className={`h-2 w-2 rounded-full shrink-0 ${step.completedAt ? 'bg-green-400' : 'bg-surface-3 border border-border'}`}
                    />
                    <span className="text-sm text-foreground flex-1">{step.label}</span>
                    <span className="text-xs text-muted">
                      {step.completedAt
                        ? new Date(step.completedAt).toLocaleDateString()
                        : 'Pending'}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          )}

          <p className="text-[11px] text-muted border-t border-border pt-3">
            This assessment reflects findings at the time of assessment. Not all risk factors may be covered. See limitations above.
          </p>
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
