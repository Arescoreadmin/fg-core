'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-OBSERVATIONS';
const AUTHORITY = 'Observations Panel Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/findings';
const customerSafe = true;

export type PortalObservationType = 'gap' | 'strength' | 'concern' | 'finding' | 'note';

export interface PortalObservation {
  id: string;
  domain: string;
  observationType: PortalObservationType;
  severity: string;
  title: string;
  description: string;
  createdAt: string;
}

interface Props {
  observations: PortalObservation[];
  loading: boolean;
  lastUpdated?: string;
}

const TYPE_CLASS: Record<PortalObservationType, string> = {
  gap: 'border-red-500/40 bg-red-500/10 text-red-300',
  strength: 'border-green-500/40 bg-green-500/10 text-green-300',
  concern: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  finding: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  note: 'border-border bg-surface-2 text-muted',
};

export default function ObservationsPanel({ observations, loading, lastUpdated }: Props) {
  const domains = Array.from(new Set(observations.map((o) => o.domain)));

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Assessment Observations"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Observations"
      lastUpdated={lastUpdated}
    >
      <section aria-label="observations-panel" data-testid="observations-panel">
        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && observations.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No observations recorded for this engagement.</p>
        )}

        {!loading && observations.length > 0 && (
          <div className="space-y-4">
            {domains.map((domain) => {
              const domainObs = observations.filter((o) => o.domain === domain);
              return (
                <div key={domain}>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted/70 mb-2">
                    {domain}
                  </p>
                  <div className="space-y-2">
                    {domainObs.map((obs) => (
                      <div key={obs.id} className="rounded border border-border bg-surface-2 p-3 space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${TYPE_CLASS[obs.observationType]}`}>
                            {obs.observationType.charAt(0).toUpperCase() + obs.observationType.slice(1)}
                          </span>
                          {obs.severity && obs.severity !== 'none' && (
                            <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-border bg-surface text-muted font-medium">
                              {obs.severity}
                            </span>
                          )}
                        </div>
                        <p className="text-sm font-medium text-foreground">{obs.title}</p>
                        <p className="text-xs text-muted leading-relaxed">{obs.description}</p>
                        <p className="text-[10px] text-muted">{new Date(obs.createdAt).toLocaleString()}</p>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
