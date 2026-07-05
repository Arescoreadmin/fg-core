'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-QUESTIONNAIRE';
const AUTHORITY = 'Questionnaire Summary Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/reports';
const customerSafe = true;

export interface QuestionnaireStatus {
  id: string;
  framework: string;
  frameworkVersion: string;
  status: string;
  submittedAt: string | null;
  responseCount: number;
  implementedCount: number;
  partialCount: number;
  notImplementedCount: number;
}

interface Props {
  questionnaires: QuestionnaireStatus[];
  loading: boolean;
  lastUpdated?: string;
}

const STATUS_CLASS: Record<string, string> = {
  submitted: 'border-green-500/40 bg-green-500/10 text-green-300',
  in_progress: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  draft: 'border-border bg-surface-2 text-muted',
  complete: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
};

export default function QuestionnaireSummary({ questionnaires, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Questionnaire Summary"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Questionnaire Summary"
      lastUpdated={lastUpdated}
    >
      <section aria-label="questionnaire-summary" data-testid="questionnaire-summary">
        {loading && (
          <div className="space-y-3" aria-busy="true">
            {[1, 2].map((i) => (
              <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && questionnaires.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No questionnaires available for this engagement.</p>
        )}

        {!loading && questionnaires.length > 0 && (
          <div className="space-y-3">
            {questionnaires.map((q) => {
              const cls = STATUS_CLASS[q.status] ?? STATUS_CLASS.draft;
              const total = q.responseCount;
              const implementedPct = total > 0 ? Math.round((q.implementedCount / total) * 100) : 0;
              return (
                <div key={q.id} className="rounded border border-border bg-surface-2 p-3 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="text-sm font-medium text-foreground">{q.framework}</p>
                      <p className="text-[11px] text-muted">v{q.frameworkVersion}</p>
                    </div>
                    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
                      {q.status.replace(/_/g, ' ').charAt(0).toUpperCase() + q.status.replace(/_/g, ' ').slice(1)}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2 text-center text-xs">
                    <div className="rounded border border-green-500/30 bg-green-500/5 px-2 py-1.5">
                      <div className="text-lg font-semibold text-green-300">{q.implementedCount}</div>
                      <div className="text-[10px] text-muted">Implemented</div>
                    </div>
                    <div className="rounded border border-amber-500/30 bg-amber-500/5 px-2 py-1.5">
                      <div className="text-lg font-semibold text-amber-200">{q.partialCount}</div>
                      <div className="text-[10px] text-muted">Partial</div>
                    </div>
                    <div className="rounded border border-red-500/30 bg-red-500/5 px-2 py-1.5">
                      <div className="text-lg font-semibold text-red-300">{q.notImplementedCount}</div>
                      <div className="text-[10px] text-muted">Not Implemented</div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-xs text-muted">
                    <span>{q.responseCount} controls assessed · {implementedPct}% implemented</span>
                    {q.submittedAt && (
                      <span>Submitted: {new Date(q.submittedAt).toLocaleDateString()}</span>
                    )}
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
