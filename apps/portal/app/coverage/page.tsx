'use client';

import { Suspense, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  portalApi,
  PortalApiError,
  type Questionnaire,
  type QuestionnaireControlResponse,
  type ResponseStatus,
} from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CATEGORIES = ['GOVERN', 'MAP', 'MEASURE', 'MANAGE'] as const;
type Category = (typeof CATEGORIES)[number];

const CATEGORY_LABELS: Record<Category, string> = {
  GOVERN: 'GOVERN — Policies, accountability & culture',
  MAP: 'MAP — Context, risk identification & interdependencies',
  MEASURE: 'MEASURE — Testing, evaluation & monitoring',
  MANAGE: 'MANAGE — Risk treatment, response & continual improvement',
};

const STATUS_COLOR: Record<ResponseStatus, string> = {
  implemented: 'bg-green-500/20 border-green-500/40 text-green-300',
  partial: 'bg-amber-500/20 border-amber-500/40 text-amber-200',
  not_implemented: 'bg-red-500/20 border-red-500/40 text-red-300',
  not_assessed: 'bg-surface-3 border-border text-muted',
  not_applicable: 'bg-surface-3 border-border/40 text-muted/50',
};

const STATUS_DOT: Record<ResponseStatus, string> = {
  implemented: 'bg-green-400',
  partial: 'bg-amber-400',
  not_implemented: 'bg-red-400',
  not_assessed: 'bg-surface-3 border border-border',
  not_applicable: 'bg-surface-3 border border-border/40',
};

const STATUS_LABEL: Record<ResponseStatus, string> = {
  implemented: 'Implemented',
  partial: 'Partial',
  not_implemented: 'Not implemented',
  not_assessed: 'Not assessed',
  not_applicable: 'N/A',
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SummaryBar({ questionnaire }: { questionnaire: Questionnaire }) {
  const responses = questionnaire.responses;
  const total = responses.length;
  const implemented = responses.filter((r) => r.response_status === 'implemented').length;
  const partial = responses.filter((r) => r.response_status === 'partial').length;
  const notImpl = responses.filter((r) => r.response_status === 'not_implemented').length;
  const notAssessed = responses.filter((r) => r.response_status === 'not_assessed').length;
  const na = responses.filter((r) => r.response_status === 'not_applicable').length;
  const applicable = total - na;
  const coveragePct = applicable > 0 ? Math.round((implemented / applicable) * 100) : null;

  return (
    <div className="rounded border border-border bg-surface-2 p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-2xl font-bold text-foreground">{coveragePct === null ? 'Unavailable' : `${coveragePct}%`}</p>
          <p className="text-xs text-muted">
            NIST AI RMF implementation coverage
            {applicable < total ? ` (${applicable} applicable controls)` : ''}
          </p>
        </div>
        {questionnaire.status !== 'draft' ? (
          <span className="text-xs px-2 py-1 rounded bg-green-500/10 border border-green-500/30 text-green-300 font-medium">
            Submitted {questionnaire.submitted_at?.slice(0, 10) ?? ''}
          </span>
        ) : (
          <span className="text-xs px-2 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-200">
            Assessment in progress
          </span>
        )}
      </div>

      {coveragePct !== null && <div className="h-2 w-full rounded-full bg-surface-3 overflow-hidden">
        <div className="h-full rounded-full bg-green-500/60 transition-all duration-500" style={{ width: `${coveragePct}%` }} />
      </div>}

      <div className="flex flex-wrap gap-x-5 gap-y-1.5 text-xs">
        {[
          { label: 'Implemented', count: implemented, status: 'implemented' as ResponseStatus },
          { label: 'Partial', count: partial, status: 'partial' as ResponseStatus },
          { label: 'Not implemented', count: notImpl, status: 'not_implemented' as ResponseStatus },
          { label: 'Not assessed', count: notAssessed, status: 'not_assessed' as ResponseStatus },
          { label: 'N/A', count: na, status: 'not_applicable' as ResponseStatus },
        ].map(({ label, count, status }) => (
          <span key={status} className="flex items-center gap-1.5 text-muted">
            <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${STATUS_DOT[status]}`} />
            <span className="font-semibold text-foreground">{count}</span>
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

type CollectionCoverage = {
  state: 'loading' | 'unavailable' | 'unreleased' | 'available';
  coverage?: Record<string, unknown>;
};

function CoverageLimitations({ data }: { data: CollectionCoverage }) {
  const coverage = data.coverage ?? {};
  const scanCounts = (coverage.scan_status_counts ?? {}) as Record<string, number>;
  const observationCounts = (coverage.observation_status_counts ?? {}) as Record<string, number>;
  const limitationCount = Array.isArray(coverage.limitations) ? coverage.limitations.length : null;
  const statement = typeof coverage.coverage_statement === 'string' ? coverage.coverage_statement : null;
  const determinable = coverage.coverage_determinable === true;
  const percentage = typeof coverage.coverage_percentage === 'number' ? coverage.coverage_percentage : null;
  const rows = [
    ...Object.entries(scanCounts).map(([status, count]) => ({ source: 'Scans', status, count })),
    ...Object.entries(observationCounts).map(([status, count]) => ({ source: 'Observations', status, count })),
  ];

  return (
    <section className="rounded border border-amber-500/30 bg-amber-500/5 p-4 space-y-2" aria-label="collection-limitations">
      <h3 className="text-sm font-semibold text-foreground">Collection completeness and limitations</h3>
      {data.state === 'loading' && <p className="text-xs text-muted">Loading authoritative collection status…</p>}
      {data.state === 'unreleased' && <p className="text-xs text-amber-200">Collection limitation details are unavailable until a report is released. This does not indicate complete coverage.</p>}
      {data.state === 'unavailable' && <p className="text-xs text-muted">Authoritative collection limitation details are unavailable.</p>}
      {data.state === 'available' && (
        <>
          <p className="text-xs text-foreground">{statement ?? 'Collection status unavailable.'}</p>
          <p className="text-xs text-muted">
            {determinable && percentage !== null ? `Coverage percentage: ${percentage}%` : 'Coverage percentage unavailable'}
            {limitationCount !== null ? ` · ${limitationCount} reported limitation${limitationCount === 1 ? '' : 's'}` : ''}
          </p>
          {rows.length > 0 ? (
            <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
              {rows.map(({ source, status, count }) => (
                <li key={`${source}:${status}`}>{source}: <span className="font-medium text-foreground">{status.replace(/_/g, ' ')}</span> ({count})</li>
              ))}
            </ul>
          ) : <p className="text-xs text-muted">Collection status counts unavailable.</p>}
        </>
      )}
    </section>
  );
}

function ControlChip({ control }: { control: QuestionnaireControlResponse }) {
  const [hovered, setHovered] = useState(false);
  const colorClass = STATUS_COLOR[control.response_status] ?? STATUS_COLOR.not_assessed;

  return (
    <div className="relative">
      <button
        type="button"
        className={`rounded border px-1.5 py-0.5 text-[11px] font-mono font-medium transition-colors ${colorClass} hover:opacity-90`}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        onFocus={() => setHovered(true)}
        onBlur={() => setHovered(false)}
        aria-label={`${control.control_id}: ${control.control_name} — ${STATUS_LABEL[control.response_status]}`}
      >
        {control.control_id}
      </button>
      {hovered && (
        <div className="absolute bottom-full left-0 mb-1.5 z-10 w-64 rounded border border-border bg-surface-2 p-2 shadow-lg pointer-events-none">
          <p className="text-[11px] font-mono font-semibold text-primary">{control.control_id}</p>
          <p className="text-[11px] text-foreground mt-0.5 leading-snug">{control.control_name}</p>
          <p className={`text-[11px] mt-1 font-medium ${STATUS_COLOR[control.response_status]?.split(' ')[2] ?? 'text-muted'}`}>
            {STATUS_LABEL[control.response_status]}
          </p>
          {control.evidence_text && (
            <p className="text-[11px] text-muted mt-1 line-clamp-2">{control.evidence_text}</p>
          )}
        </div>
      )}
    </div>
  );
}

function CategorySection({
  category,
  controls,
}: {
  category: Category;
  controls: QuestionnaireControlResponse[];
}) {
  const implemented = controls.filter((c) => c.response_status === 'implemented').length;
  const partial = controls.filter((c) => c.response_status === 'partial').length;
  const gaps = controls.filter((c) => c.response_status === 'not_implemented').length;
  const notAssessed = controls.filter((c) => c.response_status === 'not_assessed').length;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <p className="text-xs font-semibold text-foreground">{category}</p>
        <p className="text-xs text-muted flex-1">{CATEGORY_LABELS[category].split('—')[1]?.trim()}</p>
        <div className="flex gap-2 text-[11px] text-muted shrink-0">
          {implemented > 0 && <span className="text-green-400">{implemented} impl.</span>}
          {partial > 0 && <span className="text-amber-300">{partial} partial</span>}
          {gaps > 0 && <span className="text-red-400">{gaps} gaps</span>}
          {notAssessed > 0 && <span>{notAssessed} pending</span>}
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {controls.map((c) => (
          <ControlChip key={c.control_id} control={c} />
        ))}
      </div>
    </div>
  );
}

function Legend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] text-muted">
      {(Object.entries(STATUS_LABEL) as [ResponseStatus, string][]).map(([status, label]) => (
        <span key={status} className="flex items-center gap-1">
          <span
            className={`inline-block w-3 h-3 rounded border text-[10px] font-mono font-semibold flex items-center justify-center ${STATUS_COLOR[status]}`}
          />
          {label}
        </span>
      ))}
      <span className="text-muted italic">Hover a control ID to see details</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function CoveragePageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') || getStoredEngagementId();

  const [questionnaire, setQuestionnaire] = useState<Questionnaire | null>(null);
  const [collectionCoverage, setCollectionCoverage] = useState<CollectionCoverage>({ state: 'loading' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    setError(null);
    portalApi
      .listQuestionnaires(engagementId)
      .then((list) => {
        setQuestionnaire(list[0] ?? null);
      })
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setError('Engagement not found.');
        } else {
          setError('Failed to load coverage data.');
        }
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  useEffect(() => {
    if (!engagementId) return;
    let active = true;
    setCollectionCoverage({ state: 'loading' });
    portalApi.listReports(engagementId, { limit: 1, offset: 0 }).then(async (reports) => {
      const latestPage = reports.total > 1
        ? await portalApi.listReports(engagementId, { limit: 1, offset: reports.total - 1 })
        : reports;
      const latest = latestPage.items[0];
      if (!latest || (latest.status !== 'finalized' && latest.status !== 'finalized_limited')) {
        if (active) setCollectionCoverage({ state: latest ? 'unreleased' : 'unavailable' });
        return;
      }
      const document = await portalApi.getReport(engagementId, latest.version);
      const proof = document.report.report_proof as Record<string, unknown> | undefined;
      const coverage = proof?.coverage;
      if (active && coverage && typeof coverage === 'object') {
        setCollectionCoverage({ state: 'available', coverage: coverage as Record<string, unknown> });
      } else if (active) {
        setCollectionCoverage({ state: 'unavailable' });
      }
    }).catch((error: unknown) => {
      if (active) setCollectionCoverage({
        state: error instanceof PortalApiError && error.status === 403 ? 'unreleased' : 'unavailable',
      });
    });
    return () => { active = false; };
  }, [engagementId]);

  if (!engagementId) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <p className="text-sm font-semibold text-foreground">No engagement selected</p>
        <p className="mt-1 text-xs text-muted">
          <Link href="/" className="underline hover:text-foreground transition-colors">
            Select an engagement from the dashboard.
          </Link>
        </p>
      </div>
    );
  }

  const byCategory: Record<Category, QuestionnaireControlResponse[]> = {
    GOVERN: [],
    MAP: [],
    MEASURE: [],
    MANAGE: [],
  };
  if (questionnaire) {
    for (const r of questionnaire.responses) {
      const cat = r.category as Category;
      if (byCategory[cat]) byCategory[cat].push(r);
    }
  }

  return (
    <div className="space-y-6" aria-label="coverage-page">
      <div>
        <h2 className="text-base font-semibold text-foreground">NIST AI RMF Control Coverage</h2>
        <p className="mt-0.5 text-xs text-muted">
          Per-control implementation status across all 69 NIST AI RMF 1.0 subcategories.
        </p>
      </div>

      {loading && (
        <div className="space-y-3">
          <div className="h-28 rounded border border-border bg-surface-2 animate-pulse" />
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {error && !loading && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {!loading && !error && <CoverageLimitations data={collectionCoverage} />}

      {!loading && !error && !questionnaire && (
        <div className="rounded border border-border bg-surface-2 p-6 text-center space-y-1">
          <p className="text-sm font-medium text-foreground">Assessment not started</p>
          <p className="text-xs text-muted">
            The NIST AI RMF questionnaire has not been initiated for this engagement.
            Contact your assessor to begin the control evaluation.
          </p>
        </div>
      )}

      {!loading && questionnaire && (
        <>
          <SummaryBar questionnaire={questionnaire} />

          <Legend />

          <div className="space-y-5">
            {CATEGORIES.map((cat) => (
              <div key={cat} className="rounded border border-border bg-surface-2 p-4">
                <CategorySection category={cat} controls={byCategory[cat]} />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export default function CoveragePage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-3">
          <div className="h-28 rounded border border-border bg-surface-2 animate-pulse" />
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      }
    >
      <CoveragePageInner />
    </Suspense>
  );
}
