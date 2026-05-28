'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  portalApi,
  PortalApiError,
  type AttestationHealthSummary,
  type EngagementSummary,
  type FindingSummary,
  type RemediationRoadmap,
  type Questionnaire,
  type RemediationPhaseFinding,
} from '@/lib/portalApi';
import {
  getStoredEngagementId,
  setStoredEngagementId,
} from '@/lib/engagementStore';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';
type NistFunction = 'GOVERN' | 'MAP' | 'MEASURE' | 'MANAGE';

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface FunctionCoverage {
  fn: NistFunction;
  implemented: number;
  partial: number;
  total: number;
}

// ---------------------------------------------------------------------------
// Derived data helpers
// ---------------------------------------------------------------------------

const NIST_FUNCTIONS: NistFunction[] = ['GOVERN', 'MAP', 'MEASURE', 'MANAGE'];

function deriveSeverityCounts(findings: FindingSummary[]): SeverityCounts {
  const open = findings.filter((f) => f.status === 'open' || f.status === 'in_progress');
  return {
    critical: open.filter((f) => f.severity === 'critical').length,
    high: open.filter((f) => f.severity === 'high').length,
    medium: open.filter((f) => f.severity === 'medium').length,
    low: open.filter((f) => f.severity === 'low').length,
  };
}

function deriveFunctionCoverage(questionnaires: Questionnaire[]): FunctionCoverage[] {
  if (!questionnaires.length) return [];
  const responses = questionnaires[0].responses;
  const buckets: Record<NistFunction, { implemented: number; partial: number; total: number }> = {
    GOVERN: { implemented: 0, partial: 0, total: 0 },
    MAP: { implemented: 0, partial: 0, total: 0 },
    MEASURE: { implemented: 0, partial: 0, total: 0 },
    MANAGE: { implemented: 0, partial: 0, total: 0 },
  };
  for (const r of responses) {
    const fn = (r.control_id.split('-')[0] ?? '') as NistFunction;
    if (!(fn in buckets)) continue;
    buckets[fn].total += 1;
    if (r.response_status === 'implemented') buckets[fn].implemented += 1;
    if (r.response_status === 'partial') buckets[fn].partial += 1;
  }
  return NIST_FUNCTIONS.map((fn) => ({ fn, ...buckets[fn] }));
}

function pickImmediateActions(roadmap: RemediationRoadmap): RemediationPhaseFinding[] {
  const phase = roadmap.phases.find((p) => p.phase_id === 'immediate');
  if (!phase) return [];
  return phase.findings.slice(0, 3);
}

// ---------------------------------------------------------------------------
// Style maps
// ---------------------------------------------------------------------------

const SEV_STYLE: Record<SeverityKey, { border: string; text: string; label: string }> = {
  critical: { border: 'border-red-500/40 bg-red-500/10', text: 'text-red-300', label: 'Critical' },
  high: { border: 'border-orange-500/40 bg-orange-500/10', text: 'text-orange-300', label: 'High' },
  medium: { border: 'border-amber-500/40 bg-amber-500/10', text: 'text-amber-200', label: 'Medium' },
  low: { border: 'border-blue-500/40 bg-blue-500/10', text: 'text-blue-300', label: 'Low' },
  info: { border: 'border-border bg-surface-2', text: 'text-muted', label: 'Info' },
};

const EFFORT_TEXT: Record<string, string> = {
  low: 'text-green-300',
  medium: 'text-amber-200',
  high: 'text-red-300',
};

const FN_COLOR: Record<NistFunction, { bar: string; text: string }> = {
  GOVERN: { bar: 'bg-blue-500', text: 'text-blue-300' },
  MAP: { bar: 'bg-purple-500', text: 'text-purple-300' },
  MEASURE: { bar: 'bg-cyan-500', text: 'text-cyan-300' },
  MANAGE: { bar: 'bg-teal-500', text: 'text-teal-300' },
};

const HEALTH_ACCENT = {
  green: { border: 'hover:border-green-500/40', value: 'text-green-300' },
  amber: { border: 'hover:border-amber-500/40', value: 'text-amber-200' },
  red: { border: 'hover:border-red-500/40', value: 'text-red-300' },
  default: { border: 'hover:border-primary/40', value: 'text-foreground' },
};

// ---------------------------------------------------------------------------
// Small primitives
// ---------------------------------------------------------------------------

function SkeletonBar({ h = 'h-3' }: { h?: string }) {
  return <div className={`${h} rounded-full bg-surface-3 animate-pulse`} />;
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-xs font-semibold text-muted uppercase tracking-wider">{children}</p>
  );
}

// ---------------------------------------------------------------------------
// Panel 1 — NIST AI RMF coverage bar
// ---------------------------------------------------------------------------

function CoveragePanel({ roadmap }: { roadmap: RemediationRoadmap }) {
  const cur = roadmap.current_coverage_pct;
  const proj = roadmap.projected_coverage_pct;
  const delta = proj - cur;

  return (
    <div className="rounded border border-border bg-surface-2 p-4 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div>
          <p className="text-xs font-semibold text-muted uppercase tracking-wider">
            NIST AI RMF Coverage
          </p>
          <div className="flex items-end gap-2 mt-1">
            <p className="text-2xl font-bold text-foreground">{cur}%</p>
            {delta > 0 && (
              <p className="text-sm text-muted mb-0.5">
                → <span className="text-green-300 font-semibold">{proj}%</span>
                <span className="ml-1 text-green-400 text-xs">+{delta.toFixed(1)}pp potential</span>
              </p>
            )}
          </div>
        </div>
        <Link
          href={`/coverage`}
          className="text-xs text-muted hover:text-foreground transition-colors underline shrink-0"
        >
          View matrix →
        </Link>
      </div>

      <div className="space-y-1">
        <div className="relative h-2.5 w-full rounded-full bg-surface-3 overflow-hidden">
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-green-500/25 transition-all duration-700"
            style={{ width: `${proj}%` }}
          />
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-green-500/70 transition-all duration-700"
            style={{ width: `${cur}%` }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-muted">
          <span>0%</span>
          <span>100%</span>
        </div>
      </div>

      <div className="flex flex-wrap gap-4 text-xs text-muted">
        <span>
          <span className="font-semibold text-foreground">{roadmap.total_open_findings}</span> open findings
        </span>
        {roadmap.phases.find((p) => p.phase_id === 'immediate')?.findings.length ? (
          <span className="text-red-300">
            <span className="font-semibold">
              {roadmap.phases.find((p) => p.phase_id === 'immediate')!.findings.length}
            </span>{' '}
            need immediate action
          </span>
        ) : null}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel 2 — Finding severity strip
// ---------------------------------------------------------------------------

function SeverityStrip({
  counts,
  engagementId,
}: {
  counts: SeverityCounts;
  engagementId: string;
}) {
  const sevs: SeverityKey[] = ['critical', 'high', 'medium', 'low'];
  const total = sevs.reduce((s, k) => s + counts[k], 0);

  return (
    <div className="rounded border border-border bg-surface-2 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <SectionLabel>Open Findings</SectionLabel>
        <Link
          href={`/findings?e=${engagementId}`}
          className="text-xs text-muted hover:text-foreground transition-colors underline"
        >
          View all →
        </Link>
      </div>

      {total === 0 ? (
        <p className="text-xs text-green-300 font-medium">No open findings — all clear.</p>
      ) : (
        <div className="grid grid-cols-4 gap-2">
          {sevs.map((sev) => {
            const { border, text, label } = SEV_STYLE[sev];
            const count = counts[sev];
            return (
              <Link
                key={sev}
                href={`/findings?e=${engagementId}&severity=${sev}`}
                className={`rounded border ${border} p-2.5 text-center space-y-0.5 hover:opacity-80 transition-opacity`}
              >
                <p className={`text-xl font-bold ${text}`}>{count}</p>
                <p className={`text-[10px] font-medium ${text}`}>{label}</p>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel 3 — NIST function heatmap
// ---------------------------------------------------------------------------

function NistFunctionHeatmap({
  coverage,
  engagementId,
}: {
  coverage: FunctionCoverage[];
  engagementId: string;
}) {
  if (!coverage.length) return null;

  return (
    <div className="rounded border border-border bg-surface-2 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <SectionLabel>Control Coverage by Function</SectionLabel>
        <Link
          href={`/coverage?e=${engagementId}`}
          className="text-xs text-muted hover:text-foreground transition-colors underline"
        >
          Full matrix →
        </Link>
      </div>

      <div className="space-y-2.5">
        {coverage.map(({ fn, implemented, partial, total }) => {
          if (total === 0) return null;
          const implPct = Math.round((implemented / total) * 100);
          const partPct = Math.round((partial / total) * 100);
          const { bar, text } = FN_COLOR[fn];
          const notCoveredCount = total - implemented - partial;

          return (
            <div key={fn} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className={`font-semibold ${text}`}>{fn}</span>
                <span className="text-muted">
                  <span className={`font-medium ${implPct >= 60 ? 'text-foreground' : implPct >= 30 ? 'text-amber-200' : 'text-red-300'}`}>
                    {implemented}/{total}
                  </span>
                  {' '}implemented
                  {partial > 0 && (
                    <span className="text-muted"> · {partial} partial</span>
                  )}
                  {notCoveredCount > 0 && (
                    <span className="text-red-300/60"> · {notCoveredCount} gap{notCoveredCount !== 1 ? 's' : ''}</span>
                  )}
                </span>
              </div>
              <div className="relative h-1.5 w-full rounded-full bg-surface-3 overflow-hidden">
                <div
                  className={`absolute inset-y-0 left-0 rounded-full ${bar} opacity-30 transition-all duration-700`}
                  style={{ width: `${implPct + partPct}%` }}
                />
                <div
                  className={`absolute inset-y-0 left-0 rounded-full ${bar} transition-all duration-700`}
                  style={{ width: `${implPct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      <p className="text-[10px] text-muted">
        Based on NIST AI RMF 1.0 — scan evidence fused with manual questionnaire responses.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel 4 — Immediate actions callout
// ---------------------------------------------------------------------------

function ImmediateActionsCallout({
  actions,
  engagementId,
}: {
  actions: RemediationPhaseFinding[];
  engagementId: string;
}) {
  if (!actions.length) return null;

  return (
    <div className="rounded border border-red-500/25 bg-red-500/5 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2 h-2 rounded-full bg-red-400" />
          <SectionLabel>Immediate Actions</SectionLabel>
        </div>
        <Link
          href={`/remediation?e=${engagementId}`}
          className="text-xs text-muted hover:text-foreground transition-colors underline"
        >
          Full roadmap →
        </Link>
      </div>

      <div className="space-y-1.5">
        {actions.map((f) => {
          const sev = SEV_STYLE[f.severity as SeverityKey] ?? SEV_STYLE.info;
          return (
            <div key={f.finding_id} className="flex items-center gap-2 text-xs">
              <span className={`rounded px-1.5 py-0.5 border text-[10px] font-medium ${sev.border} ${sev.text} shrink-0`}>
                {f.severity.charAt(0).toUpperCase() + f.severity.slice(1)}
              </span>
              <span className="flex-1 min-w-0 truncate text-foreground">{f.title}</span>
              <span className={`shrink-0 font-medium ${EFFORT_TEXT[f.effort_level] ?? 'text-muted'}`}>
                {f.effort_level} effort
              </span>
            </div>
          );
        })}
      </div>

      <p className="text-[10px] text-muted">
        Score ≥ 28 — severity × scan evidence × NIST control coverage.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Findings pagination helper — pages through all findings up to HARD_MAX
// ---------------------------------------------------------------------------

async function fetchAllFindings(
  engagementId: string,
  hardMax = 500,
): Promise<FindingSummary[]> {
  const PAGE = 100;
  const all: FindingSummary[] = [];
  let offset = 0;
  while (true) {
    const res = await portalApi.listFindings(engagementId, { limit: PAGE, offset });
    all.push(...res.items);
    if (res.items.length < PAGE || all.length >= hardMax) break;
    offset += PAGE;
  }
  return all;
}

// ---------------------------------------------------------------------------
// Risk posture panel (composite — shown when engagement is active)
// ---------------------------------------------------------------------------

function RiskPosturePanel({ engagementId }: { engagementId: string }) {
  const [roadmap, setRoadmap] = useState<RemediationRoadmap | null>(null);
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [questionnaires, setQuestionnaires] = useState<Questionnaire[]>([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let isCurrent = true;
    setLoading(true);
    setFailed(false);
    Promise.allSettled([
      portalApi.getRemediationRoadmap(engagementId),
      fetchAllFindings(engagementId),
      portalApi.listQuestionnaires(engagementId),
    ]).then(([rmRes, fnRes, qsRes]) => {
      if (!isCurrent) return;
      if (rmRes.status === 'fulfilled') setRoadmap(rmRes.value);
      if (fnRes.status === 'fulfilled') setFindings(fnRes.value);
      if (qsRes.status === 'fulfilled') setQuestionnaires(qsRes.value);
      const allFailed = [rmRes, fnRes, qsRes].every((r) => r.status === 'rejected');
      if (allFailed) setFailed(true);
      setLoading(false);
    });
    return () => {
      isCurrent = false;
    };
  }, [engagementId]);

  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <SkeletonBar h="h-28" />
        <SkeletonBar h="h-20" />
        <SkeletonBar h="h-24" />
      </div>
    );
  }

  if (failed) {
    return (
      <p className="text-xs text-muted text-center py-4">
        Risk data unavailable — check connection or engagement status.
      </p>
    );
  }

  const severityCounts = deriveSeverityCounts(findings);
  const functionCoverage = deriveFunctionCoverage(questionnaires);
  const immediateActions = roadmap ? pickImmediateActions(roadmap) : [];

  return (
    <div className="space-y-3">
      {roadmap && <CoveragePanel roadmap={roadmap} />}
      <SeverityStrip counts={severityCounts} engagementId={engagementId} />
      {functionCoverage.length > 0 && (
        <NistFunctionHeatmap coverage={functionCoverage} engagementId={engagementId} />
      )}
      {immediateActions.length > 0 && (
        <ImmediateActionsCallout actions={immediateActions} engagementId={engagementId} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attestation health cards (existing, unchanged)
// ---------------------------------------------------------------------------

function HealthCard({
  title,
  value,
  subtitle,
  href,
  accent = 'default',
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  href: string;
  accent?: keyof typeof HEALTH_ACCENT;
}) {
  const { border, value: valClass } = HEALTH_ACCENT[accent];
  return (
    <Link
      href={href}
      className={`rounded border border-border bg-surface-2 p-4 block space-y-1 transition-colors ${border}`}
    >
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">{title}</p>
      <p className={`text-2xl font-bold ${valClass}`}>{value}</p>
      {subtitle && <p className="text-xs text-muted">{subtitle}</p>}
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Engagement card
// ---------------------------------------------------------------------------

const ENG_PAGE_LINKS = [
  { key: 'findings', label: 'Findings', path: '/findings' },
  { key: 'reports', label: 'Reports', path: '/reports' },
  { key: 'coverage', label: 'Coverage', path: '/coverage' },
  { key: 'remediation', label: 'Remediation', path: '/remediation' },
] as const;

function EngagementCard({
  eng,
  active,
  onSelect,
}: {
  eng: EngagementSummary;
  active: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <div
      className={`rounded border p-4 space-y-3 transition-colors ${
        active ? 'border-primary/40 bg-surface-2' : 'border-border bg-surface-2'
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-foreground">{eng.client_name}</p>
          <p className="text-xs text-muted capitalize mt-0.5">
            {eng.assessment_type.replace(/_/g, ' ')} &middot;{' '}
            {eng.status.replace(/_/g, ' ')}
          </p>
        </div>
        {active && (
          <span className="text-[11px] px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20 text-primary font-medium shrink-0">
            Active
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {ENG_PAGE_LINKS.map(({ key, label, path }) => (
          <Link
            key={key}
            href={`${path}?e=${eng.id}`}
            onClick={() => onSelect(eng.id)}
            className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 hover:border-primary/30 transition-colors"
          >
            {label}
          </Link>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page root
// ---------------------------------------------------------------------------

export default function PortalHome() {
  const [health, setHealth] = useState<AttestationHealthSummary | null>(null);
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeId, setActiveId] = useState<string>('');

  useEffect(() => {
    setActiveId(getStoredEngagementId());
    Promise.allSettled([
      portalApi.getAttestationHealth(),
      portalApi.listEngagements({ limit: 20 }),
    ]).then(([healthRes, engRes]) => {
      if (healthRes.status === 'fulfilled') setHealth(healthRes.value);
      if (engRes.status === 'fulfilled') {
        const items = engRes.value.items;
        setEngagements(items);
        const storedId = getStoredEngagementId();
        const storedValid = storedId !== '' && items.some((e) => e.id === storedId);
        if (storedId && !storedValid) {
          setActiveId('');
          setStoredEngagementId('');
        }
        if (items.length === 1 && !storedValid) {
          setActiveId(items[0].id);
          setStoredEngagementId(items[0].id);
        }
      }
      setLoading(false);
    });
  }, []);

  function handleSelect(id: string) {
    setActiveId(id);
    setStoredEngagementId(id);
  }

  const healthPct = health ? Math.round(health.health_pct) : null;
  const overdueCount = health?.overdue ?? 0;
  const dueSoonCount = health?.due_soon ?? 0;

  return (
    <div className="space-y-8" aria-label="portal-overview">
      <div>
        <h1 className="text-xl font-bold text-foreground">AI Governance Portal</h1>
        <p className="mt-1 text-sm text-muted">
          View your assessment findings, reports, and compliance status.
        </p>
      </div>

      {/* Engagement selector */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <SectionLabel>
            {engagements.length === 1 ? 'Your Engagement' : 'Your Engagements'}
          </SectionLabel>
          {loading && <span className="text-xs text-muted">Loading…</span>}
        </div>

        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2].map((i) => (
              <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && engagements.length === 0 && (
          <div className="rounded border border-border bg-surface-2 p-6 text-center space-y-1">
            <p className="text-sm font-medium text-foreground">No engagements available</p>
            <p className="text-xs text-muted">
              Your assessor will create an engagement and notify you when it is ready.
            </p>
          </div>
        )}

        {!loading && engagements.length > 0 && (
          <div className="space-y-2">
            {engagements.map((eng) => (
              <EngagementCard
                key={eng.id}
                eng={eng}
                active={eng.id === activeId}
                onSelect={handleSelect}
              />
            ))}
          </div>
        )}
      </div>

      {/* Risk posture dashboard — only shown when an engagement is active */}
      {!loading && activeId && (
        <div className="space-y-3">
          <SectionLabel>Risk Posture</SectionLabel>
          <RiskPosturePanel engagementId={activeId} />
        </div>
      )}

      {/* Attestation health */}
      {!loading && health && (
        <div className="space-y-3">
          <SectionLabel>Compliance Health</SectionLabel>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <HealthCard
              title="Health Score"
              value={`${healthPct}%`}
              subtitle="Attestation compliance"
              href="/continuity"
              accent={
                healthPct != null && healthPct >= 80
                  ? 'green'
                  : healthPct != null && healthPct >= 60
                  ? 'amber'
                  : 'red'
              }
            />
            <HealthCard
              title="Overdue"
              value={overdueCount}
              subtitle="Assets past due"
              href="/attestation"
              accent={overdueCount > 0 ? 'red' : 'green'}
            />
            <HealthCard
              title="Due Soon"
              value={dueSoonCount}
              subtitle="Upcoming attestations"
              href="/attestation"
              accent={dueSoonCount > 0 ? 'amber' : 'green'}
            />
            <HealthCard
              title="Compliant"
              value={health.compliant}
              subtitle={`of ${health.total} total assets`}
              href="/continuity"
              accent="green"
            />
          </div>
        </div>
      )}

      {/* Quick access — fallback navigation when no engagement selected */}
      {!loading && !activeId && (
        <div className="space-y-3">
          <SectionLabel>Quick Access</SectionLabel>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Link
              href="/findings"
              className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
            >
              <p className="text-sm font-semibold text-foreground">Findings</p>
              <p className="mt-1 text-xs text-muted">
                Review assessment findings by severity and framework mapping.
              </p>
            </Link>
            <Link
              href="/reports"
              className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
            >
              <p className="text-sm font-semibold text-foreground">Reports</p>
              <p className="mt-1 text-xs text-muted">
                Download signed governance reports in JSON or PDF format.
              </p>
            </Link>
            <Link
              href="/attestation"
              className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
            >
              <p className="text-sm font-semibold text-foreground">Attestation</p>
              <p className="mt-1 text-xs text-muted">
                Submit asset attestations for operator review and track history.
              </p>
            </Link>
            <Link
              href="/continuity"
              className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
            >
              <p className="text-sm font-semibold text-foreground">Continuity</p>
              <p className="mt-1 text-xs text-muted">
                Track overdue attestations and asset governance gaps.
              </p>
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
