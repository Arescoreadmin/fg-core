'use client';

import { Suspense, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  portalApi,
  PortalApiError,
  type RemediationRoadmap,
  type RemediationPhaseFinding,
  type RemediationPhase,
} from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  info: 'border-border bg-surface-2 text-muted',
};

const EFFORT_CLASS: Record<string, string> = {
  low: 'text-green-300',
  medium: 'text-amber-200',
  high: 'text-red-300',
};

const EFFORT_LABEL: Record<string, string> = {
  low: 'Low effort',
  medium: 'Medium effort',
  high: 'High effort',
};

const PHASE_ACCENT: Record<string, { border: string; badge: string; dot: string }> = {
  immediate: {
    border: 'border-red-500/30',
    badge: 'bg-red-500/10 border-red-500/30 text-red-300',
    dot: 'bg-red-400',
  },
  short_term: {
    border: 'border-amber-500/30',
    badge: 'bg-amber-500/10 border-amber-500/30 text-amber-200',
    dot: 'bg-amber-400',
  },
  planned: {
    border: 'border-blue-500/30',
    badge: 'bg-blue-500/10 border-blue-500/30 text-blue-300',
    dot: 'bg-blue-400',
  },
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function OverviewBanner({ roadmap }: { roadmap: RemediationRoadmap }) {
  const delta = roadmap.projected_coverage_pct - roadmap.current_coverage_pct;
  const totalFindings = roadmap.total_open_findings;
  const immediateCount = roadmap.phases.find((p) => p.phase_id === 'immediate')?.findings.length ?? 0;

  return (
    <div className="rounded border border-border bg-surface-2 p-5 space-y-4">
      <div className="flex flex-wrap gap-6 items-start">
        <div>
          <p className="text-3xl font-bold text-foreground">{roadmap.current_coverage_pct}%</p>
          <p className="text-xs text-muted mt-0.5">Current NIST AI RMF coverage</p>
        </div>
        <div className="flex items-center gap-2 self-center">
          <div className="h-px w-8 bg-border" />
          <span className="text-xs text-muted">full roadmap</span>
          <div className="h-px w-8 bg-border" />
        </div>
        <div>
          <p className="text-3xl font-bold text-green-300">{roadmap.projected_coverage_pct}%</p>
          <p className="text-xs text-muted mt-0.5">
            Projected coverage
            {delta > 0 && (
              <span className="ml-1.5 text-green-400 font-semibold">+{delta.toFixed(1)}pp</span>
            )}
          </p>
        </div>
      </div>

      <div className="space-y-1.5">
        <div className="flex justify-between text-xs text-muted">
          <span>Today</span>
          <span>After all phases</span>
        </div>
        <div className="relative h-3 w-full rounded-full bg-surface-3 overflow-hidden">
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-surface-3"
            style={{ width: '100%' }}
          />
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-green-500/30 transition-all duration-700"
            style={{ width: `${roadmap.projected_coverage_pct}%` }}
          />
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-green-500/70 transition-all duration-700"
            style={{ width: `${roadmap.current_coverage_pct}%` }}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-4 text-xs text-muted pt-1">
        <span>
          <span className="font-semibold text-foreground">{totalFindings}</span> open findings
        </span>
        {immediateCount > 0 && (
          <span className="text-red-300">
            <span className="font-semibold">{immediateCount}</span> require immediate action
          </span>
        )}
        <span>
          <span className="font-semibold text-foreground">{roadmap.phases.reduce((a, p) => a + p.nist_controls_addressed, 0)}</span> NIST controls addressable
        </span>
      </div>
    </div>
  );
}

function FindingCard({
  finding,
  phaseId,
}: {
  finding: RemediationPhaseFinding;
  phaseId: string;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="rounded border border-border bg-surface-3 p-3 space-y-2 cursor-pointer hover:border-border/80 transition-colors"
      onClick={() => setExpanded((v) => !v)}
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      onKeyDown={(e) => e.key === 'Enter' && setExpanded((v) => !v)}
    >
      <div className="flex flex-wrap items-start gap-2">
        <SeverityBadge severity={finding.severity} />
        <span className="flex-1 min-w-0 text-sm font-medium text-foreground">{finding.title}</span>
        <span className={`text-xs font-medium shrink-0 ${EFFORT_CLASS[finding.effort_level] ?? 'text-muted'}`}>
          {EFFORT_LABEL[finding.effort_level]}
        </span>
        <span className="text-muted text-sm">{expanded ? '▲' : '▼'}</span>
      </div>

      {finding.nist_controls_addressed > 0 && (
        <p className="text-xs text-muted">
          Addresses <span className="text-foreground font-medium">{finding.nist_controls_addressed}</span> NIST control{finding.nist_controls_addressed !== 1 ? 's' : ''}
        </p>
      )}

      {expanded && (
        <div className="pt-1 space-y-3 border-t border-border mt-2">
          {finding.remediation_hint && (
            <p className="text-xs text-foreground leading-relaxed">{finding.remediation_hint}</p>
          )}
          {finding.nist_ai_rmf_mappings.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.nist_ai_rmf_mappings.map((m) => (
                <span key={m} className="rounded px-1.5 py-0.5 text-xs border border-blue-500/20 bg-blue-500/5 text-blue-300">
                  {m}
                </span>
              ))}
            </div>
          )}
          <p className="text-[11px] text-muted font-mono">ID: {finding.finding_id}</p>
        </div>
      )}
    </div>
  );
}

function PhaseCard({ phase }: { phase: RemediationPhase }) {
  const accent = PHASE_ACCENT[phase.phase_id] ?? PHASE_ACCENT.planned;
  const isEmpty = phase.findings.length === 0;

  return (
    <div className={`rounded border ${accent.border} bg-surface-2 overflow-hidden`}>
      <div className="p-4 space-y-1 border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2 h-2 rounded-full ${accent.dot}`} />
            <p className="text-sm font-semibold text-foreground">{phase.label}</p>
            <span className={`text-[11px] px-1.5 py-0.5 rounded border font-medium ${accent.badge}`}>
              {phase.window}
            </span>
          </div>
          <div className="flex gap-3 text-xs text-muted shrink-0">
            <span>
              <span className="font-semibold text-foreground">{phase.findings.length}</span> finding{phase.findings.length !== 1 ? 's' : ''}
            </span>
            {phase.compliance_delta_pct > 0 && (
              <span className="text-green-400 font-semibold">
                +{phase.compliance_delta_pct}pp coverage
              </span>
            )}
          </div>
        </div>
        {phase.nist_controls_addressed > 0 && (
          <p className="text-xs text-muted pl-4">
            Addresses {phase.nist_controls_addressed} unique NIST AI RMF control{phase.nist_controls_addressed !== 1 ? 's' : ''}
          </p>
        )}
      </div>

      <div className="p-3 space-y-2">
        {isEmpty ? (
          <p className="text-xs text-muted text-center py-4">No findings in this phase.</p>
        ) : (
          phase.findings.map((f) => (
            <FindingCard key={f.finding_id} finding={f} phaseId={phase.phase_id} />
          ))
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Quick-wins matrix
// ---------------------------------------------------------------------------

function QuickWinsMatrix({ roadmap }: { roadmap: RemediationRoadmap }) {
  const all = roadmap.phases.flatMap((p) => p.findings);
  if (all.length === 0) return null;

  const IMPACT: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0, info: 0 };
  const EFFORT_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 };

  type Cell = { label: string; subLabel: string; accent: string };
  const GRID: Cell[][] = [
    [
      { label: 'Quick Wins', subLabel: 'High impact · Low effort', accent: 'border-green-500/30 bg-green-500/5 text-green-300' },
      { label: 'Strategic', subLabel: 'High impact · Medium effort', accent: 'border-amber-500/30 bg-amber-500/5 text-amber-200' },
      { label: 'Hard Sells', subLabel: 'High impact · High effort', accent: 'border-red-500/30 bg-red-500/5 text-red-300' },
    ],
    [
      { label: 'Fill-ins', subLabel: 'Medium impact · Low effort', accent: 'border-green-500/20 bg-surface-2 text-muted' },
      { label: 'Routine', subLabel: 'Medium impact · Medium effort', accent: 'border-border bg-surface-2 text-muted' },
      { label: 'Defer', subLabel: 'Medium impact · High effort', accent: 'border-border bg-surface-2 text-muted/60' },
    ],
    [
      { label: 'Backlog', subLabel: 'Low impact · Low effort', accent: 'border-border bg-surface-2 text-muted/60' },
      { label: 'Backlog', subLabel: 'Low impact · Medium effort', accent: 'border-border bg-surface-2 text-muted/60' },
      { label: 'Backlog', subLabel: 'Low impact · High effort', accent: 'border-border bg-surface-2 text-muted/60' },
    ],
  ];

  // Assign each finding to its cell.
  const matrix: RemediationPhaseFinding[][][] = GRID.map((row) => row.map(() => []));
  for (const f of all) {
    const impact = IMPACT[f.severity] ?? 0;
    const effortRank = EFFORT_RANK[f.effort_level] ?? 1;
    const row = impact >= 2 ? 0 : impact >= 1 ? 1 : 2;
    matrix[row][effortRank].push(f);
  }

  const quickWins = matrix[0][0];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold text-muted uppercase tracking-wider">Quick-Wins Matrix</p>
        <p className="text-xs text-muted">Impact vs. effort · hover a cell for findings</p>
      </div>

      {quickWins.length > 0 && (
        <div className={`rounded border ${GRID[0][0].accent} p-3 space-y-1.5`}>
          <p className="text-xs font-semibold">{GRID[0][0].label} — start here</p>
          <div className="space-y-1">
            {quickWins.map((f) => (
              <div key={f.finding_id} className="flex items-center gap-2 text-xs text-foreground">
                <SeverityBadge severity={f.severity} />
                <span className="flex-1 min-w-0 truncate">{f.title}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-xs border-collapse" aria-label="quick-wins-matrix">
          <thead>
            <tr>
              <th className="text-left text-muted font-medium pb-1.5 pr-2 w-24">Impact ↑ / Effort →</th>
              <th className="text-center text-green-300 font-medium pb-1.5 px-1">Low</th>
              <th className="text-center text-amber-200 font-medium pb-1.5 px-1">Medium</th>
              <th className="text-center text-red-300 font-medium pb-1.5 px-1">High</th>
            </tr>
          </thead>
          <tbody>
            {(['High', 'Medium', 'Low'] as const).map((impactLabel, rowIdx) => (
              <tr key={impactLabel}>
                <td className="text-muted font-medium pr-2 py-1 whitespace-nowrap">{impactLabel}</td>
                {GRID[rowIdx].map((cell, colIdx) => {
                  const count = matrix[rowIdx][colIdx].length;
                  return (
                    <td key={colIdx} className="px-1 py-1">
                      <div className={`rounded border ${cell.accent} p-2 text-center min-w-[80px]`}>
                        <p className="font-semibold text-[11px]">{cell.label}</p>
                        {count > 0 ? (
                          <p className="text-[11px] font-bold mt-0.5">{count}</p>
                        ) : (
                          <p className="text-[11px] opacity-40 mt-0.5">—</p>
                        )}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function RemediationPageInner() {
  const params = useSearchParams();
  const engagementId = params.get('e') || getStoredEngagementId();

  const [roadmap, setRoadmap] = useState<RemediationRoadmap | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'phases' | 'matrix'>('phases');

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    setError(null);
    portalApi
      .getRemediationRoadmap(engagementId)
      .then(setRoadmap)
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setError('Engagement not found.');
        } else {
          setError('Failed to load remediation roadmap.');
        }
      })
      .finally(() => setLoading(false));
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

  return (
    <div className="space-y-6" aria-label="remediation-page">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-foreground">Remediation Roadmap</h2>
          <p className="mt-0.5 text-xs text-muted">
            Findings grouped by execution phase · prioritized by severity, scan evidence, and NIST control coverage.
          </p>
        </div>
        {roadmap && (
          <div className="flex gap-1 rounded border border-border p-0.5 bg-surface-3 shrink-0">
            <button
              type="button"
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${view === 'phases' ? 'bg-surface-2 text-foreground' : 'text-muted hover:text-foreground'}`}
              onClick={() => setView('phases')}
            >
              Phases
            </button>
            <button
              type="button"
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${view === 'matrix' ? 'bg-surface-2 text-foreground' : 'text-muted hover:text-foreground'}`}
              onClick={() => setView('matrix')}
            >
              Matrix
            </button>
          </div>
        )}
      </div>

      {loading && (
        <div className="space-y-3">
          <div className="h-32 rounded border border-border bg-surface-2 animate-pulse" />
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {error && !loading && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {!loading && !error && roadmap && roadmap.total_open_findings === 0 && (
        <div className="rounded border border-green-500/30 bg-green-500/5 p-6 text-center space-y-1">
          <p className="text-sm font-semibold text-green-300">No open findings</p>
          <p className="text-xs text-muted">All findings have been resolved or accepted. Run a new scan to check for regressions.</p>
        </div>
      )}

      {!loading && !error && roadmap && roadmap.total_open_findings > 0 && (
        <>
          <OverviewBanner roadmap={roadmap} />

          {view === 'phases' && (
            <div className="space-y-4">
              {roadmap.phases.map((phase) => (
                <PhaseCard key={phase.phase_id} phase={phase} />
              ))}
            </div>
          )}

          {view === 'matrix' && <QuickWinsMatrix roadmap={roadmap} />}
        </>
      )}
    </div>
  );
}

export default function RemediationPage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-3">
          <div className="h-32 rounded border border-border bg-surface-2 animate-pulse" />
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      }
    >
      <RemediationPageInner />
    </Suspense>
  );
}
