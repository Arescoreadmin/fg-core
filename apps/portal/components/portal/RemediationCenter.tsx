'use client';
import PortalShell from './PortalShell';
import type { RemediationRoadmap, RemediationPhaseFinding } from '@/lib/portalApi';

const MCIM_ID = 'MCIM-18.6-PORTAL-REMEDIATION';
const AUTHORITY = 'Customer Remediation Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/remediation';
const customerSafe = true;

export type RemediationTab = 'open' | 'overdue' | 'completed' | 'blocked';

interface Props {
  roadmap: RemediationRoadmap | null;
  activeTab: RemediationTab;
  onTabChange?: (t: RemediationTab) => void;
  loading: boolean;
  lastUpdated?: string;
}

const TABS: { id: RemediationTab; label: string }[] = [
  { id: 'open', label: 'Open' },
  { id: 'overdue', label: 'Overdue' },
  { id: 'completed', label: 'Completed' },
  { id: 'blocked', label: 'Blocked' },
];

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  info: 'border-border bg-surface-2 text-muted',
};

const EFFORT_CLASS: Record<string, string> = {
  low: 'border-green-500/40 bg-green-500/10 text-green-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  high: 'border-red-500/40 bg-red-500/10 text-red-300',
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

function getTabFindings(
  roadmap: RemediationRoadmap,
  tab: RemediationTab,
): Array<RemediationPhaseFinding & { phaseLabel: string }> {
  const all = roadmap.phases.flatMap((phase) =>
    phase.findings.map((f) => ({ ...f, phaseLabel: phase.label })),
  );

  switch (tab) {
    case 'open':
      return all.filter((f) => f.status === 'open' || f.status === 'in_progress');
    case 'overdue':
      // Show high/critical open findings as overdue proxy
      return all.filter(
        (f) =>
          (f.status === 'open' || f.status === 'in_progress') &&
          (f.severity === 'critical' || f.severity === 'high'),
      );
    case 'completed':
      return all.filter((f) => f.status === 'resolved' || f.status === 'remediated');
    case 'blocked':
      return all.filter((f) => f.status === 'deferred' || f.status === 'accepted');
    default:
      return [];
  }
}

export default function RemediationCenter({ roadmap, activeTab, onTabChange, loading, lastUpdated }: Props) {
  const tabFindings = roadmap ? getTabFindings(roadmap, activeTab) : [];

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Remediation"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Remediation Center"
      lastUpdated={lastUpdated}
    >
      <section aria-label="remediation-center" data-testid="remediation-center">
      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-border pb-2">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-primary/10 text-primary border border-primary/30'
                : 'text-muted hover:text-foreground hover:bg-surface-2 border border-transparent'
            }`}
            onClick={() => onTabChange?.(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && !roadmap && (
        <p className="text-sm text-muted text-center py-8">No remediation data available.</p>
      )}

      {!loading && roadmap && tabFindings.length === 0 && (
        <p className="text-sm text-muted text-center py-8">
          No items in the {activeTab} state.
        </p>
      )}

      {!loading && tabFindings.length > 0 && (
        <div className="space-y-3">
          {tabFindings.map((f) => (
            <div
              key={f.finding_id}
              className="rounded border border-border bg-surface-2 p-3 space-y-2"
            >
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <span
                  className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${EFFORT_CLASS[f.effort_level] ?? 'border-border bg-surface-2 text-muted'}`}
                >
                  {f.effort_level.charAt(0).toUpperCase() + f.effort_level.slice(1)} effort
                </span>
                <span className="text-xs text-muted ml-auto">Phase: {f.phaseLabel}</span>
              </div>
              <p className="text-sm font-medium text-foreground">{f.title}</p>
              {f.remediation_hint && (
                <p className="text-xs text-muted">{f.remediation_hint}</p>
              )}
              <div className="flex items-center gap-2 pt-1">
                <button
                  type="button"
                  disabled
                  title="Contact your engagement team to request clarification."
                  className="rounded border border-border bg-surface-2 px-2.5 py-1 text-xs text-muted cursor-not-allowed opacity-60"
                  aria-disabled="true"
                >
                  Request Clarification
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
