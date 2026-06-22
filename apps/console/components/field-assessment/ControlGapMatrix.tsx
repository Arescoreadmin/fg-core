'use client';

// Renders the framework_summary section from a GovernanceReport.
// framework_summary maps framework names to covered control IDs.
// Known frameworks with no coverage are shown as gap rows.
// DIFF-3: clicking a framework row expands inline to show relevant observations.

import { useState } from 'react';
import type { Observation } from '@/lib/fieldAssessmentApi';

const KNOWN_FRAMEWORKS = ['NIST-AI-RMF', 'HIPAA', 'CMMC', 'SOC2'];

// Reverse-maps framework → observation domains that feed it
const FRAMEWORK_DOMAINS: Record<string, string[]> = {
  'NIST-AI-RMF': ['ai_governance', 'data_security', 'access_management', 'operational_security', 'incident_response', 'training'],
  'HIPAA': ['data_security', 'compliance', 'vendor_management', 'incident_response', 'training'],
  'SOC2': ['data_security', 'access_management', 'operational_security', 'compliance', 'vendor_management', 'incident_response', 'training'],
  'CMMC': ['access_management', 'operational_security', 'incident_response', 'compliance'],
  'ISO-27001': ['data_security', 'access_management', 'operational_security', 'vendor_management', 'incident_response'],
};

type CellState = 'covered' | 'gap' | 'partial' | 'unknown';

const CELL_LABEL: Record<CellState, string> = {
  covered: 'Covered',
  gap: 'Gap',
  partial: 'Partial',
  unknown: 'Unknown',
};

const CELL_COLOR: Record<CellState, string> = {
  covered: 'text-success border-success/30 bg-success/5',
  gap: 'text-danger border-danger/30 bg-danger/5',
  partial: 'text-warning border-warning/30 bg-warning/5',
  unknown: 'text-muted border-border bg-surface-2',
};

const OBS_TYPE_COLOR: Record<string, string> = {
  finding: 'text-red-300 border-red-500/30 bg-red-500/5',
  gap: 'text-amber-300 border-amber-500/30 bg-amber-500/5',
  concern: 'text-orange-300 border-orange-500/30 bg-orange-500/5',
};

function CellBadge({ state }: { state: CellState }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${CELL_COLOR[state]}`}
      aria-label={CELL_LABEL[state]}
    >
      {CELL_LABEL[state]}
    </span>
  );
}

interface Props {
  data: Record<string, string[]> | null | undefined;
  observations?: Observation[];
}

export function ControlGapMatrix({ data, observations = [] }: Props) {
  const [expandedFw, setExpandedFw] = useState<string | null>(null);

  if (data == null) return null;

  const backendFrameworks = Object.keys(data);
  const allFrameworks = [
    ...KNOWN_FRAMEWORKS,
    ...backendFrameworks.filter((f) => !KNOWN_FRAMEWORKS.includes(f)),
  ];

  function relatedObservations(fw: string): Observation[] {
    const domains = FRAMEWORK_DOMAINS[fw] ?? [];
    return observations.filter(
      (o) => domains.includes(o.domain) && !o.deleted_at
        && ['finding', 'gap', 'concern'].includes(o.observation_type)
    );
  }

  return (
    <div className="space-y-2" aria-label="control-gap-matrix">
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">Control Gap Matrix</p>
      <p className="text-[11px] text-muted">Click a framework row to see related observations.</p>
      <div className="overflow-x-auto">
        <table className="w-full text-xs border-collapse" role="table" aria-label="Framework control coverage">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left py-2 px-3 text-muted font-semibold w-40" scope="col">Framework</th>
              <th className="text-left py-2 px-3 text-muted font-semibold" scope="col">Coverage</th>
              <th className="text-left py-2 px-3 text-muted font-semibold w-20" scope="col">Status</th>
              <th className="text-left py-2 px-3 text-muted font-semibold w-20" scope="col">Controls</th>
            </tr>
          </thead>
          <tbody>
            {allFrameworks.map((fw) => {
              const controls = data[fw] ?? [];
              const state: CellState = controls.length === 0 ? 'gap' : 'covered';
              const isExpanded = expandedFw === fw;
              const related = relatedObservations(fw);

              return [
                <tr
                  key={fw}
                  className={`border-b border-border transition-colors cursor-pointer select-none ${isExpanded ? 'bg-surface-2' : 'hover:bg-surface-2'}`}
                  onClick={() => setExpandedFw(isExpanded ? null : fw)}
                  aria-expanded={isExpanded}
                  tabIndex={0}
                  onKeyDown={(e) => e.key === 'Enter' && setExpandedFw(isExpanded ? null : fw)}
                >
                  <td className="py-2 px-3 font-medium text-foreground" scope="row">
                    <span className="flex items-center gap-1">
                      <span className="text-[10px] text-muted">{isExpanded ? '▲' : '▼'}</span>
                      {fw}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    {controls.length > 0 ? (
                      <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
                        {controls.map((c, i) => (
                          <span
                            key={i}
                            className="font-mono inline-flex items-center rounded px-1.5 py-0.5 border border-info/20 bg-info/5 text-info"
                            aria-label={`Control ${c} covered`}
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-muted">No controls mapped</span>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <CellBadge state={state} />
                  </td>
                  <td className="py-2 px-3 font-mono text-muted">{controls.length}</td>
                </tr>,
                isExpanded && (
                  <tr key={`${fw}-detail`} className="border-b border-border bg-surface-1">
                    <td colSpan={4} className="px-3 py-2">
                      {related.length === 0 ? (
                        <p className="text-xs text-muted py-1">No gap/finding observations captured for this framework yet.</p>
                      ) : (
                        <div className="space-y-1.5 py-1">
                          <p className="text-[11px] font-semibold text-muted uppercase tracking-wide">
                            {related.length} observation{related.length !== 1 ? 's' : ''} driving this framework coverage
                          </p>
                          {related.map((o) => (
                            <div key={o.id} className="rounded border border-border bg-surface-2 p-2 space-y-0.5">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-medium text-xs text-foreground">{o.title}</span>
                                <span className={`inline-flex items-center rounded px-1 py-0.5 text-[10px] border font-medium ${OBS_TYPE_COLOR[o.observation_type] ?? 'text-muted border-border'}`}>
                                  {o.observation_type}
                                </span>
                                <span className="text-[10px] text-muted capitalize">{o.severity}</span>
                                <span className="text-[10px] text-muted capitalize ml-auto">{o.domain.replace(/_/g, ' ')}</span>
                              </div>
                              <p className="text-[11px] text-muted line-clamp-2">{o.description}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                ),
              ];
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
