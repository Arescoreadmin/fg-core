'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp, BookOpen } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-PLAYBOOK-PANEL';
const AUTHORITY = 'Playbook Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

export interface PlaybookStep {
  name: string;
  authority: string;
  drillDown: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  authorities: string[];
  workflow: PlaybookStep[];
  evidence: string[];
  reports: string[];
  remediation: string[];
  policies: string[];
  simulations: string[];
  timeline: string[];
}

interface PlaybookPanelProps {
  playbooks: Playbook[];
  loading?: boolean;
  lastUpdated?: string;
}

function PlaybookRow({ playbook }: { playbook: Playbook }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <li className="rounded border border-border bg-surface-2 text-xs">
      <button
        type="button"
        className="flex w-full items-start justify-between gap-2 px-3 py-2 text-left"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        aria-controls={`playbook-detail-${playbook.id}`}
      >
        <div className="min-w-0 flex-1 flex items-start gap-2">
          <BookOpen className="h-3.5 w-3.5 shrink-0 text-muted mt-0.5" aria-hidden="true" />
          <div>
            <span className="font-medium text-foreground">{playbook.name}</span>
            <p className="text-muted mt-0.5 truncate max-w-sm">{playbook.description}</p>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-3 w-3 shrink-0 text-muted mt-0.5" aria-hidden="true" />
        ) : (
          <ChevronDown className="h-3 w-3 shrink-0 text-muted mt-0.5" aria-hidden="true" />
        )}
      </button>

      {expanded && (
        <div
          id={`playbook-detail-${playbook.id}`}
          className="border-t border-border px-3 py-2 space-y-3 text-[11px]"
        >
          {/* Authorities */}
          {playbook.authorities.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-1">
                Authorities
              </p>
              <div className="flex flex-wrap gap-1">
                {playbook.authorities.map((a) => (
                  <Badge key={a} variant="default" className="text-[10px]">{a}</Badge>
                ))}
              </div>
            </div>
          )}

          {/* Workflow steps */}
          {playbook.workflow.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-1">
                Workflow
              </p>
              <ol className="space-y-1 list-decimal list-inside">
                {playbook.workflow.map((step, idx) => (
                  <li key={`${step.name}-${idx}`} className="text-muted">
                    <span className="text-foreground font-medium">{step.name}</span>
                    {' '}— {step.authority}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Evidence, reports, remediation, policies, simulations, timeline */}
          {[
            { label: 'Evidence', items: playbook.evidence },
            { label: 'Reports', items: playbook.reports },
            { label: 'Remediation', items: playbook.remediation },
            { label: 'Policies', items: playbook.policies },
            { label: 'Simulations', items: playbook.simulations },
            { label: 'Timeline', items: playbook.timeline },
          ]
            .filter(({ items }) => items.length > 0)
            .map(({ label, items }) => (
              <div key={label}>
                <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">
                  {label}
                </p>
                <ul className="font-mono text-[10px] space-y-0.5 text-muted">
                  {items.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ))}

          <p className="text-[10px] text-muted/60 italic">
            Read-only orchestration — no write operations permitted from this panel.
          </p>
        </div>
      )}
    </li>
  );
}

export default function PlaybookPanel({ playbooks, loading, lastUpdated }: PlaybookPanelProps) {
  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Playbook Panel"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Playbook Panel"
    >
      <section aria-label="playbook-panel">
        {loading && (
          <div className="space-y-2" aria-label="Loading playbooks">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-14 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && playbooks.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No playbooks available.</p>
        )}

        {!loading && playbooks.length > 0 && (
          <ul className="space-y-2" aria-label="Playbook list">
            {playbooks.map((pb) => (
              <PlaybookRow key={pb.id} playbook={pb} />
            ))}
          </ul>
        )}
      </section>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
