'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-CASE-WORKSPACE';
const AUTHORITY = 'Case Workspace Authority';
const sourceOfTruth = '/api/core/decisions';
const drillDown = '/dashboard/decisions';

export interface WorkspaceCase {
  id: string;
  title: string;
  status: 'open' | 'in-progress' | 'blocked' | 'closed';
  priority: 'critical' | 'high' | 'medium' | 'low';
  linkedAssessments: string[];
  linkedDecisions: string[];
  linkedReports: string[];
  linkedEvidence: string[];
  owner: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

interface CaseWorkspaceProps {
  cases: WorkspaceCase[];
  loading?: boolean;
  lastUpdated?: string;
}

const STATUS_VARIANT: Record<WorkspaceCase['status'], 'default' | 'warning' | 'danger' | 'secondary'> = {
  open: 'default',
  'in-progress': 'warning',
  blocked: 'danger',
  closed: 'secondary',
};

const PRIORITY_VARIANT: Record<WorkspaceCase['priority'], 'critical' | 'high' | 'medium' | 'low'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
};

function CaseRow({ item }: { item: WorkspaceCase }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <li className="rounded border border-border bg-surface-2 text-xs">
      <button
        type="button"
        className="flex w-full items-start justify-between gap-2 px-3 py-2 text-left"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        aria-controls={`case-detail-${item.id}`}
      >
        <div className="min-w-0 flex-1">
          <span className="font-medium text-foreground block truncate">{item.title}</span>
          <div className="mt-1 flex flex-wrap gap-1">
            <Badge variant={STATUS_VARIANT[item.status]} className="text-[10px]">
              {item.status}
            </Badge>
            <Badge variant={PRIORITY_VARIANT[item.priority]} className="text-[10px]">
              {item.priority}
            </Badge>
            {item.owner && (
              <span className="text-muted">Owner: {item.owner}</span>
            )}
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
          id={`case-detail-${item.id}`}
          className="border-t border-border px-3 py-2 space-y-2 text-muted"
        >
          <div className="font-mono text-[10px] space-y-1">
            <p className="font-semibold text-foreground">Case ID: {item.id}</p>
            {item.createdAt && (
              <p>Created: {new Date(item.createdAt).toLocaleString()}</p>
            )}
            {item.updatedAt && (
              <p>Updated: {new Date(item.updatedAt).toLocaleString()}</p>
            )}
          </div>
          {item.linkedAssessments.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">
                Linked Assessments
              </p>
              <ul className="font-mono text-[10px] space-y-0.5">
                {item.linkedAssessments.map((id) => (
                  <li key={id}>{id}</li>
                ))}
              </ul>
            </div>
          )}
          {item.linkedDecisions.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">
                Linked Decisions
              </p>
              <ul className="font-mono text-[10px] space-y-0.5">
                {item.linkedDecisions.map((id) => (
                  <li key={id}>{id}</li>
                ))}
              </ul>
            </div>
          )}
          {item.linkedReports.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">
                Linked Reports
              </p>
              <ul className="font-mono text-[10px] space-y-0.5">
                {item.linkedReports.map((id) => (
                  <li key={id}>{id}</li>
                ))}
              </ul>
            </div>
          )}
          {item.linkedEvidence.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">
                Linked Evidence
              </p>
              <ul className="font-mono text-[10px] space-y-0.5">
                {item.linkedEvidence.map((id) => (
                  <li key={id}>{id}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

export default function CaseWorkspace({ cases, loading, lastUpdated }: CaseWorkspaceProps) {
  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Case Workspace"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Case Workspace"
    >
      <div className="space-y-2">
        {loading && (
          <div className="space-y-2" aria-label="Loading cases">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-14 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && cases.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No cases found.</p>
        )}

        {!loading && cases.length > 0 && (
          <ul className="space-y-2" aria-label="Case list">
            {cases.map((item) => (
              <CaseRow key={item.id} item={item} />
            ))}
          </ul>
        )}
      </div>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
