'use client';

import { Badge } from '@/components/ui/badge';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-WORKFLOW-PROGRESS';
const AUTHORITY = 'Workflow Progress Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

export type WorkflowStageName = 'not-started' | 'active' | 'waiting' | 'blocked' | 'completed';

export interface WorkflowStage {
  name: string;
  status: WorkflowStageName;
}

export interface WorkflowState {
  id: string;
  name: string;
  type:
    | 'assessment'
    | 'evidence'
    | 'verification'
    | 'report'
    | 'portal'
    | 'remediation'
    | 'governance'
    | 'trust'
    | 'simulation'
    | 'replay';
  stages: WorkflowStage[];
  currentStage: string;
}

interface WorkflowProgressProps {
  workflows: WorkflowState[];
  loading?: boolean;
  lastUpdated?: string;
}

const STAGE_COLOR: Record<WorkflowStageName, string> = {
  'not-started': 'bg-muted',
  active: 'bg-primary',
  waiting: 'bg-warning',
  blocked: 'bg-danger',
  completed: 'bg-success',
};

const STAGE_BADGE_VARIANT: Record<WorkflowStageName, 'secondary' | 'default' | 'warning' | 'danger' | 'success'> = {
  'not-started': 'secondary',
  active: 'default',
  waiting: 'warning',
  blocked: 'danger',
  completed: 'success',
};

function WorkflowRow({ wf }: { wf: WorkflowState }) {
  const completedCount = wf.stages.filter((s) => s.status === 'completed').length;
  const totalCount = wf.stages.length;
  const progressPct = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

  return (
    <li className="rounded border border-border bg-surface-2 px-3 py-2 text-xs space-y-2">
      <div className="flex items-center justify-between gap-2">
        <span className="font-medium text-foreground truncate">{wf.name}</span>
        <Badge variant="secondary" className="text-[10px] shrink-0">{wf.type}</Badge>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 w-full rounded-full bg-muted/30" role="progressbar" aria-valuenow={progressPct} aria-valuemin={0} aria-valuemax={100} aria-label={`${wf.name} progress`}>
        <div
          className="h-full rounded-full bg-primary transition-all duration-300"
          style={{ width: `${progressPct}%` }}
        />
      </div>

      {/* Stage dots */}
      <div className="flex flex-wrap gap-1.5 items-center">
        {wf.stages.map((stage) => (
          <div key={stage.name} className="flex items-center gap-1">
            <div
              className={`h-2 w-2 rounded-full ${STAGE_COLOR[stage.status]}`}
              title={`${stage.name}: ${stage.status}`}
              aria-hidden="true"
            />
            <span
              className={`text-[10px] ${stage.name === wf.currentStage ? 'font-semibold text-foreground' : 'text-muted'}`}
            >
              {stage.name}
            </span>
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between text-[10px] text-muted">
        <span>Current: <span className="font-semibold text-foreground">{wf.currentStage}</span></span>
        <span>{completedCount}/{totalCount} stages</span>
      </div>
    </li>
  );
}

export default function WorkflowProgress({ workflows, loading, lastUpdated }: WorkflowProgressProps) {
  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Workflow Progress"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="authority-derived"
      lastUpdated={lastUpdated}
      title="Workflow Progress"
    >
      <div className="space-y-2">
        {loading && (
          <div className="space-y-2" aria-label="Loading workflows">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-20 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && workflows.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No active workflows.</p>
        )}

        {!loading && workflows.length > 0 && (
          <ul className="space-y-2" aria-label="Workflow list">
            {workflows.map((wf) => (
              <WorkflowRow key={wf.id} wf={wf} />
            ))}
          </ul>
        )}

        {/* Stage legend */}
        {!loading && workflows.length > 0 && (
          <div className="flex flex-wrap gap-2 pt-1 text-[10px] text-muted" aria-label="Stage status legend">
            {(Object.entries(STAGE_BADGE_VARIANT) as [WorkflowStageName, typeof STAGE_BADGE_VARIANT[WorkflowStageName]][]).map(([status, variant]) => (
              <Badge key={status} variant={variant} className="text-[10px]">
                {status}
              </Badge>
            ))}
          </div>
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
