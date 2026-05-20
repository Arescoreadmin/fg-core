'use client';

import type { ExecutionState } from '@/lib/fieldAssessmentApi';

interface GuidedExecutionPanelProps {
  executionState: ExecutionState | null;
  loading?: boolean;
  error?: string | null;
  onSectionClick?: (section: string) => void;
}

const STATE_LABELS: Record<string, string> = {
  blocked: 'Blocked',
  needs_review: 'Needs review',
  warning: 'Warnings',
  ready: 'Ready',
};

const STATUS_CLASS: Record<string, string> = {
  blocked: 'border-red-500/40 bg-red-500/10 text-red-200',
  warning: 'border-amber-500/40 bg-amber-500/10 text-amber-100',
  passed: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-100',
  not_applicable: 'border-border bg-surface-2 text-muted',
};

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'text-red-300',
  high: 'text-orange-300',
  medium: 'text-amber-200',
  low: 'text-blue-200',
  info: 'text-muted',
};

function label(value: string) {
  return value.replace(/_/g, ' ');
}

export function GuidedExecutionPanel({
  executionState,
  loading = false,
  error = null,
  onSectionClick,
}: GuidedExecutionPanelProps) {
  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <div className="h-5 w-36 animate-pulse rounded bg-surface-2" />
        <div className="h-20 animate-pulse rounded bg-surface-2" />
        <div className="h-28 animate-pulse rounded bg-surface-2" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-100">
        {error}
      </div>
    );
  }

  if (!executionState) {
    return (
      <div className="rounded border border-border bg-surface-2 p-3 text-xs text-muted">
        Execution state is not available.
      </div>
    );
  }

  const blockingGates = executionState.gates.filter((gate) => gate.status === 'blocked');
  const warningGates = executionState.gates.filter((gate) => gate.status === 'warning');
  const visibleGates = [...blockingGates, ...warningGates].slice(0, 5);
  const categories = Object.entries(executionState.readiness_categories);

  return (
    <section className="space-y-4" aria-label="Guided execution state">
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-muted">Guided Execution</p>
            <p className="text-sm font-semibold text-foreground">
              {STATE_LABELS[executionState.overall_readiness_state] ?? label(executionState.overall_readiness_state)}
            </p>
          </div>
          <div className="text-right">
            <p className="text-lg font-semibold text-foreground">{executionState.readiness_score}%</p>
            <p className="text-[11px] text-muted">readiness</p>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-2 text-center text-[11px]">
          <div className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1">
            <span className="block text-sm font-semibold text-red-200">{executionState.blocking_gate_count}</span>
            <span className="text-red-100">blocked</span>
          </div>
          <div className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1">
            <span className="block text-sm font-semibold text-amber-100">{executionState.warning_gate_count}</span>
            <span className="text-amber-100">warnings</span>
          </div>
          <div className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1">
            <span className="block text-sm font-semibold text-emerald-100">{executionState.completed_gate_count}</span>
            <span className="text-emerald-100">closed</span>
          </div>
        </div>
      </div>

      {categories.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted">Readiness categories</p>
          <div className="space-y-1">
            {categories.map(([category, state]) => (
              <div key={category} className="flex items-center justify-between gap-2 text-xs">
                <span className="capitalize text-muted">{label(category)}</span>
                <span className="capitalize text-foreground">{label(state)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-2">
        <p className="text-xs font-medium text-muted">Next best actions</p>
        {executionState.next_actions.length === 0 ? (
          <p className="rounded border border-border bg-surface-2 p-2 text-xs text-muted">
            No next actions are open.
          </p>
        ) : (
          executionState.next_actions.slice(0, 4).map((action) => (
            <button
              key={action.action_id}
              type="button"
              onClick={() => onSectionClick?.(action.target_ui_section)}
              className="w-full rounded border border-border bg-surface-1 p-2 text-left transition hover:border-primary/50 focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              <span className="flex items-center justify-between gap-2 text-xs">
                <span className="font-medium text-foreground">{action.title}</span>
                <span className={SEVERITY_CLASS[action.severity] ?? 'text-muted'}>{action.priority}</span>
              </span>
              <span className="mt-1 block text-xs text-muted">{action.instruction}</span>
              <span className="mt-1 block text-[11px] text-muted">Evidence: {action.expected_evidence.join(', ')}</span>
            </button>
          ))
        )}
      </div>

      {visibleGates.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted">Blocking gates and warnings</p>
          {visibleGates.map((gate) => (
            <div key={gate.gate_id} className={`rounded border p-2 ${STATUS_CLASS[gate.status] ?? STATUS_CLASS.not_applicable}`}>
              <div className="flex items-start justify-between gap-2">
                <p className="text-xs font-medium">{gate.title}</p>
                <span className="text-[11px] capitalize">{label(gate.status)}</span>
              </div>
              <p className="mt-1 text-[11px] opacity-90">{gate.why_it_matters}</p>
              {gate.missing_items.length > 0 && (
                <p className="mt-1 text-[11px] opacity-90">Missing: {gate.missing_items.join(', ')}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {executionState.escalation_items.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted">Escalations</p>
          {executionState.escalation_items.slice(0, 3).map((item) => (
            <div key={item.escalation_id} className="rounded border border-orange-500/30 bg-orange-500/10 p-2 text-xs">
              <p className="font-medium text-orange-100">{label(item.ambiguity_type)}</p>
              <p className="mt-1 text-orange-100/90">{item.reason}</p>
              <p className="mt-1 text-[11px] text-muted">Reviewer: {label(item.recommended_reviewer_role)}</p>
            </div>
          ))}
        </div>
      )}

      {executionState.transition_blockers.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted">Transition blockers</p>
          {executionState.transition_blockers.map((blocker) => (
            <div key={blocker.target_status} className="rounded border border-border p-2 text-xs">
              <p className="font-medium capitalize text-foreground">{label(blocker.target_status)}</p>
              <p className="mt-1 text-muted">{blocker.explanation}</p>
            </div>
          ))}
        </div>
      )}

      {executionState.asset_candidate_actions.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted">Asset registry bridge</p>
          {executionState.asset_candidate_actions.slice(0, 3).map((action) => (
            <button
              key={action.candidate_action_id}
              type="button"
              onClick={() => onSectionClick?.(action.target_ui_section)}
              className="w-full rounded border border-border bg-surface-1 p-2 text-left text-xs transition hover:border-primary/50 focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              <span className="font-medium text-foreground">{action.title}</span>
              <span className="mt-1 block text-muted">{action.instruction}</span>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}
