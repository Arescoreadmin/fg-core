'use client';

import { useState } from 'react';
import { Button, Input } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { VALID_TRANSITIONS, type EngagementStatus } from '@/lib/fieldAssessmentApi';
import { StatusBadge } from './StatusBadge';

const STATUS_LABELS: Record<EngagementStatus, string> = {
  in_progress: 'In Progress',
  delivered: 'Delivered',
  remediation: 'Remediation',
  monitoring: 'Monitoring',
  closed: 'Closed',
  cancelled: 'Cancelled',
};

interface Props {
  currentStatus: EngagementStatus;
  onTransition: (newStatus: EngagementStatus, reason: string) => Promise<void>;
}

export function StatusTransitionBar({ currentStatus, onTransition }: Props) {
  const [selected, setSelected] = useState<EngagementStatus | null>(null);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const allowed = VALID_TRANSITIONS[currentStatus];

  if (allowed.length === 0) {
    return (
      <div className="flex items-center gap-3 p-3 rounded border border-border bg-surface-2">
        <span className="text-xs text-muted">Current status:</span>
        <StatusBadge status={currentStatus} />
        <span className="text-xs text-muted ml-auto">No further transitions available</span>
      </div>
    );
  }

  function selectTransition(next: EngagementStatus) {
    setSelected(next);
    setReason('');
    setError(null);
  }

  function cancel() {
    setSelected(null);
    setReason('');
    setError(null);
  }

  async function confirm() {
    if (!selected || reason.trim() === '' || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await onTransition(selected, reason.trim());
      setSelected(null);
      setReason('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Transition failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3 p-3 rounded border border-border bg-surface-2">
        <span className="text-xs text-muted">Status:</span>
        <StatusBadge status={currentStatus} />
        {!selected && (
          <>
            <span className="text-xs text-muted">→ Advance to:</span>
            {allowed
              .filter((s) => s !== 'cancelled')
              .map((next) => (
                <Button
                  key={next}
                  size="sm"
                  variant="outline"
                  onClick={() => selectTransition(next)}
                  aria-label={`Transition to ${STATUS_LABELS[next]}`}
                >
                  {STATUS_LABELS[next]}
                </Button>
              ))}
            {allowed.includes('cancelled') && (
              <Button
                size="sm"
                variant="ghost"
                className="text-danger hover:text-danger ml-auto"
                onClick={() => selectTransition('cancelled')}
                aria-label="Cancel engagement"
              >
                Cancel engagement
              </Button>
            )}
          </>
        )}
        {selected && (
          <span className="text-xs text-muted ml-auto">
            → <span className="font-medium text-foreground">{STATUS_LABELS[selected]}</span>
          </span>
        )}
      </div>

      {selected && (
        <div className="flex flex-wrap items-center gap-2 p-3 rounded border border-border bg-surface-2"
          aria-label="transition-reason-form">
          <span className="text-xs text-muted shrink-0">Reason *</span>
          <Input
            className="flex-1 h-8 text-xs min-w-[200px]"
            placeholder={`Reason for advancing to ${STATUS_LABELS[selected]}…`}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && confirm()}
            aria-label="Transition reason"
            aria-required="true"
            autoFocus
          />
          <Button
            size="sm"
            disabled={reason.trim() === '' || submitting}
            onClick={confirm}
            aria-label="Confirm transition"
          >
            {submitting ? 'Advancing…' : 'Confirm'}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={submitting}
            onClick={cancel}
            aria-label="Cancel transition"
          >
            Back
          </Button>
        </div>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}
