'use client';

import { useState } from 'react';
import { Button } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { VALID_TRANSITIONS, type EngagementStatus } from '@/lib/fieldAssessmentApi';
import { StatusBadge } from './StatusBadge';

const STATUS_LABELS: Record<EngagementStatus, string> = {
  scheduled: 'Scheduled',
  pre_visit: 'Pre-Visit',
  in_progress: 'In Progress',
  evidence_collected: 'Evidence Collected',
  report_generation: 'Report Generation',
  delivered: 'Delivered',
  remediation: 'Remediation',
  monitoring: 'Monitoring',
  closed: 'Closed',
  cancelled: 'Cancelled',
};

interface Props {
  currentStatus: EngagementStatus;
  onTransition: (newStatus: EngagementStatus, reason?: string) => Promise<void>;
}

export function StatusTransitionBar({ currentStatus, onTransition }: Props) {
  const [pending, setPending] = useState<EngagementStatus | null>(null);
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

  async function handleTransition(next: EngagementStatus) {
    setPending(next);
    setError(null);
    try {
      await onTransition(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Transition failed');
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3 p-3 rounded border border-border bg-surface-2">
        <span className="text-xs text-muted">Status:</span>
        <StatusBadge status={currentStatus} />
        <span className="text-xs text-muted">→ Advance to:</span>
        {allowed
          .filter((s) => s !== 'cancelled')
          .map((next) => (
            <Button
              key={next}
              size="sm"
              variant="outline"
              disabled={pending !== null}
              onClick={() => handleTransition(next)}
              aria-label={`Transition to ${STATUS_LABELS[next]}`}
            >
              {pending === next ? 'Advancing…' : STATUS_LABELS[next]}
            </Button>
          ))}
        {allowed.includes('cancelled') && (
          <Button
            size="sm"
            variant="ghost"
            className="text-danger hover:text-danger ml-auto"
            disabled={pending !== null}
            onClick={() => handleTransition('cancelled')}
            aria-label="Cancel engagement"
          >
            Cancel
          </Button>
        )}
      </div>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}
