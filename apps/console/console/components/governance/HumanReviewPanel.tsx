import { AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/cn';

export function HumanReviewPanel({
  requestId,
  summary,
  policy,
  loading,
  onApprove,
  onReject,
  onEscalate,
  className,
}: {
  requestId: string;
  summary: string;
  policy?: string;
  loading?: boolean;
  onApprove?: () => void;
  onReject?: () => void;
  onEscalate?: () => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'rounded-lg border border-warning/40 bg-warning/5 p-4',
        className,
      )}
    >
      <div className="mb-3 flex items-center gap-2 text-sm font-medium text-warning">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        Human Review Required
      </div>
      <p className="mb-1 text-xs text-foreground">{summary}</p>
      {policy && <p className="mb-3 text-xs text-muted">Policy: {policy}</p>}
      <p className="mb-4 font-mono text-[10px] text-muted/60">request_id: {requestId}</p>
      <div className="flex flex-wrap gap-2">
        {onApprove && (
          <button
            onClick={onApprove}
            disabled={loading}
            className="rounded border border-success/40 bg-success/10 px-3 py-1.5 text-xs font-medium text-success hover:bg-success/20 disabled:opacity-50"
          >
            Approve
          </button>
        )}
        {onReject && (
          <button
            onClick={onReject}
            disabled={loading}
            className="rounded border border-danger/40 bg-danger/10 px-3 py-1.5 text-xs font-medium text-danger hover:bg-danger/20 disabled:opacity-50"
          >
            Reject
          </button>
        )}
        {onEscalate && (
          <button
            onClick={onEscalate}
            disabled={loading}
            className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-muted hover:text-foreground disabled:opacity-50"
          >
            Escalate
          </button>
        )}
      </div>
    </div>
  );
}
