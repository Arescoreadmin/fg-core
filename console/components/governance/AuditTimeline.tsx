import { cn } from '@/lib/cn';

export interface TimelineEvent {
  id: string;
  ts: string;
  actor?: string;
  action: string;
  status: string;
  summary?: string;
  requestId?: string;
}

const STATUS_DOT: Record<string, string> = {
  success: 'bg-success',
  allow:   'bg-success',
  allowed: 'bg-success',
  deny:    'bg-primary',
  denied:  'bg-primary',
  block:   'bg-primary',
  blocked: 'bg-primary',
  error:   'bg-danger',
};

function dot(status: string) {
  return STATUS_DOT[(status || '').toLowerCase()] ?? 'bg-muted';
}

export function AuditTimeline({
  events,
  className,
}: {
  events: TimelineEvent[];
  className?: string;
}) {
  if (!events.length) {
    return (
      <p className="py-4 text-center text-sm text-muted">No events to display.</p>
    );
  }

  return (
    <ol className={cn('relative space-y-0', className)}>
      {events.map((ev, i) => (
        <li key={`${ev.id}-${i}`} className="flex gap-3">
          {/* Spine */}
          <div className="flex flex-col items-center">
            <span className={cn('mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full', dot(ev.status))} />
            {i < events.length - 1 && (
              <span className="w-px flex-1 bg-border" />
            )}
          </div>

          {/* Content */}
          <div className="pb-4 pt-0.5">
            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
              <span className="text-xs font-medium text-foreground">{ev.action}</span>
              {ev.actor && (
                <span className="text-[10px] text-muted">{ev.actor}</span>
              )}
              <span className="text-[10px] text-muted/60">{ev.ts}</span>
            </div>
            {ev.summary && (
              <p className="mt-0.5 text-xs text-muted">{ev.summary}</p>
            )}
            {ev.requestId && (
              <p className="mt-0.5 font-mono text-[10px] text-muted/50">req: {ev.requestId}</p>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
