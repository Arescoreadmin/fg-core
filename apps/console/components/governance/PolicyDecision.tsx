import { CheckCircle2, XCircle, Clock, ShieldOff } from 'lucide-react';
import { cn } from '@/lib/cn';

const ACTION_MAP: Record<string, { icon: React.ComponentType<{ className?: string }>; color: string; label: string }> = {
  allow:      { icon: CheckCircle2, color: 'text-success', label: 'Allowed' },
  allowed:    { icon: CheckCircle2, color: 'text-success', label: 'Allowed' },
  deny:       { icon: XCircle,      color: 'text-danger',  label: 'Denied' },
  denied:     { icon: XCircle,      color: 'text-danger',  label: 'Denied' },
  block:      { icon: XCircle,      color: 'text-danger',  label: 'Blocked' },
  blocked:    { icon: XCircle,      color: 'text-danger',  label: 'Blocked' },
  review:     { icon: Clock,        color: 'text-warning', label: 'Review Required' },
  quarantine: { icon: ShieldOff,    color: 'text-danger',  label: 'Quarantined' },
};

export function PolicyDecision({
  action,
  reason,
  policy,
  className,
}: {
  action: string;
  reason?: string;
  policy?: string;
  className?: string;
}) {
  const normalized = (action || '').toLowerCase();
  const map = ACTION_MAP[normalized] ?? { icon: Clock, color: 'text-muted', label: action || 'Unknown' };
  const Icon = map.icon;

  return (
    <div className={cn('flex flex-col gap-1', className)}>
      <div className={cn('flex items-center gap-1.5 text-sm font-medium', map.color)}>
        <Icon className="h-4 w-4 shrink-0" />
        {map.label}
      </div>
      {policy && <p className="text-xs text-muted">Policy: {policy}</p>}
      {reason && <p className="text-xs text-muted">{reason}</p>}
    </div>
  );
}
