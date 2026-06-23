import { ShieldCheck, ShieldAlert, ShieldOff, Shield } from 'lucide-react';
import { cn } from '@/lib/cn';

type TrustStatus = 'verified' | 'unverified' | 'degraded' | 'unknown';

const STATUS_MAP: Record<TrustStatus, { icon: React.ComponentType<{ className?: string }>; color: string; label: string }> = {
  verified:   { icon: ShieldCheck, color: 'text-info',    label: 'Chain Verified' },
  unverified: { icon: ShieldOff,   color: 'text-danger',  label: 'Unverified' },
  degraded:   { icon: ShieldAlert, color: 'text-warning', label: 'Chain Degraded' },
  unknown:    { icon: Shield,      color: 'text-muted',   label: 'Unknown' },
};

export function TrustIndicator({
  status,
  label,
  requestId,
  hash,
  className,
}: {
  status: TrustStatus | string;
  label?: string;
  requestId?: string;
  hash?: string;
  className?: string;
}) {
  const normalized = (status || 'unknown').toLowerCase() as TrustStatus;
  const map = STATUS_MAP[normalized] ?? STATUS_MAP.unknown;
  const Icon = map.icon;

  return (
    <div className={cn('flex flex-col gap-1.5 rounded-lg border bg-surface-2 p-3', className)}>
      <div className={cn('flex items-center gap-2 text-sm font-medium', map.color)}>
        <Icon className="h-4 w-4 shrink-0" />
        {label || map.label}
      </div>
      {(requestId || hash) && (
        <div className="space-y-0.5">
          {requestId && (
            <p className="font-mono text-[10px] text-muted/60">request_id: {requestId}</p>
          )}
          {hash && (
            <p className="truncate font-mono text-[10px] text-muted/60">hash: {hash}</p>
          )}
        </div>
      )}
    </div>
  );
}
