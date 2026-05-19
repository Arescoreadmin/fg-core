import { cn } from '@/lib/cn';

export function ConfidenceMeter({
  value,
  label,
  className,
}: {
  value: number;
  label?: string;
  className?: string;
}) {
  // Accept 0–1 or 0–100
  const pct = value > 1 ? Math.min(value, 100) : Math.min(value * 100, 100);
  const color =
    pct >= 70 ? 'bg-success' :
    pct >= 40 ? 'bg-warning' :
    'bg-danger';

  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted">{label ?? 'Confidence'}</span>
        <span className="text-xs font-semibold text-foreground">{Math.round(pct)}%</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
        <div
          className={cn('h-full rounded-full transition-all', color)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
