import { cn } from '@/lib/cn';
import { PolicyDecision } from './PolicyDecision';

export function ProviderRouteCard({
  provider,
  model,
  latencyMs,
  decision,
  tokenCount,
  className,
}: {
  provider: string;
  model?: string;
  latencyMs?: number;
  decision?: string;
  tokenCount?: number;
  className?: string;
}) {
  const initial = (provider || '?').charAt(0).toUpperCase();

  return (
    <div className={cn('flex items-center gap-3 rounded-lg border bg-surface-2 px-3 py-2.5', className)}>
      {/* Provider avatar */}
      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-info/10 font-semibold text-xs text-info">
        {initial}
      </div>

      {/* Details */}
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-foreground">{provider}</p>
        {model && <p className="text-[10px] text-muted">{model}</p>}
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3 shrink-0">
        {tokenCount !== undefined && (
          <span className="font-mono text-[10px] text-muted/60">{tokenCount} tok</span>
        )}
        {latencyMs !== undefined && (
          <span className="font-mono text-[10px] text-muted/60">{latencyMs}ms</span>
        )}
        {decision && (
          <PolicyDecision action={decision} />
        )}
      </div>
    </div>
  );
}
