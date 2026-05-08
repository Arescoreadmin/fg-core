import { cn } from '@/lib/cn';

const LEVEL_STYLES: Record<string, string> = {
  critical: 'bg-risk-critical/10 text-risk-critical border-risk-critical/30',
  high:     'bg-risk-high/10 text-risk-high border-risk-high/30',
  medium:   'bg-risk-medium/10 text-risk-medium border-risk-medium/30',
  low:      'bg-risk-low/10 text-risk-low border-risk-low/30',
};

export function RiskBadge({ level, className }: { level: string; className?: string }) {
  const normalized = (level || '').toLowerCase();
  const style = LEVEL_STYLES[normalized] ?? 'bg-muted/10 text-muted border-muted/20';
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
        style,
        className,
      )}
    >
      {level || 'unknown'}
    </span>
  );
}
