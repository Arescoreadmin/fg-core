import { cn } from '@/lib/cn';

export interface EvidenceField {
  label: string;
  value: string | number | null | undefined;
}

export function EvidenceCard({
  title,
  fields,
  highlight,
  collapsible,
  className,
}: {
  title: string;
  fields: EvidenceField[];
  highlight?: boolean;
  collapsible?: boolean;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'rounded-lg border bg-surface-2 p-4',
        highlight && 'border-l-2 border-l-primary border-border',
        className,
      )}
    >
      <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">{title}</p>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
        {fields.map((f) => (
          <div key={f.label} className="flex flex-col gap-0.5">
            <dt className="text-[10px] uppercase tracking-wide text-muted/60">{f.label}</dt>
            <dd className="break-all font-mono text-xs text-foreground">
              {f.value !== null && f.value !== undefined && f.value !== '' ? String(f.value) : '—'}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
