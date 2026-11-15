'use client';

import { Checkbox } from '@/components/ui/checkbox';
import { DELEGABLE_CAPABILITIES } from '@/lib/mspConsole';

interface Props {
  /** Capabilities that may be chosen. Defaults to every delegable one. */
  offered?: string[];
  selected: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
  legend: string;
}

/** Checkbox list of read-only delegable capabilities, with plain descriptions. */
export function CapabilityPicker({ offered, selected, onChange, disabled, legend }: Props) {
  const offeredSet = offered ? new Set(offered) : null;
  const caps = DELEGABLE_CAPABILITIES.filter((c) => !offeredSet || offeredSet.has(c.id));
  const toggle = (id: string, on: boolean) =>
    onChange(on ? Array.from(new Set([...selected, id])) : selected.filter((s) => s !== id));

  return (
    <fieldset className="space-y-2" disabled={disabled}>
      <legend className="text-sm font-medium text-foreground">{legend}</legend>
      {caps.map((cap) => {
        const inputId = `cap-${cap.id.replace('.', '-')}`;
        return (
          <div key={cap.id} className="flex items-start gap-2">
            <Checkbox
              id={inputId}
              checked={selected.includes(cap.id)}
              onCheckedChange={(v) => toggle(cap.id, v === true)}
              aria-describedby={`${inputId}-desc`}
              disabled={disabled}
            />
            <label htmlFor={inputId} className="text-sm leading-tight">
              <span className="font-medium text-foreground">{cap.label}</span>
              <span id={`${inputId}-desc`} className="block text-xs text-muted">
                {cap.description}
              </span>
            </label>
          </div>
        );
      })}
    </fieldset>
  );
}
