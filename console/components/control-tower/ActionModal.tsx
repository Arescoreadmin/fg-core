'use client';

import { useEffect, useRef, useState } from 'react';
import { X, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/cn';

export interface ModalField {
  name: string;
  label: string;
  placeholder?: string;
  required?: boolean;
  type?: 'text' | 'number';
}

interface ActionModalProps {
  open: boolean;
  title: string;
  description: string;
  fields?: ModalField[];
  destructive?: boolean;
  loading?: boolean;
  lastResult?: string;
  auditReason: string;
  onAuditReasonChange: (v: string) => void;
  onConfirm: (values: Record<string, string>) => void;
  onClose: () => void;
}

export function ActionModal({
  open,
  title,
  description,
  fields = [],
  destructive = false,
  loading = false,
  lastResult,
  auditReason,
  onAuditReasonChange,
  onConfirm,
  onClose,
}: ActionModalProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  const firstInputRef = useRef<HTMLInputElement>(null);

  // Reset field values when modal opens
  useEffect(() => {
    if (open) {
      setValues({});
      setTimeout(() => firstInputRef.current?.focus(), 50);
    }
  }, [open]);

  if (!open) return null;

  function handleConfirm() {
    const payload: Record<string, string> = { ...values, audit_reason: auditReason };
    onConfirm(payload);
  }

  const canConfirm =
    !loading &&
    fields.filter((f) => f.required).every((f) => (values[f.name] || '').trim() !== '');

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-md rounded-xl border border-border bg-surface-2 shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-border px-5 py-4">
          <div>
            <h2 className="text-sm font-semibold text-foreground">{title}</h2>
            <p className="mt-0.5 text-xs text-muted">{description}</p>
          </div>
          <button
            onClick={onClose}
            className="ml-3 shrink-0 text-muted hover:text-foreground"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="space-y-3 px-5 py-4">
          {destructive && (
            <div className="flex items-start gap-2 rounded border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              This action cannot be undone. Proceed with caution.
            </div>
          )}

          {fields.map((f, i) => (
            <label key={f.name} className="block">
              <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-muted/70">
                {f.label}{f.required && <span className="ml-0.5 text-danger">*</span>}
              </span>
              <input
                ref={i === 0 ? firstInputRef : undefined}
                type={f.type ?? 'text'}
                value={values[f.name] ?? ''}
                onChange={(e) => setValues((prev) => ({ ...prev, [f.name]: e.target.value }))}
                placeholder={f.placeholder}
                className="w-full rounded border border-border bg-surface px-3 py-2 text-sm text-foreground placeholder:text-muted/40 focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </label>
          ))}

          {/* Audit reason — always present */}
          <label className="block">
            <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-muted/70">
              Audit Reason
            </span>
            <input
              type="text"
              value={auditReason}
              onChange={(e) => onAuditReasonChange(e.target.value)}
              placeholder="Reason for this action"
              className="w-full rounded border border-border bg-surface px-3 py-2 text-sm text-foreground placeholder:text-muted/40 focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </label>

          {/* Last result */}
          {lastResult && (
            <div className="rounded border border-success/30 bg-success/5 px-3 py-2 font-mono text-xs text-success">
              {lastResult}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-2 border-t border-border px-5 py-4">
          <button
            onClick={onClose}
            className="rounded border border-border bg-transparent px-4 py-2 text-xs font-medium text-muted hover:text-foreground"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!canConfirm}
            className={cn(
              'rounded px-4 py-2 text-xs font-semibold text-white disabled:opacity-40',
              destructive
                ? 'bg-danger hover:bg-danger/80'
                : 'bg-primary hover:bg-primary-hover',
            )}
          >
            {loading ? 'Running…' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  );
}
