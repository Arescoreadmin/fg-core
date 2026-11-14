'use client';

import * as Dialog from '@radix-ui/react-dialog';
import type { ReactNode } from 'react';
import { Button } from '@/components/ui/button';

interface Props {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  destructive?: boolean;
  busy?: boolean;
  children?: ReactNode;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Explicit confirmation for authority-changing MSP actions (approve, suspend,
 * resume, revoke). Radix Dialog provides focus trapping, Escape to close and
 * the dialog/aria roles. While ``busy`` the confirm button is disabled, so a
 * second click cannot submit twice.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  destructive = false,
  busy = false,
  children,
  onConfirm,
  onCancel,
}: Props) {
  return (
    <Dialog.Root open={open} onOpenChange={(next) => (!next && !busy ? onCancel() : undefined)}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-[min(92vw,32rem)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-surface p-5 shadow-xl focus:outline-none"
          data-testid="msp-confirm-dialog"
        >
          <Dialog.Title className="text-base font-semibold text-foreground">{title}</Dialog.Title>
          <Dialog.Description className="mt-2 text-sm text-muted">{description}</Dialog.Description>
          {children ? <div className="mt-4">{children}</div> : null}
          <div className="mt-5 flex justify-end gap-2">
            <Button variant="outline" size="sm" onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant={destructive ? 'destructive' : 'default'}
              size="sm"
              onClick={onConfirm}
              loading={busy}
              aria-busy={busy}
            >
              {confirmLabel}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
