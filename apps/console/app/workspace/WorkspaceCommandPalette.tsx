'use client';

import { useState } from 'react';
import { Terminal } from 'lucide-react';
import CommandPalette from '@/components/operations-workspace/CommandPalette';

export default function WorkspaceCommandPalette() {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        data-testid="workspace-command-palette-toggle"
        aria-label="Open command palette (Ctrl+K)"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:bg-surface-3 hover:text-foreground transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
      >
        <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
        Command Palette
        <kbd className="ml-1 font-mono text-[10px] opacity-60">Ctrl+K</kbd>
      </button>
      <CommandPalette open={open} onClose={() => setOpen(false)} />
    </>
  );
}
