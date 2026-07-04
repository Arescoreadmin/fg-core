'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { Search, X } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

const MCIM_ID = 'MCIM-18.6-COMMAND-PALETTE';
const AUTHORITY = 'Command Palette Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

interface CommandEntry {
  id: string;
  label: string;
  scope: string;
  path: string;
}

// Static search map — covers all scopes without external navigation package
const STATIC_ENTRIES: CommandEntry[] = [
  // Authorities
  { id: 'auth-assessment', label: 'Assessment Authority', scope: 'Authorities', path: '/dashboard/assessment' },
  { id: 'auth-evidence', label: 'Evidence Authority', scope: 'Authorities', path: '/dashboard/evidence' },
  { id: 'auth-verification', label: 'Verification Authority', scope: 'Authorities', path: '/dashboard/verification' },
  { id: 'auth-governance', label: 'Governance Authority', scope: 'Authorities', path: '/dashboard/governance' },
  { id: 'auth-decision', label: 'Decision Authority', scope: 'Authorities', path: '/dashboard/decisions' },
  { id: 'auth-replay', label: 'Replay Authority', scope: 'Authorities', path: '/dashboard/replay' },
  { id: 'auth-control-tower', label: 'Control Tower Authority', scope: 'Authorities', path: '/dashboard/control-tower' },
  // Capabilities
  { id: 'cap-forensics', label: 'Forensics Capability', scope: 'Capabilities', path: '/dashboard/forensics' },
  { id: 'cap-audit', label: 'Audit Trail Capability', scope: 'Capabilities', path: '/dashboard/audit' },
  { id: 'cap-keys', label: 'Key Management Capability', scope: 'Capabilities', path: '/keys' },
  // Assessments
  { id: 'asm-list', label: 'All Assessments', scope: 'Assessments', path: '/dashboard/assessment' },
  { id: 'asm-new', label: 'New Assessment', scope: 'Assessments', path: '/onboarding' },
  // Evidence
  { id: 'ev-list', label: 'Evidence List', scope: 'Evidence', path: '/dashboard/evidence' },
  // Reports
  { id: 'rep-list', label: 'All Reports', scope: 'Reports', path: '/dashboard/reports' },
  // Customers
  { id: 'cust-list', label: 'Customer Overview', scope: 'Customers', path: '/dashboard/customer' },
  // Policies
  { id: 'pol-list', label: 'Policy List', scope: 'Policies', path: '/dashboard/policies' },
  // Findings
  { id: 'find-list', label: 'All Findings', scope: 'Findings', path: '/dashboard/findings' },
  // Simulations
  { id: 'sim-list', label: 'Simulations', scope: 'Simulations', path: '/dashboard/simulation' },
  // Replay
  { id: 'replay-list', label: 'Replay History', scope: 'Replay', path: '/dashboard/replay' },
  // Remediation
  { id: 'rem-list', label: 'Remediation Tasks', scope: 'Remediation', path: '/dashboard/remediation' },
  // Portal
  { id: 'portal-pub', label: 'Portal Publications', scope: 'Portal', path: '/dashboard/portal' },
];

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onNavigate?: (path: string) => void;
  onOpen?: () => void;
}

export default function CommandPalette({ open, onClose, onNavigate, onOpen }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = query.trim()
    ? STATIC_ENTRIES.filter(
        (e) =>
          e.label.toLowerCase().includes(query.toLowerCase()) ||
          e.scope.toLowerCase().includes(query.toLowerCase()),
      )
    : STATIC_ENTRIES;

  // Reset on open
  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  // Global Ctrl+K listener — calls onOpen when closed so the wrapper can set open=true
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        if (!open) {
          onOpen?.();
        }
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onOpen]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx((i) => Math.min(i + 1, filtered.length - 1));
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx((i) => Math.max(i - 1, 0));
        return;
      }
      if (e.key === 'Enter' && filtered[activeIdx]) {
        const entry = filtered[activeIdx];
        onNavigate?.(entry.path);
        onClose();
      }
    },
    [filtered, activeIdx, onClose, onNavigate],
  );

  if (!open) return null;

  // Group by scope
  const scopes = Array.from(new Set(filtered.map((e) => e.scope)));

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/50"
      aria-modal="true"
      role="dialog"
      aria-label="command-palette"
      data-testid="command-palette"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      onKeyDown={handleKeyDown}
    >
      <div className="w-full max-w-lg rounded-lg border border-border bg-surface shadow-xl overflow-hidden">
        {/* Search input */}
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <Search className="h-4 w-4 text-muted shrink-0" aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted outline-none"
            placeholder="Search authorities, capabilities, assessments…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIdx(0);
            }}
            aria-label="Command palette search"
            aria-autocomplete="list"
            aria-controls="command-palette-results"
          />
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0 text-muted"
            onClick={onClose}
            aria-label="Close command palette"
          >
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>

        {/* Results */}
        <div
          id="command-palette-results"
          role="listbox"
          aria-label="Command palette results"
          className="max-h-96 overflow-y-auto"
        >
          {filtered.length === 0 && (
            <p className="py-8 text-center text-sm text-muted">No results for "{query}".</p>
          )}

          {scopes.map((scope) => {
            const scopeEntries = filtered.filter((e) => e.scope === scope);
            return (
              <div key={scope}>
                <div className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted/70 bg-muted/10">
                  {scope}
                </div>
                {scopeEntries.map((entry) => {
                  const isActive = filtered[activeIdx]?.id === entry.id;
                  return (
                    <button
                      key={entry.id}
                      role="option"
                      aria-selected={isActive}
                      type="button"
                      className={[
                        'flex w-full items-center justify-between gap-2 px-3 py-2 text-sm text-left transition-colors',
                        isActive
                          ? 'bg-primary/10 text-primary'
                          : 'text-foreground hover:bg-surface-2',
                      ].join(' ')}
                      onClick={() => {
                        onNavigate?.(entry.path);
                        onClose();
                      }}
                    >
                      <span>{entry.label}</span>
                      <Badge variant="secondary" className="text-[10px] shrink-0">
                        {scope}
                      </Badge>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="border-t border-border px-3 py-1.5 text-[10px] text-muted flex gap-3">
          <span><kbd className="font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="font-mono">Enter</kbd> select</span>
          <span><kbd className="font-mono">Esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
