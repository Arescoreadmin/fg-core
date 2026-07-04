'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { Button } from '@/components/ui/button';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-REPLAY';
const AUTHORITY = 'Governance Replay Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/evaluation';

export interface ReplayEntry {
  replayId: string;
  label: string;
  originalState: Record<string, unknown>;
  currentState: Record<string, unknown>;
  delta: Record<string, unknown>;
  replayedAt: string;
  authority: string;
}

interface GovernanceReplayCenterProps {
  entries: ReplayEntry[];
  loading?: boolean;
  lastUpdated?: string;
}

function ReplayItem({ entry }: { entry: ReplayEntry }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-md border border-border bg-surface-2">
      <div className="flex items-center justify-between px-3 py-2">
        <div className="flex items-center gap-3 text-xs">
          <span className="font-mono font-medium text-foreground">{entry.replayId}</span>
          <span className="text-foreground">{entry.label}</span>
          <span className="text-muted">{entry.authority}</span>
          <span className="text-muted">{new Date(entry.replayedAt).toLocaleString()}</span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs text-muted"
          aria-expanded={expanded}
          aria-controls={`replay-detail-${entry.replayId}`}
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? <ChevronUp className="h-3 w-3" aria-hidden="true" /> : <ChevronDown className="h-3 w-3" aria-hidden="true" />}
        </Button>
      </div>
      {expanded && (
        <div
          id={`replay-detail-${entry.replayId}`}
          className="border-t border-border px-3 py-2"
        >
          <div className="grid gap-3 sm:grid-cols-3">
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">Original</p>
              <pre className="overflow-x-auto rounded-md bg-muted/20 p-2 text-[10px] text-foreground">
                {JSON.stringify(entry.originalState, null, 2)}
              </pre>
            </div>
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">Current</p>
              <pre className="overflow-x-auto rounded-md bg-muted/20 p-2 text-[10px] text-foreground">
                {JSON.stringify(entry.currentState, null, 2)}
              </pre>
            </div>
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">Difference</p>
              <pre className="overflow-x-auto rounded-md bg-muted/20 p-2 text-[10px] text-foreground">
                {JSON.stringify(entry.delta, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function GovernanceReplayCenter({ entries, loading, lastUpdated }: GovernanceReplayCenterProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Governance state replay and comparison"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Governance Replay Center"
    >
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted">No replay entries available.</p>
      ) : (
        <div className="space-y-2">
          {entries.map((e) => (
            <ReplayItem key={e.replayId} entry={e} />
          ))}
        </div>
      )}
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
