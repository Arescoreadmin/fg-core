'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp, Lock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-DECISION-LEDGER';
const AUTHORITY = 'Decision Ledger Authority';
const sourceOfTruth = '/api/core/decisions';
const drillDown = '/dashboard/decisions';

export interface LedgerEntry {
  id: string;
  decision: string;
  businessJustification: string;
  evidence: string[];
  alternativesConsidered: string[];
  expectedOutcome: string;
  actualOutcome: string | null;
  owner: string;
  reviewer: string | null;
  reviewSchedule: string | null;
  confidence: number | null;
  provenanceChain: string[];
  linkedReports: string[];
  linkedRemediation: string[];
  linkedSimulations: string[];
  createdAt: string;
}

interface DecisionLedgerProps {
  entries: LedgerEntry[];
  loading?: boolean;
  lastUpdated?: string;
}

function EntryRow({ entry }: { entry: LedgerEntry }) {
  const [expanded, setExpanded] = useState(false);
  const confidencePct =
    entry.confidence !== null ? `${Math.round(entry.confidence * 100)}%` : null;

  return (
    <li className="rounded border border-border bg-surface-2 text-xs">
      <button
        type="button"
        className="flex w-full items-start justify-between gap-2 px-3 py-2 text-left"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        aria-controls={`ledger-detail-${entry.id}`}
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1">
            <Lock className="h-3 w-3 shrink-0 text-muted" aria-hidden="true" />
            <span className="font-medium text-foreground truncate">{entry.decision}</span>
          </div>
          <div className="mt-1 flex flex-wrap gap-x-3 text-muted">
            <span>Owner: {entry.owner}</span>
            <span>{new Date(entry.createdAt).toLocaleDateString()}</span>
            {confidencePct && <span>Confidence: {confidencePct}</span>}
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-3 w-3 shrink-0 text-muted mt-0.5" aria-hidden="true" />
        ) : (
          <ChevronDown className="h-3 w-3 shrink-0 text-muted mt-0.5" aria-hidden="true" />
        )}
      </button>

      {expanded && (
        <div
          id={`ledger-detail-${entry.id}`}
          className="border-t border-border px-3 py-2 space-y-2 text-[11px] text-muted"
        >
          <div className="space-y-1">
            <p>
              <span className="font-semibold text-foreground">Justification: </span>
              {entry.businessJustification}
            </p>
            <p>
              <span className="font-semibold text-foreground">Expected outcome: </span>
              {entry.expectedOutcome}
            </p>
            {entry.actualOutcome && (
              <p>
                <span className="font-semibold text-foreground">Actual outcome: </span>
                {entry.actualOutcome}
              </p>
            )}
            {entry.reviewer && (
              <p>
                <span className="font-semibold text-foreground">Reviewer: </span>
                {entry.reviewer}
              </p>
            )}
            {entry.reviewSchedule && (
              <p>
                <span className="font-semibold text-foreground">Review schedule: </span>
                {entry.reviewSchedule}
              </p>
            )}
          </div>

          {entry.evidence.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">Evidence</p>
              <ul className="font-mono text-[10px] space-y-0.5">
                {entry.evidence.map((e) => <li key={e}>{e}</li>)}
              </ul>
            </div>
          )}

          {entry.alternativesConsidered.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">Alternatives Considered</p>
              <ul className="text-[10px] space-y-0.5">
                {entry.alternativesConsidered.map((a) => <li key={a}>{a}</li>)}
              </ul>
            </div>
          )}

          {entry.provenanceChain.length > 0 && (
            <div>
              <p className="font-semibold uppercase tracking-wide text-[10px] text-muted/70 mb-0.5">Provenance Chain</p>
              <ol className="font-mono text-[10px] space-y-0.5 list-decimal list-inside">
                {entry.provenanceChain.map((p) => <li key={p}>{p}</li>)}
              </ol>
            </div>
          )}

          <div className="flex flex-wrap gap-1 pt-1">
            {entry.linkedReports.map((r) => (
              <Badge key={r} variant="secondary" className="text-[10px] font-mono">report:{r}</Badge>
            ))}
            {entry.linkedRemediation.map((r) => (
              <Badge key={r} variant="outline" className="text-[10px] font-mono">remediation:{r}</Badge>
            ))}
            {entry.linkedSimulations.map((s) => (
              <Badge key={s} variant="outline" className="text-[10px] font-mono">sim:{s}</Badge>
            ))}
          </div>

          <p className="text-[10px] text-muted/60 italic">
            Immutable audit record — append-only, no edits permitted.
          </p>
        </div>
      )}
    </li>
  );
}

export default function DecisionLedger({ entries, loading, lastUpdated }: DecisionLedgerProps) {
  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Decision Ledger"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="append-only"
      lastUpdated={lastUpdated}
      title="Decision Ledger"
    >
      <section aria-label="decision-ledger-panel">
        {loading && (
          <div className="space-y-2" aria-label="Loading decision ledger">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-14 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && entries.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No ledger entries.</p>
        )}

        {!loading && entries.length > 0 && (
          <ul className="space-y-2" aria-label="Decision ledger entries">
            {entries.map((entry) => (
              <EntryRow key={entry.id} entry={entry} />
            ))}
          </ul>
        )}
      </section>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
