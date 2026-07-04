'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp, HelpCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WidgetShell from './WidgetShell';
import type { DecisionOut } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-DECISION-PROVENANCE
const MCIM_ID = 'MCIM-18.6-DECISION-PROVENANCE';
const AUTHORITY = 'Decision Provenance Authority';
const sourceOfTruth = '/api/core/decisions';
const drillDown = '/dashboard/decisions';

interface DecisionProvenancePanelProps {
  decisions: DecisionOut[];
  loading?: boolean;
  lastUpdated?: string;
}

function ProvenanceRow({ decision }: { decision: DecisionOut }) {
  const [expanded, setExpanded] = useState(false);

  const threatLabel: 'critical' | 'high' | 'warning' | 'outline' =
    decision.threat_level === 'critical'
      ? 'critical'
      : decision.threat_level === 'high'
        ? 'high'
        : decision.threat_level === 'medium'
          ? 'warning'
          : 'outline';

  return (
    <li
      className="rounded-md border border-border"
      data-testid={`decision-${decision.id}`}
      aria-label="decision-row"
    >
      <button
        type="button"
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left"
        aria-expanded={expanded}
        data-provenance={expanded ? 'provenance-expanded' : 'provenance-collapsed'}
        onClick={() => setExpanded((v) => !v)}
      >
        <div className="flex items-center gap-2 min-w-0">
          <Badge variant={threatLabel} className="text-[9px] shrink-0">
            {decision.threat_level ?? 'unknown'}
          </Badge>
          <span className="text-xs font-medium text-foreground truncate">
            {decision.explain_summary ?? decision.event_type ?? `Decision ${decision.id.slice(0, 8)}`}
          </span>
        </div>
        {expanded ? (
          <ChevronUp className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden="true" />
        ) : (
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden="true" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-border px-3 pb-3 pt-2 space-y-1.5 text-[10px] text-muted">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            <div aria-label="provenance-why" data-testid="provenance-why">
              <span className="font-semibold text-foreground">Why: </span>
              <span>{decision.explain_summary ?? '—'}</span>
            </div>
            <div aria-label="provenance-evidence" data-testid="provenance-evidence">
              <span className="font-semibold text-foreground">Evidence: </span>
              <span className="font-mono">{decision.event_id ?? '—'}</span>
            </div>
            <div>
              <span className="font-semibold text-foreground">Event Type: </span>
              <span>{decision.event_type ?? '—'}</span>
            </div>
            <div>
              <span className="font-semibold text-foreground">Source: </span>
              <span>{decision.source ?? '—'}</span>
            </div>
            <div aria-label="provenance-confidence" data-testid="provenance-confidence">
              <span className="font-semibold text-foreground">Confidence: </span>
              <span>from API</span>
            </div>
            <div>
              <span className="font-semibold text-foreground">Timestamp: </span>
              <span>{decision.created_at ? new Date(decision.created_at).toLocaleString() : '—'}</span>
            </div>
            <div>
              <span className="font-semibold text-foreground">Reviewer: </span>
              <span>—</span>
            </div>
            <div aria-label="provenance-authority" data-testid="provenance-authority">
              <span className="font-semibold text-foreground">Authority: </span>
              <span>{AUTHORITY}</span>
            </div>
            <div data-testid="provenance-alternatives">
              <span className="font-semibold text-foreground">Alternatives: </span>
              <span>
                {(decision as Record<string, unknown>).alternatives != null
                  ? String((decision as Record<string, unknown>).alternatives)
                  : 'No alternatives documented'}
              </span>
            </div>
            <div data-testid="provenance-impact">
              <span className="font-semibold text-foreground">Impact: </span>
              <span>
                {(decision as Record<string, unknown>).impact != null
                  ? String((decision as Record<string, unknown>).impact)
                  : 'Expected impact: unknown'}
              </span>
            </div>
          </div>
        </div>
      )}
    </li>
  );
}

export default function DecisionProvenancePanel({
  decisions,
  loading = false,
  lastUpdated,
}: DecisionProvenancePanelProps) {
  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Decision Provenance Panel"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Decision Provenance"
    >
      <div
        aria-label="decision-provenance-panel"
        data-testid="decision-provenance-panel"
      >
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : decisions.length === 0 ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No decisions available.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <ul className="space-y-1.5" role="list">
            {decisions.map((d) => (
              <ProvenanceRow key={d.id} decision={d} />
            ))}
          </ul>
        )}
      </div>
    </WidgetShell>
  );
}
