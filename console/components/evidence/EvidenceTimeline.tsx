'use client';

import { Clock, FileCheck, FileX, HelpCircle, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  type EvidenceReference,
  type TrustState,
  extractSafeSourceMeta,
  deriveTrustState,
} from '@/lib/evidenceApi';

interface EvidenceTimelineProps {
  items: EvidenceReference[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function trustVariant(s: TrustState): 'success' | 'critical' | 'high' | 'medium' | 'outline' | 'secondary' {
  const map: Record<TrustState, 'success' | 'critical' | 'high' | 'medium' | 'outline' | 'secondary'> = {
    valid: 'success',
    invalid: 'critical',
    missing: 'high',
    stale: 'medium',
    unknown: 'outline',
    unverifiable: 'secondary',
    restricted: 'secondary',
  };
  return map[s];
}

function trustIcon(s: TrustState) {
  if (s === 'valid') return <FileCheck className="h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />;
  if (s === 'invalid' || s === 'missing') return <FileX className="h-3.5 w-3.5 shrink-0 text-risk-critical" aria-hidden="true" />;
  if (s === 'stale') return <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-risk-medium" aria-hidden="true" />;
  return <HelpCircle className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden="true" />;
}

export function EvidenceTimeline({ items, selectedId, onSelect }: EvidenceTimelineProps) {
  if (items.length === 0) {
    return (
      <Card aria-label="evidence-timeline">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Evidence Timeline</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="timeline-empty">
            No evidence items match the current filters.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card aria-label="evidence-timeline">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">
          Evidence Timeline
          <span className="ml-2 text-xs font-normal text-muted-foreground">
            ({items.length} item{items.length !== 1 ? 's' : ''})
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {/* Bounded render: max 100 visible items; server-side pagination recommended for larger sets */}
        <ol className="relative border-l border-border pl-4" aria-label="evidence-timeline-list">
          {items.slice(0, 100).map((ev) => {
            const safeMeta = extractSafeSourceMeta(ev.evidence_source_metadata);
            const trust = deriveTrustState(safeMeta);
            const isSelected = ev.evidence_id === selectedId;

            return (
              <li
                key={ev.evidence_id}
                className={`relative mb-3 last:mb-0 cursor-pointer rounded border px-3 py-2 transition-colors ${
                  isSelected
                    ? 'border-ring bg-surface-3'
                    : 'border-border bg-background hover:border-ring/50 hover:bg-surface-2'
                }`}
                aria-label={`evidence-item-${ev.evidence_id}`}
                aria-selected={isSelected}
                role="option"
                onClick={() => onSelect(ev.evidence_id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelect(ev.evidence_id);
                  }
                }}
                tabIndex={0}
              >
                {/* Timeline node */}
                <span
                  className="absolute -left-[1.125rem] top-3 flex h-4 w-4 items-center justify-center rounded-full border border-border bg-background"
                  aria-hidden="true"
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${trust === 'valid' ? 'bg-success' : trust === 'invalid' || trust === 'missing' ? 'bg-risk-critical' : trust === 'stale' ? 'bg-risk-medium' : 'bg-muted'}`} />
                </span>

                <div className="flex items-start gap-2">
                  {trustIcon(trust)}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5 mb-0.5">
                      <span className="text-xs font-medium text-foreground truncate" title={ev.evidence_title}>
                        {ev.evidence_title}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge variant={trustVariant(trust)} className="text-xs">
                        {trust}
                      </Badge>
                      {ev.evidence_type && (
                        <span className="text-xs text-muted-foreground">{ev.evidence_type}</span>
                      )}
                      {ev.evidence_classification && (
                        <span className="text-xs text-muted-foreground">
                          · {ev.evidence_classification}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" aria-hidden="true" />
                      <time dateTime={ev.submitted_at}>
                        {new Date(ev.submitted_at).toLocaleString()}
                      </time>
                      <span>· {ev.submitted_by}</span>
                    </div>
                    {ev.control_ids.length > 0 && (
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {ev.control_ids.length} control{ev.control_ids.length !== 1 ? 's' : ''} linked
                      </p>
                    )}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
        {items.length > 100 && (
          <p className="mt-2 text-xs text-muted-foreground" aria-label="timeline-truncated">
            Showing 100 of {items.length} items. Refine filters to narrow results.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
