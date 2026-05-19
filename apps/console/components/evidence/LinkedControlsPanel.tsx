'use client';

import { AlertTriangle, Link } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { EvidenceReference } from '@/lib/evidenceApi';

interface LinkedControlsPanelProps {
  evidence: EvidenceReference | null;
}

export function LinkedControlsPanel({ evidence }: LinkedControlsPanelProps) {
  if (!evidence) {
    return (
      <Card aria-label="linked-controls-panel">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Linked Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="linked-controls-empty">
            Select an evidence item to view linked controls.
          </p>
        </CardContent>
      </Card>
    );
  }

  const { control_ids, evidence_id, evidence_type } = evidence;

  return (
    <Card aria-label="linked-controls-panel">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">
          Linked Controls
          <span className="ml-2 text-xs font-normal text-muted-foreground">
            ({control_ids.length})
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {control_ids.length === 0 ? (
          <div
            className="flex items-center gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2"
            aria-label="no-controls-warning"
          >
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-600" aria-hidden="true" />
            <p className="text-xs text-amber-700 dark:text-amber-400">
              No controls linked to this evidence item. Evidence without control linkage may not
              contribute to readiness scoring.
            </p>
          </div>
        ) : (
          <ul className="flex flex-col gap-1.5" aria-label="control-id-list">
            {control_ids.map((id) => (
              <li
                key={id}
                className="flex items-center gap-2 rounded border border-border bg-surface-2 px-3 py-1.5"
                aria-label={`linked-control-${id}`}
              >
                <Link className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden="true" />
                <span className="font-mono text-xs text-foreground break-all">{id}</span>
              </li>
            ))}
          </ul>
        )}

        {/* Evidence basis context */}
        <div className="mt-3 text-xs text-muted-foreground" aria-label="evidence-contribution-basis">
          <p>
            Evidence type: <span className="font-medium text-foreground">{evidence_type}</span>
          </p>
          <p className="mt-0.5">
            Evidence ID:{' '}
            <span className="font-mono font-medium text-foreground break-all">{evidence_id}</span>
          </p>
          <p className="mt-2 text-muted-foreground/70">
            Control linkage is authoritative from the readiness API. Do not infer control
            contribution client-side.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
