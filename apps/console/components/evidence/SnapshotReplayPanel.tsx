'use client';

import { GitCommitHorizontal, Info } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { EvidenceReference } from '@/lib/evidenceApi';

interface SnapshotReplayPanelProps {
  evidence: EvidenceReference | null;
  assessmentId: string | null;
}

function MetaRow({ label, value, mono = false }: { label: string; value: string | null | undefined; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`text-xs font-medium break-all ${mono ? 'font-mono' : ''}`}>
        {value ?? <span className="italic text-muted-foreground">—</span>}
      </span>
    </div>
  );
}

export function SnapshotReplayPanel({ evidence, assessmentId }: SnapshotReplayPanelProps) {
  if (!evidence) {
    return (
      <Card aria-label="snapshot-replay-panel">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Snapshot & Replay</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="snapshot-replay-empty">
            Select an evidence item to view snapshot and replay context.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card aria-label="snapshot-replay-panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-sm font-semibold">
          <GitCommitHorizontal className="h-4 w-4 text-muted" aria-hidden="true" />
          Snapshot & Replay
        </CardTitle>
      </CardHeader>
      <CardContent>
        {/* Assessment + evidence anchor */}
        <div className="mb-4 grid gap-2 sm:grid-cols-2 text-xs" aria-label="snapshot-anchor">
          <MetaRow label="Assessment ID" value={assessmentId} mono />
          <MetaRow label="Evidence ID" value={evidence.evidence_id} mono />
          <MetaRow label="Submitted At" value={new Date(evidence.submitted_at).toLocaleString()} />
          <MetaRow label="Submitted By" value={evidence.submitted_by} />
        </div>

        {/* Snapshot contract fields */}
        <div className="mb-4 grid gap-2 text-xs" aria-label="snapshot-contract-fields">
          <MetaRow label="Evidence Type" value={evidence.evidence_type} />
          <MetaRow label="Classification" value={evidence.evidence_classification} />
        </div>

        {/* Forensic replay seam — Gap D */}
        {/* aria-label="forensic-replay-panel" reserved for future forensic replay surface */}
        <div
          className="flex items-start gap-2 rounded border border-border bg-surface-2 px-3 py-2"
          aria-label="forensic-replay-seam"
        >
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" aria-hidden="true" />
          <div className="text-xs text-muted-foreground">
            <p className="font-medium text-foreground">Forensic Replay</p>
            <p className="mt-0.5">
              Deterministic replay verification is not yet wired for this deployment. When
              available, replay will confirm evidence snapshot integrity against the canonical
              provenance chain.
            </p>
          </div>
        </div>

        <p className="mt-3 text-xs text-muted-foreground/70" aria-label="snapshot-authority-note">
          Snapshot context reflects evidence at time of submission. Replay integrity is
          authoritative from the forensic replay API, not derived client-side.
        </p>
      </CardContent>
    </Card>
  );
}
