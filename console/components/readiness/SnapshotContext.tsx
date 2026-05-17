'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { GapReplayContract, Assessment } from '@/lib/readinessApi';

interface SnapshotContextProps {
  contract: GapReplayContract;
  assessment: Assessment;
}

function MetaRow({
  label,
  value,
  ariaLabel,
}: {
  label: string;
  value: string | null | undefined;
  ariaLabel: string;
}) {
  return (
    <div className="flex flex-col gap-0.5" aria-label={ariaLabel}>
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="break-all font-mono text-xs font-medium">
        {value ?? <span className="font-sans italic text-muted-foreground">—</span>}
      </span>
    </div>
  );
}

export function SnapshotContext({ contract, assessment }: SnapshotContextProps) {
  return (
    <Card aria-label="snapshot-context">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Snapshot &amp; Replay Context</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2">
          <MetaRow
            label="Analysis Version"
            value={contract.analysis_version}
            ariaLabel="analysis-version"
          />
          <MetaRow
            label="Framework Version"
            value={contract.framework_version}
            ariaLabel="framework-version"
          />
          <MetaRow
            label="Scoring Contract Version"
            value={contract.scoring_contract_version}
            ariaLabel="scoring-contract-version"
          />
          <MetaRow
            label="Maturity Model Version"
            value={contract.maturity_model_version}
            ariaLabel="maturity-model-version"
          />
          <MetaRow
            label="Mapping Version"
            value={contract.mapping_version}
            ariaLabel="mapping-version"
          />
          <MetaRow
            label="Evidence Snapshot Version"
            value={contract.evidence_snapshot_version}
            ariaLabel="evidence-snapshot-version"
          />
        </div>

        <hr className="my-3 border-border" />

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-0.5" aria-label="assessment-created-at">
            <span className="text-xs text-muted-foreground">Assessment Created</span>
            <span className="text-xs font-medium">
              {new Date(assessment.created_at).toLocaleString()}
            </span>
          </div>
          {assessment.activated_at && (
            <div className="flex flex-col gap-0.5" aria-label="assessment-activated-at">
              <span className="text-xs text-muted-foreground">Activated</span>
              <span className="text-xs font-medium">
                {new Date(assessment.activated_at).toLocaleString()}
              </span>
            </div>
          )}
          {assessment.finalized_at && (
            <div className="flex flex-col gap-0.5" aria-label="assessment-finalized-at">
              <span className="text-xs text-muted-foreground">Finalized</span>
              <span className="text-xs font-medium">
                {new Date(assessment.finalized_at).toLocaleString()}
              </span>
            </div>
          )}
          <div className="flex flex-col gap-0.5" aria-label="assessment-snapshot-version">
            <span className="text-xs text-muted-foreground">Snapshot Version</span>
            <span className="text-xs font-medium tabular-nums">
              {assessment.snapshot_version}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
