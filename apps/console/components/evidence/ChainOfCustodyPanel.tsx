'use client';

import { ShieldCheck, ShieldAlert, Hash } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  type EvidenceReference,
  extractSafeSourceMeta,
} from '@/lib/evidenceApi';

interface ChainOfCustodyPanelProps {
  evidence: EvidenceReference | null;
}

function ReadinessIndicator({ label, value }: { label: string; value: string | undefined }) {
  const isReady = value === 'true';
  const isNotReady = value === 'false';
  return (
    <div className="flex items-center justify-between gap-2 rounded border border-border bg-surface-2 px-3 py-2">
      <span className="text-xs text-muted-foreground">{label}</span>
      <div className="flex items-center gap-1.5">
        {isReady ? (
          <ShieldCheck className="h-3.5 w-3.5 text-success" aria-hidden="true" />
        ) : isNotReady ? (
          <ShieldAlert className="h-3.5 w-3.5 text-risk-high" aria-hidden="true" />
        ) : null}
        <span
          className={`text-xs font-medium ${isReady ? 'text-success' : isNotReady ? 'text-risk-high' : 'text-muted-foreground'}`}
        >
          {isReady ? 'Ready' : isNotReady ? 'Not Ready' : 'Unknown'}
        </span>
      </div>
    </div>
  );
}

export function ChainOfCustodyPanel({ evidence }: ChainOfCustodyPanelProps) {
  if (!evidence) {
    return (
      <Card aria-label="chain-of-custody-panel">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Chain of Custody</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="coc-panel-empty">
            Select an evidence item to view chain of custody metadata.
          </p>
        </CardContent>
      </Card>
    );
  }

  const safeMeta = extractSafeSourceMeta(evidence.evidence_source_metadata);
  const cocReady = safeMeta.chain_of_custody_ready;
  const integrityVerified = safeMeta.integrity_verified;
  const exportSafe = safeMeta.export_safe;
  const hashAlgorithm = safeMeta.hash_algorithm;
  const hashVerified = safeMeta.hash_verified;

  const allReady = cocReady === 'true' && integrityVerified === 'true' && exportSafe === 'true';
  const anyFailed = cocReady === 'false' || integrityVerified === 'false' || exportSafe === 'false';

  return (
    <Card aria-label="chain-of-custody-panel">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">
          Chain of Custody
          {allReady && (
            <span className="ml-2 text-xs font-normal text-success" aria-label="coc-ready-indicator">
              Ready
            </span>
          )}
          {anyFailed && !allReady && (
            <span className="ml-2 text-xs font-normal text-risk-high" aria-label="coc-not-ready-indicator">
              Not Ready
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2" aria-label="coc-readiness-indicators">
          <ReadinessIndicator label="CoC Ready" value={cocReady} />
          <ReadinessIndicator label="Integrity Verified" value={integrityVerified} />
          <ReadinessIndicator label="Export Safe" value={exportSafe} />
        </div>

        {/* Hash information */}
        {(hashAlgorithm || hashVerified) && (
          <div className="mt-3 space-y-1.5 text-xs" aria-label="coc-hash-info">
            <div className="flex items-center gap-1 text-muted-foreground">
              <Hash className="h-3 w-3" aria-hidden="true" />
              <span className="text-xs font-medium uppercase tracking-wide">Hash</span>
            </div>
            {hashAlgorithm && (
              <div className="flex flex-col gap-0.5">
                <span className="text-muted-foreground">Algorithm</span>
                <span className="font-mono font-medium text-foreground">{hashAlgorithm}</span>
              </div>
            )}
            {hashVerified && (
              <div className="flex flex-col gap-0.5">
                <span className="text-muted-foreground">Hash Verified</span>
                <span className="font-medium text-foreground">
                  {hashVerified === 'true' ? 'Yes' : hashVerified === 'false' ? 'No' : 'Unknown'}
                </span>
              </div>
            )}
          </div>
        )}

        {/* Source + format */}
        <div className="mt-3 space-y-1.5 text-xs" aria-label="coc-source-info">
          {safeMeta.evidence_format && (
            <div className="flex flex-col gap-0.5">
              <span className="text-muted-foreground">Evidence Format</span>
              <span className="font-mono font-medium text-foreground">{safeMeta.evidence_format}</span>
            </div>
          )}
          {safeMeta.source_category && (
            <div className="flex flex-col gap-0.5">
              <span className="text-muted-foreground">Source Category</span>
              <span className="font-medium text-foreground">{safeMeta.source_category}</span>
            </div>
          )}
        </div>

        <p className="mt-3 text-xs text-muted-foreground/70" aria-label="coc-authority-note">
          Chain-of-custody readiness is authoritative from the evidence API. Readiness does not constitute legal certification.
        </p>
      </CardContent>
    </Card>
  );
}
