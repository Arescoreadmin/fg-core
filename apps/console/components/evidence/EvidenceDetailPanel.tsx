'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  type EvidenceReference,
  type TrustState,
  extractSafeSourceMeta,
  deriveTrustState,
  SAFE_SOURCE_META_KEYS,
} from '@/lib/evidenceApi';

interface EvidenceDetailPanelProps {
  evidence: EvidenceReference | null;
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

export function EvidenceDetailPanel({ evidence }: EvidenceDetailPanelProps) {
  if (!evidence) {
    return (
      <Card aria-label="evidence-detail-panel">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Evidence Detail</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="evidence-detail-empty">
            Select an evidence item from the timeline to view details.
          </p>
        </CardContent>
      </Card>
    );
  }

  const safeMeta = extractSafeSourceMeta(evidence.evidence_source_metadata);
  const trust = deriveTrustState(safeMeta);
  const totalMetaKeys = Object.keys(evidence.evidence_source_metadata).length;
  const displayedMetaKeys = Object.keys(safeMeta).length;
  const hiddenKeyCount = totalMetaKeys - displayedMetaKeys;

  return (
    <Card aria-label="evidence-detail-panel">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Evidence Detail</CardTitle>
      </CardHeader>
      <CardContent>
        {/* Identity */}
        <div className="mb-4 flex flex-wrap items-center gap-2" aria-label="evidence-identity">
          <span className="font-mono text-xs text-muted-foreground break-all">
            {evidence.evidence_id}
          </span>
          <Badge variant={trustVariant(trust)} aria-label="trust-state-badge">
            {trust}
          </Badge>
        </div>

        {/* Core fields */}
        <div className="grid gap-3 sm:grid-cols-2 mb-4">
          <MetaRow label="Title" value={evidence.evidence_title} />
          <MetaRow label="Evidence Type" value={evidence.evidence_type} />
          <MetaRow label="Classification" value={evidence.evidence_classification} />
          <MetaRow label="Submitted By" value={evidence.submitted_by} />
          <div className="flex flex-col gap-0.5" aria-label="submitted-at">
            <span className="text-xs text-muted-foreground">Submitted At</span>
            <time className="text-xs font-medium" dateTime={evidence.submitted_at}>
              {new Date(evidence.submitted_at).toLocaleString()}
            </time>
          </div>
          <div className="flex flex-col gap-0.5" aria-label="assessment-linkage">
            <span className="text-xs text-muted-foreground">Assessment</span>
            <span className="font-mono text-xs font-medium break-all">
              {evidence.assessment_id}
            </span>
          </div>
        </div>

        {/* Notes */}
        {evidence.notes && (
          <div className="mb-4" aria-label="evidence-notes">
            <p className="text-xs text-muted-foreground mb-1">Notes</p>
            <p className="text-xs text-foreground rounded border border-border bg-surface-2 px-3 py-2">
              {evidence.notes}
            </p>
          </div>
        )}

        {/* Safe source metadata */}
        {displayedMetaKeys > 0 && (
          <div className="mb-2" aria-label="source-metadata-safe">
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Source Metadata
            </p>
            <div className="grid gap-2 sm:grid-cols-2 rounded border border-border bg-surface-2 px-3 py-2">
              {(Object.entries(safeMeta) as [string, string][]).map(([k, v]) => (
                <MetaRow key={k} label={k.replace(/_/g, ' ')} value={v} mono />
              ))}
            </div>
            {hiddenKeyCount > 0 && (
              <p className="mt-1 text-xs text-muted-foreground" aria-label="metadata-hidden-count">
                {hiddenKeyCount} additional metadata field{hiddenKeyCount !== 1 ? 's' : ''} not
                displayed (export-safe keys only).
              </p>
            )}
          </div>
        )}

        {/* Export / review readiness indicators */}
        <div className="mt-3 grid gap-2 sm:grid-cols-3 text-xs" aria-label="export-readiness-indicators">
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">Export Safe</span>
            <span className="font-medium">
              {safeMeta.export_safe === 'true'
                ? 'Yes'
                : safeMeta.export_safe === 'false'
                  ? 'No'
                  : 'Unknown'}
            </span>
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">Integrity Verified</span>
            <span className="font-medium">
              {safeMeta.integrity_verified === 'true'
                ? 'Yes'
                : safeMeta.integrity_verified === 'false'
                  ? 'No'
                  : 'Unknown'}
            </span>
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">CoC Ready</span>
            <span className="font-medium">
              {safeMeta.chain_of_custody_ready === 'true'
                ? 'Yes'
                : safeMeta.chain_of_custody_ready === 'false'
                  ? 'No'
                  : 'Unknown'}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
