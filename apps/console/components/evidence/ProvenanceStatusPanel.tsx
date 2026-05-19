'use client';

import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  type EvidenceReference,
  type TrustState,
  extractSafeSourceMeta,
  deriveTrustState,
} from '@/lib/evidenceApi';

interface ProvenanceStatusPanelProps {
  evidence: EvidenceReference | null;
}

function TrustIcon({ state }: { state: TrustState }) {
  if (state === 'valid') return <CheckCircle2 className="h-4 w-4 shrink-0 text-success" aria-hidden="true" />;
  if (state === 'invalid') return <XCircle className="h-4 w-4 shrink-0 text-risk-critical" aria-hidden="true" />;
  if (state === 'missing') return <XCircle className="h-4 w-4 shrink-0 text-risk-critical" aria-hidden="true" />;
  if (state === 'stale') return <ShieldAlert className="h-4 w-4 shrink-0 text-risk-medium" aria-hidden="true" />;
  if (state === 'restricted') return <AlertTriangle className="h-4 w-4 shrink-0 text-muted" aria-hidden="true" />;
  return <HelpCircle className="h-4 w-4 shrink-0 text-muted" aria-hidden="true" />;
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

function warningFor(state: TrustState): string | null {
  if (state === 'invalid') return 'Provenance validation failed. This evidence may not meet compliance requirements.';
  if (state === 'missing') return 'Provenance data is missing. Evidence without provenance cannot be used for compliance attestation.';
  if (state === 'stale') return 'Provenance data is stale. Re-validation may be required before inclusion in an audit package.';
  if (state === 'unverifiable') return 'Provenance cannot be independently verified. Treat as unconfirmed for governance purposes.';
  if (state === 'restricted') return 'Provenance access is restricted. Contact your compliance administrator.';
  return null;
}

export function ProvenanceStatusPanel({ evidence }: ProvenanceStatusPanelProps) {
  if (!evidence) {
    return (
      <Card aria-label="provenance-status-panel">
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Provenance Status</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground" aria-label="provenance-status-empty">
            Select an evidence item to view provenance status.
          </p>
        </CardContent>
      </Card>
    );
  }

  const safeMeta = extractSafeSourceMeta(evidence.evidence_source_metadata);
  const trust = deriveTrustState(safeMeta);
  const warning = warningFor(trust);

  return (
    <Card aria-label="provenance-status-panel">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Provenance Status</CardTitle>
      </CardHeader>
      <CardContent>
        {/* Trust state header */}
        <div className="mb-4 flex items-center gap-2" aria-label="provenance-trust-state">
          <TrustIcon state={trust} />
          <Badge variant={trustVariant(trust)} aria-label="provenance-trust-badge">
            {trust}
          </Badge>
        </div>

        {/* Warning for degraded states */}
        {warning && (
          <div
            className="mb-4 flex items-start gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2"
            aria-label="provenance-warning"
          >
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600" aria-hidden="true" />
            <p className="text-xs text-amber-700 dark:text-amber-400">{warning}</p>
          </div>
        )}

        {/* Provenance fields from safe metadata */}
        <div className="space-y-2 text-xs" aria-label="provenance-metadata">
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">Validation Status</span>
            <span className="font-mono font-medium text-foreground">
              {safeMeta.validation_status ?? <span className="italic text-muted-foreground">—</span>}
            </span>
          </div>
          {safeMeta.validation_reason && (
            <div className="flex flex-col gap-0.5" aria-label="provenance-validation-reason">
              <span className="text-muted-foreground">Validation Reason</span>
              <span className="font-medium text-foreground break-all">{safeMeta.validation_reason}</span>
            </div>
          )}
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">Source System</span>
            <span className="font-mono font-medium text-foreground break-all">
              {safeMeta.source_system ?? <span className="italic text-muted-foreground">—</span>}
            </span>
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">Source Type</span>
            <span className="font-medium text-foreground">
              {safeMeta.source_type ?? <span className="italic text-muted-foreground">—</span>}
            </span>
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">Ingestion Method</span>
            <span className="font-medium text-foreground">
              {safeMeta.ingestion_method ?? <span className="italic text-muted-foreground">—</span>}
            </span>
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-muted-foreground">Integrity Verified</span>
            <span className="font-medium text-foreground" aria-label="provenance-integrity-verified">
              {safeMeta.integrity_verified === 'true'
                ? 'Yes'
                : safeMeta.integrity_verified === 'false'
                  ? 'No'
                  : 'Unknown'}
            </span>
          </div>
        </div>

        <p className="mt-3 text-xs text-muted-foreground/70" aria-label="provenance-authority-note">
          Provenance status is derived from server-validated metadata. Do not infer compliance
          posture from trust state alone.
        </p>
      </CardContent>
    </Card>
  );
}
