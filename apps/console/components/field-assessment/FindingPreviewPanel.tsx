'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { SeverityBadge } from './StatusBadge';
import type { Finding } from '@/lib/fieldAssessmentApi';

const STATUS_LABEL: Record<string, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  remediated: 'Remediated',
  accepted_risk: 'Accepted Risk',
  closed: 'Closed',
};

const STATUS_COLOR: Record<string, string> = {
  open: 'text-danger',
  acknowledged: 'text-warning',
  remediated: 'text-success',
  accepted_risk: 'text-muted',
  closed: 'text-muted',
};

interface Props {
  findings: Finding[];
  loading?: boolean;
  error?: string | null;
}

export function FindingPreviewPanel({ findings, loading, error }: Props) {
  if (loading) {
    return (
      <div className="space-y-3" aria-label="finding-preview-panel" aria-busy="true">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-20 rounded border border-border bg-surface-2 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive" aria-label="finding-preview-panel">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  if (findings.length === 0) {
    return (
      <div
        aria-label="finding-preview-panel"
        className="flex flex-col items-center justify-center py-12 text-center text-muted"
      >
        <p className="text-sm font-medium">No findings yet</p>
        <p className="text-xs mt-1">Findings are normalized by the governance substrate from scan and observation data</p>
      </div>
    );
  }

  return (
    <div className="space-y-3" aria-label="finding-preview-panel">
      {findings.map((f) => (
        <Card key={f.id} className="border-border">
          <CardHeader className="pb-2 pt-3 px-4">
            <div className="flex flex-wrap items-start gap-2">
              <SeverityBadge severity={f.severity} />
              <span className={`text-xs font-semibold ${STATUS_COLOR[f.status] ?? 'text-muted'}`}>
                {STATUS_LABEL[f.status] ?? f.status}
              </span>
              <span className="text-xs text-muted ml-auto font-mono">
                confidence: {f.confidence_score}%
              </span>
            </div>
            <CardTitle className="text-sm font-medium text-foreground mt-1">{f.title}</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-2">
            <p className="text-xs text-muted line-clamp-2">{f.description}</p>
            <div className="flex flex-wrap gap-3 text-xs text-muted">
              <span>Source: <span className="text-foreground">{f.source_attribution}</span></span>
              {f.evidence_ref_ids.length > 0 && (
                <span>Evidence refs: <span className="text-foreground">{f.evidence_ref_ids.length}</span></span>
              )}
            </div>
            {(f.framework_mappings.length > 0 || f.nist_ai_rmf_mappings.length > 0) && (
              <div className="flex flex-wrap gap-1 mt-1">
                {f.nist_ai_rmf_mappings.slice(0, 4).map((m, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-info/20 bg-info/5 text-info"
                  >
                    NIST AI RMF
                  </span>
                ))}
                {f.framework_mappings.slice(0, 4).map((m, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-border bg-surface-2 text-muted"
                  >
                    Framework
                  </span>
                ))}
              </div>
            )}
            {f.remediation_hint && (
              <p className="text-xs text-muted border-l-2 border-warning/40 pl-2 mt-1">
                {f.remediation_hint}
              </p>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
