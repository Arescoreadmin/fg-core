'use client';

import { useState } from 'react';
import { Button, Input } from '@fg/ui';
import { Card, CardContent, CardHeader, CardTitle } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { SeverityBadge } from './StatusBadge';
import { fieldAssessmentApi, type Finding } from '@/lib/fieldAssessmentApi';

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
  engagementId: string;
  loading?: boolean;
  error?: string | null;
  onRemediationSaved?: () => void;
}

function RemediationForm({ engagementId, finding, onSaved }: { engagementId: string; finding: Finding; onSaved?: () => void }) {
  const [hint, setHint] = useState(finding.remediation_hint ?? '');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!hint.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await fieldAssessmentApi.patchFindingRemediation(engagementId, finding.id, hint.trim());
      setSaved(true);
      onSaved?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSave} className="space-y-2 border-t border-border pt-3 mt-2">
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">Remediation Guidance</p>
      <Input
        value={hint}
        onChange={(e) => { setHint(e.target.value); setSaved(false); }}
        placeholder="Describe remediation steps, owner, and timeline…"
        disabled={saving}
        className="text-xs"
      />
      {error && <p className="text-xs text-danger">{error}</p>}
      <div className="flex items-center gap-2">
        <Button type="submit" disabled={saving || !hint.trim()} className="h-7 text-xs px-3">
          {saving ? 'Saving…' : 'Save'}
        </Button>
        {saved && <span className="text-xs text-success">Saved</span>}
      </div>
    </form>
  );
}

export function FindingPreviewPanel({ findings, engagementId, loading, error, onRemediationSaved }: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
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
      {findings.map((f) => {
        const expanded = expandedId === f.id;
        return (
          <Card key={f.id} className="border-border">
            <CardHeader
              className="pb-2 pt-3 px-4 cursor-pointer select-none"
              onClick={() => setExpandedId(expanded ? null : f.id)}
              role="button"
              aria-expanded={expanded}
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && setExpandedId(expanded ? null : f.id)}
            >
              <div className="flex flex-wrap items-start gap-2">
                <SeverityBadge severity={f.severity} />
                <span className={`text-xs font-semibold ${STATUS_COLOR[f.status] ?? 'text-muted'}`}>
                  {STATUS_LABEL[f.status] ?? f.status}
                </span>
                <span className="text-xs text-muted ml-auto font-mono">
                  confidence: {f.confidence_score}%
                </span>
                <span className="text-xs text-muted">{expanded ? '▲' : '▼'}</span>
              </div>
              <CardTitle className="text-sm font-medium text-foreground mt-1">{f.title}</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3 space-y-2">
              <p className={`text-xs text-muted ${expanded ? '' : 'line-clamp-2'}`}>{f.description}</p>

              {!expanded && (
                <div className="flex flex-wrap gap-3 text-xs text-muted">
                  <span>Source: <span className="text-foreground">{f.source_attribution}</span></span>
                  {f.evidence_ref_ids.length > 0 && (
                    <span>Evidence refs: <span className="text-foreground">{f.evidence_ref_ids.length}</span></span>
                  )}
                </div>
              )}

              {expanded && (
                <div className="space-y-3 border-t border-border pt-3 mt-1">
                  <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                    <dt className="text-muted">Finding ID</dt>
                    <dd className="font-mono text-foreground truncate">{f.id}</dd>
                    <dt className="text-muted">Type</dt>
                    <dd className="text-foreground">{f.finding_type}</dd>
                    <dt className="text-muted">Source</dt>
                    <dd className="text-foreground">{f.source_attribution}</dd>
                    <dt className="text-muted">Confidence</dt>
                    <dd className="text-foreground font-mono">{f.confidence_score}%</dd>
                    <dt className="text-muted">Schema</dt>
                    <dd className="text-foreground font-mono">{f.schema_version}</dd>
                  </dl>

                  {f.evidence_ref_ids.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs font-semibold text-muted uppercase tracking-wider">Evidence Refs ({f.evidence_ref_ids.length})</p>
                      <div className="flex flex-wrap gap-1">
                        {f.evidence_ref_ids.map((ref, i) => (
                          <span key={i} className="font-mono text-xs bg-surface-2 border border-border rounded px-1.5 py-0.5 text-foreground">{ref}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {f.nist_ai_rmf_mappings.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs font-semibold text-muted uppercase tracking-wider">NIST AI RMF Mappings</p>
                      <div className="flex flex-wrap gap-1">
                        {f.nist_ai_rmf_mappings.map((m, i) => (
                          <span key={i} className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-info/20 bg-info/5 text-info font-mono">
                            {typeof m === 'string' ? m : JSON.stringify(m)}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {f.framework_mappings.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs font-semibold text-muted uppercase tracking-wider">Framework Mappings</p>
                      <div className="flex flex-wrap gap-1">
                        {f.framework_mappings.map((m, i) => (
                          <span key={i} className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-border bg-surface-2 text-muted font-mono">
                            {typeof m === 'string' ? m : JSON.stringify(m)}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {(f.framework_mappings.length > 0 || f.nist_ai_rmf_mappings.length > 0) && !expanded && (
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

              {f.remediation_hint && !expanded && (
                <p className="text-xs text-muted border-l-2 border-warning/40 pl-2 mt-1">
                  {f.remediation_hint}
                </p>
              )}

              {expanded && (
                <RemediationForm
                  engagementId={engagementId}
                  finding={f}
                  onSaved={onRemediationSaved}
                />
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
