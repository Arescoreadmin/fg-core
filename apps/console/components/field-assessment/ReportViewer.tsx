'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { SeverityBadge } from './StatusBadge';
import { fieldAssessmentApi, type FindingExplanation } from '@/lib/fieldAssessmentApi';
import type { ReportDocument } from '@/lib/fieldAssessmentApi';

// Safe string coercion — no raw objects/payloads in UI
function safeStr(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

function safeArr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function safeObj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}

function SectionAccordion({ title, children, defaultOpen = false }: {
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded">
      <button
        className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-semibold text-foreground bg-surface-2 hover:bg-surface-3 transition-colors rounded"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span>{title}</span>
        <span className="text-muted">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 pt-2">
          {children}
        </div>
      )}
    </div>
  );
}

function FindingRow({
  finding,
  engagementId,
  onShowEvidence,
}: {
  finding: Record<string, unknown>;
  engagementId?: string;
  onShowEvidence?: (findingId: string) => void;
}) {
  const severity = safeStr(finding.severity) || 'info';
  const title = safeStr(finding.title) || safeStr(finding.finding_type) || 'Untitled finding';
  const id = safeStr(finding.id) || safeStr(finding.finding_id);
  const confidence = finding.confidence_score != null ? Number(finding.confidence_score) : null;
  const frameworks = safeArr(finding.framework_mappings);
  const nistMappings = safeArr(finding.nist_ai_rmf_mappings);
  const evidenceRefs = safeArr(finding.evidence_ref_ids);

  const [explanation, setExplanation] = useState<FindingExplanation | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [showExplain, setShowExplain] = useState(false);

  async function handleExplain() {
    if (explanation) { setShowExplain((v) => !v); return; }
    if (!engagementId || !id) return;
    setExplainLoading(true);
    setExplainError(null);
    setShowExplain(true);
    try {
      const result = await fieldAssessmentApi.explainFinding(engagementId, id);
      setExplanation(result);
    } catch {
      setExplainError('Could not load explanation.');
    } finally {
      setExplainLoading(false);
    }
  }

  return (
    <div className="p-2.5 rounded border border-border bg-surface-2 space-y-1.5 text-xs">
      <div className="flex flex-wrap items-start gap-2">
        <SeverityBadge severity={severity as never} />
        <span className="font-medium text-foreground flex-1 min-w-0">{title}</span>
        {confidence !== null && (
          <span className="font-mono text-muted">confidence: {confidence}%</span>
        )}
        {engagementId && id && (
          <button
            type="button"
            onClick={handleExplain}
            className="text-[11px] text-primary hover:underline focus:outline-none shrink-0"
          >
            {showExplain ? 'Hide' : 'Explain →'}
          </button>
        )}
      </div>
      {id && (
        <div className="font-mono text-muted truncate">ID: {id}</div>
      )}
      {(frameworks.length > 0 || nistMappings.length > 0) && (
        <div className="flex flex-wrap gap-1">
          {nistMappings.slice(0, 4).map((m, i) => (
            <span key={i} className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-info/20 bg-info/5 text-info">
              {typeof m === 'string' ? m : 'NIST AI RMF'}
            </span>
          ))}
          {frameworks.slice(0, 4).map((m, i) => (
            <span key={i} className="inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-border bg-surface-2 text-muted">
              {typeof m === 'string' ? m : 'Framework'}
            </span>
          ))}
        </div>
      )}
      {evidenceRefs.length > 0 && (
        <div className="text-muted">Evidence refs: <span className="text-foreground">{evidenceRefs.length}</span></div>
      )}

      {showExplain && (
        <div className="mt-1.5 rounded border border-primary/20 bg-primary/5 p-2.5 space-y-2">
          {explainLoading && (
            <div className="space-y-1.5" aria-busy="true">
              <div className="h-3 w-3/4 rounded bg-surface-3 animate-pulse" />
              <div className="h-3 w-1/2 rounded bg-surface-3 animate-pulse" />
            </div>
          )}
          {explainError && (
            <p className="text-red-300">{explainError}</p>
          )}
          {explanation && !explainLoading && (
            <>
              <p className="text-foreground font-medium">{explanation.plain_summary}</p>
              <p className="text-muted">{explanation.what_it_means}</p>
              {explanation.affected_entities.length > 0 && (
                <ul className="space-y-0.5 pl-3">
                  {explanation.affected_entities.map((e, i) => (
                    <li key={i} className="text-muted list-disc">
                      <span className="font-semibold text-foreground">{e.count}</span>{' '}
                      {e.label}
                    </li>
                  ))}
                </ul>
              )}
              {explanation.framework_impact.length > 0 && (
                <div className="flex flex-wrap gap-1 pt-0.5">
                  {explanation.framework_impact.map((fw) => (
                    <span key={fw} className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] border border-info/20 bg-info/5 text-info font-medium">
                      {fw}
                    </span>
                  ))}
                </div>
              )}
              {explanation.explanation_confidence < 0.7 && (
                <p className="text-[11px] text-amber-300">
                  Limited scan evidence — explanation based on finding metadata only.
                </p>
              )}
              {explanation.signals_used.length > 0 && (
                <details className="pt-0.5">
                  <summary className="text-[11px] text-muted cursor-pointer hover:text-foreground select-none">
                    Provenance — {explanation.signals_used.length} signal{explanation.signals_used.length !== 1 ? 's' : ''}
                  </summary>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {explanation.signals_used.map((s) => (
                      <span key={s} className="font-mono text-[10px] rounded px-1 py-0.5 border border-border bg-surface-3 text-muted">
                        {s}
                      </span>
                    ))}
                  </div>
                </details>
              )}
              <div className="flex items-center gap-3 pt-0.5">
                {onShowEvidence && id && (
                  <button
                    type="button"
                    onClick={() => onShowEvidence(id)}
                    className="text-[11px] text-primary hover:underline focus:outline-none"
                  >
                    Show evidence →
                  </button>
                )}
                <span className="text-[11px] text-muted ml-auto">
                  {explanation.evidence_count} scan{explanation.evidence_count !== 1 ? 's' : ''} ·{' '}
                  confidence {Math.round(explanation.explanation_confidence * 100)}% ·{' '}
                  template {explanation.template}
                </span>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function EvidenceRefRow({ ref: ev }: { ref: Record<string, unknown> }) {
  const id = safeStr(ev.evidence_id) || safeStr(ev.id);
  const source = safeStr(ev.source);
  const classification = safeStr(ev.classification);
  return (
    <div className="flex flex-wrap gap-3 text-xs p-2 rounded border border-border bg-surface-2">
      {id && <span className="font-mono text-foreground truncate max-w-[160px]">{id}</span>}
      {source && <span className="text-muted capitalize">{source.replace(/_/g, ' ')}</span>}
      {classification && <span className="text-muted">{classification}</span>}
    </div>
  );
}

interface Props {
  document: ReportDocument | null;
  loading: boolean;
  error: string | null;
  engagementId?: string;
  onShowEvidence?: (findingId: string) => void;
}

export function ReportViewer({ document: doc, loading, error, engagementId, onShowEvidence }: Props) {
  if (loading) {
    return (
      <div className="space-y-3" aria-label="report-viewer" aria-busy="true">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-12 rounded border border-border bg-surface-2 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive" aria-label="report-viewer">
        <AlertDescription className="text-xs">{error}</AlertDescription>
      </Alert>
    );
  }

  if (!doc) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-center text-muted" aria-label="report-viewer">
        <p className="text-sm font-medium">Select a report version to view details</p>
      </div>
    );
  }

  const body = safeObj(doc.report);
  const findings = safeArr(body.findings);
  const remediations = safeArr(body.remediations);
  const evidenceAppendix = safeArr(body.evidence_appendix);
  const normalizedFindings = safeArr(body.normalized_findings);
  const frameworkSummary = safeObj(body.framework_summary);
  const confidence = safeObj(body.confidence);

  return (
    <Card className="border-border" aria-label="report-viewer">
      <CardHeader className="pb-2 pt-4 px-4">
        <div className="flex flex-wrap items-center gap-3">
          <CardTitle className="text-sm">
            Report v{doc.version}
            {doc.report_type && (
              <span className="ml-2 font-normal text-muted capitalize">
                — {doc.report_type.replace(/_/g, ' ')}
              </span>
            )}
          </CardTitle>
        </div>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs mt-2">
          <dt className="text-muted">Report ID</dt>
          <dd className="font-mono text-foreground truncate">{doc.report_id}</dd>
          <dt className="text-muted">Schema</dt>
          <dd className="font-mono text-foreground">{doc.schema_version}</dd>
          <dt className="text-muted">Generated</dt>
          <dd className="text-foreground">{new Date(doc.generated_at).toLocaleString()}</dd>
          {doc.compiled_by && (
            <>
              <dt className="text-muted">Compiled by</dt>
              <dd className="text-foreground">{doc.compiled_by}</dd>
            </>
          )}
          <dt className="text-muted">Manifest hash</dt>
          <dd className="font-mono text-muted truncate max-w-[200px]">{doc.manifest_hash}</dd>
          <dt className="text-muted">Signature</dt>
          <dd className="font-mono text-muted truncate max-w-[200px]">
            {doc.signature ? `${doc.signature.slice(0, 16)}…` : 'none'}
          </dd>
        </dl>
      </CardHeader>

      <CardContent className="px-4 pb-4 space-y-3">

        {findings.length > 0 && (
          <SectionAccordion title={`Findings (${findings.length})`} defaultOpen>
            <div className="space-y-2">
              {findings.map((f, i) => (
                <FindingRow
                  key={i}
                  finding={safeObj(f)}
                  engagementId={engagementId}
                  onShowEvidence={onShowEvidence}
                />
              ))}
            </div>
          </SectionAccordion>
        )}

        {normalizedFindings.length > 0 && (
          <SectionAccordion title={`Findings Register (${normalizedFindings.length})`}>
            <div className="space-y-2">
              {normalizedFindings.map((f, i) => (
                <FindingRow
                  key={i}
                  finding={safeObj(f)}
                  engagementId={engagementId}
                  onShowEvidence={onShowEvidence}
                />
              ))}
            </div>
          </SectionAccordion>
        )}

        {remediations.length > 0 && (
          <SectionAccordion title={`Remediations (${remediations.length})`}>
            <div className="space-y-1.5">
              {remediations.map((r, i) => {
                const rem = safeObj(r);
                return (
                  <div key={i} className="text-xs p-2.5 rounded border border-border bg-surface-2 space-y-1">
                    {safeStr(rem.title) && (
                      <p className="font-medium text-foreground">{safeStr(rem.title)}</p>
                    )}
                    {safeStr(rem.description) && (
                      <p className="text-muted">{safeStr(rem.description)}</p>
                    )}
                  </div>
                );
              })}
            </div>
          </SectionAccordion>
        )}

        {evidenceAppendix.length > 0 && (
          <SectionAccordion title={`Evidence Lineage (${evidenceAppendix.length})`}>
            <div className="space-y-1.5">
              {evidenceAppendix.map((ev, i) => (
                <EvidenceRefRow key={i} ref={safeObj(ev)} />
              ))}
            </div>
          </SectionAccordion>
        )}

        {Object.keys(frameworkSummary).length > 0 && (
          <SectionAccordion title="Framework Summary">
            <div className="space-y-2">
              {Object.entries(frameworkSummary).map(([fw, controls]) => (
                <div key={fw} className="text-xs">
                  <p className="font-medium text-foreground mb-1">{fw}</p>
                  <div className="flex flex-wrap gap-1">
                    {safeArr(controls).map((c, i) => (
                      <span key={i} className="font-mono inline-flex items-center rounded px-1.5 py-0.5 text-xs border border-info/20 bg-info/5 text-info">
                        {safeStr(c) || String(c)}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </SectionAccordion>
        )}

        {Object.keys(confidence).length > 0 && (
          <SectionAccordion title="Confidence">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              {Object.entries(confidence)
                .filter(([, v]) => typeof v === 'number' || typeof v === 'string')
                .map(([k, v]) => (
                  <>
                    <dt key={`k-${k}`} className="text-muted capitalize">{k.replace(/_/g, ' ')}</dt>
                    <dd key={`v-${k}`} className="font-mono text-foreground">{safeStr(v)}</dd>
                  </>
                ))}
            </dl>
          </SectionAccordion>
        )}

        {Object.keys(doc.section_hashes).length > 0 && (
          <SectionAccordion title="Section Hashes">
            <dl className="space-y-1 text-xs">
              {Object.entries(doc.section_hashes).map(([section, hash]) => (
                <div key={section} className="flex gap-3">
                  <dt className="text-muted min-w-[120px] capitalize">{section.replace(/_/g, ' ')}</dt>
                  <dd className="font-mono text-foreground truncate">{hash}</dd>
                </div>
              ))}
            </dl>
          </SectionAccordion>
        )}

      </CardContent>
    </Card>
  );
}
