'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Label } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import {
  fieldAssessmentApi,
  type DocumentAnalysis,
  type Questionnaire,
  type QuestionnaireCategory,
  type QuestionnaireResponseItem,
  type ResponseStatus,
} from '@/lib/fieldAssessmentApi';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CATEGORIES: QuestionnaireCategory[] = ['GOVERN', 'MAP', 'MEASURE', 'MANAGE'];

const CATEGORY_LABELS: Record<QuestionnaireCategory, string> = {
  GOVERN: 'GOVERN — Policies, accountability & culture',
  MAP: 'MAP — Context, risk identification & interdependencies',
  MEASURE: 'MEASURE — Testing, evaluation & monitoring',
  MANAGE: 'MANAGE — Risk treatment, response & continual improvement',
};

const STATUS_OPTIONS: { value: ResponseStatus; label: string; color: string }[] = [
  { value: 'not_assessed', label: 'Not assessed', color: 'text-muted' },
  { value: 'implemented', label: 'Implemented', color: 'text-success' },
  { value: 'partial', label: 'Partial', color: 'text-warning' },
  { value: 'not_implemented', label: 'Not implemented', color: 'text-danger' },
  { value: 'not_applicable', label: 'N/A', color: 'text-muted' },
];

const SAVE_DEBOUNCE_MS = 800;

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ProgressBar({ assessed, total }: { assessed: number; total: number }) {
  const pct = total > 0 ? Math.round((assessed / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-muted">
        <span>{assessed} of {total} controls assessed</span>
        <span>{pct}%</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-surface-2 overflow-hidden">
        <div
          className="h-full rounded-full bg-primary transition-all duration-300"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: ResponseStatus }) {
  const opt = STATUS_OPTIONS.find((o) => o.value === status);
  return (
    <span className={`text-xs font-medium ${opt?.color ?? 'text-muted'}`}>
      {opt?.label ?? status}
    </span>
  );
}

interface ControlRowProps {
  response: QuestionnaireResponseItem;
  documents: DocumentAnalysis[];
  disabled: boolean;
  onSave: (controlId: string, status: ResponseStatus, evidence: string, evidenceDocId: string | null) => void;
}

function ControlRow({ response, documents, disabled, onSave }: ControlRowProps) {
  const [status, setStatus] = useState<ResponseStatus>(response.response_status);
  const [evidence, setEvidence] = useState(response.evidence_text ?? '');
  const [evidenceDocId, setEvidenceDocId] = useState<string | null>(response.evidence_doc_id ?? null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showEvidence = status !== 'not_assessed' && status !== 'not_applicable';
  const showDocPicker = status === 'implemented' || status === 'partial';

  function scheduleAutoSave(newStatus: ResponseStatus, newEvidence: string, newDocId: string | null) {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    setSaved(false);
    debounceRef.current = setTimeout(async () => {
      setSaving(true);
      try {
        await onSave(response.control_id, newStatus, newEvidence, newDocId);
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      } finally {
        setSaving(false);
      }
    }, SAVE_DEBOUNCE_MS);
  }

  function handleStatusChange(val: ResponseStatus) {
    setStatus(val);
    const ev = (val === 'not_assessed' || val === 'not_applicable') ? '' : evidence;
    const docId = (val === 'implemented' || val === 'partial') ? evidenceDocId : null;
    setEvidence(ev);
    if (docId !== evidenceDocId) setEvidenceDocId(docId);
    scheduleAutoSave(val, ev, docId);
  }

  function handleEvidenceChange(val: string) {
    setEvidence(val);
    scheduleAutoSave(status, val, evidenceDocId);
  }

  function handleDocChange(docId: string) {
    const resolved = docId || null;
    setEvidenceDocId(resolved);
    scheduleAutoSave(status, evidence, resolved);
  }

  const attachedDoc = evidenceDocId ? documents.find((d) => d.id === evidenceDocId) : null;

  return (
    <div className="rounded border border-border bg-surface p-3 space-y-2">
      <div className="flex flex-wrap items-start gap-2">
        <span className="text-xs font-mono font-semibold text-primary shrink-0 w-28">
          {response.control_id}
        </span>
        <p className="text-xs text-foreground flex-1 min-w-0">{response.control_name}</p>
        {saving && <span className="text-xs text-muted shrink-0">saving…</span>}
        {saved && !saving && <span className="text-xs text-success shrink-0">saved</span>}
      </div>

      <div className="flex flex-wrap gap-1.5">
        {STATUS_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            type="button"
            disabled={disabled}
            onClick={() => handleStatusChange(opt.value)}
            className={`px-2 py-0.5 rounded text-xs border transition-colors ${
              status === opt.value
                ? 'border-primary bg-primary/10 text-foreground font-medium'
                : 'border-border text-muted hover:text-foreground hover:border-border/80'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {showEvidence && (
        <div className="space-y-1">
          <Label htmlFor={`evidence-${response.control_id}`} className="text-xs text-muted">
            Evidence / notes
          </Label>
          <textarea
            id={`evidence-${response.control_id}`}
            rows={3}
            disabled={disabled}
            value={evidence}
            onChange={(e) => handleEvidenceChange(e.target.value)}
            placeholder="Describe the evidence, policy reference, or system in place…"
            className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-xs text-foreground placeholder:text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary resize-y disabled:opacity-50"
          />
        </div>
      )}

      {showDocPicker && (
        <div className="space-y-1">
          <Label htmlFor={`doc-${response.control_id}`} className="text-xs text-muted">
            Supporting document
          </Label>
          {disabled ? (
            attachedDoc ? (
              <span className="inline-flex items-center gap-1 text-xs text-foreground bg-surface-2 border border-border rounded px-2 py-0.5">
                <svg className="w-3 h-3 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                {attachedDoc.document_name}
              </span>
            ) : (
              <span className="text-xs text-muted">No document attached</span>
            )
          ) : (
            <select
              id={`doc-${response.control_id}`}
              disabled={disabled}
              value={evidenceDocId ?? ''}
              onChange={(e) => handleDocChange(e.target.value)}
              className="w-full rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary disabled:opacity-50"
            >
              <option value="">— No document attached —</option>
              {documents.map((doc) => (
                <option key={doc.id} value={doc.id}>
                  {doc.document_name}
                  {doc.version_label ? ` (${doc.version_label})` : ''}
                </option>
              ))}
            </select>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

interface Props {
  engagementId: string;
  onSubmitted?: () => void;
}

export function QuestionnairePanel({ engagementId, onSubmitted }: Props) {
  const [questionnaire, setQuestionnaire] = useState<Questionnaire | null>(null);
  const [documents, setDocuments] = useState<DocumentAnalysis[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState<QuestionnaireCategory>('GOVERN');

  const loadQuestionnaire = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [q, docs] = await Promise.all([
        fieldAssessmentApi.initQuestionnaire(engagementId),
        fieldAssessmentApi.listDocuments(engagementId),
      ]);
      setQuestionnaire(q);
      setDocuments(docs);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load questionnaire');
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    loadQuestionnaire();
  }, [loadQuestionnaire]);

  async function handleSave(
    controlId: string,
    status: ResponseStatus,
    evidenceText: string,
    evidenceDocId: string | null,
  ) {
    if (!questionnaire) return;
    const update = await fieldAssessmentApi.patchResponse(engagementId, questionnaire.id, controlId, {
      response_status: status,
      evidence_text: evidenceText || null,
      evidence_doc_id: evidenceDocId,
    });
    setQuestionnaire((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        responses: prev.responses.map((r) =>
          r.control_id === controlId
            ? {
                ...r,
                response_status: status,
                evidence_text: evidenceText || null,
                evidence_doc_id: update.evidence_doc_id ?? null,
              }
            : r,
        ),
      };
    });
  }

  async function handleSubmit() {
    if (!questionnaire) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const updated = await fieldAssessmentApi.submitQuestionnaire(engagementId, questionnaire.id);
      setQuestionnaire(updated);
      onSubmitted?.();
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : 'Submit failed');
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <div className="space-y-2 animate-pulse">
        <div className="h-4 w-48 bg-surface-2 rounded" />
        <div className="h-2 w-full bg-surface-2 rounded" />
        {[1, 2, 3].map((i) => <div key={i} className="h-16 bg-surface-2 rounded" />)}
      </div>
    );
  }

  if (error || !questionnaire) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{error ?? 'Failed to load questionnaire'}</AlertDescription>
      </Alert>
    );
  }

  const isReadOnly = questionnaire.status !== 'draft';
  const responses = questionnaire.responses;
  const assessedCount = responses.filter(
    (r) => r.response_status !== 'not_assessed',
  ).length;

  const byCategory: Record<QuestionnaireCategory, QuestionnaireResponseItem[]> = {
    GOVERN: [],
    MAP: [],
    MEASURE: [],
    MANAGE: [],
  };
  for (const r of responses) {
    const cat = r.category as QuestionnaireCategory;
    if (byCategory[cat]) byCategory[cat].push(r);
  }

  return (
    <div className="space-y-4" aria-label="questionnaire-panel">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1 flex-1 min-w-0">
          <p className="text-xs font-semibold text-foreground">
            NIST AI RMF 1.0 — {responses.length} controls
          </p>
          <ProgressBar assessed={assessedCount} total={responses.length} />
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {isReadOnly ? (
            <span className="text-xs px-2 py-1 rounded bg-success/10 text-success font-medium">
              Submitted {questionnaire.submitted_at?.slice(0, 10) ?? ''}
            </span>
          ) : (
            <Button
              type="button"
              onClick={handleSubmit}
              disabled={submitting || assessedCount === 0}
              className="text-xs h-8 px-3"
            >
              {submitting ? 'Submitting…' : 'Submit questionnaire'}
            </Button>
          )}
        </div>
      </div>

      {submitError && (
        <Alert variant="destructive">
          <AlertDescription>{submitError}</AlertDescription>
        </Alert>
      )}

      {isReadOnly && (
        <Alert variant="info">
          <AlertDescription className="text-xs">
            This questionnaire has been submitted. Responses are read-only.
            Evidence links to matching findings have been created automatically.
          </AlertDescription>
        </Alert>
      )}

      {/* Category tabs */}
      <div className="flex gap-1 flex-wrap border-b border-border pb-2">
        {CATEGORIES.map((cat) => {
          const catResponses = byCategory[cat];
          const catAssessed = catResponses.filter((r) => r.response_status !== 'not_assessed').length;
          return (
            <button
              key={cat}
              type="button"
              onClick={() => setActiveCategory(cat)}
              className={`px-3 py-1.5 rounded-t text-xs font-medium transition-colors ${
                activeCategory === cat
                  ? 'bg-surface-2 text-foreground border border-border border-b-background'
                  : 'text-muted hover:text-foreground'
              }`}
            >
              {cat}
              <span className="ml-1.5 text-muted font-normal">
                {catAssessed}/{catResponses.length}
              </span>
            </button>
          );
        })}
      </div>

      <div className="space-y-1">
        <p className="text-xs text-muted">{CATEGORY_LABELS[activeCategory]}</p>
      </div>

      <div className="space-y-2">
        {byCategory[activeCategory].map((r) => (
          <ControlRow
            key={r.control_id}
            response={r}
            documents={documents}
            disabled={isReadOnly}
            onSave={handleSave}
          />
        ))}
      </div>
    </div>
  );
}
