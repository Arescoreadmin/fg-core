'use client';

import { useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardCopy,
  HelpCircle,
  ShieldCheck,
  ShieldOff,
  XCircle,
} from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ProvenanceValidationSourceSummary {
  source_id?: string | null;
  chunk_id?: string | null;
  chunk_index?: number | null;
  included_in_prompt?: boolean;
}

export interface ProvenanceValidationCitation {
  citation_id?: string | null;
  source_id?: string | null;
  chunk_id?: string | null;
  document_id?: string | null;
  corpus_id?: string | null;
  status: 'valid' | 'invalid' | 'rejected' | 'unavailable' | 'unknown';
  reason_code?: string | null;
  retrieved?: boolean | null;
  included_in_prompt?: boolean | null;
  cited?: boolean | null;
}

export interface ProvenanceValidationData {
  provenance_status?: string | null;
  used_rag?: boolean;
  context_count?: number | null;
  // prompt-included chunk IDs (from API: source_chunk_ids)
  source_chunk_ids?: string[] | null;
  // all retrieved chunk IDs — future API field
  retrieved_source_chunk_ids?: string[] | null;
  source_summaries?: ProvenanceValidationSourceSummary[] | null;
  // validated citation IDs — future API field
  citation_source_ids?: string[] | null;
  // rejected citation IDs — future API field
  invalid_source_ids?: string[] | null;
  // structured per-citation data — future API field
  citations?: ProvenanceValidationCitation[] | null;
  retrieval_trace_id?: string | null;
  retrieval_strategy?: string | null;
  lexical_fallback?: boolean;
}

export interface ProvenanceValidationPanelProps {
  provenance?: ProvenanceValidationData | null;
  requestId?: string | null;
  correlationId?: string | null;
  apiFailure?: boolean;
}

// ─── Provenance status config ─────────────────────────────────────────────────

type ProvenanceState = 'valid' | 'invalid' | 'no_context' | 'unavailable' | 'unknown';

interface StatusConfig {
  state: ProvenanceState;
  label: string;
  detail: string;
  textClass: string;
  Icon: React.ComponentType<{ className?: string }>;
}

const STATUS_CONFIG: Record<string, StatusConfig> = {
  PROVENANCE_VALID: {
    state: 'valid',
    label: 'Provenance Valid',
    detail: 'All cited sources were retrieved and included in the prompt context.',
    textClass: 'text-success',
    Icon: CheckCircle2,
  },
  PROVENANCE_SOURCE_NOT_RETRIEVED: {
    state: 'invalid',
    label: 'Provenance Invalid — Source Not Retrieved',
    detail: 'Citation rejected: source was not retrieved for this request.',
    textClass: 'text-danger',
    Icon: XCircle,
  },
  PROVENANCE_SOURCE_NOT_IN_PROMPT: {
    state: 'invalid',
    label: 'Provenance Invalid — Source Not In Prompt',
    detail: 'Citation rejected: source was retrieved but not included in the prompt context.',
    textClass: 'text-danger',
    Icon: XCircle,
  },
  PROVENANCE_NO_CONTEXT_AVAILABLE: {
    state: 'no_context',
    label: 'No Context Available',
    detail: 'No relevant context was available. Answer was generated without retrieval evidence.',
    textClass: 'text-muted',
    Icon: HelpCircle,
  },
};

function getStatusConfig(status: string | null | undefined): StatusConfig {
  if (status != null && Object.prototype.hasOwnProperty.call(STATUS_CONFIG, status)) {
    return STATUS_CONFIG[status];
  }
  if (status != null) {
    return {
      state: 'unknown',
      label: `Unknown status: ${status}`,
      detail: 'Provenance status is unrecognized. Treat this response with caution.',
      textClass: 'text-warning',
      Icon: AlertCircle,
    };
  }
  return {
    state: 'unavailable',
    label: 'Provenance Unavailable',
    detail: 'Provenance validation data was not returned for this response.',
    textClass: 'text-muted',
    Icon: HelpCircle,
  };
}

// ─── Rejection reason mapping ─────────────────────────────────────────────────

interface RejectionReason {
  short: string;
  detail: string;
}

const REJECTION_REASONS: Record<string, RejectionReason> = {
  PROVENANCE_SOURCE_NOT_RETRIEVED: {
    short: 'Source not retrieved',
    detail:
      'Source was not retrieved for this request. No retrieval evidence exists for this citation. The answer has been suppressed.',
  },
  PROVENANCE_SOURCE_NOT_IN_PROMPT: {
    short: 'Source not in prompt context',
    detail:
      'Source was retrieved but not included in the prompt context. The citation refers to evidence filtered before generation. The answer has been suppressed.',
  },
  PROVENANCE_NO_CONTEXT_AVAILABLE: {
    short: 'No context available',
    detail:
      'No relevant context was available for this request. Answer was generated without retrieval evidence.',
  },
};

function getRejectionReason(code: string | null | undefined): RejectionReason | null {
  if (code == null) return null;
  return (
    REJECTION_REASONS[code] ?? {
      short: 'Unknown rejection reason',
      detail: `Rejection reason code: ${code}. Treat with caution.`,
    }
  );
}

// ─── Trust level derivation ───────────────────────────────────────────────────

// Trust level is derived conservatively from provenance status.
// Derivation rules (documented for test verification):
//   PROVENANCE_VALID                  → trusted
//   PROVENANCE_NO_CONTEXT_AVAILABLE   → no_context (not a trust failure; answer had no citations)
//   PROVENANCE_SOURCE_NOT_RETRIEVED   → untrusted (citation was fabricated — never retrieved)
//   PROVENANCE_SOURCE_NOT_IN_PROMPT   → untrusted (retrieved but filtered from prompt)
//   null / unrecognized               → unavailable
export type TrustLevel = 'trusted' | 'untrusted' | 'no_context' | 'unavailable';

interface TrustConfig {
  label: string;
  detail: string;
  textClass: string;
  Icon: React.ComponentType<{ className?: string }>;
}

const TRUST_CONFIG: Record<TrustLevel, TrustConfig> = {
  trusted: {
    label: 'Trusted',
    detail: 'All provenance checks passed. Sources are verified.',
    textClass: 'text-success',
    Icon: ShieldCheck,
  },
  untrusted: {
    label: 'Untrusted',
    detail: 'Provenance validation failed. Do not treat citations as verified.',
    textClass: 'text-danger',
    Icon: ShieldOff,
  },
  no_context: {
    label: 'No Context',
    detail: 'Answer was generated without retrieval context. No source claims to validate.',
    textClass: 'text-muted',
    Icon: HelpCircle,
  },
  unavailable: {
    label: 'Unavailable',
    detail: 'Provenance trust status could not be determined.',
    textClass: 'text-muted',
    Icon: HelpCircle,
  },
};

export function deriveTrustLevel(status: string | null | undefined): TrustLevel {
  if (status == null) return 'unavailable';
  if (status === 'PROVENANCE_VALID') return 'trusted';
  if (status === 'PROVENANCE_NO_CONTEXT_AVAILABLE') return 'no_context';
  if (
    status === 'PROVENANCE_SOURCE_NOT_RETRIEVED' ||
    status === 'PROVENANCE_SOURCE_NOT_IN_PROMPT'
  ) {
    return 'untrusted';
  }
  // Unknown status codes are conservatively mapped to unavailable
  return 'unavailable';
}

// ─── Export-safe summary ──────────────────────────────────────────────────────

// Safe export payload: no raw vectors, no raw prompts, no raw chunk text,
// no provider payloads, no credentials.
export interface ProvenanceExportSummary {
  provenance_status: string | null;
  trust_level: TrustLevel;
  citation_count: number;
  invalid_citation_count: number;
  prompt_included_chunk_count: number;
  retrieved_chunk_count: number;
  used_rag: boolean | null;
  context_count: number | null;
  retrieval_trace_id: string | null;
  retrieval_strategy: string | null;
  export_safe: true;
  generated_at: string;
}

export function buildProvenanceExportSummary(
  data: ProvenanceValidationData,
): ProvenanceExportSummary {
  const summaries = data.source_summaries ?? [];
  const includedCount = summaries.filter(s => s.included_in_prompt === true).length;

  // Derive citation counts from explicit fields when available; fall back to
  // source_summaries + provenance_status for the current _rag_provenance_ui_metadata
  // payload which does not yet include citation_source_ids or invalid_source_ids.
  const hasExplicitCitationData =
    data.citation_source_ids != null || data.invalid_source_ids != null;

  let citationCount: number;
  let invalidCitationCount: number;

  if (hasExplicitCitationData) {
    citationCount = (data.citation_source_ids ?? []).length;
    invalidCitationCount = (data.invalid_source_ids ?? []).length;
  } else {
    const status = data.provenance_status;
    if (status === 'PROVENANCE_VALID') {
      // Prompt-included chunks are the validated citations on a PROVENANCE_VALID response
      citationCount = includedCount;
      invalidCitationCount = 0;
    } else if (status === 'PROVENANCE_SOURCE_NOT_IN_PROMPT') {
      // Not-included chunks are the invalid ones; included chunks would have been valid
      const notIncludedCount = summaries.filter(s => s.included_in_prompt === false).length;
      citationCount = includedCount;
      invalidCitationCount = notIncludedCount;
    } else {
      // For NOT_RETRIEVED the invalid source was never retrieved so it is absent from
      // summaries; cannot derive a count without the future citation_source_ids field.
      citationCount = 0;
      invalidCitationCount = 0;
    }
  }

  return {
    provenance_status: data.provenance_status ?? null,
    trust_level: deriveTrustLevel(data.provenance_status),
    citation_count: citationCount,
    invalid_citation_count: invalidCitationCount,
    prompt_included_chunk_count: includedCount,
    retrieved_chunk_count: summaries.length,
    used_rag: data.used_rag ?? null,
    context_count: data.context_count ?? null,
    retrieval_trace_id: data.retrieval_trace_id ?? null,
    retrieval_strategy: data.retrieval_strategy ?? null,
    export_safe: true,
    generated_at: new Date().toISOString(),
  };
}

// ─── Citation ordering ────────────────────────────────────────────────────────

// Deterministic ordering: invalid/rejected first, then valid, then unknown/unavailable
// Tie-break within a group: citation_id → chunk_id → source_id → document_id (all ascending)
const CITATION_STATUS_ORDER: Record<ProvenanceValidationCitation['status'], number> = {
  invalid: 0,
  rejected: 1,
  valid: 2,
  unknown: 3,
  unavailable: 4,
};

export function sortCitations(
  citations: ProvenanceValidationCitation[],
): ProvenanceValidationCitation[] {
  return [...citations].sort((a, b) => {
    const statusDiff =
      (CITATION_STATUS_ORDER[a.status] ?? 5) - (CITATION_STATUS_ORDER[b.status] ?? 5);
    if (statusDiff !== 0) return statusDiff;
    const aKey = [a.citation_id, a.chunk_id, a.source_id, a.document_id]
      .filter(Boolean)
      .join('|');
    const bKey = [b.citation_id, b.chunk_id, b.source_id, b.document_id]
      .filter(Boolean)
      .join('|');
    return aKey.localeCompare(bKey);
  });
}

// Derive structured citations from raw provenance data. Three-tier resolution:
//   1. Explicit structured citations prop (richer future API contract)
//   2. Explicit citation_source_ids / invalid_source_ids (future API extension)
//   3. Fallback: source_summaries + provenance_status (current API payload from
//      _rag_provenance_ui_metadata which has included_in_prompt per chunk but no
//      citation_source_ids or invalid_source_ids)
export function deriveCitationsFromProvenance(
  data: ProvenanceValidationData,
): ProvenanceValidationCitation[] {
  // Tier 1: explicit structured citations
  if (data.citations != null && data.citations.length > 0) {
    return sortCitations(data.citations);
  }

  // Tier 2: explicit ID lists
  if (data.citation_source_ids != null || data.invalid_source_ids != null) {
    const result: ProvenanceValidationCitation[] = [];
    const invalidSet = new Set(data.invalid_source_ids ?? []);
    const citationIds = data.citation_source_ids ?? [];

    for (const id of citationIds) {
      result.push({
        citation_id: id,
        source_id: id,
        status: invalidSet.has(id) ? 'invalid' : 'valid',
        retrieved: !invalidSet.has(id) || data.provenance_status !== 'PROVENANCE_SOURCE_NOT_RETRIEVED',
        included_in_prompt:
          !invalidSet.has(id) || data.provenance_status !== 'PROVENANCE_SOURCE_NOT_IN_PROMPT',
      });
    }
    for (const id of data.invalid_source_ids ?? []) {
      if (!citationIds.includes(id)) {
        result.push({
          citation_id: id,
          source_id: id,
          status: 'invalid',
          reason_code: data.provenance_status,
          retrieved: data.provenance_status !== 'PROVENANCE_SOURCE_NOT_RETRIEVED',
          included_in_prompt: false,
        });
      }
    }
    return sortCitations(result);
  }

  // Tier 3: fallback — derive from source_summaries + provenance_status
  const summaries = (data.source_summaries ?? []).filter(
    (s): s is ProvenanceValidationSourceSummary => s != null && typeof s === 'object',
  );
  if (summaries.length === 0) return [];

  const status = data.provenance_status;
  return sortCitations(
    summaries.map(s => {
      const id = s.chunk_id ?? s.source_id ?? null;
      if (status === 'PROVENANCE_VALID') {
        // All retrieved chunks are validated citations on a clean provenance result
        return {
          citation_id: id,
          source_id: s.source_id ?? null,
          chunk_id: s.chunk_id ?? null,
          status: 'valid' as const,
          retrieved: true,
          included_in_prompt: s.included_in_prompt ?? null,
          cited: s.included_in_prompt === true,
        };
      }
      if (status === 'PROVENANCE_SOURCE_NOT_IN_PROMPT' && s.included_in_prompt === false) {
        // This chunk was retrieved but not included in the prompt — the cause of rejection
        return {
          citation_id: id,
          source_id: s.source_id ?? null,
          chunk_id: s.chunk_id ?? null,
          status: 'invalid' as const,
          reason_code: status,
          retrieved: true,
          included_in_prompt: false,
          cited: false,
        };
      }
      // NOT_RETRIEVED: the invalid source was never retrieved so it is absent from
      // source_summaries; show present retrieved chunks as unavailable in this context.
      // NOT_IN_PROMPT (included chunks): retrieved+included but overall validation failed.
      return {
        citation_id: id,
        source_id: s.source_id ?? null,
        chunk_id: s.chunk_id ?? null,
        status: 'unavailable' as const,
        retrieved: true,
        included_in_prompt: s.included_in_prompt ?? null,
        cited: false,
      };
    }),
  );
}

// ─── Collapsible section ──────────────────────────────────────────────────────

function CollapsibleSection({
  id,
  title,
  defaultOpen = true,
  children,
}: {
  id: string;
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const contentId = `${id}-content`;
  return (
    <section aria-label={id}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={contentId}
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-center justify-between py-1.5 text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-primary"
      >
        <h3 className="text-[10px] font-semibold uppercase tracking-widest text-muted/60">
          {title}
        </h3>
        {open ? (
          <ChevronDown className="h-3 w-3 text-muted/40" aria-hidden="true" />
        ) : (
          <ChevronRight className="h-3 w-3 text-muted/40" aria-hidden="true" />
        )}
      </button>
      <div id={contentId} hidden={!open}>
        {children}
      </div>
    </section>
  );
}

// ─── Citation card ────────────────────────────────────────────────────────────

function CitationCard({
  citation,
  fallbackReasonCode,
}: {
  citation: ProvenanceValidationCitation;
  fallbackReasonCode?: string | null;
}) {
  const isInvalid = citation.status === 'invalid' || citation.status === 'rejected';
  const reason = isInvalid
    ? getRejectionReason(citation.reason_code ?? fallbackReasonCode)
    : null;
  const displayId =
    (typeof citation.citation_id === 'string' && citation.citation_id.length > 0
      ? citation.citation_id
      : null) ??
    (typeof citation.chunk_id === 'string' && citation.chunk_id.length > 0
      ? citation.chunk_id
      : null) ??
    (typeof citation.source_id === 'string' && citation.source_id.length > 0
      ? citation.source_id
      : null) ??
    'Unknown ID';

  return (
    <li
      className={`rounded-lg border px-3 py-2 ${
        isInvalid
          ? 'border-danger/30 bg-danger/5'
          : citation.status === 'valid'
          ? 'border-success/30 bg-success/5'
          : 'border-border bg-surface-2'
      }`}
      aria-label={`citation-card-${citation.status}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            {isInvalid ? (
              <XCircle className="h-3 w-3 shrink-0 text-danger" aria-hidden="true" />
            ) : citation.status === 'valid' ? (
              <CheckCircle2 className="h-3 w-3 shrink-0 text-success" aria-hidden="true" />
            ) : (
              <HelpCircle className="h-3 w-3 shrink-0 text-muted/50" aria-hidden="true" />
            )}
            <span
              className={`text-xs font-medium ${
                isInvalid
                  ? 'text-danger'
                  : citation.status === 'valid'
                  ? 'text-success'
                  : 'text-muted'
              }`}
              aria-label="citation-validation-status"
            >
              {isInvalid ? 'Rejected' : citation.status === 'valid' ? 'Valid' : 'Unavailable'}
            </span>
          </div>
          <p
            className="mt-0.5 truncate font-mono text-[10px] text-muted/70"
            aria-label="citation-id"
          >
            {displayId}
          </p>
          {citation.source_id != null &&
            citation.source_id !== displayId &&
            citation.source_id.length > 0 && (
              <p className="truncate font-mono text-[10px] text-muted/50">
                src: {citation.source_id}
              </p>
            )}
          {citation.chunk_id != null &&
            citation.chunk_id !== displayId &&
            citation.chunk_id.length > 0 && (
              <p className="truncate font-mono text-[10px] text-muted/50">
                chunk: {citation.chunk_id}
              </p>
            )}
          {citation.document_id != null && citation.document_id.length > 0 && (
            <p className="truncate font-mono text-[10px] text-muted/50">
              doc: {citation.document_id}
            </p>
          )}
          {citation.corpus_id != null && citation.corpus_id.length > 0 && (
            <p className="truncate font-mono text-[10px] text-muted/50">
              corpus: {citation.corpus_id}
            </p>
          )}
        </div>
        <div className="shrink-0 space-y-0.5 text-right">
          {citation.retrieved != null && (
            <p
              className={`text-[9px] font-medium ${
                citation.retrieved ? 'text-success' : 'text-danger'
              }`}
              aria-label="citation-retrieved-state"
            >
              {citation.retrieved ? 'Retrieved' : 'Not retrieved'}
            </p>
          )}
          {citation.included_in_prompt != null && (
            <p
              className={`text-[9px] font-medium ${
                citation.included_in_prompt ? 'text-success' : 'text-warning'
              }`}
              aria-label="citation-included-state"
            >
              {citation.included_in_prompt ? 'In prompt' : 'Not in prompt'}
            </p>
          )}
          {citation.cited != null && (
            <p
              className={`text-[9px] font-medium ${
                citation.cited ? 'text-primary' : 'text-muted/50'
              }`}
              aria-label="citation-cited-state"
            >
              {citation.cited ? 'Cited' : 'Not cited'}
            </p>
          )}
        </div>
      </div>

      {isInvalid && reason != null && (
        <div className="mt-2 border-t border-danger/20 pt-2">
          <p className="text-[9px] font-semibold uppercase tracking-wide text-danger/70">
            Rejection Reason
          </p>
          {(citation.reason_code ?? fallbackReasonCode) != null && (
            <p
              className="font-mono text-[9px] text-muted/60"
              aria-label="rejection-reason-code"
            >
              {citation.reason_code ?? fallbackReasonCode}
            </p>
          )}
          <p className="mt-0.5 text-[10px] text-danger/80" aria-label="rejection-reason-detail">
            {reason.detail}
          </p>
        </div>
      )}
    </li>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export function ProvenanceValidationPanel({
  provenance,
  requestId,
  correlationId,
  apiFailure = false,
}: ProvenanceValidationPanelProps) {
  const [exportCopied, setExportCopied] = useState<'idle' | 'ok' | 'fail'>('idle');

  async function handleExportCopy() {
    if (provenance == null) return;
    const summary = buildProvenanceExportSummary(provenance);
    const text = JSON.stringify(summary, null, 2);
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(text);
        setExportCopied('ok');
      } catch {
        setExportCopied('fail');
      }
    } else {
      setExportCopied('fail');
    }
    setTimeout(() => setExportCopied('idle'), 2000);
  }

  if (apiFailure) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="provenance-validation-api-failure"
      >
        <XCircle className="h-7 w-7 text-danger/40" aria-hidden="true" />
        <p className="text-xs font-medium text-muted">Provenance validation unavailable</p>
        <p className="max-w-[220px] text-[10px] text-muted/50">
          Provenance data could not be loaded.
        </p>
      </div>
    );
  }

  if (provenance == null) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="provenance-validation-empty"
      >
        <ShieldCheck className="h-7 w-7 text-muted/20" aria-hidden="true" />
        <p className="text-xs text-muted">Provenance validation will appear here</p>
        <p className="max-w-[220px] text-[10px] text-muted/50">
          Submit a query to see citation validation results.
        </p>
      </div>
    );
  }

  const data = provenance;
  const status = data.provenance_status;
  const statusCfg = getStatusConfig(status);
  const trustLevel = deriveTrustLevel(status);
  const trustCfg = TRUST_CONFIG[trustLevel];
  const TrustIcon = trustCfg.Icon;
  const StatusIcon = statusCfg.Icon;

  const isInvalidState = statusCfg.state === 'invalid' || statusCfg.state === 'unknown';
  const isNoContext = statusCfg.state === 'no_context';

  const summaries = (data.source_summaries ?? []).filter(
    (s): s is ProvenanceValidationSourceSummary => s != null && typeof s === 'object',
  );
  const retrievedCount = summaries.length;
  const includedCount = summaries.filter(s => s.included_in_prompt === true).length;
  const notIncludedCount = summaries.filter(s => s.included_in_prompt === false).length;

  const citedIds = new Set(data.citation_source_ids ?? []);
  const citedChunkCount = summaries.filter(
    s => s.chunk_id != null && citedIds.has(s.chunk_id),
  ).length;

  const rejectionReason = isInvalidState ? getRejectionReason(status) : null;

  const citations = deriveCitationsFromProvenance(data);
  const invalidCitations = citations.filter(
    c => c.status === 'invalid' || c.status === 'rejected',
  );
  const validCitations = citations.filter(c => c.status === 'valid');
  const unknownCitations = citations.filter(
    c => c.status !== 'invalid' && c.status !== 'rejected' && c.status !== 'valid',
  );

  const exportSummary = buildProvenanceExportSummary(data);

  return (
    <div className="space-y-4" aria-label="provenance-validation-panel">

      {/* Validation status header */}
      <section aria-label="provenance-validation-status-section">
        <div
          className={`flex items-start gap-3 rounded-lg border px-3 py-3 ${
            isInvalidState
              ? 'border-danger/30 bg-danger/5'
              : isNoContext
              ? 'border-border bg-surface-2'
              : statusCfg.state === 'valid'
              ? 'border-success/30 bg-success/5'
              : 'border-border bg-surface-2'
          }`}
          role={isInvalidState ? 'alert' : undefined}
          aria-label="provenance-validation-state"
        >
          <StatusIcon
            className={`mt-0.5 h-4 w-4 shrink-0 ${statusCfg.textClass}`}
            aria-hidden="true"
          />
          <div className="min-w-0 flex-1">
            <p
              className={`text-xs font-semibold ${statusCfg.textClass}`}
              aria-label="provenance-status-label"
            >
              {statusCfg.label}
            </p>
            <p
              className="mt-0.5 text-[10px] text-muted/70"
              aria-label="provenance-status-detail"
            >
              {statusCfg.detail}
            </p>
            {status != null && (
              <p
                className="mt-0.5 font-mono text-[9px] text-muted/50"
                aria-label="provenance-reason-code"
              >
                {status}
              </p>
            )}
          </div>
        </div>
      </section>

      {/* Rejection reason (when invalid) */}
      {isInvalidState && rejectionReason != null && (
        <section aria-label="provenance-rejection-reason-section">
          <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted/60">
            Rejection Reason
          </h3>
          <div
            className="rounded-lg border border-danger/20 bg-danger/5 px-3 py-2"
            aria-label="rejection-reason-banner"
          >
            <p
              className="text-xs font-medium text-danger"
              aria-label="rejection-reason-short"
            >
              {rejectionReason.short}
            </p>
            <p
              className="mt-1 text-[10px] text-danger/80"
              aria-label="rejection-reason-explanation"
            >
              {rejectionReason.detail}
            </p>
            {status != null && (
              <p
                className="mt-1 font-mono text-[9px] text-muted/50"
                aria-label="rejection-reason-code"
              >
                Reason code: {status}
              </p>
            )}
          </div>
        </section>
      )}

      {/* No-context explicit state */}
      {isNoContext && (
        <section aria-label="provenance-no-context-section">
          <div
            className="rounded-lg border border-border bg-surface-2 px-3 py-2"
            aria-label="no-context-provenance-state"
          >
            <p className="text-xs font-medium text-foreground">No Retrieval Context</p>
            <p className="mt-0.5 text-[10px] text-muted/70">
              Answer was generated without retrieved evidence. No citation claims should be trusted.
            </p>
            <p className="mt-1 text-[10px] text-warning" aria-label="no-context-export-warning">
              Export-safe warning: citations, if present, are not provenance-validated.
            </p>
          </div>
        </section>
      )}

      {/* Trust status */}
      <CollapsibleSection id="provenance-trust-status-section" title="Trust Status">
        <div className="pt-1 space-y-1">
          <div className="flex items-center gap-1.5">
            <TrustIcon
              className={`h-3.5 w-3.5 shrink-0 ${trustCfg.textClass}`}
              aria-hidden="true"
            />
            <span
              className={`text-xs font-medium ${trustCfg.textClass}`}
              aria-label="provenance-trust-level"
            >
              {trustCfg.label}
            </span>
          </div>
          <p
            className="text-[10px] text-muted/60"
            aria-label="provenance-trust-detail"
          >
            {trustCfg.detail}
          </p>
          {!isNoContext && (
            <p className="text-[9px] text-muted/40" aria-label="trust-derivation-source">
              Derived from: {status ?? 'no status code'}
            </p>
          )}
        </div>
      </CollapsibleSection>

      {/* Citation validation grouped by status */}
      {citations.length > 0 ? (
        <CollapsibleSection
          id="citation-validation-section"
          title={`Citation Validation (${citations.length})`}
        >
          <div className="pt-1 space-y-3">
            {invalidCitations.length > 0 && (
              <div aria-label="invalid-citations-group">
                <p className="mb-1.5 text-[9px] font-semibold uppercase tracking-wide text-danger/70">
                  Rejected ({invalidCitations.length})
                </p>
                <ul className="space-y-1.5" aria-label="invalid-citations-list">
                  {invalidCitations.map((c, i) => (
                    <CitationCard
                      key={c.citation_id ?? c.chunk_id ?? c.source_id ?? i}
                      citation={c}
                      fallbackReasonCode={status}
                    />
                  ))}
                </ul>
              </div>
            )}

            {validCitations.length > 0 && (
              <div aria-label="valid-citations-group">
                <p className="mb-1.5 text-[9px] font-semibold uppercase tracking-wide text-success/70">
                  Valid ({validCitations.length})
                </p>
                <ul className="space-y-1.5" aria-label="valid-citations-list">
                  {validCitations.map((c, i) => (
                    <CitationCard
                      key={c.citation_id ?? c.chunk_id ?? c.source_id ?? i}
                      citation={c}
                      fallbackReasonCode={status}
                    />
                  ))}
                </ul>
              </div>
            )}

            {unknownCitations.length > 0 && (
              <div aria-label="unavailable-citations-group">
                <p className="mb-1.5 text-[9px] font-semibold uppercase tracking-wide text-muted/50">
                  Unavailable ({unknownCitations.length})
                </p>
                <ul className="space-y-1.5" aria-label="unavailable-citations-list">
                  {unknownCitations.map((c, i) => (
                    <CitationCard
                      key={c.citation_id ?? c.chunk_id ?? c.source_id ?? i}
                      citation={c}
                      fallbackReasonCode={status}
                    />
                  ))}
                </ul>
              </div>
            )}
          </div>
        </CollapsibleSection>
      ) : (
        <div
          aria-label={
            isNoContext ? 'no-citations-no-context-state' : 'no-citation-detail-state'
          }
        >
          <p className="text-[10px] text-muted/50">
            {isNoContext
              ? 'No citations to validate — no context was available.'
              : 'No citation detail available for this response.'}
          </p>
        </div>
      )}

      {/* Chunk breakdown: retrieved / prompt-included / cited */}
      {!isNoContext && (
        <CollapsibleSection id="chunk-breakdown-section" title="Chunk Breakdown">
          <div className="pt-1 space-y-2">
            <p className="text-[9px] text-muted/50" aria-label="chunk-distinction-note">
              Retrieved ≠ Included in prompt. Included ≠ Cited. Cited ≠ Valid.
            </p>
            <dl
              className="grid grid-cols-3 gap-2 text-center"
              aria-label="chunk-pipeline-counts"
            >
              <div>
                <dt className="text-[9px] uppercase tracking-wide text-muted/50">Retrieved</dt>
                <dd
                  className="font-mono text-sm font-semibold text-foreground"
                  aria-label="retrieved-chunk-count"
                >
                  {retrievedCount > 0 ? retrievedCount : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-[9px] uppercase tracking-wide text-muted/50">In Prompt</dt>
                <dd
                  className="font-mono text-sm font-semibold text-success"
                  aria-label="included-chunk-count"
                >
                  {includedCount > 0 ? includedCount : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-[9px] uppercase tracking-wide text-muted/50">Cited</dt>
                <dd
                  className="font-mono text-sm font-semibold text-primary"
                  aria-label="cited-chunk-count"
                >
                  {citedChunkCount > 0 ? citedChunkCount : '—'}
                </dd>
              </div>
            </dl>

            {notIncludedCount > 0 && (
              <p
                className="text-[10px] text-warning"
                aria-label="not-included-chunk-warning"
              >
                {notIncludedCount} chunk{notIncludedCount !== 1 ? 's' : ''} retrieved but not included in prompt context.
              </p>
            )}

            {summaries.length > 0 ? (
              <div className="overflow-x-auto" aria-label="chunk-breakdown-table">
                <table
                  className="w-full min-w-[300px] text-left"
                  aria-label="chunk-pipeline-table"
                >
                  <thead>
                    <tr className="border-b border-border">
                      <th
                        scope="col"
                        className="pb-1 pr-2 text-[9px] uppercase tracking-wide text-muted/60"
                      >
                        Chunk
                      </th>
                      <th
                        scope="col"
                        className="pb-1 pr-2 text-[9px] uppercase tracking-wide text-muted/60"
                      >
                        Retrieved
                      </th>
                      <th
                        scope="col"
                        className="pb-1 pr-2 text-[9px] uppercase tracking-wide text-muted/60"
                      >
                        In Prompt
                      </th>
                      <th
                        scope="col"
                        className="pb-1 text-[9px] uppercase tracking-wide text-muted/60"
                      >
                        Cited
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {summaries.map((s, i) => {
                      const isCited = s.chunk_id != null && citedIds.has(s.chunk_id);
                      return (
                        <tr
                          key={s.chunk_id ?? i}
                          className="border-b border-border/40"
                          aria-label="chunk-breakdown-row"
                        >
                          <td className="max-w-[80px] py-1 pr-2">
                            <span
                              className="block truncate font-mono text-[9px] text-muted/70"
                              aria-label="chunk-id-cell"
                            >
                              {s.chunk_id ?? '—'}
                            </span>
                          </td>
                          <td className="py-1 pr-2">
                            <span
                              className="text-[9px] font-medium text-success"
                              aria-label="retrieved-cell"
                            >
                              Yes
                            </span>
                          </td>
                          <td className="py-1 pr-2">
                            {s.included_in_prompt === true ? (
                              <span
                                className="text-[9px] font-medium text-success"
                                aria-label="included-cell"
                              >
                                Yes
                              </span>
                            ) : s.included_in_prompt === false ? (
                              <span
                                className="text-[9px] font-medium text-warning"
                                aria-label="not-included-cell"
                              >
                                No
                              </span>
                            ) : (
                              <span
                                className="text-[9px] text-muted/40"
                                aria-label="included-unknown-cell"
                              >
                                —
                              </span>
                            )}
                          </td>
                          <td className="py-1">
                            {isCited ? (
                              <span
                                className="text-[9px] font-medium text-primary"
                                aria-label="cited-cell"
                              >
                                Yes
                              </span>
                            ) : (
                              <span
                                className="text-[9px] text-muted/40"
                                aria-label="not-cited-cell"
                              >
                                —
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <p
                className="text-[10px] text-muted/50"
                aria-label="no-chunk-detail-state"
              >
                No chunk detail available.
              </p>
            )}
          </div>
        </CollapsibleSection>
      )}

      {/* Export-safe summary */}
      <CollapsibleSection
        id="export-safe-summary-section"
        title="Export-Safe Summary"
        defaultOpen={false}
      >
        <div className="pt-1 space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-[10px] text-muted/60">
              Safe subset only — no raw vectors, prompts, or credentials.
            </p>
            <button
              type="button"
              onClick={handleExportCopy}
              className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] text-muted/60 hover:text-foreground focus:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              aria-label="Copy export summary to clipboard"
            >
              <ClipboardCopy className="h-2.5 w-2.5" aria-hidden="true" />
              {exportCopied === 'ok'
                ? 'Copied'
                : exportCopied === 'fail'
                ? 'Failed'
                : 'Copy'}
            </button>
          </div>
          <p
            className="text-[9px] font-medium text-success"
            aria-label="export-safe-indicator"
          >
            Export safe — no credentials, no vectors, no raw prompts
          </p>
          <dl className="space-y-1" aria-label="export-summary-fields">
            <div className="flex justify-between gap-2">
              <dt className="shrink-0 text-[9px] text-muted/50">Status</dt>
              <dd className="truncate font-mono text-[9px] text-foreground">
                {exportSummary.provenance_status ?? 'unavailable'}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="shrink-0 text-[9px] text-muted/50">Trust Level</dt>
              <dd className={`text-[9px] font-medium ${trustCfg.textClass}`}>
                {exportSummary.trust_level}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="shrink-0 text-[9px] text-muted/50">Retrieved chunks</dt>
              <dd className="font-mono text-[9px] text-foreground">
                {exportSummary.retrieved_chunk_count}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="shrink-0 text-[9px] text-muted/50">Prompt-included chunks</dt>
              <dd className="font-mono text-[9px] text-foreground">
                {exportSummary.prompt_included_chunk_count}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="shrink-0 text-[9px] text-muted/50">Citations</dt>
              <dd className="font-mono text-[9px] text-foreground">
                {exportSummary.citation_count}
              </dd>
            </div>
            {exportSummary.retrieval_strategy != null && (
              <div className="flex justify-between gap-2">
                <dt className="shrink-0 text-[9px] text-muted/50">Strategy</dt>
                <dd className="truncate font-mono text-[9px] text-muted/60">
                  {exportSummary.retrieval_strategy}
                </dd>
              </div>
            )}
            {exportSummary.retrieval_trace_id != null && (
              <div className="flex justify-between gap-2">
                <dt className="shrink-0 text-[9px] text-muted/50">Trace ID</dt>
                <dd className="truncate font-mono text-[9px] text-muted/60">
                  {exportSummary.retrieval_trace_id}
                </dd>
              </div>
            )}
            {requestId != null && (
              <div className="flex justify-between gap-2">
                <dt className="shrink-0 text-[9px] text-muted/50">Request ID</dt>
                <dd className="truncate font-mono text-[9px] text-muted/60">{requestId}</dd>
              </div>
            )}
            {correlationId != null && (
              <div className="flex justify-between gap-2">
                <dt className="shrink-0 text-[9px] text-muted/50">Correlation ID</dt>
                <dd className="truncate font-mono text-[9px] text-muted/60">{correlationId}</dd>
              </div>
            )}
          </dl>
        </div>
      </CollapsibleSection>

      {/* Future-ready placeholders — collapsed by default, clearly marked not yet available */}
      <CollapsibleSection
        id="provenance-future-capabilities-section"
        title="Future Capabilities"
        defaultOpen={false}
      >
        <ul className="mt-1.5 space-y-1.5" aria-label="provenance-future-placeholders">
          {[
            {
              label: 'Evidence graph',
              detail: 'Visual answer-to-source mapping — not yet available',
            },
            {
              label: 'Answer-to-source mapping',
              detail: 'Line-level citation attribution — not yet available',
            },
            {
              label: 'Legal review mode',
              detail: 'Formal legal/compliance review workflow — not yet available',
            },
            {
              label: 'Citation lineage',
              detail: 'Full provenance chain from chunk to answer — not yet available',
            },
            {
              label: 'Exportable legal packet',
              detail: 'Structured audit export for legal review — not yet available',
            },
          ].map(({ label, detail }) => (
            <li
              key={label}
              className="rounded border border-dashed border-border px-2.5 py-2 text-[10px] opacity-60"
              aria-label="provenance-future-placeholder"
            >
              <p className="font-medium text-muted">{label}</p>
              <p className="text-[9px] text-muted/50">{detail}</p>
            </li>
          ))}
        </ul>
      </CollapsibleSection>

    </div>
  );
}
