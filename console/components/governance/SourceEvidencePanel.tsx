'use client';

import { useState } from 'react';
import {
  AlertCircle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  HelpCircle,
  XCircle,
} from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SourceSummaryItem {
  source_id?: string | null;
  chunk_id?: string | null;
  chunk_index?: number | null;
  included_in_prompt?: boolean;
  phi_sensitivity_level?: string | null;
  phi_types?: string[] | null;
}

export interface SourceEvidenceData {
  used_rag?: boolean;
  context_count?: number | null;
  source_chunk_ids?: string[] | null;
  source_summaries?: SourceSummaryItem[] | null;
  confidence?: number | null;
  confidence_reason?: string | null;
  why_this_chunk?: Record<string, unknown> | null;
  retrieval_strategy?: string | null;
  provenance_status?: string | null;
  retrieval_trace_id?: string | null;
  lexical_fallback?: boolean;
}

export interface SourceCitation {
  index: number;
  source: string;
  excerpt?: string;
  url?: string;
}

export interface SourceEvidencePanelProps {
  provenance?: SourceEvidenceData | null;
  citations?: SourceCitation[] | null;
  apiFailure?: boolean;
}

// ─── Safe extraction helpers ──────────────────────────────────────────────────

function safeNum(val: unknown): number | null {
  return typeof val === 'number' && isFinite(val) ? val : null;
}

function safeStr(val: unknown): string | null {
  return typeof val === 'string' && val.length > 0 ? val : null;
}

function safeStrArr(val: unknown): string[] | null {
  if (!Array.isArray(val)) return null;
  const r = val.filter((x): x is string => typeof x === 'string' && x.length > 0);
  return r.length > 0 ? r : null;
}

function parseWhyEntry(raw: unknown): WhyEntry {
  if (raw === null || typeof raw !== 'object') return {};
  const o = raw as Record<string, unknown>;
  const sc =
    o['score_components'] != null && typeof o['score_components'] === 'object'
      ? (o['score_components'] as Record<string, unknown>)
      : {};
  return {
    rank_reason: safeStr(o['rank_reason']),
    lexical_score: safeNum(o['lexical_score']),
    semantic_score: safeNum(o['semantic_score']),
    rrf_score: safeNum(o['rrf_score']),
    combined_score: safeNum(o['combined_score']),
    matched_term_count: safeNum(o['matched_term_count']),
    matched_categories: safeStrArr(o['matched_categories']),
    corpus_id: safeStr(o['corpus_id']),
    document_id: safeStr(o['document_id']),
    lexical_rank: safeNum(o['lexical_rank']),
    semantic_rank: safeNum(o['semantic_rank']),
    rrf_rank: safeNum(o['rrf_rank']),
    rerank_score: safeNum(sc['rerank_score']),
    final_score: safeNum(sc['final_score']),
    rerank_reason: safeStr(o['rerank_reason']),
  };
}

interface WhyEntry {
  rank_reason?: string | null;
  lexical_score?: number | null;
  semantic_score?: number | null;
  rrf_score?: number | null;
  combined_score?: number | null;
  matched_term_count?: number | null;
  matched_categories?: string[] | null;
  corpus_id?: string | null;
  document_id?: string | null;
  lexical_rank?: number | null;
  semantic_rank?: number | null;
  rrf_rank?: number | null;
  rerank_score?: number | null;
  final_score?: number | null;
  rerank_reason?: string | null;
}

function formatScore(n: number): string {
  return n.toFixed(3);
}

// ─── Deterministic ordering ───────────────────────────────────────────────────

function orderSummaries(
  summaries: SourceSummaryItem[],
  whyMap: Record<string, WhyEntry>,
): SourceSummaryItem[] {
  return [...summaries].sort((a, b) => {
    const wa = whyMap[a.chunk_id ?? ''];
    const wb = whyMap[b.chunk_id ?? ''];
    // 1) retrieval rank (lower = better)
    const rankA = wa?.rrf_rank ?? wa?.lexical_rank ?? Infinity;
    const rankB = wb?.rrf_rank ?? wb?.lexical_rank ?? Infinity;
    if (rankA !== rankB) return rankA - rankB;
    // 2) final_score if available, then combined_score (higher = better)
    const scoreA = wa?.final_score ?? wa?.combined_score ?? wa?.rrf_score ?? -Infinity;
    const scoreB = wb?.final_score ?? wb?.combined_score ?? wb?.rrf_score ?? -Infinity;
    if (scoreA !== scoreB) return scoreB - scoreA;
    // 3) chunk_id tie-break (stable alphabetical)
    return (a.chunk_id ?? '').localeCompare(b.chunk_id ?? '');
  });
}

// ─── Retrieval strategy display ───────────────────────────────────────────────

const STRATEGY_LABELS: Record<string, string> = {
  lexical: 'Lexical',
  semantic: 'Semantic',
  hybrid: 'Hybrid (Lexical + Semantic)',
  hybrid_rrf: 'Hybrid RRF',
  legacy_in_memory: 'Legacy In-Memory',
};

function strategyLabel(s: string): string {
  return STRATEGY_LABELS[s.toLowerCase()] ?? s;
}

// ─── Confidence grounding ─────────────────────────────────────────────────────

type GroundingLevel = 'grounded' | 'weakly-grounded' | 'ungrounded' | 'unavailable';

function groundingLevel(confidence: number | null | undefined): GroundingLevel {
  if (confidence == null) return 'unavailable';
  if (confidence >= 0.7) return 'grounded';
  if (confidence >= 0.4) return 'weakly-grounded';
  return 'ungrounded';
}

const GROUNDING_CONFIG: Record<
  GroundingLevel,
  { label: string; textClass: string; Icon: React.ComponentType<{ className?: string }>; statusText: string }
> = {
  grounded: {
    label: 'Grounded',
    textClass: 'text-success',
    Icon: CheckCircle2,
    statusText: 'Answer is well-supported by retrieved context.',
  },
  'weakly-grounded': {
    label: 'Weakly Grounded',
    textClass: 'text-warning',
    Icon: AlertCircle,
    statusText: 'Answer is partially supported. Verify sources.',
  },
  ungrounded: {
    label: 'Ungrounded',
    textClass: 'text-danger',
    Icon: XCircle,
    statusText: 'Answer has low retrieval support. Treat with caution.',
  },
  unavailable: {
    label: 'Unavailable',
    textClass: 'text-muted',
    Icon: HelpCircle,
    statusText: 'Confidence was not measured for this response.',
  },
};

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
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between py-1.5 text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-primary"
      >
        <h3 className="text-[10px] font-semibold uppercase tracking-widest text-muted/60">
          {title}
        </h3>
        {open ? (
          <ChevronDown className="h-3 w-3 text-muted/50" aria-hidden="true" />
        ) : (
          <ChevronRight className="h-3 w-3 text-muted/50" aria-hidden="true" />
        )}
      </button>
      <div id={contentId} hidden={!open}>
        {children}
      </div>
    </section>
  );
}

// ─── Source card ──────────────────────────────────────────────────────────────

function SourceCard({
  summary,
  rank,
  whyEntry,
}: {
  summary: SourceSummaryItem;
  rank: number;
  whyEntry: WhyEntry | null;
}) {
  const [open, setOpen] = useState(false);
  const cardId = `source-card-${summary.chunk_id ?? rank}`;
  const contentId = `${cardId}-detail`;

  const hasScores =
    whyEntry != null &&
    (whyEntry.lexical_score != null ||
      whyEntry.semantic_score != null ||
      whyEntry.rrf_score != null ||
      whyEntry.combined_score != null ||
      whyEntry.rerank_score != null ||
      whyEntry.final_score != null);

  const retrievalRank =
    whyEntry?.rrf_rank ?? whyEntry?.lexical_rank ?? whyEntry?.semantic_rank ?? rank + 1;

  return (
    <li
      className="rounded-lg border border-border bg-surface-2"
      aria-label="source-card"
    >
      {/* Card header — always visible */}
      <button
        type="button"
        aria-expanded={open}
        aria-controls={contentId}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start justify-between gap-2 px-3 py-2.5 text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-primary"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span
              className="shrink-0 rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-primary"
              aria-label="retrieval-rank"
            >
              #{retrievalRank}
            </span>
            {summary.chunk_id && (
              <span
                className="truncate font-mono text-[10px] text-muted/70"
                aria-label="chunk-reference"
              >
                {summary.chunk_id}
              </span>
            )}
          </div>
          {summary.source_id && (
            <p className="mt-0.5 truncate font-mono text-[10px] text-muted/50">
              src: {summary.source_id}
            </p>
          )}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-0.5">
          {summary.included_in_prompt !== undefined && (
            <span
              className={`text-[9px] font-medium ${summary.included_in_prompt ? 'text-success' : 'text-muted/50'}`}
              aria-label="inclusion-status"
            >
              {summary.included_in_prompt ? 'Included' : 'Not in prompt'}
            </span>
          )}
          {open ? (
            <ChevronDown className="h-3 w-3 text-muted/40" aria-hidden="true" />
          ) : (
            <ChevronRight className="h-3 w-3 text-muted/40" aria-hidden="true" />
          )}
        </div>
      </button>

      {/* Card detail — collapsible */}
      <div id={contentId} hidden={!open}>
        <div className="border-t border-border px-3 pb-3 pt-2 space-y-2.5">

          {/* Retrieval scores */}
          <div aria-label="retrieval-score-section">
            <p className="mb-1 text-[9px] uppercase tracking-wide text-muted/50">Retrieval Scores</p>
            {hasScores ? (
              <dl className="grid grid-cols-2 gap-x-3 gap-y-1">
                {whyEntry?.lexical_score != null && (
                  <>
                    <dt className="text-[9px] text-muted/60">Lexical</dt>
                    <dd className="font-mono text-[10px] text-foreground">
                      {formatScore(whyEntry.lexical_score)}
                    </dd>
                  </>
                )}
                {whyEntry?.semantic_score != null && (
                  <>
                    <dt className="text-[9px] text-muted/60">Semantic</dt>
                    <dd className="font-mono text-[10px] text-foreground">
                      {formatScore(whyEntry.semantic_score)}
                    </dd>
                  </>
                )}
                {whyEntry?.rrf_score != null && (
                  <>
                    <dt className="text-[9px] text-muted/60">RRF</dt>
                    <dd className="font-mono text-[10px] text-foreground">
                      {formatScore(whyEntry.rrf_score)}
                    </dd>
                  </>
                )}
                {whyEntry?.combined_score != null && (
                  <>
                    <dt className="text-[9px] text-muted/60">Combined</dt>
                    <dd className="font-mono text-[10px] text-foreground">
                      {formatScore(whyEntry.combined_score)}
                    </dd>
                  </>
                )}
                {whyEntry?.rerank_score != null && (
                  <>
                    <dt className="text-[9px] text-muted/60" aria-label="rerank-score-label">Rerank</dt>
                    <dd className="font-mono text-[10px] text-foreground" aria-label="rerank-score-value">
                      {formatScore(whyEntry.rerank_score)}
                    </dd>
                  </>
                )}
                {whyEntry?.final_score != null && (
                  <>
                    <dt className="text-[9px] text-muted/60" aria-label="final-score-label">Final</dt>
                    <dd className="font-mono text-[10px] text-foreground font-semibold" aria-label="final-score-value">
                      {formatScore(whyEntry.final_score)}
                    </dd>
                  </>
                )}
              </dl>
            ) : (
              <p className="text-[10px] text-muted/50" aria-label="score-unavailable">
                Scores unavailable
              </p>
            )}
          </div>

          {/* Why-this-chunk */}
          {whyEntry != null && (
            <div aria-label="why-this-chunk-section">
              <p className="mb-1 text-[9px] uppercase tracking-wide text-muted/50">Why Retrieved</p>
              {whyEntry.rank_reason && (
                <p className="text-[10px] text-muted" aria-label="rank-reason">
                  {whyEntry.rank_reason}
                </p>
              )}
              {whyEntry.rerank_reason && (
                <p className="text-[10px] text-muted/70" aria-label="rerank-reason">
                  Rerank: {whyEntry.rerank_reason.replace(/_/g, ' ')}
                </p>
              )}
              {whyEntry.matched_term_count != null && (
                <p className="text-[10px] text-muted/60">
                  Matched terms: {whyEntry.matched_term_count}
                </p>
              )}
              {whyEntry.matched_categories != null && (
                <p className="text-[10px] text-muted/60">
                  Categories: {whyEntry.matched_categories.join(', ')}
                </p>
              )}
              {whyEntry.rank_reason == null &&
                whyEntry.rerank_reason == null &&
                whyEntry.matched_term_count == null &&
                whyEntry.matched_categories == null && (
                  <p className="text-[10px] text-muted/50">Explanation not available</p>
                )}
            </div>
          )}

          {/* Source/document metadata */}
          <div aria-label="source-metadata-section">
            <p className="mb-1 text-[9px] uppercase tracking-wide text-muted/50">Metadata</p>
            <dl className="space-y-0.5">
              {summary.chunk_index != null && (
                <div className="flex gap-2">
                  <dt className="text-[9px] text-muted/50 w-16 shrink-0">Chunk idx</dt>
                  <dd className="font-mono text-[10px] text-muted/70">{summary.chunk_index}</dd>
                </div>
              )}
              {whyEntry?.corpus_id && (
                <div className="flex gap-2">
                  <dt className="text-[9px] text-muted/50 w-16 shrink-0">Corpus</dt>
                  <dd className="truncate font-mono text-[10px] text-muted/70">{whyEntry.corpus_id}</dd>
                </div>
              )}
              {whyEntry?.document_id && (
                <div className="flex gap-2">
                  <dt className="text-[9px] text-muted/50 w-16 shrink-0">Document</dt>
                  <dd className="truncate font-mono text-[10px] text-muted/70">{whyEntry.document_id}</dd>
                </div>
              )}
              {summary.phi_sensitivity_level && summary.phi_sensitivity_level.toUpperCase() !== 'NONE' && (
                <div className="flex gap-2">
                  <dt className="text-[9px] text-muted/50 w-16 shrink-0">PHI</dt>
                  <dd className="text-[10px] text-warning">{summary.phi_sensitivity_level}</dd>
                </div>
              )}
            </dl>
          </div>

        </div>
      </div>
    </li>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export function SourceEvidencePanel({
  provenance,
  citations,
  apiFailure = false,
}: SourceEvidencePanelProps) {
  // API failure state
  if (apiFailure) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="api-failure-state"
      >
        <XCircle className="h-7 w-7 text-danger/40" aria-hidden="true" />
        <p className="text-xs text-muted">Evidence unavailable</p>
        <p className="max-w-[200px] text-[10px] text-muted/50">
          Retrieval data could not be loaded.
        </p>
      </div>
    );
  }

  // No provenance data yet
  if (provenance == null) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="evidence-empty"
      >
        <BookOpen className="h-7 w-7 text-muted/20" aria-hidden="true" />
        <p className="text-xs text-muted">Sources will appear here</p>
      </div>
    );
  }

  const prov = provenance;
  const noContext = prov.used_rag === false || (prov.context_count ?? 0) === 0;
  const summaries = prov.source_summaries ?? [];
  const chunkIds = prov.source_chunk_ids ?? [];
  const hasSources =
    summaries.length > 0 ||
    chunkIds.length > 0 ||
    (citations != null && citations.length > 0);

  // No-context state
  if (noContext) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="no-context-state"
      >
        <HelpCircle className="h-7 w-7 text-muted/20" aria-hidden="true" />
        <p className="text-xs text-muted">No retrieval context available</p>
        <p className="max-w-[200px] text-[10px] text-muted/50">
          Answer was generated without retrieved evidence.
        </p>
      </div>
    );
  }

  // Invalid provenance state
  const isInvalidProvenance =
    prov.provenance_status != null &&
    prov.provenance_status !== 'PROVENANCE_VALID' &&
    prov.provenance_status !== 'PROVENANCE_NO_CONTEXT_AVAILABLE';

  // No-source state (context existed but no source metadata returned)
  if (!hasSources) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-2 py-12 text-center"
        aria-label="no-source-state"
      >
        <BookOpen className="h-7 w-7 text-muted/20" aria-hidden="true" />
        <p className="text-xs text-muted">No source references returned</p>
        <p className="max-w-[200px] text-[10px] text-muted/50">
          {prov.provenance_status === 'PROVENANCE_NO_CONTEXT_AVAILABLE'
            ? 'No retrieval context was available.'
            : 'The response was generated but no source metadata was returned.'}
        </p>
      </div>
    );
  }

  // Build why_this_chunk map
  const rawWhy = prov.why_this_chunk ?? {};
  const whyMap: Record<string, WhyEntry> = {};
  for (const [k, v] of Object.entries(rawWhy)) {
    whyMap[k] = parseWhyEntry(v);
  }

  // Deterministically ordered source summaries
  const orderedSummaries = orderSummaries(summaries, whyMap);

  // Retrieval strategy
  const strategy = prov.retrieval_strategy;
  const isLexicalFallback =
    prov.lexical_fallback === true ||
    (strategy != null && strategy.toLowerCase() === 'lexical' && summaries.length > 0);

  // Confidence
  const confidence = prov.confidence;
  const confidenceReason = prov.confidence_reason;
  const grounding = groundingLevel(confidence);
  const groundingCfg = GROUNDING_CONFIG[grounding];
  const GroundingIcon = groundingCfg.Icon;

  return (
    <div className="space-y-4" aria-label="source-evidence-panel">

      {/* Invalid provenance warning */}
      {isInvalidProvenance && (
        <div
          className="flex items-center gap-2 rounded border border-warning/30 bg-warning/5 px-3 py-2 text-xs text-warning"
          aria-label="invalid-provenance-state"
          role="alert"
        >
          <AlertCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Provenance validation did not pass — treat sources with caution.</span>
        </div>
      )}

      {/* Retrieval strategy */}
      {strategy && (
        <CollapsibleSection id="retrieval-strategy-section" title="Retrieval Strategy">
          <div className="pt-1 space-y-1">
            <p
              className="font-mono text-xs text-foreground"
              aria-label="retrieval-strategy"
            >
              {strategyLabel(strategy)}
            </p>
            {isLexicalFallback && (
              <p
                className="text-[10px] text-warning"
                aria-label="lexical-fallback-indicator"
              >
                Lexical fallback active — semantic retrieval was unavailable or disabled.
              </p>
            )}
          </div>
        </CollapsibleSection>
      )}

      {/* Retrieval unavailable — no strategy returned */}
      {!strategy && (
        <div aria-label="retrieval-unavailable-state">
          <p className="text-[10px] text-muted/50">Retrieval strategy not reported</p>
        </div>
      )}

      {/* Confidence explanation */}
      <CollapsibleSection id="confidence-explanation" title="Confidence">
        <div className="pt-1 space-y-1">
          <div className="flex items-center gap-1.5">
            <GroundingIcon
              className={`h-3.5 w-3.5 shrink-0 ${groundingCfg.textClass}`}
              aria-hidden="true"
            />
            <span
              className={`text-xs font-medium ${groundingCfg.textClass}`}
              aria-label="confidence-grounding-level"
            >
              {groundingCfg.label}
            </span>
            {confidence != null && (
              <span className="font-mono text-[10px] text-muted/60">
                ({formatScore(confidence)})
              </span>
            )}
          </div>
          <p className="text-[10px] text-muted/60">{groundingCfg.statusText}</p>
          {confidenceReason && (
            <p className="text-[10px] text-muted/50" aria-label="confidence-reason">
              {confidenceReason}
            </p>
          )}
        </div>
      </CollapsibleSection>

      {/* Source cards */}
      {orderedSummaries.length > 0 && (
        <CollapsibleSection
          id="source-cards-section"
          title={`Source Cards (${orderedSummaries.length})`}
        >
          <ul className="mt-1.5 space-y-2" aria-label="source-cards-list">
            {orderedSummaries.map((s, i) => (
              <SourceCard
                key={s.chunk_id ?? i}
                summary={s}
                rank={i}
                whyEntry={s.chunk_id != null ? (whyMap[s.chunk_id] ?? null) : null}
              />
            ))}
          </ul>
        </CollapsibleSection>
      )}

      {/* Chunk IDs fallback when no summaries */}
      {chunkIds.length > 0 && summaries.length === 0 && (
        <CollapsibleSection id="chunk-ids-section" title="Chunk References">
          <ul className="mt-1 space-y-1" aria-label="chunk-ids-list">
            {chunkIds.slice(0, 10).map((id) => (
              <li
                key={id}
                className="truncate font-mono text-[10px] text-muted/70"
                aria-label="chunk-reference"
              >
                {id}
              </li>
            ))}
            {chunkIds.length > 10 && (
              <li className="text-[10px] text-muted/50">
                +{chunkIds.length - 10} more chunk references
              </li>
            )}
          </ul>
        </CollapsibleSection>
      )}

      {/* API-provided citations */}
      {citations != null && citations.length > 0 && (
        <CollapsibleSection id="citations-section" title={`Citations (${citations.length})`}>
          <ul className="mt-1.5 space-y-1.5" aria-label="citation-list">
            {citations.map((c) => (
              <li
                key={c.index}
                className="rounded border border-border bg-surface-2 px-2.5 py-2 text-[10px]"
                aria-label="citation-item"
              >
                <p className="font-medium text-foreground">{c.source}</p>
                {c.excerpt && (
                  <p className="mt-0.5 text-muted/70 line-clamp-2">{c.excerpt}</p>
                )}
              </li>
            ))}
          </ul>
        </CollapsibleSection>
      )}

      {/* Future-ready placeholders */}
      <CollapsibleSection id="future-capabilities-section" title="Future Capabilities" defaultOpen={false}>
        <ul className="mt-1.5 space-y-1.5" aria-label="future-placeholders-list">
          {[
            'Source freshness',
            'Conflicting evidence detection',
            'Citation lineage',
          ].map((label) => (
            <li
              key={label}
              className="rounded border border-dashed border-border px-2.5 py-2 text-[10px] opacity-60"
              aria-label="future-placeholder"
            >
              <span className="text-muted">{label}</span>
              <span className="ml-1 text-muted/50">— not yet available</span>
            </li>
          ))}
        </ul>
      </CollapsibleSection>

    </div>
  );
}
