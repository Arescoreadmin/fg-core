'use client';

import { useState } from 'react';
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  HelpCircle,
  XCircle,
} from 'lucide-react';
import type { TraceStep } from './RetrievalTrace';
import type { SourceEvidenceData, SourceSummaryItem } from './SourceEvidencePanel';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RetrievalTraceExplorerProps {
  provenance?: SourceEvidenceData | null;
  retrievalSteps?: TraceStep[] | null;
  apiFailure?: boolean;
}

type SortField = 'rank' | 'lexical' | 'semantic' | 'rrf' | 'combined';
type SortDir = 'asc' | 'desc';
type FilterState = 'all' | 'accepted' | 'rejected';

interface WhyEntry {
  rank_reason?: string | null;
  lexical_score?: number | null;
  semantic_score?: number | null;
  rrf_score?: number | null;
  combined_score?: number | null;
  lexical_rank?: number | null;
  semantic_rank?: number | null;
  rrf_rank?: number | null;
  matched_term_count?: number | null;
}

interface ChunkRow {
  chunkId: string;
  sourceId: string | null;
  includedInPrompt: boolean | undefined;
  lexicalScore: number | null;
  semanticScore: number | null;
  rrfScore: number | null;
  combinedScore: number | null;
  lexicalRank: number | null;
  semanticRank: number | null;
  rrfRank: number | null;
  rankReason: string | null;
  retrievalRank: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_VISIBLE_CHUNKS = 20;

const STRATEGY_PATH: Record<string, string[]> = {
  lexical: ['Lexical'],
  semantic: ['Semantic'],
  hybrid: ['Lexical', 'Semantic', 'Hybrid Merge'],
  hybrid_rrf: ['Lexical', 'Semantic', 'RRF Fusion', 'Combined Rank'],
  legacy_in_memory: ['In-Memory Lexical'],
};

// ─── Safe helpers ─────────────────────────────────────────────────────────────

function safeNum(v: unknown): number | null {
  return typeof v === 'number' && isFinite(v) ? v : null;
}

function safeStr(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function parseWhyEntry(raw: unknown): WhyEntry {
  if (raw === null || typeof raw !== 'object') return {};
  const o = raw as Record<string, unknown>;
  return {
    rank_reason: safeStr(o['rank_reason']),
    lexical_score: safeNum(o['lexical_score']),
    semantic_score: safeNum(o['semantic_score']),
    rrf_score: safeNum(o['rrf_score']),
    combined_score: safeNum(o['combined_score']),
    lexical_rank: safeNum(o['lexical_rank']),
    semantic_rank: safeNum(o['semantic_rank']),
    rrf_rank: safeNum(o['rrf_rank']),
    matched_term_count: safeNum(o['matched_term_count']),
  };
}

function fmt(n: number): string {
  return n.toFixed(3);
}

// ─── Build chunk rows ─────────────────────────────────────────────────────────

function buildChunkRows(
  summaries: SourceSummaryItem[],
  whyMap: Record<string, WhyEntry>,
): ChunkRow[] {
  return summaries.map((s, i) => {
    const why = s.chunk_id ? (whyMap[s.chunk_id] ?? {}) : {};
    return {
      chunkId: s.chunk_id ?? `chunk-${i}`,
      sourceId: s.source_id ?? null,
      includedInPrompt: s.included_in_prompt,
      lexicalScore: safeNum(why.lexical_score),
      semanticScore: safeNum(why.semantic_score),
      rrfScore: safeNum(why.rrf_score),
      combinedScore: safeNum(why.combined_score),
      lexicalRank: safeNum(why.lexical_rank),
      semanticRank: safeNum(why.semantic_rank),
      rrfRank: safeNum(why.rrf_rank),
      rankReason: safeStr(why.rank_reason),
      retrievalRank: i + 1,
    };
  });
}

// ─── Deterministic sort ───────────────────────────────────────────────────────

function sortRows(rows: ChunkRow[], field: SortField, dir: SortDir): ChunkRow[] {
  return [...rows].sort((a, b) => {
    let av: number;
    let bv: number;
    const inf = dir === 'asc' ? Infinity : -Infinity;
    switch (field) {
      case 'lexical':
        av = a.lexicalScore ?? inf;
        bv = b.lexicalScore ?? inf;
        break;
      case 'semantic':
        av = a.semanticScore ?? inf;
        bv = b.semanticScore ?? inf;
        break;
      case 'rrf':
        av = a.rrfScore ?? inf;
        bv = b.rrfScore ?? inf;
        break;
      case 'combined':
        av = a.combinedScore ?? inf;
        bv = b.combinedScore ?? inf;
        break;
      default:
        av = a.retrievalRank;
        bv = b.retrievalRank;
    }
    if (av !== bv) return dir === 'asc' ? av - bv : bv - av;
    return a.chunkId.localeCompare(b.chunkId); // stable tie-break
  });
}

// ─── Filter rows ──────────────────────────────────────────────────────────────

function filterRows(rows: ChunkRow[], filter: FilterState): ChunkRow[] {
  if (filter === 'accepted') return rows.filter(r => r.includedInPrompt === true);
  if (filter === 'rejected') return rows.filter(r => r.includedInPrompt === false);
  return rows;
}

// ─── Confidence grounding ─────────────────────────────────────────────────────

type GroundingLevel = 'grounded' | 'weakly-grounded' | 'ungrounded' | 'unavailable';

function groundingLevel(c: number | null | undefined): GroundingLevel {
  if (c == null) return 'unavailable';
  if (c >= 0.7) return 'grounded';
  if (c >= 0.4) return 'weakly-grounded';
  return 'ungrounded';
}

const GROUNDING_CONFIG: Record<
  GroundingLevel,
  { label: string; className: string; Icon: React.ComponentType<{ className?: string }> }
> = {
  grounded: { label: 'Grounded', className: 'text-success', Icon: CheckCircle2 },
  'weakly-grounded': { label: 'Weakly Grounded', className: 'text-warning', Icon: AlertCircle },
  ungrounded: { label: 'Ungrounded', className: 'text-danger', Icon: XCircle },
  unavailable: { label: 'Unavailable', className: 'text-muted', Icon: HelpCircle },
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

// ─── Score cell ───────────────────────────────────────────────────────────────

function ScoreCell({ value }: { value: number | null }) {
  if (value == null) {
    return (
      <span className="text-[9px] text-muted/40" aria-label="score-unavailable">
        —
      </span>
    );
  }
  return <span className="font-mono text-[10px] text-foreground">{fmt(value)}</span>;
}

// ─── Sort header button ───────────────────────────────────────────────────────

function sortAriaValue(
  field: SortField,
  current: SortField,
  dir: SortDir,
): 'ascending' | 'descending' | 'none' {
  if (field !== current) return 'none';
  return dir === 'asc' ? 'ascending' : 'descending';
}

function SortHeaderBtn({
  field,
  label,
  current,
  dir,
  onSort,
}: {
  field: SortField;
  label: string;
  current: SortField;
  dir: SortDir;
  onSort: (f: SortField) => void;
}) {
  const active = current === field;
  return (
    <button
      type="button"
      onClick={() => onSort(field)}
      className={`text-[9px] uppercase tracking-wide hover:text-foreground focus:outline-none focus-visible:ring-1 focus-visible:ring-primary ${
        active ? 'font-semibold text-primary' : 'text-muted/60'
      }`}
    >
      {label}
      {active && (
        <span aria-hidden="true" className="ml-0.5">
          {dir === 'asc' ? '↑' : '↓'}
        </span>
      )}
    </button>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function RetrievalTraceExplorer({
  provenance,
  retrievalSteps,
  apiFailure = false,
}: RetrievalTraceExplorerProps) {
  const [sortField, setSortField] = useState<SortField>('rank');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [filterState, setFilterState] = useState<FilterState>('all');

  function handleSort(field: SortField) {
    if (field === sortField) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  }

  if (apiFailure) {
    return (
      <div aria-label="trace-api-failure-state" className="py-4 text-center">
        <XCircle className="mx-auto h-5 w-5 text-danger/30" aria-hidden="true" />
        <p className="mt-1 text-xs text-muted">Retrieval trace unavailable</p>
        <p className="text-[10px] text-muted/50">Trace data could not be loaded.</p>
      </div>
    );
  }

  if (provenance == null && (!retrievalSteps || retrievalSteps.length === 0)) {
    return (
      <div aria-label="no-trace-state" className="py-4 text-center">
        <HelpCircle className="mx-auto h-5 w-5 text-muted/20" aria-hidden="true" />
        <p className="mt-1 text-xs text-muted">No retrieval trace available</p>
        <p className="text-[10px] text-muted/50">
          Submit a query to inspect retrieval execution.
        </p>
      </div>
    );
  }

  const prov = provenance ?? {};
  const strategy = prov.retrieval_strategy ?? null;
  const confidence = prov.confidence ?? null;
  const confidenceReason = prov.confidence_reason ?? null;
  const contextCount = prov.context_count ?? 0;
  const noContext = prov.used_rag === false || contextCount === 0;
  const summaries = (prov.source_summaries ?? []) as SourceSummaryItem[];
  const rawWhy = prov.why_this_chunk ?? {};

  const isLexicalFallback =
    prov.lexical_fallback === true ||
    (strategy != null && strategy.toLowerCase() === 'lexical' && summaries.length > 0);

  const whyMap: Record<string, WhyEntry> = {};
  for (const [k, v] of Object.entries(rawWhy)) {
    whyMap[k] = parseWhyEntry(v);
  }

  const allRows = buildChunkRows(summaries, whyMap);
  const sortedRows = sortRows(allRows, sortField, sortDir);
  const filteredRows = filterRows(sortedRows, filterState);
  const visibleRows = filteredRows.slice(0, MAX_VISIBLE_CHUNKS);
  const hiddenCount = filteredRows.length - visibleRows.length;

  const acceptedCount = allRows.filter(r => r.includedInPrompt === true).length;
  const rejectedCount = allRows.filter(r => r.includedInPrompt === false).length;

  const grounding = groundingLevel(confidence);
  const groundingCfg = GROUNDING_CONFIG[grounding];
  const GroundingIcon = groundingCfg.Icon;

  const pathSteps =
    strategy != null
      ? (STRATEGY_PATH[strategy.toLowerCase()] ?? [strategy])
      : null;

  const totalMs =
    retrievalSteps && retrievalSteps.length > 0
      ? retrievalSteps.reduce((acc, s) => acc + (s.latencyMs ?? 0), 0)
      : null;

  return (
    <div className="space-y-3" aria-label="retrieval-trace-explorer">

      {/* Retrieval Path */}
      <CollapsibleSection id="retrieval-path-section" title="Retrieval Path">
        <div className="pt-1 space-y-1.5">
          {pathSteps != null ? (
            <>
              <div
                className="flex flex-wrap items-center gap-1"
                aria-label="retrieval-path-visualization"
              >
                {pathSteps.map((step, i) => (
                  <span key={step} className="flex items-center gap-1">
                    <span
                      className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[9px] text-foreground"
                      aria-label="retrieval-path-stage"
                    >
                      {step}
                    </span>
                    {i < pathSteps.length - 1 && (
                      <ArrowRight
                        className="h-2.5 w-2.5 shrink-0 text-muted/40"
                        aria-hidden="true"
                      />
                    )}
                  </span>
                ))}
              </div>
              {isLexicalFallback && (
                <p
                  className="text-[10px] text-warning"
                  aria-label="lexical-fallback-indicator"
                >
                  Lexical fallback — semantic retrieval was unavailable.
                </p>
              )}
            </>
          ) : (
            <p
              className="text-[10px] text-muted/50"
              aria-label="retrieval-path-unavailable"
            >
              Retrieval path not reported.
            </p>
          )}
        </div>
      </CollapsibleSection>

      {/* Execution Timeline */}
      {retrievalSteps != null && retrievalSteps.length > 0 && (
        <CollapsibleSection
          id="execution-timeline-section"
          title={`Execution Timeline (${retrievalSteps.length} stage${retrievalSteps.length !== 1 ? 's' : ''})`}
        >
          <div className="pt-1 space-y-1">
            {totalMs != null && totalMs > 0 && (
              <p
                className="font-mono text-[10px] text-muted/60"
                aria-label="total-timing"
              >
                Total: {totalMs}ms
              </p>
            )}
            <ol aria-label="timeline-stages">
              {retrievalSteps.map((step, i) => (
                <li key={i} className="flex items-start gap-2 py-0.5">
                  <span className="mt-0.5 w-4 shrink-0 font-mono text-[9px] text-muted/40">
                    {i + 1}.
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[10px] text-foreground">{step.step}</p>
                    {step.detail && (
                      <p className="text-[9px] text-muted/60">{step.detail}</p>
                    )}
                  </div>
                  {step.latencyMs != null && (
                    <span
                      className="shrink-0 font-mono text-[9px] text-muted/50"
                      aria-label="stage-timing"
                    >
                      {step.latencyMs}ms
                    </span>
                  )}
                </li>
              ))}
            </ol>
          </div>
        </CollapsibleSection>
      )}

      {/* Timing unavailable state */}
      {(retrievalSteps == null || retrievalSteps.length === 0) && (
        <div aria-label="timing-unavailable-state">
          <p className="text-[10px] text-muted/50">
            Timing data not reported for this request.
          </p>
        </div>
      )}

      {/* Candidate Flow */}
      {!noContext ? (
        <CollapsibleSection id="candidate-flow-section" title="Candidate Flow">
          <div className="pt-1" aria-label="candidate-flow">
            <dl className="grid grid-cols-3 gap-2 text-center">
              <div>
                <dt className="text-[9px] uppercase tracking-wide text-muted/50">Returned</dt>
                <dd
                  className="font-mono text-sm font-semibold text-foreground"
                  aria-label="returned-count"
                >
                  {contextCount}
                </dd>
              </div>
              <div>
                <dt className="text-[9px] uppercase tracking-wide text-muted/50">Accepted</dt>
                <dd
                  className="font-mono text-sm font-semibold text-success"
                  aria-label="accepted-count"
                >
                  {acceptedCount > 0 ? acceptedCount : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-[9px] uppercase tracking-wide text-muted/50">Filtered</dt>
                <dd
                  className="font-mono text-sm font-semibold text-muted"
                  aria-label="rejected-count"
                >
                  {rejectedCount > 0 ? rejectedCount : '—'}
                </dd>
              </div>
            </dl>
          </div>
        </CollapsibleSection>
      ) : (
        <div aria-label="no-context-trace-state">
          <p className="text-[10px] text-muted/50">
            No retrieval context — no candidates to display.
          </p>
        </div>
      )}

      {/* Chunk Rankings */}
      {allRows.length > 0 && (
        <CollapsibleSection
          id="chunk-rankings-section"
          title={`Chunk Rankings (${allRows.length})`}
        >
          <div className="pt-1 space-y-2">

            {/* Filter controls */}
            <fieldset aria-label="filter-controls">
              <legend className="sr-only">Filter by inclusion status</legend>
              <div className="flex flex-wrap gap-1.5">
                {(['all', 'accepted', 'rejected'] as FilterState[]).map(f => (
                  <button
                    key={f}
                    type="button"
                    aria-pressed={filterState === f}
                    onClick={() => setFilterState(f)}
                    className={`rounded px-2 py-0.5 text-[9px] font-medium capitalize focus:outline-none focus-visible:ring-1 focus-visible:ring-primary ${
                      filterState === f
                        ? 'bg-primary/10 text-primary'
                        : 'bg-surface-3 text-muted/70 hover:text-foreground'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </fieldset>

            {/* Rankings table */}
            {visibleRows.length > 0 ? (
              <div className="overflow-x-auto" aria-label="chunk-rankings-table">
                <table
                  className="w-full min-w-[360px] text-left"
                  aria-label="chunk-rankings"
                >
                  <thead>
                    <tr className="border-b border-border">
                      <th
                        scope="col"
                        className="pb-1 pr-2"
                        aria-sort={sortAriaValue('rank', sortField, sortDir)}
                      >
                        <SortHeaderBtn
                          field="rank"
                          label="#"
                          current={sortField}
                          dir={sortDir}
                          onSort={handleSort}
                        />
                      </th>
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
                        Status
                      </th>
                      <th
                        scope="col"
                        className="pb-1 pr-2"
                        aria-sort={sortAriaValue('lexical', sortField, sortDir)}
                      >
                        <SortHeaderBtn
                          field="lexical"
                          label="Lex"
                          current={sortField}
                          dir={sortDir}
                          onSort={handleSort}
                        />
                      </th>
                      <th
                        scope="col"
                        className="pb-1 pr-2"
                        aria-sort={sortAriaValue('semantic', sortField, sortDir)}
                      >
                        <SortHeaderBtn
                          field="semantic"
                          label="Sem"
                          current={sortField}
                          dir={sortDir}
                          onSort={handleSort}
                        />
                      </th>
                      <th
                        scope="col"
                        className="pb-1 pr-2"
                        aria-sort={sortAriaValue('rrf', sortField, sortDir)}
                      >
                        <SortHeaderBtn
                          field="rrf"
                          label="RRF"
                          current={sortField}
                          dir={sortDir}
                          onSort={handleSort}
                        />
                      </th>
                      <th
                        scope="col"
                        className="pb-1"
                        aria-sort={sortAriaValue('combined', sortField, sortDir)}
                      >
                        <SortHeaderBtn
                          field="combined"
                          label="Comb"
                          current={sortField}
                          dir={sortDir}
                          onSort={handleSort}
                        />
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleRows.map(row => (
                      <tr
                        key={row.chunkId}
                        className="border-b border-border/40"
                        aria-label="chunk-ranking-row"
                      >
                        <td className="py-1 pr-2 font-mono text-[9px] text-muted/60">
                          {row.retrievalRank}
                        </td>
                        <td className="max-w-[80px] py-1 pr-2">
                          <span className="block truncate font-mono text-[9px] text-muted/70">
                            {row.chunkId}
                          </span>
                        </td>
                        <td className="py-1 pr-2">
                          {row.includedInPrompt === true ? (
                            <span
                              className="text-[9px] font-medium text-success"
                              aria-label="chunk-accepted"
                            >
                              Accepted
                            </span>
                          ) : row.includedInPrompt === false ? (
                            <span
                              className="text-[9px] font-medium text-muted/50"
                              aria-label="chunk-filtered"
                            >
                              Filtered
                            </span>
                          ) : (
                            <span
                              className="text-[9px] text-muted/30"
                              aria-label="chunk-status-unknown"
                            >
                              —
                            </span>
                          )}
                        </td>
                        <td className="py-1 pr-2">
                          <ScoreCell value={row.lexicalScore} />
                        </td>
                        <td className="py-1 pr-2">
                          <ScoreCell value={row.semanticScore} />
                        </td>
                        <td className="py-1 pr-2">
                          <ScoreCell value={row.rrfScore} />
                        </td>
                        <td className="py-1">
                          <ScoreCell value={row.combinedScore} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p
                className="text-[10px] text-muted/50"
                aria-label="no-chunks-for-filter"
              >
                No chunks match the current filter.
              </p>
            )}

            {hiddenCount > 0 && (
              <p
                className="text-[10px] text-muted/50"
                aria-label="large-result-truncation"
              >
                {hiddenCount} more chunk{hiddenCount !== 1 ? 's' : ''} not shown
                (limit {MAX_VISIBLE_CHUNKS}).
              </p>
            )}
          </div>
        </CollapsibleSection>
      )}

      {/* Confidence Derivation */}
      <CollapsibleSection id="confidence-derivation-section" title="Confidence Derivation">
        <div className="pt-1 space-y-1">
          <div className="flex items-center gap-1.5">
            <GroundingIcon
              className={`h-3.5 w-3.5 shrink-0 ${groundingCfg.className}`}
              aria-hidden="true"
            />
            <span
              className={`text-xs font-medium ${groundingCfg.className}`}
              aria-label="confidence-grounding-label"
            >
              {groundingCfg.label}
            </span>
            {confidence != null && (
              <span
                className="font-mono text-[10px] text-muted/60"
                aria-label="confidence-value"
              >
                ({fmt(confidence)})
              </span>
            )}
          </div>
          {confidenceReason && (
            <p className="text-[10px] text-muted/60" aria-label="confidence-reason">
              {confidenceReason}
            </p>
          )}
          {confidence == null && (
            <p
              className="text-[10px] text-muted/50"
              aria-label="confidence-unavailable"
            >
              Confidence not reported for this request.
            </p>
          )}
        </div>
      </CollapsibleSection>

      {/* Future Capabilities */}
      <CollapsibleSection
        id="future-trace-capabilities-section"
        title="Future Capabilities"
        defaultOpen={false}
      >
        <ul className="mt-1 space-y-1" aria-label="future-trace-placeholders">
          {[
            'Rerank visualization',
            'Retrieval drift analysis',
            'Source freshness scoring',
            'Citation lineage',
            'Retrieval replay',
            'Semantic drift analysis',
          ].map(label => (
            <li
              key={label}
              className="rounded border border-dashed border-border px-2 py-1 text-[9px] opacity-60"
              aria-label="future-trace-placeholder"
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
