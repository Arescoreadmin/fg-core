'use client';

import { useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  HelpCircle,
  Layers,
  Lock,
  Shield,
  ShieldCheck,
  ShieldOff,
  XCircle,
} from 'lucide-react';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Repository-approved retrieval strategies only. Must match backend _STRATEGIES frozenset. */
export const RETRIEVAL_STRATEGIES = ['lexical', 'semantic', 'hybrid', 'hybrid_rrf'] as const;
export type RetrievalStrategy = typeof RETRIEVAL_STRATEGIES[number];

/** Safe top-k bounds. Must match backend policy enforcement limits. */
export const TOP_K_MIN = 1;
export const TOP_K_MAX = 20;

// ─── Types ────────────────────────────────────────────────────────────────────

export type CorpusAccessState =
  | 'allowed'
  | 'denied'
  | 'inherited'
  | 'unavailable'
  | 'unknown';

export interface CorpusEntry {
  corpus_id: string;
  name?: string | null;
  access_state: CorpusAccessState;
}

export interface RetrievalPolicyData {
  tenant_id: string;
  allowed_corpora: string[];
  denied_corpora: string[];
  retrieval_strategy: RetrievalStrategy;
  top_k: number;
  semantic_enabled: boolean;
  grounded_answer_required: boolean;
  lexical_fallback_enabled: boolean;
  fallback_strategy: RetrievalStrategy | null;
  reranking_enabled: boolean;
  policy_version?: number | null;
  updated_by?: string | null;
  updated_at?: string | null;
}

export interface RetrievalPolicyValidationError {
  field: string;
  code: string;
  message: string;
}

export interface RetrievalPolicyCenterProps {
  /** Tenant-scoped policy data from backend. Never accepts cross-tenant data. */
  policy?: RetrievalPolicyData | null;
  /** All tenant-scoped corpora. Never includes cross-tenant corpora. */
  availableCorpora?: CorpusEntry[] | null;
  /** Audit change log entries. */
  auditEntries?: RetrievalPolicyAuditEntry[] | null;
  /** True when the API returned a failure loading the policy. */
  apiFailure?: boolean;
  /** True when saving is in progress. */
  saving?: boolean;
  /** Validation errors from the last save attempt. */
  validationErrors?: RetrievalPolicyValidationError[] | null;
  /** Called when operator requests a policy save. Receives validated payload. */
  onSave?: (policy: RetrievalPolicyData) => void;
}

export interface RetrievalPolicyPreviewData {
  effective_corpora: string[];
  denied_corpora: string[];
  retrieval_strategy: RetrievalStrategy;
  semantic_active: boolean;
  fallback_active: boolean;
  grounded_answer_required: boolean;
  effective_top_k: number;
  empty_scope: boolean;
  warnings: string[];
}

export interface RetrievalPolicyAuditEntry {
  timestamp: string;
  actor?: string | null;
  changed_fields: string[];
  reason_code?: string | null;
  request_id?: string | null;
}

// ─── Validation ───────────────────────────────────────────────────────────────

/** Validate a retrieval policy client-side. Returns [] when valid. */
export function validateRetrievalPolicy(
  policy: RetrievalPolicyData,
): RetrievalPolicyValidationError[] {
  const errors: RetrievalPolicyValidationError[] = [];

  // top_k bounds
  if (
    !Number.isInteger(policy.top_k) ||
    policy.top_k < TOP_K_MIN ||
    policy.top_k > TOP_K_MAX
  ) {
    errors.push({
      field: 'top_k',
      code: 'INVALID_TOP_K',
      message: `top_k must be an integer between ${TOP_K_MIN} and ${TOP_K_MAX}. Received: ${policy.top_k}`,
    });
  }

  // Strategy must be a recognized value
  if (!RETRIEVAL_STRATEGIES.includes(policy.retrieval_strategy)) {
    errors.push({
      field: 'retrieval_strategy',
      code: 'UNSUPPORTED_STRATEGY',
      message: `Retrieval strategy '${policy.retrieval_strategy}' is not supported. Allowed: ${RETRIEVAL_STRATEGIES.join(', ')}`,
    });
  }

  // Semantic strategy requires semantic_enabled
  if (
    (policy.retrieval_strategy === 'semantic' ||
      policy.retrieval_strategy === 'hybrid' ||
      policy.retrieval_strategy === 'hybrid_rrf') &&
    !policy.semantic_enabled
  ) {
    errors.push({
      field: 'semantic_enabled',
      code: 'SEMANTIC_DISABLED_WITH_SEMANTIC_STRATEGY',
      message: `Retrieval strategy '${policy.retrieval_strategy}' requires semantic_enabled to be true.`,
    });
  }

  // Fallback strategy must be recognized if set
  if (
    policy.fallback_strategy !== null &&
    !RETRIEVAL_STRATEGIES.includes(policy.fallback_strategy as RetrievalStrategy)
  ) {
    errors.push({
      field: 'fallback_strategy',
      code: 'UNSUPPORTED_FALLBACK_STRATEGY',
      message: `Fallback strategy '${policy.fallback_strategy}' is not supported. Allowed: ${RETRIEVAL_STRATEGIES.join(', ')} or null.`,
    });
  }

  // Denied corpora override: warn if corpus appears in both lists (reject)
  const deniedSet = new Set(policy.denied_corpora);
  const allowedSet = new Set(policy.allowed_corpora);
  const contradictions = policy.allowed_corpora.filter((id) => deniedSet.has(id));
  if (contradictions.length > 0) {
    errors.push({
      field: 'allowed_corpora',
      code: 'CONTRADICTORY_CORPUS_POLICY',
      message: `The following corpora appear in both allowed and denied lists (denied takes precedence — remove from one list): ${contradictions.join(', ')}`,
    });
  }

  // tenant_id required
  if (!policy.tenant_id || !policy.tenant_id.trim()) {
    errors.push({
      field: 'tenant_id',
      code: 'MISSING_TENANT_ID',
      message: 'tenant_id is required.',
    });
  }

  return errors;
}

// ─── Preview builder ──────────────────────────────────────────────────────────

/** Build a safe, deterministic policy preview. Does NOT execute live retrieval. */
export function buildRetrievalPolicyPreview(
  policy: RetrievalPolicyData,
  availableCorpora: CorpusEntry[],
): RetrievalPolicyPreviewData {
  const deniedSet = new Set(policy.denied_corpora);
  const allowedSet = new Set(policy.allowed_corpora);

  // Effective corpora: allowed list minus denied.
  // If allowedSet is empty, all available corpora are candidates (minus denied).
  const allIds = availableCorpora.map((c) => c.corpus_id);
  const candidates = allowedSet.size > 0 ? Array.from(allowedSet) : allIds;
  const effective = candidates.filter((id) => !deniedSet.has(id));

  const semanticActive =
    policy.semantic_enabled &&
    (policy.retrieval_strategy === 'semantic' ||
      policy.retrieval_strategy === 'hybrid' ||
      policy.retrieval_strategy === 'hybrid_rrf');

  const warnings: string[] = [];

  if (effective.length === 0) {
    warnings.push(
      'Effective corpus scope is empty. Retrieval will return no results.',
    );
  }
  if (policy.denied_corpora.length > 0 && effective.length === 0) {
    warnings.push(
      'All candidate corpora are denied. Retrieval will be blocked.',
    );
  }
  if (
    (policy.retrieval_strategy === 'semantic' ||
      policy.retrieval_strategy === 'hybrid' ||
      policy.retrieval_strategy === 'hybrid_rrf') &&
    !policy.semantic_enabled
  ) {
    warnings.push(
      `Strategy '${policy.retrieval_strategy}' requires semantic enabled. Retrieval may fall back to lexical or fail.`,
    );
  }
  if (policy.lexical_fallback_enabled && !policy.semantic_enabled) {
    warnings.push(
      'Lexical fallback is enabled but semantic is already disabled. Fallback has no effect.',
    );
  }

  return {
    effective_corpora: effective,
    denied_corpora: policy.denied_corpora,
    retrieval_strategy: policy.retrieval_strategy,
    semantic_active: semanticActive,
    fallback_active: policy.lexical_fallback_enabled,
    grounded_answer_required: policy.grounded_answer_required,
    effective_top_k: Math.min(
      Math.max(policy.top_k, TOP_K_MIN),
      TOP_K_MAX,
    ),
    empty_scope: effective.length === 0,
    warnings,
  };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

interface CorpusAccessBadgeProps {
  state: CorpusAccessState;
}

function CorpusAccessBadge({ state }: CorpusAccessBadgeProps) {
  const cfg: {
    label: string;
    className: string;
    Icon: React.ComponentType<{ className?: string }>;
  } = (() => {
    switch (state) {
      case 'allowed':
        return { label: 'Allowed', className: 'text-success', Icon: CheckCircle2 };
      case 'denied':
        return { label: 'Denied', className: 'text-danger', Icon: XCircle };
      case 'inherited':
        return { label: 'Inherited', className: 'text-muted', Icon: HelpCircle };
      case 'unavailable':
        return { label: 'Unavailable', className: 'text-muted/50', Icon: Lock };
      default:
        return { label: 'Unknown', className: 'text-muted/50', Icon: HelpCircle };
    }
  })();

  const { Icon } = cfg;

  return (
    <span
      className={`inline-flex items-center gap-1 text-xs font-medium ${cfg.className}`}
      aria-label={`corpus-access-state-${state}`}
    >
      <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
      {cfg.label}
    </span>
  );
}

// ─── CorpusPolicyMatrix ───────────────────────────────────────────────────────

interface CorpusPolicyMatrixProps {
  corpora: CorpusEntry[];
  allowedCorpora: string[];
  deniedCorpora: string[];
  onChange?: (allowed: string[], denied: string[]) => void;
  readOnly?: boolean;
}

export function CorpusPolicyMatrix({
  corpora,
  allowedCorpora,
  deniedCorpora,
  onChange,
  readOnly = false,
}: CorpusPolicyMatrixProps) {
  const allowedSet = new Set(allowedCorpora);
  const deniedSet = new Set(deniedCorpora);

  function deriveState(corpusId: string): CorpusAccessState {
    if (deniedSet.has(corpusId)) return 'denied';
    if (allowedSet.has(corpusId)) return 'allowed';
    return 'inherited';
  }

  function handleAllow(corpusId: string) {
    if (readOnly || !onChange) return;
    const newAllowed = allowedSet.has(corpusId)
      ? allowedCorpora.filter((id) => id !== corpusId)
      : [...allowedCorpora, corpusId];
    const newDenied = deniedCorpora.filter((id) => id !== corpusId);
    onChange(newAllowed, newDenied);
  }

  function handleDeny(corpusId: string) {
    if (readOnly || !onChange) return;
    const newDenied = deniedSet.has(corpusId)
      ? deniedCorpora.filter((id) => id !== corpusId)
      : [...deniedCorpora, corpusId];
    const newAllowed = allowedCorpora.filter((id) => id !== corpusId);
    onChange(newAllowed, newDenied);
  }

  if (corpora.length === 0) {
    return (
      <div
        className="flex flex-col items-center gap-2 py-6 text-center"
        aria-label="corpus-policy-matrix-empty"
      >
        <Layers className="h-6 w-6 text-muted/30" aria-hidden="true" />
        <p className="text-xs text-muted">No corpora available for this tenant.</p>
      </div>
    );
  }

  return (
    <div aria-label="corpus-policy-matrix">
      <table className="w-full text-xs" role="table" aria-label="Corpus access policy table">
        <thead>
          <tr className="border-b border-border">
            <th className="pb-2 text-left font-semibold text-muted/60" scope="col">
              Corpus
            </th>
            <th className="pb-2 text-left font-semibold text-muted/60" scope="col">
              State
            </th>
            {!readOnly && (
              <th className="pb-2 text-right font-semibold text-muted/60" scope="col">
                Actions
              </th>
            )}
          </tr>
        </thead>
        <tbody className="divide-y divide-border/50">
          {corpora.map((corpus) => {
            const state = deriveState(corpus.corpus_id);
            return (
              <tr
                key={corpus.corpus_id}
                aria-label={`corpus-row-${corpus.corpus_id}`}
                className="py-1"
              >
                <td className="py-1.5 pr-2">
                  <span
                    className="font-mono text-[10px] text-foreground/80"
                    aria-label="corpus-id"
                  >
                    {corpus.corpus_id}
                  </span>
                  {corpus.name && (
                    <span className="ml-1.5 text-[10px] text-muted">
                      ({corpus.name})
                    </span>
                  )}
                </td>
                <td className="py-1.5 pr-2">
                  <CorpusAccessBadge state={state} />
                </td>
                {!readOnly && (
                  <td className="py-1.5 text-right">
                    <div className="inline-flex gap-1">
                      <button
                        type="button"
                        onClick={() => handleAllow(corpus.corpus_id)}
                        aria-label={`allow-corpus-${corpus.corpus_id}`}
                        aria-pressed={state === 'allowed'}
                        className={`rounded px-2 py-0.5 text-[10px] font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary ${
                          state === 'allowed'
                            ? 'bg-success/10 text-success'
                            : 'bg-surface-2 text-muted hover:bg-surface-2/80 hover:text-foreground'
                        }`}
                      >
                        Allow
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDeny(corpus.corpus_id)}
                        aria-label={`deny-corpus-${corpus.corpus_id}`}
                        aria-pressed={state === 'denied'}
                        className={`rounded px-2 py-0.5 text-[10px] font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary ${
                          state === 'denied'
                            ? 'bg-danger/10 text-danger'
                            : 'bg-surface-2 text-muted hover:bg-surface-2/80 hover:text-foreground'
                        }`}
                      >
                        Deny
                      </button>
                    </div>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>

      {/* Effective scope note */}
      <p className="mt-2 text-[10px] text-muted/60" aria-label="corpus-scope-note">
        Denied corpora override allowed corpora. Empty allowed list = all non-denied tenant corpora.
        Cross-tenant corpora are never shown.
      </p>
    </div>
  );
}

// ─── RetrievalStrategyPanel ───────────────────────────────────────────────────

interface RetrievalStrategyPanelProps {
  strategy: RetrievalStrategy;
  semanticEnabled: boolean;
  lexicalFallbackEnabled: boolean;
  fallbackStrategy: RetrievalStrategy | null;
  rerankingEnabled: boolean;
  onChange?: (updates: {
    strategy?: RetrievalStrategy;
    semanticEnabled?: boolean;
    lexicalFallbackEnabled?: boolean;
    fallbackStrategy?: RetrievalStrategy | null;
    rerankingEnabled?: boolean;
  }) => void;
  readOnly?: boolean;
}

const STRATEGY_LABELS: Record<RetrievalStrategy, string> = {
  lexical: 'Lexical (keyword-based)',
  semantic: 'Semantic (embedding-based)',
  hybrid: 'Hybrid (lexical + semantic)',
  hybrid_rrf: 'Hybrid RRF (reciprocal rank fusion)',
};

const STRATEGY_DESCRIPTIONS: Record<RetrievalStrategy, string> = {
  lexical: 'BM25-style term matching. No embedding model required. Fail-safe default.',
  semantic: 'Dense vector similarity search. Requires semantic enabled and embedding provider.',
  hybrid: 'Combines lexical and semantic scores. Requires semantic enabled.',
  hybrid_rrf: 'Reciprocal Rank Fusion over lexical and semantic results. Requires semantic enabled.',
};

export function RetrievalStrategyPanel({
  strategy,
  semanticEnabled,
  lexicalFallbackEnabled,
  fallbackStrategy,
  rerankingEnabled,
  onChange,
  readOnly = false,
}: RetrievalStrategyPanelProps) {
  const semanticStrategy =
    strategy === 'semantic' || strategy === 'hybrid' || strategy === 'hybrid_rrf';

  return (
    <div className="space-y-3" aria-label="retrieval-strategy-panel">

      {/* Strategy select */}
      <div>
        <label
          htmlFor="retrieval-strategy-select"
          className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-muted/60"
        >
          Retrieval Strategy
        </label>
        {readOnly ? (
          <div
            className="rounded border border-border bg-surface-2 px-2.5 py-1.5"
            aria-label="retrieval-strategy-display"
          >
            <p className="text-xs font-medium text-foreground">
              {STRATEGY_LABELS[strategy]}
            </p>
            <p className="text-[10px] text-muted">{STRATEGY_DESCRIPTIONS[strategy]}</p>
          </div>
        ) : (
          <select
            id="retrieval-strategy-select"
            value={strategy}
            disabled={readOnly}
            onChange={(e) =>
              onChange?.({ strategy: e.target.value as RetrievalStrategy })
            }
            aria-label="retrieval-strategy-select"
            className="w-full rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {RETRIEVAL_STRATEGIES.map((s) => (
              <option key={s} value={s}>
                {STRATEGY_LABELS[s]}
              </option>
            ))}
          </select>
        )}
        {!readOnly && (
          <p className="mt-0.5 text-[10px] text-muted" aria-label="strategy-description">
            {STRATEGY_DESCRIPTIONS[strategy]}
          </p>
        )}
      </div>

      {/* Semantic enabled */}
      <div className="flex items-start gap-2" aria-label="semantic-enabled-control">
        {readOnly ? (
          <span
            className={`mt-0.5 text-xs font-medium ${semanticEnabled ? 'text-success' : 'text-muted'}`}
            aria-label="semantic-enabled-display"
          >
            {semanticEnabled ? 'Semantic: Enabled' : 'Semantic: Disabled'}
          </span>
        ) : (
          <>
            <input
              id="semantic-enabled-checkbox"
              type="checkbox"
              checked={semanticEnabled}
              onChange={(e) => onChange?.({ semanticEnabled: e.target.checked })}
              aria-label="Enable semantic retrieval"
              className="mt-0.5 h-3.5 w-3.5 rounded border-border text-primary focus:ring-1 focus:ring-primary"
            />
            <label
              htmlFor="semantic-enabled-checkbox"
              className="text-xs text-foreground"
            >
              Semantic retrieval enabled
              <span className="ml-1 text-[10px] text-muted">
                (required for semantic, hybrid, hybrid_rrf strategies)
              </span>
            </label>
          </>
        )}
      </div>

      {/* Semantic / strategy warning */}
      {semanticStrategy && !semanticEnabled && (
        <div
          className="flex items-start gap-1.5 rounded border border-warning/30 bg-warning/5 px-2 py-1.5"
          role="alert"
          aria-label="semantic-strategy-warning"
        >
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden="true" />
          <p className="text-[10px] text-warning">
            Strategy &apos;{strategy}&apos; requires semantic retrieval enabled.
            Retrieval may fall back to lexical or be denied.
          </p>
        </div>
      )}

      {/* Lexical fallback */}
      <div className="flex items-start gap-2" aria-label="lexical-fallback-control">
        {readOnly ? (
          <span
            className={`text-xs font-medium ${lexicalFallbackEnabled ? 'text-foreground' : 'text-muted'}`}
            aria-label="lexical-fallback-display"
          >
            {lexicalFallbackEnabled
              ? 'Lexical fallback: Enabled'
              : 'Lexical fallback: Disabled'}
          </span>
        ) : (
          <>
            <input
              id="lexical-fallback-checkbox"
              type="checkbox"
              checked={lexicalFallbackEnabled}
              onChange={(e) =>
                onChange?.({ lexicalFallbackEnabled: e.target.checked })
              }
              aria-label="Enable lexical fallback"
              className="mt-0.5 h-3.5 w-3.5 rounded border-border text-primary focus:ring-1 focus:ring-primary"
            />
            <label
              htmlFor="lexical-fallback-checkbox"
              className="text-xs text-foreground"
            >
              Lexical fallback when semantic unavailable
              <span className="ml-1 text-[10px] text-muted">
                (does not bypass denied corpora or tenant isolation)
              </span>
            </label>
          </>
        )}
      </div>

      {/* Reranking */}
      <div className="flex items-start gap-2" aria-label="reranking-control">
        {readOnly ? (
          <span
            className={`text-xs font-medium ${rerankingEnabled ? 'text-foreground' : 'text-muted'}`}
            aria-label="reranking-display"
          >
            {rerankingEnabled ? 'Reranking: Enabled' : 'Reranking: Disabled'}
          </span>
        ) : (
          <>
            <input
              id="reranking-checkbox"
              type="checkbox"
              checked={rerankingEnabled}
              onChange={(e) => onChange?.({ rerankingEnabled: e.target.checked })}
              aria-label="Enable reranking"
              className="mt-0.5 h-3.5 w-3.5 rounded border-border text-primary focus:ring-1 focus:ring-primary"
            />
            <label htmlFor="reranking-checkbox" className="text-xs text-foreground">
              Reranking enabled
              <span className="ml-1 text-[10px] text-muted">
                (post-retrieval candidate reordering; does not broaden corpus scope)
              </span>
            </label>
          </>
        )}
      </div>
    </div>
  );
}

// ─── GroundingEnforcementPanel ────────────────────────────────────────────────

interface GroundingEnforcementPanelProps {
  groundedAnswerRequired: boolean;
  /** Repo law: grounded-answer enforcement is always on in prod.
   *  If editing is not permitted, pass readOnly=true. */
  readOnly?: boolean;
  onChange?: (value: boolean) => void;
}

export function GroundingEnforcementPanel({
  groundedAnswerRequired,
  readOnly = false,
  onChange,
}: GroundingEnforcementPanelProps) {
  return (
    <div className="space-y-2" aria-label="grounding-enforcement-panel">
      <div className="flex items-start gap-2">
        {groundedAnswerRequired ? (
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden="true" />
        ) : (
          <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
        )}
        <div className="flex-1">
          <p className="text-xs font-medium text-foreground" aria-label="grounding-state-label">
            {groundedAnswerRequired
              ? 'Grounded-answer enforcement: Active'
              : 'Grounded-answer enforcement: Relaxed'}
          </p>
          <p className="text-[10px] text-muted">
            {groundedAnswerRequired
              ? 'Answers require retrieved context. Ungrounded answers are suppressed.'
              : 'Answers may be generated without retrieved context. Not recommended for production.'}
          </p>
        </div>
        {!readOnly && (
          <input
            id="grounded-answer-checkbox"
            type="checkbox"
            checked={groundedAnswerRequired}
            onChange={(e) => onChange?.(e.target.checked)}
            aria-label="Require grounded answer"
            className="mt-0.5 h-3.5 w-3.5 shrink-0 rounded border-border text-primary focus:ring-1 focus:ring-primary"
          />
        )}
      </div>

      {/* Enforcement note */}
      {readOnly && (
        <p
          className="text-[10px] text-muted/60"
          aria-label="grounding-enforcement-note"
        >
          Grounded-answer enforcement cannot be disabled in this deployment.
          Contact your platform administrator to change grounding policy.
        </p>
      )}

      {!groundedAnswerRequired && !readOnly && (
        <div
          className="flex items-start gap-1.5 rounded border border-warning/30 bg-warning/5 px-2 py-1.5"
          role="alert"
          aria-label="grounding-disabled-warning"
        >
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden="true" />
          <p className="text-[10px] text-warning">
            Disabling grounded-answer enforcement allows AI responses without
            source citation. This weakens answer accuracy guarantees. Use only
            with explicit operator approval.
          </p>
        </div>
      )}
    </div>
  );
}

// ─── RetrievalFallbackPanel ───────────────────────────────────────────────────

interface RetrievalFallbackPanelProps {
  lexicalFallbackEnabled: boolean;
  fallbackStrategy: RetrievalStrategy | null;
  readOnly?: boolean;
  onChange?: (updates: {
    lexicalFallbackEnabled?: boolean;
    fallbackStrategy?: RetrievalStrategy | null;
  }) => void;
}

export function RetrievalFallbackPanel({
  lexicalFallbackEnabled,
  fallbackStrategy,
  readOnly = false,
  onChange,
}: RetrievalFallbackPanelProps) {
  return (
    <div className="space-y-2" aria-label="retrieval-fallback-panel">
      <p className="text-[10px] text-muted">
        Fallback behavior does not bypass denied corpora, tenant isolation, or
        provenance enforcement.
      </p>

      <div className="flex items-start gap-2">
        {readOnly ? (
          <span
            className={`text-xs font-medium ${lexicalFallbackEnabled ? 'text-foreground' : 'text-muted'}`}
            aria-label="fallback-state-display"
          >
            {lexicalFallbackEnabled
              ? 'Lexical fallback: Enabled'
              : 'Lexical fallback: Disabled'}
          </span>
        ) : (
          <>
            <input
              id="fallback-lexical-checkbox"
              type="checkbox"
              checked={lexicalFallbackEnabled}
              onChange={(e) =>
                onChange?.({ lexicalFallbackEnabled: e.target.checked })
              }
              aria-label="Enable lexical fallback"
              className="mt-0.5 h-3.5 w-3.5 shrink-0 rounded border-border text-primary focus:ring-1 focus:ring-primary"
            />
            <label
              htmlFor="fallback-lexical-checkbox"
              className="text-xs text-foreground"
            >
              Enable lexical fallback when semantic unavailable
            </label>
          </>
        )}
      </div>

      {lexicalFallbackEnabled && (
        <div className="mt-1">
          <label
            htmlFor="fallback-strategy-select"
            className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Fallback Strategy
          </label>
          {readOnly ? (
            <span
              className="text-xs text-foreground"
              aria-label="fallback-strategy-display"
            >
              {fallbackStrategy ?? 'lexical (default)'}
            </span>
          ) : (
            <select
              id="fallback-strategy-select"
              value={fallbackStrategy ?? 'lexical'}
              onChange={(e) =>
                onChange?.({
                  fallbackStrategy: e.target.value as RetrievalStrategy,
                })
              }
              aria-label="fallback-strategy-select"
              className="w-full rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              {RETRIEVAL_STRATEGIES.map((s) => (
                <option key={s} value={s}>
                  {STRATEGY_LABELS[s]}
                </option>
              ))}
            </select>
          )}
        </div>
      )}
    </div>
  );
}

// ─── RetrievalPolicyPreview ───────────────────────────────────────────────────

interface RetrievalPolicyPreviewProps {
  preview: RetrievalPolicyPreviewData;
  topK: number;
}

export function RetrievalPolicyPreview({
  preview,
  topK,
}: RetrievalPolicyPreviewProps) {
  return (
    <div
      className="space-y-3 rounded border border-border bg-surface-2/40 p-3"
      aria-label="retrieval-policy-preview"
    >
      <div className="flex items-center gap-1.5">
        <Shield className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
        <p className="text-xs font-semibold text-foreground">Policy Preview</p>
        <span className="ml-auto rounded bg-primary/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-primary">
          Preview only
        </span>
      </div>

      <p className="text-[10px] text-muted">
        This preview explains effective policy state. It does not execute live retrieval and does not reflect actual query results.
      </p>

      {/* Warnings */}
      {preview.warnings.length > 0 && (
        <div className="space-y-1" aria-label="preview-warnings">
          {preview.warnings.map((warning) => (
            <div
              key={warning}
              className="flex items-start gap-1.5 rounded border border-warning/30 bg-warning/5 px-2 py-1"
              role="alert"
            >
              <AlertCircle
                className="mt-0.5 h-3 w-3 shrink-0 text-warning"
                aria-hidden="true"
              />
              <p className="text-[10px] text-warning">{warning}</p>
            </div>
          ))}
        </div>
      )}

      {/* Preview fields */}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5">
        <div>
          <dt className="text-[10px] font-semibold text-muted/60">Strategy</dt>
          <dd
            className="text-xs text-foreground"
            aria-label="preview-strategy"
          >
            {preview.retrieval_strategy}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold text-muted/60">Top-K</dt>
          <dd
            className="text-xs text-foreground"
            aria-label="preview-top-k"
          >
            {preview.effective_top_k}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold text-muted/60">Semantic</dt>
          <dd
            className={`text-xs font-medium ${preview.semantic_active ? 'text-success' : 'text-muted'}`}
            aria-label="preview-semantic-active"
          >
            {preview.semantic_active ? 'Active' : 'Inactive'}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold text-muted/60">Grounded Answer</dt>
          <dd
            className={`text-xs font-medium ${preview.grounded_answer_required ? 'text-success' : 'text-warning'}`}
            aria-label="preview-grounded-answer"
          >
            {preview.grounded_answer_required ? 'Required' : 'Not required'}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold text-muted/60">Lexical Fallback</dt>
          <dd
            className={`text-xs ${preview.fallback_active ? 'text-foreground' : 'text-muted'}`}
            aria-label="preview-fallback"
          >
            {preview.fallback_active ? 'Enabled' : 'Disabled'}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold text-muted/60">Corpus Scope</dt>
          <dd
            className={`text-xs font-medium ${preview.empty_scope ? 'text-danger' : 'text-foreground'}`}
            aria-label="preview-corpus-scope"
          >
            {preview.empty_scope
              ? 'Empty — no retrieval'
              : `${preview.effective_corpora.length} corpus${preview.effective_corpora.length !== 1 ? 'es' : ''}`}
          </dd>
        </div>
      </dl>

      {/* Denied corpora list */}
      {preview.denied_corpora.length > 0 && (
        <div aria-label="preview-denied-corpora">
          <p className="mb-0.5 text-[10px] font-semibold text-muted/60">
            Denied Corpora ({preview.denied_corpora.length})
          </p>
          <ul className="space-y-0.5" aria-label="denied-corpora-list">
            {preview.denied_corpora.map((id) => (
              <li
                key={id}
                className="flex items-center gap-1 font-mono text-[10px] text-danger/70"
                aria-label={`denied-corpus-${id}`}
              >
                <XCircle className="h-2.5 w-2.5 shrink-0" aria-hidden="true" />
                {id}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Legal note */}
      <p className="text-[10px] text-muted/50" aria-label="preview-legal-note">
        Preview reflects configured policy state only. No legal or compliance approval is implied. Actual retrieval behavior depends on backend enforcement.
      </p>
    </div>
  );
}

// ─── RetrievalPolicyAuditSummary ──────────────────────────────────────────────

interface RetrievalPolicyAuditSummaryProps {
  entries?: RetrievalPolicyAuditEntry[] | null;
  policy?: RetrievalPolicyData | null;
}

export function RetrievalPolicyAuditSummary({
  entries,
  policy,
}: RetrievalPolicyAuditSummaryProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="space-y-2" aria-label="retrieval-policy-audit-summary">
      {/* Policy version / last updated */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px]">
        {policy?.policy_version != null && (
          <span
            className="text-muted"
            aria-label="policy-version"
          >
            Version: {policy.policy_version}
          </span>
        )}
        {policy?.updated_at && (
          <span className="text-muted" aria-label="policy-updated-at">
            Last updated: {policy.updated_at}
          </span>
        )}
        {policy?.updated_by && (
          <span className="text-muted" aria-label="policy-updated-by">
            Updated by: {policy.updated_by}
          </span>
        )}
      </div>

      {/* Audit entries */}
      {entries && entries.length > 0 && (
        <div>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="flex items-center gap-1.5 text-[10px] font-medium text-muted hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
            aria-expanded={expanded}
            aria-controls="audit-entries-list"
            aria-label="toggle-audit-entries"
          >
            {expanded ? (
              <ChevronDown className="h-3 w-3" aria-hidden="true" />
            ) : (
              <ChevronRight className="h-3 w-3" aria-hidden="true" />
            )}
            Audit log ({entries.length} entr{entries.length !== 1 ? 'ies' : 'y'})
          </button>

          {expanded && (
            <ul
              id="audit-entries-list"
              className="mt-1.5 space-y-1"
              aria-label="audit-entries-list"
            >
              {entries.map((entry, idx) => (
                <li
                  key={`${entry.timestamp}-${idx}`}
                  className="rounded border border-border/50 bg-surface-2/30 px-2 py-1.5 text-[10px]"
                  aria-label={`audit-entry-${idx}`}
                >
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-muted/60">
                    <span aria-label="audit-timestamp">{entry.timestamp}</span>
                    {entry.actor && (
                      <span aria-label="audit-actor">Actor: {entry.actor}</span>
                    )}
                    {entry.request_id && (
                      <span
                        className="font-mono"
                        aria-label="audit-request-id"
                      >
                        req: {entry.request_id}
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {entry.changed_fields.map((field) => (
                      <span
                        key={field}
                        className="rounded bg-surface-2 px-1 py-0.5 font-mono text-[9px] text-foreground/70"
                        aria-label={`changed-field-${field}`}
                      >
                        {field}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {(!entries || entries.length === 0) && (
        <p className="text-[10px] text-muted/50" aria-label="no-audit-entries">
          No policy change audit entries available.
        </p>
      )}
    </div>
  );
}

// ─── RetrievalPolicyEditor ────────────────────────────────────────────────────

interface RetrievalPolicyEditorProps {
  policy: RetrievalPolicyData;
  availableCorpora: CorpusEntry[];
  validationErrors?: RetrievalPolicyValidationError[] | null;
  saving?: boolean;
  onChange: (updates: Partial<RetrievalPolicyData>) => void;
  onSave: () => void;
  onCancel: () => void;
}

export function RetrievalPolicyEditor({
  policy,
  availableCorpora,
  validationErrors,
  saving = false,
  onChange,
  onSave,
  onCancel,
}: RetrievalPolicyEditorProps) {
  const [tab, setTab] = useState<'corpus' | 'strategy' | 'grounding' | 'fallback'>(
    'corpus',
  );

  const hasErrors = validationErrors && validationErrors.length > 0;

  function fieldErrors(field: string): RetrievalPolicyValidationError[] {
    return (validationErrors ?? []).filter((e) => e.field === field);
  }

  return (
    <div className="space-y-4" aria-label="retrieval-policy-editor">

      {/* Global validation errors */}
      {hasErrors && (
        <div
          className="space-y-1 rounded border border-danger/30 bg-danger/5 p-3"
          role="alert"
          aria-label="validation-error-summary"
        >
          <p className="text-xs font-semibold text-danger">
            Policy validation failed. Fix the following before saving:
          </p>
          <ul className="space-y-0.5">
            {validationErrors!.map((err) => (
              <li
                key={`${err.field}-${err.code}`}
                className="text-[10px] text-danger"
                aria-label={`validation-error-${err.field}`}
              >
                [{err.code}] {err.field}: {err.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Editor tabs */}
      <div
        className="flex gap-0.5 rounded border border-border bg-surface-2/40 p-0.5"
        role="tablist"
        aria-label="policy-editor-tabs"
      >
        {(
          [
            { id: 'corpus', label: 'Corpus Access' },
            { id: 'strategy', label: 'Strategy' },
            { id: 'grounding', label: 'Grounding' },
            { id: 'fallback', label: 'Fallback' },
          ] as const
        ).map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            aria-controls={`tab-panel-${t.id}`}
            onClick={() => setTab(t.id)}
            className={`flex-1 rounded px-2 py-1 text-[10px] font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary ${
              tab === t.id
                ? 'bg-surface text-foreground shadow-sm'
                : 'text-muted hover:text-foreground'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab panels */}
      {tab === 'corpus' && (
        <div
          id="tab-panel-corpus"
          role="tabpanel"
          aria-label="corpus-access-panel"
        >
          <CorpusPolicyMatrix
            corpora={availableCorpora}
            allowedCorpora={policy.allowed_corpora}
            deniedCorpora={policy.denied_corpora}
            onChange={(allowed, denied) =>
              onChange({ allowed_corpora: allowed, denied_corpora: denied })
            }
          />
        </div>
      )}

      {tab === 'strategy' && (
        <div
          id="tab-panel-strategy"
          role="tabpanel"
          aria-label="strategy-panel"
          className="space-y-4"
        >
          {/* Top-K */}
          <div>
            <label
              htmlFor="top-k-input"
              className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Top-K (retrieval depth)
            </label>
            <input
              id="top-k-input"
              type="number"
              min={TOP_K_MIN}
              max={TOP_K_MAX}
              value={policy.top_k}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                onChange({ top_k: Number.isNaN(v) ? policy.top_k : v });
              }}
              aria-label="top-k-input"
              aria-describedby="top-k-description"
              className={`w-24 rounded border px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary ${
                fieldErrors('top_k').length > 0
                  ? 'border-danger bg-danger/5'
                  : 'border-border bg-surface-2'
              }`}
            />
            <p
              id="top-k-description"
              className="mt-0.5 text-[10px] text-muted"
            >
              Allowed range: {TOP_K_MIN}–{TOP_K_MAX}. Determines maximum
              retrieved chunks. Backend enforces max_top_k from policy.
            </p>
            {fieldErrors('top_k').map((e) => (
              <p
                key={e.code}
                className="mt-0.5 text-[10px] text-danger"
                role="alert"
                aria-label={`top-k-error-${e.code}`}
              >
                {e.message}
              </p>
            ))}
          </div>

          <RetrievalStrategyPanel
            strategy={policy.retrieval_strategy}
            semanticEnabled={policy.semantic_enabled}
            lexicalFallbackEnabled={policy.lexical_fallback_enabled}
            fallbackStrategy={policy.fallback_strategy}
            rerankingEnabled={policy.reranking_enabled}
            onChange={(updates) => {
              const patch: Partial<RetrievalPolicyData> = {};
              if (updates.strategy !== undefined)
                patch.retrieval_strategy = updates.strategy;
              if (updates.semanticEnabled !== undefined)
                patch.semantic_enabled = updates.semanticEnabled;
              if (updates.lexicalFallbackEnabled !== undefined)
                patch.lexical_fallback_enabled = updates.lexicalFallbackEnabled;
              if (updates.fallbackStrategy !== undefined)
                patch.fallback_strategy = updates.fallbackStrategy;
              if (updates.rerankingEnabled !== undefined)
                patch.reranking_enabled = updates.rerankingEnabled;
              onChange(patch);
            }}
          />
        </div>
      )}

      {tab === 'grounding' && (
        <div
          id="tab-panel-grounding"
          role="tabpanel"
          aria-label="grounding-panel"
        >
          <GroundingEnforcementPanel
            groundedAnswerRequired={policy.grounded_answer_required}
            readOnly={false}
            onChange={(v) => onChange({ grounded_answer_required: v })}
          />
        </div>
      )}

      {tab === 'fallback' && (
        <div
          id="tab-panel-fallback"
          role="tabpanel"
          aria-label="fallback-panel"
        >
          <RetrievalFallbackPanel
            lexicalFallbackEnabled={policy.lexical_fallback_enabled}
            fallbackStrategy={policy.fallback_strategy}
            onChange={(updates) => {
              const patch: Partial<RetrievalPolicyData> = {};
              if (updates.lexicalFallbackEnabled !== undefined)
                patch.lexical_fallback_enabled = updates.lexicalFallbackEnabled;
              if (updates.fallbackStrategy !== undefined)
                patch.fallback_strategy = updates.fallbackStrategy;
              onChange(patch);
            }}
          />
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-end gap-2 border-t border-border pt-3">
        <button
          type="button"
          onClick={onCancel}
          disabled={saving}
          aria-label="cancel-policy-edit"
          className="rounded border border-border px-3 py-1.5 text-xs font-medium text-muted transition-colors hover:bg-surface-2 hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={saving || !!hasErrors}
          aria-label="save-retrieval-policy"
          className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-white transition-opacity hover:opacity-90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save Policy'}
        </button>
      </div>
    </div>
  );
}

// ─── RetrievalPolicyCenter ────────────────────────────────────────────────────

export function RetrievalPolicyCenter({
  policy,
  availableCorpora = [],
  auditEntries,
  apiFailure = false,
  saving = false,
  validationErrors,
  onSave,
}: RetrievalPolicyCenterProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<RetrievalPolicyData | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [clientErrors, setClientErrors] = useState<RetrievalPolicyValidationError[]>([]);

  const safeCorpora: CorpusEntry[] = (availableCorpora ?? []).map((c) => ({
    corpus_id: c.corpus_id,
    name: c.name ?? null,
    access_state: c.access_state,
  }));

  // ── Error / loading states ────────────────────────────────────────────────

  if (apiFailure) {
    return (
      <div
        className="flex flex-col items-center gap-3 py-10 text-center"
        aria-label="policy-api-failure"
        role="alert"
      >
        <AlertCircle className="h-8 w-8 text-danger/50" aria-hidden="true" />
        <p className="text-sm font-medium text-foreground">
          Retrieval policy unavailable
        </p>
        <p className="max-w-sm text-xs text-muted">
          The retrieval policy could not be loaded. Verify API connectivity and
          refresh. Policy controls are disabled until the policy loads
          successfully.
        </p>
      </div>
    );
  }

  if (!policy) {
    return (
      <div
        className="flex flex-col items-center gap-3 py-10 text-center"
        aria-label="policy-not-configured"
      >
        <Shield className="h-8 w-8 text-muted/30" aria-hidden="true" />
        <p className="text-sm font-medium text-foreground">
          No retrieval policy configured
        </p>
        <p className="max-w-sm text-xs text-muted">
          No retrieval governance policy has been loaded for this tenant.
          Policy controls appear here once a policy is available from the
          backend.
        </p>
      </div>
    );
  }

  // ── Edit mode helpers ─────────────────────────────────────────────────────

  function startEdit() {
    setDraft({ ...policy! });
    setClientErrors([]);
    setEditing(true);
    setShowPreview(false);
  }

  function cancelEdit() {
    setDraft(null);
    setClientErrors([]);
    setEditing(false);
  }

  function handleChange(updates: Partial<RetrievalPolicyData>) {
    if (!draft) return;
    const updated = { ...draft, ...updates };
    setDraft(updated);
    // Re-validate on every change so errors are immediate
    setClientErrors(validateRetrievalPolicy(updated));
  }

  function handleSave() {
    if (!draft) return;
    const errors = validateRetrievalPolicy(draft);
    if (errors.length > 0) {
      setClientErrors(errors);
      return;
    }
    setClientErrors([]);
    onSave?.(draft);
    setEditing(false);
  }

  // Active policy for display / preview
  const activePolicyForPreview = editing && draft ? draft : policy;
  const preview = buildRetrievalPolicyPreview(activePolicyForPreview, safeCorpora);
  const mergedErrors =
    clientErrors.length > 0
      ? clientErrors
      : (validationErrors ?? []);

  return (
    <div className="space-y-4" aria-label="retrieval-policy-center">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />
          <div>
            <p className="text-xs font-semibold text-foreground">
              Retrieval Policy
            </p>
            <p className="text-[10px] text-muted">
              Tenant: <span className="font-mono">{policy.tenant_id}</span>
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setShowPreview((v) => !v)}
            aria-expanded={showPreview}
            aria-label="toggle-policy-preview"
            className="rounded border border-border px-2.5 py-1 text-[10px] font-medium text-muted transition-colors hover:bg-surface-2 hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
          >
            {showPreview ? 'Hide Preview' : 'Show Preview'}
          </button>
          {!editing && (
            <button
              type="button"
              onClick={startEdit}
              aria-label="edit-retrieval-policy"
              className="rounded bg-primary px-2.5 py-1 text-[10px] font-medium text-white transition-opacity hover:opacity-90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
            >
              Edit Policy
            </button>
          )}
        </div>
      </div>

      {/* Preview panel */}
      {showPreview && (
        <RetrievalPolicyPreview
          preview={preview}
          topK={activePolicyForPreview.top_k}
        />
      )}

      {/* Editor or read-only display */}
      {editing && draft ? (
        <RetrievalPolicyEditor
          policy={draft}
          availableCorpora={safeCorpora}
          validationErrors={mergedErrors}
          saving={saving}
          onChange={handleChange}
          onSave={handleSave}
          onCancel={cancelEdit}
        />
      ) : (
        <div className="space-y-4" aria-label="policy-read-only-view">

          {/* Corpus matrix (read-only) */}
          <section aria-labelledby="corpus-section-heading">
            <h3
              id="corpus-section-heading"
              className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Corpus Access
            </h3>
            <CorpusPolicyMatrix
              corpora={safeCorpora}
              allowedCorpora={policy.allowed_corpora}
              deniedCorpora={policy.denied_corpora}
              readOnly
            />
          </section>

          {/* Strategy (read-only) */}
          <section aria-labelledby="strategy-section-heading">
            <h3
              id="strategy-section-heading"
              className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Strategy &amp; Controls
            </h3>

            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
              <div>
                <dt className="text-[10px] text-muted/60">Strategy</dt>
                <dd
                  className="font-medium text-foreground"
                  aria-label="policy-strategy-display"
                >
                  {policy.retrieval_strategy}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] text-muted/60">Top-K</dt>
                <dd
                  className="font-medium text-foreground"
                  aria-label="policy-top-k-display"
                >
                  {policy.top_k}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] text-muted/60">Semantic</dt>
                <dd
                  className={`font-medium ${policy.semantic_enabled ? 'text-success' : 'text-muted'}`}
                  aria-label="policy-semantic-display"
                >
                  {policy.semantic_enabled ? 'Enabled' : 'Disabled'}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] text-muted/60">Reranking</dt>
                <dd
                  className={`font-medium ${policy.reranking_enabled ? 'text-foreground' : 'text-muted'}`}
                  aria-label="policy-reranking-display"
                >
                  {policy.reranking_enabled ? 'Enabled' : 'Disabled'}
                </dd>
              </div>
            </dl>
          </section>

          {/* Grounding (read-only) */}
          <section aria-labelledby="grounding-section-heading">
            <h3
              id="grounding-section-heading"
              className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Grounded Answer Enforcement
            </h3>
            <GroundingEnforcementPanel
              groundedAnswerRequired={policy.grounded_answer_required}
              readOnly
            />
          </section>

          {/* Fallback (read-only) */}
          <section aria-labelledby="fallback-section-heading">
            <h3
              id="fallback-section-heading"
              className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Fallback Controls
            </h3>
            <RetrievalFallbackPanel
              lexicalFallbackEnabled={policy.lexical_fallback_enabled}
              fallbackStrategy={policy.fallback_strategy}
              readOnly
            />
          </section>

          {/* Audit summary */}
          <section aria-labelledby="audit-section-heading">
            <h3
              id="audit-section-heading"
              className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Audit &amp; Change Log
            </h3>
            <RetrievalPolicyAuditSummary
              entries={auditEntries}
              policy={policy}
            />
          </section>
        </div>
      )}
    </div>
  );
}
