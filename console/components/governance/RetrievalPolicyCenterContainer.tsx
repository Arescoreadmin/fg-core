'use client';

import { useCallback, useEffect, useState } from 'react';

import {
  type CorpusEntry,
  type RetrievalPolicyAuditEntry,
  type RetrievalPolicyData,
  type RetrievalPolicyValidationError,
  RetrievalPolicyCenter,
  RETRIEVAL_STRATEGIES,
} from './RetrievalPolicyCenter';
import {
  type CorpusListEntry,
  type StoredRetrievalPolicy,
  getCorpora,
  getRetrievalPolicy,
  putRetrievalPolicy,
} from '@/lib/retrievalPolicyApi';

// ---------------------------------------------------------------------------
// Mapping: backend ↔ frontend policy shape
// ---------------------------------------------------------------------------

function toFrontendPolicy(stored: StoredRetrievalPolicy): RetrievalPolicyData {
  const strategies = stored.allowed_retrieval_strategies ?? ['lexical'];
  // Primary strategy: first non-lexical strategy, or lexical
  const primaryStrategy =
    (strategies.find(
      (s) => s !== 'lexical' && (RETRIEVAL_STRATEGIES as ReadonlyArray<string>).includes(s),
    ) as RetrievalPolicyData['retrieval_strategy']) ?? 'lexical';

  return {
    tenant_id: stored.tenant_id,
    allowed_corpora: stored.allowed_corpus_ids ?? [],
    denied_corpora: stored.denied_corpus_ids ?? [],
    retrieval_strategy: primaryStrategy,
    top_k: stored.max_top_k ?? 4,
    semantic_enabled: stored.allow_semantic ?? false,
    grounded_answer_required: stored.require_grounded_response ?? true,
    lexical_fallback_enabled: stored.allow_lexical_fallback ?? false,
    fallback_strategy: null,
    reranking_enabled: stored.reranking_enabled ?? false,
    policy_version: stored.policy_version,
    updated_by: stored.updated_by ?? null,
    updated_at: stored.updated_at ?? null,
  };
}

function toBackendRequest(
  data: RetrievalPolicyData,
): Parameters<typeof putRetrievalPolicy>[0] {
  // Build allowed_retrieval_strategies: always include lexical + any semantic variants
  const strategies: string[] = ['lexical'];
  if (data.retrieval_strategy !== 'lexical') {
    strategies.push(data.retrieval_strategy);
  }
  if (data.semantic_enabled) {
    for (const s of ['semantic', 'hybrid', 'hybrid_rrf'] as const) {
      if (!strategies.includes(s)) strategies.push(s);
    }
  }

  return {
    rag_enabled: true,
    allowed_corpus_ids: data.allowed_corpora,
    denied_corpus_ids: data.denied_corpora,
    max_top_k: data.top_k,
    allowed_retrieval_strategies: strategies,
    require_grounded_response: data.grounded_answer_required,
    no_answer_on_ungrounded: true,
    require_grounded_context: false,
    allow_lexical_fallback: data.lexical_fallback_enabled,
    allow_semantic: data.semantic_enabled,
    allow_no_context_answer: true,
    reranking_enabled: data.reranking_enabled,
  };
}

function toCorpusEntries(list: CorpusListEntry[], policy: RetrievalPolicyData): CorpusEntry[] {
  const allowed = new Set(policy.allowed_corpora);
  const denied = new Set(policy.denied_corpora);
  return list.map((c) => {
    let access_state: CorpusEntry['access_state'] = 'inherited';
    if (denied.has(c.corpus_id)) access_state = 'denied';
    else if (allowed.has(c.corpus_id)) access_state = 'allowed';
    return { corpus_id: c.corpus_id, name: c.name, access_state };
  });
}

function parseBackendErrors(raw: unknown): RetrievalPolicyValidationError[] {
  if (!raw || typeof raw !== 'object') return [];
  const detail = (raw as { detail?: unknown }).detail;
  if (!detail || typeof detail !== 'object') return [];
  const errorsStr = (detail as { errors?: unknown }).errors;
  if (typeof errorsStr !== 'string') return [];

  return errorsStr.split(';').map((part) => {
    const [code, field, ...msgParts] = part.trim().split(':');
    return {
      code: code?.trim() ?? 'UNKNOWN',
      field: field?.trim() ?? 'unknown',
      message: msgParts.join(':').trim() || part.trim(),
    };
  });
}

// ---------------------------------------------------------------------------
// Container component
// ---------------------------------------------------------------------------

export function RetrievalPolicyCenterContainer() {
  const [policy, setPolicy] = useState<RetrievalPolicyData | null>(null);
  const [corpora, setCorpora] = useState<CorpusEntry[]>([]);
  const [auditEntries, setAuditEntries] = useState<RetrievalPolicyAuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiFailure, setApiFailure] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveErrors, setSaveErrors] = useState<RetrievalPolicyValidationError[]>([]);
  const [notConfigured, setNotConfigured] = useState(false);

  const fetchPolicy = useCallback(async () => {
    setLoading(true);
    setApiFailure(false);
    setNotConfigured(false);
    try {
      const [stored, corpusList] = await Promise.allSettled([
        getRetrievalPolicy(),
        getCorpora(),
      ]);

      let loadedPolicy: RetrievalPolicyData | null = null;
      if (stored.status === 'fulfilled') {
        loadedPolicy = toFrontendPolicy(stored.value);
        setPolicy(loadedPolicy);
      } else {
        const err = stored.reason as { code?: string; status?: number };
        if (err?.code === 'NOT_FOUND' || err?.status === 404) {
          setNotConfigured(true);
        } else {
          setApiFailure(true);
        }
      }

      if (corpusList.status === 'fulfilled') {
        setCorpora(
          loadedPolicy
            ? toCorpusEntries(corpusList.value, loadedPolicy)
            : corpusList.value.map((c) => ({
                corpus_id: c.corpus_id,
                name: c.name,
                access_state: 'inherited' as const,
              })),
        );
      }
      // corpus fetch failure is non-fatal: UI renders with empty list
    } catch {
      setApiFailure(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicy();
  }, [fetchPolicy]);

  const handleSave = useCallback(
    async (draft: RetrievalPolicyData) => {
      setSaving(true);
      setSaveErrors([]);
      try {
        const stored = await putRetrievalPolicy(toBackendRequest(draft));
        const saved = toFrontendPolicy(stored);
        setPolicy(saved);
        setNotConfigured(false);
        // Append audit entry for the change
        setAuditEntries((prev) => [
          {
            timestamp: stored.updated_at ?? new Date().toISOString(),
            actor: stored.updated_by ?? undefined,
            changed_fields: ['policy'],
            reason_code: 'POLICY_SAVED',
          },
          ...prev,
        ]);
        // Refresh corpus display with updated policy
        getCorpora()
          .then((list) => setCorpora(toCorpusEntries(list, saved)))
          .catch(() => {
            /* non-fatal */
          });
      } catch (err: unknown) {
        const errors = parseBackendErrors(err);
        if (errors.length > 0) {
          setSaveErrors(errors);
        } else {
          setSaveErrors([
            {
              code: 'SAVE_FAILED',
              field: 'policy',
              message:
                err instanceof Error
                  ? err.message
                  : 'Save failed — please retry.',
            },
          ]);
        }
      } finally {
        setSaving(false);
      }
    },
    [],
  );

  if (loading) {
    return (
      <div
        className="flex items-center justify-center py-8 text-xs text-muted"
        aria-label="retrieval-policy-loading"
        aria-busy="true"
      >
        Loading retrieval policy…
      </div>
    );
  }

  if (notConfigured && !policy) {
    return (
      <div
        className="flex flex-col items-center gap-2 py-6 text-center"
        aria-label="policy-not-configured"
      >
        <p className="text-sm font-medium text-foreground">
          No retrieval policy configured
        </p>
        <p className="max-w-sm text-xs text-muted">
          Use the editor below to create the initial policy for this tenant.
        </p>
        <RetrievalPolicyCenter
          policy={null}
          availableCorpora={corpora}
          saving={saving}
          validationErrors={saveErrors.length > 0 ? saveErrors : null}
          onSave={handleSave}
        />
      </div>
    );
  }

  if (apiFailure && !policy) {
    return (
      <div
        className="flex items-center justify-center py-6 text-xs text-muted"
        aria-label="retrieval-policy-api-failure"
      >
        Unable to load retrieval policy — backend unavailable.
      </div>
    );
  }

  return (
    <RetrievalPolicyCenter
      policy={policy}
      availableCorpora={corpora}
      auditEntries={auditEntries.length > 0 ? auditEntries : null}
      apiFailure={apiFailure}
      saving={saving}
      validationErrors={saveErrors.length > 0 ? saveErrors : null}
      onSave={handleSave}
    />
  );
}
