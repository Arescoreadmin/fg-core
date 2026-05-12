# Retrieval Policy Engine

PR 27 adds tenant-scoped retrieval governance for persisted RAG. The policy
engine controls corpus scope, retrieval depth, retrieval strategy eligibility,
semantic usage, lexical fallback, and no-context answer behavior before any
retrieval query is executed.

This is retrieval governance only. It does not add UI, billing, auth-provider
changes, provider routing changes, reranking, external policy engines, or
retrieval score changes beyond policy filtering and `top_k` clamping.

## Policy Model

Retrieval policy is part of `services.ai.policy.AiRagRules`.

Supported fields:

- `allowed_corpus_ids`: corpus allowlist. Empty means no allowlist restriction.
- `denied_corpus_ids`: corpus denylist. Denied corpora are never retrieved.
- `max_top_k`: maximum returned context depth; requested depth is clamped.
- `allowed_retrieval_strategies`: allowed strategy IDs.
- `require_grounded_context`: blocks no-context answers when true.
- `allow_lexical_fallback`: permits fallback from disallowed semantic strategies
  to lexical retrieval when lexical is allowed.
- `allow_semantic`: enables semantic, hybrid, and hybrid RRF strategy use.
- `allow_no_context_answer`: explicitly permits no-context answers.

Legacy policy files that only contain the earlier `enabled`,
`require_grounded_response`, and `no_answer_on_ungrounded` fields still load.
The new fields receive safe defaults:

- strategy defaults to `lexical`
- semantic is disabled
- lexical fallback is disabled
- empty persisted retrieval is allowed to return the existing safe no-answer
  path unless `require_grounded_context` is explicitly enabled
- `max_top_k` defaults to `4`

## Enforcement

`services.ai.retrieval_policy.evaluate_retrieval_policy()` evaluates policy
before persisted retrieval runs.

The decision:

- validates tenant ID and `top_k`
- clamps `top_k` to `max_top_k`
- resolves strategy eligibility before retrieval
- filters requested corpora through allowlist, denylist, and tenant ownership
- treats unknown or wrong-tenant corpus IDs as empty scope
- prevents denied or unknown corpus scopes from broadening to all tenant corpora

`services.ai.rag_context.retrieve_persisted_rag_context()` consumes the decision
and only calls retrieval with the effective corpus IDs and clamped depth. If a
policy-scoped request resolves to no corpus IDs, retrieval is skipped rather
than invoked with an empty filter that would otherwise mean all tenant corpora.

## Tenant Governance

Cross-tenant access remains denied by the existing persisted RAG SQL and corpus
store ownership checks. The policy engine adds a pre-query ownership check with
`get_corpus(db, tenant_id, corpus_id)` so a foreign corpus ID resolves to empty
scope for the caller.

Denied corpora take precedence over allowed corpora. Requested corpora are never
expanded beyond the caller's explicit list. When no corpus is requested, an
allowlist constrains retrieval to allowed corpora; a denylist constrains
retrieval to the tenant's remaining corpora.

## Strategy Controls

Allowed strategies are validated against:

- `lexical`
- `semantic`
- `hybrid`
- `hybrid_rrf`

Semantic-family strategies also require `allow_semantic=True`. If a semantic
strategy is requested but denied, the request fails closed unless
`allow_lexical_fallback=True` and lexical retrieval is allowed.

The persisted RAG service adapter routes the policy-approved effective strategy
to the matching retriever:

- `lexical` uses `api.rag_retrieval.retrieve_rag_context`
- `semantic` uses the existing semantic retrieval module with semantic-only
  weighting
- `hybrid` uses `api.rag_semantic_retrieval.retrieve_rag_context_hybrid`
- `hybrid_rrf` uses `api.rag_hybrid_retrieval.retrieve_rag_context_hybrid_rrf`

Semantic-family strategies require an explicit embedding provider from the
caller. The adapter does not create network-backed providers and does not alter
AI provider routing, answer generation, or reranking.

## No-Context Behavior

No-context behavior is explicit:

- `require_grounded_context=True` and `allow_no_context_answer=False` raises
  `RETRIEVAL_POLICY_NO_CONTEXT_DENIED` when retrieval returns no context.
- Setting `allow_no_context_answer=True` permits an empty context result.
- Setting `require_grounded_context=False` also permits no-context operation.

## Audit Safety

Every policy decision emits `ai.retrieval_policy.decision` with safe metadata:

- reason code
- allowed boolean
- requested and effective corpus counts
- requested and effective `top_k`
- requested and effective strategy
- allowlist and denylist counts
- grounded/no-context flags
- semantic/fallback flags

Audit metadata propagated through `services.ai.audit.build_ai_audit_metadata()`
contains the same safe decision fields. It never includes chunk text, raw
vectors, prompts, provider secrets, auth tokens, or policy file contents.

## Failure Modes

- Invalid policy file: fails closed through existing `AI_POLICY_INVALID`.
- Disabled RAG policy: retrieval denied with `RETRIEVAL_POLICY_DISABLED`.
- Disallowed strategy: retrieval denied with
  `RETRIEVAL_POLICY_STRATEGY_DENIED`, unless lexical fallback is explicitly
  allowed.
- Denied, unknown, or wrong-tenant corpus scope: resolves to empty context and
  cannot broaden to all corpora.
- Required grounded context with empty retrieval: raises
  `RETRIEVAL_POLICY_NO_CONTEXT_DENIED`.
