from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from api.rag_corpus_store import get_corpus, list_corpora
from services.ai.policy import AiRagRules

RETRIEVAL_POLICY_ALLOWED = "RETRIEVAL_POLICY_ALLOWED"
RETRIEVAL_POLICY_EMPTY_SCOPE = "RETRIEVAL_POLICY_EMPTY_SCOPE"
RETRIEVAL_POLICY_DISABLED = "RETRIEVAL_POLICY_DISABLED"
RETRIEVAL_POLICY_STRATEGY_DENIED = "RETRIEVAL_POLICY_STRATEGY_DENIED"
RETRIEVAL_POLICY_LEXICAL_FALLBACK = "RETRIEVAL_POLICY_LEXICAL_FALLBACK"
RETRIEVAL_POLICY_NO_CONTEXT_DENIED = "RETRIEVAL_POLICY_NO_CONTEXT_DENIED"

_STRATEGIES = frozenset({"lexical", "semantic", "hybrid", "hybrid_rrf"})

logger = logging.getLogger("frostgate.ai.retrieval_policy")


@dataclass(frozen=True)
class RetrievalPolicyDecision:
    tenant_id: str
    allowed: bool
    reason_code: str
    requested_corpus_ids: tuple[str, ...]
    effective_corpus_ids: tuple[str, ...]
    requested_top_k: int
    effective_top_k: int
    requested_strategy: str
    effective_strategy: str | None
    denied_corpus_ids: tuple[str, ...]
    allowed_corpus_ids: tuple[str, ...]
    require_grounded_context: bool
    allow_no_context_answer: bool
    semantic_allowed: bool
    lexical_fallback_used: bool = False

    def audit_metadata(self) -> dict[str, object]:
        return {
            "reason_code": self.reason_code,
            "allowed": self.allowed,
            "requested_corpus_count": len(self.requested_corpus_ids),
            "effective_corpus_count": len(self.effective_corpus_ids),
            "requested_top_k": self.requested_top_k,
            "effective_top_k": self.effective_top_k,
            "requested_strategy": self.requested_strategy,
            "effective_strategy": self.effective_strategy,
            "denied_corpus_count": len(self.denied_corpus_ids),
            "allowed_corpus_count": len(self.allowed_corpus_ids),
            "require_grounded_context": self.require_grounded_context,
            "allow_no_context_answer": self.allow_no_context_answer,
            "semantic_allowed": self.semantic_allowed,
            "lexical_fallback_used": self.lexical_fallback_used,
        }


def evaluate_retrieval_policy(
    db: Session,
    *,
    tenant_id: str,
    corpus_ids: list[str] | None,
    top_k: int,
    requested_strategy: str,
    rag_rules: AiRagRules,
) -> RetrievalPolicyDecision:
    tenant = _require_tenant(tenant_id)
    requested = _normalize_ids(corpus_ids or [])
    requested_top_k = _positive_top_k(top_k)
    effective_top_k = min(requested_top_k, rag_rules.max_top_k)
    strategy = _normalize_strategy(requested_strategy)
    effective_strategy, allowed, reason, fallback = _resolve_strategy(
        strategy, rag_rules
    )

    if not rag_rules.enabled:
        decision = RetrievalPolicyDecision(
            tenant_id=tenant,
            allowed=False,
            reason_code=RETRIEVAL_POLICY_DISABLED,
            requested_corpus_ids=requested,
            effective_corpus_ids=(),
            requested_top_k=requested_top_k,
            effective_top_k=effective_top_k,
            requested_strategy=strategy,
            effective_strategy=None,
            denied_corpus_ids=rag_rules.denied_corpus_ids,
            allowed_corpus_ids=rag_rules.allowed_corpus_ids,
            require_grounded_context=rag_rules.require_grounded_context,
            allow_no_context_answer=rag_rules.allow_no_context_answer,
            semantic_allowed=rag_rules.allow_semantic,
        )
        audit_retrieval_policy_decision(decision)
        return decision

    effective_corpus_ids = _effective_corpus_ids(
        db,
        tenant_id=tenant,
        requested_corpus_ids=requested,
        allowed_corpus_ids=rag_rules.allowed_corpus_ids,
        denied_corpus_ids=rag_rules.denied_corpus_ids,
    )
    if allowed and requested and not effective_corpus_ids:
        reason = RETRIEVAL_POLICY_EMPTY_SCOPE
    decision = RetrievalPolicyDecision(
        tenant_id=tenant,
        allowed=allowed,
        reason_code=reason,
        requested_corpus_ids=requested,
        effective_corpus_ids=effective_corpus_ids,
        requested_top_k=requested_top_k,
        effective_top_k=effective_top_k,
        requested_strategy=strategy,
        effective_strategy=effective_strategy,
        denied_corpus_ids=rag_rules.denied_corpus_ids,
        allowed_corpus_ids=rag_rules.allowed_corpus_ids,
        require_grounded_context=rag_rules.require_grounded_context,
        allow_no_context_answer=rag_rules.allow_no_context_answer,
        semantic_allowed=rag_rules.allow_semantic,
        lexical_fallback_used=fallback,
    )
    audit_retrieval_policy_decision(decision)
    return decision


def audit_retrieval_policy_decision(decision: RetrievalPolicyDecision) -> None:
    logger.info(
        "ai.retrieval_policy.decision",
        extra={
            "event": "ai.retrieval_policy.decision",
            "tenant_id": decision.tenant_id,
            **decision.audit_metadata(),
        },
    )


def no_context_allowed(decision: RetrievalPolicyDecision) -> bool:
    return not decision.require_grounded_context or decision.allow_no_context_answer


def _require_tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id is required and must not be blank")
    return tenant_id.strip()


def _positive_top_k(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("top_k must be a positive integer")
    return value


def _normalize_ids(values: list[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = str(value).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        normalized.append(cleaned)
    return tuple(normalized)


def _normalize_strategy(value: str) -> str:
    strategy = str(value or "lexical").strip()
    return strategy if strategy in _STRATEGIES else "lexical"


def _resolve_strategy(
    requested_strategy: str, rag_rules: AiRagRules
) -> tuple[str | None, bool, str, bool]:
    allowed_strategies = set(rag_rules.allowed_retrieval_strategies)
    semantic_requested = requested_strategy in {"semantic", "hybrid", "hybrid_rrf"}
    strategy_allowed = requested_strategy in allowed_strategies
    if semantic_requested and not rag_rules.allow_semantic:
        strategy_allowed = False
    if strategy_allowed:
        return requested_strategy, True, RETRIEVAL_POLICY_ALLOWED, False
    if rag_rules.allow_lexical_fallback and "lexical" in allowed_strategies:
        return "lexical", True, RETRIEVAL_POLICY_LEXICAL_FALLBACK, True
    return None, False, RETRIEVAL_POLICY_STRATEGY_DENIED, False


def _effective_corpus_ids(
    db: Session,
    *,
    tenant_id: str,
    requested_corpus_ids: tuple[str, ...],
    allowed_corpus_ids: tuple[str, ...],
    denied_corpus_ids: tuple[str, ...],
) -> tuple[str, ...]:
    denied = set(denied_corpus_ids)
    allowed = set(allowed_corpus_ids)
    if requested_corpus_ids:
        candidates = requested_corpus_ids
    elif allowed_corpus_ids:
        candidates = allowed_corpus_ids
    elif denied_corpus_ids:
        candidates = tuple(str(row["corpus_id"]) for row in list_corpora(db, tenant_id))
    else:
        return ()

    effective: list[str] = []
    for corpus_id in candidates:
        if corpus_id in denied:
            continue
        if allowed and corpus_id not in allowed:
            continue
        if get_corpus(db, tenant_id, corpus_id) is None:
            continue
        effective.append(corpus_id)
    return tuple(effective)
