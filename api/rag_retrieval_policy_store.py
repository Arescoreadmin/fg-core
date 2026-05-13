"""
api/rag_retrieval_policy_store.py — Tenant-scoped retrieval policy persistence.

Provides get and upsert operations for the tenant_retrieval_policies table.
Each tenant has at most one row — upsert on PUT.

All operations:
- Require non-empty tenant_id (raise ValueError if blank).
- Filter strictly by tenant_id — never returns cross-tenant data.
- Accept a SQLAlchemy Session from api/db.py.

rag_rules_from_db() converts a stored row into AiRagRules so the retrieval
policy engine can consume it without an additional DB call at query time.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models import TenantRetrievalPolicy
from services.ai.policy import AiRagRules

logger = logging.getLogger("frostgate.rag_retrieval_policy_store")

_VALID_STRATEGIES = frozenset({"lexical", "semantic", "hybrid", "hybrid_rrf"})
TOP_K_MIN = 1
TOP_K_MAX = 20


def _require_tenant(tenant_id: Optional[str]) -> str:
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id is required and must not be blank")
    return str(tenant_id).strip()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_dict(row: TenantRetrievalPolicy) -> dict[str, Any]:
    return {
        "tenant_id": row.tenant_id,
        "rag_enabled": bool(row.rag_enabled),
        "allowed_corpus_ids": list(row.allowed_corpus_ids or []),
        "denied_corpus_ids": list(row.denied_corpus_ids or []),
        "max_top_k": int(row.max_top_k),
        "allowed_retrieval_strategies": list(
            row.allowed_retrieval_strategies or ["lexical"]
        ),
        "require_grounded_response": bool(row.require_grounded_response),
        "no_answer_on_ungrounded": bool(row.no_answer_on_ungrounded),
        "require_grounded_context": bool(row.require_grounded_context),
        "allow_lexical_fallback": bool(row.allow_lexical_fallback),
        "allow_semantic": bool(row.allow_semantic),
        "allow_no_context_answer": bool(row.allow_no_context_answer),
        "reranking_enabled": bool(row.reranking_enabled),
        "policy_version": int(row.policy_version),
        "updated_by": row.updated_by,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def get_retrieval_policy(conn: Session, tenant_id: str) -> Optional[dict[str, Any]]:
    """Return stored policy for tenant_id, or None if not yet configured."""
    tid = _require_tenant(tenant_id)
    stmt = select(TenantRetrievalPolicy).where(TenantRetrievalPolicy.tenant_id == tid)
    row = conn.execute(stmt).scalar_one_or_none()
    return _row_to_dict(row) if row is not None else None


def upsert_retrieval_policy(
    conn: Session,
    tenant_id: str,
    payload: dict[str, Any],
    updated_by: Optional[str] = None,
) -> dict[str, Any]:
    """
    Validate and persist retrieval policy for tenant_id.

    Validation is authoritative and runs before any write.
    Invalid payloads raise ValueError with machine-readable error codes.
    Returns the persisted row as a plain dict.
    """
    tid = _require_tenant(tenant_id)
    validated = _validate_policy_payload(payload)

    stmt = select(TenantRetrievalPolicy).where(TenantRetrievalPolicy.tenant_id == tid)
    row = conn.execute(stmt).scalar_one_or_none()
    now = _utc_now()

    if row is None:
        row = TenantRetrievalPolicy(
            tenant_id=tid,
            policy_version=1,
            updated_by=updated_by,
            updated_at=now,
            **validated,
        )
        conn.add(row)
    else:
        for key, value in validated.items():
            setattr(row, key, value)
        row.policy_version = (row.policy_version or 0) + 1
        row.updated_by = updated_by
        row.updated_at = now

    conn.commit()
    conn.refresh(row)
    logger.info(
        "rag_retrieval_policy_store.upserted",
        extra={
            "event": "retrieval_policy.upserted",
            "tenant_id": tid,
            "version": row.policy_version,
        },
    )
    return _row_to_dict(row)


def rag_rules_from_db(conn: Session, tenant_id: str) -> Optional[AiRagRules]:
    """
    Load AiRagRules from the DB-stored policy for tenant_id.

    Returns None if no policy has been stored — callers should fall back to
    resolve_ai_policy_for_tenant() or the built-in default.
    """
    stored = get_retrieval_policy(conn, tenant_id)
    if stored is None:
        return None
    return AiRagRules(
        enabled=stored["rag_enabled"],
        require_grounded_response=stored["require_grounded_response"],
        no_answer_on_ungrounded=stored["no_answer_on_ungrounded"],
        allowed_corpus_ids=tuple(str(x) for x in stored["allowed_corpus_ids"]),
        denied_corpus_ids=tuple(str(x) for x in stored["denied_corpus_ids"]),
        max_top_k=stored["max_top_k"],
        allowed_retrieval_strategies=tuple(
            str(s) for s in stored["allowed_retrieval_strategies"]
        ),
        require_grounded_context=stored["require_grounded_context"],
        allow_lexical_fallback=stored["allow_lexical_fallback"],
        allow_semantic=stored["allow_semantic"],
        allow_no_context_answer=stored["allow_no_context_answer"],
    )


# ---------------------------------------------------------------------------
# Internal validation — fail closed, no silent coercion
# ---------------------------------------------------------------------------


def _validate_policy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Validate retrieval policy payload and return a normalised field dict.

    Raises ValueError with semicolon-separated CODE:field:message entries
    so callers can return structured error responses.
    """
    errors: list[str] = []

    # top_k
    max_top_k = payload.get("max_top_k", 4)
    if not isinstance(max_top_k, int) or isinstance(max_top_k, bool):
        errors.append("INVALID_TOP_K:max_top_k:must be an integer")
        max_top_k = 4
    elif max_top_k < TOP_K_MIN or max_top_k > TOP_K_MAX:
        errors.append(
            f"INVALID_TOP_K:max_top_k:must be between {TOP_K_MIN} and {TOP_K_MAX}"
        )

    # allowed_retrieval_strategies
    strategies = payload.get("allowed_retrieval_strategies", ["lexical"])
    if not isinstance(strategies, list) or not strategies:
        errors.append(
            "INVALID_STRATEGY:allowed_retrieval_strategies:must be a non-empty list"
        )
        strategies = ["lexical"]
    else:
        unknown = sorted(s for s in strategies if s not in _VALID_STRATEGIES)
        if unknown:
            errors.append(
                f"UNSUPPORTED_STRATEGY:allowed_retrieval_strategies:"
                f"unknown strategies: {unknown}"
            )

    # corpus id lists
    allowed_ids = payload.get("allowed_corpus_ids", [])
    denied_ids = payload.get("denied_corpus_ids", [])
    if not isinstance(allowed_ids, list):
        errors.append("INVALID_CORPUS:allowed_corpus_ids:must be a list")
        allowed_ids = []
    if not isinstance(denied_ids, list):
        errors.append("INVALID_CORPUS:denied_corpus_ids:must be a list")
        denied_ids = []

    overlap = set(str(x).strip() for x in allowed_ids if str(x).strip()) & set(
        str(x).strip() for x in denied_ids if str(x).strip()
    )
    if overlap:
        errors.append(
            f"CONTRADICTORY_CORPUS:allowed_corpus_ids,denied_corpus_ids:"
            f"corpus in both allow and deny: {sorted(overlap)}"
        )

    # semantic consistency
    allow_semantic = bool(payload.get("allow_semantic", False))
    if allow_semantic and isinstance(strategies, list):
        semantic_strats = {"semantic", "hybrid", "hybrid_rrf"}
        if not any(s in semantic_strats for s in strategies):
            errors.append(
                "INCOMPATIBLE_SEMANTIC:allow_semantic:"
                "semantic enabled but no semantic strategy in allowed_retrieval_strategies"
            )

    if errors:
        raise ValueError("; ".join(errors))

    return {
        "rag_enabled": bool(payload.get("rag_enabled", True)),
        "allowed_corpus_ids": [str(x).strip() for x in allowed_ids if str(x).strip()],
        "denied_corpus_ids": [str(x).strip() for x in denied_ids if str(x).strip()],
        "max_top_k": int(max_top_k),
        "allowed_retrieval_strategies": [str(s) for s in strategies],
        "require_grounded_response": bool(
            payload.get("require_grounded_response", True)
        ),
        "no_answer_on_ungrounded": bool(payload.get("no_answer_on_ungrounded", True)),
        "require_grounded_context": bool(
            payload.get("require_grounded_context", False)
        ),
        "allow_lexical_fallback": bool(payload.get("allow_lexical_fallback", False)),
        "allow_semantic": allow_semantic,
        "allow_no_context_answer": bool(payload.get("allow_no_context_answer", True)),
        "reranking_enabled": bool(payload.get("reranking_enabled", False)),
    }
