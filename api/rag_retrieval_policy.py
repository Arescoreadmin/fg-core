"""
api/rag_retrieval_policy.py — Tenant-scoped retrieval policy governance endpoints.

GET  /rag/retrieval-policy   → current policy (404 if not configured)
PUT  /rag/retrieval-policy   → validate + persist + audit
GET  /rag/corpora            → tenant-scoped corpus list for policy UI

Security: All endpoints require verify_api_key + governance:write scope.
Tenant isolation: every operation is scoped to the authenticated tenant via
require_bound_tenant().  Cross-tenant access is structurally impossible.

Audit: PUT writes a structured log entry (no secrets, no vectors, no prompts).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes, verify_api_key
from api.deps import tenant_db_required
from api.rag_corpus_store import list_corpora
from api.rag_retrieval_policy_store import get_retrieval_policy, upsert_retrieval_policy

log = logging.getLogger("frostgate.rag_retrieval_policy")


class RetrievalPolicyRequest(BaseModel):
    rag_enabled: bool = True
    allowed_corpus_ids: list[str] = Field(default_factory=list)
    denied_corpus_ids: list[str] = Field(default_factory=list)
    max_top_k: int = Field(default=4)
    allowed_retrieval_strategies: list[str] = Field(default_factory=lambda: ["lexical"])
    require_grounded_response: bool = True
    no_answer_on_ungrounded: bool = True
    require_grounded_context: bool = False
    allow_lexical_fallback: bool = False
    allow_semantic: bool = False
    allow_no_context_answer: bool = True
    reranking_enabled: bool = False


router = APIRouter(
    prefix="/rag",
    tags=["rag", "governance"],
    dependencies=[
        Depends(verify_api_key),
        Depends(require_scopes("governance:write")),
    ],
)


def _tenant(request: Request) -> str:
    return require_bound_tenant(request)


@router.get("/retrieval-policy")
def get_retrieval_policy_endpoint(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """Return the current retrieval policy for the authenticated tenant.

    Returns 404 if no policy has been configured yet.
    Never returns data outside the authenticated tenant boundary.
    """
    tenant_id = _tenant(request)
    policy = get_retrieval_policy(db, tenant_id)
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "POLICY_NOT_CONFIGURED", "tenant_id": tenant_id},
        )
    return policy


@router.put("/retrieval-policy")
def put_retrieval_policy_endpoint(
    req: RetrievalPolicyRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """Validate and persist the retrieval policy for the authenticated tenant.

    Validation is authoritative and executes before any write.
    Invalid configurations fail closed with machine-readable error codes.
    All successful saves are audit-logged.
    """
    tenant_id = _tenant(request)
    actor: Optional[str] = request.headers.get(
        "x-frostgate-user"
    ) or request.headers.get("x-api-key-prefix")

    payload = req.model_dump()
    try:
        result = upsert_retrieval_policy(db, tenant_id, payload, updated_by=actor)
    except ValueError as exc:
        log.warning(
            "rag_retrieval_policy.put.invalid",
            extra={
                "event": "retrieval_policy.put.invalid",
                "tenant_id": tenant_id,
                "errors": str(exc),
            },
        )
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_RETRIEVAL_POLICY", "errors": str(exc)},
        )
    except Exception as exc:
        db.rollback()
        log.error("rag_retrieval_policy.put.error: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Retrieval policy service unavailable",
        )

    _audit_policy_change(request, tenant_id, actor, result)
    return result


@router.get("/corpora")
def list_corpora_endpoint(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> list[dict[str, Any]]:
    """Return all tenant-scoped corpora for use in the policy UI.

    Never returns cross-tenant corpora.
    Returns [] if no corpora have been ingested yet.
    Does not expose raw vectors, embeddings, or document content.
    """
    tenant_id = _tenant(request)
    rows = list_corpora(db, tenant_id)
    return [
        {
            "corpus_id": r["corpus_id"],
            "name": r.get("name") or r["corpus_id"],
            "description": r.get("description"),
        }
        for r in rows
    ]


def _audit_policy_change(
    request: Request,
    tenant_id: str,
    actor: Optional[str],
    result: dict[str, Any],
) -> None:
    """Write an audit-safe structured log entry for the policy change.

    Does not log: secrets, provider payloads, raw prompts, vectors,
    corpus content, or individual corpus IDs.
    Logs: tenant_id, actor (key prefix only), policy_version, field counts,
    boolean enforcement flags, request_id.
    """
    log.info(
        "rag_retrieval_policy.changed",
        extra={
            "event": "rag_retrieval_policy.changed",
            "tenant_id": tenant_id,
            "actor": actor,
            "policy_version": result.get("policy_version"),
            "request_id": request.headers.get("x-request-id"),
            "max_top_k": result.get("max_top_k"),
            "allow_semantic": result.get("allow_semantic"),
            "require_grounded_response": result.get("require_grounded_response"),
            "allow_lexical_fallback": result.get("allow_lexical_fallback"),
            "reranking_enabled": result.get("reranking_enabled"),
            "allowed_corpus_count": len(result.get("allowed_corpus_ids") or []),
            "denied_corpus_count": len(result.get("denied_corpus_ids") or []),
        },
    )
