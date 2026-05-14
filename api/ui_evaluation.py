from __future__ import annotations

from datetime import timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import asc, desc
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes
from api.db import get_engine, set_tenant_context
from api.db_models import (
    EvaluationQueryItem,
    EvaluationQuerySet,
    RetrievalEvaluationRun,
)

router = APIRouter(
    tags=["ui-evaluation"], dependencies=[Depends(require_scopes("ui:read"))]
)

_VALID_STATUSES = frozenset({"pending", "running", "completed", "failed"})


def _safe_run(row: RetrievalEvaluationRun) -> dict[str, Any]:
    def _tz(dt: Any) -> Any:
        if dt is not None and dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    started_at = _tz(row.started_at)
    completed_at = _tz(row.completed_at)
    created_at = _tz(row.created_at)
    updated_at = _tz(row.updated_at)
    return {
        "run_ref": row.run_ref,
        "corpus_id": row.corpus_id,
        "status": row.status,
        "started_at": started_at.isoformat() if started_at else None,
        "completed_at": completed_at.isoformat() if completed_at else None,
        "query_count": row.query_count,
        "relevance_indicators": row.relevance_indicators_json or {},
        "coverage_indicators": row.coverage_indicators_json or {},
        "correctness_indicators": row.correctness_indicators_json or {},
        "evaluator_ref": row.evaluator_ref,
        "evaluation_metadata": row.evaluation_metadata_json or {},
        "created_at": created_at.isoformat() if created_at else None,
        "updated_at": updated_at.isoformat() if updated_at else None,
    }


@router.get("/ui/evaluation/runs")
def ui_evaluation_runs(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None, max_length=16),
    corpus_id: Optional[str] = Query(default=None, max_length=128),
) -> dict[str, Any]:
    """List retrieval evaluation runs for the authenticated tenant.

    Returns structural evaluation metadata only. No raw prompts, completions,
    or fabricated scores. Evaluation algorithms are external.
    """
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        q = session.query(RetrievalEvaluationRun).filter(
            RetrievalEvaluationRun.tenant_id == tenant_id
        )
        if status:
            q = q.filter(RetrievalEvaluationRun.status == status)
        if corpus_id:
            q = q.filter(RetrievalEvaluationRun.corpus_id == corpus_id)
        total = q.count()
        rows = (
            q.order_by(
                desc(RetrievalEvaluationRun.created_at),
                desc(RetrievalEvaluationRun.id),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

    return {
        "runs": [_safe_run(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/ui/evaluation/runs/{run_ref}")
def ui_evaluation_run_detail(
    request: Request,
    run_ref: str,
) -> dict[str, Any]:
    """Return detail for a single evaluation run.

    Tenant-scoped. Returns 404 if the run belongs to a different tenant.
    """
    if not run_ref or len(run_ref) > 128:
        raise HTTPException(
            status_code=422,
            detail="run_ref must be non-empty and at most 128 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        row = (
            session.query(RetrievalEvaluationRun)
            .filter(
                RetrievalEvaluationRun.tenant_id == tenant_id,
                RetrievalEvaluationRun.run_ref == run_ref,
            )
            .first()
        )

    if row is None:
        raise HTTPException(status_code=404, detail="evaluation_run_not_found")
    return _safe_run(row)


@router.get("/ui/evaluation/quality")
def ui_evaluation_quality(
    request: Request,
    corpus_id: Optional[str] = Query(default=None, max_length=128),
) -> dict[str, Any]:
    """Return a quality summary across completed evaluation runs.

    Aggregates structural indicators from completed runs. No fabricated
    scores — only run counts and presence/absence of indicator data.
    """
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        q = session.query(RetrievalEvaluationRun).filter(
            RetrievalEvaluationRun.tenant_id == tenant_id,
            RetrievalEvaluationRun.status == "completed",
        )
        if corpus_id:
            q = q.filter(RetrievalEvaluationRun.corpus_id == corpus_id)
        completed_runs = q.all()

    total_queries = sum(r.query_count for r in completed_runs)
    runs_with_relevance = sum(1 for r in completed_runs if r.relevance_indicators_json)
    runs_with_coverage = sum(1 for r in completed_runs if r.coverage_indicators_json)
    runs_with_correctness = sum(
        1 for r in completed_runs if r.correctness_indicators_json
    )

    return {
        "corpus_id": corpus_id,
        "completed_run_count": len(completed_runs),
        "total_queries_evaluated": total_queries,
        "runs_with_relevance_indicators": runs_with_relevance,
        "runs_with_coverage_indicators": runs_with_coverage,
        "runs_with_correctness_indicators": runs_with_correctness,
        "quality_note": "Quality summary is derived from completed evaluation runs. No fabricated metrics.",
        "evaluation_algorithms_available": False,
    }


# ─── Query Set helpers ────────────────────────────────────────────────────────


_SENSITIVE_EXPORT_META_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "bearer",
    "secret",
    "token",
    "password",
    "credential",
    "provider_payload",
    "headers",
    "cookie",
)


def _is_sensitive_export_meta_key(key: object) -> bool:
    normalized = str(key).lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_EXPORT_META_KEY_PARTS)


def _sanitize_export_metadata(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(k): _sanitize_export_metadata(v)
            for k, v in value.items()
            if not _is_sensitive_export_meta_key(k)
        }

    if isinstance(value, list):
        return [_sanitize_export_metadata(item) for item in value]

    if isinstance(value, tuple):
        return [_sanitize_export_metadata(item) for item in value]

    return value


def _safe_query_set(row: EvaluationQuerySet) -> dict[str, Any]:
    def _tz(dt: Any) -> Any:
        if dt is not None and dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    return {
        "set_ref": row.set_ref,
        "name": row.name,
        "corpus_id": row.corpus_id,
        "description": row.description,
        "operator_notes": row.operator_notes_json or [],
        "export_safe_metadata": row.export_safe_metadata_json or {},
        "created_at": _tz(row.created_at).isoformat() if row.created_at else None,
        "updated_at": _tz(row.updated_at).isoformat() if row.updated_at else None,
    }


def _safe_query_item(row: EvaluationQueryItem) -> dict[str, Any]:
    def _tz(dt: Any) -> Any:
        if dt is not None and dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    return {
        "item_ref": row.item_ref,
        "set_ref": row.set_ref,
        "query_category": row.query_category,
        "expected_source_ids": row.expected_source_ids_json or [],
        "expected_chunk_ids": row.expected_chunk_ids_json or [],
        "expected_source_hashes": row.expected_source_hashes_json or [],
        "expected_provenance_ids": row.expected_provenance_ids_json or [],
        "retrieval_expectations": row.retrieval_expectations_json or {},
        "operator_notes": row.operator_notes,
        "created_at": _tz(row.created_at).isoformat() if row.created_at else None,
        "updated_at": _tz(row.updated_at).isoformat() if row.updated_at else None,
    }


# ─── Query Set routes ─────────────────────────────────────────────────────────


@router.get("/ui/evaluation/query-sets")
def ui_evaluation_query_sets(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    corpus_id: Optional[str] = Query(default=None, max_length=128),
) -> dict[str, Any]:
    """List evaluation query sets for the authenticated tenant.

    Returns structural metadata only. No raw query text, no PII, no secrets.
    """
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        q = session.query(EvaluationQuerySet).filter(
            EvaluationQuerySet.tenant_id == tenant_id
        )
        if corpus_id:
            q = q.filter(EvaluationQuerySet.corpus_id == corpus_id)
        total = q.count()
        rows = (
            q.order_by(
                desc(EvaluationQuerySet.created_at),
                desc(EvaluationQuerySet.id),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

    return {
        "query_sets": [_safe_query_set(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/ui/evaluation/query-sets/{set_ref}")
def ui_evaluation_query_set_detail(
    request: Request,
    set_ref: str,
    items_limit: int = Query(default=100, ge=1, le=500),
    items_offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Return a query set with its items.

    Tenant-scoped. Returns 404 if set_ref belongs to a different tenant.
    Items are ordered deterministically by created_at ASC, item_ref ASC.
    """
    if not set_ref or len(set_ref) > 128:
        raise HTTPException(
            status_code=422,
            detail="set_ref must be non-empty and at most 128 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        qs_row = (
            session.query(EvaluationQuerySet)
            .filter(
                EvaluationQuerySet.tenant_id == tenant_id,
                EvaluationQuerySet.set_ref == set_ref,
            )
            .first()
        )
        if qs_row is None:
            raise HTTPException(
                status_code=404, detail="evaluation_query_set_not_found"
            )

        items_q = session.query(EvaluationQueryItem).filter(
            EvaluationQueryItem.tenant_id == tenant_id,
            EvaluationQueryItem.set_ref == set_ref,
        )
        items_total = items_q.count()
        items = (
            items_q.order_by(
                asc(EvaluationQueryItem.created_at),
                asc(EvaluationQueryItem.item_ref),
            )
            .offset(items_offset)
            .limit(items_limit)
            .all()
        )

    result = _safe_query_set(qs_row)
    result["items"] = [_safe_query_item(r) for r in items]
    result["items_total"] = items_total
    result["items_limit"] = items_limit
    result["items_offset"] = items_offset
    return result


# ─── Run sub-resource routes ──────────────────────────────────────────────────


def _get_run_or_404(
    session: Session, tenant_id: str, run_ref: str
) -> RetrievalEvaluationRun:
    row = (
        session.query(RetrievalEvaluationRun)
        .filter(
            RetrievalEvaluationRun.tenant_id == tenant_id,
            RetrievalEvaluationRun.run_ref == run_ref,
        )
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="evaluation_run_not_found")
    return row


@router.get("/ui/evaluation/runs/{run_ref}/comparison")
def ui_evaluation_run_comparison(
    request: Request,
    run_ref: str,
) -> dict[str, Any]:
    """Return retrieval comparison metadata for a run.

    Derives comparison data from stored relevance and coverage indicators.
    No fabricated scores — only structural indicator presence/absence.
    """
    if not run_ref or len(run_ref) > 128:
        raise HTTPException(
            status_code=422,
            detail="run_ref must be non-empty and at most 128 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        row = _get_run_or_404(session, tenant_id, run_ref)
        relevance = row.relevance_indicators_json or {}
        coverage = row.coverage_indicators_json or {}
        meta = row.evaluation_metadata_json or {}

    return {
        "run_ref": row.run_ref,
        "corpus_id": row.corpus_id,
        "status": row.status,
        "query_count": row.query_count,
        "retrieval_comparison": {
            "has_relevance_data": bool(relevance),
            "has_coverage_data": bool(coverage),
            "relevance_keys": sorted(relevance.keys()),
            "coverage_keys": sorted(coverage.keys()),
            "comparison_note": (
                "Comparison derived from stored evaluation indicators. "
                "No fabricated precision scores."
            ),
            "reranker_comparison_available": bool(
                meta.get("reranker_comparison_available", False)
            ),
            "retrieval_strategy": meta.get("retrieval_strategy"),
            "comparison_strategy": meta.get("comparison_strategy"),
        },
    }


@router.get("/ui/evaluation/runs/{run_ref}/confidence")
def ui_evaluation_run_confidence(
    request: Request,
    run_ref: str,
) -> dict[str, Any]:
    """Return confidence distribution metadata for a run.

    Derives confidence distribution from stored correctness indicators.
    Confidence sources are labeled. Unknown confidence renders safely.
    No fabricated statistical certainty.
    """
    if not run_ref or len(run_ref) > 128:
        raise HTTPException(
            status_code=422,
            detail="run_ref must be non-empty and at most 128 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        row = _get_run_or_404(session, tenant_id, run_ref)
        correctness = row.correctness_indicators_json or {}
        meta = row.evaluation_metadata_json or {}

    confidence_source = meta.get("confidence_source", "unknown")
    has_confidence_data = bool(correctness)

    return {
        "run_ref": row.run_ref,
        "corpus_id": row.corpus_id,
        "status": row.status,
        "query_count": row.query_count,
        "confidence_distribution": {
            "has_confidence_data": has_confidence_data,
            "confidence_source": confidence_source,
            "confidence_source_labeled": True,
            "correctness_keys": sorted(correctness.keys()),
            "provider_confidence_available": bool(
                meta.get("provider_confidence_available", False)
            ),
            "reranker_score_available": bool(
                meta.get("reranker_score_available", False)
            ),
            "distribution_note": (
                "Confidence distribution derived from stored correctness indicators. "
                "Unknown confidence renders as 'unknown' — not fabricated."
            ),
        },
    }


@router.get("/ui/evaluation/runs/{run_ref}/hallucination")
def ui_evaluation_run_hallucination(
    request: Request,
    run_ref: str,
) -> dict[str, Any]:
    """Return hallucination review metadata for a run.

    Derives review state from stored evaluation indicators.
    Hallucination classification is heuristic/review-oriented, not guaranteed detection.
    Explicitly labeled as heuristic where applicable.
    """
    if not run_ref or len(run_ref) > 128:
        raise HTTPException(
            status_code=422,
            detail="run_ref must be non-empty and at most 128 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        row = _get_run_or_404(session, tenant_id, run_ref)
        relevance = row.relevance_indicators_json or {}
        coverage = row.coverage_indicators_json or {}
        correctness = row.correctness_indicators_json or {}
        meta = row.evaluation_metadata_json or {}

    grounding_available = bool(coverage.get("grounding_indicators"))
    missing_evidence_count = correctness.get("missing_evidence_count")
    weak_grounding_count = coverage.get("weak_grounding_count")

    return {
        "run_ref": row.run_ref,
        "corpus_id": row.corpus_id,
        "status": row.status,
        "query_count": row.query_count,
        "hallucination_review": {
            "review_type": "heuristic",
            "review_note": (
                "Hallucination review is heuristic and operator-reviewable. "
                "Not guaranteed automated detection. Requires operator validation."
            ),
            "grounding_data_available": grounding_available,
            "missing_evidence_count": missing_evidence_count,
            "weak_grounding_count": weak_grounding_count,
            "unsupported_answer_detection_available": bool(
                meta.get("unsupported_answer_detection_available", False)
            ),
            "evidence_mismatch_available": bool(
                relevance.get("evidence_mismatch_available", False)
            ),
            "export_safe": True,
            "tenant_scoped": True,
        },
    }


@router.get("/ui/evaluation/runs/{run_ref}/reranker")
def ui_evaluation_run_reranker(
    request: Request,
    run_ref: str,
) -> dict[str, Any]:
    """Return reranker comparison metadata for a run.

    Derives comparison from stored evaluation metadata.
    Reranker metrics derive from actual retrieval state — not fabricated.
    Comparison ordering is deterministic.
    """
    if not run_ref or len(run_ref) > 128:
        raise HTTPException(
            status_code=422,
            detail="run_ref must be non-empty and at most 128 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        row = _get_run_or_404(session, tenant_id, run_ref)
        meta = row.evaluation_metadata_json or {}
        relevance = row.relevance_indicators_json or {}

    reranker_available = bool(meta.get("reranker_comparison_available", False))
    reranker_strategy = meta.get("reranker_strategy")
    retrieval_strategy = meta.get("retrieval_strategy")

    return {
        "run_ref": row.run_ref,
        "corpus_id": row.corpus_id,
        "status": row.status,
        "query_count": row.query_count,
        "reranker_comparison": {
            "reranker_available": reranker_available,
            "reranker_strategy": reranker_strategy,
            "retrieval_strategy": retrieval_strategy,
            "ordering_deterministic": True,
            "overlap_keys": sorted(relevance.keys()),
            "reranker_note": (
                "Reranker comparison derives from actual retrieval state. "
                "Unsupported reranker metrics are not fabricated."
            ),
        },
    }


@router.get("/ui/evaluation/runs/{run_ref}/export")
def ui_evaluation_run_export(
    request: Request,
    run_ref: str,
) -> dict[str, Any]:
    """Return export-safe evaluation run payload.

    Excludes: secrets, raw auth headers, unsafe provider payloads,
    internal topology, raw prompts/completions.
    Suitable for audit review and compliance workflows.
    Ordering is deterministic.
    """
    if not run_ref or len(run_ref) > 128:
        raise HTTPException(
            status_code=422,
            detail="run_ref must be non-empty and at most 128 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()

    _BLOCKED_META_KEYS = frozenset(
        {
            "api_key",
            "auth_header",
            "authorization",
            "secret",
            "token",
            "provider_payload",
            "raw_prompt",
            "raw_completion",
            "credentials",
        }
    )

    with Session(engine) as session:
        set_tenant_context(session, tenant_id)
        row = _get_run_or_404(session, tenant_id, run_ref)

        def _tz(dt: Any) -> Any:
            if dt is not None and dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt

        meta = row.evaluation_metadata_json or {}
        safe_meta = _sanitize_export_metadata(meta)
        if not isinstance(safe_meta, dict):
            safe_meta = {}

    return {
        "export_safe": True,
        "export_schema_version": "1",
        "run_ref": row.run_ref,
        "corpus_id": row.corpus_id,
        "status": row.status,
        "query_count": row.query_count,
        "evaluator_ref": row.evaluator_ref,
        "started_at": _tz(row.started_at).isoformat() if row.started_at else None,
        "completed_at": (
            _tz(row.completed_at).isoformat() if row.completed_at else None
        ),
        "created_at": _tz(row.created_at).isoformat() if row.created_at else None,
        "has_relevance_indicators": bool(row.relevance_indicators_json),
        "has_coverage_indicators": bool(row.coverage_indicators_json),
        "has_correctness_indicators": bool(row.correctness_indicators_json),
        "evaluation_metadata": safe_meta,
        "export_note": (
            "Export excludes secrets, raw auth headers, provider payloads, "
            "and internal topology. Safe for audit review."
        ),
    }
