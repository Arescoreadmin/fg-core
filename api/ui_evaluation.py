from __future__ import annotations

from datetime import timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes
from api.db import get_engine
from api.db_models import RetrievalEvaluationRun

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
