"""
api/assessments.py — Customer-facing AI governance assessment engine.

Endpoints:
  POST  /assessment/orgs                         Create org + draft assessment
  GET   /assessment/assessments/{id}/questions   Fetch question bank
  GET   /assessment/assessments/{id}             Get assessment + scores
  PATCH /assessment/assessments/{id}/responses   Autosave responses
  POST  /assessment/assessments/{id}/submit      Score and finalise

These routes are intentionally auth-free for the customer onboarding flow.
The assessment UUID is the access token. Tenant-dashboard endpoints that list
all assessments for a tenant are gated by fg-core's existing auth system.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_sessionmaker
from api.db_models import AssessmentRecord, AssessmentSchema, OrgProfile

log = logging.getLogger("frostgate.assessments")

router = APIRouter(prefix="/assessment", tags=["assessment"])


# ─── DB session (no tenant context required for public endpoints) ─────────────

def _get_db():
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─── Profile classification ───────────────────────────────────────────────────

def _parse_employee_upper(ec: str) -> int:
    """Parse '51-200' → 200, '1001+' → 9999."""
    if not ec:
        return 0
    clean = ec.replace("+", "").replace(",", "")
    parts = clean.split("-")
    try:
        return int(parts[-1].strip())
    except ValueError:
        return 0


def classify_profile(
    industry: str,
    employee_count: str,
    handles_phi: bool,
    handles_cui: bool,
    is_dod_contractor: bool,
    fedramp_required: bool,
) -> str:
    if is_dod_contractor or handles_cui or fedramp_required:
        return "govcon"
    if handles_phi or industry in ("banking", "healthcare", "insurance"):
        return "regulated"
    n = _parse_employee_upper(employee_count)
    if n > 1000:
        return "enterprise"
    if n > 200:
        return "midmarket"
    if n > 50:
        return "smb_growth"
    return "smb_basic"


# ─── Scoring engine ───────────────────────────────────────────────────────────

# Base domain weights (must sum to 1.0)
_BASE_WEIGHTS: dict[str, float] = {
    "data_governance":      0.25,
    "security_posture":     0.20,
    "ai_maturity":          0.20,
    "infra_readiness":      0.15,
    "compliance_awareness": 0.12,
    "automation_potential": 0.08,
}

# Profile weight multipliers (applied to base weights then renormalised)
_PROFILE_MULTIPLIERS: dict[str, dict[str, float]] = {
    "smb_basic": {
        "compliance_awareness": 0.50,
        "automation_potential": 0.50,
    },
    "smb_growth": {
        "compliance_awareness": 0.75,
    },
    "midmarket": {},
    "enterprise": {},
    "regulated": {
        "data_governance":      1.30,
        "security_posture":     1.15,
        "compliance_awareness": 1.25,
    },
    "govcon": {
        "data_governance":      1.40,
        "security_posture":     1.30,
        "compliance_awareness": 1.50,
        "infra_readiness":      1.20,
    },
}


def _effective_weights(profile_type: str) -> dict[str, float]:
    mods = _PROFILE_MULTIPLIERS.get(profile_type, {})
    raw = {d: w * mods.get(d, 1.0) for d, w in _BASE_WEIGHTS.items()}
    total = sum(raw.values())
    return {d: v / total for d, v in raw.items()}


def _question_score(q: dict[str, Any], raw_value: Any) -> float | None:
    """Convert a raw response value to a 0-100 score. Returns None if unanswered."""
    if raw_value is None:
        return None
    qtype = q.get("type", "boolean")
    if qtype == "boolean":
        return 100.0 if raw_value is True else 0.0
    if qtype == "scale":
        try:
            v = int(raw_value)
            return max(0.0, min(100.0, (v - 1) * 25.0))
        except (TypeError, ValueError):
            return None
    if qtype == "select":
        opts = q.get("options", [])
        if not opts:
            return None
        try:
            idx = opts.index(raw_value)
            return (idx / (len(opts) - 1)) * 100.0
        except (ValueError, ZeroDivisionError):
            return None
    if qtype == "text":
        # Text answers get 50 points for providing any response
        return 50.0 if str(raw_value).strip() else None
    return None


def score_assessment(
    questions: list[dict[str, Any]],
    responses: dict[str, Any],
    profile_type: str,
) -> dict[str, Any]:
    """
    Returns:
      {
        "domain_scores": {"data_governance": 47.3, ...},
        "overall_score": 51.2,
        "risk_band": "high",
        "answered": 28,
        "total": 35,
      }
    """
    weights = _effective_weights(profile_type)

    # Accumulate weighted scores per domain
    domain_totals: dict[str, list[float]] = {d: [] for d in _BASE_WEIGHTS}

    for q in questions:
        domain = q.get("domain")
        if domain not in domain_totals:
            continue
        raw = responses.get(q["id"])
        s = _question_score(q, raw)
        if s is None:
            continue
        q_weight = float(q.get("weight", 1.0))
        # Replicate weight as repeated entries for weighted average
        domain_totals[domain].extend([s] * round(q_weight * 10))

    domain_scores: dict[str, float] = {}
    for domain, scores in domain_totals.items():
        domain_scores[domain] = round(sum(scores) / len(scores), 2) if scores else 0.0

    overall = round(
        sum(domain_scores[d] * weights[d] for d in _BASE_WEIGHTS), 2
    )

    if overall < 25:
        band = "critical"
    elif overall < 50:
        band = "high"
    elif overall < 75:
        band = "medium"
    else:
        band = "low"

    answered = sum(1 for q in questions if responses.get(q["id"]) is not None)

    return {
        "domain_scores": domain_scores,
        "overall_score": overall,
        "risk_band": band,
        "answered": answered,
        "total": len(questions),
    }


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class OrgCreateRequest(BaseModel):
    name: str
    industry: str = "other"
    employee_count: str = ""
    revenue: str = ""
    handles_phi: bool = False
    handles_cui: bool = False
    is_dod_contractor: bool = False
    fedramp_required: bool = False


class OrgCreateResponse(BaseModel):
    org_id: str
    assessment_id: str
    profile_type: str
    schema_version: str


class SaveResponsesRequest(BaseModel):
    responses: dict[str, Any]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load_questions(db: Session) -> list[dict[str, Any]]:
    schema = (
        db.query(AssessmentSchema)
        .filter(AssessmentSchema.is_current.is_(True))
        .first()
    )
    if schema is None:
        # Fallback: any schema
        schema = db.query(AssessmentSchema).first()
    if schema is None:
        return []
    questions = schema.questions
    if isinstance(questions, str):
        questions = json.loads(questions)
    return questions or []


def _get_assessment_or_404(assessment_id: str, db: Session) -> AssessmentRecord:
    rec = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return rec


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/orgs", response_model=OrgCreateResponse, status_code=201)
def create_org(body: OrgCreateRequest, db: Session = Depends(_get_db)):
    """
    Create an org profile + draft assessment in a single call.
    Called by the onboarding wizard on the final "Launch Assessment" step.
    """
    profile_type = classify_profile(
        industry=body.industry,
        employee_count=body.employee_count,
        handles_phi=body.handles_phi,
        handles_cui=body.handles_cui,
        is_dod_contractor=body.is_dod_contractor,
        fedramp_required=body.fedramp_required,
    )

    org_id = str(uuid.uuid4())
    org = OrgProfile(
        org_id=org_id,
        tenant_id="public",
        org_name=body.name,
        industry=body.industry,
        employee_count=body.employee_count,
        revenue=body.revenue,
        profile_type=profile_type,
        handles_phi=body.handles_phi,
        handles_cui=body.handles_cui,
        is_dod_contractor=body.is_dod_contractor,
        fedramp_required=body.fedramp_required,
    )
    db.add(org)
    db.flush()  # get org.id

    assessment_id = str(uuid.uuid4())
    assessment = AssessmentRecord(
        id=assessment_id,
        tenant_id="public",
        org_profile_id=org.id,
        org_id=org_id,
        schema_version="v2025.1-base",
        profile_type=profile_type,
        status="draft",
        responses={},
    )
    db.add(assessment)
    db.commit()

    log.info(
        "assessment.org_created org_id=%s profile=%s assessment_id=%s",
        org_id, profile_type, assessment_id,
    )

    return OrgCreateResponse(
        org_id=org_id,
        assessment_id=assessment_id,
        profile_type=profile_type,
        schema_version="v2025.1-base",
    )


@router.get("/assessments/{assessment_id}/questions")
def get_questions(assessment_id: str, db: Session = Depends(_get_db)):
    """Return the full question bank for this assessment's profile."""
    _get_assessment_or_404(assessment_id, db)
    questions = _load_questions(db)
    return questions


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str, db: Session = Depends(_get_db)):
    """Return assessment metadata + scores (if scored)."""
    rec = _get_assessment_or_404(assessment_id, db)
    return {
        "id": rec.id,
        "org_id": rec.org_id,
        "profile_type": rec.profile_type,
        "schema_version": rec.schema_version,
        "status": rec.status,
        "overall_score": rec.overall_score,
        "risk_band": rec.risk_band,
        "scores": rec.scores,
        "responses": rec.responses,
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        "submitted_at": rec.submitted_at.isoformat() if rec.submitted_at else None,
    }


@router.patch("/assessments/{assessment_id}/responses", status_code=200)
def save_responses(
    assessment_id: str,
    body: SaveResponsesRequest,
    db: Session = Depends(_get_db),
):
    """Autosave partial responses. Called every 30s by the assessment wizard."""
    rec = _get_assessment_or_404(assessment_id, db)
    if rec.status in ("submitted", "scored"):
        raise HTTPException(status_code=409, detail="Assessment already submitted")

    existing = dict(rec.responses or {})
    existing.update(body.responses)
    rec.responses = existing
    rec.status = "in_progress"
    rec.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"saved": True, "response_count": len(existing)}


@router.post("/assessments/{assessment_id}/submit")
def submit_assessment(assessment_id: str, db: Session = Depends(_get_db)):
    """
    Score the assessment and mark it complete.
    Called by the assessment wizard on final submission.
    """
    rec = _get_assessment_or_404(assessment_id, db)
    if rec.status in ("submitted", "scored"):
        # Idempotent — return existing scores
        return {
            "assessment_id": rec.id,
            "overall_score": rec.overall_score,
            "risk_band": rec.risk_band,
            "domain_scores": rec.scores or {},
        }

    questions = _load_questions(db)
    if not questions:
        raise HTTPException(
            status_code=503, detail="Question bank not loaded — run database seeds"
        )

    responses = rec.responses or {}
    result = score_assessment(questions, responses, rec.profile_type)

    now = datetime.now(timezone.utc)
    rec.scores = result["domain_scores"]
    rec.overall_score = result["overall_score"]
    rec.risk_band = result["risk_band"]
    rec.status = "scored"
    rec.submitted_at = now
    rec.scored_at = now
    rec.updated_at = now
    db.commit()

    log.info(
        "assessment.scored assessment_id=%s score=%.1f band=%s",
        assessment_id, result["overall_score"], result["risk_band"],
    )

    return {
        "assessment_id": rec.id,
        "overall_score": result["overall_score"],
        "risk_band": result["risk_band"],
        "domain_scores": result["domain_scores"],
    }
