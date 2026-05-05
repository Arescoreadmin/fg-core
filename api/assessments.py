"""
api/assessments.py — Customer-facing AI governance assessment engine.

Endpoints:
  POST  /assessment/orgs                   Create org + draft assessment
  GET   /assessment/{id}/questions         Fetch question bank
  GET   /assessment/{id}                   Get assessment + scores
  PATCH /assessment/{id}/responses         Autosave responses
  POST  /assessment/{id}/checkout          Create checkout session
  POST  /assessment/{id}/submit            Score and finalize

These routes are intentionally auth-free for the customer onboarding flow.
The assessment UUID is the access token. Tenant-dashboard endpoints that list
all assessments for a tenant are gated by fg-core's existing auth system.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_sessionmaker
from api.db_models import AssessmentRecord, AssessmentSchema, OrgProfile
from api.auth_scopes.resolution import require_scopes

log = logging.getLogger("frostgate.assessments")

router = APIRouter(
    prefix="/ingest/assessment",
    tags=["assessment"],
    dependencies=[Depends(require_scopes("ingest:assessment"))],
)


def _get_db():
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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


_BASE_WEIGHTS: dict[str, float] = {
    "data_governance": 0.25,
    "security_posture": 0.20,
    "ai_maturity": 0.20,
    "infra_readiness": 0.15,
    "compliance_awareness": 0.12,
    "automation_potential": 0.08,
}

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
        "data_governance": 1.30,
        "security_posture": 1.15,
        "compliance_awareness": 1.25,
    },
    "govcon": {
        "data_governance": 1.40,
        "security_posture": 1.30,
        "compliance_awareness": 1.50,
        "infra_readiness": 1.20,
    },
}


def _effective_weights(profile_type: str) -> dict[str, float]:
    mods = _PROFILE_MULTIPLIERS.get(profile_type, {})
    raw = {
        domain: weight * mods.get(domain, 1.0)
        for domain, weight in _BASE_WEIGHTS.items()
    }
    total = sum(raw.values())
    return {domain: value / total for domain, value in raw.items()}


def _question_score(q: dict[str, Any], raw_value: Any) -> float | None:
    """Convert a raw response value to a 0-100 score. Returns None if unanswered."""
    if raw_value is None:
        return None

    qtype = q.get("type", "boolean")

    if qtype == "boolean":
        return 100.0 if raw_value is True else 0.0

    if qtype == "scale":
        try:
            value = int(raw_value)
            return max(0.0, min(100.0, (value - 1) * 25.0))
        except (TypeError, ValueError):
            return None

    if qtype == "select":
        options = q.get("options", [])
        if not options:
            return None
        try:
            index = options.index(raw_value)
            return (index / (len(options) - 1)) * 100.0
        except (ValueError, ZeroDivisionError):
            return None

    if qtype == "text":
        return 50.0 if str(raw_value).strip() else None

    return None


def score_assessment(
    questions: list[dict[str, Any]],
    responses: dict[str, Any],
    profile_type: str,
) -> dict[str, Any]:
    weights = _effective_weights(profile_type)
    domain_totals: dict[str, list[float]] = {domain: [] for domain in _BASE_WEIGHTS}

    for question in questions:
        domain = question.get("domain")
        if domain not in domain_totals:
            continue

        raw = responses.get(question["id"])
        score = _question_score(question, raw)
        if score is None:
            continue

        question_weight = float(question.get("weight", 1.0))
        domain_totals[domain].extend([score] * max(1, round(question_weight * 10)))

    domain_scores = {
        domain: round(sum(scores) / len(scores), 2) if scores else 0.0
        for domain, scores in domain_totals.items()
    }

    overall = round(
        sum(domain_scores[domain] * weights[domain] for domain in _BASE_WEIGHTS), 2
    )

    if overall < 25:
        risk_band = "critical"
    elif overall < 50:
        risk_band = "high"
    elif overall < 75:
        risk_band = "medium"
    else:
        risk_band = "low"

    answered = sum(
        1 for question in questions if responses.get(question["id"]) is not None
    )

    return {
        "domain_scores": domain_scores,
        "overall_score": overall,
        "risk_band": risk_band,
        "answered": answered,
        "total": len(questions),
    }


_TIER_PRICES: dict[str, int] = {
    "smb_basic": 29900,
    "smb_growth": 29900,
    "midmarket": 59900,
    "enterprise": 59900,
    "regulated": 99900,
    "govcon": 99900,
}

_TIER_LABELS: dict[str, str] = {
    "smb_basic": "SMB Basic",
    "smb_growth": "SMB Growth",
    "midmarket": "Mid-Market",
    "enterprise": "Enterprise",
    "regulated": "Regulated",
    "govcon": "GovCon",
}


class OrgCreateRequest(BaseModel):
    name: str
    industry: str = "other"
    employee_count: str = ""
    revenue: str = ""
    handles_phi: bool = False
    handles_cui: bool = False
    is_dod_contractor: bool = False
    fedramp_required: bool = False
    email: str = ""


class OrgCreateResponse(BaseModel):
    org_id: str
    assessment_id: str
    profile_type: str
    schema_version: str


class SaveResponsesRequest(BaseModel):
    responses: dict[str, Any]


def _load_questions(db: Session) -> list[dict[str, Any]]:
    schema = (
        db.query(AssessmentSchema).filter(AssessmentSchema.is_current.is_(True)).first()
    )
    if schema is None:
        schema = db.query(AssessmentSchema).first()
    if schema is None:
        return []

    questions = schema.questions
    if isinstance(questions, str):
        questions = json.loads(questions)

    return questions or []


def _get_assessment_or_404(assessment_id: str, db: Session) -> AssessmentRecord:
    rec = (
        db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    )
    if rec is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return rec


@router.post("/orgs", response_model=OrgCreateResponse, status_code=201)
def create_org(body: OrgCreateRequest, db: Session = Depends(_get_db)):
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
        email=body.email or None,
    )
    db.add(org)
    db.flush()

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
        email=body.email or None,
        tier=profile_type,
    )
    db.add(assessment)
    db.commit()

    log.info(
        "assessment.org_created org_id=%s profile=%s assessment_id=%s",
        org_id,
        profile_type,
        assessment_id,
    )

    return OrgCreateResponse(
        org_id=org_id,
        assessment_id=assessment_id,
        profile_type=profile_type,
        schema_version="v2025.1-base",
    )


@router.get("/{assessment_id}/questions")
def get_questions(assessment_id: str, db: Session = Depends(_get_db)):
    _get_assessment_or_404(assessment_id, db)
    return _load_questions(db)


@router.get("/{assessment_id}")
def get_assessment(assessment_id: str, db: Session = Depends(_get_db)):
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
        "payment_status": rec.payment_status,
        "tier": rec.tier,
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        "submitted_at": rec.submitted_at.isoformat() if rec.submitted_at else None,
    }


@router.patch("/{assessment_id}/responses", status_code=200)
def save_responses(
    assessment_id: str,
    body: SaveResponsesRequest,
    db: Session = Depends(_get_db),
):
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


@router.post("/{assessment_id}/checkout")
def create_checkout_session(assessment_id: str, db: Session = Depends(_get_db)):
    rec = _get_assessment_or_404(assessment_id, db)

    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not stripe_key:
        rec.payment_status = "paid"
        rec.tier = rec.profile_type
        db.commit()

        log.info(
            "assessment.checkout_dev_bypass assessment_id=%s profile=%s",
            assessment_id,
            rec.profile_type,
        )

        return {
            "checkout_url": None,
            "dev_bypass": True,
            "assessment_id": assessment_id,
        }

    if rec.payment_status == "paid":
        return {
            "checkout_url": None,
            "already_paid": True,
            "assessment_id": assessment_id,
        }

    import stripe  # noqa: PLC0415

    stripe.api_key = stripe_key

    amount = _TIER_PRICES.get(rec.profile_type, 29900)
    tier_label = _TIER_LABELS.get(rec.profile_type, rec.profile_type)
    base_url = os.environ.get("CONSOLE_BASE_URL", "https://app.frostgate.ai")

    org = db.query(OrgProfile).filter(OrgProfile.id == rec.org_profile_id).first()
    customer_email = (org.email if org else None) or rec.email or None

    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[
            {
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": f"FrostGate AI Governance Assessment — {tier_label}",
                        "description": (
                            "One-time AI governance risk assessment with "
                            "personalized Claude-powered advisory report."
                        ),
                    },
                    "unit_amount": amount,
                },
                "quantity": 1,
            }
        ],
        mode="payment",
        success_url=f"{base_url}/assessment?id={assessment_id}&payment=success",
        cancel_url=f"{base_url}/onboarding",
        metadata={"assessment_id": assessment_id},
        customer_email=customer_email,
    )

    rec.stripe_session_id = session.id
    rec.tier = rec.profile_type
    db.commit()

    log.info(
        "assessment.checkout_created assessment_id=%s session_id=%s amount=%d",
        assessment_id,
        session.id,
        amount,
    )

    return {"checkout_url": session.url, "assessment_id": assessment_id}


@router.post("/{assessment_id}/submit")
def submit_assessment(assessment_id: str, db: Session = Depends(_get_db)):
    rec = _get_assessment_or_404(assessment_id, db)

    if os.environ.get("STRIPE_SECRET_KEY") and rec.payment_status != "paid":
        raise HTTPException(
            status_code=402,
            detail="Payment required. Complete checkout to unlock your assessment report.",
        )

    if rec.status in ("submitted", "scored"):
        return {
            "assessment_id": rec.id,
            "overall_score": rec.overall_score,
            "risk_band": rec.risk_band,
            "domain_scores": rec.scores or {},
        }

    questions = _load_questions(db)
    if not questions:
        raise HTTPException(
            status_code=503,
            detail="Question bank not loaded — run database seeds",
        )

    result = score_assessment(questions, rec.responses or {}, rec.profile_type)

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
        assessment_id,
        result["overall_score"],
        result["risk_band"],
    )

    return {
        "assessment_id": rec.id,
        "overall_score": result["overall_score"],
        "risk_band": result["risk_band"],
        "domain_scores": result["domain_scores"],
    }
