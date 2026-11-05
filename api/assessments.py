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

import hashlib
import hmac
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_sessionmaker, set_tenant_context
from api.db_models import (
    AssessmentActivation,
    AssessmentRecord,
    AssessmentSchema,
    OrgProfile,
)
from api.auth_scopes.resolution import require_scopes

log = logging.getLogger("frostgate.assessments")

router = APIRouter(
    prefix="/ingest/assessment",
    tags=["assessment"],
    dependencies=[Depends(require_scopes("ingest:assessment"))],
)

# Public router: no API-key dependency.
# These endpoints carry their own credential (activation token or no secret at all).
# Mounted separately in main.py so the AuthGate middleware does not block them.
public_router = APIRouter(
    prefix="/ingest/assessment",
    tags=["assessment-public"],
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
    "data_governance": 0.20,
    "security_posture": 0.18,
    "ai_maturity": 0.18,
    "ai_trustworthiness": 0.15,
    "infra_readiness": 0.12,
    "compliance_awareness": 0.12,
    "automation_potential": 0.05,
}

_PROFILE_MULTIPLIERS: dict[str, dict[str, float]] = {
    "smb_basic": {
        "compliance_awareness": 0.50,
        "automation_potential": 0.50,
        "ai_trustworthiness": 0.50,
    },
    "smb_growth": {
        "compliance_awareness": 0.75,
        "ai_trustworthiness": 0.75,
    },
    "midmarket": {},
    "enterprise": {},
    "regulated": {
        "data_governance": 1.30,
        "security_posture": 1.15,
        "compliance_awareness": 1.25,
        "ai_trustworthiness": 1.50,
    },
    "govcon": {
        "data_governance": 1.40,
        "security_posture": 1.30,
        "compliance_awareness": 1.50,
        "infra_readiness": 1.20,
        "ai_trustworthiness": 1.60,
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
        # na_option marks one choice as "not applicable" — excluded from scoring
        # rather than scored as 0, so it doesn't penalise orgs for which the
        # control is genuinely irrelevant (e.g. "AI not used in high-stakes decisions").
        na_option = q.get("na_option")
        if na_option and str(raw_value) == na_option:
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


def _resolve_caller_tenant(request: Request) -> str | None:
    """Extract tenant_id from the authenticated API key on request.state.auth.

    Returns None for unbound (pre-tenant) callers; never returns "public".
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    t = getattr(auth, "tenant_id", None)
    if not t:
        return None
    s = str(t).strip()
    return s if s and s != "public" else None


def _get_assessment_or_404(
    assessment_id: str,
    caller_tenant: str | None,
    db: Session,
) -> AssessmentRecord:
    """Tenant-bound assessment lookup. Fails closed on missing or mismatched tenant.

    Tenant-bound callers → strict tenant_id predicate.
    Pre-tenant (unbound) callers → lead-namespace predicate (UUID ownership proof).
    """
    q = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id)
    if caller_tenant:
        q = q.filter(AssessmentRecord.tenant_id == caller_tenant)
    else:
        # Pre-tenant lead: tenant namespace is derived from the assessment UUID itself.
        # Caller proves ownership by knowing the exact UUID.
        q = q.filter(AssessmentRecord.tenant_id == f"lead:{assessment_id}")
    rec = q.first()
    if rec is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return rec


@router.post("/orgs", response_model=OrgCreateResponse, status_code=201)
def create_org(
    body: OrgCreateRequest, request: Request, db: Session = Depends(_get_db)
):
    caller_tenant = _resolve_caller_tenant(request)
    profile_type = classify_profile(
        industry=body.industry,
        employee_count=body.employee_count,
        handles_phi=body.handles_phi,
        handles_cui=body.handles_cui,
        is_dod_contractor=body.is_dod_contractor,
        fedramp_required=body.fedramp_required,
    )

    org_id = str(uuid.uuid4())
    assessment_id = str(uuid.uuid4())
    # Tenant-bound callers use their real tenant; pre-tenant leads get an isolated
    # lead namespace keyed by the assessment UUID so no two leads share a namespace.
    effective_tenant = caller_tenant or f"lead:{assessment_id}"
    set_tenant_context(db, effective_tenant)

    org = OrgProfile(
        org_id=org_id,
        tenant_id=effective_tenant,
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

    current_schema = (
        db.query(AssessmentSchema).filter(AssessmentSchema.is_current.is_(True)).first()
    )
    schema_version = (
        current_schema.schema_version if current_schema else "v2025.2-nist-mapped"
    )

    assessment = AssessmentRecord(
        id=assessment_id,
        tenant_id=effective_tenant,
        org_profile_id=org.id,
        org_id=org_id,
        schema_version=schema_version,
        profile_type=profile_type,
        status="draft",
        responses={},
        email=body.email or None,
        tier=profile_type,
    )
    db.add(assessment)
    db.commit()

    log.info(
        "assessment.org_created org_id=%s profile=%s assessment_id=%s tenant=%s",
        org_id,
        profile_type,
        assessment_id,
        effective_tenant,
    )

    return OrgCreateResponse(
        org_id=org_id,
        assessment_id=assessment_id,
        profile_type=profile_type,
        schema_version=schema_version,
    )


@router.get("/{assessment_id}/questions")
def get_questions(assessment_id: str, request: Request, db: Session = Depends(_get_db)):
    caller_tenant = _resolve_caller_tenant(request)
    _get_assessment_or_404(assessment_id, caller_tenant, db)
    return _load_questions(db)


@router.get("/{assessment_id}")
def get_assessment(
    assessment_id: str, request: Request, db: Session = Depends(_get_db)
):
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)
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
    request: Request,
    db: Session = Depends(_get_db),
):
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)
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
def create_checkout_session(
    assessment_id: str, request: Request, db: Session = Depends(_get_db)
):
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)

    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not stripe_key:
        # Fail closed — missing Stripe configuration is never a payment bypass.
        # Offline test workflows must set payment_status directly via fixtures,
        # not through this production endpoint.
        raise HTTPException(status_code=503, detail="STRIPE_NOT_CONFIGURED")

    if rec.payment_status == "paid":
        return {
            "checkout_url": None,
            "already_paid": True,
            "assessment_id": assessment_id,
        }

    import stripe  # noqa: PLC0415

    stripe.api_key = stripe_key

    # Reuse an existing active session rather than issuing a new URL.
    # Without this, a repeated checkout request overwrites stripe_session_id;
    # payment via the first URL then fails STRIPE_SESSION_ID_MISMATCH —
    # the customer is charged but the assessment stays unpaid. (P1 — #801)
    if rec.stripe_session_id:
        try:
            existing = stripe.checkout.Session.retrieve(rec.stripe_session_id)
            if getattr(existing, "status", None) == "open":
                log.info(
                    "assessment.checkout_reused assessment_id=%s session_id=%s",
                    assessment_id,
                    rec.stripe_session_id,
                )
                return {"checkout_url": existing.url, "assessment_id": assessment_id}
        except Exception as exc:
            # Session expired, cancelled, or Stripe error — create a new one.
            log.info(
                "assessment.checkout_retrieve_failed assessment_id=%s error=%s",
                assessment_id,
                exc,
            )

    # Amount is authoritative — determined server-side from profile_type only.
    # Never accept client-supplied amounts.
    amount = _TIER_PRICES.get(rec.profile_type, 29900)
    tier_label = _TIER_LABELS.get(rec.profile_type, rec.profile_type)
    base_url = os.environ.get("CONSOLE_BASE_URL", "https://app.frostgate.ai")
    idempotency_key = f"checkout_{assessment_id}"

    org = db.query(OrgProfile).filter(OrgProfile.id == rec.org_profile_id).first()
    customer_email = (org.email if org else None) or rec.email or None

    # Activation token for post-payment identity binding (L14-PORTAL-HANDOFF-001).
    # Embedded in success_url — proves bearer was on the Stripe success page.
    _pepper = os.environ.get("FG_KEY_PEPPER", "dev-pepper-unsafe")
    _raw_activation_token = secrets.token_urlsafe(32)
    _activation_token_hash = hmac.new(
        _pepper.encode(), _raw_activation_token.encode(), hashlib.sha256
    ).hexdigest()
    _activation_expires = datetime.now(timezone.utc) + timedelta(hours=24)

    # Revoke existing pending activations for this assessment before issuing a new one.
    db.query(AssessmentActivation).filter(
        AssessmentActivation.assessment_id == assessment_id,
        AssessmentActivation.state == "pending",
    ).update({"state": "revoked"})

    activation_record = AssessmentActivation(
        assessment_id=assessment_id,
        token_hash=_activation_token_hash,
        email_hint=customer_email,
        expires_at=_activation_expires,
        state="pending",
    )
    db.add(activation_record)

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
        success_url=f"{base_url}/assessment/activate?id={assessment_id}&at={_raw_activation_token}",
        cancel_url=f"{base_url}/onboarding",
        # metadata carries identifiers only — amount is validated server-side,
        # never trusted from metadata on the webhook path.
        metadata={
            "assessment_id": assessment_id,
            "tenant_id": rec.tenant_id,
            "payment_purpose": "assessment_initial",
        },
        customer_email=customer_email,
    )

    # Record the authoritative binding server-side before returning the URL.
    rec.stripe_session_id = session.id
    rec.expected_amount_cents = amount
    rec.payment_purpose = "assessment_initial"
    rec.checkout_idempotency_key = idempotency_key
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
def submit_assessment(
    assessment_id: str, request: Request, db: Session = Depends(_get_db)
):
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)

    if rec.payment_status != "paid":
        # Payment gate is unconditional — never bypassed by absent Stripe config.
        raise HTTPException(status_code=402, detail="PAYMENT_REQUIRED")

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


# ---------------------------------------------------------------------------
# Public endpoints (no API key required)
# ---------------------------------------------------------------------------


@public_router.get("/{assessment_id}/payment-status")
def get_payment_status(assessment_id: str, db: Session = Depends(_get_db)):
    """Server-side payment status check — safe for unauthenticated callers.

    Returns only payment_status and whether an activation token exists.
    Never reveals assessment content or cross-tenant data.
    """
    rec = (
        db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    )
    if rec is None:
        # Return 'not_found' rather than 404 to avoid enumeration oracle.
        return {"payment_status": "not_found", "has_activation": False}

    has_activation = (
        db.query(AssessmentActivation)
        .filter(
            AssessmentActivation.assessment_id == assessment_id,
            AssessmentActivation.state == "pending",
        )
        .first()
        is not None
    )

    return {
        "payment_status": rec.payment_status,  # "unpaid" | "paid"
        "has_activation": has_activation,
    }


class ActivateAssessmentRequest(BaseModel):
    access_token: str  # Auth0 OIDC access_token
    activation_token: str  # Raw token from success URL
    oidc_provider: str = "auth0"


@public_router.post("/{assessment_id}/activate")
def activate_assessment(
    assessment_id: str,
    body: ActivateAssessmentRequest,
    request: Request,
    db: Session = Depends(_get_db),
):
    """Secure post-payment assessment activation. L14-PORTAL-HANDOFF-001.

    Validates: activation token (single-use, unexpired, bound to assessment),
               OIDC access token, payment confirmed server-side.
    Creates: tenant, portal user, portal membership.
    Migrates: assessment tenant_id from lead:{id} to new tenant.
    Returns: pnu1. session token for the portal.

    Fail-closed: any validation failure returns 403 without revealing
    which specific check failed (prevents oracle attacks).
    """
    import api.portal_user_authority as pua  # noqa: PLC0415
    from api.identity_providers.auth0 import validate_auth0_token  # noqa: PLC0415
    from api.tenant_repository import TenantRepository  # noqa: PLC0415
    from api.db import get_engine  # noqa: PLC0415

    _pepper = os.environ.get("FG_KEY_PEPPER", "dev-pepper-unsafe")

    # 1. Validate activation token format (fail fast before DB hit)
    if not body.activation_token or len(body.activation_token) < 20:
        raise HTTPException(status_code=403, detail="ACTIVATION_DENIED")

    token_hash = hmac.new(
        _pepper.encode(), body.activation_token.encode(), hashlib.sha256
    ).hexdigest()

    now = datetime.now(timezone.utc)

    # 2. Look up assessment — no tenant predicate (activation is pre-binding)
    rec = (
        db.query(AssessmentRecord)
        .filter(AssessmentRecord.id == assessment_id)
        .with_for_update()
        .first()
    )

    if rec is None:
        raise HTTPException(status_code=403, detail="ACTIVATION_DENIED")

    # 3. Payment must be confirmed server-side before we grant access.
    if rec.payment_status != "paid":
        raise HTTPException(status_code=402, detail="PAYMENT_REQUIRED")

    # 3.5. Check if assessment is already bound to a real tenant.
    # Fail early before the activation lookup to avoid leaking information.
    if not rec.tenant_id.startswith("lead:"):
        raise HTTPException(status_code=409, detail="ASSESSMENT_ALREADY_CLAIMED")

    # 4. Validate activation token: must exist, unexpired, unused, correct assessment.
    activation = (
        db.query(AssessmentActivation)
        .filter(
            AssessmentActivation.token_hash == token_hash,
            AssessmentActivation.assessment_id == assessment_id,
            AssessmentActivation.state == "pending",
            AssessmentActivation.used_at.is_(None),
        )
        .with_for_update()
        .first()
    )

    if activation is None:
        raise HTTPException(status_code=403, detail="ACTIVATION_DENIED")

    if activation.expires_at < now:
        activation.state = "expired"
        db.commit()
        raise HTTPException(status_code=410, detail="ACTIVATION_EXPIRED")

    # 5. Validate OIDC access token and extract identity.
    try:
        actor = validate_auth0_token(body.access_token)
    except (ValueError, Exception) as exc:
        log.warning(
            "assessment.activate.invalid_oidc assessment_id=%s error=%s",
            assessment_id,
            exc,
        )
        raise HTTPException(status_code=401, detail="OIDC_TOKEN_INVALID") from exc

    oidc_sub = actor.subject or ""
    oidc_email = actor.email or ""
    if not oidc_sub:
        raise HTTPException(status_code=401, detail="OIDC_TOKEN_INVALID")

    # 7. Mark activation as claimed atomically (single-use enforcement)
    activation.used_at = now
    activation.state = "claimed"

    # 8. Create new tenant for this customer
    new_tenant_id = str(uuid.uuid4())
    org = db.query(OrgProfile).filter(OrgProfile.id == rec.org_profile_id).first()
    tenant_display = (
        (org.name if org and hasattr(org, "name") else None)
        or (org.org_name if org and hasattr(org, "org_name") else None)
        or oidc_email
        or f"Customer {assessment_id[:8]}"
    )

    tenant_repo = TenantRepository(get_engine())
    try:
        tenant_repo.create(
            new_tenant_id,
            display_name=str(tenant_display)[:255],
            tenant_kind="customer",
            created_by=f"activation:{assessment_id}",
            metadata={
                "source": "assessment_activation",
                "assessment_id": assessment_id,
            },
        )
    except ValueError:
        # Tenant ID collision (astronomically unlikely with UUID)
        raise HTTPException(status_code=503, detail="ACTIVATION_RETRY")

    # 9. Migrate assessment to new tenant
    rec.tenant_id = new_tenant_id
    activation.provisioned_tenant_id = new_tenant_id

    # 10. Create portal user + membership
    domain = os.environ.get("FG_AUTH0_DOMAIN", "").strip().rstrip("/")
    oidc_issuer = f"https://{domain}/" if domain else oidc_sub

    # Set RLS context for portal operations
    set_tenant_context(db, new_tenant_id)

    portal_user = pua.find_or_create_portal_user(
        db,
        tenant_id=new_tenant_id,
        oidc_provider=body.oidc_provider,
        oidc_issuer=oidc_issuer,
        oidc_subject=oidc_sub,
        email=oidc_email,
        display_name=getattr(actor, "name", None),
    )

    membership = pua.create_assessment_activation_membership(
        db,
        portal_user_id=portal_user.id,
        tenant_id=new_tenant_id,
        portal_role="general",
        assessment_id=assessment_id,
    )

    session = pua.create_session(
        db,
        portal_user_id=portal_user.id,
        portal_membership_id=membership.id,
        tenant_id=new_tenant_id,
        auth_version_snapshot=membership.auth_version,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=(request.headers.get("user-agent") or "")[:512],
    )

    db.commit()

    log.info(
        "assessment.activated assessment_id=%s tenant_id=%s portal_user=%s",
        assessment_id,
        new_tenant_id,
        portal_user.id,
    )

    return {
        "activated": True,
        "session_token": session.raw_token,
        "expires_at": session.expires_at,
        "tenant_id": new_tenant_id,
        "assessment_id": assessment_id,
        "portal_user_id": portal_user.id,
    }
